#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Minimal GDB remote-serial-protocol client for timed fault injection.

QEMU's gdbstub (qemu-system-x86_64 -S -gdb tcp:127.0.0.1:<port>) can read
and write guest memory and set breakpoints, which is what the SDK's plugin
API (v4) cannot do. This client implements only what the fault campaign
needs: memory read/write, software breakpoints, continue, single step.
Registers are deliberately never read or written, which avoids the target
description (32/64-bit register layout) entirely.

Fault timing built on it:
  post-boot   at the first arm point write the patch bytes, then continue:
              a permanent fault that appears after the boot self-test
  transient   at the arm point of one scenario, break on the k-th execution
              of the site, write the patch, single-step the patched bytes,
              restore the original bytes, continue: a single-shot fault

Pure stdlib; the packet layer is testable without QEMU (see
test_fault_gdb.py).
"""

import socket
import time


class GdbError(RuntimeError):
    pass


def checksum(payload: bytes) -> int:
    return sum(payload) & 0xFF


def encode_packet(payload: str) -> bytes:
    body = payload.encode("ascii")
    return b"$" + body + b"#" + f"{checksum(body):02x}".encode("ascii")


def decode_packet(frame: bytes) -> str:
    """Return the payload of one '$...#cc' frame; raise on a bad checksum."""
    if not frame.startswith(b"$") or b"#" not in frame:
        raise GdbError(f"malformed packet {frame!r}")
    body, _, tail = frame[1:].rpartition(b"#")
    if len(tail) != 2:
        raise GdbError(f"malformed packet trailer {frame!r}")
    if int(tail, 16) != checksum(body):
        raise GdbError(f"bad packet checksum {frame!r}")
    return body.decode("ascii")


def is_stop_reply(payload: str) -> bool:
    return payload[:1] in ("S", "T")


class Gdb:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.sock.settimeout(30)
        self.buffer = b""

    @classmethod
    def connect(cls, port: int, timeout: float = 20.0) -> "Gdb":
        deadline = time.time() + timeout
        while True:
            try:
                return cls(socket.create_connection(("127.0.0.1", port), 2))
            except OSError:
                if time.time() > deadline:
                    raise GdbError("could not connect to the gdbstub")
                time.sleep(0.1)

    # --- framing --------------------------------------------------------
    def _read_frame(self) -> bytes:
        while True:
            start = self.buffer.find(b"$")
            if start >= 0:
                end = self.buffer.find(b"#", start)
                if end >= 0 and len(self.buffer) >= end + 3:
                    frame = self.buffer[start:end + 3]
                    self.buffer = self.buffer[end + 3:]
                    return frame
            chunk = self.sock.recv(4096)
            if not chunk:
                raise GdbError("connection closed")
            self.buffer += chunk

    def _send(self, payload: str) -> None:
        self.sock.sendall(encode_packet(payload))

    def _recv(self) -> str:
        payload = decode_packet(self._read_frame())
        self.sock.sendall(b"+")
        return payload

    def _await_ack(self) -> None:
        while True:
            if not self.buffer:
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise GdbError("connection closed")
                self.buffer += chunk
            byte, self.buffer = self.buffer[:1], self.buffer[1:]
            if byte == b"+":
                return
            if byte == b"-":
                raise GdbError("packet rejected by the stub")
            if byte == b"$":
                self.buffer = byte + self.buffer
                return

    def command(self, payload: str) -> str:
        self._send(payload)
        self._await_ack()
        return self._recv()

    # --- operations -----------------------------------------------------
    def halt_reason(self) -> str:
        return self.command("?")

    def read(self, addr: int, length: int) -> bytes:
        reply = self.command(f"m{addr:x},{length:x}")
        if reply.startswith("E") or len(reply) != 2 * length:
            raise GdbError(f"memory read failed at {addr:#x}: {reply!r}")
        return bytes.fromhex(reply)

    def write(self, addr: int, data: bytes) -> None:
        reply = self.command(f"M{addr:x},{len(data):x}:{data.hex()}")
        if reply != "OK":
            raise GdbError(f"memory write failed at {addr:#x}: {reply!r}")

    def set_breakpoint(self, addr: int) -> None:
        if self.command(f"Z0,{addr:x},1") != "OK":
            raise GdbError(f"cannot set breakpoint at {addr:#x}")

    def clear_breakpoint(self, addr: int) -> None:
        if self.command(f"z0,{addr:x},1") != "OK":
            raise GdbError(f"cannot clear breakpoint at {addr:#x}")

    def cont(self, timeout: float = 12.0) -> str:
        """Continue; return the stop reply, or '' when the guest exits or no
        stop arrives within `timeout` seconds (the breakpoint is never
        reached: the guest runs to its idle loop and QEMU does not exit)."""
        self._send("c")
        self._await_ack()
        previous = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        try:
            return self._recv()
        except (GdbError, socket.timeout):
            return ""
        finally:
            self.sock.settimeout(previous)

    def step(self) -> str:
        return self.command("s")

    def detach(self) -> None:
        try:
            self._send("D")
        except OSError:
            pass


def run_post_boot(gdb: Gdb, arm: int, site: int, new: bytes,
                  old: bytes) -> None:
    """Permanent fault after the boot self-test: patch at the first arm hit."""
    gdb.set_breakpoint(arm)
    if not is_stop_reply(gdb.cont()):
        raise GdbError("target never reached the arm point")
    if gdb.read(site, len(old)) != old:
        raise GdbError("guest bytes at the site differ from the disassembly")
    gdb.clear_breakpoint(arm)
    gdb.write(site, new)
    gdb.detach()


def run_transient(gdb: Gdb, arm: int, site: int, new: bytes, old: bytes,
                  scenario: int, hit: int) -> bool:
    """Single-shot fault: patch on the `hit`-th execution of `site` after the
    arm point of `scenario`, step over it, restore. Returns False if the site
    was never executed that often (the fault never happened).

    QEMU's gdbstub reports the SAME breakpoint again, without running any
    code, if it is told to continue while stopped on it. Every continue from
    a breakpoint stop is therefore preceded by one single step.
    """
    gdb.set_breakpoint(arm)
    for index in range(scenario):
        if not is_stop_reply(gdb.cont()):
            raise GdbError("target never reached the arm point")
        if index + 1 < scenario:
            gdb.step()                      # leave this arm hit behind
    gdb.clear_breakpoint(arm)
    gdb.step()                              # off the arm breakpoint's pc
    gdb.set_breakpoint(site)
    for index in range(hit):
        if not is_stop_reply(gdb.cont()):
            gdb.detach()
            return False
        if index + 1 < hit:
            gdb.step()
    if gdb.read(site, len(old)) != old:
        raise GdbError("guest bytes at the site differ from the disassembly")
    gdb.write(site, new)
    gdb.clear_breakpoint(site)
    # A NOP fill is len(new) one-byte instructions; any other patch (branch
    # inversion, identity control) is exactly one instruction.
    steps = len(new) if new == bytes([0x90]) * len(new) else 1
    for _ in range(steps):
        gdb.step()
    gdb.write(site, old)
    gdb.detach()
    return True
