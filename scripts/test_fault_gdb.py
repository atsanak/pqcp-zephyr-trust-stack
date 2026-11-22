#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Packet-layer tests for fault_gdb and a fake-stub run of both timings."""

import socket
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fault_gdb as g  # noqa: E402


class Packets(unittest.TestCase):
    def test_encode_known_vector(self):
        self.assertEqual(g.encode_packet("OK"), b"$OK#9a")
        self.assertEqual(g.encode_packet("g"), b"$g#67")

    def test_roundtrip_and_bad_checksum_rejected(self):
        self.assertEqual(g.decode_packet(g.encode_packet("m1000,4")), "m1000,4")
        with self.assertRaises(g.GdbError):
            g.decode_packet(b"$OK#00")
        with self.assertRaises(g.GdbError):
            g.decode_packet(b"OK#9a")
        with self.assertRaises(g.GdbError):
            g.decode_packet(b"$OK#9")

    def test_stop_reply_detection(self):
        self.assertTrue(g.is_stop_reply("T05thread:1;"))
        self.assertTrue(g.is_stop_reply("S05"))
        self.assertFalse(g.is_stop_reply("OK"))
        self.assertFalse(g.is_stop_reply(""))


class FakeStub(threading.Thread):
    """Just enough of a gdbstub: memory, breakpoints, scripted stops."""

    def __init__(self, memory: dict, stops: list):
        super().__init__(daemon=True)
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.port = self.server.getsockname()[1]
        self.memory = memory
        self.stops = list(stops)
        self.writes = []
        self.steps = 0
        self.breakpoints = set()

    def run(self):
        conn, _ = self.server.accept()
        buf = b""
        while True:
            data = conn.recv(4096)
            if not data:
                return
            buf += data
            while b"$" in buf and b"#" in buf and \
                    len(buf) >= buf.index(b"#") + 3:
                s = buf.index(b"$")
                e = buf.index(b"#")
                frame, buf = buf[s:e + 3], buf[e + 3:]
                conn.sendall(b"+")
                cmd = g.decode_packet(frame)
                reply = self.handle(cmd)
                if reply is None:
                    return
                conn.sendall(g.encode_packet(reply))
                if buf[:1] == b"+":
                    buf = buf[1:]

    def handle(self, cmd):
        if cmd[0] == "m":
            addr, length = (int(x, 16) for x in cmd[1:].split(","))
            return bytes(self.memory.get(addr + i, 0)
                         for i in range(length)).hex()
        if cmd[0] == "M":
            head, data = cmd[1:].split(":")
            addr, length = (int(x, 16) for x in head.split(","))
            raw = bytes.fromhex(data)
            self.writes.append((addr, raw))
            for i, b in enumerate(raw):
                self.memory[addr + i] = b
            return "OK"
        if cmd.startswith("Z0"):
            self.breakpoints.add(int(cmd.split(",")[1], 16))
            return "OK"
        if cmd.startswith("z0"):
            self.breakpoints.discard(int(cmd.split(",")[1], 16))
            return "OK"
        if cmd == "c":
            return self.stops.pop(0) if self.stops else "W00"
        if cmd == "s":
            self.steps += 1
            return "T05"
        if cmd == "D":
            return None
        return ""


def client(stub):
    stub.start()
    return g.Gdb.connect(stub.port)


class Timings(unittest.TestCase):
    OLD, NEW = bytes([0x74, 0x02]), bytes([0x90, 0x90])

    def test_post_boot_patches_once_at_the_first_arm_hit(self):
        stub = FakeStub({0x500: 0x74, 0x501: 0x02}, ["T05"])
        gdb = client(stub)
        g.run_post_boot(gdb, 0x100, 0x500, self.NEW, self.OLD)
        self.assertEqual(stub.writes, [(0x500, self.NEW)])
        self.assertNotIn(0x100, stub.breakpoints)

    def test_post_boot_refuses_when_guest_bytes_differ(self):
        stub = FakeStub({0x500: 0x75, 0x501: 0x02}, ["T05"])
        gdb = client(stub)
        with self.assertRaises(g.GdbError):
            g.run_post_boot(gdb, 0x100, 0x500, self.NEW, self.OLD)
        self.assertEqual(stub.writes, [])

    def test_post_boot_fails_if_the_arm_point_is_never_reached(self):
        stub = FakeStub({0x500: 0x74, 0x501: 0x02}, ["W00"])
        gdb = client(stub)
        with self.assertRaises(g.GdbError):
            g.run_post_boot(gdb, 0x100, 0x500, self.NEW, self.OLD)

    def test_transient_patches_steps_and_restores(self):
        # scenario 2: two arm stops, then the 3rd execution of the site.
        stub = FakeStub({0x500: 0x74, 0x501: 0x02},
                        ["T05", "T05", "T05", "T05", "T05"])
        gdb = client(stub)
        done = g.run_transient(gdb, 0x100, 0x500, self.NEW, self.OLD,
                               scenario=2, hit=3)
        self.assertTrue(done)
        self.assertEqual(stub.writes, [(0x500, self.NEW), (0x500, self.OLD)])
        self.assertEqual(stub.steps, 2)
        self.assertEqual(stub.memory[0x500], 0x74)

    def test_transient_steps_one_instruction_for_a_non_nop_patch(self):
        inverted = bytes([0x75, 0x02])
        stub = FakeStub({0x500: 0x74, 0x501: 0x02}, ["T05", "T05"])
        gdb = client(stub)
        g.run_transient(gdb, 0x100, 0x500, inverted, self.OLD,
                        scenario=1, hit=1)
        self.assertEqual(stub.steps, 1)       # not len(old) == 2

    def test_transient_reports_a_fault_that_never_happened(self):
        stub = FakeStub({0x500: 0x74, 0x501: 0x02}, ["T05", "W00"])
        gdb = client(stub)
        done = g.run_transient(gdb, 0x100, 0x500, self.NEW, self.OLD,
                               scenario=1, hit=1)
        self.assertFalse(done)
        self.assertEqual(stub.writes, [])


if __name__ == "__main__":
    unittest.main()
