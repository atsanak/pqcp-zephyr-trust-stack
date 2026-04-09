#!/usr/bin/env python3
"""
Drive the pqcp_serial_acvp sample over either a serial port or a subprocess.

This is intentionally a thin, deterministic host-side harness rather than a
full NIST ACVP client. Its purpose is to validate the stable `RESULT:*` /
`ERROR:*` protocol and demonstrate how external tooling can integrate with the
serial sample in the lab.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, List, Optional

try:
    import serial  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - optional dependency
    serial = None


MLKEM_SIZES = {
    512: {"pk": 800, "ct": 768},
    768: {"pk": 1184, "ct": 1088},
    1024: {"pk": 1568, "ct": 1568},
}

MLDSA_SIZES = {
    44: {"pk": 1312},
    65: {"pk": 1952},
    87: {"pk": 2592},
}

DEFAULT_SEED_HEX = (
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f"
)
DEFAULT_MESSAGE_HEX = "616376702d736d6f6b652d6d7367"

HOST_ENV_BLACKLIST = (
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "CPATH",
    "SDKROOT",
)
ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


@dataclass
class CommandRecord:
    command: str
    response: str


class SessionError(RuntimeError):
    pass


class BaseTransport:
    def send_line(self, line: str) -> None:
        raise NotImplementedError

    def wait_for(self, predicate: Callable[[str], bool], timeout: float) -> str:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    @property
    def transcript(self) -> List[str]:
        raise NotImplementedError


class SubprocessTransport(BaseTransport):
    def __init__(
        self,
        command: str,
        *,
        cwd: Optional[Path],
        env: Optional[dict[str, str]],
        char_delay: float,
    ) -> None:
        self._command = shlex.split(command)
        if not self._command:
            raise SessionError("run command must not be empty")

        self._cwd = str(cwd) if cwd else None
        self._env = env
        self._char_delay = max(char_delay, 0.0)
        self._queue: queue.Queue[Optional[str]] = queue.Queue()
        self._transcript: List[str] = []
        self._partial = ""
        self._proc = subprocess.Popen(
            self._command,
            cwd=self._cwd,
            env=self._env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=0,
            start_new_session=True,
        )
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def _reader(self) -> None:
        assert self._proc.stdout is not None

        while True:
            char = self._proc.stdout.read(1)
            if char == "":
                if self._partial.strip():
                    self._transcript.append(self._partial.rstrip())
                    self._queue.put(self._partial.rstrip())
                self._queue.put(None)
                return

            self._partial += char
            if char == "\n":
                line = self._partial.rstrip("\r\n")
                self._transcript.append(line)
                self._queue.put(line)
                self._partial = ""

    def send_line(self, line: str) -> None:
        if self._proc.stdin is None:
            raise SessionError("subprocess stdin is unavailable")
        payload = line + "\n"
        if self._char_delay > 0:
            for char in payload:
                self._proc.stdin.write(char)
                self._proc.stdin.flush()
                time.sleep(self._char_delay)
            return
        self._proc.stdin.write(payload)
        self._proc.stdin.flush()

    def wait_for(self, predicate: Callable[[str], bool], timeout: float) -> str:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SessionError("timed out waiting for subprocess response")
            try:
                item = self._queue.get(timeout=remaining)
            except queue.Empty as exc:
                raise SessionError("timed out waiting for subprocess output") from exc
            if item is None:
                raise SessionError("subprocess exited before the expected response")
            if predicate(item):
                return item

    def close(self) -> None:
        if self._proc.poll() is not None:
            return

        try:
            os.killpg(self._proc.pid, signal.SIGTERM)
            self._proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(self._proc.pid, signal.SIGKILL)
            except OSError:
                pass

    @property
    def transcript(self) -> List[str]:
        return list(self._transcript)


class SerialTransport(BaseTransport):
    def __init__(self, port: str, *, baudrate: int, char_delay: float) -> None:
        if serial is None:
            raise SessionError(
                "pyserial is required for --serial-port mode; install it with 'python -m pip install pyserial'"
            )
        self._serial = serial.Serial(port=port, baudrate=baudrate, timeout=0.1, write_timeout=5)
        self._char_delay = max(char_delay, 0.0)
        self._transcript: List[str] = []

    def send_line(self, line: str) -> None:
        payload = line + "\n"
        if self._char_delay > 0:
            for char in payload:
                self._serial.write(char.encode("ascii"))
                self._serial.flush()
                time.sleep(self._char_delay)
            return
        self._serial.write(payload.encode("ascii"))
        self._serial.flush()

    def wait_for(self, predicate: Callable[[str], bool], timeout: float) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            raw = self._serial.readline()
            if not raw:
                continue
            line = raw.decode("ascii", errors="replace").rstrip("\r\n")
            self._transcript.append(line)
            if predicate(line):
                return line
        raise SessionError("timed out waiting for serial response")

    def close(self) -> None:
        self._serial.close()

    @property
    def transcript(self) -> List[str]:
        return list(self._transcript)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a deterministic ACVP smoke session against pqcp_serial_acvp"
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--serial-port", help="Serial port connected to pqcp_serial_acvp")
    target.add_argument("--run-command", help="Command that launches the sample on stdio (for example: 'west build -d build-acvp -t run')")
    parser.add_argument("--cwd", type=Path, help="Working directory used with --run-command")
    parser.add_argument("--baudrate", type=int, default=115200, help="Serial baud rate")
    parser.add_argument("--kem-level", type=int, default=768, choices=sorted(MLKEM_SIZES))
    parser.add_argument("--sig-level", type=int, default=65, choices=sorted(MLDSA_SIZES))
    parser.add_argument("--seed-hex", default=DEFAULT_SEED_HEX, help="Deterministic seed used for the smoke session")
    parser.add_argument("--message-hex", default=DEFAULT_MESSAGE_HEX, help="Message payload used for ML-DSA sign/verify")
    parser.add_argument("--startup-timeout", type=float, default=60.0)
    parser.add_argument("--response-timeout", type=float, default=20.0)
    parser.add_argument(
        "--command-delay",
        type=float,
        default=0.2,
        help="Small settling delay between command/response exchanges",
    )
    parser.add_argument(
        "--char-delay",
        type=float,
        default=0.001,
        help="Per-character pacing delay used when sending commands",
    )
    parser.add_argument("--json-out", type=Path, help="Optional JSON summary output path")
    parser.add_argument("--transcript-out", type=Path, help="Optional raw transcript output path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print command/response pairs as they execute")
    return parser.parse_args()


def expect_result_ok(response: str) -> None:
    if response != "RESULT:OK":
        raise SessionError(f"expected RESULT:OK, got {response}")


def expect_result_invalid(response: str) -> None:
    if response != "RESULT:INVALID":
        raise SessionError(f"expected RESULT:INVALID, got {response}")


def extract_hex_payload(response: str) -> str:
    if not response.startswith("RESULT:") or response in {"RESULT:OK", "RESULT:INVALID"}:
        raise SessionError(f"expected RESULT:<hex payload>, got {response}")
    payload = response.split(":", 1)[1]
    if not re.fullmatch(r"[0-9a-f]+", payload):
        raise SessionError(f"expected lowercase hex payload, got {response}")
    return payload


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub("", text)


def extract_protocol_response(line: str) -> Optional[str]:
    cleaned = strip_ansi(line).strip()
    for marker in ("RESULT:", "ERROR:"):
        idx = cleaned.find(marker)
        if idx != -1:
            return cleaned[idx:].strip()
    return None


def wait_for_startup(transport: BaseTransport, timeout: float) -> str:
    return transport.wait_for(
        lambda line: (
            "Ready for commands" in strip_ansi(line)
            or strip_ansi(line).startswith("PQCP Serial ACVP Interface")
        ),
        timeout,
    )


def issue_command(
    transport: BaseTransport,
    command: str,
    *,
    timeout: float,
    command_delay: float,
    verbose: bool,
    records: List[CommandRecord],
) -> str:
    if command_delay > 0:
        time.sleep(command_delay)
    if verbose:
        print(f"> {command}")
    transport.send_line(command)
    response_line = transport.wait_for(
        lambda line: extract_protocol_response(line) is not None,
        timeout,
    )
    response = extract_protocol_response(response_line)
    if response is None:
        raise SessionError(f"missing protocol response for {command}")
    records.append(CommandRecord(command=command, response=response))
    if verbose:
        print(response)
    if response.startswith("ERROR:"):
        raise SessionError(f"{command} failed with {response}")
    return response


def tamper_last_byte(hex_payload: str) -> str:
    last = int(hex_payload[-2:], 16) ^ 0x01
    return hex_payload[:-2] + f"{last:02x}"


def run_smoke_session(transport: BaseTransport, args: argparse.Namespace) -> dict[str, object]:
    records: List[CommandRecord] = []
    wait_for_startup(transport, args.startup_timeout)

    expect_result_ok(
        issue_command(
            transport,
            "SELFTEST::",
            timeout=args.response_timeout,
            command_delay=args.command_delay,
            verbose=args.verbose,
            records=records,
        )
    )
    expect_result_ok(
        issue_command(
            transport,
            f"SEED:DRBG:0:{args.seed_hex}",
            timeout=args.response_timeout,
            command_delay=args.command_delay,
            verbose=args.verbose,
            records=records,
        )
    )

    mlkem_keygen = extract_hex_payload(
        issue_command(
            transport,
            f"KEYGEN:MLKEM:{args.kem_level}:",
            timeout=args.response_timeout,
            command_delay=args.command_delay,
            verbose=args.verbose,
            records=records,
        )
    )
    mlkem_pk_hex_len = MLKEM_SIZES[args.kem_level]["pk"] * 2
    mlkem_pk_hex = mlkem_keygen[:mlkem_pk_hex_len]
    mlkem_sk_hex = mlkem_keygen[mlkem_pk_hex_len:]

    mlkem_encaps = extract_hex_payload(
        issue_command(
            transport,
            f"ENCAPS:MLKEM:{args.kem_level}:{mlkem_pk_hex}",
            timeout=args.response_timeout,
            command_delay=args.command_delay,
            verbose=args.verbose,
            records=records,
        )
    )
    mlkem_ct_hex_len = MLKEM_SIZES[args.kem_level]["ct"] * 2
    mlkem_ct_hex = mlkem_encaps[:mlkem_ct_hex_len]
    mlkem_ss_hex = mlkem_encaps[mlkem_ct_hex_len:]

    mlkem_decaps = extract_hex_payload(
        issue_command(
            transport,
            f"DECAPS:MLKEM:{args.kem_level}:{mlkem_ct_hex}{mlkem_sk_hex}",
            timeout=args.response_timeout,
            command_delay=args.command_delay,
            verbose=args.verbose,
            records=records,
        )
    )
    if mlkem_decaps != mlkem_ss_hex:
        raise SessionError("ML-KEM shared secrets did not match")

    mldsa_keygen = extract_hex_payload(
        issue_command(
            transport,
            f"KEYGEN:MLDSA:{args.sig_level}:",
            timeout=args.response_timeout,
            command_delay=args.command_delay,
            verbose=args.verbose,
            records=records,
        )
    )
    mldsa_pk_hex_len = MLDSA_SIZES[args.sig_level]["pk"] * 2
    mldsa_pk_hex = mldsa_keygen[:mldsa_pk_hex_len]
    mldsa_sk_hex = mldsa_keygen[mldsa_pk_hex_len:]

    mldsa_sig = extract_hex_payload(
        issue_command(
            transport,
            f"SIGN:MLDSA:{args.sig_level}:{mldsa_sk_hex}{args.message_hex}",
            timeout=args.response_timeout,
            command_delay=args.command_delay,
            verbose=args.verbose,
            records=records,
        )
    )

    expect_result_ok(
        issue_command(
            transport,
            f"VERIFY:MLDSA:{args.sig_level}:{mldsa_pk_hex}{args.message_hex}{mldsa_sig}",
            timeout=args.response_timeout,
            command_delay=args.command_delay,
            verbose=args.verbose,
            records=records,
        )
    )
    expect_result_invalid(
        issue_command(
            transport,
            f"VERIFY:MLDSA:{args.sig_level}:{mldsa_pk_hex}{args.message_hex}{tamper_last_byte(mldsa_sig)}",
            timeout=args.response_timeout,
            command_delay=args.command_delay,
            verbose=args.verbose,
            records=records,
        )
    )

    return {
        "kem_level": args.kem_level,
        "sig_level": args.sig_level,
        "message_hex": args.message_hex,
        "seed_hex": args.seed_hex,
        "mlkem_pk_bytes": len(mlkem_pk_hex) // 2,
        "mlkem_sk_bytes": len(mlkem_sk_hex) // 2,
        "mlkem_ct_bytes": len(mlkem_ct_hex) // 2,
        "mlkem_ss_bytes": len(mlkem_ss_hex) // 2,
        "mldsa_pk_bytes": len(mldsa_pk_hex) // 2,
        "mldsa_sk_bytes": len(mldsa_sk_hex) // 2,
        "mldsa_sig_bytes": len(mldsa_sig) // 2,
        "commands": [asdict(record) for record in records],
    }


def build_transport(args: argparse.Namespace) -> BaseTransport:
    if args.serial_port:
        return SerialTransport(
            args.serial_port,
            baudrate=args.baudrate,
            char_delay=args.char_delay,
        )

    env = os.environ.copy()
    for key in HOST_ENV_BLACKLIST:
        env.pop(key, None)

    return SubprocessTransport(
        args.run_command,
        cwd=args.cwd.resolve() if args.cwd else None,
        env=env,
        char_delay=args.char_delay,
    )


def main() -> int:
    args = parse_args()
    transport = build_transport(args)

    try:
        summary = run_smoke_session(transport, args)
    except SessionError as exc:
        if args.transcript_out:
            args.transcript_out.write_text("\n".join(transport.transcript) + "\n")
        print(f"ACVP smoke failed: {exc}", file=sys.stderr)
        return 1
    finally:
        transport.close()

    if args.transcript_out:
        args.transcript_out.write_text("\n".join(transport.transcript) + "\n")

    if args.json_out:
        args.json_out.write_text(json.dumps(summary, indent=2) + "\n")

    print("ACVP smoke session completed successfully.")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
