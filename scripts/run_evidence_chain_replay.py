#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Capture a live device evidence transcript and replay it on host.

This is the executable bridge between the firmware deployment evidence
chain and the host assurance ledger:

1. build samples/pqcp_deployment_advisor for qemu_x86_64,
2. run it and capture the device transcript (the full marker chain through
   PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY),
3. build tools/evidence_verifier with the host toolchain (the UNMODIFIED
   firmware verifier C compiled for host),
4. replay the captured transcript with pqcp-evidence-verify and require
   CHAIN OK.

The captured device transcript is echoed to stdout in full so the calling
release gate hash-binds device evidence and host verdict into one step
transcript. Orchestration only: every verification decision is made by the
compiled C verifier.
"""

import argparse
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from local_workflow import (  # noqa: E402
    clean_env,
    detect_west_root,
    discover_west,
    run_command,
)

DEVICE_SUCCESS_MARKERS = (
    "PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY",
    "PROJECT EXECUTION SUCCESSFUL",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--west-root", type=Path, help="Zephyr workspace root")
    parser.add_argument("--west", help="Explicit west binary or command")
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=None,
        help="Zephyr build directory for the advisor sample",
    )
    parser.add_argument(
        "--host-build-dir",
        type=Path,
        default=None,
        help="CMake build directory for the host verifier",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory for the captured transcript and JSON summary",
    )
    parser.add_argument(
        "--run-timeout",
        type=int,
        default=120,
        help="Per-command wall-clock timeout in seconds",
    )
    parser.add_argument(
        "--transcript",
        type=Path,
        default=None,
        help="Replay an existing device transcript instead of running QEMU",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    env = clean_env()
    output_dir = args.output_dir or (MODULE_PATH / "build-evidence-chain-replay")
    output_dir.mkdir(parents=True, exist_ok=True)
    transcript_path = output_dir / "device_transcript.log"
    summary_path = output_dir / "replay_summary.json"

    if args.transcript is not None:
        transcript_path = args.transcript
        print(f"[evidence-chain] Using existing transcript {transcript_path}")
    else:
        west_root = detect_west_root(args.west_root or MODULE_PATH)
        west_cmd = discover_west(args.west, west_root, MODULE_PATH)
        build_dir = args.build_dir or (output_dir / "build-advisor")

        print("[evidence-chain] Building deployment advisor sample")
        run_command(
            [
                *west_cmd,
                "build",
                "-p",
                "always",
                "-b",
                "qemu_x86_64",
                str(MODULE_PATH / "samples/pqcp_deployment_advisor"),
                "-d",
                str(build_dir),
                "--",
                f"-DZEPHYR_EXTRA_MODULES={MODULE_PATH}",
            ],
            cwd=west_root,
            env=env,
            timeout=600,
        )

        print("[evidence-chain] Capturing device transcript")
        device_output = run_command(
            [*west_cmd, "build", "-d", str(build_dir), "-t", "run"],
            cwd=west_root,
            env=env,
            timeout=args.run_timeout,
            success_markers=DEVICE_SUCCESS_MARKERS,
        )
        transcript_path.write_text(device_output, encoding="utf-8")

    transcript_body = transcript_path.read_text(encoding="utf-8",
                                                errors="replace")
    missing = [m for m in DEVICE_SUCCESS_MARKERS if m not in transcript_body]
    if missing:
        print("[evidence-chain] Device transcript missing markers: "
              + ", ".join(missing))
        return 1

    print("[evidence-chain] ---- captured device transcript begin ----")
    print(transcript_body, end="" if transcript_body.endswith("\n") else "\n")
    print("[evidence-chain] ---- captured device transcript end ----")

    host_build_dir = args.host_build_dir or (output_dir / "build-host-verifier")
    print("[evidence-chain] Building host evidence verifier")
    run_command(
        [
            "cmake",
            "-S",
            str(MODULE_PATH / "tools/evidence_verifier"),
            "-B",
            str(host_build_dir),
            "-DCMAKE_BUILD_TYPE=Release",
        ],
        cwd=MODULE_PATH,
        env=env,
        timeout=120,
    )
    run_command(
        ["cmake", "--build", str(host_build_dir)],
        cwd=MODULE_PATH,
        env=env,
        timeout=300,
    )

    print("[evidence-chain] Replaying transcript with the host verifier")
    binary = host_build_dir / "pqcp-evidence-verify"
    result = subprocess.run(
        [str(binary), "--json", str(summary_path), str(transcript_path)],
        cwd=str(MODULE_PATH),
        env=env,
        capture_output=True,
        text=True,
    )
    print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.stderr:
        print(result.stderr, end="" if result.stderr.endswith("\n") else "\n")
    if result.returncode != 0:
        print(f"[evidence-chain] FAIL: host replay exited {result.returncode}")
        return 1

    print(f"[evidence-chain] JSON summary written to {summary_path}")
    print("[evidence-chain] PASS: device evidence chain replayed on host")
    return 0


if __name__ == "__main__":
    sys.exit(main())
