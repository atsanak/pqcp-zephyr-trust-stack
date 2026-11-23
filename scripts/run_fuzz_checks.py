#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build and run the evidence-grammar fuzzer under ASan+UBSan.

Orchestration only: tools/evidence_fuzzer drives the unmodified firmware
marker parsers with mutated transcript lines, plus the host-portable fleet
parsers (deterministic CBOR, COSE_Sign1, COSE_Key, policy module codec)
with mutated binary inputs seeded from the real encoders. Sanitizers turn
any memory error or UB into a nonzero exit, and the binary targets also
assert round-trip and rejected-input invariants. A clean run prints one
PQCP_FUZZ PASS marker per seed (plus a PQCP_FUZZ BINARY_ACCEPTED line),
which the release gate hash-binds into the assurance ledger.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from local_workflow import clean_env, run_command  # noqa: E402

FUZZER_DIR = MODULE_PATH / "tools" / "evidence_fuzzer"
DEFAULT_CORPUS = (
    MODULE_PATH / "tools/evidence_verifier/testdata/advisor_qemu_transcript.log",
    MODULE_PATH / "tools/evidence_verifier/testdata/signed_passport_transcript.log",
)
DEFAULT_SEEDS = ("0x1", "0xdeadbeef", "0x9e3779b97f4a7c15")

# 6 text replay parsers + fleet CBOR, COSE_Sign1, COSE_Key, policy codec.
# generate_assurance_ledger.EVIDENCE_FUZZ_MIN_TARGETS must match.
EXPECTED_TARGETS = 10
BINARY_ACCEPTED_RE = re.compile(
    r"PQCP_FUZZ BINARY_ACCEPTED cbor=(\d+) cose_sign1=(\d+) cose_key=(\d+) "
    r"policy=(\d+) policy_verified=(\d+) policy_vm_decided=(\d+)"
)
TARGETS_RE = re.compile(r"PQCP_FUZZ PASS targets=(\d+)\b")


def check_campaign_output(stdout: str) -> str | None:
    """Return a failure reason, or None when the campaign marker is sound."""
    marker = TARGETS_RE.search(stdout)
    if marker is None:
        return "PQCP_FUZZ PASS marker lacks a targets= field"
    if int(marker.group(1)) != EXPECTED_TARGETS:
        return (
            f"PQCP_FUZZ PASS reports targets={marker.group(1)}, "
            f"expected {EXPECTED_TARGETS}"
        )
    accepted = BINARY_ACCEPTED_RE.search(stdout)
    if accepted is None:
        return "missing PQCP_FUZZ BINARY_ACCEPTED line"
    if any(int(count) == 0 for count in accepted.groups()):
        return (
            "a binary parser accepted no inputs "
            f"({accepted.group(0)}); the campaign never got past the "
            "rejection gates"
        )
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=MODULE_PATH / "build-evidence-fuzz",
        help="CMake build directory for the fuzzer",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=200000,
        help="Mutated inputs per seed",
    )
    parser.add_argument(
        "--seeds",
        nargs="+",
        default=list(DEFAULT_SEEDS),
        help="PRNG seeds; each runs a full campaign",
    )
    parser.add_argument(
        "--corpus",
        nargs="+",
        type=Path,
        default=list(DEFAULT_CORPUS),
        help="Transcript files used as the seed corpus",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    env = clean_env()

    for corpus in args.corpus:
        if not corpus.exists():
            print(f"[fuzz] FAIL: corpus file missing: {corpus}")
            return 1

    print("[fuzz] Building evidence fuzzer (ASan+UBSan)")
    run_command(
        ["cmake", "-S", str(FUZZER_DIR), "-B", str(args.build_dir),
         "-DCMAKE_BUILD_TYPE=RelWithDebInfo"],
        cwd=MODULE_PATH, env=env, timeout=120)
    run_command(
        ["cmake", "--build", str(args.build_dir)],
        cwd=MODULE_PATH, env=env, timeout=600)

    binary = args.build_dir / "pqcp-evidence-fuzz"
    for seed in args.seeds:
        print(f"[fuzz] Campaign seed={seed} iterations={args.iterations}")
        result = subprocess.run(
            [str(binary), "--iterations", str(args.iterations),
             "--seed", str(seed),
             *[str(c) for c in args.corpus]],
            cwd=str(MODULE_PATH), env=env, capture_output=True, text=True)
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
        if result.stderr:
            print(result.stderr,
                  end="" if result.stderr.endswith("\n") else "\n")
        if result.returncode != 0 or "PQCP_FUZZ PASS" not in result.stdout:
            print(f"[fuzz] FAIL: campaign seed={seed} exited "
                  f"{result.returncode}")
            return 1
        problem = check_campaign_output(result.stdout)
        if problem is not None:
            print(f"[fuzz] FAIL: campaign seed={seed}: {problem}")
            return 1

    print(f"[fuzz] PASS: {len(args.seeds)} campaign(s) x "
          f"{args.iterations} iterations, no sanitizer findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
