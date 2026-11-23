#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for the fleet-level drift audit.

Builds the host verifier once, then drives scripts/run_fleet_audit.py over
homogeneous, drifted, and tampered fleets. The per-device verification is
the C verifier; these tests check the fleet aggregation logic and exit
codes.
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent.parent
TOOL_DIR = MODULE_ROOT / "tools" / "evidence_verifier"
TESTDATA = TOOL_DIR / "testdata"
ADVISOR = TESTDATA / "advisor_qemu_transcript.log"
SIGNED = TESTDATA / "signed_passport_transcript.log"
FLEET = MODULE_ROOT / "scripts" / "run_fleet_audit.py"


def build_verifier(build_dir: Path) -> Path:
    subprocess.run(["cmake", "-S", str(TOOL_DIR), "-B", str(build_dir),
                    "-DCMAKE_BUILD_TYPE=Release"],
                   check=True, capture_output=True, text=True)
    subprocess.run(["cmake", "--build", str(build_dir)],
                   check=True, capture_output=True, text=True)
    return build_dir / "pqcp-evidence-verify"


def run_fleet(binary: Path, *args: str):
    return subprocess.run(
        [sys.executable, str(FLEET), "--verifier", str(binary), *args],
        capture_output=True, text=True)


def main() -> int:
    if shutil.which("cmake") is None:
        print("SKIP: cmake not available")
        return 0
    for fixture in (ADVISOR, SIGNED):
        if not fixture.exists():
            print(f"FAIL: fixture missing: {fixture}")
            return 1

    failures = []

    def check(label: str, cond: bool, detail: str = "") -> None:
        print(f"{'ok  ' if cond else 'FAIL'} - {label} {detail if not cond else ''}")
        if not cond:
            failures.append(label)

    with tempfile.TemporaryDirectory(prefix="pqcp-fleet-test-") as tmp:
        workdir = Path(tmp)
        binary = build_verifier(workdir / "build")

        # 1. Homogeneous fleet: three identical devices agree.
        result = run_fleet(binary, "--lenient",
                            str(ADVISOR), str(ADVISOR), str(ADVISOR))
        check("homogeneous fleet passes", result.returncode == 0,
              result.stdout + result.stderr)
        check("homogeneous fleet emits PASS marker",
              "PQCP_FLEET_AUDIT PASS" in result.stdout)

        # 2. Drift: two individually-valid but divergent devices fail strict.
        result = run_fleet(binary, "--lenient", str(ADVISOR), str(SIGNED))
        check("drifted fleet fails strict", result.returncode == 1)
        check("drifted fleet emits DRIFT marker",
              "PQCP_FLEET_AUDIT DRIFT" in result.stdout)

        # 3. Drift tolerated with --allow-drift.
        result = run_fleet(binary, "--lenient", "--allow-drift",
                            str(ADVISOR), str(SIGNED))
        check("drifted fleet passes with --allow-drift",
              result.returncode == 0)

        # 4. A tampered device fails per-device verification, so the fleet
        # fails regardless of drift policy.
        tampered = workdir / "tampered.log"
        tampered.write_text(
            ADVISOR.read_text().replace("passport_digest=d0df1fd5",
                                        "passport_digest=e0df1fd5"))
        result = run_fleet(binary, "--lenient", "--allow-drift",
                           str(ADVISOR), str(tampered))
        check("tampered device fails even with --allow-drift",
              result.returncode == 1)

        # 5. JSON summary is written and well-formed.
        json_path = workdir / "fleet.json"
        result = run_fleet(binary, "--lenient", "--json", str(json_path),
                           str(ADVISOR), str(ADVISOR))
        import json as _json
        summary = _json.loads(json_path.read_text())
        check("json reports a consistent homogeneous fleet",
              summary["fleet_consistent"] is True
              and summary["device_count"] == 2
              and len(summary["unique_passport_digests"]) == 1)

    if failures:
        print(f"\n{len(failures)} test(s) failed")
        return 1
    print("\nAll fleet audit tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
