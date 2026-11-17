#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Run every host-side assurance check that needs no Zephyr workspace.

One entry point shared by developers and CI, so a green local run means a
green job. Needs only Python 3, cmake and a C compiler:

  1. py_compile every script
  2. ztest suites are all registered with twister
  3. evidence-coverage ratchet
  4. local tool regression tests
  5. host evidence verifier tests (builds the unmodified firmware verifier)
  6. mutation checks: weakened verifier security checks must be caught
  7. coverage-guided evidence-grammar fuzz under ASan+UBSan

Writes host_assurance_report.json and, under GitHub Actions, a markdown
job summary. Exits nonzero if any step failed; every step still runs so one
failure never hides another.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = MODULE_ROOT / "scripts"


def step_commands(output_dir: Path, fuzz_iterations: int) -> list[tuple[str, list[str]]]:
    py = sys.executable
    return [
        ("python compile",
         [py, "-m", "py_compile", *sorted(str(p) for p in SCRIPTS.glob("*.py"))]),
        ("testcase registry",
         [py, str(SCRIPTS / "generate_testcase_yaml.py"), "--check"]),
        ("evidence coverage ratchet",
         [py, str(SCRIPTS / "audit_evidence_coverage.py"), "--check",
          "--json", str(output_dir / "evidence_coverage.json")]),
        ("local tool tests",
         [py, str(SCRIPTS / "run_local_tool_tests.py")]),
        ("evidence verifier tests",
         [py, str(SCRIPTS / "test_evidence_verifier.py")]),
        ("verifier mutation checks",
         [py, str(SCRIPTS / "run_mutation_checks.py")]),
        ("evidence parser fuzz",
         [py, str(SCRIPTS / "run_fuzz_checks.py"),
          "--build-dir", str(output_dir / "fuzz-build"),
          "--iterations", str(fuzz_iterations)]),
    ]


def run_step(name: str, cmd: list[str]) -> dict:
    started = time.monotonic()
    proc = subprocess.run(cmd, cwd=MODULE_ROOT, capture_output=True, text=True)
    elapsed = time.monotonic() - started
    output = (proc.stdout or "") + (proc.stderr or "")
    status = "PASS" if proc.returncode == 0 else "FAIL"
    print(f"[host-assurance] {status} {name} ({elapsed:.1f}s)", flush=True)
    if proc.returncode != 0:
        print(output[-4000:], flush=True)
    return {"step": name, "status": status, "returncode": proc.returncode,
            "seconds": round(elapsed, 1), "tail": output[-600:]}


def write_summary(results: list[dict]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    lines = ["## Host assurance", "", "| Step | Result | Seconds |",
             "|---|---|---|"]
    for item in results:
        mark = "✅" if item["status"] == "PASS" else "❌"
        lines.append(f"| {item['step']} | {mark} {item['status']} | "
                     f"{item['seconds']} |")
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--output-dir", type=Path,
                        default=MODULE_ROOT / "build-host-assurance")
    parser.add_argument("--fuzz-iterations", type=int, default=50000)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    results = [run_step(name, cmd)
               for name, cmd in step_commands(args.output_dir,
                                              args.fuzz_iterations)]

    failed = [r["step"] for r in results if r["status"] != "PASS"]
    report = {"schema_version": 1, "passed": not failed, "steps": results}
    (args.output_dir / "host_assurance_report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    write_summary(results)

    if failed:
        print(f"[host-assurance] FAIL: {', '.join(failed)}")
        return 1
    print(f"PQCP_HOST_ASSURANCE PASS steps={len(results)}")
    print("[host-assurance] PASS: all host assurance steps succeeded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
