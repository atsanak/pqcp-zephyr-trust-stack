#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Release-gate wrapper for the emulated fault campaign.

Runs the exhaustive single-instruction campaign on two images and judges
the pair against scripts/fault_campaign_baseline.json:

  boot            the existing valid-only power-on self-test. The campaign
                  must still find exploitable sites here (otherwise the
                  campaign is not sensitive and says nothing).
  boot-negative   the power-on self-test with negative vectors. It must
                  leave ZERO exploitable sites.

Calibration (identical golden runs, identity-patch controls) is enforced
inside run_fault_campaign.py. Prints the two campaign marker lines and then
PQCP_FAULT_GATE PASS exploitable_boot=<n> exploitable_boot_negative=0 ...
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR.parent
BASELINE = SCRIPT_DIR / "fault_campaign_baseline.json"

MARKER_RE = re.compile(
    r"PQCP_FAULT_CAMPAIGN variant=(\S+) sites=(\d+) kem_fo_bypass=(\d+) "
    r"sig_verify_bypass=(\d+) detected_boot=(\d+) "
    r"(?:detected_runtime=\d+ )?fail_safe=(\d+) "
    r"corrupt=(\d+) no_effect=(\d+) crash=(\d+) timeout=(\d+) "
    r"controls_ok=(\d+)/(\d+)")


def parse_marker(text: str) -> dict | None:
    m = MARKER_RE.search(text)
    if not m:
        return None
    g = m.groups()
    return {"variant": g[0], "sites": int(g[1]), "kem": int(g[2]),
            "sig": int(g[3]), "detected_boot": int(g[4]),
            "controls_ok": int(g[10]), "controls": int(g[11]),
            "exploitable": int(g[2]) + int(g[3])}


def judge(results: dict, baseline: dict) -> tuple[list[str], str]:
    problems = []
    for variant in ("boot", "boot-negative"):
        r = results.get(variant)
        if r is None:
            problems.append(f"no campaign marker for variant {variant}")
            continue
        if r["sites"] < baseline["min_sites"]:
            problems.append(f"{variant}: only {r['sites']} sites")
        if r["controls"] == 0 or r["controls_ok"] != r["controls"]:
            problems.append(f"{variant}: identity controls not all clean")
    if problems:
        return problems, "PQCP_FAULT_GATE FAIL"
    boot, neg = results["boot"], results["boot-negative"]
    if boot["exploitable"] < baseline["boot_exploitable_min"]:
        problems.append(
            f"campaign not sensitive: valid-only boot image shows "
            f"{boot['exploitable']} exploitable sites, expected at least "
            f"{baseline['boot_exploitable_min']}")
    if neg["exploitable"] > baseline["boot_negative_exploitable_max"]:
        problems.append(
            f"{neg['exploitable']} exploitable site(s) survive the "
            "negative-vector boot self-test")
    if neg["detected_boot"] <= boot["detected_boot"]:
        problems.append("negative vectors detect no more than valid-only")
    status = "FAIL" if problems else "PASS"
    return problems, (
        f"PQCP_FAULT_GATE {status} sites={neg['sites']} "
        f"exploitable_boot={boot['exploitable']} "
        f"exploitable_boot_negative={neg['exploitable']} "
        f"detected_boot={boot['detected_boot']} "
        f"detected_boot_negative={neg['detected_boot']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--west-root", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    results = {}
    for variant in ("boot", "boot-negative"):
        cmd = [sys.executable, str(SCRIPT_DIR / "run_fault_campaign.py"),
               "--variant", variant, "--jobs", str(args.jobs),
               "--output-dir", str(args.output_dir / variant)]
        if args.west_root:
            cmd += ["--west-root", str(args.west_root)]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              cwd=MODULE_PATH)
        text = proc.stdout + proc.stderr
        for line in text.splitlines():
            if line.startswith(("[fault] EXPLOITABLE", "PQCP_FAULT_CAMPAIGN")):
                print(line)
        parsed = parse_marker(text)
        if proc.returncode != 0 or parsed is None:
            print(f"[fault-gate] FAIL: campaign {variant} did not complete")
            print(text[-1500:])
            return 1
        results[variant] = parsed
    problems, marker = judge(results, baseline)
    print(marker)
    for p in problems:
        print(f"[fault-gate] FAIL: {p}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
