#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Release-gate wrapper for the fault-timing countermeasure ablation.

Re-measures the four cells the claim rests on (full campaigns, every
instruction of the ML-KEM-768 decapsulation and ML-DSA-65 verify code):

                        post-boot permanent    transient single-shot
  boot-negative (base)  must find exploitable  must find exploitable
  hardened              must find NONE         must find NONE

The base image proves the campaign is sensitive for BOTH timings (otherwise
a zero on the hardened image would say nothing). The hardened image is the
canary + duplication configuration; the two single-countermeasure images
(canary: transient survives; duplicate: permanent survives) are published
in docs/fault-campaign.md from the full table, not re-run here.

Prints the campaign markers and then
  PQCP_FAULT_TIMING_GATE PASS base_postboot=<n> base_transient=<n>
      hardened_postboot=0 hardened_transient=0 ...
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR.parent
BASELINE = SCRIPT_DIR / "fault_timing_baseline.json"
CELLS = (("boot-negative", "post-boot"), ("hardened", "post-boot"),
         ("boot-negative", "transient"), ("hardened", "transient"))

MARKER_RE = re.compile(
    r"PQCP_FAULT_CAMPAIGN variant=(\S+) sites=(\d+) kem_fo_bypass=(\d+) "
    r"sig_verify_bypass=(\d+) .*?harness_error=(\d+) controls_ok=(\d+)/(\d+) "
    r"timing=(\S+) exploitable_sites=(\d+)")


def parse_marker(text: str) -> dict | None:
    m = MARKER_RE.search(text)
    if not m:
        return None
    g = m.groups()
    return {"variant": g[0], "sites": int(g[1]),
            "exploitable_runs": int(g[2]) + int(g[3]),
            "harness_error": int(g[4]), "controls_ok": int(g[5]),
            "controls": int(g[6]), "timing": g[7],
            "exploitable_sites": int(g[8])}


def judge(results: dict, baseline: dict) -> tuple[list[str], str]:
    """results: {(variant, timing): parsed marker}."""
    problems = []
    for cell in CELLS:
        r = results.get(cell)
        label = f"{cell[0]}/{cell[1]}"
        if r is None:
            problems.append(f"no campaign marker for {label}")
            continue
        if r["timing"] != cell[1] or r["variant"] != cell[0]:
            problems.append(f"{label}: marker is for {r['variant']}/"
                            f"{r['timing']}")
        if r["sites"] < baseline["min_sites"]:
            problems.append(f"{label}: only {r['sites']} faults")
        if r["controls"] == 0 or r["controls_ok"] != r["controls"]:
            problems.append(f"{label}: identity controls not all clean")
        if r["harness_error"] != 0:
            problems.append(f"{label}: {r['harness_error']} harness errors")
    if problems:
        return problems, "PQCP_FAULT_TIMING_GATE FAIL"
    bp = results[("boot-negative", "post-boot")]["exploitable_sites"]
    bt = results[("boot-negative", "transient")]["exploitable_sites"]
    hp = results[("hardened", "post-boot")]["exploitable_sites"]
    ht = results[("hardened", "transient")]["exploitable_sites"]
    if bp < baseline["base_postboot_min"]:
        problems.append(f"campaign not sensitive post-boot: base has {bp} "
                        f"exploitable sites, expected >= "
                        f"{baseline['base_postboot_min']}")
    if bt < baseline["base_transient_min"]:
        problems.append(f"campaign not sensitive to transient faults: base "
                        f"has {bt}, expected >= "
                        f"{baseline['base_transient_min']}")
    if hp > baseline["hardened_postboot_max"]:
        problems.append(f"{hp} exploitable site(s) survive on the hardened "
                        "image after boot (permanent)")
    if ht > baseline["hardened_transient_max"]:
        problems.append(f"{ht} exploitable site(s) survive on the hardened "
                        "image (transient)")
    status = "FAIL" if problems else "PASS"
    return problems, (
        f"PQCP_FAULT_TIMING_GATE {status} "
        f"sites_postboot={results[('hardened', 'post-boot')]['sites']} "
        f"sites_transient={results[('hardened', 'transient')]['sites']} "
        f"base_postboot={bp} base_transient={bt} "
        f"hardened_postboot={hp} hardened_transient={ht}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--west-root", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    results = {}
    for variant, timing in CELLS:
        cmd = [sys.executable, str(SCRIPT_DIR / "run_fault_campaign.py"),
               "--variant", variant, "--timing", timing,
               "--jobs", str(args.jobs),
               "--output-dir", str(args.output_dir / f"{variant}-{timing}")]
        if args.west_root:
            cmd += ["--west-root", str(args.west_root)]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              cwd=MODULE_PATH)
        text = proc.stdout + proc.stderr
        for line in text.splitlines():
            if line.startswith(("[fault] EXPLOITABLE", "PQCP_FAULT_CAMPAIGN")):
                print(line, flush=True)
        parsed = parse_marker(text)
        if proc.returncode != 0 or parsed is None:
            print(f"[fault-timing] FAIL: campaign {variant}/{timing} did "
                  "not complete")
            print(text[-1500:])
            return 1
        results[(variant, timing)] = parsed
    problems, marker = judge(results, baseline)
    print(marker)
    for p in problems:
        print(f"[fault-timing] FAIL: {p}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
