#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize a twister run, with failing-suite log tails.

CI job logs and artifacts can be unavailable (storage quota, expired
blobs), which leaves a red twister job undiagnosable. This reads
twister.json plus the per-instance handler/build logs and writes a compact
digest to stdout and, under GitHub Actions, to the job summary, which is
stored independently of both.

Always exits 0: it is a diagnostic, not a gate. The twister step itself
decides pass/fail.
"""

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

TAIL_LINES = 40
MAX_FAILURES_DETAILED = 8


def tail(path: Path, count: int = TAIL_LINES) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[-count:])


def instance_dir(outdir: Path, suite: dict) -> Path | None:
    """Locate outdir/<platform>/<toolchain>/<path>/<scenario>."""
    platform = suite.get("platform", "").replace("/", "_")
    scenario = suite.get("name", "")
    suite_path = Path(suite.get("path", "")).name
    if not scenario:
        return None
    for candidate in outdir.glob(f"**/{scenario}"):
        text = str(candidate)
        if candidate.is_dir() and platform in text and suite_path in text:
            return candidate
    for candidate in outdir.glob(f"**/{scenario}"):
        if candidate.is_dir():
            return candidate
    return None


def summarize(outdir: Path) -> tuple[str, int]:
    report = outdir / "twister.json"
    if not report.exists():
        return (f"twister.json not found under {outdir}; the run likely "
                "died before reporting (runner loss or build crash).\n", 0)

    suites = json.loads(report.read_text(encoding="utf-8"))["testsuites"]
    counts = Counter(s.get("status", "unknown") for s in suites)
    cases = Counter(tc.get("status", "unknown")
                    for s in suites for tc in s.get("testcases", []))
    bad = [s for s in suites
           if s.get("status") not in ("passed", "skipped", "filtered")]

    out = ["### Twister summary", "",
           f"- suites: {dict(counts)}",
           f"- test cases: {dict(cases)}", ""]
    if not bad:
        out.append("All executed suites passed.")
        return "\n".join(out) + "\n", 0

    out.append(f"**{len(bad)} non-passing suite(s):**")
    out.append("")
    for suite in bad:
        reason = suite.get("reason") or "(no reason recorded)"
        out.append(f"- `{suite.get('name')}` "
                   f"({Path(suite.get('path', '')).name}): "
                   f"{suite.get('status')} - {reason}")
    out.append("")

    for suite in bad[:MAX_FAILURES_DETAILED]:
        folder = instance_dir(outdir, suite)
        out.append(f"<details><summary>{suite.get('name')} log tail"
                   "</summary>\n")
        if folder is None:
            out.append("(instance directory not found)\n")
        else:
            for log_name in ("handler.log", "build.log"):
                body = tail(folder / log_name)
                if body:
                    out.append(f"`{log_name}` (last {TAIL_LINES} lines)\n")
                    out.append("```")
                    out.append(body)
                    out.append("```\n")
                    break
        out.append("</details>\n")
    if len(bad) > MAX_FAILURES_DETAILED:
        out.append(f"({len(bad) - MAX_FAILURES_DETAILED} more not shown)")
    return "\n".join(out) + "\n", len(bad)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--outdir", type=Path, required=True)
    args = parser.parse_args()

    text, failures = summarize(args.outdir)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(text)
    print(f"[twister-summary] non_passing={failures}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
