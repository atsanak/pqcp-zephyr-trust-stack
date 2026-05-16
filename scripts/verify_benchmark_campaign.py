#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Replay-check benchmark-campaign evidence."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"{path} root must be a JSON object")
    return raw


def verify(campaign_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    campaign = load_json(campaign_path)
    if campaign.get("schema_version") != 1:
        failures.append(f"unsupported campaign schema_version={campaign.get('schema_version')!r}")
    if campaign.get("passed") is not True:
        failures.append("benchmark campaign result did not pass")
    context = campaign.get("comparison_context")
    required_context = ("source_dataset", "source_ecosystem", "board_class", "statistic_type", "environment_type")
    for key in required_context:
        ok = isinstance(context, dict) and context.get(key) not in (None, "")
        checks.append({"check": "comparison_context", "field": key, "passed": ok})
        if not ok:
            failures.append(f"benchmark campaign comparison_context.{key} is required")
    statistics = campaign.get("statistics")
    if not isinstance(statistics, list) or not statistics:
        failures.append("benchmark campaign must contain non-empty statistics")
    else:
        for index, row in enumerate(statistics, start=1):
            for key in ("min", "median", "p90", "p99", "mad", "sample_count"):
                ok = isinstance(row, dict) and isinstance(row.get(key), (int, float))
                checks.append({"check": "statistic_row", "row": index, "field": key, "passed": ok})
                if not ok:
                    failures.append(f"benchmark campaign row {index} missing numeric {key}")
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": not failures,
        "checks": checks,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    result = verify(args.campaign)
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: benchmark campaign verified")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("FAIL: benchmark campaign verification failed")
    for failure in result["failures"]:
        print(f"  - {failure}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
