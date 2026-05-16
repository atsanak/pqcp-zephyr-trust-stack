#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Promote CT sample analysis into a campaign-level replay artifact."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--min-algorithms", type=int, default=3)
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"{path} root must be a JSON object")
    return raw


def verify_indexes(indexes: list[Any]) -> bool:
    ints = [int(item) for item in indexes]
    return len(ints) == len(set(ints)) and sorted(ints) == list(range(len(ints)))


def run(args: argparse.Namespace) -> dict[str, Any]:
    analysis = load_json(args.analysis)
    manifest = load_json(args.manifest)
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    if analysis.get("passed") is not True:
        failures.append("CT sample analysis did not pass")
    if manifest.get("schema_version") != 1:
        failures.append(f"unsupported CT sample manifest schema_version={manifest.get('schema_version')!r}")
    algorithms = manifest.get("algorithms")
    if not isinstance(algorithms, list) or len(algorithms) < args.min_algorithms:
        failures.append(f"CT campaign requires at least {args.min_algorithms} algorithms")
        algorithms = algorithms if isinstance(algorithms, list) else []
    analysis_by_alg = {
        row.get("algorithm"): row
        for row in analysis.get("algorithms") or []
        if isinstance(row, dict)
    }
    campaign_rows: list[dict[str, Any]] = []
    for row in algorithms:
        if not isinstance(row, dict):
            failures.append("CT sample manifest algorithm row must be an object")
            continue
        alg = row.get("algorithm")
        valid_indexes = row.get("valid_indexes") or []
        invalid_indexes = row.get("invalid_indexes") or []
        counts_match = row.get("valid_count") == row.get("invalid_count")
        valid_contiguous = verify_indexes(valid_indexes)
        invalid_contiguous = verify_indexes(invalid_indexes)
        has_analysis = alg in analysis_by_alg
        passed = counts_match and valid_contiguous and invalid_contiguous and has_analysis and row.get("passed") is True
        checks.append({"check": "ct_campaign_algorithm", "algorithm": alg, "passed": passed})
        if not counts_match:
            failures.append(f"{alg} valid/invalid CT sample counts differ")
        if not valid_contiguous:
            failures.append(f"{alg} valid CT sample indexes are not contiguous")
        if not invalid_contiguous:
            failures.append(f"{alg} invalid CT sample indexes are not contiguous")
        if not has_analysis:
            failures.append(f"{alg} missing from CT sample analysis")
        campaign_rows.append(
            {
                "algorithm": alg,
                "valid_count": row.get("valid_count"),
                "invalid_count": row.get("invalid_count"),
                "valid_contiguous": valid_contiguous,
                "invalid_contiguous": invalid_contiguous,
                "passed": passed,
            }
        )
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/run_ct_campaign.py",
        "passed": not failures,
        "summary": {"algorithms": len(campaign_rows), "failures": len(failures)},
        "algorithms": campaign_rows,
        "checks": checks,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    result = run(args)
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: CT campaign evidence generated")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("FAIL: CT campaign evidence failed")
    for failure in result["failures"]:
        print(f"  - {failure}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
