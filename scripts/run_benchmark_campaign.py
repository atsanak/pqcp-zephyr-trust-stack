#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Build benchmark-campaign evidence from local CSV/provenance artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import export_results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parent / "pqc_benchmark_campaign.json")
    parser.add_argument("--benchmark-csv", type=Path, required=True)
    parser.add_argument("--benchmark-provenance", type=Path, required=True)
    parser.add_argument("--external-reference-result", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"{path} root must be a JSON object")
    return raw


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def numeric(value: str | None) -> float | None:
    try:
        parsed = float(value or "")
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def mad(values: list[float]) -> float:
    if not values:
        return 0.0
    med = statistics.median(values)
    return float(statistics.median([abs(value - med) for value in values]))


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((pct / 100.0) * (len(ordered) - 1))))
    return float(ordered[index])


def summarize_rows(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], list[float]] = {}
    for row in rows:
        operation = str(row.get("operation") or "")
        if operation.endswith(("_cycles_min", "_cycles_median", "_cycles_p90", "_cycles_p99", "_cycles_max", "_cycles_mad", "_sample_count")):
            continue
        cycles = numeric(row.get("cycles"))
        if cycles is None:
            continue
        key = (
            str(row.get("parameter_set") or row.get("suite") or ""),
            str(row.get("implementation") or ""),
            operation,
        )
        groups.setdefault(key, []).append(cycles)
    summaries = []
    for (parameter_set, implementation, operation), values in sorted(groups.items()):
        summaries.append(
            {
                "parameter_set": parameter_set,
                "implementation": implementation,
                "operation": operation,
                "sample_count": len(values),
                "min": min(values),
                "median": statistics.median(values),
                "p90": percentile(values, 90),
                "p99": percentile(values, 99),
                "mad": mad(values),
            }
        )
    return summaries


def run(args: argparse.Namespace) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    config = load_json(args.config)
    provenance = load_json(args.benchmark_provenance)
    rows = read_rows(args.benchmark_csv)
    for item in export_results.validate_benchmark_csv(args.benchmark_csv):
        failures.append(f"benchmark CSV [{item['check']}]: {item['message']}")
    for item in export_results.verify_provenance(args.benchmark_csv, args.benchmark_provenance):
        failures.append(f"benchmark provenance [{item['check']}]: {item['message']}")
    context_failures = [
        f"{item['check']}: {item['message']}"
        for item in export_results.validate_comparison_context(provenance.get("comparison_context"))
    ]
    failures.extend(context_failures)
    summaries = summarize_rows(rows)
    if not summaries:
        failures.append("benchmark campaign found no numeric base-operation rows")
    for stat in config.get("required_statistics") or []:
        ok = all(stat in row for row in summaries)
        checks.append({"check": "statistic", "statistic": stat, "passed": ok})
        if not ok:
            failures.append(f"missing required benchmark statistic: {stat}")
    external_reference = None
    if args.external_reference_result:
        external_reference = load_json(args.external_reference_result)
        if external_reference.get("passed") is not True:
            failures.append("external reference result did not pass")
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/run_benchmark_campaign.py",
        "passed": not failures,
        "config": config,
        "comparison_context": provenance.get("comparison_context"),
        "summary": {
            "groups": len(summaries),
            "csv_rows": len(rows),
            "failures": len(failures),
            "comparison_context": provenance.get("comparison_context"),
        },
        "statistics": summaries,
        "external_reference": external_reference,
        "checks": checks,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    result = run(args)
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: benchmark campaign evidence generated")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("FAIL: benchmark campaign evidence failed")
    for failure in result["failures"]:
        print(f"  - {failure}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
