#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build benchmark-campaign evidence from local CSV/provenance artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import math
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
    groups: dict[tuple[str, str, str, str], list[float]] = {}
    resources: dict[tuple[str, str, str, str], dict[str, list[float]]] = {}
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
            str(row.get("backend") or ""),
            operation,
        )
        groups.setdefault(key, []).append(cycles)
        for field in ("rom_bytes", "ram_bytes"):
            value = numeric(row.get(field))
            if value is not None:
                resources.setdefault(key, {}).setdefault(field, []).append(value)
    summaries = []
    for (parameter_set, implementation, backend, operation), values in sorted(groups.items()):
        row: dict[str, Any] = {
            "parameter_set": parameter_set,
            "implementation": implementation,
            "backend": backend,
            "operation": operation,
            "sample_count": len(values),
            "min": min(values),
            "median": statistics.median(values),
            "p90": percentile(values, 90),
            "p99": percentile(values, 99),
            "max": max(values),
            "mad": mad(values),
        }
        for field, field_values in resources.get((parameter_set, implementation, backend, operation), {}).items():
            if field_values:
                row[field] = max(field_values)
        summaries.append(row)
    return summaries


def geomean(values: list[float]) -> float | None:
    positive = [value for value in values if value > 0.0 and math.isfinite(value)]
    if not positive:
        return None
    return math.exp(sum(math.log(value) for value in positive) / len(positive))


def build_pairwise_ratios(summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_group: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in summaries:
        key = (
            str(row.get("parameter_set") or ""),
            str(row.get("operation") or ""),
            str(row.get("implementation") or ""),
        )
        by_group.setdefault(key, []).append(row)
    ratios: list[dict[str, Any]] = []
    keys = sorted({(key[0], key[1]) for key in by_group})
    for parameter_set, operation in keys:
        candidate = select_backend_row(by_group.get((parameter_set, operation, "pqcp"), []), preferred_backend="auto")
        baseline = select_backend_row(by_group.get((parameter_set, operation, "baseline"), []), preferred_backend="clean")
        if candidate is None or baseline is None:
            continue
        candidate_median = float(candidate.get("median") or 0.0)
        baseline_median = float(baseline.get("median") or 0.0)
        ratio = candidate_median / baseline_median if baseline_median > 0.0 else None
        ratios.append(
            {
                "parameter_set": parameter_set,
                "operation": operation,
                "candidate_implementation": "pqcp",
                "baseline_implementation": "baseline",
                "candidate_backend": candidate.get("backend") or "",
                "baseline_backend": baseline.get("backend") or "",
                "candidate_median_cycles": candidate_median,
                "baseline_median_cycles": baseline_median,
                "ratio": ratio,
                "candidate_sample_count": candidate.get("sample_count", 0),
                "baseline_sample_count": baseline.get("sample_count", 0),
            }
        )
    return ratios


def select_backend_row(rows: list[dict[str, Any]], *, preferred_backend: str) -> dict[str, Any] | None:
    if not rows:
        return None
    for row in rows:
        if str(row.get("backend") or "") == preferred_backend:
            return row
    for row in rows:
        if str(row.get("backend") or "") in ("", "auto", "clean"):
            return row
    return sorted(rows, key=lambda row: str(row.get("backend") or ""))[0]


def build_backend_rankings(summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_target: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in summaries:
        if str(row.get("implementation") or "") != "pqcp":
            continue
        backend = str(row.get("backend") or "")
        if not backend:
            continue
        key = (str(row.get("parameter_set") or ""), str(row.get("operation") or ""))
        by_target.setdefault(key, []).append(row)
    rankings: list[dict[str, Any]] = []
    for (parameter_set, operation), rows in sorted(by_target.items()):
        unique: dict[str, dict[str, Any]] = {
            str(row.get("backend") or ""): row
            for row in rows
        }
        if len(unique) < 2:
            continue
        ordered = sorted(
            unique.values(),
            key=lambda row: (
                float(row.get("median") or math.inf),
                str(row.get("backend") or ""),
            ),
        )
        fastest = ordered[0]
        auto = unique.get("auto")
        rankings.append(
            {
                "parameter_set": parameter_set,
                "operation": operation,
                "fastest_backend": fastest.get("backend"),
                "fastest_median_cycles": fastest.get("median"),
                "auto_median_cycles": auto.get("median") if auto else None,
                "auto_is_fastest": bool(auto and auto.get("backend") == fastest.get("backend")),
                "candidates": [
                    {
                        "backend": row.get("backend"),
                        "median_cycles": row.get("median"),
                        "sample_count": row.get("sample_count"),
                    }
                    for row in ordered
                ],
            }
        )
    return rankings


def comparison_summary(ratios: list[dict[str, Any]]) -> dict[str, Any]:
    numeric_ratios = [
        float(row["ratio"])
        for row in ratios
        if isinstance(row.get("ratio"), (int, float))
    ]
    better = sum(1 for value in numeric_ratios if value < 1.0)
    same_or_slower = sum(1 for value in numeric_ratios if value >= 1.0)
    return {
        "comparison_count": len(ratios),
        "numeric_ratio_count": len(numeric_ratios),
        "pqcp_faster_count": better,
        "pqcp_same_or_slower_count": same_or_slower,
        "geomean_ratio": geomean(numeric_ratios),
        "best_ratio": min(numeric_ratios) if numeric_ratios else None,
        "worst_ratio": max(numeric_ratios) if numeric_ratios else None,
    }


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
    ratios = build_pairwise_ratios(summaries)
    ratio_summary = comparison_summary(ratios)
    backend_rankings = build_backend_rankings(summaries)
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
            "pairwise_comparisons": ratio_summary,
            "backend_selection": {
                "ranking_count": len(backend_rankings),
                "auto_not_fastest_count": sum(1 for row in backend_rankings if not row.get("auto_is_fastest")),
            },
        },
        "statistics": summaries,
        "pairwise_ratios": ratios,
        "backend_rankings": backend_rankings,
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
