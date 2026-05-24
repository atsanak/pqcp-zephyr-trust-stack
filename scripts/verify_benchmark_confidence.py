#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Replay-check benchmark distribution confidence.

This verifier is intentionally stricter about shape than about performance.
It catches broken or under-sampled benchmark evidence without changing the
existing benchmark wire format or making QEMU numbers look like hardware data.
"""

from __future__ import annotations

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_MIN_DISTRIBUTION_SAMPLES = 5
DEFAULT_MIN_PAPER_SAMPLES = 20
DEFAULT_MAX_TAIL_SPREAD_RATIO = 3.0
DEFAULT_MAX_OUTLIER_SPREAD_RATIO = 5.0
DEFAULT_MAX_ROBUST_NOISE_RATIO = 0.25


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--min-distribution-samples", type=int, default=DEFAULT_MIN_DISTRIBUTION_SAMPLES)
    parser.add_argument("--min-paper-samples", type=int, default=DEFAULT_MIN_PAPER_SAMPLES)
    parser.add_argument("--max-tail-spread-ratio", type=float, default=DEFAULT_MAX_TAIL_SPREAD_RATIO)
    parser.add_argument("--max-outlier-spread-ratio", type=float, default=DEFAULT_MAX_OUTLIER_SPREAD_RATIO)
    parser.add_argument("--max-robust-noise-ratio", type=float, default=DEFAULT_MAX_ROBUST_NOISE_RATIO)
    parser.add_argument(
        "--require-paper-comparable",
        action="store_true",
        help="Fail if any benchmark row is coherent but under-sampled for paper-style comparison.",
    )
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"{path} root must be a JSON object")
    return raw


def finite_number(value: Any) -> float | None:
    if not isinstance(value, (int, float)):
        return None
    parsed = float(value)
    if not math.isfinite(parsed):
        return None
    return parsed


def positive_int(value: Any) -> int | None:
    if not isinstance(value, int):
        return None
    return value if value > 0 else None


def confidence_tier(sample_count: int, min_distribution_samples: int, min_paper_samples: int) -> str:
    if sample_count <= 1:
        return "single_observation"
    if sample_count < min_distribution_samples:
        return "low"
    if sample_count < min_paper_samples:
        return "distribution"
    return "paper_comparable"


def assess_statistic_row(
    row: dict[str, Any],
    *,
    index: int,
    min_distribution_samples: int,
    min_paper_samples: int,
    max_tail_spread_ratio: float,
    max_outlier_spread_ratio: float,
    max_robust_noise_ratio: float,
    require_paper_comparable: bool,
) -> tuple[dict[str, Any], list[str], list[str]]:
    failures: list[str] = []
    warnings: list[str] = []
    numeric: dict[str, float] = {}
    for field in ("min", "median", "p90", "p99", "max", "mad"):
        value = finite_number(row.get(field))
        if value is None or value < 0.0:
            failures.append(f"row {index} has invalid {field}")
            value = 0.0
        numeric[field] = value
    sample_count = positive_int(row.get("sample_count"))
    if sample_count is None:
        failures.append(f"row {index} has invalid sample_count")
        sample_count = 0
    if not failures:
        if numeric["min"] > numeric["median"]:
            failures.append(f"row {index} violates min <= median")
        if numeric["median"] > numeric["p90"]:
            failures.append(f"row {index} violates median <= p90")
        if numeric["p90"] > numeric["p99"]:
            failures.append(f"row {index} violates p90 <= p99")
        if numeric["p99"] > numeric["max"]:
            failures.append(f"row {index} violates p99 <= max")
    median = numeric["median"]
    tail_spread_ratio = numeric["p99"] / median if median > 0.0 else None
    outlier_spread_ratio = numeric["max"] / median if median > 0.0 else None
    robust_noise_ratio = numeric["mad"] / median if median > 0.0 else None
    tier = confidence_tier(sample_count, min_distribution_samples, min_paper_samples)
    paper_comparable = (
        tier == "paper_comparable"
        and tail_spread_ratio is not None
        and tail_spread_ratio <= max_tail_spread_ratio
        and outlier_spread_ratio is not None
        and outlier_spread_ratio <= max_outlier_spread_ratio
        and robust_noise_ratio is not None
        and robust_noise_ratio <= max_robust_noise_ratio
    )
    label = f"{row.get('parameter_set', '')}/{row.get('implementation', '')}/{row.get('operation', '')}"
    if sample_count == 1:
        warnings.append(f"{label}: single observation; usable for regression smoke, not paper comparison")
    elif sample_count < min_distribution_samples:
        warnings.append(f"{label}: fewer than {min_distribution_samples} samples")
    if tail_spread_ratio is not None and tail_spread_ratio > max_tail_spread_ratio:
        warnings.append(f"{label}: p99/median tail spread {tail_spread_ratio:.3f} exceeds {max_tail_spread_ratio:.3f}")
    if outlier_spread_ratio is not None and outlier_spread_ratio > max_outlier_spread_ratio:
        warnings.append(
            f"{label}: max/median outlier spread {outlier_spread_ratio:.3f} exceeds {max_outlier_spread_ratio:.3f}"
        )
    if robust_noise_ratio is not None and robust_noise_ratio > max_robust_noise_ratio:
        warnings.append(f"{label}: MAD/median noise {robust_noise_ratio:.3f} exceeds {max_robust_noise_ratio:.3f}")
    if require_paper_comparable and not paper_comparable:
        failures.append(f"row {index} is not paper-comparable under the configured thresholds")
    assessment = {
        "row": index,
        "parameter_set": row.get("parameter_set", ""),
        "implementation": row.get("implementation", ""),
        "backend": row.get("backend", ""),
        "operation": row.get("operation", ""),
        "sample_count": sample_count,
        "confidence_tier": tier,
        "paper_comparable": paper_comparable,
        "tail_spread_ratio": tail_spread_ratio,
        "outlier_spread_ratio": outlier_spread_ratio,
        "robust_noise_ratio": robust_noise_ratio,
    }
    return assessment, failures, warnings


def verify_pairwise_rows(pairwise: Any) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    checks: list[dict[str, Any]] = []
    failures: list[str] = []
    warnings: list[str] = []
    if pairwise is None:
        return checks, failures, warnings
    if not isinstance(pairwise, list):
        return checks, ["pairwise_ratios must be a list"], warnings
    for index, row in enumerate(pairwise, start=1):
        if not isinstance(row, dict):
            failures.append(f"pairwise row {index} is not an object")
            continue
        candidate_samples = positive_int(row.get("candidate_sample_count"))
        baseline_samples = positive_int(row.get("baseline_sample_count"))
        ratio = row.get("ratio")
        ratio_ok = ratio is None or finite_number(ratio) is not None
        if not ratio_ok:
            failures.append(f"pairwise row {index} has invalid ratio")
        balanced_samples = candidate_samples is not None and baseline_samples is not None and candidate_samples == baseline_samples
        if not balanced_samples:
            failures.append(f"pairwise row {index} has missing or mismatched sample counts")
        if candidate_samples == 1 and baseline_samples == 1:
            warnings.append(f"pairwise row {index} compares single-observation medians")
        checks.append(
            {
                "check": "pairwise_sample_balance",
                "row": index,
                "candidate_sample_count": candidate_samples,
                "baseline_sample_count": baseline_samples,
                "passed": balanced_samples,
            }
        )
    return checks, failures, warnings


def verify(
    campaign_path: Path,
    *,
    min_distribution_samples: int = DEFAULT_MIN_DISTRIBUTION_SAMPLES,
    min_paper_samples: int = DEFAULT_MIN_PAPER_SAMPLES,
    max_tail_spread_ratio: float = DEFAULT_MAX_TAIL_SPREAD_RATIO,
    max_outlier_spread_ratio: float = DEFAULT_MAX_OUTLIER_SPREAD_RATIO,
    max_robust_noise_ratio: float = DEFAULT_MAX_ROBUST_NOISE_RATIO,
    require_paper_comparable: bool = False,
) -> dict[str, Any]:
    failures: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, Any]] = []
    row_assessments: list[dict[str, Any]] = []
    campaign = load_json(campaign_path)
    if campaign.get("schema_version") != 1:
        failures.append(f"unsupported campaign schema_version={campaign.get('schema_version')!r}")
    if campaign.get("passed") is not True:
        failures.append("benchmark campaign result did not pass")
    statistics = campaign.get("statistics")
    if not isinstance(statistics, list) or not statistics:
        failures.append("benchmark campaign must contain non-empty statistics")
    else:
        for index, row in enumerate(statistics, start=1):
            if not isinstance(row, dict):
                failures.append(f"row {index} is not an object")
                continue
            assessment, row_failures, row_warnings = assess_statistic_row(
                row,
                index=index,
                min_distribution_samples=min_distribution_samples,
                min_paper_samples=min_paper_samples,
                max_tail_spread_ratio=max_tail_spread_ratio,
                max_outlier_spread_ratio=max_outlier_spread_ratio,
                max_robust_noise_ratio=max_robust_noise_ratio,
                require_paper_comparable=require_paper_comparable,
            )
            row_assessments.append(assessment)
            failures.extend(row_failures)
            warnings.extend(row_warnings)
    pairwise_checks, pairwise_failures, pairwise_warnings = verify_pairwise_rows(campaign.get("pairwise_ratios"))
    checks.extend(pairwise_checks)
    failures.extend(pairwise_failures)
    warnings.extend(pairwise_warnings)
    paper_rows = [row for row in row_assessments if row["paper_comparable"]]
    single_rows = [row for row in row_assessments if row["confidence_tier"] == "single_observation"]
    tail_values = [
        float(row["tail_spread_ratio"])
        for row in row_assessments
        if isinstance(row.get("tail_spread_ratio"), (int, float))
    ]
    noise_values = [
        float(row["robust_noise_ratio"])
        for row in row_assessments
        if isinstance(row.get("robust_noise_ratio"), (int, float))
    ]
    outlier_values = [
        float(row["outlier_spread_ratio"])
        for row in row_assessments
        if isinstance(row.get("outlier_spread_ratio"), (int, float))
    ]
    checks.append(
        {
            "check": "benchmark_confidence_rows",
            "row_count": len(row_assessments),
            "paper_comparable_rows": len(paper_rows),
            "passed": bool(row_assessments),
        }
    )
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": not failures,
        "thresholds": {
            "min_distribution_samples": min_distribution_samples,
            "min_paper_samples": min_paper_samples,
            "max_tail_spread_ratio": max_tail_spread_ratio,
            "max_outlier_spread_ratio": max_outlier_spread_ratio,
            "max_robust_noise_ratio": max_robust_noise_ratio,
            "require_paper_comparable": require_paper_comparable,
        },
        "summary": {
            "row_count": len(row_assessments),
            "paper_comparable_rows": len(paper_rows),
            "single_observation_rows": len(single_rows),
            "max_tail_spread_ratio": max(tail_values) if tail_values else None,
            "max_outlier_spread_ratio": max(outlier_values) if outlier_values else None,
            "max_robust_noise_ratio": max(noise_values) if noise_values else None,
        },
        "row_assessments": row_assessments,
        "checks": checks,
        "warnings": warnings,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    result = verify(
        args.campaign,
        min_distribution_samples=args.min_distribution_samples,
        min_paper_samples=args.min_paper_samples,
        max_tail_spread_ratio=args.max_tail_spread_ratio,
        max_outlier_spread_ratio=args.max_outlier_spread_ratio,
        max_robust_noise_ratio=args.max_robust_noise_ratio,
        require_paper_comparable=args.require_paper_comparable,
    )
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: benchmark confidence replay passed")
        print(f"  paper-comparable rows: {result['summary']['paper_comparable_rows']}/{result['summary']['row_count']}")
        if result["warnings"]:
            print(f"  warnings: {len(result['warnings'])}")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("FAIL: benchmark confidence replay failed")
    for failure in result["failures"]:
        print(f"  - {failure}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
