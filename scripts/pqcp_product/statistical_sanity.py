#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Statistical sanity checks for benchmark/result CSV evidence."""

from __future__ import annotations

import math
import statistics
from pathlib import Path
from typing import Any

from .errors import Diagnostic, warning
from .fs import utc_now, write_json_atomic, write_text_atomic
from .result_quality import validate_result_csvs


def analyze_statistics(
    *,
    csv_paths: list[Path],
    output_root: Path,
    min_samples: int = 3,
    cv_warn_threshold: float = 0.10,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    quality = validate_result_csvs(
        csv_paths=csv_paths,
        output_root=output_root / "_quality_for_statistics",
        require_core_combos=False,
    )
    diagnostics: list[Diagnostic] = []
    groups = _group_rows(quality["normalized_rows"])
    summaries: list[dict[str, Any]] = []
    for key, values in sorted(groups.items()):
        summary = _summary_for_group(key, values, min_samples=min_samples, cv_warn_threshold=cv_warn_threshold)
        summaries.append(summary)
        if summary["rerun_required"]:
            diagnostics.append(warning("stats_rerun_required", "|".join(key), "sample count is below minimum"))
        if summary["high_variance"]:
            diagnostics.append(warning("stats_high_variance", "|".join(key), "coefficient of variation exceeds threshold"))
        if summary["outlier_count"] > 0:
            diagnostics.append(warning("stats_outliers", "|".join(key), "IQR outliers detected"))
    status = "WARN" if diagnostics or quality["status"] != "PASS" else "PASS"
    if quality["status"] == "FAIL":
        status = "FAIL"
    result = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": status,
        "passed": status != "FAIL",
        "csv_paths": [str(path) for path in csv_paths],
        "group_count": len(summaries),
        "groups": summaries,
        "quality_status": quality["status"],
        "diagnostics": [item.to_dict() for item in diagnostics],
    }
    write_json_atomic(output_root / "statistical-sanity-report.json", result)
    write_text_atomic(output_root / "statistical-sanity-summary.md", render_statistics_summary(result))
    return result


def _group_rows(rows: list[dict[str, Any]]) -> dict[tuple[str, ...], list[float]]:
    groups: dict[tuple[str, ...], list[float]] = {}
    for row in rows:
        value = row.get("numeric_value")
        if not isinstance(value, (int, float)) or math.isnan(value) or math.isinf(value):
            continue
        key = (
            str(row.get("algorithm", "")),
            str(row.get("operation", "")),
            str(row.get("parameter_set", "")),
            str(row.get("implementation", "")),
            str(row.get("board", "")),
            str(row.get("profile", "")),
            str(row.get("metric", "")),
            str(row.get("unit", "")),
        )
        groups.setdefault(key, []).append(float(value))
    return groups


def _summary_for_group(
    key: tuple[str, ...],
    values: list[float],
    *,
    min_samples: int,
    cv_warn_threshold: float,
) -> dict[str, Any]:
    ordered = sorted(values)
    count = len(ordered)
    mean = statistics.fmean(ordered) if ordered else 0.0
    median = statistics.median(ordered) if ordered else 0.0
    stddev = statistics.stdev(ordered) if count >= 2 else 0.0
    cv = stddev / mean if mean else 0.0
    q1, q3 = _quartiles(ordered)
    iqr = q3 - q1
    lower = q1 - 1.5 * iqr
    upper = q3 + 1.5 * iqr
    outliers = [value for value in ordered if value < lower or value > upper] if count >= 4 else []
    return {
        "key": list(key),
        "count": count,
        "min": ordered[0] if ordered else None,
        "max": ordered[-1] if ordered else None,
        "mean": mean,
        "median": median,
        "stddev": stddev,
        "coefficient_of_variation": cv,
        "q1": q1,
        "q3": q3,
        "outlier_count": len(outliers),
        "rerun_required": count < min_samples,
        "high_variance": cv > cv_warn_threshold,
    }


def _quartiles(ordered: list[float]) -> tuple[float, float]:
    if not ordered:
        return 0.0, 0.0
    if len(ordered) == 1:
        return ordered[0], ordered[0]
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        lower = ordered[:midpoint]
        upper = ordered[midpoint + 1 :]
    else:
        lower = ordered[:midpoint]
        upper = ordered[midpoint:]
    return statistics.median(lower), statistics.median(upper)


def render_statistics_summary(result: dict[str, Any]) -> str:
    lines = [
        "# Statistical Sanity",
        "",
        f"Status: **{result['status']}**",
        f"Groups checked: {result['group_count']}",
        "",
        "| Metric Group | Count | Mean | Median | CV | Rerun |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for group in result.get("groups", []):
        key = ":".join(group["key"])
        lines.append(
            f"| `{key}` | {group['count']} | {group['mean']:.6g} | {group['median']:.6g} | "
            f"{group['coefficient_of_variation']:.6g} | {group['rerun_required']} |"
        )
    if result.get("diagnostics"):
        lines.extend(["", "## Diagnostics"])
        for diag in result["diagnostics"]:
            lines.append(f"- {diag['severity'].upper()} `{diag['code']}` `{diag['location']}`: {diag['message']}")
    return "\n".join(lines).rstrip() + "\n"
