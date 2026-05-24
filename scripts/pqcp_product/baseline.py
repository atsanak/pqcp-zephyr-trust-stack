#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Benchmark baseline CSV loading and regression comparison."""

from __future__ import annotations

import csv
import math
from pathlib import Path
from statistics import median

from .errors import BaselineComparisonError, Diagnostic, error, warning
from .fs import utc_now, write_json_atomic, write_text_atomic
from .models import BaselineComparisonReport, BaselineRow, ComparisonResult

REQUIRED_LOGICAL_FIELDS = ("algorithm", "operation", "parameter_set", "implementation", "board", "profile", "metric", "value")


def load_baseline_csv(path: Path) -> tuple[list[BaselineRow], tuple[Diagnostic, ...]]:
    diagnostics: list[Diagnostic] = []
    if not path.exists():
        raise BaselineComparisonError(f"missing CSV: {path}")
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            diagnostics.append(error("csv_header", str(path), "CSV has no header"))
            return [], tuple(diagnostics)
        rows = []
        for row_number, raw in enumerate(reader, start=2):
            row = BaselineRow.from_dict(dict(raw), row_number)
            rows.append(row)
            diagnostics.extend(validate_row(row, path))
    return rows, tuple(diagnostics)


def validate_row(row: BaselineRow, path: Path) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    location = f"{path}:{row.row_number}"
    if not row.algorithm:
        diagnostics.append(error("csv_algorithm", location, "missing algorithm"))
    if not row.operation:
        diagnostics.append(error("csv_operation", location, "missing operation"))
    if not row.parameter_set:
        diagnostics.append(error("csv_parameter", location, "missing parameter set"))
    if not row.implementation:
        diagnostics.append(error("csv_implementation", location, "missing implementation"))
    if not row.board:
        diagnostics.append(error("csv_board", location, "missing board"))
    if not row.profile:
        diagnostics.append(warning("csv_profile", location, "missing profile; comparison may be too broad"))
    if not row.metric:
        diagnostics.append(error("csv_metric", location, "missing metric"))
    if math.isnan(row.value):
        diagnostics.append(error("csv_value", location, "value is not numeric"))
    if row.value < 0:
        diagnostics.append(error("csv_negative_value", location, "value must be non-negative"))
    if not row.unit:
        diagnostics.append(warning("csv_unit", location, "unit is missing"))
    if not row.source:
        diagnostics.append(warning("csv_source", location, "source/provenance field is missing"))
    return diagnostics


def index_rows(rows: list[BaselineRow]) -> dict[tuple[str, ...], BaselineRow]:
    index: dict[tuple[str, ...], BaselineRow] = {}
    for row in rows:
        key = row.comparison_key()
        previous = index.get(key)
        if previous is None or row.statistic == "median":
            index[key] = row
    return index


def compare_csvs(
    *,
    candidate_csv: Path,
    baseline_csv: Path,
    threshold: float = 1.05,
    output_root: Path | None = None,
) -> BaselineComparisonReport:
    candidate_rows, candidate_diags = load_baseline_csv(candidate_csv)
    baseline_rows, baseline_diags = load_baseline_csv(baseline_csv)
    diagnostics: list[Diagnostic] = list(candidate_diags) + list(baseline_diags)
    candidate_index = index_rows(candidate_rows)
    baseline_index = index_rows(baseline_rows)
    results: list[ComparisonResult] = []
    all_keys = sorted(set(candidate_index) | set(baseline_index))
    for key in all_keys:
        candidate = candidate_index.get(key)
        baseline = baseline_index.get(key)
        if candidate is None:
            diag = error("candidate_missing_pair", ":".join(key), "candidate row is missing for baseline key")
            diagnostics.append(diag)
            results.append(ComparisonResult(key, None, baseline, None, "missing_candidate", threshold, (diag,)))
            continue
        if baseline is None:
            diag = error("baseline_missing_pair", ":".join(key), "baseline row is missing for candidate key")
            diagnostics.append(diag)
            results.append(ComparisonResult(key, candidate, None, None, "missing_baseline", threshold, (diag,)))
            continue
        ratio = candidate.value / baseline.value if baseline.value not in (0, 0.0) else None
        if ratio is None:
            diag = error("baseline_zero", ":".join(key), "baseline value is zero, ratio cannot be computed")
            diagnostics.append(diag)
            results.append(ComparisonResult(key, candidate, baseline, None, "invalid", threshold, (diag,)))
        elif ratio > threshold:
            diag = error("regression_detected", ":".join(key), f"candidate/baseline ratio {ratio:.4f} exceeds {threshold:.4f}")
            diagnostics.append(diag)
            results.append(ComparisonResult(key, candidate, baseline, ratio, "regression", threshold, (diag,)))
        else:
            results.append(ComparisonResult(key, candidate, baseline, ratio, "pass", threshold, ()))
    report = BaselineComparisonReport(
        schema_version=1,
        generated_at=utc_now(),
        candidate_csv=str(candidate_csv),
        baseline_csv=str(baseline_csv),
        threshold=threshold,
        results=tuple(results),
        diagnostics=tuple(diagnostics),
    )
    if output_root:
        output_root.mkdir(parents=True, exist_ok=True)
        write_json_atomic(output_root / "baseline-comparison.json", report.to_dict())
        write_text_atomic(output_root / "baseline-comparison.csv", comparison_csv_text(report))
    return report


def comparison_csv_text(report: BaselineComparisonReport) -> str:
    lines = ["algorithm,operation,parameter_set,board,profile,metric,candidate,baseline,ratio,status,threshold"]
    for result in report.results:
        key = list(result.key)
        candidate = "" if result.candidate is None else f"{result.candidate.value:g}"
        baseline = "" if result.baseline is None else f"{result.baseline.value:g}"
        ratio = "" if result.ratio is None else f"{result.ratio:.8f}"
        safe_key = [item.replace(",", " ") for item in key]
        lines.append(",".join([*safe_key, candidate, baseline, ratio, result.status, f"{result.threshold:g}"]))
    return "\n".join(lines) + "\n"


def summarize_metric_family(rows: list[BaselineRow]) -> dict[str, dict[str, float]]:
    grouped: dict[str, list[float]] = {}
    for row in rows:
        if math.isnan(row.value):
            continue
        family = f"{row.algorithm}:{row.operation}:{row.metric}"
        grouped.setdefault(family, []).append(row.value)
    summary: dict[str, dict[str, float]] = {}
    for family, values in grouped.items():
        values_sorted = sorted(values)
        summary[family] = {
            "count": float(len(values)),
            "min": values_sorted[0],
            "median": median(values_sorted),
            "max": values_sorted[-1],
        }
    return summary
