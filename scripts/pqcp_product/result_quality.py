#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CSV result quality validation for paper-grade evidence."""

from __future__ import annotations

import csv
import math
from pathlib import Path
from typing import Any

from .errors import Diagnostic, error, warning
from .fs import utc_now, write_json_atomic, write_text_atomic

ALIASES = {
    "algorithm": ("algorithm", "alg", "scheme"),
    "operation": ("operation", "op"),
    "parameter_set": ("parameter_set", "parameter", "level", "param"),
    "implementation": ("implementation", "impl"),
    "board": ("board", "target"),
    "profile": ("profile",),
    "metric": ("metric", "statistic_type"),
    "statistic": ("statistic", "stat"),
    "value": ("value", "median", "median_cycles", "cycles"),
    "unit": ("unit",),
    "source": ("source", "source_url", "source_dataset"),
}
CORE_COMBOS = (
    ("ML-KEM", "keygen"),
    ("ML-KEM", "encaps"),
    ("ML-KEM", "decaps"),
    ("ML-DSA", "keygen"),
    ("ML-DSA", "sign"),
    ("ML-DSA", "verify"),
)
STAT_ORDER = ("min", "median", "p90", "p99", "max")


def validate_result_csvs(
    *,
    csv_paths: list[Path],
    output_root: Path,
    zero_is_fail: bool = False,
    require_core_combos: bool = True,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    diagnostics: list[Diagnostic] = []
    rows: list[dict[str, Any]] = []
    for path in csv_paths:
        rows.extend(_load_csv(path, diagnostics))
    _validate_duplicates(rows, diagnostics)
    _validate_distribution_order(rows, diagnostics)
    if require_core_combos:
        _validate_core_combos(rows, diagnostics)
    status = _status(diagnostics)
    if zero_is_fail:
        _promote_zero_warnings(diagnostics)
        status = _status(diagnostics)
    result = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": status,
        "passed": status != "FAIL",
        "csv_paths": [str(path) for path in csv_paths],
        "row_count": len(rows),
        "normalized_rows": rows,
        "diagnostics": [item.to_dict() for item in diagnostics],
    }
    write_json_atomic(output_root / "result-quality-report.json", result)
    write_text_atomic(output_root / "result-quality-summary.md", render_quality_summary(result))
    return result


def _load_csv(path: Path, diagnostics: list[Diagnostic]) -> list[dict[str, Any]]:
    if not path.exists():
        diagnostics.append(error("quality_csv_missing", str(path), "CSV artifact is missing"))
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            diagnostics.append(error("quality_csv_header", str(path), "CSV has no header"))
            return []
        for row_number, raw in enumerate(reader, start=2):
            normalized = _normalize_row(raw, path, row_number)
            rows.append(normalized)
            _validate_row(normalized, diagnostics)
    return rows


def _normalize_row(raw: dict[str, str], path: Path, row_number: int) -> dict[str, Any]:
    normalized: dict[str, Any] = {"source_file": str(path), "row_number": row_number}
    for field, aliases in ALIASES.items():
        normalized[field] = _first(raw, aliases)
    normalized["algorithm"] = _normalize_algorithm(normalized["algorithm"])
    normalized["operation"] = _normalize_operation(normalized["operation"])
    normalized["statistic"] = _normalize_statistic(normalized)
    normalized["numeric_value"] = _parse_float(normalized["value"])
    return normalized


def _first(raw: dict[str, str], aliases: tuple[str, ...]) -> str:
    for alias in aliases:
        value = raw.get(alias)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _normalize_algorithm(value: str) -> str:
    compact = value.replace("-", "").replace("_", "").replace(" ", "").upper()
    if compact in {"MLKEM", "KYBER"}:
        return "ML-KEM"
    if compact in {"MLDSA", "DILITHIUM"}:
        return "ML-DSA"
    return value


def _normalize_operation(value: str) -> str:
    compact = value.lower().replace("_", "").replace("-", "")
    mapping = {
        "keygen": "keygen",
        "keygeneration": "keygen",
        "encaps": "encaps",
        "encapsulation": "encaps",
        "decaps": "decaps",
        "decapsulation": "decaps",
        "sign": "sign",
        "signature": "sign",
        "siggen": "sign",
        "verify": "verify",
        "verification": "verify",
        "sigver": "verify",
    }
    return mapping.get(compact, value.lower())


def _normalize_statistic(row: dict[str, Any]) -> str:
    stat = str(row.get("statistic", "")).lower()
    metric = str(row.get("metric", "")).lower()
    for candidate in STAT_ORDER:
        if stat == candidate or metric.endswith("_" + candidate) or metric == candidate:
            return candidate
    if not stat:
        return "value"
    return stat


def _parse_float(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float("nan")


def _validate_row(row: dict[str, Any], diagnostics: list[Diagnostic]) -> None:
    loc = f"{row['source_file']}:{row['row_number']}"
    for field in ALIASES:
        if field == "statistic":
            continue
        if row.get(field) in (None, ""):
            diagnostics.append(error("quality_empty_field", f"{loc}:{field}", "required logical field is empty"))
    value = row["numeric_value"]
    if math.isnan(value) or math.isinf(value):
        diagnostics.append(error("quality_bad_number", f"{loc}:value", "metric value is NaN or infinite"))
    elif value < 0:
        diagnostics.append(error("quality_negative_value", f"{loc}:value", "metric value is negative"))
    elif value == 0:
        diagnostics.append(warning("quality_zero_value", f"{loc}:value", "metric value is zero and should be reviewed"))


def _validate_duplicates(rows: list[dict[str, Any]], diagnostics: list[Diagnostic]) -> None:
    seen: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        key = (
            row.get("algorithm"),
            row.get("operation"),
            row.get("parameter_set"),
            row.get("implementation"),
            row.get("board"),
            row.get("profile"),
            row.get("metric"),
            row.get("statistic"),
            row.get("source"),
        )
        if key in seen:
            diagnostics.append(error("quality_duplicate_row", f"{row['source_file']}:{row['row_number']}", "duplicate logical metric row"))
        seen[key] = row


def _validate_distribution_order(rows: list[dict[str, Any]], diagnostics: list[Diagnostic]) -> None:
    grouped: dict[tuple[Any, ...], dict[str, dict[str, Any]]] = {}
    for row in rows:
        stat = row.get("statistic")
        if stat not in STAT_ORDER:
            continue
        key = (
            row.get("algorithm"),
            row.get("operation"),
            row.get("parameter_set"),
            row.get("implementation"),
            row.get("board"),
            row.get("profile"),
            _metric_base(str(row.get("metric", ""))),
        )
        grouped.setdefault(key, {})[stat] = row
    for key, stats in grouped.items():
        previous_name = None
        previous_value = None
        for stat in STAT_ORDER:
            row = stats.get(stat)
            if row is None or math.isnan(row["numeric_value"]):
                continue
            if previous_value is not None and row["numeric_value"] < previous_value:
                diagnostics.append(
                    error(
                        "quality_distribution_order",
                        f"{row['source_file']}:{row['row_number']}",
                        f"{stat} is lower than {previous_name} for {key}",
                    )
                )
            previous_name = stat
            previous_value = row["numeric_value"]


def _metric_base(metric: str) -> str:
    for suffix in STAT_ORDER:
        if metric.endswith("_" + suffix):
            return metric[: -(len(suffix) + 1)]
    return metric


def _validate_core_combos(rows: list[dict[str, Any]], diagnostics: list[Diagnostic]) -> None:
    present = {(row.get("algorithm"), row.get("operation")) for row in rows}
    for combo in CORE_COMBOS:
        if combo not in present:
            diagnostics.append(error("quality_missing_combo", ":".join(combo), "required algorithm-operation combination is missing"))


def _promote_zero_warnings(diagnostics: list[Diagnostic]) -> None:
    for index, diag in enumerate(list(diagnostics)):
        if diag.code == "quality_zero_value" and diag.severity == "warning":
            diagnostics[index] = error(diag.code, diag.location, diag.message, diag.hint)


def _status(diagnostics: list[Diagnostic]) -> str:
    if any(item.is_error for item in diagnostics):
        return "FAIL"
    if any(item.is_warning for item in diagnostics):
        return "WARN"
    return "PASS"


def render_quality_summary(result: dict[str, Any]) -> str:
    lines = ["# Result Quality", "", f"Status: **{result['status']}**", f"Rows checked: {result['row_count']}", ""]
    if result.get("diagnostics"):
        lines.append("## Diagnostics")
        for diag in result["diagnostics"]:
            lines.append(f"- {diag['severity'].upper()} `{diag['code']}` `{diag['location']}`: {diag['message']}")
    return "\n".join(lines).rstrip() + "\n"
