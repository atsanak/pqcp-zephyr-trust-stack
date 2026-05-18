#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Export paper-comparable benchmark rows from local campaign evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REQUIRED_FIELDS = (
    "source_dataset",
    "source_ecosystem",
    "platform_class",
    "environment_type",
    "clock_source",
    "clock_mhz",
    "compiler",
    "toolchain",
    "optimization_flags",
    "backend_family",
    "statistic_type",
)

CSV_FIELDS = (
    "source_dataset",
    "source_ecosystem",
    "platform_class",
    "environment_type",
    "clock_source",
    "clock_mhz",
    "compiler",
    "toolchain",
    "optimization_flags",
    "backend_family",
    "parameter_set",
    "implementation",
    "backend",
    "operation",
    "sample_count",
    "min",
    "median",
    "p90",
    "p99",
    "mad",
    "rom_bytes",
    "ram_bytes",
    "transcript_sha256",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-campaign", type=Path, required=True)
    parser.add_argument("--output-csv", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"{path} root must be a JSON object")
    return raw


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def context_value(context: dict[str, Any], primary: str, fallback: str | None = None) -> str:
    value = context.get(primary)
    if value in (None, "") and fallback:
        value = context.get(fallback)
    return str(value or "")


def is_local_qemu_context(context: dict[str, Any]) -> bool:
    ecosystem = str(context.get("source_ecosystem") or "")
    environment = str(context.get("environment_type") or "")
    board_class = str(context.get("board_class") or context.get("platform_class") or "")
    return ecosystem == "pqcp-zephyr-trust-stack" and (
        environment == "qemu" or board_class == "qemu"
    )


def normalized_context(context: dict[str, Any]) -> dict[str, str]:
    normalized = {
        "source_dataset": context_value(context, "source_dataset"),
        "source_ecosystem": context_value(context, "source_ecosystem"),
        "platform_class": context_value(context, "platform_class", "board_class"),
        "environment_type": context_value(context, "environment_type"),
        "clock_source": context_value(context, "clock_source", "clock_assumption"),
        "clock_mhz": context_value(context, "clock_mhz", "clock_hz"),
        "compiler": context_value(context, "compiler"),
        "toolchain": context_value(context, "toolchain"),
        "optimization_flags": context_value(context, "optimization_flags"),
        "backend_family": context_value(context, "backend_family"),
        "statistic_type": context_value(context, "statistic_type"),
    }
    if not normalized["clock_mhz"] and is_local_qemu_context(context):
        normalized["clock_mhz"] = "not_applicable_qemu"
    return normalized


def cell(value: Any) -> str:
    if value is None:
        return ""
    if value == "":
        return ""
    return str(value)


def build_rows(campaign: dict[str, Any]) -> tuple[list[dict[str, str]], list[str]]:
    failures: list[str] = []
    context = normalized_context(campaign.get("comparison_context") or {})
    for key in REQUIRED_FIELDS:
        if not context.get(key):
            failures.append(f"comparison_context.{key} is required")

    rows: list[dict[str, str]] = []
    for index, stat in enumerate(campaign.get("statistics") or [], start=1):
        if not isinstance(stat, dict):
            failures.append(f"statistics[{index}] must be an object")
            continue
        operation = str(stat.get("operation") or "")
        parameter_set = str(stat.get("parameter_set") or "")
        implementation = str(stat.get("implementation") or "")
        backend = str(stat.get("backend") or "")
        transcript_key = "|".join((parameter_set, implementation, backend, operation, str(stat.get("sample_count") or "")))
        row: dict[str, str] = {
            **context,
            "parameter_set": parameter_set,
            "implementation": implementation,
            "backend": backend,
            "operation": operation,
            "sample_count": cell(stat.get("sample_count")),
            "min": cell(stat.get("min")),
            "median": cell(stat.get("median")),
            "p90": cell(stat.get("p90")),
            "p99": cell(stat.get("p99")),
            "mad": cell(stat.get("mad")),
            "rom_bytes": cell(stat.get("rom_bytes")),
            "ram_bytes": cell(stat.get("ram_bytes")),
            "transcript_sha256": sha256_text(transcript_key),
        }
        for field in ("parameter_set", "operation", "sample_count", "median", "p90", "p99", "mad"):
            if not row[field]:
                failures.append(f"row {index} missing {field}")
        rows.append(row)
    if not rows:
        failures.append("no benchmark statistics available for paper-comparison export")
    return rows, failures


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in CSV_FIELDS})


def main() -> int:
    args = parse_args()
    try:
        campaign = load_json(args.benchmark_campaign.resolve())
        rows, failures = build_rows(campaign)
        write_csv(args.output_csv.resolve(), rows)
        result = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "scripts/run_paper_comparison_campaign.py",
            "passed": not failures and campaign.get("passed") is True,
            "summary": {
                "rows": len(rows),
                "failures": len(failures),
                "source_ecosystem": (campaign.get("comparison_context") or {}).get("source_ecosystem"),
            },
            "csv": str(args.output_csv.resolve()),
            "csv_sha256": sha256_text(args.output_csv.resolve().read_text(encoding="utf-8")),
            "comparison_context": normalized_context(campaign.get("comparison_context") or {}),
            "failures": failures if campaign.get("passed") is True else failures + ["benchmark campaign did not pass"],
        }
    except (OSError, RuntimeError, json.JSONDecodeError) as exc:
        result = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "scripts/run_paper_comparison_campaign.py",
            "passed": False,
            "summary": {"rows": 0, "failures": 1},
            "failures": [str(exc)],
        }
    output_json = args.output_json.resolve()
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: paper-comparison campaign exported")
        print(f"  csv: {args.output_csv.resolve()}")
        print(f"  json: {output_json}")
        return 0
    print("FAIL: paper-comparison campaign export failed", file=sys.stderr)
    for failure in result.get("failures", []):
        print(f"  - {failure}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
