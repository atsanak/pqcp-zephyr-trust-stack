#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Summarize cost-of-assurance benchmark runs into comparison-friendly CSVs.

This helper consumes the JSON artifacts written by scripts/run_benchmarks.py
and emits:
  - one build/resource row per run,
  - one primitive row per algorithm/level,
  - one protocol row per TLS suite block.

The schema already distinguishes implementation identity from backend policy so
future non-PQCP providers can be added without a disruptive format change.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize cost-of-assurance benchmark artifacts"
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        required=True,
        help="Benchmark output directory produced by scripts/run_benchmarks.py",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Directory for the summarized CSV outputs (defaults to --input-dir)",
    )
    return parser.parse_args()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def normalize_value(value: Any) -> Any:
    if isinstance(value, (int, float)):
        return value
    if not isinstance(value, str):
        return value

    stripped = value.strip()
    if stripped == "":
        return ""

    try:
        return int(stripped)
    except ValueError:
        try:
            return float(stripped)
        except ValueError:
            return stripped


def write_csv(rows: List[Dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        output_path.write_text("")
        return

    preferred = [
        "run_id",
        "board",
        "profile",
        "sample",
        "implementation",
        "backend",
        "run_mode",
        "component",
        "algorithm",
        "level",
        "suite_index",
        "suite",
        "suite_mode",
        "auth_algorithm",
        "auth_level",
        "key_exchange_algorithm",
        "key_exchange_level",
        "rom_bytes",
        "ram_bytes",
        "handshake_time",
        "handshake_time_unit",
        "handshake_provider_overhead",
        "handshake_provider_overhead_unit",
        "auth_time",
        "auth_time_unit",
        "key_exchange_time",
        "key_exchange_time_unit",
        "handshake_certificate_bytes",
        "handshake_certificate_bytes_unit",
        "handshake_key_exchange_bytes",
        "handshake_key_exchange_bytes_unit",
        "handshake_transport_overhead_bytes",
        "handshake_transport_overhead_bytes_unit",
        "handshake_rtos_isr_count",
        "handshake_rtos_isr_count_unit",
        "handshake_rtos_yield_count",
        "handshake_rtos_yield_count_unit",
        "handshake_rtos_jitter_p50",
        "handshake_rtos_jitter_p50_unit",
        "handshake_rtos_jitter_p90",
        "handshake_rtos_jitter_p90_unit",
        "handshake_rtos_jitter_p99",
        "handshake_rtos_jitter_p99_unit",
    ]
    seen = set(preferred)
    extra = sorted({key for row in rows for key in row.keys() if key not in seen})
    fieldnames = [key for key in preferred if any(key in row for row in rows)] + extra

    with output_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def load_inputs(input_dir: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    metrics = load_json(input_dir / "consolidated_metrics.json")
    runs = {
        entry["run_id"]: entry
        for entry in load_json(input_dir / "runs.json")
    }
    return metrics, runs


def collect_build_metrics(
    metrics: Iterable[Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    build_metrics: Dict[str, Dict[str, Any]] = {}
    for row in metrics:
        if row.get("component") != "build":
            continue
        run_id = row["run_id"]
        build_metrics.setdefault(run_id, {})[row["metric"]] = normalize_value(row["value"])
    return build_metrics


def base_row(run: Dict[str, Any], component: str) -> Dict[str, Any]:
    run_mode = run.get("run_mode")
    if not run_mode:
        run_mode = "build_only" if run.get("build_only") else "run"
    return {
        "run_id": run["run_id"],
        "board": run["board"],
        "profile": run["profile"],
        "sample": run["sample"],
        "implementation": run.get("implementation", "pqcp"),
        "backend": run.get("backend", "auto"),
        "run_mode": run_mode,
        "component": component,
    }


def summarize_builds(
    runs: Dict[str, Dict[str, Any]],
    build_metrics: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for run_id, run in runs.items():
        row = {
            **base_row(run, "build"),
            "build_ok": run.get("build_ok"),
            "run_ok": run.get("run_ok"),
            "timed_out": run.get("timed_out"),
        }
        row.update(build_metrics.get(run_id, {}))
        rows.append(row)

    return sorted(
        rows,
        key=lambda item: (
            item["board"],
            item["profile"],
            item["sample"],
            item["implementation"],
            item["backend"],
            item["run_id"],
        ),
    )


def summarize_primitives(
    metrics: List[Dict[str, Any]],
    runs: Dict[str, Dict[str, Any]],
    build_metrics: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    rows: Dict[Tuple[str, str, int], Dict[str, Any]] = {}

    for metric in metrics:
        if metric.get("component") != "primitive":
            continue

        run_id = metric["run_id"]
        key = (run_id, metric["algorithm"], int(metric["level"]))
        row = rows.setdefault(
            key,
            {
                **base_row(runs[run_id], "primitive"),
                "algorithm": metric["algorithm"],
                "level": int(metric["level"]),
            },
        )
        column = f"{metric['operation']}_{metric['metric']}"
        row[column] = normalize_value(metric["value"])
        if metric.get("unit"):
            row[f"{column}_unit"] = metric["unit"]

    for row in rows.values():
        row.update(build_metrics.get(row["run_id"], {}))

    return sorted(
        rows.values(),
        key=lambda item: (
            item["board"],
            item["profile"],
            item["sample"],
            item["implementation"],
            item["backend"],
            item["algorithm"],
            item["level"],
        ),
    )


def finalize_protocol_row(
    row: Dict[str, Any],
    build_metrics: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    if row.get("auth_level") is not None and row.get("key_exchange_level") is not None:
        row["suite"] = (
            f"{row['key_exchange_algorithm']}{row['key_exchange_level']}"
            f"+{row['auth_algorithm']}{row['auth_level']}"
        )
        if (
            str(row.get("key_exchange_algorithm", "")).upper().startswith("MLKEM")
            and str(row.get("auth_algorithm", "")).upper().startswith("MLDSA")
        ):
            row["suite_mode"] = "pure_pq"
        else:
            row["suite_mode"] = "hybrid_or_other"
    row.update(build_metrics.get(row["run_id"], {}))
    return row


def summarize_protocol(
    metrics: List[Dict[str, Any]],
    runs: Dict[str, Dict[str, Any]],
    build_metrics: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    rows_by_run: Dict[str, List[Dict[str, Any]]] = {}
    for metric in metrics:
        if metric.get("component") == "protocol":
            rows_by_run.setdefault(metric["run_id"], []).append(metric)

    summarized: List[Dict[str, Any]] = []

    for run_id, entries in rows_by_run.items():
        suite_index = 0
        current: Dict[str, Any] | None = None

        for metric in entries:
            if metric["operation"] == "handshake" and metric["metric"] == "time":
                if current is not None:
                    summarized.append(finalize_protocol_row(current, build_metrics))
                suite_index += 1
                current = {
                    **base_row(runs[run_id], "protocol"),
                    "algorithm": metric["algorithm"],
                    "level": int(metric["level"]),
                    "suite_index": suite_index,
                }

            if current is None:
                continue

            value = normalize_value(metric["value"])
            if metric["operation"] == "auth":
                current["auth_algorithm"] = metric["algorithm"]
                current["auth_level"] = int(metric["level"])
                current[f"auth_{metric['metric']}"] = value
                if metric.get("unit"):
                    current[f"auth_{metric['metric']}_unit"] = metric["unit"]
            elif metric["operation"] == "key_exchange":
                current["key_exchange_algorithm"] = metric["algorithm"]
                current["key_exchange_level"] = int(metric["level"])
                current[f"key_exchange_{metric['metric']}"] = value
                if metric.get("unit"):
                    current[f"key_exchange_{metric['metric']}_unit"] = metric["unit"]
            elif metric["operation"] == "handshake":
                current[f"handshake_{metric['metric']}"] = value
                if metric.get("unit"):
                    current[f"handshake_{metric['metric']}_unit"] = metric["unit"]

        if current is not None:
            summarized.append(finalize_protocol_row(current, build_metrics))

    return sorted(
        summarized,
        key=lambda item: (
            item["board"],
            item["profile"],
            item["sample"],
            item["implementation"],
            item["backend"],
            item["suite_index"],
        ),
    )


def main() -> int:
    args = parse_args()
    input_dir = args.input_dir.resolve()
    output_dir = args.output_dir.resolve() if args.output_dir else input_dir
    metrics, runs = load_inputs(input_dir)
    build_metrics = collect_build_metrics(metrics)

    build_rows = summarize_builds(runs, build_metrics)
    primitive_rows = summarize_primitives(metrics, runs, build_metrics)
    protocol_rows = summarize_protocol(metrics, runs, build_metrics)

    build_path = output_dir / "cost_of_assurance_builds.csv"
    primitive_path = output_dir / "cost_of_assurance_primitives.csv"
    protocol_path = output_dir / "cost_of_assurance_protocols.csv"

    write_csv(build_rows, build_path)
    write_csv(primitive_rows, primitive_path)
    write_csv(protocol_rows, protocol_path)

    print(f"Wrote {len(build_rows)} build comparison row(s) to {build_path}")
    print(f"Wrote {len(primitive_rows)} primitive comparison row(s) to {primitive_path}")
    print(f"Wrote {len(protocol_rows)} protocol comparison row(s) to {protocol_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
