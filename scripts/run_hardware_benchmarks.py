#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Capture or normalize QEMU/MCU benchmark evidence for paper-style comparisons."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from local_workflow import clean_env, detect_west_root, discover_west  # noqa: E402
from parse_logs import parse_log_file  # noqa: E402


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("qemu", "transcript", "import-reference"),
        required=True,
        help=(
            "qemu runs the existing benchmark matrix locally; transcript "
            "normalizes a captured UART/QEMU log; import-reference normalizes "
            "a paper/reference CSV without executing code."
        ),
    )
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT)
    parser.add_argument("--west-root", type=Path)
    parser.add_argument("--west", help="Explicit west command.")
    parser.add_argument("--board", default="qemu_x86_64")
    parser.add_argument("--transcript", type=Path, help="Captured UART/QEMU stdout log.")
    parser.add_argument("--reference-csv", type=Path, help="Reference benchmark CSV to import.")
    parser.add_argument("--reference-name", default="external-reference")
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, default=SCRIPT_DIR / "cost_of_assurance_matrix.json")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--verbose", "-v", action="store_true")
    return parser.parse_args()


def normalize_reference_csv(path: Path, source_name: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader, start=1):
            rows.append(
                {
                    "source": source_name,
                    "row_index": index,
                    "algorithm": row.get("algorithm") or row.get("parameter_set") or row.get("scheme") or "",
                    "operation": row.get("operation") or row.get("op") or "",
                    "cycles": row.get("cycles") or row.get("median_cycles") or "",
                    "time_us": row.get("time_us") or row.get("us") or "",
                    "rom_bytes": row.get("rom_bytes") or row.get("text") or "",
                    "ram_bytes": row.get("ram_bytes") or row.get("ram") or "",
                    "platform": row.get("platform") or row.get("board") or "",
                    "raw": row,
                }
            )
    return rows


def summarize_metrics(metrics: list[dict[str, Any]]) -> dict[str, Any]:
    by_component: dict[str, int] = {}
    by_metric: dict[str, int] = {}
    for item in metrics:
        component = str(item.get("component", item.get("type", "unknown")))
        metric = str(item.get("metric", item.get("operation", "unknown")))
        by_component[component] = by_component.get(component, 0) + 1
        by_metric[metric] = by_metric.get(metric, 0) + 1
    return {
        "metric_count": len(metrics),
        "by_component": by_component,
        "by_metric": by_metric,
    }


def run_qemu_matrix(args: argparse.Namespace, output_root: Path) -> dict[str, Any]:
    module_path = args.module_path.resolve()
    west_root = args.west_root.resolve() if args.west_root else detect_west_root(module_path)
    west_cmd = discover_west(args.west, west_root, module_path)
    run_output = output_root / "qemu_matrix"
    cmd = [
        sys.executable,
        str(module_path / "scripts/run_benchmarks.py"),
        "--config",
        str(args.matrix.resolve()),
        "--output",
        str(run_output),
        "--west-root",
        str(west_root),
        "--module-path",
        str(module_path),
        "--west",
        " ".join(west_cmd),
    ]
    if args.verbose:
        print(" ".join(cmd))
    proc = subprocess.run(
        cmd,
        cwd=str(module_path),
        env=clean_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=args.timeout,
        check=False,
    )
    transcript = output_root / "qemu_benchmark_stdout.log"
    transcript.write_text(proc.stdout or "", encoding="utf-8")
    return {
        "mode": "qemu",
        "board": args.board,
        "command": cmd,
        "returncode": proc.returncode,
        "transcript": str(transcript),
        "transcript_sha256": sha256_file(transcript),
        "run_output": str(run_output),
        "passed": proc.returncode == 0,
    }


def write_markdown(report: dict[str, Any], output_path: Path) -> None:
    lines = [
        "# PQCP Hardware Benchmark Report",
        "",
        f"- Generated: `{report['generated_at']}`",
        f"- Mode: `{report['mode']}`",
        f"- Board: `{report.get('board', 'n/a')}`",
        f"- Passed: `{str(report.get('passed')).lower()}`",
        f"- Metric count: `{report.get('summary', {}).get('metric_count', 0)}`",
        "",
        "This report normalizes local QEMU, captured UART, or imported reference",
        "results for comparison. It does not claim hardware validation unless a",
        "hardware transcript is supplied by the caller.",
        "",
    ]
    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    args = parse_args()
    output_root = args.output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).isoformat()

    if args.mode == "qemu":
        execution = run_qemu_matrix(args, output_root)
        metrics: list[dict[str, Any]] = []
    elif args.mode == "transcript":
        if args.transcript is None:
            raise SystemExit("--transcript is required in transcript mode")
        transcript = args.transcript.resolve()
        metrics = parse_log_file(transcript)
        execution = {
            "mode": "transcript",
            "board": args.board,
            "transcript": str(transcript),
            "transcript_sha256": sha256_file(transcript),
            "passed": True,
        }
    else:
        if args.reference_csv is None:
            raise SystemExit("--reference-csv is required in import-reference mode")
        reference = args.reference_csv.resolve()
        metrics = normalize_reference_csv(reference, args.reference_name)
        execution = {
            "mode": "import-reference",
            "board": args.board,
            "reference_csv": str(reference),
            "reference_sha256": sha256_file(reference),
            "passed": True,
        }

    report = {
        "schema_version": 1,
        "generated_at": generated_at,
        "generator": "scripts/run_hardware_benchmarks.py",
        "mode": args.mode,
        "board": args.board,
        "host": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
        },
        "module_path": str(args.module_path.resolve()),
        "execution": execution,
        "summary": summarize_metrics(metrics),
        "metrics": metrics,
        "passed": bool(execution.get("passed")),
    }
    json_path = output_root / "hardware_benchmark_report.json"
    md_path = output_root / "hardware_benchmark_report.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(report, md_path)
    print(f"Wrote hardware benchmark report: {json_path}")
    print(f"Wrote hardware benchmark summary: {md_path}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
