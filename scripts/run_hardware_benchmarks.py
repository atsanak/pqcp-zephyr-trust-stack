#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Capture or normalize QEMU/MCU benchmark evidence for paper-style comparisons."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import re
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

OPERATION_ALIASES = {
    "keygen": "keygen",
    "keypair": "keygen",
    "key_pair": "keygen",
    "crypto_kem_keypair": "keygen",
    "encaps": "encaps",
    "encapsulation": "encaps",
    "encap": "encaps",
    "crypto_kem_enc": "encaps",
    "decaps": "decaps",
    "decapsulation": "decaps",
    "decap": "decaps",
    "crypto_kem_dec": "decaps",
    "sign": "sign",
    "signature": "sign",
    "crypto_sign": "sign",
    "verify": "verify",
    "verification": "verify",
    "crypto_sign_verify": "verify",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_algorithm_name(value: Any) -> str:
    text = str(value or "").strip()
    compact = re.sub(r"[^a-z0-9]", "", text.lower())
    if not compact:
        return ""

    for prefix in ("mlkem", "kyber"):
        if compact.startswith(prefix):
            level = compact[len(prefix):]
            if level in {"512", "768", "1024"}:
                return f"ML-KEM-{level}"

    for prefix in ("mldsa", "dilithium"):
        if compact.startswith(prefix):
            level = compact[len(prefix):]
            if level in {"44", "65", "87"}:
                return f"ML-DSA-{level}"
            if level in {"2", "3", "5"}:
                return {"2": "ML-DSA-44", "3": "ML-DSA-65", "5": "ML-DSA-87"}[level]

    return text


def canonical_operation_name(value: Any) -> str:
    text = str(value or "").strip()
    normalized = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return OPERATION_ALIASES.get(normalized, normalized or text)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("qemu", "transcript", "import-reference", "compare-reference"),
        required=True,
        help=(
            "qemu runs the existing benchmark matrix locally; transcript "
            "normalizes a captured UART/QEMU log; import-reference normalizes "
            "a paper/reference CSV without executing code; compare-reference "
            "compares a local benchmark CSV against an imported reference CSV."
        ),
    )
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT)
    parser.add_argument("--west-root", type=Path)
    parser.add_argument("--west", help="Explicit west command.")
    parser.add_argument("--board", default="qemu_x86_64")
    parser.add_argument("--transcript", type=Path, help="Captured UART/QEMU stdout log.")
    parser.add_argument("--candidate-csv", type=Path, help="Local benchmark CSV to compare.")
    parser.add_argument("--reference-csv", type=Path, help="Reference benchmark CSV to import.")
    parser.add_argument("--reference-name", default="external-reference")
    parser.add_argument("--source-ecosystem", choices=("pqm4", "supercop", "liboqs", "paper", "other"))
    parser.add_argument("--board-class")
    parser.add_argument("--clock-mhz", type=float)
    parser.add_argument("--clock-assumption")
    parser.add_argument("--compiler")
    parser.add_argument("--toolchain")
    parser.add_argument("--optimization-flags")
    parser.add_argument("--statistic-type")
    parser.add_argument(
        "--environment-type",
        choices=("qemu", "native_host", "physical_hardware", "external_reference"),
    )
    parser.add_argument(
        "--allow-partial-reference",
        action="store_true",
        help=(
            "In compare-reference mode, pass when at least one candidate/reference "
            "pair matches and all context metadata is valid. Missing pairs remain "
            "reported as coverage gaps."
        ),
    )
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
                    "algorithm": canonical_algorithm_name(
                        row.get("algorithm") or row.get("parameter_set") or row.get("scheme") or ""
                    ),
                    "operation": canonical_operation_name(row.get("operation") or row.get("op") or ""),
                    "cycles": row.get("cycles") or row.get("median_cycles") or "",
                    "time_us": row.get("time_us") or row.get("us") or "",
                    "rom_bytes": row.get("rom_bytes") or row.get("text") or "",
                    "ram_bytes": row.get("ram_bytes") or row.get("ram") or "",
                    "platform": row.get("platform") or row.get("board") or "",
                    "comparison_context": {
                        "source_dataset": row.get("source_dataset") or row.get("source") or source_name,
                        "source_ecosystem": row.get("source_ecosystem") or row.get("ecosystem") or "",
                        "board_class": row.get("board_class") or row.get("platform_class") or "",
                        "clock_mhz": row.get("clock_mhz") or row.get("mhz") or "",
                        "clock_assumption": row.get("clock_assumption") or "",
                        "compiler": row.get("compiler") or "",
                        "toolchain": row.get("toolchain") or "",
                        "optimization_flags": row.get("optimization_flags") or row.get("cflags") or "",
                        "statistic_type": row.get("statistic_type") or row.get("statistic") or "",
                        "environment_type": row.get("environment_type") or row.get("environment") or "",
                    },
                    "raw": row,
                }
            )
    return rows


def normalize_candidate_csv(path: Path, source_name: str = "candidate") -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader, start=1):
            operation = str(row.get("operation") or "")
            if operation.endswith(("_cycles_min", "_cycles_median", "_cycles_p90",
                                   "_cycles_p99", "_cycles_max", "_cycles_mad",
                                   "_sample_count")):
                continue
            rows.append(
                {
                    "source": source_name,
                    "row_index": index,
                    "algorithm": canonical_algorithm_name(row.get("parameter_set") or row.get("suite") or ""),
                    "operation": canonical_operation_name(operation),
                    "implementation": row.get("implementation") or "",
                    "backend": row.get("backend") or "",
                    "cycles": row.get("cycles") or "",
                    "time_us": row.get("time_us") or "",
                    "rom_bytes": row.get("rom_bytes") or "",
                    "ram_bytes": row.get("ram_bytes") or "",
                    "platform": row.get("platform") or "",
                    "raw": row,
                }
            )
    return rows


def _numeric(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number <= 0:
        return None
    return number


def compare_candidate_to_reference(
    candidate_rows: list[dict[str, Any]],
    reference_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    reference_index: dict[tuple[str, str], dict[str, Any]] = {}
    for row in reference_rows:
        key = (str(row.get("algorithm", "")), str(row.get("operation", "")))
        if not key[0] or not key[1] or key in reference_index:
            continue
        reference_index[key] = row

    comparisons: list[dict[str, Any]] = []
    for row in candidate_rows:
        key = (str(row.get("algorithm", "")), str(row.get("operation", "")))
        if not key[0] or not key[1]:
            continue
        reference = reference_index.get(key)
        candidate_cycles = _numeric(row.get("cycles"))
        reference_cycles = _numeric(reference.get("cycles")) if reference else None
        ratio = (
            candidate_cycles / reference_cycles
            if candidate_cycles is not None and reference_cycles is not None
            else None
        )
        comparisons.append(
            {
                "algorithm": key[0],
                "operation": key[1],
                "candidate_cycles": candidate_cycles,
                "reference_cycles": reference_cycles,
                "candidate_source": row.get("source", "candidate"),
                "reference_source": reference.get("source") if reference else None,
                "ratio": ratio,
                "passed": ratio is not None,
                "failure_reason": None if ratio is not None else "missing numeric reference pair",
            }
        )
    return comparisons


def summarize_comparisons(comparisons: list[dict[str, Any]]) -> dict[str, Any]:
    ratios = [
        float(item["ratio"])
        for item in comparisons
        if isinstance(item.get("ratio"), (int, float)) and item["ratio"] > 0
    ]
    if ratios:
        geomean_ratio = math.exp(sum(math.log(ratio) for ratio in ratios) / len(ratios))
    else:
        geomean_ratio = None
    return {
        "comparison_count": len(comparisons),
        "matched_count": len(ratios),
        "missing_count": len(comparisons) - len(ratios),
        "geomean_ratio": geomean_ratio,
    }


def comparison_passed(
    comparisons: list[dict[str, Any]],
    context_failures: list[str],
    *,
    allow_partial_reference: bool,
) -> bool:
    if context_failures or not comparisons:
        return False
    if allow_partial_reference:
        return any(item.get("passed") for item in comparisons)
    return all(item.get("passed") for item in comparisons)


def build_comparison_context(
    args: argparse.Namespace,
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    row_contexts = [
        row.get("comparison_context")
        for row in rows
        if isinstance(row.get("comparison_context"), dict)
    ]

    def first_value(key: str) -> Any:
        for context in row_contexts:
            value = context.get(key)
            if value not in (None, ""):
                return value
        return None

    return {
        "source_dataset": args.reference_name,
        "source_ecosystem": args.source_ecosystem or first_value("source_ecosystem"),
        "board_class": args.board_class or first_value("board_class"),
        "clock_mhz": args.clock_mhz if args.clock_mhz is not None else first_value("clock_mhz"),
        "clock_assumption": args.clock_assumption or first_value("clock_assumption"),
        "compiler": args.compiler or first_value("compiler"),
        "toolchain": args.toolchain or first_value("toolchain"),
        "optimization_flags": args.optimization_flags or first_value("optimization_flags"),
        "backend_family": "PQ Code Package reference comparison",
        "statistic_type": args.statistic_type or first_value("statistic_type"),
        "environment_type": args.environment_type or first_value("environment_type"),
    }


def validate_comparison_context(context: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    required = (
        "source_dataset",
        "source_ecosystem",
        "board_class",
        "statistic_type",
        "environment_type",
    )
    for key in required:
        if context.get(key) in (None, ""):
            failures.append(f"comparison_context.{key} is required")
    if context.get("clock_mhz") in (None, "") and not context.get("clock_assumption"):
        failures.append("comparison_context requires clock_mhz or clock_assumption")
    return failures


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
    context = report.get("comparison_context") or {}
    if context:
        lines.extend(
            [
                "## Comparison Context",
                "",
                f"- Source dataset: `{context.get('source_dataset', 'n/a')}`",
                f"- Source ecosystem: `{context.get('source_ecosystem', 'n/a')}`",
                f"- Board class: `{context.get('board_class', 'n/a')}`",
                f"- Environment type: `{context.get('environment_type', 'n/a')}`",
                f"- Statistic type: `{context.get('statistic_type', 'n/a')}`",
                "",
            ]
        )
    comparisons = report.get("comparisons") or []
    if comparisons:
        comparison_summary = report.get("comparison_summary") or {}
        geomean = comparison_summary.get("geomean_ratio")
        if isinstance(geomean, (int, float)):
            lines.extend(
                [
                    f"- Matched comparisons: `{comparison_summary.get('matched_count', 0)}`",
                    f"- Missing comparisons: `{comparison_summary.get('missing_count', 0)}`",
                    f"- Geomean candidate/reference ratio: `{geomean:.3f}`",
                    "",
                ]
            )
        lines.extend(
            [
                "| Algorithm | Operation | Candidate cycles | Reference cycles | Ratio |",
                "|---|---|---:|---:|---:|",
            ]
        )
        for item in comparisons:
            ratio = item.get("ratio")
            ratio_text = f"{ratio:.3f}" if isinstance(ratio, (int, float)) else "n/a"
            lines.append(
                f"| {item.get('algorithm', '')} | {item.get('operation', '')} | "
                f"{item.get('candidate_cycles') or 'n/a'} | "
                f"{item.get('reference_cycles') or 'n/a'} | {ratio_text} |"
            )
        lines.append("")
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
        context_failures: list[str]
        if args.mode == "import-reference":
            metrics = normalize_reference_csv(reference, args.reference_name)
            comparison_context = build_comparison_context(args, metrics)
            context_failures = validate_comparison_context(comparison_context)
            execution = {
                "mode": "import-reference",
                "board": args.board,
                "reference_csv": str(reference),
                "reference_sha256": sha256_file(reference),
                "passed": not context_failures,
                "failures": context_failures,
            }
            comparisons: list[dict[str, Any]] = []
        else:
            if args.candidate_csv is None:
                raise SystemExit("--candidate-csv is required in compare-reference mode")
            candidate = args.candidate_csv.resolve()
            candidate_rows = normalize_candidate_csv(candidate)
            reference_rows = normalize_reference_csv(reference, args.reference_name)
            comparison_context = build_comparison_context(args, reference_rows)
            context_failures = validate_comparison_context(comparison_context)
            comparisons = compare_candidate_to_reference(candidate_rows, reference_rows)
            comparison_summary = summarize_comparisons(comparisons)
            metrics = [*candidate_rows, *reference_rows]
            execution = {
                "mode": "compare-reference",
                "board": args.board,
                "candidate_csv": str(candidate),
                "candidate_sha256": sha256_file(candidate),
                "reference_csv": str(reference),
                "reference_sha256": sha256_file(reference),
                "comparison_count": len(comparisons),
                "allow_partial_reference": bool(args.allow_partial_reference),
                "passed": comparison_passed(
                    comparisons,
                    context_failures,
                    allow_partial_reference=bool(args.allow_partial_reference),
                ),
                "failures": context_failures,
            }
    if args.mode != "compare-reference":
        comparison_summary = {}
    if args.mode in {"qemu", "transcript"}:
        comparison_context = {
            "source_dataset": args.mode,
            "source_ecosystem": "pqcp-local",
            "board_class": "qemu" if "qemu" in args.board else args.board,
            "clock_mhz": None,
            "clock_assumption": "local runner reported by Zephyr/QEMU when available",
            "compiler": args.compiler,
            "toolchain": args.toolchain,
            "optimization_flags": args.optimization_flags,
            "backend_family": "PQ Code Package local backend",
            "statistic_type": args.statistic_type or "single_or_distribution",
            "environment_type": args.environment_type or ("qemu" if "qemu" in args.board else "physical_hardware"),
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
        "comparison_context": comparison_context,
        "summary": summarize_metrics(metrics),
        "metrics": metrics,
        "comparison_summary": comparison_summary,
        "comparisons": comparisons if args.mode == "compare-reference" else [],
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
