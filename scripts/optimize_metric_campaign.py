#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Decide whether safe optimization candidates improve PQCP metrics.

The optimizer is intentionally evidence-first: it consumes benchmark-campaign
JSON files that were generated and replay-verified by the existing tooling, then
records keep/reject decisions without mutating source or Kconfig files.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import run_benchmark_campaign


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent


DEFAULT_TARGETS: tuple[dict[str, Any], ...] = (
    {
        "id": "mldsa.sign",
        "family": "ML-DSA",
        "parameter_sets": ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"),
        "operations": ("sign",),
        "priority": 1,
    },
    {
        "id": "mlkem.encaps",
        "family": "ML-KEM",
        "parameter_sets": ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"),
        "operations": ("encaps",),
        "priority": 2,
    },
    {
        "id": "mlkem.decaps",
        "family": "ML-KEM",
        "parameter_sets": ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"),
        "operations": ("decaps",),
        "priority": 3,
    },
    {
        "id": "stack.ram",
        "family": "resource",
        "parameter_sets": ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"),
        "operations": ("keygen", "encaps", "decaps", "sign", "verify"),
        "priority": 4,
    },
    {
        "id": "protocol.overhead",
        "family": "protocol",
        "parameter_sets": ("ML-KEM-768+ML-DSA-65", "ML-KEM-512+ML-DSA-87"),
        "operations": ("handshake",),
        "priority": 5,
    },
    {
        "id": "acvp.parser",
        "family": "acvp",
        "parameter_sets": ("ACVP",),
        "operations": ("decode", "dispatch"),
        "priority": 6,
    },
)


SAFE_CANDIDATES: tuple[dict[str, Any], ...] = (
    {
        "id": "opt_o3",
        "class": "compiler",
        "description": "Speed-biased compiler optimization",
        "overlay_lines": ('CONFIG_SPEED_OPTIMIZATIONS=y',),
    },
    {
        "id": "opt_os",
        "class": "compiler",
        "description": "Size-biased compiler optimization",
        "overlay_lines": ('CONFIG_SIZE_OPTIMIZATIONS=y',),
    },
    {
        "id": "lto",
        "class": "linker",
        "description": "Link-time optimization when supported by the board/toolchain",
        "overlay_lines": ('CONFIG_LTO=y',),
    },
    {
        "id": "monolithic_native",
        "class": "backend",
        "description": "Native monolithic ML-KEM/ML-DSA build paths",
        "overlay_lines": ('CONFIG_PQCP_MLKEM_MONOLITHIC=y', 'CONFIG_PQCP_MLDSA_MONOLITHIC=y'),
    },
    {
        "id": "single_level",
        "class": "footprint",
        "description": "Build only the selected parameter level in the measured image",
        "overlay_template": (
            'CONFIG_PQCP_MLKEM_MULTI_LEVEL=n',
            'CONFIG_PQCP_MLDSA_MULTI_LEVEL=n',
            'CONFIG_PQCP_MLKEM_LEVEL_<512|768|1024>=y',
            'CONFIG_PQCP_MLDSA_LEVEL_<44|65|87>=y',
        ),
    },
    {
        "id": "force_native",
        "class": "backend",
        "description": "Force production native backend for backend-selection evidence",
        "overlay_lines": ('CONFIG_PQCP_BACKEND_FORCE_NATIVE=y',),
    },
    {
        "id": "force_c",
        "class": "backend",
        "description": "Force portable C backend for backend-selection evidence",
        "overlay_lines": ('CONFIG_PQCP_BACKEND_FORCE_C=y',),
    },
    {
        "id": "reduce_ram",
        "class": "footprint",
        "description": "Enable backend reduced-RAM mode for stack/RAM footprint campaigns",
        "overlay_lines": ('CONFIG_PQCP_REDUCE_RAM=y',),
    },
    {
        "id": "reduced_distribution_samples",
        "class": "measurement",
        "description": "Reduce distribution samples for fast candidate screening only",
        "overlay_lines": ('CONFIG_PQCP_BENCH_DISTRIBUTION_SAMPLES=32',),
    },
    {
        "id": "stack_right_size",
        "class": "footprint",
        "description": "Right-size benchmark stacks after stack-usage evidence is available",
        "overlay_template": ('CONFIG_MAIN_STACK_SIZE=<measured_stack_plus_margin>',),
    },
)


def level_kconfig(*, mlkem: str = "768", mldsa: str = "65") -> tuple[str, ...]:
    return (
        f"CONFIG_PQCP_MLKEM_LEVEL_512={'y' if mlkem == '512' else 'n'}",
        f"CONFIG_PQCP_MLKEM_LEVEL_768={'y' if mlkem == '768' else 'n'}",
        f"CONFIG_PQCP_MLKEM_LEVEL_1024={'y' if mlkem == '1024' else 'n'}",
        f"CONFIG_PQCP_MLDSA_LEVEL_44={'y' if mldsa == '44' else 'n'}",
        f"CONFIG_PQCP_MLDSA_LEVEL_65={'y' if mldsa == '65' else 'n'}",
        f"CONFIG_PQCP_MLDSA_LEVEL_87={'y' if mldsa == '87' else 'n'}",
    )


def sig_run_target(level: str) -> dict[str, Any]:
    return {
        "target_id": "mldsa.sign",
        "sample": "pqcp_basic_sig",
        "parameter_set": f"ML-DSA-{level}",
        "operation": "sign",
        "extra_kconfig": level_kconfig(mldsa=level),
    }


def kem_run_target(level: str, operation: str) -> dict[str, Any]:
    return {
        "target_id": f"mlkem.{operation}",
        "sample": "pqcp_basic_kem",
        "parameter_set": f"ML-KEM-{level}",
        "operation": operation,
        "extra_kconfig": level_kconfig(mlkem=level),
    }


RUN_TARGETS: dict[str, dict[str, Any]] = {
    "mldsa44-sign": sig_run_target("44"),
    "mldsa65-sign": sig_run_target("65"),
    "mldsa87-sign": sig_run_target("87"),
    "mlkem512-encaps": kem_run_target("512", "encaps"),
    "mlkem768-encaps": kem_run_target("768", "encaps"),
    "mlkem1024-encaps": kem_run_target("1024", "encaps"),
    "mlkem512-decaps": kem_run_target("512", "decaps"),
    "mlkem768-decaps": kem_run_target("768", "decaps"),
    "mlkem1024-decaps": kem_run_target("1024", "decaps"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-campaign", type=Path)
    parser.add_argument(
        "--candidate-campaign",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="Candidate benchmark campaign result to compare against the baseline.",
    )
    parser.add_argument("--cost-evidence", type=Path, help="Optional cost-of-assurance evidence for priority reporting.")
    parser.add_argument("--hardware-result", type=Path, help="Optional hardware-promotion result JSON.")
    parser.add_argument(
        "--emit-overlays",
        type=Path,
        help="Write safe candidate overlay files/templates under this output directory.",
    )
    parser.add_argument("--target", action="append", help="Limit evaluation to a target id.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--min-median-improvement", type=float, default=0.05)
    parser.add_argument("--max-tail-regression", type=float, default=0.03)
    parser.add_argument("--max-resource-regression", type=float, default=0.0)
    parser.add_argument(
        "--require-kept",
        action="store_true",
        help="Fail if no candidate is accepted. Useful only after candidate data is available.",
    )
    parser.add_argument(
        "--run-target",
        choices=sorted(RUN_TARGETS),
        help="Run a focused qemu_x86_64 target benchmark before evaluating candidates.",
    )
    parser.add_argument(
        "--run-candidate",
        action="append",
        choices=sorted(candidate["id"] for candidate in SAFE_CANDIDATES if candidate.get("overlay_lines")),
        help="Safe candidate id to run for --run-target. Repeatable.",
    )
    parser.add_argument("--run-output-root", type=Path, default=Path("/tmp/pqcp-metric-candidates"))
    parser.add_argument("--west-root", type=Path, default=REPO_ROOT.parent)
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT)
    parser.add_argument("--west", default=None)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--run-repetitions", type=int, default=1)
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"{path} root must be a JSON object")
    return raw


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_candidate(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("candidate must use NAME=PATH")
    name, path = value.split("=", 1)
    if not name.strip() or not path.strip():
        raise argparse.ArgumentTypeError("candidate must use NAME=PATH")
    return name.strip(), Path(path).expanduser()


def candidate_by_id(candidate_id: str) -> dict[str, Any]:
    for candidate in SAFE_CANDIDATES:
        if candidate["id"] == candidate_id:
            return candidate
    raise RuntimeError(f"unknown candidate id: {candidate_id}")


def selected_targets(ids: list[str] | None) -> list[dict[str, Any]]:
    targets = list(DEFAULT_TARGETS)
    if not ids:
        return targets
    selected = [target for target in targets if target["id"] in ids]
    missing = sorted(set(ids) - {target["id"] for target in selected})
    if missing:
        raise RuntimeError(f"unknown optimization target(s): {', '.join(missing)}")
    return selected


def as_float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed):
        return None
    return parsed


def parameter_set_name(algorithm: str, level: str) -> str:
    normalized = str(algorithm or "").upper()
    if normalized == "MLDSA":
        return f"ML-DSA-{level}"
    if normalized == "MLKEM":
        return f"ML-KEM-{level}"
    return f"{algorithm}-{level}"


def rows_from_consolidated_metrics(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def campaign_from_metric_rows(source_rows: list[dict[str, str]], *, label: str, paths: list[Path]) -> dict[str, Any]:
    groups: dict[tuple[str, str, str, str], list[float]] = {}
    resources_by_run: dict[str, dict[str, float]] = {}
    for row in source_rows:
        if row.get("component") == "build" and row.get("operation") == "artifact":
            value = as_float(row.get("value"))
            if value is not None and row.get("metric") in ("rom_bytes", "ram_bytes"):
                resources_by_run.setdefault(str(row.get("run_id") or ""), {})[str(row.get("metric"))] = value
            continue
        if row.get("metric") != "cycles":
            continue
        cycles = as_float(row.get("value"))
        if cycles is None:
            continue
        key = (
            parameter_set_name(str(row.get("algorithm") or ""), str(row.get("level") or "")),
            str(row.get("implementation") or ""),
            str(row.get("backend") or ""),
            str(row.get("operation") or ""),
        )
        groups.setdefault(key, []).append(cycles)
    summaries: list[dict[str, Any]] = []
    for (parameter_set, implementation, backend, operation), values in sorted(groups.items()):
        run_resources: dict[str, float] = {}
        for row in source_rows:
            if (
                row.get("implementation") == implementation
                and row.get("backend") == backend
                and row.get("operation") == operation
                and row.get("metric") == "cycles"
            ):
                run_resources = resources_by_run.get(str(row.get("run_id") or ""), {})
                break
        summary: dict[str, Any] = {
            "parameter_set": parameter_set,
            "implementation": implementation,
            "backend": backend,
            "operation": operation,
            "sample_count": len(values),
            "min": min(values),
            "median": run_benchmark_campaign.statistics.median(values),
            "p90": run_benchmark_campaign.percentile(values, 90),
            "p99": run_benchmark_campaign.percentile(values, 99),
            "mad": run_benchmark_campaign.mad(values),
        }
        summary.update(run_resources)
        summaries.append(summary)
    ratios = run_benchmark_campaign.build_pairwise_ratios(summaries)
    rankings = run_benchmark_campaign.build_backend_rankings(summaries)
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/optimize_metric_campaign.py",
        "passed": bool(summaries),
        "source": {
            "label": label,
            "consolidated_metrics": [str(path.resolve()) for path in paths],
            "file_count": len(paths),
        },
        "comparison_context": {
            "source_dataset": "qemu",
            "source_ecosystem": "pqcp-local",
            "board_class": "qemu",
            "statistic_type": "single_or_distribution",
            "environment_type": "qemu",
        },
        "statistics": summaries,
        "pairwise_ratios": ratios,
        "backend_rankings": rankings,
        "summary": {
            "groups": len(summaries),
            "pairwise_comparisons": run_benchmark_campaign.comparison_summary(ratios),
            "backend_selection": {
                "ranking_count": len(rankings),
                "auto_not_fastest_count": sum(1 for row in rankings if not row.get("auto_is_fastest")),
            },
        },
        "failures": [] if summaries else [f"{label} contained no cycle metrics"],
    }


def campaign_from_consolidated_metrics(path: Path, *, label: str) -> dict[str, Any]:
    return campaign_from_metric_rows(rows_from_consolidated_metrics(path), label=label, paths=[path])


def campaign_from_consolidated_metric_files(paths: list[Path], *, label: str) -> dict[str, Any]:
    rows: list[dict[str, str]] = []
    for path in paths:
        rows.extend(rows_from_consolidated_metrics(path))
    return campaign_from_metric_rows(rows, label=label, paths=paths)


def backend_policy_for_candidate(candidate_id: str) -> str:
    if candidate_id == "force_native":
        return "force_native"
    if candidate_id == "force_c":
        return "force_c"
    return "auto"


def kconfig_for_candidate(candidate_id: str) -> list[str]:
    candidate = candidate_by_id(candidate_id)
    return [
        str(line)
        for line in candidate.get("overlay_lines") or ()
        if not str(line).startswith("CONFIG_PQCP_BACKEND_")
    ]


def benchmark_command(
    *,
    module_path: Path,
    west_root: Path,
    west: str | None,
    target: dict[str, Any],
    output_dir: Path,
    backend_policy: str,
    extra_kconfig: list[str],
    timeout: int,
) -> list[str]:
    cmd = [
        sys.executable,
        str(module_path / "scripts/run_benchmarks.py"),
        "--board",
        "qemu_x86_64",
        "--profile",
        "COA_QEMU_SINGLE_LEVEL",
        "--sample",
        str(target["sample"]),
        "--implementation",
        "pqcp",
        "--backend-policy",
        backend_policy,
        "--west-root",
        str(west_root),
        "--module-path",
        str(module_path),
        "--output",
        str(output_dir),
        "--timeout",
        str(timeout),
    ]
    if west:
        cmd.extend(["--west", west])
    for line in extra_kconfig:
        cmd.extend(["--kconfig", line])
    return cmd


def run_subprocess(cmd: list[str], *, cwd: Path, timeout: int) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return {
            "command": cmd,
            "started_at": started_at,
            "returncode": completed.returncode,
            "timed_out": False,
            "stdout_tail": completed.stdout[-4000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": cmd,
            "started_at": started_at,
            "returncode": None,
            "timed_out": True,
            "stdout_tail": (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else "",
        }


def run_target_candidates(args: argparse.Namespace) -> tuple[dict[str, Any], list[tuple[str, dict[str, Any]]], list[dict[str, Any]], list[str]]:
    if not args.run_target:
        raise RuntimeError("--run-target is required for benchmark execution mode")
    candidates = args.run_candidate or []
    if not candidates:
        raise RuntimeError("--run-candidate is required with --run-target")
    target = RUN_TARGETS[args.run_target]
    root = args.run_output_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    run_records: list[dict[str, Any]] = []
    failures: list[str] = []
    repetitions = max(1, int(args.run_repetitions or 1))
    target_kconfig = list(target["extra_kconfig"])
    module_path = args.module_path.resolve()
    west_root = args.west_root.resolve()
    baseline_metric_paths: list[Path] = []
    for repetition in range(repetitions):
        base_output = root / f"{args.run_target}__baseline_auto__rep{repetition + 1}"
        baseline_cmd = benchmark_command(
            module_path=module_path,
            west_root=west_root,
            west=args.west,
            target=target,
            output_dir=base_output,
            backend_policy="auto",
            extra_kconfig=target_kconfig,
            timeout=args.timeout,
        )
        baseline_record = run_subprocess(baseline_cmd, cwd=module_path, timeout=args.timeout + 60)
        baseline_metrics = base_output / "consolidated_metrics.csv"
        baseline_metrics_sha = sha256_file(baseline_metrics) if baseline_metrics.exists() else None
        run_records.append(
            {
                "name": "baseline_auto",
                "candidate_id": "baseline_auto",
                "target_id": str(target["target_id"]),
                "run_target": args.run_target,
                "sample": str(target["sample"]),
                "parameter_set": str(target["parameter_set"]),
                "operation": str(target["operation"]),
                "backend_policy": "auto",
                "extra_kconfig": target_kconfig,
                "repetition": repetition + 1,
                "output_dir": str(base_output),
                "consolidated_metrics": str(baseline_metrics),
                "metrics_sha256": baseline_metrics_sha,
                **baseline_record,
            }
        )
        if baseline_record["returncode"] == 0 and baseline_metrics.exists():
            baseline_metric_paths.append(baseline_metrics)
    if not baseline_metric_paths:
        failures.append(f"baseline run for {args.run_target} failed")
        return {"schema_version": 1, "passed": False, "statistics": [], "failures": failures}, [], run_records, failures
    baseline_campaign = campaign_from_consolidated_metric_files(baseline_metric_paths, label="baseline_auto")
    candidate_campaigns: list[tuple[str, dict[str, Any]]] = []
    for candidate_id in candidates:
        candidate_metric_paths: list[Path] = []
        for repetition in range(repetitions):
            candidate_output = root / f"{args.run_target}__{candidate_id}__rep{repetition + 1}"
            candidate_cmd = benchmark_command(
                module_path=module_path,
                west_root=west_root,
                west=args.west,
                target=target,
                output_dir=candidate_output,
                backend_policy=backend_policy_for_candidate(candidate_id),
                extra_kconfig=target_kconfig + kconfig_for_candidate(candidate_id),
                timeout=args.timeout,
            )
            record = run_subprocess(candidate_cmd, cwd=module_path, timeout=args.timeout + 60)
            metrics_path = candidate_output / "consolidated_metrics.csv"
            metrics_sha = sha256_file(metrics_path) if metrics_path.exists() else None
            backend_policy = backend_policy_for_candidate(candidate_id)
            run_records.append(
                {
                    "name": candidate_id,
                    "candidate_id": candidate_id,
                    "target_id": str(target["target_id"]),
                    "run_target": args.run_target,
                    "sample": str(target["sample"]),
                    "parameter_set": str(target["parameter_set"]),
                    "operation": str(target["operation"]),
                    "backend_policy": backend_policy,
                    "extra_kconfig": target_kconfig + kconfig_for_candidate(candidate_id),
                    "repetition": repetition + 1,
                    "output_dir": str(candidate_output),
                    "consolidated_metrics": str(metrics_path),
                    "metrics_sha256": metrics_sha,
                    **record,
                }
            )
            if record["returncode"] == 0 and metrics_path.exists():
                candidate_metric_paths.append(metrics_path)
        if not candidate_metric_paths:
            failures.append(f"candidate run {candidate_id} for {args.run_target} failed")
            continue
        candidate_campaigns.append(
            (
                candidate_id,
                campaign_from_consolidated_metric_files(candidate_metric_paths, label=candidate_id),
            )
        )
    return baseline_campaign, candidate_campaigns, run_records, failures


def stat_matches(row: dict[str, Any], target: dict[str, Any]) -> bool:
    parameter_set = str(row.get("parameter_set") or "")
    operation = str(row.get("operation") or "")
    implementation = str(row.get("implementation") or "")
    if implementation and implementation != "pqcp":
        return False
    return parameter_set in target["parameter_sets"] and operation in target["operations"]


def stat_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(row.get("parameter_set") or ""),
        str(row.get("operation") or ""),
        str(row.get("backend") or "auto"),
    )


def preferred_pqcp_stats(campaign: dict[str, Any], target: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    rows = [
        row
        for row in campaign.get("statistics") or []
        if isinstance(row, dict) and stat_matches(row, target)
    ]
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        key = (str(row.get("parameter_set") or ""), str(row.get("operation") or ""))
        grouped.setdefault(key, []).append(row)
    preferred: dict[tuple[str, str], dict[str, Any]] = {}
    for key, group in grouped.items():
        exact = [row for row in group if str(row.get("backend") or "") == "auto"]
        if exact:
            preferred[key] = exact[0]
        else:
            preferred[key] = sorted(group, key=lambda row: str(row.get("backend") or ""))[0]
    return preferred


def compare_stat_rows(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    *,
    min_improvement: float,
    max_tail_regression: float,
    max_resource_regression: float,
) -> dict[str, Any]:
    base_median = as_float(baseline.get("median"))
    cand_median = as_float(candidate.get("median"))
    if base_median is None or cand_median is None or base_median <= 0:
        return {
            "passed": False,
            "decision": "reject",
            "failure_reason": "missing or invalid median values",
        }
    improvement = (base_median - cand_median) / base_median
    tail_checks: list[dict[str, Any]] = []
    resource_checks: list[dict[str, Any]] = []
    failures: list[str] = []
    for field in ("p90", "p99"):
        base_value = as_float(baseline.get(field))
        cand_value = as_float(candidate.get(field))
        if base_value is None or cand_value is None:
            failures.append(f"missing {field}")
            tail_checks.append({"field": field, "passed": False})
            continue
        limit = base_value * (1.0 + max_tail_regression)
        passed = cand_value <= limit
        if not passed:
            failures.append(f"{field} regressed {cand_value:.3f} > {limit:.3f}")
        tail_checks.append(
            {
                "field": field,
                "baseline": base_value,
                "candidate": cand_value,
                "limit": limit,
                "passed": passed,
            }
        )
    for field in ("rom_bytes", "ram_bytes"):
        base_value = as_float(baseline.get(field))
        cand_value = as_float(candidate.get(field))
        if base_value is None or cand_value is None:
            continue
        limit = base_value * (1.0 + max_resource_regression)
        passed = cand_value <= limit
        if not passed:
            failures.append(f"{field} regressed {cand_value:.3f} > {limit:.3f}")
        resource_checks.append(
            {
                "field": field,
                "baseline": base_value,
                "candidate": cand_value,
                "limit": limit,
                "passed": passed,
            }
        )
    median_passed = improvement >= min_improvement
    if not median_passed:
        failures.append(f"median improvement {improvement:.4f} below threshold {min_improvement:.4f}")
    passed = median_passed and not failures
    return {
        "passed": passed,
        "decision": "keep" if passed else "reject",
        "parameter_set": baseline.get("parameter_set"),
        "operation": baseline.get("operation"),
        "baseline_backend": baseline.get("backend") or "",
        "candidate_backend": candidate.get("backend") or "",
        "baseline_median": base_median,
        "candidate_median": cand_median,
        "median_improvement": improvement,
        "tail_checks": tail_checks,
        "resource_checks": resource_checks,
        "failure_reason": "; ".join(failures) if failures else None,
    }


def evaluate_candidate(
    *,
    name: str,
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    targets: list[dict[str, Any]],
    min_improvement: float,
    max_tail_regression: float,
    max_resource_regression: float,
) -> dict[str, Any]:
    target_results: list[dict[str, Any]] = []
    integrity_failures: list[str] = []
    kept = 0
    rejected = 0
    not_available = 0
    for target in targets:
        base_stats = preferred_pqcp_stats(baseline, target)
        cand_stats = preferred_pqcp_stats(candidate, target)
        if not base_stats and not cand_stats:
            not_available += 1
            target_results.append(
                {
                    "target": target["id"],
                    "status": "not_available",
                    "decision": "not_evaluated",
                    "reason": "no matching benchmark statistics in baseline or candidate",
                }
            )
            continue
        comparisons: list[dict[str, Any]] = []
        missing: list[str] = []
        for key, base_row in sorted(base_stats.items()):
            cand_row = cand_stats.get(key)
            if cand_row is None:
                missing.append("/".join(key))
                continue
            comparisons.append(
                compare_stat_rows(
                    base_row,
                    cand_row,
                    min_improvement=min_improvement,
                    max_tail_regression=max_tail_regression,
                    max_resource_regression=max_resource_regression,
                )
            )
        if missing:
            integrity_failures.append(
                f"candidate {name} missing {target['id']} metric(s): {', '.join(missing)}"
            )
        accepted = bool(comparisons) and all(row.get("passed") for row in comparisons) and not missing
        if accepted:
            kept += 1
        else:
            rejected += 1
        target_results.append(
            {
                "target": target["id"],
                "status": "evaluated",
                "decision": "keep" if accepted else "reject",
                "comparisons": comparisons,
                "missing_metrics": missing,
            }
        )
    return {
        "name": name,
        "passed": not integrity_failures,
        "decision": "keep" if kept > 0 and rejected == 0 else "reject",
        "kept_targets": kept,
        "rejected_targets": rejected,
        "not_available_targets": not_available,
        "target_results": target_results,
        "failures": integrity_failures,
    }


def best_candidate_recommendations(candidate_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    winners: dict[str, dict[str, Any]] = {}
    for candidate in candidate_results:
        if candidate.get("production_promotion_allowed") is not True:
            continue
        candidate_name = str(candidate.get("name") or "")
        candidate_class = str((candidate.get("candidate_metadata") or {}).get("class") or "")
        for target_result in candidate.get("target_results") or []:
            if target_result.get("decision") != "keep":
                continue
            target_id = str(target_result.get("target") or "")
            for comparison in target_result.get("comparisons") or []:
                if comparison.get("passed") is not True:
                    continue
                improvement = as_float(comparison.get("median_improvement"))
                candidate_median = as_float(comparison.get("candidate_median"))
                if improvement is None or candidate_median is None:
                    continue
                current = winners.get(target_id)
                replacement = {
                    "target": target_id,
                    "candidate": candidate_name,
                    "candidate_class": candidate_class,
                    "parameter_set": comparison.get("parameter_set"),
                    "operation": comparison.get("operation"),
                    "median_improvement": improvement,
                    "baseline_median": comparison.get("baseline_median"),
                    "candidate_median": candidate_median,
                    "tail_checks": comparison.get("tail_checks") or [],
                    "resource_checks": comparison.get("resource_checks") or [],
                }
                if current is None:
                    winners[target_id] = replacement
                    continue
                current_improvement = as_float(current.get("median_improvement")) or -math.inf
                current_median = as_float(current.get("candidate_median")) or math.inf
                if improvement > current_improvement or (
                    math.isclose(improvement, current_improvement) and candidate_median < current_median
                ):
                    winners[target_id] = replacement
    return [winners[key] for key in sorted(winners)]


def near_miss_candidates(candidate_results: list[dict[str, Any]], *, min_improvement: float) -> list[dict[str, Any]]:
    near_misses: list[dict[str, Any]] = []
    for candidate in candidate_results:
        candidate_name = str(candidate.get("name") or "")
        candidate_class = str((candidate.get("candidate_metadata") or {}).get("class") or "")
        for target_result in candidate.get("target_results") or []:
            if target_result.get("status") != "evaluated":
                continue
            for comparison in target_result.get("comparisons") or []:
                improvement = as_float(comparison.get("median_improvement"))
                if improvement is None or improvement <= 0.0 or improvement >= min_improvement:
                    continue
                checks = list(comparison.get("tail_checks") or []) + list(comparison.get("resource_checks") or [])
                if any(check.get("passed") is False for check in checks):
                    continue
                near_misses.append(
                    {
                        "target": target_result.get("target"),
                        "candidate": candidate_name,
                        "candidate_class": candidate_class,
                        "parameter_set": comparison.get("parameter_set"),
                        "operation": comparison.get("operation"),
                        "median_improvement": improvement,
                        "required_improvement": min_improvement,
                        "improvement_gap": min_improvement - improvement,
                        "baseline_median": comparison.get("baseline_median"),
                        "candidate_median": comparison.get("candidate_median"),
                    }
                )
    return sorted(near_misses, key=lambda row: (row["improvement_gap"], row["target"], row["candidate"]))


def priority_from_pairwise(campaign: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in campaign.get("pairwise_ratios") or []:
        if not isinstance(row, dict):
            continue
        ratio = as_float(row.get("ratio"))
        if ratio is None:
            continue
        rows.append(
            {
                "parameter_set": row.get("parameter_set"),
                "operation": row.get("operation"),
                "candidate_backend": row.get("candidate_backend") or "",
                "baseline_backend": row.get("baseline_backend") or "",
                "ratio": ratio,
                "priority": "high" if ratio >= 1.0 else "medium",
            }
        )
    return sorted(rows, key=lambda item: float(item["ratio"]), reverse=True)[:limit]


def cost_evidence_priorities(path: Path | None) -> list[dict[str, Any]]:
    if not path:
        return []
    payload = load_json(path)
    rows: list[dict[str, Any]] = []
    for comparison in payload.get("comparisons") or []:
        if not isinstance(comparison, dict):
            continue
        for metric in comparison.get("metrics") or []:
            if not isinstance(metric, dict):
                continue
            ratio = as_float(metric.get("ratio"))
            if ratio is None:
                continue
            rows.append(
                {
                    "comparison": comparison.get("name"),
                    "metric": metric.get("metric"),
                    "ratio": ratio,
                    "passed": metric.get("passed"),
                }
            )
    return sorted(rows, key=lambda item: float(item["ratio"]), reverse=True)[:12]


def backend_selection(campaign: dict[str, Any]) -> dict[str, Any]:
    rankings = [
        row
        for row in campaign.get("backend_rankings") or []
        if isinstance(row, dict)
    ]
    auto_not_fastest = [row for row in rankings if row.get("auto_is_fastest") is False]
    return {
        "status": "evaluated" if rankings else "insufficient_data",
        "ranking_count": len(rankings),
        "auto_not_fastest_count": len(auto_not_fastest),
        "auto_not_fastest": auto_not_fastest,
    }


def hardware_promotion(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {
            "status": "not_available",
            "reason": "no hardware-result artifact supplied",
            "required_before_claiming_physical_performance": True,
        }
    payload = load_json(path)
    return {
        "status": "provided",
        "passed": payload.get("passed"),
        "artifact": str(path),
        "summary": payload.get("summary"),
    }


def emit_candidate_overlays(output_dir: Path | None) -> list[dict[str, str]]:
    if output_dir is None:
        return []
    emitted: list[dict[str, str]] = []
    output_dir.mkdir(parents=True, exist_ok=True)
    for candidate in SAFE_CANDIDATES:
        lines = candidate.get("overlay_lines")
        suffix = ".conf"
        if not lines:
            lines = candidate.get("overlay_template") or ()
            suffix = ".conf.template"
        path = output_dir / f"{candidate['id']}{suffix}"
        path.write_text("\n".join(str(line) for line in lines) + "\n", encoding="utf-8")
        emitted.append({"candidate": str(candidate["id"]), "path": str(path.resolve())})
    return emitted


def command_plan(output_root: str = "/tmp/pqcp-opt-campaign") -> list[dict[str, str]]:
    return [
        {
            "name": "cost_of_assurance_smoke",
            "command": (
                "python3 scripts/run_extended_checks.py --strict --run-cost-of-assurance-smoke "
                f"--cost-of-assurance-evidence {output_root}/cost_of_assurance_evidence.json"
            ),
        },
        {
            "name": "benchmark_campaign",
            "command": (
                "python3 scripts/run_benchmark_campaign.py "
                f"--benchmark-csv {output_root}/benchmark_results.csv "
                f"--benchmark-provenance {output_root}/benchmark_provenance.json "
                f"--output {output_root}/benchmark_campaign_result.json"
            ),
        },
        {
            "name": "benchmark_campaign_replay",
            "command": (
                "python3 scripts/verify_benchmark_campaign.py "
                f"--campaign {output_root}/benchmark_campaign_result.json "
                f"--output {output_root}/benchmark_campaign_verify_result.json"
            ),
        },
    ]


def run(args: argparse.Namespace) -> dict[str, Any]:
    run_records: list[dict[str, Any]] = []
    execution_failures: list[str] = []
    if args.run_target:
        run_target = RUN_TARGETS[args.run_target]
        target_ids = [run_target["target_id"]]
        if args.target:
            target_ids.extend(args.target)
        targets = selected_targets(target_ids)
        baseline, executed_candidates, run_records, execution_failures = run_target_candidates(args)
        artifact_hashes: dict[str, str] = {}
        for record in run_records:
            metrics_path = Path(str(record.get("consolidated_metrics") or ""))
            if metrics_path.exists():
                artifact_hashes[str(metrics_path.resolve())] = sha256_file(metrics_path)
        candidate_items = executed_candidates
    else:
        targets = selected_targets(args.target)
        if args.baseline_campaign is None:
            raise RuntimeError("--baseline-campaign is required unless --run-target is used")
        baseline_path = args.baseline_campaign.resolve()
        baseline = load_json(baseline_path)
        artifact_hashes = {str(baseline_path): sha256_file(baseline_path)}
        candidate_items = []
        for raw in args.candidate_campaign:
            name, path = parse_candidate(raw)
            candidate_path = path.resolve()
            candidate = load_json(candidate_path)
            artifact_hashes[str(candidate_path)] = sha256_file(candidate_path)
            candidate_items.append((name, candidate))
    failures: list[str] = []
    failures.extend(execution_failures)
    candidate_results: list[dict[str, Any]] = []
    for name, candidate in candidate_items:
        if candidate.get("passed") is not True:
            failures.append(f"candidate {name} campaign did not pass replay preconditions")
        result = evaluate_candidate(
            name=name,
            baseline=baseline,
            candidate=candidate,
            targets=targets,
            min_improvement=args.min_median_improvement,
            max_tail_regression=args.max_tail_regression,
            max_resource_regression=args.max_resource_regression,
        )
        metadata = candidate_by_id(name) if name in {candidate["id"] for candidate in SAFE_CANDIDATES} else {}
        result["candidate_metadata"] = metadata
        if metadata.get("class") == "measurement":
            result["production_promotion_allowed"] = False
            result["promotion_scope"] = "measurement_only"
        else:
            result["production_promotion_allowed"] = result.get("decision") == "keep"
            result["promotion_scope"] = "production_candidate" if result.get("decision") == "keep" else "rejected"
        failures.extend(result.get("failures") or [])
        candidate_results.append(result)
    if baseline.get("passed") is not True:
        failures.append("baseline campaign did not pass replay preconditions")
    if args.require_kept and not any(result.get("decision") == "keep" for result in candidate_results):
        failures.append("--require-kept was set but no candidate was accepted")
    if args.cost_evidence:
        artifact_hashes[str(args.cost_evidence.resolve())] = sha256_file(args.cost_evidence.resolve())
    if args.hardware_result:
        artifact_hashes[str(args.hardware_result.resolve())] = sha256_file(args.hardware_result.resolve())
    emitted_overlays = emit_candidate_overlays(args.emit_overlays)
    for overlay in emitted_overlays:
        path = Path(overlay["path"])
        artifact_hashes[str(path)] = sha256_file(path)
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/optimize_metric_campaign.py",
        "passed": not failures,
        "policy": {
            "min_median_improvement": args.min_median_improvement,
            "max_tail_regression": args.max_tail_regression,
            "max_resource_regression": args.max_resource_regression,
            "safe_candidates_only": True,
        },
        "targets": targets,
        "candidate_matrix": list(SAFE_CANDIDATES),
        "emitted_overlays": emitted_overlays,
        "baseline_priorities": priority_from_pairwise(baseline),
        "cost_of_assurance_priorities": cost_evidence_priorities(args.cost_evidence),
        "candidate_results": candidate_results,
        "best_candidate_recommendations": best_candidate_recommendations(candidate_results),
        "near_miss_candidates": near_miss_candidates(candidate_results, min_improvement=args.min_median_improvement),
        "backend_selection": backend_selection(baseline),
        "hardware_promotion": hardware_promotion(args.hardware_result),
        "execution": {
            "mode": "targeted_qemu" if args.run_target else "replay",
            "run_target": args.run_target,
            "run_records": run_records,
        },
        "commands": command_plan(),
        "artifact_hashes": artifact_hashes,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    try:
        result = run(args)
    except Exception as exc:  # noqa: BLE001 - CLI must report a concise actionable failure.
        print(f"FAIL: metric optimization campaign failed: {exc}", file=sys.stderr)
        return 1
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: metric optimization campaign evidence generated")
        print(f"  output: {args.output.resolve()}")
        kept = sum(1 for row in result["candidate_results"] if row.get("decision") == "keep")
        rejected = sum(1 for row in result["candidate_results"] if row.get("decision") == "reject")
        print(f"  candidates: kept={kept} rejected={rejected}")
        return 0
    print("FAIL: metric optimization campaign evidence failed")
    for failure in result["failures"]:
        print(f"  - {failure}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
