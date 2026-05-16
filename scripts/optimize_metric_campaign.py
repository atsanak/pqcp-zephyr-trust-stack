#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Decide whether safe optimization candidates improve PQCP metrics.

The optimizer is intentionally evidence-first: it consumes benchmark-campaign
JSON files that were generated and replay-verified by the existing tooling, then
records keep/reject decisions without mutating source or Kconfig files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-campaign", type=Path, required=True)
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
    targets = selected_targets(args.target)
    baseline_path = args.baseline_campaign.resolve()
    baseline = load_json(baseline_path)
    artifact_hashes = {str(baseline_path): sha256_file(baseline_path)}
    failures: list[str] = []
    candidate_results: list[dict[str, Any]] = []
    for raw in args.candidate_campaign:
        name, path = parse_candidate(raw)
        candidate_path = path.resolve()
        candidate = load_json(candidate_path)
        artifact_hashes[str(candidate_path)] = sha256_file(candidate_path)
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
        failures.extend(result.get("failures") or [])
        candidate_results.append(result)
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
        "backend_selection": backend_selection(baseline),
        "hardware_promotion": hardware_promotion(args.hardware_result),
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
