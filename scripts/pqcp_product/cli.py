#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Command line interface for product-grade evidence workflows."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .api import ProductEvidenceApi
from .errors import ProductEvidenceError
from .fs import write_json_atomic, write_text_atomic
from .reports import render_baseline_report, render_catalog_report, render_pack_report, render_run_report

REPO_ROOT = Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PQCP product/research evidence toolkit")
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT, help="Repository root to inspect")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("list-experiments", help="List catalog experiments")
    _catalog_arg(p)
    p.add_argument("--profile", choices=("fast", "paper", "product", "hardware", "all"))
    p.add_argument("--category", action="append")
    p.add_argument("--glob")
    p.add_argument("--contains")
    p.add_argument("--limit", type=int)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("validate-catalog", help="Validate the experiment catalog")
    _catalog_arg(p)
    p.add_argument("--output", type=Path)
    p.add_argument("--report", type=Path)

    p = sub.add_parser("plan-experiments", help="Create a dry-run manifest for selected experiments")
    _selection_args(p)
    p.add_argument("--output-root", type=Path, required=True)
    p.add_argument("--timeout", type=int, default=300)

    p = sub.add_parser("run-experiments", help="Execute selected experiment commands")
    _selection_args(p)
    p.add_argument("--output-root", type=Path, required=True)
    p.add_argument("--timeout", type=int, default=300)

    p = sub.add_parser("build-pack", help="Build a hash-bound evidence pack manifest")
    p.add_argument("--output-root", type=Path, required=True)
    p.add_argument("--pack-id", default="pqcp-product-evidence")
    p.add_argument("--profile", default="product")
    p.add_argument("--tag")
    p.add_argument("--required", action="append", default=[])
    p.add_argument("--report", type=Path)

    p = sub.add_parser("validate-pack", help="Replay evidence pack artifact hashes")
    p.add_argument("--output-root", type=Path, required=True)
    p.add_argument("--output", type=Path)

    p = sub.add_parser("compare-baselines", help="Compare candidate and baseline CSV metrics")
    p.add_argument("--candidate", type=Path, required=True)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    p.add_argument("--threshold", type=float, default=1.05)
    p.add_argument("--report", type=Path)

    p = sub.add_parser("readiness-matrix", help="Generate executable experiment readiness matrix")
    _catalog_arg(p)
    p.add_argument("--output", type=Path)

    p = sub.add_parser("compare-runs", help="Compare two or more evidence packs for reproducibility")
    p.add_argument("--pack", action="append", type=Path, required=True, help="Evidence pack root; pass at least twice")
    p.add_argument("--output-root", type=Path, required=True)

    p = sub.add_parser("validate-coverage", help="Validate experiment catalog coverage against product/research defaults")
    _catalog_arg(p)
    p.add_argument("--output-root", type=Path, required=True)

    p = sub.add_parser("validate-results", help="Validate CSV result quality and required metric combinations")
    p.add_argument("--csv", action="append", type=Path, required=True, dest="csv_paths")
    p.add_argument("--output-root", type=Path, required=True)
    p.add_argument("--zero-is-fail", action="store_true")
    p.add_argument("--no-core-combos", action="store_true")

    p = sub.add_parser("stats-summary", help="Compute statistical sanity summaries for result CSV files")
    p.add_argument("--csv", action="append", type=Path, required=True, dest="csv_paths")
    p.add_argument("--output-root", type=Path, required=True)
    p.add_argument("--min-samples", type=int, default=3)
    p.add_argument("--cv-warn-threshold", type=float, default=0.10)

    p = sub.add_parser("paper-report", help="Aggregate validator outputs into a compact paper evidence report")
    p.add_argument("--output-root", type=Path, required=True)
    p.add_argument("--reproducibility-report", type=Path)
    p.add_argument("--coverage-report", type=Path)
    p.add_argument("--baseline-report", type=Path)
    p.add_argument("--regression-report", type=Path)
    p.add_argument("--quality-report", type=Path)
    p.add_argument("--statistics-report", type=Path)

    p = sub.add_parser("recommend-deployment", help="Rank PQC deployment candidates for a constrained scenario")
    _decision_evidence_args(p)
    p.add_argument("--scenario", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)

    p = sub.add_parser("plan-evidence", help="Plan missing experiments for a deployment scenario")
    _decision_evidence_args(p)
    _catalog_arg(p)
    p.add_argument("--scenario", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)

    p = sub.add_parser("claim-matrix", help="Map product/paper claims to available evidence")
    _decision_evidence_args(p)
    p.add_argument("--output-root", type=Path, required=True)

    p = sub.add_parser("compare-scenarios", help="Compare supportability of multiple deployment scenarios")
    _decision_evidence_args(p)
    p.add_argument("--scenario", action="append", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)

    p = sub.add_parser("environment", help="Capture reproducibility metadata")
    p.add_argument("--output", type=Path)

    return parser


def _catalog_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--catalog", type=Path, help="Experiment catalog path")


def _selection_args(parser: argparse.ArgumentParser) -> None:
    _catalog_arg(parser)
    parser.add_argument("--profile", choices=("fast", "paper", "product", "hardware", "all"), default="fast")
    parser.add_argument("--id", action="append", dest="ids")
    parser.add_argument("--category", action="append")
    parser.add_argument("--glob")
    parser.add_argument("--contains")
    parser.add_argument("--limit", type=int)


def _decision_evidence_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pack", action="append", type=Path, default=[], help="Evidence pack root")
    parser.add_argument("--csv", action="append", type=Path, default=[], dest="csv_paths", help="Benchmark/result CSV")
    parser.add_argument("--validation-report", action="append", type=Path, default=[], help="Validation JSON report")


def _select(api: ProductEvidenceApi, args: argparse.Namespace):
    ids = getattr(args, "ids", None)
    categories = getattr(args, "category", None)
    glob = getattr(args, "glob", None)
    contains = getattr(args, "contains", None)
    profile = getattr(args, "profile", None)
    limit = getattr(args, "limit", None)
    catalog = getattr(args, "catalog", None)
    if ids:
        return api.select_experiments(catalog_path=catalog, ids=ids, limit=limit)
    if categories or glob or contains:
        return api.select_experiments(
            catalog_path=catalog,
            categories=categories,
            glob=glob,
            contains=contains,
            limit=limit,
        )
    return api.select_experiments(catalog_path=catalog, profile=profile, limit=limit)


def cmd_list(api: ProductEvidenceApi, args: argparse.Namespace) -> int:
    selection = _select(api, args)
    if args.json:
        print(json.dumps(selection.to_dict(), indent=2, sort_keys=True))
    else:
        for item in selection.experiments:
            print(f"{item.id}\t{item.category}\t{item.command_count()} command(s)\t{item.objective}")
    return 0


def cmd_validate_catalog(api: ProductEvidenceApi, args: argparse.Namespace) -> int:
    result = api.validate_catalog(args.catalog)
    payload = result.to_dict()
    if args.output:
        write_json_atomic(args.output, payload)
    if args.report:
        write_text_atomic(args.report, render_catalog_report(result))
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if result.passed else 1


def cmd_plan_or_run(api: ProductEvidenceApi, args: argparse.Namespace, *, dry_run: bool) -> int:
    selection = _select(api, args)
    manifest = api.run_experiments(
        selection=selection,
        output_root=args.output_root,
        dry_run=dry_run,
        timeout_seconds=args.timeout,
    )
    write_text_atomic(Path(args.output_root) / "run-report.md", render_run_report(manifest))
    print(json.dumps(manifest.to_dict(), indent=2, sort_keys=True))
    return 0 if manifest.passed() else 1


def cmd_build_pack(api: ProductEvidenceApi, args: argparse.Namespace) -> int:
    manifest = api.build_evidence_pack(
        output_root=args.output_root,
        pack_id=args.pack_id,
        profile=args.profile,
        tag=args.tag,
        required=args.required,
    )
    if args.report:
        write_text_atomic(args.report, render_pack_report(manifest))
    print(json.dumps(manifest.to_dict(), indent=2, sort_keys=True))
    return 0 if manifest.passed() else 1


def cmd_validate_pack(api: ProductEvidenceApi, args: argparse.Namespace) -> int:
    result = api.validate_evidence_pack(output_root=args.output_root)
    if args.output:
        write_json_atomic(args.output, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("passed") else 1


def cmd_compare(api: ProductEvidenceApi, args: argparse.Namespace) -> int:
    report = api.compare_baselines(
        candidate_csv=args.candidate,
        baseline_csv=args.baseline,
        output_root=args.output_root,
        threshold=args.threshold,
    )
    if args.report:
        write_text_atomic(args.report, render_baseline_report(report))
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return 0 if report.passed() else 1


def cmd_readiness_matrix(api: ProductEvidenceApi, args: argparse.Namespace) -> int:
    payload = api.readiness_matrix(catalog_path=args.catalog)
    if args.output:
        write_json_atomic(args.output, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload.get("passed") else 1


def cmd_environment(api: ProductEvidenceApi, args: argparse.Namespace) -> int:
    snapshot = api.reproducibility()
    payload = snapshot.to_dict()
    if args.output:
        write_json_atomic(args.output, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if snapshot.passed() else 1


def _status_exit(payload: dict[str, object]) -> int:
    return 1 if payload.get("status") == "FAIL" or payload.get("passed") is False else 0


def cmd_compare_runs(api: ProductEvidenceApi, args: argparse.Namespace) -> int:
    payload = api.compare_runs(packs=args.pack, output_root=args.output_root)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return _status_exit(payload)


def cmd_validate_coverage(api: ProductEvidenceApi, args: argparse.Namespace) -> int:
    payload = api.validate_coverage(output_root=args.output_root, catalog_path=args.catalog)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return _status_exit(payload)


def cmd_validate_results(api: ProductEvidenceApi, args: argparse.Namespace) -> int:
    payload = api.validate_results(
        csv_paths=args.csv_paths,
        output_root=args.output_root,
        zero_is_fail=args.zero_is_fail,
        require_core_combos=not args.no_core_combos,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return _status_exit(payload)


def cmd_stats_summary(api: ProductEvidenceApi, args: argparse.Namespace) -> int:
    payload = api.statistical_sanity(
        csv_paths=args.csv_paths,
        output_root=args.output_root,
        min_samples=args.min_samples,
        cv_warn_threshold=args.cv_warn_threshold,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return _status_exit(payload)


def cmd_paper_report(api: ProductEvidenceApi, args: argparse.Namespace) -> int:
    payload = api.paper_evidence_report(
        output_root=args.output_root,
        reports={
            "reproducibility": args.reproducibility_report,
            "coverage": args.coverage_report,
            "baseline": args.baseline_report,
            "regression": args.regression_report,
            "quality": args.quality_report,
            "statistics": args.statistics_report,
        },
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return _status_exit(payload)


def cmd_recommend_deployment(api: ProductEvidenceApi, args: argparse.Namespace) -> int:
    payload = api.recommend_deployment(
        scenario_path=args.scenario,
        output_root=args.output_root,
        packs=args.pack,
        csv_paths=args.csv_paths,
        validation_reports=args.validation_report,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return _status_exit(payload)


def cmd_plan_evidence(api: ProductEvidenceApi, args: argparse.Namespace) -> int:
    payload = api.plan_evidence(
        scenario_path=args.scenario,
        output_root=args.output_root,
        catalog_path=args.catalog,
        packs=args.pack,
        csv_paths=args.csv_paths,
        validation_reports=args.validation_report,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return _status_exit(payload)


def cmd_claim_matrix(api: ProductEvidenceApi, args: argparse.Namespace) -> int:
    payload = api.claim_matrix(
        output_root=args.output_root,
        packs=args.pack,
        csv_paths=args.csv_paths,
        validation_reports=args.validation_report,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return _status_exit(payload)


def cmd_compare_scenarios(api: ProductEvidenceApi, args: argparse.Namespace) -> int:
    payload = api.compare_scenarios(
        scenario_paths=args.scenario,
        output_root=args.output_root,
        packs=args.pack,
        csv_paths=args.csv_paths,
        validation_reports=args.validation_report,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return _status_exit(payload)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    api = ProductEvidenceApi(args.module_path)
    try:
        if args.command == "list-experiments":
            return cmd_list(api, args)
        if args.command == "validate-catalog":
            return cmd_validate_catalog(api, args)
        if args.command == "plan-experiments":
            return cmd_plan_or_run(api, args, dry_run=True)
        if args.command == "run-experiments":
            return cmd_plan_or_run(api, args, dry_run=False)
        if args.command == "build-pack":
            return cmd_build_pack(api, args)
        if args.command == "validate-pack":
            return cmd_validate_pack(api, args)
        if args.command == "compare-baselines":
            return cmd_compare(api, args)
        if args.command == "readiness-matrix":
            return cmd_readiness_matrix(api, args)
        if args.command == "compare-runs":
            return cmd_compare_runs(api, args)
        if args.command == "validate-coverage":
            return cmd_validate_coverage(api, args)
        if args.command == "validate-results":
            return cmd_validate_results(api, args)
        if args.command == "stats-summary":
            return cmd_stats_summary(api, args)
        if args.command == "paper-report":
            return cmd_paper_report(api, args)
        if args.command == "recommend-deployment":
            return cmd_recommend_deployment(api, args)
        if args.command == "plan-evidence":
            return cmd_plan_evidence(api, args)
        if args.command == "claim-matrix":
            return cmd_claim_matrix(api, args)
        if args.command == "compare-scenarios":
            return cmd_compare_scenarios(api, args)
        if args.command == "environment":
            return cmd_environment(api, args)
        parser.error(f"unhandled command: {args.command}")
        return 2
    except ProductEvidenceError as exc:
        print(exc.format_for_console(), file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
