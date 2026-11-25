#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run pure-Python local tooling regression tests."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent


TOOL_TESTS = (
    "test_sovereign_audit_collect.py",
    "test_sovereign_audit_collect_qemu.py",
    "test_acvp_negative_scenario_floor.py",
    "test_pqc_asset_trace_map.py",
    "test_audit_evidence_coverage.py",
    "test_run_mutation_checks.py",
    "test_model_checks.py",
    "test_ct_trace_analysis.py",
    "test_ct_static_scan.py",
    "test_fault_inject.py",
    "test_fault_oracle.py",
    "test_fault_gate.py",
    "test_fault_gdb.py",
    "test_fault_timing_gate.py",
    "test_transparent_appraisal.py",
    "test_kit_provenance.py",
    "test_check_declared_defined.py",
    "test_pqc_evidence_graph.py",
    "test_firmware_assurance_digest.py",
    "test_assurance_ledger.py",
    "test_pqc_assurance_passport.py",
    "test_release_evidence_pack.py",
    "test_release_environment.py",
    "test_local_release_workflows.py",
    "test_pqc_assurance_profile.py",
    "test_pqc_evidence_quality.py",
    "test_migration_readiness_report.py",
    "test_pqc_claim_closure.py",
    "test_pqc_performance_hardening.py",
    "test_backend_update_evaluation.py",
    "test_benchmark_campaign.py",
    "test_benchmark_confidence.py",
    "test_optimize_metric_campaign.py",
    "test_ct_campaign.py",
    "test_acvp_json_schema.py",
    "test_device_evidence_token.py",
    "test_pqc_appraisal_evidence.py",
    "test_pqc_reference_values.py",
    "test_firmware_assurance_status.py",
    "test_acvp_json_interop.py",
    "test_acvp_json_interop_verifier.py",
    "test_pqc_build_provenance.py",
    "test_ct_sample_analysis.py",
    "test_backend_currency.py",
    "test_backend_contract.py",
    "test_provider_scope.py",
    "test_paper_comparison_campaign.py",
    "test_release_reference_values.py",
    "test_partner_review_scorecard.py",
    "test_evidence_tamper_drill.py",
    "test_research_product_dossier.py",
    "test_evidence_schema_contract.py",
    "test_research_experiment_catalog.py",
    "test_pqcp_product_catalog.py",
    "test_pqcp_product_runner.py",
    "test_pqcp_product_evidence_pack.py",
    "test_pqcp_product_baseline.py",
    "test_pqcp_product_cli.py",
    "test_pqcp_product_reproducibility.py",
    "test_pqcp_product_generated_rules.py",
    "test_pqcp_product_generated_selection.py",
    "test_pqcp_product_experiment_matrix.py",
    "test_pqcp_product_reproducibility_compare.py",
    "test_pqcp_product_coverage.py",
    "test_pqcp_product_result_quality.py",
    "test_pqcp_product_statistical_sanity.py",
    "test_pqcp_product_paper_evidence.py",
    "test_pqcp_product_deployment_decision.py",
    "test_pqcp_product_cross_framework_bridge.py",
)

GENERATED_CHECKS = (
    "generate_runtime_channel_policy_catalogs.py",
    "generate_operation_conformance_catalogs.py",
    "generate_operation_plan_catalogs.py",
    "generate_operation_scenario_catalogs.py",
    "generate_runtime_channel_guard_catalogs.py",
    "generate_operation_transition_catalogs.py",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run pure-Python regression tests for local PQCP release tooling."
    )
    parser.add_argument(
        "--module-path",
        type=Path,
        default=REPO_ROOT,
        help="PQCP module repository root.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List test scripts without running them.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    module_path = args.module_path.resolve()
    script_dir = module_path / "scripts"

    tests = [script_dir / name for name in TOOL_TESTS]
    missing = [path for path in tests if not path.exists()]
    if missing:
        print("FAIL: missing local tooling test script(s):")
        for path in missing:
            print(f"  - {path}")
        return 1

    if args.list:
        for name in GENERATED_CHECKS:
            print(f"scripts/{name} --output-dir <tmp> (then --check)")
        for path in tests:
            print(path.relative_to(module_path))
        return 0

    # Generate every catalog into a scratch directory, then re-run each
    # generator with --check against it: this proves the generators run and
    # that their output is deterministic.
    with tempfile.TemporaryDirectory(prefix="pqcp-generated-") as generated:
        for name in GENERATED_CHECKS:
            path = script_dir / name
            print(f"\n[RUN ] {name}")
            for extra in ([], ["--check"]):
                result = subprocess.run(
                    [sys.executable, str(path), *extra, "--output-dir", generated],
                    cwd=str(module_path),
                    stdout=subprocess.DEVNULL,
                    check=False,
                )
                if result.returncode != 0:
                    print(f"[FAIL] {name} {' '.join(extra)} exited with {result.returncode}")
                    return result.returncode
            print(f"[PASS] {name} (deterministic)")

    for path in tests:
        print(f"\n[RUN ] {path.name}")
        result = subprocess.run([sys.executable, str(path)], cwd=str(module_path), check=False)
        if result.returncode != 0:
            print(f"[FAIL] {path.name} exited with {result.returncode}")
            return result.returncode
        print(f"[PASS] {path.name}")

    print("\n[PASS] local tooling regression tests completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
