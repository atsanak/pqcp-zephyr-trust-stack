#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Generated executable rules for the research/product experiment catalog."""

from __future__ import annotations

from pathlib import Path

from .errors import Diagnostic, error, warning
from .models import ExperimentSpec

RULE_IDS: tuple[str, ...] = (
    'claim.release_version_consistency',
    'claim.release_tag_integrity',
    'claim.kat_offline_provenance',
    'claim.kat_mlkem_512',
    'claim.kat_mlkem_768',
    'claim.kat_mlkem_1024',
    'claim.kat_mldsa_44',
    'claim.kat_mldsa_65',
    'claim.kat_mldsa_87',
    'claim.benchmark_csv_validity',
    'claim.benchmark_provenance_binding',
    'claim.benchmark_mlkem_throughput',
    'claim.benchmark_mldsa_throughput',
    'claim.benchmark_distribution_quality',
    'claim.cost_of_assurance_guardrails',
    'claim.release_local_bundle',
    'claim.release_transcript_binding',
    'claim.acvp_negative_path_rejection',
    'claim.acvp_timeout_recovery',
    'claim.acvp_negative_scenarios_replay',
    'claim.acvp_mlkem_negative_paths',
    'claim.acvp_mldsa_negative_paths',
    'claim.acvp_negative_scenario_floor',
    'claim.security_asan_clean',
    'claim.security_ubsan_clean',
    'claim.boot_kat_self_verify',
    'claim.security_ct_smoke',
    'claim.security_mlkem_decap_instruction_policy',
    'claim.supply_chain_cbom_crypto_inventory',
    'claim.supply_chain_pqc_assurance_attestation',
    'claim.supply_chain_crypto_asset_traceability',
    'claim.supply_chain_evidence_graph_integrity',
    'claim.release_policy_pass',
    'claim.firmware_assurance_digest_manifest',
    'claim.firmware_assurance_digest_embeddable',
    'claim.supply_chain_assurance_profile_policy',
    'claim.supply_chain_evidence_quality_index',
    'claim.crypto_agility_profile_separation',
    'claim.release_migration_readiness',
    'claim.security_production_rng_policy',
    'claim.release_reference_values',
    'claim.firmware_assurance_status_report',
    'claim.acvp_json_interop',
    'claim.supply_chain_slsa_build_provenance',
    'claim.security_ct_sample_analysis',
    'claim.release_evidence_appraisal_profile',
    'claim.supply_chain_backend_update_evaluation',
    'claim.benchmark_campaign_reproducibility',
    'claim.benchmark_external_reference_context',
    'claim.security_ct_campaign_analysis',
    'claim.acvp_json_schema_coverage',
    'claim.firmware_device_evidence_token',
    'claim.release_strict_partner_policy',
    'claim.supply_chain_backend_contract',
    'claim.supply_chain_liboqs_non_native_scope',
    'claim.benchmark_paper_comparison_export',
    'claim.release_reference_provider_scope',
    'asset.crypto_mlkem_512',
    'asset.crypto_mlkem_768',
    'asset.crypto_mlkem_1024',
    'asset.crypto_mldsa_44',
    'asset.crypto_mldsa_65',
    'asset.crypto_mldsa_87',
    'asset.validation_acvp_serial',
    'asset.validation_tls_selftest',
    'asset.rng_zephyr_entropy',
    'asset.rng_psa',
    'asset.rng_deterministic_test',
    'asset.boot_kat_self_verify',
    'asset.security_ct_smoke',
    'asset.crypto_slhdsa_external',
    'asset.crypto_hqc_external',
    'artifact.acvp_json_interop_result',
    'artifact.acvp_json_schema_result',
    'artifact.acvp_json_transcript_manifest',
    'artifact.acvp_negative_scenario_floor_result',
    'artifact.assurance_ledger',
    'artifact.assurance_ledger_markdown',
    'artifact.assurance_report_html',
    'artifact.backend_contract_result',
    'artifact.backend_update_evaluation',
    'artifact.benchmark_campaign_result',
    'artifact.benchmark_campaign_verify_result',
    'artifact.benchmark_confidence_result',
    'artifact.benchmark_provenance',
    'artifact.benchmark_results_csv',
    'artifact.benchmark_summary_markdown',
    'artifact.cost_of_assurance_evidence',
    'artifact.ct_campaign_result',
    'artifact.ct_instruction_policy_result',
    'artifact.ct_sample_analysis_result',
    'artifact.device_evidence_token',
    'artifact.device_evidence_token_result',
    'artifact.evidence_tamper_drill_result',
    'artifact.evidence_transcript_manifest',
    'artifact.external_non_native_inventory',
    'artifact.firmware_assurance_status_result',
    'artifact.firmware_digest_header',
    'artifact.mcu_protocol_footprint_csv',
    'artifact.paper_comparison_campaign_csv',
    'artifact.paper_comparison_campaign_json',
    'artifact.partner_review_scorecard',
    'artifact.partner_review_scorecard_markdown',
    'artifact.partner_review_scorecard_result',
    'artifact.pqc_appraisal_evidence',
    'artifact.pqc_appraisal_result',
    'artifact.pqc_asset_trace_result',
    'artifact.pqc_assurance_digest',
    'artifact.pqc_assurance_profile_result',
    'artifact.pqc_attestation',
    'artifact.pqc_build_provenance',
    'artifact.pqc_build_provenance_result',
    'artifact.pqc_cbom',
    'artifact.pqc_claim_closure_result',
    'artifact.pqc_environment_result',
    'artifact.pqc_evidence_graph_json',
    'artifact.pqc_evidence_graph_markdown',
    'artifact.pqc_evidence_quality_result',
    'artifact.pqc_migration_readiness_json',
    'artifact.pqc_migration_readiness_markdown',
    'artifact.pqc_policy_result',
    'artifact.pqc_reference_values',
    'artifact.pqc_reference_values_result',
    'artifact.provider_scope_result',
    'artifact.release_manifest',
    'artifact.release_notes_markdown',
    'artifact.release_reference_values_result',
    'benchmark.paper_comparable_campaign',
    'benchmark.external_reference_import',
    'acvp.malformed_then_valid_recovery',
    'acvp.operation_schema_coverage',
    'ct.sample_balance',
    'ct.instruction_policy_coverage',
    'hardware.uart_transcript_capture',
    'hardware.entropy_source_review',
    'product.cli_release_pack',
    'product.dashboard_ingest_contract',
    'product.customer_policy_overlay',
    'product.signed_pack_readiness',
)

CATEGORY_RULE_COUNTS: dict[str, int] = {
    'acvp_interop': 2,
    'artifact_schema': 55,
    'asset_traceability': 15,
    'benchmark_methodology': 2,
    'claim_replay': 57,
    'hardware_promotion': 2,
    'product_packaging': 4,
    'side_channel_smoke': 2,
}

def _contains_action(text: str) -> bool:
    lower = text.lower()
    return any(word in lower for word in ("remove", "corrupt", "tamper", "malformed", "missing", "invalid", "stale", "duplicate"))

def _check_common(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    if len(experiment.objective.split()) < 6:
        diagnostics.append(error("rule_objective_depth", experiment.id, "objective is too short for a replayable experiment"))
    if len(experiment.acceptance_criteria) < 3:
        diagnostics.append(error("rule_acceptance_floor", experiment.id, "acceptance criteria floor not met"))
    if not _contains_action(experiment.negative_control):
        diagnostics.append(warning("rule_negative_control_action", experiment.id, "negative control should name an explicit falsification action"))
    for rel in experiment.repository_inputs:
        if not (module_path / rel).exists():
            diagnostics.append(error("rule_missing_input", f"{experiment.id}:{rel}", "repository input missing"))
    return diagnostics

def validate_claim_release_version_consistency(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.release_version_consistency."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.release_version_consistency'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_release_tag_integrity(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.release_tag_integrity."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.release_tag_integrity'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_kat_offline_provenance(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.kat_offline_provenance."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.kat_offline_provenance'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_kat_mlkem_512(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.kat_mlkem_512."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.kat_mlkem_512'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_kat_mlkem_768(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.kat_mlkem_768."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.kat_mlkem_768'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_kat_mlkem_1024(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.kat_mlkem_1024."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.kat_mlkem_1024'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_kat_mldsa_44(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.kat_mldsa_44."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.kat_mldsa_44'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_kat_mldsa_65(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.kat_mldsa_65."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.kat_mldsa_65'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_kat_mldsa_87(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.kat_mldsa_87."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.kat_mldsa_87'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_benchmark_csv_validity(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.benchmark_csv_validity."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.benchmark_csv_validity'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_benchmark_provenance_binding(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.benchmark_provenance_binding."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.benchmark_provenance_binding'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_benchmark_mlkem_throughput(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.benchmark_mlkem_throughput."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.benchmark_mlkem_throughput'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_benchmark_mldsa_throughput(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.benchmark_mldsa_throughput."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.benchmark_mldsa_throughput'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_benchmark_distribution_quality(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.benchmark_distribution_quality."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.benchmark_distribution_quality'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_cost_of_assurance_guardrails(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.cost_of_assurance_guardrails."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.cost_of_assurance_guardrails'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_release_local_bundle(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.release_local_bundle."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.release_local_bundle'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_release_transcript_binding(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.release_transcript_binding."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.release_transcript_binding'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_acvp_negative_path_rejection(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.acvp_negative_path_rejection."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.acvp_negative_path_rejection'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_acvp_timeout_recovery(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.acvp_timeout_recovery."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.acvp_timeout_recovery'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_acvp_negative_scenarios_replay(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.acvp_negative_scenarios_replay."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.acvp_negative_scenarios_replay'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_acvp_mlkem_negative_paths(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.acvp_mlkem_negative_paths."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.acvp_mlkem_negative_paths'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_acvp_mldsa_negative_paths(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.acvp_mldsa_negative_paths."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.acvp_mldsa_negative_paths'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_acvp_negative_scenario_floor(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.acvp_negative_scenario_floor."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.acvp_negative_scenario_floor'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_security_asan_clean(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.security_asan_clean."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.security_asan_clean'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_security_ubsan_clean(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.security_ubsan_clean."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.security_ubsan_clean'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_boot_kat_self_verify(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.boot_kat_self_verify."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.boot_kat_self_verify'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_security_ct_smoke(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.security_ct_smoke."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.security_ct_smoke'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_security_mlkem_decap_instruction_policy(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.security_mlkem_decap_instruction_policy."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.security_mlkem_decap_instruction_policy'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_supply_chain_cbom_crypto_inventory(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.supply_chain_cbom_crypto_inventory."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.supply_chain_cbom_crypto_inventory'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_supply_chain_pqc_assurance_attestation(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.supply_chain_pqc_assurance_attestation."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.supply_chain_pqc_assurance_attestation'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_supply_chain_crypto_asset_traceability(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.supply_chain_crypto_asset_traceability."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.supply_chain_crypto_asset_traceability'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_supply_chain_evidence_graph_integrity(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.supply_chain_evidence_graph_integrity."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.supply_chain_evidence_graph_integrity'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_release_policy_pass(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.release_policy_pass."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.release_policy_pass'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_firmware_assurance_digest_manifest(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.firmware_assurance_digest_manifest."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.firmware_assurance_digest_manifest'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_firmware_assurance_digest_embeddable(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.firmware_assurance_digest_embeddable."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.firmware_assurance_digest_embeddable'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_supply_chain_assurance_profile_policy(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.supply_chain_assurance_profile_policy."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.supply_chain_assurance_profile_policy'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_supply_chain_evidence_quality_index(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.supply_chain_evidence_quality_index."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.supply_chain_evidence_quality_index'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_crypto_agility_profile_separation(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.crypto_agility_profile_separation."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.crypto_agility_profile_separation'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_release_migration_readiness(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.release_migration_readiness."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.release_migration_readiness'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_security_production_rng_policy(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.security_production_rng_policy."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.security_production_rng_policy'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_release_reference_values(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.release_reference_values."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.release_reference_values'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_firmware_assurance_status_report(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.firmware_assurance_status_report."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.firmware_assurance_status_report'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_acvp_json_interop(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.acvp_json_interop."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.acvp_json_interop'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_supply_chain_slsa_build_provenance(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.supply_chain_slsa_build_provenance."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.supply_chain_slsa_build_provenance'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_security_ct_sample_analysis(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.security_ct_sample_analysis."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.security_ct_sample_analysis'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_release_evidence_appraisal_profile(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.release_evidence_appraisal_profile."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.release_evidence_appraisal_profile'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_supply_chain_backend_update_evaluation(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.supply_chain_backend_update_evaluation."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.supply_chain_backend_update_evaluation'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_benchmark_campaign_reproducibility(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.benchmark_campaign_reproducibility."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.benchmark_campaign_reproducibility'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_benchmark_external_reference_context(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.benchmark_external_reference_context."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.benchmark_external_reference_context'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_security_ct_campaign_analysis(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.security_ct_campaign_analysis."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.security_ct_campaign_analysis'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_acvp_json_schema_coverage(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.acvp_json_schema_coverage."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.acvp_json_schema_coverage'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_firmware_device_evidence_token(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.firmware_device_evidence_token."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.firmware_device_evidence_token'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_release_strict_partner_policy(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.release_strict_partner_policy."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.release_strict_partner_policy'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_supply_chain_backend_contract(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.supply_chain_backend_contract."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.supply_chain_backend_contract'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_supply_chain_liboqs_non_native_scope(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.supply_chain_liboqs_non_native_scope."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.supply_chain_liboqs_non_native_scope'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_benchmark_paper_comparison_export(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.benchmark_paper_comparison_export."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.benchmark_paper_comparison_export'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_claim_release_reference_provider_scope(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for claim.release_reference_provider_scope."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'claim.release_reference_provider_scope'
    expected_category = 'claim_replay'
    expected_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    expected_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    expected_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_asset_crypto_mlkem_512(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for asset.crypto_mlkem_512."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'asset.crypto_mlkem_512'
    expected_category = 'asset_traceability'
    expected_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mlkem.h', 'src/mlkem_zephyr.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_acvp_kat/src/main.c', 'tests/ztest_ct_smoke/src/main.c', 'scripts/verify_ct_instruction_policy.py')
    expected_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    expected_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_asset_crypto_mlkem_768(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for asset.crypto_mlkem_768."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'asset.crypto_mlkem_768'
    expected_category = 'asset_traceability'
    expected_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mlkem.h', 'src/mlkem_zephyr.c', 'src/psa_mlkem_driver.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_ct_smoke/src/main.c', 'tests/ztest_primitive/src/main.c', 'scripts/verify_ct_instruction_policy.py')
    expected_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    expected_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_asset_crypto_mlkem_1024(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for asset.crypto_mlkem_1024."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'asset.crypto_mlkem_1024'
    expected_category = 'asset_traceability'
    expected_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mlkem.h', 'src/mlkem_zephyr.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_acvp_kat/src/main.c', 'tests/ztest_ct_smoke/src/main.c', 'scripts/verify_ct_instruction_policy.py')
    expected_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    expected_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_asset_crypto_mldsa_44(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for asset.crypto_mldsa_44."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'asset.crypto_mldsa_44'
    expected_category = 'asset_traceability'
    expected_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mldsa.h', 'src/mldsa_zephyr.c', 'src/mldsa_streaming.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_acvp_kat/src/main.c')
    expected_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    expected_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_asset_crypto_mldsa_65(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for asset.crypto_mldsa_65."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'asset.crypto_mldsa_65'
    expected_category = 'asset_traceability'
    expected_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mldsa.h', 'src/mldsa_zephyr.c', 'src/mldsa_streaming.c', 'src/psa_mldsa_driver.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_primitive/src/main.c')
    expected_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    expected_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_asset_crypto_mldsa_87(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for asset.crypto_mldsa_87."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'asset.crypto_mldsa_87'
    expected_category = 'asset_traceability'
    expected_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mldsa.h', 'src/mldsa_zephyr.c', 'src/mldsa_streaming.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_acvp_kat/src/main.c')
    expected_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    expected_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_asset_validation_acvp_serial(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for asset.validation_acvp_serial."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'asset.validation_acvp_serial'
    expected_category = 'asset_traceability'
    expected_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/acvp_cmd.h', 'src/acvp_cmd.c', 'samples/pqcp_serial_acvp/src/main.c', 'scripts/acvp_negative_scenarios.json', 'scripts/acvp_negative_scenario_floor.json', 'tests/ztest_acvp_serial/src/main.c', 'tests/ztest_acvp_serial_negative/src/main.c')
    expected_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    expected_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_asset_validation_tls_selftest(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for asset.validation_tls_selftest."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'asset.validation_tls_selftest'
    expected_category = 'asset_traceability'
    expected_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/tls_selftest.h', 'src/tls_selftest.c', 'samples/pqcp_tls_mbedtls_psa/src/main.c', 'tests/ztest_tls_selftest/src/main.c')
    expected_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    expected_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_asset_rng_zephyr_entropy(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for asset.rng_zephyr_entropy."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'asset.rng_zephyr_entropy'
    expected_category = 'asset_traceability'
    expected_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/rng.h', 'src/rng_common.c', 'src/rng_zephyr_entropy.c', 'tests/ztest_rng/src/main.c')
    expected_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    expected_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_asset_rng_psa(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for asset.rng_psa."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'asset.rng_psa'
    expected_category = 'asset_traceability'
    expected_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/rng.h', 'src/rng_common.c', 'src/rng_psa.c', 'tests/ztest_rng/src/main.c')
    expected_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    expected_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_asset_rng_deterministic_test(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for asset.rng_deterministic_test."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'asset.rng_deterministic_test'
    expected_category = 'asset_traceability'
    expected_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/rng.h', 'src/rng_common.c', 'src/rng_deterministic.c', 'samples/pqcp_kat_deterministic/src/main.c', 'tests/ztest_primitive/src/main.c')
    expected_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    expected_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_asset_boot_kat_self_verify(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for asset.boot_kat_self_verify."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'asset.boot_kat_self_verify'
    expected_category = 'asset_traceability'
    expected_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'src/kat_boot_verify.c', 'tests/ztest_kat_boot_verify/src/main.c')
    expected_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    expected_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_asset_security_ct_smoke(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for asset.security_ct_smoke."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'asset.security_ct_smoke'
    expected_category = 'asset_traceability'
    expected_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'tests/ztest_ct_smoke/src/main.c', 'scripts/verify_ct_instruction_policy.py')
    expected_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    expected_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_asset_crypto_slhdsa_external(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for asset.crypto_slhdsa_external."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'asset.crypto_slhdsa_external'
    expected_category = 'asset_traceability'
    expected_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'scripts/export_liboqs_inventory.py', 'scripts/verify_provider_scope.py')
    expected_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    expected_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_asset_crypto_hqc_external(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for asset.crypto_hqc_external."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'asset.crypto_hqc_external'
    expected_category = 'asset_traceability'
    expected_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'scripts/export_liboqs_inventory.py', 'scripts/verify_provider_scope.py')
    expected_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    expected_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_acvp_json_interop_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.acvp_json_interop_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.acvp_json_interop_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_acvp_json_schema_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.acvp_json_schema_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.acvp_json_schema_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_acvp_json_transcript_manifest(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.acvp_json_transcript_manifest."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.acvp_json_transcript_manifest'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_acvp_negative_scenario_floor_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.acvp_negative_scenario_floor_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.acvp_negative_scenario_floor_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_assurance_ledger(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.assurance_ledger."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.assurance_ledger'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_assurance_ledger_markdown(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.assurance_ledger_markdown."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.assurance_ledger_markdown'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_assurance_report_html(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.assurance_report_html."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.assurance_report_html'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_backend_contract_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.backend_contract_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.backend_contract_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_backend_update_evaluation(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.backend_update_evaluation."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.backend_update_evaluation'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_benchmark_campaign_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.benchmark_campaign_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.benchmark_campaign_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_benchmark_campaign_verify_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.benchmark_campaign_verify_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.benchmark_campaign_verify_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_benchmark_confidence_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.benchmark_confidence_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.benchmark_confidence_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_benchmark_provenance(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.benchmark_provenance."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.benchmark_provenance'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_benchmark_results_csv(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.benchmark_results_csv."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.benchmark_results_csv'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_benchmark_summary_markdown(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.benchmark_summary_markdown."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.benchmark_summary_markdown'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_cost_of_assurance_evidence(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.cost_of_assurance_evidence."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.cost_of_assurance_evidence'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_ct_campaign_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.ct_campaign_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.ct_campaign_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_ct_instruction_policy_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.ct_instruction_policy_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.ct_instruction_policy_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_ct_sample_analysis_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.ct_sample_analysis_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.ct_sample_analysis_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_device_evidence_token(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.device_evidence_token."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.device_evidence_token'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_device_evidence_token_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.device_evidence_token_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.device_evidence_token_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_evidence_tamper_drill_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.evidence_tamper_drill_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.evidence_tamper_drill_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_evidence_transcript_manifest(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.evidence_transcript_manifest."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.evidence_transcript_manifest'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_external_non_native_inventory(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.external_non_native_inventory."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.external_non_native_inventory'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_firmware_assurance_status_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.firmware_assurance_status_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.firmware_assurance_status_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_firmware_digest_header(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.firmware_digest_header."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.firmware_digest_header'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_mcu_protocol_footprint_csv(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.mcu_protocol_footprint_csv."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.mcu_protocol_footprint_csv'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_paper_comparison_campaign_csv(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.paper_comparison_campaign_csv."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.paper_comparison_campaign_csv'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_paper_comparison_campaign_json(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.paper_comparison_campaign_json."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.paper_comparison_campaign_json'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_partner_review_scorecard(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.partner_review_scorecard."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.partner_review_scorecard'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_partner_review_scorecard_markdown(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.partner_review_scorecard_markdown."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.partner_review_scorecard_markdown'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_partner_review_scorecard_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.partner_review_scorecard_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.partner_review_scorecard_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_appraisal_evidence(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_appraisal_evidence."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_appraisal_evidence'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_appraisal_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_appraisal_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_appraisal_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_asset_trace_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_asset_trace_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_asset_trace_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_assurance_digest(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_assurance_digest."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_assurance_digest'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_assurance_profile_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_assurance_profile_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_assurance_profile_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_attestation(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_attestation."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_attestation'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_build_provenance(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_build_provenance."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_build_provenance'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_build_provenance_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_build_provenance_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_build_provenance_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_cbom(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_cbom."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_cbom'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_claim_closure_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_claim_closure_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_claim_closure_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_environment_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_environment_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_environment_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_evidence_graph_json(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_evidence_graph_json."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_evidence_graph_json'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_evidence_graph_markdown(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_evidence_graph_markdown."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_evidence_graph_markdown'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_evidence_quality_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_evidence_quality_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_evidence_quality_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_migration_readiness_json(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_migration_readiness_json."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_migration_readiness_json'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_migration_readiness_markdown(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_migration_readiness_markdown."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_migration_readiness_markdown'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_policy_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_policy_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_policy_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_reference_values(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_reference_values."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_reference_values'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_pqc_reference_values_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.pqc_reference_values_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.pqc_reference_values_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_provider_scope_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.provider_scope_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.provider_scope_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_release_manifest(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.release_manifest."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.release_manifest'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_release_notes_markdown(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.release_notes_markdown."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.release_notes_markdown'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_artifact_release_reference_values_result(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for artifact.release_reference_values_result."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'artifact.release_reference_values_result'
    expected_category = 'artifact_schema'
    expected_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    expected_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    expected_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_benchmark_paper_comparable_campaign(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for benchmark.paper_comparable_campaign."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'benchmark.paper_comparable_campaign'
    expected_category = 'benchmark_methodology'
    expected_inputs = ('scripts/run_benchmark_campaign.py',)
    expected_commands = ('python3 scripts/run_benchmark_campaign.py --help',)
    expected_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_benchmark_external_reference_import(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for benchmark.external_reference_import."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'benchmark.external_reference_import'
    expected_category = 'benchmark_methodology'
    expected_inputs = ('scripts/run_paper_comparison_campaign.py',)
    expected_commands = ('python3 scripts/run_paper_comparison_campaign.py --help',)
    expected_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_acvp_malformed_then_valid_recovery(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for acvp.malformed_then_valid_recovery."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'acvp.malformed_then_valid_recovery'
    expected_category = 'acvp_interop'
    expected_inputs = ('scripts/run_acvp_json_vectors.py',)
    expected_commands = ('python3 scripts/run_acvp_json_vectors.py --help',)
    expected_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_acvp_operation_schema_coverage(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for acvp.operation_schema_coverage."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'acvp.operation_schema_coverage'
    expected_category = 'acvp_interop'
    expected_inputs = ('scripts/validate_acvp_json_schema.py',)
    expected_commands = ('python3 scripts/validate_acvp_json_schema.py --help',)
    expected_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_ct_sample_balance(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for ct.sample_balance."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'ct.sample_balance'
    expected_category = 'side_channel_smoke'
    expected_inputs = ('scripts/analyze_ct_samples.py',)
    expected_commands = ('python3 scripts/analyze_ct_samples.py --help',)
    expected_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_ct_instruction_policy_coverage(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for ct.instruction_policy_coverage."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'ct.instruction_policy_coverage'
    expected_category = 'side_channel_smoke'
    expected_inputs = ('scripts/verify_ct_instruction_policy.py',)
    expected_commands = ('python3 scripts/verify_ct_instruction_policy.py --help',)
    expected_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_hardware_uart_transcript_capture(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for hardware.uart_transcript_capture."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'hardware.uart_transcript_capture'
    expected_category = 'hardware_promotion'
    expected_inputs = ('scripts/run_hardware_benchmarks.py',)
    expected_commands = ('python3 scripts/run_hardware_benchmarks.py --help',)
    expected_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_hardware_entropy_source_review(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for hardware.entropy_source_review."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'hardware.entropy_source_review'
    expected_category = 'hardware_promotion'
    expected_inputs = ('include/pqcp_zephyr/rng.h',)
    expected_commands = ('python3 scripts/run_local_tool_tests.py --list',)
    expected_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_product_cli_release_pack(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for product.cli_release_pack."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'product.cli_release_pack'
    expected_category = 'product_packaging'
    expected_inputs = ('scripts/verify_product_readiness.py',)
    expected_commands = ('python3 scripts/verify_product_readiness.py --help',)
    expected_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_product_dashboard_ingest_contract(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for product.dashboard_ingest_contract."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'product.dashboard_ingest_contract'
    expected_category = 'product_packaging'
    expected_inputs = ('docs/evidence-schema-contract.md',)
    expected_commands = ('python3 scripts/run_local_tool_tests.py --list',)
    expected_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_product_customer_policy_overlay(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for product.customer_policy_overlay."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'product.customer_policy_overlay'
    expected_category = 'product_packaging'
    expected_inputs = ('scripts/pqc_assurance_policy.json',)
    expected_commands = ('python3 scripts/run_local_tool_tests.py --list',)
    expected_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

def validate_product_signed_pack_readiness(experiment: ExperimentSpec, module_path: Path) -> list[Diagnostic]:
    """Validate catalog contract for product.signed_pack_readiness."""
    diagnostics = _check_common(experiment, module_path)
    expected_id = 'product.signed_pack_readiness'
    expected_category = 'product_packaging'
    expected_inputs = ('docs/release.md',)
    expected_commands = ('python3 scripts/run_local_tool_tests.py --list',)
    expected_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    min_acceptance = 5
    if experiment.id != expected_id:
        diagnostics.append(error("rule_id_mismatch", expected_id, f"got {experiment.id}"))
    if experiment.category != expected_category:
        diagnostics.append(error("rule_category_mismatch", expected_id, f"expected {expected_category}, got {experiment.category}"))
    missing_inputs = sorted(set(expected_inputs) - set(experiment.repository_inputs))
    if missing_inputs:
        diagnostics.append(error("rule_input_removed", expected_id, "catalog input(s) removed: " + ", ".join(missing_inputs)))
    missing_commands = sorted(set(expected_commands) - set(experiment.commands))
    if missing_commands:
        diagnostics.append(error("rule_command_removed", expected_id, "catalog command(s) removed: " + "; ".join(missing_commands)))
    missing_outputs = sorted(set(expected_outputs) - set(experiment.expected_outputs))
    if missing_outputs:
        diagnostics.append(error("rule_output_removed", expected_id, "expected output(s) removed: " + ", ".join(missing_outputs)))
    if len(experiment.acceptance_criteria) < min_acceptance:
        diagnostics.append(error("rule_acceptance_weakened", expected_id, "acceptance criteria count decreased"))
    if not any(command.startswith("python3 ") or " python3 " in command or command.startswith("west ") for command in experiment.commands):
        diagnostics.append(warning("rule_command_executable", expected_id, "experiment lacks a python3/west command"))
    return diagnostics

RULES = {
    'claim.release_version_consistency': validate_claim_release_version_consistency,
    'claim.release_tag_integrity': validate_claim_release_tag_integrity,
    'claim.kat_offline_provenance': validate_claim_kat_offline_provenance,
    'claim.kat_mlkem_512': validate_claim_kat_mlkem_512,
    'claim.kat_mlkem_768': validate_claim_kat_mlkem_768,
    'claim.kat_mlkem_1024': validate_claim_kat_mlkem_1024,
    'claim.kat_mldsa_44': validate_claim_kat_mldsa_44,
    'claim.kat_mldsa_65': validate_claim_kat_mldsa_65,
    'claim.kat_mldsa_87': validate_claim_kat_mldsa_87,
    'claim.benchmark_csv_validity': validate_claim_benchmark_csv_validity,
    'claim.benchmark_provenance_binding': validate_claim_benchmark_provenance_binding,
    'claim.benchmark_mlkem_throughput': validate_claim_benchmark_mlkem_throughput,
    'claim.benchmark_mldsa_throughput': validate_claim_benchmark_mldsa_throughput,
    'claim.benchmark_distribution_quality': validate_claim_benchmark_distribution_quality,
    'claim.cost_of_assurance_guardrails': validate_claim_cost_of_assurance_guardrails,
    'claim.release_local_bundle': validate_claim_release_local_bundle,
    'claim.release_transcript_binding': validate_claim_release_transcript_binding,
    'claim.acvp_negative_path_rejection': validate_claim_acvp_negative_path_rejection,
    'claim.acvp_timeout_recovery': validate_claim_acvp_timeout_recovery,
    'claim.acvp_negative_scenarios_replay': validate_claim_acvp_negative_scenarios_replay,
    'claim.acvp_mlkem_negative_paths': validate_claim_acvp_mlkem_negative_paths,
    'claim.acvp_mldsa_negative_paths': validate_claim_acvp_mldsa_negative_paths,
    'claim.acvp_negative_scenario_floor': validate_claim_acvp_negative_scenario_floor,
    'claim.security_asan_clean': validate_claim_security_asan_clean,
    'claim.security_ubsan_clean': validate_claim_security_ubsan_clean,
    'claim.boot_kat_self_verify': validate_claim_boot_kat_self_verify,
    'claim.security_ct_smoke': validate_claim_security_ct_smoke,
    'claim.security_mlkem_decap_instruction_policy': validate_claim_security_mlkem_decap_instruction_policy,
    'claim.supply_chain_cbom_crypto_inventory': validate_claim_supply_chain_cbom_crypto_inventory,
    'claim.supply_chain_pqc_assurance_attestation': validate_claim_supply_chain_pqc_assurance_attestation,
    'claim.supply_chain_crypto_asset_traceability': validate_claim_supply_chain_crypto_asset_traceability,
    'claim.supply_chain_evidence_graph_integrity': validate_claim_supply_chain_evidence_graph_integrity,
    'claim.release_policy_pass': validate_claim_release_policy_pass,
    'claim.firmware_assurance_digest_manifest': validate_claim_firmware_assurance_digest_manifest,
    'claim.firmware_assurance_digest_embeddable': validate_claim_firmware_assurance_digest_embeddable,
    'claim.supply_chain_assurance_profile_policy': validate_claim_supply_chain_assurance_profile_policy,
    'claim.supply_chain_evidence_quality_index': validate_claim_supply_chain_evidence_quality_index,
    'claim.crypto_agility_profile_separation': validate_claim_crypto_agility_profile_separation,
    'claim.release_migration_readiness': validate_claim_release_migration_readiness,
    'claim.security_production_rng_policy': validate_claim_security_production_rng_policy,
    'claim.release_reference_values': validate_claim_release_reference_values,
    'claim.firmware_assurance_status_report': validate_claim_firmware_assurance_status_report,
    'claim.acvp_json_interop': validate_claim_acvp_json_interop,
    'claim.supply_chain_slsa_build_provenance': validate_claim_supply_chain_slsa_build_provenance,
    'claim.security_ct_sample_analysis': validate_claim_security_ct_sample_analysis,
    'claim.release_evidence_appraisal_profile': validate_claim_release_evidence_appraisal_profile,
    'claim.supply_chain_backend_update_evaluation': validate_claim_supply_chain_backend_update_evaluation,
    'claim.benchmark_campaign_reproducibility': validate_claim_benchmark_campaign_reproducibility,
    'claim.benchmark_external_reference_context': validate_claim_benchmark_external_reference_context,
    'claim.security_ct_campaign_analysis': validate_claim_security_ct_campaign_analysis,
    'claim.acvp_json_schema_coverage': validate_claim_acvp_json_schema_coverage,
    'claim.firmware_device_evidence_token': validate_claim_firmware_device_evidence_token,
    'claim.release_strict_partner_policy': validate_claim_release_strict_partner_policy,
    'claim.supply_chain_backend_contract': validate_claim_supply_chain_backend_contract,
    'claim.supply_chain_liboqs_non_native_scope': validate_claim_supply_chain_liboqs_non_native_scope,
    'claim.benchmark_paper_comparison_export': validate_claim_benchmark_paper_comparison_export,
    'claim.release_reference_provider_scope': validate_claim_release_reference_provider_scope,
    'asset.crypto_mlkem_512': validate_asset_crypto_mlkem_512,
    'asset.crypto_mlkem_768': validate_asset_crypto_mlkem_768,
    'asset.crypto_mlkem_1024': validate_asset_crypto_mlkem_1024,
    'asset.crypto_mldsa_44': validate_asset_crypto_mldsa_44,
    'asset.crypto_mldsa_65': validate_asset_crypto_mldsa_65,
    'asset.crypto_mldsa_87': validate_asset_crypto_mldsa_87,
    'asset.validation_acvp_serial': validate_asset_validation_acvp_serial,
    'asset.validation_tls_selftest': validate_asset_validation_tls_selftest,
    'asset.rng_zephyr_entropy': validate_asset_rng_zephyr_entropy,
    'asset.rng_psa': validate_asset_rng_psa,
    'asset.rng_deterministic_test': validate_asset_rng_deterministic_test,
    'asset.boot_kat_self_verify': validate_asset_boot_kat_self_verify,
    'asset.security_ct_smoke': validate_asset_security_ct_smoke,
    'asset.crypto_slhdsa_external': validate_asset_crypto_slhdsa_external,
    'asset.crypto_hqc_external': validate_asset_crypto_hqc_external,
    'artifact.acvp_json_interop_result': validate_artifact_acvp_json_interop_result,
    'artifact.acvp_json_schema_result': validate_artifact_acvp_json_schema_result,
    'artifact.acvp_json_transcript_manifest': validate_artifact_acvp_json_transcript_manifest,
    'artifact.acvp_negative_scenario_floor_result': validate_artifact_acvp_negative_scenario_floor_result,
    'artifact.assurance_ledger': validate_artifact_assurance_ledger,
    'artifact.assurance_ledger_markdown': validate_artifact_assurance_ledger_markdown,
    'artifact.assurance_report_html': validate_artifact_assurance_report_html,
    'artifact.backend_contract_result': validate_artifact_backend_contract_result,
    'artifact.backend_update_evaluation': validate_artifact_backend_update_evaluation,
    'artifact.benchmark_campaign_result': validate_artifact_benchmark_campaign_result,
    'artifact.benchmark_campaign_verify_result': validate_artifact_benchmark_campaign_verify_result,
    'artifact.benchmark_confidence_result': validate_artifact_benchmark_confidence_result,
    'artifact.benchmark_provenance': validate_artifact_benchmark_provenance,
    'artifact.benchmark_results_csv': validate_artifact_benchmark_results_csv,
    'artifact.benchmark_summary_markdown': validate_artifact_benchmark_summary_markdown,
    'artifact.cost_of_assurance_evidence': validate_artifact_cost_of_assurance_evidence,
    'artifact.ct_campaign_result': validate_artifact_ct_campaign_result,
    'artifact.ct_instruction_policy_result': validate_artifact_ct_instruction_policy_result,
    'artifact.ct_sample_analysis_result': validate_artifact_ct_sample_analysis_result,
    'artifact.device_evidence_token': validate_artifact_device_evidence_token,
    'artifact.device_evidence_token_result': validate_artifact_device_evidence_token_result,
    'artifact.evidence_tamper_drill_result': validate_artifact_evidence_tamper_drill_result,
    'artifact.evidence_transcript_manifest': validate_artifact_evidence_transcript_manifest,
    'artifact.external_non_native_inventory': validate_artifact_external_non_native_inventory,
    'artifact.firmware_assurance_status_result': validate_artifact_firmware_assurance_status_result,
    'artifact.firmware_digest_header': validate_artifact_firmware_digest_header,
    'artifact.mcu_protocol_footprint_csv': validate_artifact_mcu_protocol_footprint_csv,
    'artifact.paper_comparison_campaign_csv': validate_artifact_paper_comparison_campaign_csv,
    'artifact.paper_comparison_campaign_json': validate_artifact_paper_comparison_campaign_json,
    'artifact.partner_review_scorecard': validate_artifact_partner_review_scorecard,
    'artifact.partner_review_scorecard_markdown': validate_artifact_partner_review_scorecard_markdown,
    'artifact.partner_review_scorecard_result': validate_artifact_partner_review_scorecard_result,
    'artifact.pqc_appraisal_evidence': validate_artifact_pqc_appraisal_evidence,
    'artifact.pqc_appraisal_result': validate_artifact_pqc_appraisal_result,
    'artifact.pqc_asset_trace_result': validate_artifact_pqc_asset_trace_result,
    'artifact.pqc_assurance_digest': validate_artifact_pqc_assurance_digest,
    'artifact.pqc_assurance_profile_result': validate_artifact_pqc_assurance_profile_result,
    'artifact.pqc_attestation': validate_artifact_pqc_attestation,
    'artifact.pqc_build_provenance': validate_artifact_pqc_build_provenance,
    'artifact.pqc_build_provenance_result': validate_artifact_pqc_build_provenance_result,
    'artifact.pqc_cbom': validate_artifact_pqc_cbom,
    'artifact.pqc_claim_closure_result': validate_artifact_pqc_claim_closure_result,
    'artifact.pqc_environment_result': validate_artifact_pqc_environment_result,
    'artifact.pqc_evidence_graph_json': validate_artifact_pqc_evidence_graph_json,
    'artifact.pqc_evidence_graph_markdown': validate_artifact_pqc_evidence_graph_markdown,
    'artifact.pqc_evidence_quality_result': validate_artifact_pqc_evidence_quality_result,
    'artifact.pqc_migration_readiness_json': validate_artifact_pqc_migration_readiness_json,
    'artifact.pqc_migration_readiness_markdown': validate_artifact_pqc_migration_readiness_markdown,
    'artifact.pqc_policy_result': validate_artifact_pqc_policy_result,
    'artifact.pqc_reference_values': validate_artifact_pqc_reference_values,
    'artifact.pqc_reference_values_result': validate_artifact_pqc_reference_values_result,
    'artifact.provider_scope_result': validate_artifact_provider_scope_result,
    'artifact.release_manifest': validate_artifact_release_manifest,
    'artifact.release_notes_markdown': validate_artifact_release_notes_markdown,
    'artifact.release_reference_values_result': validate_artifact_release_reference_values_result,
    'benchmark.paper_comparable_campaign': validate_benchmark_paper_comparable_campaign,
    'benchmark.external_reference_import': validate_benchmark_external_reference_import,
    'acvp.malformed_then_valid_recovery': validate_acvp_malformed_then_valid_recovery,
    'acvp.operation_schema_coverage': validate_acvp_operation_schema_coverage,
    'ct.sample_balance': validate_ct_sample_balance,
    'ct.instruction_policy_coverage': validate_ct_instruction_policy_coverage,
    'hardware.uart_transcript_capture': validate_hardware_uart_transcript_capture,
    'hardware.entropy_source_review': validate_hardware_entropy_source_review,
    'product.cli_release_pack': validate_product_cli_release_pack,
    'product.dashboard_ingest_contract': validate_product_dashboard_ingest_contract,
    'product.customer_policy_overlay': validate_product_customer_policy_overlay,
    'product.signed_pack_readiness': validate_product_signed_pack_readiness,
}

def validate_catalog_rules(experiments: tuple[ExperimentSpec, ...] | list[ExperimentSpec], module_path: Path) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    by_id = {experiment.id: experiment for experiment in experiments}
    for rule_id in RULE_IDS:
        experiment = by_id.get(rule_id)
        if experiment is None:
            diagnostics.append(error("rule_experiment_removed", rule_id, "experiment disappeared from catalog"))
            continue
        diagnostics.extend(RULES[rule_id](experiment, module_path))
    extra = sorted(set(by_id) - set(RULE_IDS))
    for experiment_id in extra:
        diagnostics.append(warning("rule_experiment_added", experiment_id, "new experiment has no generated compatibility rule yet"))
    return diagnostics
