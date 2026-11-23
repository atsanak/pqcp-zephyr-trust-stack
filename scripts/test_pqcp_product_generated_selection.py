#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression tests for PQCP product evidence tooling."""

from __future__ import annotations

import csv
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))
from pqcp_product.api import ProductEvidenceApi


class GeneratedExperimentSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.api = ProductEvidenceApi(REPO_ROOT)
        cls.catalog = cls.api.catalog()

    def test_category_acvp_interop_selection_count(self) -> None:
        selection = self.api.select_experiments(categories=['acvp_interop'])
        self.assertEqual(len(selection.experiments), 2)
        self.assertEqual(selection.categories().get('acvp_interop'), 2)
        self.assertTrue(all(exp.category == selection.experiments[0].category for exp in selection.experiments))

    def test_category_artifact_schema_selection_count(self) -> None:
        selection = self.api.select_experiments(categories=['artifact_schema'])
        self.assertEqual(len(selection.experiments), 55)
        self.assertEqual(selection.categories().get('artifact_schema'), 55)
        self.assertTrue(all(exp.category == selection.experiments[0].category for exp in selection.experiments))

    def test_category_asset_traceability_selection_count(self) -> None:
        selection = self.api.select_experiments(categories=['asset_traceability'])
        self.assertEqual(len(selection.experiments), 15)
        self.assertEqual(selection.categories().get('asset_traceability'), 15)
        self.assertTrue(all(exp.category == selection.experiments[0].category for exp in selection.experiments))

    def test_category_benchmark_methodology_selection_count(self) -> None:
        selection = self.api.select_experiments(categories=['benchmark_methodology'])
        self.assertEqual(len(selection.experiments), 2)
        self.assertEqual(selection.categories().get('benchmark_methodology'), 2)
        self.assertTrue(all(exp.category == selection.experiments[0].category for exp in selection.experiments))

    def test_category_claim_replay_selection_count(self) -> None:
        selection = self.api.select_experiments(categories=['claim_replay'])
        self.assertEqual(len(selection.experiments), 57)
        self.assertEqual(selection.categories().get('claim_replay'), 57)
        self.assertTrue(all(exp.category == selection.experiments[0].category for exp in selection.experiments))

    def test_category_hardware_promotion_selection_count(self) -> None:
        selection = self.api.select_experiments(categories=['hardware_promotion'])
        self.assertEqual(len(selection.experiments), 2)
        self.assertEqual(selection.categories().get('hardware_promotion'), 2)
        self.assertTrue(all(exp.category == selection.experiments[0].category for exp in selection.experiments))

    def test_category_product_packaging_selection_count(self) -> None:
        selection = self.api.select_experiments(categories=['product_packaging'])
        self.assertEqual(len(selection.experiments), 4)
        self.assertEqual(selection.categories().get('product_packaging'), 4)
        self.assertTrue(all(exp.category == selection.experiments[0].category for exp in selection.experiments))

    def test_category_side_channel_smoke_selection_count(self) -> None:
        selection = self.api.select_experiments(categories=['side_channel_smoke'])
        self.assertEqual(len(selection.experiments), 2)
        self.assertEqual(selection.categories().get('side_channel_smoke'), 2)
        self.assertTrue(all(exp.category == selection.experiments[0].category for exp in selection.experiments))

    def test_profile_fast_selection_is_non_empty(self) -> None:
        selection = self.api.select_experiments(profile='fast', limit=20)
        self.assertGreater(len(selection.experiments), 0)
        self.assertLessEqual(len(selection.experiments), 20)
        self.assertEqual(selection.ids(), list(dict.fromkeys(selection.ids())))

    def test_profile_paper_selection_is_non_empty(self) -> None:
        selection = self.api.select_experiments(profile='paper', limit=20)
        self.assertGreater(len(selection.experiments), 0)
        self.assertLessEqual(len(selection.experiments), 20)
        self.assertEqual(selection.ids(), list(dict.fromkeys(selection.ids())))

    def test_profile_product_selection_is_non_empty(self) -> None:
        selection = self.api.select_experiments(profile='product', limit=20)
        self.assertGreater(len(selection.experiments), 0)
        self.assertLessEqual(len(selection.experiments), 20)
        self.assertEqual(selection.ids(), list(dict.fromkeys(selection.ids())))

    def test_profile_hardware_selection_is_non_empty(self) -> None:
        selection = self.api.select_experiments(profile='hardware', limit=20)
        self.assertGreater(len(selection.experiments), 0)
        self.assertLessEqual(len(selection.experiments), 20)
        self.assertEqual(selection.ids(), list(dict.fromkeys(selection.ids())))

    def test_profile_all_selection_is_non_empty(self) -> None:
        selection = self.api.select_experiments(profile='all', limit=20)
        self.assertGreater(len(selection.experiments), 0)
        self.assertLessEqual(len(selection.experiments), 20)
        self.assertEqual(selection.ids(), list(dict.fromkeys(selection.ids())))

    def test_id_selection_claim_release_version_consistency(self) -> None:
        selection = self.api.select_experiments(ids=['claim.release_version_consistency'])
        self.assertEqual(selection.ids(), ['claim.release_version_consistency'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_release_tag_integrity(self) -> None:
        selection = self.api.select_experiments(ids=['claim.release_tag_integrity'])
        self.assertEqual(selection.ids(), ['claim.release_tag_integrity'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_kat_offline_provenance(self) -> None:
        selection = self.api.select_experiments(ids=['claim.kat_offline_provenance'])
        self.assertEqual(selection.ids(), ['claim.kat_offline_provenance'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_kat_mlkem_512(self) -> None:
        selection = self.api.select_experiments(ids=['claim.kat_mlkem_512'])
        self.assertEqual(selection.ids(), ['claim.kat_mlkem_512'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_kat_mlkem_768(self) -> None:
        selection = self.api.select_experiments(ids=['claim.kat_mlkem_768'])
        self.assertEqual(selection.ids(), ['claim.kat_mlkem_768'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_kat_mlkem_1024(self) -> None:
        selection = self.api.select_experiments(ids=['claim.kat_mlkem_1024'])
        self.assertEqual(selection.ids(), ['claim.kat_mlkem_1024'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_kat_mldsa_44(self) -> None:
        selection = self.api.select_experiments(ids=['claim.kat_mldsa_44'])
        self.assertEqual(selection.ids(), ['claim.kat_mldsa_44'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_kat_mldsa_65(self) -> None:
        selection = self.api.select_experiments(ids=['claim.kat_mldsa_65'])
        self.assertEqual(selection.ids(), ['claim.kat_mldsa_65'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_kat_mldsa_87(self) -> None:
        selection = self.api.select_experiments(ids=['claim.kat_mldsa_87'])
        self.assertEqual(selection.ids(), ['claim.kat_mldsa_87'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_benchmark_csv_validity(self) -> None:
        selection = self.api.select_experiments(ids=['claim.benchmark_csv_validity'])
        self.assertEqual(selection.ids(), ['claim.benchmark_csv_validity'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_benchmark_provenance_binding(self) -> None:
        selection = self.api.select_experiments(ids=['claim.benchmark_provenance_binding'])
        self.assertEqual(selection.ids(), ['claim.benchmark_provenance_binding'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_benchmark_mlkem_throughput(self) -> None:
        selection = self.api.select_experiments(ids=['claim.benchmark_mlkem_throughput'])
        self.assertEqual(selection.ids(), ['claim.benchmark_mlkem_throughput'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_benchmark_mldsa_throughput(self) -> None:
        selection = self.api.select_experiments(ids=['claim.benchmark_mldsa_throughput'])
        self.assertEqual(selection.ids(), ['claim.benchmark_mldsa_throughput'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_benchmark_distribution_quality(self) -> None:
        selection = self.api.select_experiments(ids=['claim.benchmark_distribution_quality'])
        self.assertEqual(selection.ids(), ['claim.benchmark_distribution_quality'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_cost_of_assurance_guardrails(self) -> None:
        selection = self.api.select_experiments(ids=['claim.cost_of_assurance_guardrails'])
        self.assertEqual(selection.ids(), ['claim.cost_of_assurance_guardrails'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_release_local_bundle(self) -> None:
        selection = self.api.select_experiments(ids=['claim.release_local_bundle'])
        self.assertEqual(selection.ids(), ['claim.release_local_bundle'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_release_transcript_binding(self) -> None:
        selection = self.api.select_experiments(ids=['claim.release_transcript_binding'])
        self.assertEqual(selection.ids(), ['claim.release_transcript_binding'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_acvp_negative_path_rejection(self) -> None:
        selection = self.api.select_experiments(ids=['claim.acvp_negative_path_rejection'])
        self.assertEqual(selection.ids(), ['claim.acvp_negative_path_rejection'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_acvp_timeout_recovery(self) -> None:
        selection = self.api.select_experiments(ids=['claim.acvp_timeout_recovery'])
        self.assertEqual(selection.ids(), ['claim.acvp_timeout_recovery'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_acvp_negative_scenarios_replay(self) -> None:
        selection = self.api.select_experiments(ids=['claim.acvp_negative_scenarios_replay'])
        self.assertEqual(selection.ids(), ['claim.acvp_negative_scenarios_replay'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_acvp_mlkem_negative_paths(self) -> None:
        selection = self.api.select_experiments(ids=['claim.acvp_mlkem_negative_paths'])
        self.assertEqual(selection.ids(), ['claim.acvp_mlkem_negative_paths'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_acvp_mldsa_negative_paths(self) -> None:
        selection = self.api.select_experiments(ids=['claim.acvp_mldsa_negative_paths'])
        self.assertEqual(selection.ids(), ['claim.acvp_mldsa_negative_paths'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_acvp_negative_scenario_floor(self) -> None:
        selection = self.api.select_experiments(ids=['claim.acvp_negative_scenario_floor'])
        self.assertEqual(selection.ids(), ['claim.acvp_negative_scenario_floor'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_security_asan_clean(self) -> None:
        selection = self.api.select_experiments(ids=['claim.security_asan_clean'])
        self.assertEqual(selection.ids(), ['claim.security_asan_clean'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_security_ubsan_clean(self) -> None:
        selection = self.api.select_experiments(ids=['claim.security_ubsan_clean'])
        self.assertEqual(selection.ids(), ['claim.security_ubsan_clean'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_boot_kat_self_verify(self) -> None:
        selection = self.api.select_experiments(ids=['claim.boot_kat_self_verify'])
        self.assertEqual(selection.ids(), ['claim.boot_kat_self_verify'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_security_ct_smoke(self) -> None:
        selection = self.api.select_experiments(ids=['claim.security_ct_smoke'])
        self.assertEqual(selection.ids(), ['claim.security_ct_smoke'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_security_mlkem_decap_instruction_policy(self) -> None:
        selection = self.api.select_experiments(ids=['claim.security_mlkem_decap_instruction_policy'])
        self.assertEqual(selection.ids(), ['claim.security_mlkem_decap_instruction_policy'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_supply_chain_cbom_crypto_inventory(self) -> None:
        selection = self.api.select_experiments(ids=['claim.supply_chain_cbom_crypto_inventory'])
        self.assertEqual(selection.ids(), ['claim.supply_chain_cbom_crypto_inventory'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_supply_chain_pqc_assurance_attestation(self) -> None:
        selection = self.api.select_experiments(ids=['claim.supply_chain_pqc_assurance_attestation'])
        self.assertEqual(selection.ids(), ['claim.supply_chain_pqc_assurance_attestation'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_supply_chain_crypto_asset_traceability(self) -> None:
        selection = self.api.select_experiments(ids=['claim.supply_chain_crypto_asset_traceability'])
        self.assertEqual(selection.ids(), ['claim.supply_chain_crypto_asset_traceability'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_supply_chain_evidence_graph_integrity(self) -> None:
        selection = self.api.select_experiments(ids=['claim.supply_chain_evidence_graph_integrity'])
        self.assertEqual(selection.ids(), ['claim.supply_chain_evidence_graph_integrity'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_release_policy_pass(self) -> None:
        selection = self.api.select_experiments(ids=['claim.release_policy_pass'])
        self.assertEqual(selection.ids(), ['claim.release_policy_pass'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_firmware_assurance_digest_manifest(self) -> None:
        selection = self.api.select_experiments(ids=['claim.firmware_assurance_digest_manifest'])
        self.assertEqual(selection.ids(), ['claim.firmware_assurance_digest_manifest'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_firmware_assurance_digest_embeddable(self) -> None:
        selection = self.api.select_experiments(ids=['claim.firmware_assurance_digest_embeddable'])
        self.assertEqual(selection.ids(), ['claim.firmware_assurance_digest_embeddable'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_supply_chain_assurance_profile_policy(self) -> None:
        selection = self.api.select_experiments(ids=['claim.supply_chain_assurance_profile_policy'])
        self.assertEqual(selection.ids(), ['claim.supply_chain_assurance_profile_policy'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_supply_chain_evidence_quality_index(self) -> None:
        selection = self.api.select_experiments(ids=['claim.supply_chain_evidence_quality_index'])
        self.assertEqual(selection.ids(), ['claim.supply_chain_evidence_quality_index'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_crypto_agility_profile_separation(self) -> None:
        selection = self.api.select_experiments(ids=['claim.crypto_agility_profile_separation'])
        self.assertEqual(selection.ids(), ['claim.crypto_agility_profile_separation'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_release_migration_readiness(self) -> None:
        selection = self.api.select_experiments(ids=['claim.release_migration_readiness'])
        self.assertEqual(selection.ids(), ['claim.release_migration_readiness'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_security_production_rng_policy(self) -> None:
        selection = self.api.select_experiments(ids=['claim.security_production_rng_policy'])
        self.assertEqual(selection.ids(), ['claim.security_production_rng_policy'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_release_reference_values(self) -> None:
        selection = self.api.select_experiments(ids=['claim.release_reference_values'])
        self.assertEqual(selection.ids(), ['claim.release_reference_values'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_firmware_assurance_status_report(self) -> None:
        selection = self.api.select_experiments(ids=['claim.firmware_assurance_status_report'])
        self.assertEqual(selection.ids(), ['claim.firmware_assurance_status_report'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_acvp_json_interop(self) -> None:
        selection = self.api.select_experiments(ids=['claim.acvp_json_interop'])
        self.assertEqual(selection.ids(), ['claim.acvp_json_interop'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_supply_chain_slsa_build_provenance(self) -> None:
        selection = self.api.select_experiments(ids=['claim.supply_chain_slsa_build_provenance'])
        self.assertEqual(selection.ids(), ['claim.supply_chain_slsa_build_provenance'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_security_ct_sample_analysis(self) -> None:
        selection = self.api.select_experiments(ids=['claim.security_ct_sample_analysis'])
        self.assertEqual(selection.ids(), ['claim.security_ct_sample_analysis'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_release_evidence_appraisal_profile(self) -> None:
        selection = self.api.select_experiments(ids=['claim.release_evidence_appraisal_profile'])
        self.assertEqual(selection.ids(), ['claim.release_evidence_appraisal_profile'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_supply_chain_backend_update_evaluation(self) -> None:
        selection = self.api.select_experiments(ids=['claim.supply_chain_backend_update_evaluation'])
        self.assertEqual(selection.ids(), ['claim.supply_chain_backend_update_evaluation'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_benchmark_campaign_reproducibility(self) -> None:
        selection = self.api.select_experiments(ids=['claim.benchmark_campaign_reproducibility'])
        self.assertEqual(selection.ids(), ['claim.benchmark_campaign_reproducibility'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_benchmark_external_reference_context(self) -> None:
        selection = self.api.select_experiments(ids=['claim.benchmark_external_reference_context'])
        self.assertEqual(selection.ids(), ['claim.benchmark_external_reference_context'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_security_ct_campaign_analysis(self) -> None:
        selection = self.api.select_experiments(ids=['claim.security_ct_campaign_analysis'])
        self.assertEqual(selection.ids(), ['claim.security_ct_campaign_analysis'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_acvp_json_schema_coverage(self) -> None:
        selection = self.api.select_experiments(ids=['claim.acvp_json_schema_coverage'])
        self.assertEqual(selection.ids(), ['claim.acvp_json_schema_coverage'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_firmware_device_evidence_token(self) -> None:
        selection = self.api.select_experiments(ids=['claim.firmware_device_evidence_token'])
        self.assertEqual(selection.ids(), ['claim.firmware_device_evidence_token'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_release_strict_partner_policy(self) -> None:
        selection = self.api.select_experiments(ids=['claim.release_strict_partner_policy'])
        self.assertEqual(selection.ids(), ['claim.release_strict_partner_policy'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_supply_chain_backend_contract(self) -> None:
        selection = self.api.select_experiments(ids=['claim.supply_chain_backend_contract'])
        self.assertEqual(selection.ids(), ['claim.supply_chain_backend_contract'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_supply_chain_liboqs_non_native_scope(self) -> None:
        selection = self.api.select_experiments(ids=['claim.supply_chain_liboqs_non_native_scope'])
        self.assertEqual(selection.ids(), ['claim.supply_chain_liboqs_non_native_scope'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_benchmark_paper_comparison_export(self) -> None:
        selection = self.api.select_experiments(ids=['claim.benchmark_paper_comparison_export'])
        self.assertEqual(selection.ids(), ['claim.benchmark_paper_comparison_export'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_claim_release_reference_provider_scope(self) -> None:
        selection = self.api.select_experiments(ids=['claim.release_reference_provider_scope'])
        self.assertEqual(selection.ids(), ['claim.release_reference_provider_scope'])
        self.assertEqual(selection.experiments[0].command_count(), 2)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_asset_crypto_mlkem_512(self) -> None:
        selection = self.api.select_experiments(ids=['asset.crypto_mlkem_512'])
        self.assertEqual(selection.ids(), ['asset.crypto_mlkem_512'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_asset_crypto_mlkem_768(self) -> None:
        selection = self.api.select_experiments(ids=['asset.crypto_mlkem_768'])
        self.assertEqual(selection.ids(), ['asset.crypto_mlkem_768'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_asset_crypto_mlkem_1024(self) -> None:
        selection = self.api.select_experiments(ids=['asset.crypto_mlkem_1024'])
        self.assertEqual(selection.ids(), ['asset.crypto_mlkem_1024'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_asset_crypto_mldsa_44(self) -> None:
        selection = self.api.select_experiments(ids=['asset.crypto_mldsa_44'])
        self.assertEqual(selection.ids(), ['asset.crypto_mldsa_44'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_asset_crypto_mldsa_65(self) -> None:
        selection = self.api.select_experiments(ids=['asset.crypto_mldsa_65'])
        self.assertEqual(selection.ids(), ['asset.crypto_mldsa_65'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_asset_crypto_mldsa_87(self) -> None:
        selection = self.api.select_experiments(ids=['asset.crypto_mldsa_87'])
        self.assertEqual(selection.ids(), ['asset.crypto_mldsa_87'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_asset_validation_acvp_serial(self) -> None:
        selection = self.api.select_experiments(ids=['asset.validation_acvp_serial'])
        self.assertEqual(selection.ids(), ['asset.validation_acvp_serial'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_asset_validation_tls_selftest(self) -> None:
        selection = self.api.select_experiments(ids=['asset.validation_tls_selftest'])
        self.assertEqual(selection.ids(), ['asset.validation_tls_selftest'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_asset_rng_zephyr_entropy(self) -> None:
        selection = self.api.select_experiments(ids=['asset.rng_zephyr_entropy'])
        self.assertEqual(selection.ids(), ['asset.rng_zephyr_entropy'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_asset_rng_psa(self) -> None:
        selection = self.api.select_experiments(ids=['asset.rng_psa'])
        self.assertEqual(selection.ids(), ['asset.rng_psa'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_asset_rng_deterministic_test(self) -> None:
        selection = self.api.select_experiments(ids=['asset.rng_deterministic_test'])
        self.assertEqual(selection.ids(), ['asset.rng_deterministic_test'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_asset_boot_kat_self_verify(self) -> None:
        selection = self.api.select_experiments(ids=['asset.boot_kat_self_verify'])
        self.assertEqual(selection.ids(), ['asset.boot_kat_self_verify'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_asset_security_ct_smoke(self) -> None:
        selection = self.api.select_experiments(ids=['asset.security_ct_smoke'])
        self.assertEqual(selection.ids(), ['asset.security_ct_smoke'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_asset_crypto_slhdsa_external(self) -> None:
        selection = self.api.select_experiments(ids=['asset.crypto_slhdsa_external'])
        self.assertEqual(selection.ids(), ['asset.crypto_slhdsa_external'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_asset_crypto_hqc_external(self) -> None:
        selection = self.api.select_experiments(ids=['asset.crypto_hqc_external'])
        self.assertEqual(selection.ids(), ['asset.crypto_hqc_external'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 3)

    def test_id_selection_artifact_acvp_json_interop_result(self) -> None:
        selection = self.api.select_experiments(ids=['artifact.acvp_json_interop_result'])
        self.assertEqual(selection.ids(), ['artifact.acvp_json_interop_result'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 2)

    def test_id_selection_artifact_acvp_json_schema_result(self) -> None:
        selection = self.api.select_experiments(ids=['artifact.acvp_json_schema_result'])
        self.assertEqual(selection.ids(), ['artifact.acvp_json_schema_result'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 2)

    def test_id_selection_artifact_acvp_json_transcript_manifest(self) -> None:
        selection = self.api.select_experiments(ids=['artifact.acvp_json_transcript_manifest'])
        self.assertEqual(selection.ids(), ['artifact.acvp_json_transcript_manifest'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 2)

    def test_id_selection_artifact_acvp_negative_scenario_floor_result(self) -> None:
        selection = self.api.select_experiments(ids=['artifact.acvp_negative_scenario_floor_result'])
        self.assertEqual(selection.ids(), ['artifact.acvp_negative_scenario_floor_result'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 2)

    def test_id_selection_artifact_assurance_ledger(self) -> None:
        selection = self.api.select_experiments(ids=['artifact.assurance_ledger'])
        self.assertEqual(selection.ids(), ['artifact.assurance_ledger'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 2)

    def test_id_selection_artifact_assurance_ledger_markdown(self) -> None:
        selection = self.api.select_experiments(ids=['artifact.assurance_ledger_markdown'])
        self.assertEqual(selection.ids(), ['artifact.assurance_ledger_markdown'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 2)

    def test_id_selection_artifact_assurance_report_html(self) -> None:
        selection = self.api.select_experiments(ids=['artifact.assurance_report_html'])
        self.assertEqual(selection.ids(), ['artifact.assurance_report_html'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 2)

    def test_id_selection_artifact_backend_contract_result(self) -> None:
        selection = self.api.select_experiments(ids=['artifact.backend_contract_result'])
        self.assertEqual(selection.ids(), ['artifact.backend_contract_result'])
        self.assertEqual(selection.experiments[0].command_count(), 1)
        self.assertEqual(selection.experiments[0].expected_output_count(), 2)


if __name__ == "__main__":
    unittest.main()
