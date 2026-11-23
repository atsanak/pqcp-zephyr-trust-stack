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
from pqcp_product.catalog import ExperimentCatalog
from pqcp_product.experiment_rules import RULES, validate_catalog_rules
from pqcp_product.models import ExperimentSpec


class GeneratedExperimentRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = ExperimentCatalog(REPO_ROOT)
        cls.by_id = cls.catalog.by_id()

    def assertRulePasses(self, experiment_id: str) -> None:
        experiment = self.by_id[experiment_id]
        diagnostics = RULES[experiment_id](experiment, REPO_ROOT)
        errors = [diag.to_dict() for diag in diagnostics if diag.is_error]
        self.assertEqual(errors, [], experiment_id)

    def test_rule_claim_release_version_consistency(self) -> None:
        experiment_id = 'claim.release_version_consistency'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_release_tag_integrity(self) -> None:
        experiment_id = 'claim.release_tag_integrity'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_kat_offline_provenance(self) -> None:
        experiment_id = 'claim.kat_offline_provenance'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_kat_mlkem_512(self) -> None:
        experiment_id = 'claim.kat_mlkem_512'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_kat_mlkem_768(self) -> None:
        experiment_id = 'claim.kat_mlkem_768'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_kat_mlkem_1024(self) -> None:
        experiment_id = 'claim.kat_mlkem_1024'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_kat_mldsa_44(self) -> None:
        experiment_id = 'claim.kat_mldsa_44'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_kat_mldsa_65(self) -> None:
        experiment_id = 'claim.kat_mldsa_65'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_kat_mldsa_87(self) -> None:
        experiment_id = 'claim.kat_mldsa_87'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_benchmark_csv_validity(self) -> None:
        experiment_id = 'claim.benchmark_csv_validity'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_benchmark_provenance_binding(self) -> None:
        experiment_id = 'claim.benchmark_provenance_binding'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_benchmark_mlkem_throughput(self) -> None:
        experiment_id = 'claim.benchmark_mlkem_throughput'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_benchmark_mldsa_throughput(self) -> None:
        experiment_id = 'claim.benchmark_mldsa_throughput'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_benchmark_distribution_quality(self) -> None:
        experiment_id = 'claim.benchmark_distribution_quality'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_cost_of_assurance_guardrails(self) -> None:
        experiment_id = 'claim.cost_of_assurance_guardrails'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_release_local_bundle(self) -> None:
        experiment_id = 'claim.release_local_bundle'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_release_transcript_binding(self) -> None:
        experiment_id = 'claim.release_transcript_binding'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_acvp_negative_path_rejection(self) -> None:
        experiment_id = 'claim.acvp_negative_path_rejection'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_acvp_timeout_recovery(self) -> None:
        experiment_id = 'claim.acvp_timeout_recovery'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_acvp_negative_scenarios_replay(self) -> None:
        experiment_id = 'claim.acvp_negative_scenarios_replay'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_acvp_mlkem_negative_paths(self) -> None:
        experiment_id = 'claim.acvp_mlkem_negative_paths'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_acvp_mldsa_negative_paths(self) -> None:
        experiment_id = 'claim.acvp_mldsa_negative_paths'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_acvp_negative_scenario_floor(self) -> None:
        experiment_id = 'claim.acvp_negative_scenario_floor'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_security_asan_clean(self) -> None:
        experiment_id = 'claim.security_asan_clean'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_security_ubsan_clean(self) -> None:
        experiment_id = 'claim.security_ubsan_clean'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_boot_kat_self_verify(self) -> None:
        experiment_id = 'claim.boot_kat_self_verify'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_security_ct_smoke(self) -> None:
        experiment_id = 'claim.security_ct_smoke'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_security_mlkem_decap_instruction_policy(self) -> None:
        experiment_id = 'claim.security_mlkem_decap_instruction_policy'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_supply_chain_cbom_crypto_inventory(self) -> None:
        experiment_id = 'claim.supply_chain_cbom_crypto_inventory'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_supply_chain_pqc_assurance_attestation(self) -> None:
        experiment_id = 'claim.supply_chain_pqc_assurance_attestation'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_supply_chain_crypto_asset_traceability(self) -> None:
        experiment_id = 'claim.supply_chain_crypto_asset_traceability'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_supply_chain_evidence_graph_integrity(self) -> None:
        experiment_id = 'claim.supply_chain_evidence_graph_integrity'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_release_policy_pass(self) -> None:
        experiment_id = 'claim.release_policy_pass'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_firmware_assurance_digest_manifest(self) -> None:
        experiment_id = 'claim.firmware_assurance_digest_manifest'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_firmware_assurance_digest_embeddable(self) -> None:
        experiment_id = 'claim.firmware_assurance_digest_embeddable'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_supply_chain_assurance_profile_policy(self) -> None:
        experiment_id = 'claim.supply_chain_assurance_profile_policy'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_supply_chain_evidence_quality_index(self) -> None:
        experiment_id = 'claim.supply_chain_evidence_quality_index'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_crypto_agility_profile_separation(self) -> None:
        experiment_id = 'claim.crypto_agility_profile_separation'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_release_migration_readiness(self) -> None:
        experiment_id = 'claim.release_migration_readiness'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_security_production_rng_policy(self) -> None:
        experiment_id = 'claim.security_production_rng_policy'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_release_reference_values(self) -> None:
        experiment_id = 'claim.release_reference_values'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_firmware_assurance_status_report(self) -> None:
        experiment_id = 'claim.firmware_assurance_status_report'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_acvp_json_interop(self) -> None:
        experiment_id = 'claim.acvp_json_interop'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_supply_chain_slsa_build_provenance(self) -> None:
        experiment_id = 'claim.supply_chain_slsa_build_provenance'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_security_ct_sample_analysis(self) -> None:
        experiment_id = 'claim.security_ct_sample_analysis'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_release_evidence_appraisal_profile(self) -> None:
        experiment_id = 'claim.release_evidence_appraisal_profile'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_supply_chain_backend_update_evaluation(self) -> None:
        experiment_id = 'claim.supply_chain_backend_update_evaluation'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_benchmark_campaign_reproducibility(self) -> None:
        experiment_id = 'claim.benchmark_campaign_reproducibility'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_benchmark_external_reference_context(self) -> None:
        experiment_id = 'claim.benchmark_external_reference_context'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_security_ct_campaign_analysis(self) -> None:
        experiment_id = 'claim.security_ct_campaign_analysis'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_acvp_json_schema_coverage(self) -> None:
        experiment_id = 'claim.acvp_json_schema_coverage'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_firmware_device_evidence_token(self) -> None:
        experiment_id = 'claim.firmware_device_evidence_token'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_release_strict_partner_policy(self) -> None:
        experiment_id = 'claim.release_strict_partner_policy'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_supply_chain_backend_contract(self) -> None:
        experiment_id = 'claim.supply_chain_backend_contract'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_supply_chain_liboqs_non_native_scope(self) -> None:
        experiment_id = 'claim.supply_chain_liboqs_non_native_scope'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_benchmark_paper_comparison_export(self) -> None:
        experiment_id = 'claim.benchmark_paper_comparison_export'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_claim_release_reference_provider_scope(self) -> None:
        experiment_id = 'claim.release_reference_provider_scope'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'claim_replay')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')).issubset(set(experiment.expected_outputs)))

    def test_rule_asset_crypto_mlkem_512(self) -> None:
        experiment_id = 'asset.crypto_mlkem_512'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'asset_traceability')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mlkem.h', 'src/mlkem_zephyr.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_acvp_kat/src/main.c', 'tests/ztest_ct_smoke/src/main.c', 'scripts/verify_ct_instruction_policy.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')).issubset(set(experiment.expected_outputs)))

    def test_rule_asset_crypto_mlkem_768(self) -> None:
        experiment_id = 'asset.crypto_mlkem_768'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'asset_traceability')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mlkem.h', 'src/mlkem_zephyr.c', 'src/psa_mlkem_driver.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_ct_smoke/src/main.c', 'tests/ztest_primitive/src/main.c', 'scripts/verify_ct_instruction_policy.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')).issubset(set(experiment.expected_outputs)))

    def test_rule_asset_crypto_mlkem_1024(self) -> None:
        experiment_id = 'asset.crypto_mlkem_1024'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'asset_traceability')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mlkem.h', 'src/mlkem_zephyr.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_acvp_kat/src/main.c', 'tests/ztest_ct_smoke/src/main.c', 'scripts/verify_ct_instruction_policy.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')).issubset(set(experiment.expected_outputs)))

    def test_rule_asset_crypto_mldsa_44(self) -> None:
        experiment_id = 'asset.crypto_mldsa_44'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'asset_traceability')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mldsa.h', 'src/mldsa_zephyr.c', 'src/mldsa_streaming.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_acvp_kat/src/main.c')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')).issubset(set(experiment.expected_outputs)))

    def test_rule_asset_crypto_mldsa_65(self) -> None:
        experiment_id = 'asset.crypto_mldsa_65'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'asset_traceability')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mldsa.h', 'src/mldsa_zephyr.c', 'src/mldsa_streaming.c', 'src/psa_mldsa_driver.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_primitive/src/main.c')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')).issubset(set(experiment.expected_outputs)))

    def test_rule_asset_crypto_mldsa_87(self) -> None:
        experiment_id = 'asset.crypto_mldsa_87'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'asset_traceability')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mldsa.h', 'src/mldsa_zephyr.c', 'src/mldsa_streaming.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_acvp_kat/src/main.c')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')).issubset(set(experiment.expected_outputs)))

    def test_rule_asset_validation_acvp_serial(self) -> None:
        experiment_id = 'asset.validation_acvp_serial'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'asset_traceability')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/acvp_cmd.h', 'src/acvp_cmd.c', 'samples/pqcp_serial_acvp/src/main.c', 'scripts/acvp_negative_scenarios.json', 'scripts/acvp_negative_scenario_floor.json', 'tests/ztest_acvp_serial/src/main.c', 'tests/ztest_acvp_serial_negative/src/main.c')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')).issubset(set(experiment.expected_outputs)))

    def test_rule_asset_validation_tls_selftest(self) -> None:
        experiment_id = 'asset.validation_tls_selftest'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'asset_traceability')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/tls_selftest.h', 'src/tls_selftest.c', 'samples/pqcp_tls_mbedtls_psa/src/main.c', 'tests/ztest_tls_selftest/src/main.c')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')).issubset(set(experiment.expected_outputs)))

    def test_rule_asset_rng_zephyr_entropy(self) -> None:
        experiment_id = 'asset.rng_zephyr_entropy'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'asset_traceability')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/rng.h', 'src/rng_common.c', 'src/rng_zephyr_entropy.c', 'tests/ztest_rng/src/main.c')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')).issubset(set(experiment.expected_outputs)))

    def test_rule_asset_rng_psa(self) -> None:
        experiment_id = 'asset.rng_psa'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'asset_traceability')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/rng.h', 'src/rng_common.c', 'src/rng_psa.c', 'tests/ztest_rng/src/main.c')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')).issubset(set(experiment.expected_outputs)))

    def test_rule_asset_rng_deterministic_test(self) -> None:
        experiment_id = 'asset.rng_deterministic_test'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'asset_traceability')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/rng.h', 'src/rng_common.c', 'src/rng_deterministic.c', 'samples/pqcp_kat_deterministic/src/main.c', 'tests/ztest_primitive/src/main.c')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')).issubset(set(experiment.expected_outputs)))

    def test_rule_asset_boot_kat_self_verify(self) -> None:
        experiment_id = 'asset.boot_kat_self_verify'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'asset_traceability')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'src/kat_boot_verify.c', 'tests/ztest_kat_boot_verify/src/main.c')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')).issubset(set(experiment.expected_outputs)))

    def test_rule_asset_security_ct_smoke(self) -> None:
        experiment_id = 'asset.security_ct_smoke'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'asset_traceability')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'tests/ztest_ct_smoke/src/main.c', 'scripts/verify_ct_instruction_policy.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')).issubset(set(experiment.expected_outputs)))

    def test_rule_asset_crypto_slhdsa_external(self) -> None:
        experiment_id = 'asset.crypto_slhdsa_external'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'asset_traceability')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'scripts/export_liboqs_inventory.py', 'scripts/verify_provider_scope.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')).issubset(set(experiment.expected_outputs)))

    def test_rule_asset_crypto_hqc_external(self) -> None:
        experiment_id = 'asset.crypto_hqc_external'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'asset_traceability')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'scripts/export_liboqs_inventory.py', 'scripts/verify_provider_scope.py')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_acvp_json_interop_result(self) -> None:
        experiment_id = 'artifact.acvp_json_interop_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_acvp_json_schema_result(self) -> None:
        experiment_id = 'artifact.acvp_json_schema_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_acvp_json_transcript_manifest(self) -> None:
        experiment_id = 'artifact.acvp_json_transcript_manifest'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_acvp_negative_scenario_floor_result(self) -> None:
        experiment_id = 'artifact.acvp_negative_scenario_floor_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_assurance_ledger(self) -> None:
        experiment_id = 'artifact.assurance_ledger'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_assurance_ledger_markdown(self) -> None:
        experiment_id = 'artifact.assurance_ledger_markdown'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_assurance_report_html(self) -> None:
        experiment_id = 'artifact.assurance_report_html'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_backend_contract_result(self) -> None:
        experiment_id = 'artifact.backend_contract_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_backend_update_evaluation(self) -> None:
        experiment_id = 'artifact.backend_update_evaluation'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_benchmark_campaign_result(self) -> None:
        experiment_id = 'artifact.benchmark_campaign_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_benchmark_campaign_verify_result(self) -> None:
        experiment_id = 'artifact.benchmark_campaign_verify_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_benchmark_confidence_result(self) -> None:
        experiment_id = 'artifact.benchmark_confidence_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_benchmark_provenance(self) -> None:
        experiment_id = 'artifact.benchmark_provenance'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_benchmark_results_csv(self) -> None:
        experiment_id = 'artifact.benchmark_results_csv'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_benchmark_summary_markdown(self) -> None:
        experiment_id = 'artifact.benchmark_summary_markdown'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_cost_of_assurance_evidence(self) -> None:
        experiment_id = 'artifact.cost_of_assurance_evidence'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_ct_campaign_result(self) -> None:
        experiment_id = 'artifact.ct_campaign_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_ct_instruction_policy_result(self) -> None:
        experiment_id = 'artifact.ct_instruction_policy_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_ct_sample_analysis_result(self) -> None:
        experiment_id = 'artifact.ct_sample_analysis_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_device_evidence_token(self) -> None:
        experiment_id = 'artifact.device_evidence_token'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_device_evidence_token_result(self) -> None:
        experiment_id = 'artifact.device_evidence_token_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_evidence_tamper_drill_result(self) -> None:
        experiment_id = 'artifact.evidence_tamper_drill_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_evidence_transcript_manifest(self) -> None:
        experiment_id = 'artifact.evidence_transcript_manifest'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_external_non_native_inventory(self) -> None:
        experiment_id = 'artifact.external_non_native_inventory'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_firmware_assurance_status_result(self) -> None:
        experiment_id = 'artifact.firmware_assurance_status_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_firmware_digest_header(self) -> None:
        experiment_id = 'artifact.firmware_digest_header'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_mcu_protocol_footprint_csv(self) -> None:
        experiment_id = 'artifact.mcu_protocol_footprint_csv'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_paper_comparison_campaign_csv(self) -> None:
        experiment_id = 'artifact.paper_comparison_campaign_csv'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_paper_comparison_campaign_json(self) -> None:
        experiment_id = 'artifact.paper_comparison_campaign_json'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_partner_review_scorecard(self) -> None:
        experiment_id = 'artifact.partner_review_scorecard'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_partner_review_scorecard_markdown(self) -> None:
        experiment_id = 'artifact.partner_review_scorecard_markdown'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_partner_review_scorecard_result(self) -> None:
        experiment_id = 'artifact.partner_review_scorecard_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_appraisal_evidence(self) -> None:
        experiment_id = 'artifact.pqc_appraisal_evidence'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_appraisal_result(self) -> None:
        experiment_id = 'artifact.pqc_appraisal_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_asset_trace_result(self) -> None:
        experiment_id = 'artifact.pqc_asset_trace_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_assurance_digest(self) -> None:
        experiment_id = 'artifact.pqc_assurance_digest'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_assurance_profile_result(self) -> None:
        experiment_id = 'artifact.pqc_assurance_profile_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_attestation(self) -> None:
        experiment_id = 'artifact.pqc_attestation'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_build_provenance(self) -> None:
        experiment_id = 'artifact.pqc_build_provenance'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_build_provenance_result(self) -> None:
        experiment_id = 'artifact.pqc_build_provenance_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_cbom(self) -> None:
        experiment_id = 'artifact.pqc_cbom'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_claim_closure_result(self) -> None:
        experiment_id = 'artifact.pqc_claim_closure_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_environment_result(self) -> None:
        experiment_id = 'artifact.pqc_environment_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_evidence_graph_json(self) -> None:
        experiment_id = 'artifact.pqc_evidence_graph_json'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_evidence_graph_markdown(self) -> None:
        experiment_id = 'artifact.pqc_evidence_graph_markdown'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_evidence_quality_result(self) -> None:
        experiment_id = 'artifact.pqc_evidence_quality_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_migration_readiness_json(self) -> None:
        experiment_id = 'artifact.pqc_migration_readiness_json'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_migration_readiness_markdown(self) -> None:
        experiment_id = 'artifact.pqc_migration_readiness_markdown'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_policy_result(self) -> None:
        experiment_id = 'artifact.pqc_policy_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_reference_values(self) -> None:
        experiment_id = 'artifact.pqc_reference_values'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_pqc_reference_values_result(self) -> None:
        experiment_id = 'artifact.pqc_reference_values_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_provider_scope_result(self) -> None:
        experiment_id = 'artifact.provider_scope_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_release_manifest(self) -> None:
        experiment_id = 'artifact.release_manifest'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_release_notes_markdown(self) -> None:
        experiment_id = 'artifact.release_notes_markdown'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_artifact_release_reference_values_result(self) -> None:
        experiment_id = 'artifact.release_reference_values_result'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'artifact_schema')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('evidence schema validation result', 'schema-specific failure on malformed fixture')).issubset(set(experiment.expected_outputs)))

    def test_rule_benchmark_paper_comparable_campaign(self) -> None:
        experiment_id = 'benchmark.paper_comparable_campaign'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'benchmark_methodology')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/run_benchmark_campaign.py',)).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')).issubset(set(experiment.expected_outputs)))

    def test_rule_benchmark_external_reference_import(self) -> None:
        experiment_id = 'benchmark.external_reference_import'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'benchmark_methodology')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/run_paper_comparison_campaign.py',)).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')).issubset(set(experiment.expected_outputs)))

    def test_rule_acvp_malformed_then_valid_recovery(self) -> None:
        experiment_id = 'acvp.malformed_then_valid_recovery'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'acvp_interop')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/run_acvp_json_vectors.py',)).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')).issubset(set(experiment.expected_outputs)))

    def test_rule_acvp_operation_schema_coverage(self) -> None:
        experiment_id = 'acvp.operation_schema_coverage'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'acvp_interop')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/validate_acvp_json_schema.py',)).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')).issubset(set(experiment.expected_outputs)))

    def test_rule_ct_sample_balance(self) -> None:
        experiment_id = 'ct.sample_balance'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'side_channel_smoke')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/analyze_ct_samples.py',)).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')).issubset(set(experiment.expected_outputs)))

    def test_rule_ct_instruction_policy_coverage(self) -> None:
        experiment_id = 'ct.instruction_policy_coverage'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'side_channel_smoke')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/verify_ct_instruction_policy.py',)).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')).issubset(set(experiment.expected_outputs)))

    def test_rule_hardware_uart_transcript_capture(self) -> None:
        experiment_id = 'hardware.uart_transcript_capture'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'hardware_promotion')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/run_hardware_benchmarks.py',)).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')).issubset(set(experiment.expected_outputs)))

    def test_rule_hardware_entropy_source_review(self) -> None:
        experiment_id = 'hardware.entropy_source_review'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'hardware_promotion')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('include/pqcp_zephyr/rng.h',)).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')).issubset(set(experiment.expected_outputs)))

    def test_rule_product_cli_release_pack(self) -> None:
        experiment_id = 'product.cli_release_pack'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'product_packaging')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/verify_product_readiness.py',)).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')).issubset(set(experiment.expected_outputs)))

    def test_rule_product_dashboard_ingest_contract(self) -> None:
        experiment_id = 'product.dashboard_ingest_contract'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'product_packaging')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('docs/evidence-schema-contract.md',)).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')).issubset(set(experiment.expected_outputs)))

    def test_rule_product_customer_policy_overlay(self) -> None:
        experiment_id = 'product.customer_policy_overlay'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'product_packaging')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('scripts/pqc_assurance_policy.json',)).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')).issubset(set(experiment.expected_outputs)))

    def test_rule_product_signed_pack_readiness(self) -> None:
        experiment_id = 'product.signed_pack_readiness'
        self.assertIn(experiment_id, self.by_id)
        self.assertRulePasses(experiment_id)
        experiment = self.by_id[experiment_id]
        self.assertEqual(experiment.category, 'product_packaging')
        self.assertGreaterEqual(len(experiment.acceptance_criteria), 5)
        self.assertTrue(set(('docs/release.md',)).issubset(set(experiment.repository_inputs)))
        self.assertTrue(set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')).issubset(set(experiment.expected_outputs)))

    def test_catalog_rule_set_rejects_removed_experiment(self) -> None:
        experiments = tuple(exp for exp in self.catalog.experiments if exp.id != "claim.release_version_consistency")
        diagnostics = validate_catalog_rules(experiments, REPO_ROOT)
        self.assertTrue(any(diag.code == "rule_experiment_removed" for diag in diagnostics))

    def test_rule_rejects_removed_expected_output(self) -> None:
        experiment = self.by_id["claim.release_version_consistency"]
        mutated = ExperimentSpec(
            id=experiment.id, category=experiment.category, objective=experiment.objective,
            repository_inputs=experiment.repository_inputs, commands=experiment.commands, expected_outputs=(),
            positive_control=experiment.positive_control, negative_control=experiment.negative_control,
            acceptance_criteria=experiment.acceptance_criteria, research_value=experiment.research_value,
            product_value=experiment.product_value, status=experiment.status,
        )
        diagnostics = RULES[experiment.id](mutated, REPO_ROOT)
        self.assertTrue(any(diag.code == "rule_output_removed" for diag in diagnostics))

    def test_rule_rejects_weakened_acceptance_floor(self) -> None:
        experiment = self.by_id["claim.release_version_consistency"]
        mutated = ExperimentSpec(
            id=experiment.id, category=experiment.category, objective=experiment.objective,
            repository_inputs=experiment.repository_inputs, commands=experiment.commands, expected_outputs=experiment.expected_outputs,
            positive_control=experiment.positive_control, negative_control=experiment.negative_control,
            acceptance_criteria=experiment.acceptance_criteria[:1], research_value=experiment.research_value,
            product_value=experiment.product_value, status=experiment.status,
        )
        diagnostics = RULES[experiment.id](mutated, REPO_ROOT)
        self.assertTrue(any(diag.code == "rule_acceptance_weakened" for diag in diagnostics))


if __name__ == "__main__":
    unittest.main()
