#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Regression tests for the executable experiment readiness matrix."""

from __future__ import annotations

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
from pqcp_product.catalog import ExperimentCatalog
from pqcp_product.experiment_matrix import READINESS_BUILDERS, build_readiness_matrix, matrix_payload, validate_readiness_matrix
from pqcp_product.models import ExperimentSpec


class ProductExperimentMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.api = ProductEvidenceApi(REPO_ROOT)
        cls.catalog = ExperimentCatalog(REPO_ROOT)
        cls.by_id = cls.catalog.by_id()
        cls.rows = build_readiness_matrix(cls.catalog.experiments)

    def test_matrix_has_one_row_per_experiment(self) -> None:
        self.assertEqual(len(self.rows), len(self.catalog.experiments))
        self.assertEqual({row.experiment_id for row in self.rows}, set(self.by_id))

    def test_matrix_payload_passes_for_current_catalog(self) -> None:
        payload = matrix_payload(self.catalog.experiments, REPO_ROOT)
        self.assertTrue(payload["passed"], payload)
        self.assertEqual(payload["summary"]["experiment_count"], len(self.catalog.experiments))
        self.assertEqual(len(payload["summary"]["matrix_digest"]), 64)

    def test_matrix_validator_rejects_missing_row(self) -> None:
        diagnostics = validate_readiness_matrix(self.rows[:-1], REPO_ROOT)
        self.assertTrue(any(diag.code == "matrix_missing_row" for diag in diagnostics))

    def test_cli_generates_readiness_matrix(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="pqcp-matrix-test-"))
        try:
            out = tmp / "matrix.json"
            completed = subprocess.run([sys.executable, str(SCRIPT_DIR / "pqcp_tool.py"), "readiness-matrix", "--output", str(out)], cwd=str(REPO_ROOT), text=True, capture_output=True, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(payload["passed"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    def test_readiness_row_claim_release_version_consistency(self) -> None:
        experiment_id = 'claim.release_version_consistency'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_release_tag_integrity(self) -> None:
        experiment_id = 'claim.release_tag_integrity'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_kat_offline_provenance(self) -> None:
        experiment_id = 'claim.kat_offline_provenance'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_kat_mlkem_512(self) -> None:
        experiment_id = 'claim.kat_mlkem_512'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_kat_mlkem_768(self) -> None:
        experiment_id = 'claim.kat_mlkem_768'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_kat_mlkem_1024(self) -> None:
        experiment_id = 'claim.kat_mlkem_1024'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_kat_mldsa_44(self) -> None:
        experiment_id = 'claim.kat_mldsa_44'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_kat_mldsa_65(self) -> None:
        experiment_id = 'claim.kat_mldsa_65'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_kat_mldsa_87(self) -> None:
        experiment_id = 'claim.kat_mldsa_87'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_benchmark_csv_validity(self) -> None:
        experiment_id = 'claim.benchmark_csv_validity'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_benchmark_provenance_binding(self) -> None:
        experiment_id = 'claim.benchmark_provenance_binding'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_benchmark_mlkem_throughput(self) -> None:
        experiment_id = 'claim.benchmark_mlkem_throughput'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_benchmark_mldsa_throughput(self) -> None:
        experiment_id = 'claim.benchmark_mldsa_throughput'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_benchmark_distribution_quality(self) -> None:
        experiment_id = 'claim.benchmark_distribution_quality'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_cost_of_assurance_guardrails(self) -> None:
        experiment_id = 'claim.cost_of_assurance_guardrails'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_release_local_bundle(self) -> None:
        experiment_id = 'claim.release_local_bundle'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_release_transcript_binding(self) -> None:
        experiment_id = 'claim.release_transcript_binding'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_acvp_negative_path_rejection(self) -> None:
        experiment_id = 'claim.acvp_negative_path_rejection'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_acvp_timeout_recovery(self) -> None:
        experiment_id = 'claim.acvp_timeout_recovery'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_acvp_negative_scenarios_replay(self) -> None:
        experiment_id = 'claim.acvp_negative_scenarios_replay'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_acvp_mlkem_negative_paths(self) -> None:
        experiment_id = 'claim.acvp_mlkem_negative_paths'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_acvp_mldsa_negative_paths(self) -> None:
        experiment_id = 'claim.acvp_mldsa_negative_paths'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_acvp_negative_scenario_floor(self) -> None:
        experiment_id = 'claim.acvp_negative_scenario_floor'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_security_asan_clean(self) -> None:
        experiment_id = 'claim.security_asan_clean'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_security_ubsan_clean(self) -> None:
        experiment_id = 'claim.security_ubsan_clean'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_boot_kat_self_verify(self) -> None:
        experiment_id = 'claim.boot_kat_self_verify'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_security_ct_smoke(self) -> None:
        experiment_id = 'claim.security_ct_smoke'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_security_mlkem_decap_instruction_policy(self) -> None:
        experiment_id = 'claim.security_mlkem_decap_instruction_policy'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_supply_chain_cbom_crypto_inventory(self) -> None:
        experiment_id = 'claim.supply_chain_cbom_crypto_inventory'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_supply_chain_pqc_assurance_attestation(self) -> None:
        experiment_id = 'claim.supply_chain_pqc_assurance_attestation'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_supply_chain_crypto_asset_traceability(self) -> None:
        experiment_id = 'claim.supply_chain_crypto_asset_traceability'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_supply_chain_evidence_graph_integrity(self) -> None:
        experiment_id = 'claim.supply_chain_evidence_graph_integrity'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_release_policy_pass(self) -> None:
        experiment_id = 'claim.release_policy_pass'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_firmware_assurance_digest_manifest(self) -> None:
        experiment_id = 'claim.firmware_assurance_digest_manifest'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_firmware_assurance_digest_embeddable(self) -> None:
        experiment_id = 'claim.firmware_assurance_digest_embeddable'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_supply_chain_assurance_profile_policy(self) -> None:
        experiment_id = 'claim.supply_chain_assurance_profile_policy'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_supply_chain_evidence_quality_index(self) -> None:
        experiment_id = 'claim.supply_chain_evidence_quality_index'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_crypto_agility_profile_separation(self) -> None:
        experiment_id = 'claim.crypto_agility_profile_separation'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_release_migration_readiness(self) -> None:
        experiment_id = 'claim.release_migration_readiness'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_security_production_rng_policy(self) -> None:
        experiment_id = 'claim.security_production_rng_policy'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_release_reference_values(self) -> None:
        experiment_id = 'claim.release_reference_values'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_firmware_assurance_status_report(self) -> None:
        experiment_id = 'claim.firmware_assurance_status_report'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_acvp_json_interop(self) -> None:
        experiment_id = 'claim.acvp_json_interop'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_supply_chain_slsa_build_provenance(self) -> None:
        experiment_id = 'claim.supply_chain_slsa_build_provenance'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_security_ct_sample_analysis(self) -> None:
        experiment_id = 'claim.security_ct_sample_analysis'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_release_evidence_appraisal_profile(self) -> None:
        experiment_id = 'claim.release_evidence_appraisal_profile'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_supply_chain_backend_update_evaluation(self) -> None:
        experiment_id = 'claim.supply_chain_backend_update_evaluation'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_benchmark_campaign_reproducibility(self) -> None:
        experiment_id = 'claim.benchmark_campaign_reproducibility'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_benchmark_external_reference_context(self) -> None:
        experiment_id = 'claim.benchmark_external_reference_context'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_security_ct_campaign_analysis(self) -> None:
        experiment_id = 'claim.security_ct_campaign_analysis'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_acvp_json_schema_coverage(self) -> None:
        experiment_id = 'claim.acvp_json_schema_coverage'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_firmware_device_evidence_token(self) -> None:
        experiment_id = 'claim.firmware_device_evidence_token'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_release_strict_partner_policy(self) -> None:
        experiment_id = 'claim.release_strict_partner_policy'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_supply_chain_backend_contract(self) -> None:
        experiment_id = 'claim.supply_chain_backend_contract'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_supply_chain_liboqs_non_native_scope(self) -> None:
        experiment_id = 'claim.supply_chain_liboqs_non_native_scope'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_benchmark_paper_comparison_export(self) -> None:
        experiment_id = 'claim.benchmark_paper_comparison_export'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_claim_release_reference_provider_scope(self) -> None:
        experiment_id = 'claim.release_reference_provider_scope'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'claim_replay')
        self.assertEqual(set(row.required_inputs), set(('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')))
        self.assertEqual(set(row.required_outputs), set(('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_asset_crypto_mlkem_512(self) -> None:
        experiment_id = 'asset.crypto_mlkem_512'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'asset_traceability')
        self.assertEqual(set(row.required_inputs), set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mlkem.h', 'src/mlkem_zephyr.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_acvp_kat/src/main.c', 'tests/ztest_ct_smoke/src/main.c', 'scripts/verify_ct_instruction_policy.py')))
        self.assertEqual(set(row.required_outputs), set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_asset_crypto_mlkem_768(self) -> None:
        experiment_id = 'asset.crypto_mlkem_768'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'asset_traceability')
        self.assertEqual(set(row.required_inputs), set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mlkem.h', 'src/mlkem_zephyr.c', 'src/psa_mlkem_driver.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_ct_smoke/src/main.c', 'tests/ztest_primitive/src/main.c', 'scripts/verify_ct_instruction_policy.py')))
        self.assertEqual(set(row.required_outputs), set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_asset_crypto_mlkem_1024(self) -> None:
        experiment_id = 'asset.crypto_mlkem_1024'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'asset_traceability')
        self.assertEqual(set(row.required_inputs), set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mlkem.h', 'src/mlkem_zephyr.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_acvp_kat/src/main.c', 'tests/ztest_ct_smoke/src/main.c', 'scripts/verify_ct_instruction_policy.py')))
        self.assertEqual(set(row.required_outputs), set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_asset_crypto_mldsa_44(self) -> None:
        experiment_id = 'asset.crypto_mldsa_44'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'asset_traceability')
        self.assertEqual(set(row.required_inputs), set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mldsa.h', 'src/mldsa_zephyr.c', 'src/mldsa_streaming.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_acvp_kat/src/main.c')))
        self.assertEqual(set(row.required_outputs), set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_asset_crypto_mldsa_65(self) -> None:
        experiment_id = 'asset.crypto_mldsa_65'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'asset_traceability')
        self.assertEqual(set(row.required_inputs), set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mldsa.h', 'src/mldsa_zephyr.c', 'src/mldsa_streaming.c', 'src/psa_mldsa_driver.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_primitive/src/main.c')))
        self.assertEqual(set(row.required_outputs), set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_asset_crypto_mldsa_87(self) -> None:
        experiment_id = 'asset.crypto_mldsa_87'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'asset_traceability')
        self.assertEqual(set(row.required_inputs), set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mldsa.h', 'src/mldsa_zephyr.c', 'src/mldsa_streaming.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_acvp_kat/src/main.c')))
        self.assertEqual(set(row.required_outputs), set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_asset_validation_acvp_serial(self) -> None:
        experiment_id = 'asset.validation_acvp_serial'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'asset_traceability')
        self.assertEqual(set(row.required_inputs), set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/acvp_cmd.h', 'src/acvp_cmd.c', 'samples/pqcp_serial_acvp/src/main.c', 'scripts/acvp_negative_scenarios.json', 'scripts/acvp_negative_scenario_floor.json', 'tests/ztest_acvp_serial/src/main.c', 'tests/ztest_acvp_serial_negative/src/main.c')))
        self.assertEqual(set(row.required_outputs), set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_asset_validation_tls_selftest(self) -> None:
        experiment_id = 'asset.validation_tls_selftest'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'asset_traceability')
        self.assertEqual(set(row.required_inputs), set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/tls_selftest.h', 'src/tls_selftest.c', 'samples/pqcp_tls_mbedtls_psa/src/main.c', 'tests/ztest_tls_selftest/src/main.c')))
        self.assertEqual(set(row.required_outputs), set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_asset_rng_zephyr_entropy(self) -> None:
        experiment_id = 'asset.rng_zephyr_entropy'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'asset_traceability')
        self.assertEqual(set(row.required_inputs), set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/rng.h', 'src/rng_common.c', 'src/rng_zephyr_entropy.c', 'tests/ztest_rng/src/main.c')))
        self.assertEqual(set(row.required_outputs), set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_asset_rng_psa(self) -> None:
        experiment_id = 'asset.rng_psa'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'asset_traceability')
        self.assertEqual(set(row.required_inputs), set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/rng.h', 'src/rng_common.c', 'src/rng_psa.c', 'tests/ztest_rng/src/main.c')))
        self.assertEqual(set(row.required_outputs), set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_asset_rng_deterministic_test(self) -> None:
        experiment_id = 'asset.rng_deterministic_test'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'asset_traceability')
        self.assertEqual(set(row.required_inputs), set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/rng.h', 'src/rng_common.c', 'src/rng_deterministic.c', 'samples/pqcp_kat_deterministic/src/main.c', 'tests/ztest_primitive/src/main.c')))
        self.assertEqual(set(row.required_outputs), set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_asset_boot_kat_self_verify(self) -> None:
        experiment_id = 'asset.boot_kat_self_verify'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'asset_traceability')
        self.assertEqual(set(row.required_inputs), set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'src/kat_boot_verify.c', 'tests/ztest_kat_boot_verify/src/main.c')))
        self.assertEqual(set(row.required_outputs), set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_asset_security_ct_smoke(self) -> None:
        experiment_id = 'asset.security_ct_smoke'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'asset_traceability')
        self.assertEqual(set(row.required_inputs), set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'tests/ztest_ct_smoke/src/main.c', 'scripts/verify_ct_instruction_policy.py')))
        self.assertEqual(set(row.required_outputs), set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_asset_crypto_slhdsa_external(self) -> None:
        experiment_id = 'asset.crypto_slhdsa_external'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'asset_traceability')
        self.assertEqual(set(row.required_inputs), set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'scripts/export_liboqs_inventory.py', 'scripts/verify_provider_scope.py')))
        self.assertEqual(set(row.required_outputs), set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_asset_crypto_hqc_external(self) -> None:
        experiment_id = 'asset.crypto_hqc_external'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'asset_traceability')
        self.assertEqual(set(row.required_inputs), set(('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'scripts/export_liboqs_inventory.py', 'scripts/verify_provider_scope.py')))
        self.assertEqual(set(row.required_outputs), set(('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_acvp_json_interop_result(self) -> None:
        experiment_id = 'artifact.acvp_json_interop_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_acvp_json_schema_result(self) -> None:
        experiment_id = 'artifact.acvp_json_schema_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_acvp_json_transcript_manifest(self) -> None:
        experiment_id = 'artifact.acvp_json_transcript_manifest'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_acvp_negative_scenario_floor_result(self) -> None:
        experiment_id = 'artifact.acvp_negative_scenario_floor_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_assurance_ledger(self) -> None:
        experiment_id = 'artifact.assurance_ledger'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_assurance_ledger_markdown(self) -> None:
        experiment_id = 'artifact.assurance_ledger_markdown'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_assurance_report_html(self) -> None:
        experiment_id = 'artifact.assurance_report_html'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_backend_contract_result(self) -> None:
        experiment_id = 'artifact.backend_contract_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_backend_update_evaluation(self) -> None:
        experiment_id = 'artifact.backend_update_evaluation'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_benchmark_campaign_result(self) -> None:
        experiment_id = 'artifact.benchmark_campaign_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_benchmark_campaign_verify_result(self) -> None:
        experiment_id = 'artifact.benchmark_campaign_verify_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_benchmark_confidence_result(self) -> None:
        experiment_id = 'artifact.benchmark_confidence_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_benchmark_provenance(self) -> None:
        experiment_id = 'artifact.benchmark_provenance'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_benchmark_results_csv(self) -> None:
        experiment_id = 'artifact.benchmark_results_csv'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_benchmark_summary_markdown(self) -> None:
        experiment_id = 'artifact.benchmark_summary_markdown'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_cost_of_assurance_evidence(self) -> None:
        experiment_id = 'artifact.cost_of_assurance_evidence'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_ct_campaign_result(self) -> None:
        experiment_id = 'artifact.ct_campaign_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_ct_instruction_policy_result(self) -> None:
        experiment_id = 'artifact.ct_instruction_policy_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_ct_sample_analysis_result(self) -> None:
        experiment_id = 'artifact.ct_sample_analysis_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_device_evidence_token(self) -> None:
        experiment_id = 'artifact.device_evidence_token'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_device_evidence_token_result(self) -> None:
        experiment_id = 'artifact.device_evidence_token_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_evidence_tamper_drill_result(self) -> None:
        experiment_id = 'artifact.evidence_tamper_drill_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_evidence_transcript_manifest(self) -> None:
        experiment_id = 'artifact.evidence_transcript_manifest'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_external_non_native_inventory(self) -> None:
        experiment_id = 'artifact.external_non_native_inventory'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_firmware_assurance_status_result(self) -> None:
        experiment_id = 'artifact.firmware_assurance_status_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_firmware_digest_header(self) -> None:
        experiment_id = 'artifact.firmware_digest_header'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_mcu_protocol_footprint_csv(self) -> None:
        experiment_id = 'artifact.mcu_protocol_footprint_csv'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_paper_comparison_campaign_csv(self) -> None:
        experiment_id = 'artifact.paper_comparison_campaign_csv'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_paper_comparison_campaign_json(self) -> None:
        experiment_id = 'artifact.paper_comparison_campaign_json'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_partner_review_scorecard(self) -> None:
        experiment_id = 'artifact.partner_review_scorecard'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_partner_review_scorecard_markdown(self) -> None:
        experiment_id = 'artifact.partner_review_scorecard_markdown'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_partner_review_scorecard_result(self) -> None:
        experiment_id = 'artifact.partner_review_scorecard_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_appraisal_evidence(self) -> None:
        experiment_id = 'artifact.pqc_appraisal_evidence'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_appraisal_result(self) -> None:
        experiment_id = 'artifact.pqc_appraisal_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_asset_trace_result(self) -> None:
        experiment_id = 'artifact.pqc_asset_trace_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_assurance_digest(self) -> None:
        experiment_id = 'artifact.pqc_assurance_digest'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_assurance_profile_result(self) -> None:
        experiment_id = 'artifact.pqc_assurance_profile_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_attestation(self) -> None:
        experiment_id = 'artifact.pqc_attestation'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_build_provenance(self) -> None:
        experiment_id = 'artifact.pqc_build_provenance'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_build_provenance_result(self) -> None:
        experiment_id = 'artifact.pqc_build_provenance_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_cbom(self) -> None:
        experiment_id = 'artifact.pqc_cbom'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_claim_closure_result(self) -> None:
        experiment_id = 'artifact.pqc_claim_closure_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_environment_result(self) -> None:
        experiment_id = 'artifact.pqc_environment_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_evidence_graph_json(self) -> None:
        experiment_id = 'artifact.pqc_evidence_graph_json'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_evidence_graph_markdown(self) -> None:
        experiment_id = 'artifact.pqc_evidence_graph_markdown'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_evidence_quality_result(self) -> None:
        experiment_id = 'artifact.pqc_evidence_quality_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_migration_readiness_json(self) -> None:
        experiment_id = 'artifact.pqc_migration_readiness_json'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_migration_readiness_markdown(self) -> None:
        experiment_id = 'artifact.pqc_migration_readiness_markdown'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_policy_result(self) -> None:
        experiment_id = 'artifact.pqc_policy_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_reference_values(self) -> None:
        experiment_id = 'artifact.pqc_reference_values'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_pqc_reference_values_result(self) -> None:
        experiment_id = 'artifact.pqc_reference_values_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_provider_scope_result(self) -> None:
        experiment_id = 'artifact.provider_scope_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_release_manifest(self) -> None:
        experiment_id = 'artifact.release_manifest'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_release_notes_markdown(self) -> None:
        experiment_id = 'artifact.release_notes_markdown'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_artifact_release_reference_values_result(self) -> None:
        experiment_id = 'artifact.release_reference_values_result'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'artifact_schema')
        self.assertEqual(set(row.required_inputs), set(('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')))
        self.assertEqual(set(row.required_outputs), set(('evidence schema validation result', 'schema-specific failure on malformed fixture')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_benchmark_paper_comparable_campaign(self) -> None:
        experiment_id = 'benchmark.paper_comparable_campaign'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'benchmark_methodology')
        self.assertEqual(set(row.required_inputs), set(('scripts/run_benchmark_campaign.py',)))
        self.assertEqual(set(row.required_outputs), set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_benchmark_external_reference_import(self) -> None:
        experiment_id = 'benchmark.external_reference_import'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'benchmark_methodology')
        self.assertEqual(set(row.required_inputs), set(('scripts/run_paper_comparison_campaign.py',)))
        self.assertEqual(set(row.required_outputs), set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_acvp_malformed_then_valid_recovery(self) -> None:
        experiment_id = 'acvp.malformed_then_valid_recovery'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'acvp_interop')
        self.assertEqual(set(row.required_inputs), set(('scripts/run_acvp_json_vectors.py',)))
        self.assertEqual(set(row.required_outputs), set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_acvp_operation_schema_coverage(self) -> None:
        experiment_id = 'acvp.operation_schema_coverage'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'acvp_interop')
        self.assertEqual(set(row.required_inputs), set(('scripts/validate_acvp_json_schema.py',)))
        self.assertEqual(set(row.required_outputs), set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_ct_sample_balance(self) -> None:
        experiment_id = 'ct.sample_balance'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'side_channel_smoke')
        self.assertEqual(set(row.required_inputs), set(('scripts/analyze_ct_samples.py',)))
        self.assertEqual(set(row.required_outputs), set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_ct_instruction_policy_coverage(self) -> None:
        experiment_id = 'ct.instruction_policy_coverage'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'side_channel_smoke')
        self.assertEqual(set(row.required_inputs), set(('scripts/verify_ct_instruction_policy.py',)))
        self.assertEqual(set(row.required_outputs), set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_hardware_uart_transcript_capture(self) -> None:
        experiment_id = 'hardware.uart_transcript_capture'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'hardware_promotion')
        self.assertEqual(set(row.required_inputs), set(('scripts/run_hardware_benchmarks.py',)))
        self.assertEqual(set(row.required_outputs), set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_hardware_entropy_source_review(self) -> None:
        experiment_id = 'hardware.entropy_source_review'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'hardware_promotion')
        self.assertEqual(set(row.required_inputs), set(('include/pqcp_zephyr/rng.h',)))
        self.assertEqual(set(row.required_outputs), set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_product_cli_release_pack(self) -> None:
        experiment_id = 'product.cli_release_pack'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'product_packaging')
        self.assertEqual(set(row.required_inputs), set(('scripts/verify_product_readiness.py',)))
        self.assertEqual(set(row.required_outputs), set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_product_dashboard_ingest_contract(self) -> None:
        experiment_id = 'product.dashboard_ingest_contract'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'product_packaging')
        self.assertEqual(set(row.required_inputs), set(('docs/evidence-schema-contract.md',)))
        self.assertEqual(set(row.required_outputs), set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_product_customer_policy_overlay(self) -> None:
        experiment_id = 'product.customer_policy_overlay'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'product_packaging')
        self.assertEqual(set(row.required_inputs), set(('scripts/pqc_assurance_policy.json',)))
        self.assertEqual(set(row.required_outputs), set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)

    def test_readiness_row_product_signed_pack_readiness(self) -> None:
        experiment_id = 'product.signed_pack_readiness'
        row = READINESS_BUILDERS[experiment_id](self.by_id[experiment_id])
        self.assertEqual(row.category, 'product_packaging')
        self.assertEqual(set(row.required_inputs), set(('docs/release.md',)))
        self.assertEqual(set(row.required_outputs), set(('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')))
        self.assertGreaterEqual(row.evidence_score, 40)
        self.assertTrue(row.falsification_ready)
        self.assertIsInstance(row.risk_tags, tuple)


if __name__ == "__main__":
    unittest.main()
