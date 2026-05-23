#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for the research/product dossier generator."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import generate_research_product_dossier as dossier


class ResearchProductDossierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.module = self.root / "module"
        self.release = self.root / "release"
        (self.module / "scripts").mkdir(parents=True)
        self.release.mkdir()
        self.write_repo_inputs()
        self.write_release_outputs()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_json(self, path: Path, payload: dict) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def write_repo_inputs(self) -> None:
        self.write_json(
            self.module / "scripts/assurance_claims.json",
            {
                "schema_version": 7,
                "claims": [
                    {"id": "release.version_consistency", "claim": "versions agree", "required": True},
                    {"id": "kat.mlkem_768", "claim": "ML-KEM-768 KAT passes", "required": True},
                    {"id": "acvp.mlkem_negative_paths", "claim": "ML-KEM negative paths replay", "required": True},
                    {"id": "benchmark.distribution_quality", "claim": "benchmark distribution is coherent", "required": True},
                    {"id": "security.ct_campaign_analysis", "claim": "CT campaign smoke evidence passes", "required": True},
                    {"id": "supply_chain.backend_contract", "claim": "backend contract passes", "required": True},
                ],
            },
        )
        self.write_json(
            self.module / "scripts/pqc_asset_trace_map.json",
            {
                "schema_version": 1,
                "assets": [
                    {
                        "id": "crypto.mlkem_768",
                        "source_files": ["src/psa_mlkem_driver.c"],
                        "claim_ids": ["kat.mlkem_768", "acvp.mlkem_negative_paths"],
                    },
                    {
                        "id": "crypto.mldsa_65",
                        "source_files": ["src/psa_mldsa_driver.c"],
                        "claim_ids": ["kat.mldsa_65"],
                    },
                    {
                        "id": "security.ct_smoke",
                        "source_files": ["tests/ztest_ct_smoke/src/main.c"],
                        "claim_ids": ["security.ct_campaign_analysis"],
                    },
                ],
            },
        )
        self.write_json(
            self.module / "scripts/pqc_assurance_policy.json",
            {
                "schema_version": 3,
                "required_claim_ids": [
                    "release.version_consistency",
                    "kat.mlkem_768",
                    "supply_chain.backend_contract",
                ],
                "allow_not_applicable_claim_ids": ["firmware.device_evidence_token"],
                "required_cbom_components": ["ML-KEM-768", "ML-DSA-65"],
            },
        )
        self.write_json(
            self.module / "scripts/pqc_assurance_profile.json",
            {
                "schema_version": 1,
                "profiles": {
                    "qemu_release": {"lifecycle_status": "supported"},
                    "mcu_minimal": {"lifecycle_status": "supported"},
                },
            },
        )
        self.write_json(
            self.module / "scripts/pqc_evidence_quality.json",
            {
                "schema_version": 1,
                "claims": [
                    {"id": "release.version_consistency", "evidence_class": "replay"},
                    {"id": "kat.mlkem_768", "evidence_class": "integration"},
                ],
            },
        )
        self.write_json(
            self.module / "scripts/pqc_benchmark_campaign.json",
            {
                "schema_version": 1,
                "warmup_runs": 1,
                "repetitions": 5,
                "required_statistics": ["min", "median", "p90", "p99", "mad"],
                "required_context_fields": ["board_class", "compiler", "backend_family"],
                "default_environment_type": "qemu",
            },
        )

    def write_release_outputs(self) -> None:
        self.write_json(
            self.release / "assurance_ledger.json",
            {
                "schema_version": 7,
                "project": "pqcp-zephyr-trust-stack",
                "version": "1.0.0",
                "tag": "v1.0.0",
                "claims": [
                    {"id": "release.version_consistency", "status": "pass", "required": True},
                    {"id": "kat.mlkem_768", "status": "pass", "required": True},
                    {"id": "benchmark.distribution_quality", "status": "not_applicable", "required": True},
                ],
                "summary": {"pass": 2, "fail": 0, "not_applicable": 1},
            },
        )
        self.write_json(
            self.release / "pqc_cbom.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [
                    {
                        "type": "cryptographic-asset",
                        "name": "ML-KEM-768",
                        "properties": [
                            {"name": "pqcp:trace_asset_id", "value": "crypto.mlkem_768"},
                            {"name": "pqcp:provider_family", "value": "mlkem-native"},
                            {"name": "pqcp:production_allowed", "value": "true"},
                        ],
                    },
                    {
                        "type": "cryptographic-asset",
                        "name": "ML-DSA-65",
                        "properties": [
                            {"name": "pqcp:trace_asset_id", "value": "crypto.mldsa_65"},
                            {"name": "pqcp:provider_family", "value": "mldsa-native"},
                            {"name": "pqcp:production_allowed", "value": "true"},
                        ],
                    },
                ],
            },
        )
        self.write_json(
            self.release / "benchmark_confidence_result.json",
            {
                "schema_version": 1,
                "passed": True,
                "summary": {
                    "row_count": 4,
                    "paper_comparable_rows": 0,
                    "single_observation_rows": 4,
                    "max_tail_spread_ratio": 1.0,
                },
                "warnings": ["single observation rows"],
            },
        )
        self.write_json(self.release / "partner_review_scorecard.json", {"schema_version": 1, "passed": True})
        self.write_json(
            self.release / "transcripts/evidence_transcript_manifest.json",
            {
                "schema_version": 1,
                "transcripts": [{"name": "version-consistency", "sha256": "a" * 64}],
            },
        )

    def test_dossier_mentions_real_claims_assets_and_boundaries(self) -> None:
        output = self.root / "out"
        summary = dossier.build_dossier(
            module_path=self.module,
            release_output=self.release,
            version=None,
            tag=None,
        )
        paths = dossier.write_outputs(summary, output, depth="full")
        research = paths["research_md"].read_text(encoding="utf-8")
        product = paths["product_md"].read_text(encoding="utf-8")
        failures = dossier.validate_grounding(summary, research, product)

        self.assertFalse(failures)
        self.assertIn("kat.mlkem_768", research)
        self.assertIn("crypto.mlkem_768", research)
        self.assertIn("mlkem-native", research)
        self.assertIn("QEMU results are regression evidence", product)
        payload = json.loads(paths["json"].read_text(encoding="utf-8"))
        self.assertEqual(payload["version"], "1.0.0")
        self.assertTrue(payload["release"]["artifacts"]["ledger"]["exists"])
        self.assertRegex(payload["release"]["artifacts"]["ledger"]["sha256"], r"^[0-9a-f]{64}$")

    def test_missing_required_repo_input_fails(self) -> None:
        (self.module / "scripts/pqc_assurance_policy.json").unlink()
        with self.assertRaisesRegex(RuntimeError, "required repository input"):
            dossier.build_dossier(
                module_path=self.module,
                release_output=self.release,
                version=None,
                tag=None,
            )

    def test_can_generate_without_release_output_but_marks_it_unavailable(self) -> None:
        summary = dossier.build_dossier(
            module_path=self.module,
            release_output=None,
            version="1.0.0",
            tag="v1.0.0",
        )
        self.assertFalse(summary["release"]["available"])
        self.assertEqual(summary["version"], "1.0.0")
        self.assertIn("hardware_promotion_lane", {item["id"] for item in summary["hardening_backlog"]})

    def test_grounding_validation_rejects_overclaiming_language(self) -> None:
        summary = dossier.build_dossier(
            module_path=self.module,
            release_output=self.release,
            version=None,
            tag=None,
        )
        research = dossier.render_research_markdown(summary, depth="full")
        product = dossier.render_product_markdown(summary) + "\nThis is certified.\n"
        failures = dossier.validate_grounding(summary, research, product)
        self.assertTrue(any("overclaiming" in item for item in failures))


if __name__ == "__main__":
    unittest.main(verbosity=2)
