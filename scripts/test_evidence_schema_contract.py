#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Regression tests for the product-facing evidence schema contract."""

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
VALIDATOR = SCRIPT_DIR / "validate_evidence_schemas.py"
CATALOG = REPO_ROOT / "schemas/evidence/evidence_schema_catalog.json"
FIXTURE = SCRIPT_DIR / "testdata/evidence_schema_pack/product_mvp"


class EvidenceSchemaContractTests(unittest.TestCase):
    maxDiff = None

    def run_validator(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VALIDATOR), *args],
            cwd=str(cwd or REPO_ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def copy_fixture(self) -> tempfile.TemporaryDirectory[str]:
        tmp = tempfile.TemporaryDirectory()
        dst = Path(tmp.name) / "pack"
        shutil.copytree(FIXTURE, dst)
        tmp.path = dst  # type: ignore[attr-defined]
        return tmp

    def test_catalog_only_validates_all_schema_files(self) -> None:
        result = self.run_validator(
            "--catalog",
            str(CATALOG),
            "--mode",
            "catalog-only",
            "--output",
            "/tmp/pqcp-evidence-schema-catalog-test.json",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS: evidence schema contract validation passed", result.stdout)

    def test_contract_catalog_has_product_scale_coverage(self) -> None:
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        contracts = catalog.get("contracts", [])
        self.assertGreaterEqual(len(contracts), 50)
        required_ids = {
            "assurance_ledger",
            "evidence_transcript_manifest",
            "pqc_cbom",
            "pqc_policy_result",
            "pqc_attestation",
            "pqc_reference_values",
            "benchmark_campaign_result",
            "partner_review_scorecard",
        }
        self.assertTrue(required_ids.issubset({item["id"] for item in contracts}))

    def test_list_contracts_prints_stable_artifact_ids(self) -> None:
        result = self.run_validator("--catalog", str(CATALOG), "--list-contracts")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("assurance_ledger\tassurance_ledger.json", result.stdout)
        self.assertIn("pqc_cbom\tpqc_cbom.cdx.json", result.stdout)
        self.assertIn("partner_review_scorecard\tpartner_review_scorecard.json", result.stdout)

    def test_product_mvp_fixture_passes_strict_validation(self) -> None:
        result = self.run_validator(
            "--catalog",
            str(CATALOG),
            "--output-root",
            str(FIXTURE),
            "--tag",
            "v1.0.0",
            "--profile",
            "product_mvp",
            "--output",
            "/tmp/pqcp-evidence-schema-product-mvp-test.json",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("41 artifact contract(s)", result.stdout)

    def test_missing_required_artifact_fails_loudly(self) -> None:
        with self.copy_fixture() as tmp_name:
            pack = Path(tmp_name) / "pack"
            (pack / "pqc_cbom.cdx.json").unlink()
            result = self.run_validator(
                "--catalog",
                str(CATALOG),
                "--output-root",
                str(pack),
                "--tag",
                "v1.0.0",
                "--profile",
                "product_mvp",
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pqc_cbom.cdx.json", result.stdout)
        self.assertIn("required artifact is missing", result.stdout)

    def test_bad_sha256_format_fails_schema_validation(self) -> None:
        with self.copy_fixture() as tmp_name:
            pack = Path(tmp_name) / "pack"
            path = pack / "pqc_reference_values.json"
            raw = json.loads(path.read_text(encoding="utf-8"))
            raw["head_sha"] = "not-a-sha"
            path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
            result = self.run_validator(
                "--catalog",
                str(CATALOG),
                "--output-root",
                str(pack),
                "--tag",
                "v1.0.0",
                "--profile",
                "product_mvp",
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("$.head_sha", result.stdout)
        self.assertIn("expected lowercase SHA-256", result.stdout)

    def test_ledger_manifest_source_commit_mismatch_fails_cross_check(self) -> None:
        with self.copy_fixture() as tmp_name:
            pack = Path(tmp_name) / "pack"
            path = pack / "local_release_bundle/v1.0.0/release-manifest-v1.0.0.json"
            raw = json.loads(path.read_text(encoding="utf-8"))
            raw["source_commit"] = "b" * 64
            path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
            result = self.run_validator(
                "--catalog",
                str(CATALOG),
                "--output-root",
                str(pack),
                "--tag",
                "v1.0.0",
                "--profile",
                "product_mvp",
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ledger_vs_manifest.head/source", result.stdout)

    def test_transcript_hash_drift_fails_cross_check(self) -> None:
        with self.copy_fixture() as tmp_name:
            pack = Path(tmp_name) / "pack"
            transcript = pack / "transcripts/01-version.log"
            transcript.write_text(transcript.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")
            result = self.run_validator(
                "--catalog",
                str(CATALOG),
                "--output-root",
                str(pack),
                "--tag",
                "v1.0.0",
                "--profile",
                "product_mvp",
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("transcript hash drift", result.stdout)

    def test_available_mode_validates_subset_without_requiring_full_pack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            shutil.copy2(FIXTURE / "assurance_ledger.json", pack / "assurance_ledger.json")
            result = self.run_validator(
                "--catalog",
                str(CATALOG),
                "--output-root",
                str(pack),
                "--tag",
                "v1.0.0",
                "--profile",
                "product_mvp",
                "--mode",
                "available",
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1 artifact contract(s)", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
