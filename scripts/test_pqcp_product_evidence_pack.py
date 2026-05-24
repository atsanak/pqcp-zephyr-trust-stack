#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
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
from pqcp_product.fs import write_json_atomic, write_text_atomic


class ProductEvidencePackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = ProductEvidenceApi(REPO_ROOT)
        self.tmp = Path(tempfile.mkdtemp(prefix="pqcp-pack-test-"))
        write_json_atomic(self.tmp / "ledger.json", {"status": "pass", "claim": "fixture"})
        write_text_atomic(self.tmp / "transcripts" / "run.log", "fixture transcript\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_pack_builder_hashes_artifacts(self) -> None:
        manifest = self.api.build_evidence_pack(
            output_root=self.tmp,
            pack_id="fixture-pack",
            profile="unit",
            tag="v-test",
            required=["ledger.json", "transcripts/run.log"],
        )
        self.assertTrue(manifest.passed(), manifest.to_dict())
        self.assertEqual(manifest.pack_id, "fixture-pack")
        self.assertEqual(len(manifest.artifacts), 2)
        self.assertTrue((self.tmp / "evidence-pack-manifest.json").exists())
        for artifact in manifest.artifacts:
            self.assertEqual(len(artifact.sha256), 64)

    def test_missing_required_artifact_fails(self) -> None:
        manifest = self.api.build_evidence_pack(
            output_root=self.tmp,
            pack_id="fixture-pack",
            profile="unit",
            required=["missing.json"],
        )
        self.assertFalse(manifest.passed())
        self.assertTrue(any(diag.code == "artifact_missing" for diag in manifest.diagnostics))

    def test_pack_validation_detects_tamper(self) -> None:
        self.api.build_evidence_pack(output_root=self.tmp, pack_id="fixture", profile="unit")
        result = self.api.validate_evidence_pack(output_root=self.tmp)
        self.assertTrue(result["passed"], result)
        (self.tmp / "ledger.json").write_text("tampered\n", encoding="utf-8")
        result = self.api.validate_evidence_pack(output_root=self.tmp)
        self.assertFalse(result["passed"])
        self.assertTrue(any(item["code"] == "hash_mismatch" for item in result["diagnostics"]))


if __name__ == "__main__":
    unittest.main()
