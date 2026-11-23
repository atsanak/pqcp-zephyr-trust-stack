#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for cross-run evidence pack reproducibility validation."""

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


class ReproducibilityCompareTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pqcp-repro-compare-"))
        self.api = ProductEvidenceApi(REPO_ROOT)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_pack(self, name: str, *, profile: str = "product") -> Path:
        pack = self.tmp / name
        pack.mkdir()
        (pack / "ledger.json").write_text(json.dumps({"status": "PASS", "name": name}) + "\n", encoding="utf-8")
        (pack / "optional.log").write_text("optional evidence\n", encoding="utf-8")
        self.api.build_evidence_pack(
            output_root=pack,
            pack_id="fixture-pack",
            profile=profile,
            tag="v-fixture",
            required=["ledger.json"],
        )
        return pack

    def test_identical_packs_pass(self) -> None:
        a = self.make_pack("a")
        b = self.make_pack("b")
        (b / "ledger.json").write_text((a / "ledger.json").read_text(encoding="utf-8"), encoding="utf-8")
        self.api.build_evidence_pack(output_root=b, pack_id="fixture-pack", profile="product", tag="v-fixture", required=["ledger.json"])
        result = self.api.compare_runs(packs=[a, b], output_root=self.tmp / "out")
        self.assertEqual(result["status"], "PASS", result)

    def test_missing_required_artifact_fails(self) -> None:
        a = self.make_pack("a")
        b = self.make_pack("b")
        (b / "ledger.json").unlink()
        result = self.api.compare_runs(packs=[a, b], output_root=self.tmp / "out")
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any(d["code"] == "repro_missing_artifact" for d in result["diagnostics"]))

    def test_required_hash_drift_fails(self) -> None:
        a = self.make_pack("a")
        b = self.make_pack("b")
        (b / "ledger.json").write_text("tampered\n", encoding="utf-8")
        result = self.api.compare_runs(packs=[a, b], output_root=self.tmp / "out")
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any(d["code"] == "repro_hash_drift" for d in result["diagnostics"]))

    def test_optional_hash_drift_warns(self) -> None:
        a = self.make_pack("a")
        b = self.make_pack("b")
        (b / "ledger.json").write_text((a / "ledger.json").read_text(encoding="utf-8"), encoding="utf-8")
        self.api.build_evidence_pack(output_root=b, pack_id="fixture-pack", profile="product", tag="v-fixture", required=["ledger.json"])
        (b / "optional.log").write_text("changed optional evidence\n", encoding="utf-8")
        result = self.api.compare_runs(packs=[a, b], output_root=self.tmp / "out")
        self.assertEqual(result["status"], "WARN")
        self.assertTrue(result["passed"])

    def test_stable_metadata_mismatch_fails(self) -> None:
        a = self.make_pack("a", profile="product")
        b = self.make_pack("b", profile="paper")
        result = self.api.compare_runs(packs=[a, b], output_root=self.tmp / "out")
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any(d["code"] == "repro_metadata_mismatch" for d in result["diagnostics"]))

    def test_cli_smoke(self) -> None:
        a = self.make_pack("a")
        b = self.make_pack("b")
        (b / "ledger.json").write_text((a / "ledger.json").read_text(encoding="utf-8"), encoding="utf-8")
        self.api.build_evidence_pack(output_root=b, pack_id="fixture-pack", profile="product", tag="v-fixture", required=["ledger.json"])
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "pqcp_tool.py"),
                "compare-runs",
                "--pack",
                str(a),
                "--pack",
                str(b),
                "--output-root",
                str(self.tmp / "cli"),
            ],
            cwd=str(REPO_ROOT),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertTrue((self.tmp / "cli" / "cross-run-reproducibility-report.json").exists())


if __name__ == "__main__":
    unittest.main()
