#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for experiment coverage validation."""

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


class CoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pqcp-coverage-"))
        self.api = ProductEvidenceApi(REPO_ROOT)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_current_catalog_passes_default_coverage(self) -> None:
        result = self.api.validate_coverage(output_root=self.tmp / "coverage")
        self.assertEqual(result["status"], "PASS", result)
        self.assertTrue(all(row["covered"] for row in result["algorithm_coverage"]))
        self.assertTrue(all(row["covered"] for row in result["target_coverage"]))

    def write_catalog(self, experiments: list[dict[str, object]]) -> Path:
        path = self.tmp / "catalog.json"
        path.write_text(json.dumps({"schema_version": 1, "catalog_id": "fixture", "experiments": experiments}), encoding="utf-8")
        return path

    def experiment(self, text: str, category: str = "claim_replay") -> dict[str, object]:
        return {
            "id": "fixture.one",
            "category": category,
            "objective": text,
            "repository_inputs": [],
            "commands": ["python3 scripts/pqcp_tool.py --help"],
            "expected_outputs": ["fixture.json"],
            "positive_control": "The fixture positive control passes under expected evidence.",
            "negative_control": "Remove or corrupt the fixture evidence and confirm failure.",
            "acceptance_criteria": ["one", "two", "three"],
            "research_value": "The fixture provides a minimal falsifiable unit.",
            "product_value": "The fixture provides a product review unit.",
            "status": "fixture planned experiment.",
        }

    def test_missing_category_fails(self) -> None:
        path = self.write_catalog([self.experiment("MLKEM MLDSA qemu native nucleo baseline comparison")])
        result = self.api.validate_coverage(output_root=self.tmp / "out", catalog_path=path)
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any(d["code"] == "coverage_missing_category" for d in result["diagnostics"]))

    def test_missing_algorithm_fails(self) -> None:
        path = self.write_catalog([self.experiment("qemu native nucleo baseline comparison")])
        result = self.api.validate_coverage(output_root=self.tmp / "out", catalog_path=path)
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any(d["code"] == "coverage_missing_algorithm" for d in result["diagnostics"]))

    def test_cli_smoke(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "pqcp_tool.py"),
                "validate-coverage",
                "--output-root",
                str(self.tmp / "cli"),
            ],
            cwd=str(REPO_ROOT),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertTrue((self.tmp / "cli" / "experiment-coverage-report.json").exists())


if __name__ == "__main__":
    unittest.main()
