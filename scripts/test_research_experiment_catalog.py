#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for the research experiment catalog validator."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
CATALOG = SCRIPT_DIR / "research_experiment_catalog.json"
VALIDATOR = SCRIPT_DIR / "validate_research_experiment_catalog.py"


class ResearchExperimentCatalogTests(unittest.TestCase):
    maxDiff = None

    def run_validator(self, catalog: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VALIDATOR), "--catalog", str(catalog)],
            cwd=str(REPO_ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def write_temp_catalog(self, raw: dict) -> Path:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        with tmp:
            json.dump(raw, tmp, indent=2)
            tmp.write("\n")
        return Path(tmp.name)

    def test_current_catalog_passes(self) -> None:
        result = self.run_validator(CATALOG)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS: research experiment catalog validated", result.stdout)

    def test_catalog_has_enough_experiments_for_research_program(self) -> None:
        raw = json.loads(CATALOG.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(raw["experiments"]), 120)
        categories = {item["category"] for item in raw["experiments"]}
        self.assertIn("claim_replay", categories)
        self.assertIn("asset_traceability", categories)
        self.assertIn("artifact_schema", categories)
        self.assertIn("benchmark_methodology", categories)
        self.assertIn("product_packaging", categories)

    def test_duplicate_experiment_id_fails(self) -> None:
        raw = json.loads(CATALOG.read_text(encoding="utf-8"))
        modified = copy.deepcopy(raw)
        modified["experiments"][1]["id"] = modified["experiments"][0]["id"]
        path = self.write_temp_catalog(modified)
        result = self.run_validator(path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicates", result.stdout)

    def test_missing_repository_input_fails(self) -> None:
        raw = json.loads(CATALOG.read_text(encoding="utf-8"))
        modified = copy.deepcopy(raw)
        modified["experiments"][0]["repository_inputs"] = ["missing/path.json"]
        path = self.write_temp_catalog(modified)
        result = self.run_validator(path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("repository input does not exist", result.stdout)

    def test_empty_negative_control_fails(self) -> None:
        raw = json.loads(CATALOG.read_text(encoding="utf-8"))
        modified = copy.deepcopy(raw)
        modified["experiments"][0]["negative_control"] = ""
        path = self.write_temp_catalog(modified)
        result = self.run_validator(path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("negative_control must be a meaningful sentence", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
