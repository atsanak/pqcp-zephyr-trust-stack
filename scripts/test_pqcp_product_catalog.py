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
from pqcp_product.catalog import ExperimentCatalog


class ProductCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = ProductEvidenceApi(REPO_ROOT)
        self.catalog = ExperimentCatalog(REPO_ROOT)

    def test_catalog_validates_with_generated_rules(self) -> None:
        result = self.catalog.validate()
        self.assertTrue(result.passed, result.to_dict())
        self.assertGreaterEqual(result.catalog_summary.experiment_count, 100)
        self.assertIn("claim_replay", result.catalog_summary.category_counts)

    def test_profile_selection_is_deterministic(self) -> None:
        first = self.api.select_experiments(profile="fast", limit=12)
        second = self.api.select_experiments(profile="fast", limit=12)
        self.assertEqual(first.ids(), second.ids())
        self.assertEqual(len(first.experiments), 12)

    def test_category_selection_rejects_unknown_category(self) -> None:
        with self.assertRaises(Exception):
            self.api.select_experiments(categories=["not_a_category"])

    def test_text_selection_finds_benchmark_entries(self) -> None:
        selection = self.api.select_experiments(contains="benchmark", limit=5)
        self.assertTrue(selection.experiments)
        for experiment in selection.experiments:
            self.assertTrue(experiment.contains("benchmark"))

    def test_catalog_summary_digest_is_stable_shape(self) -> None:
        summary = self.catalog.summary().to_dict()
        self.assertEqual(len(summary["digest"]), 64)
        self.assertGreater(summary["command_count"], 0)
        self.assertGreater(summary["repository_input_count"], 0)


if __name__ == "__main__":
    unittest.main()
