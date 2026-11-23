#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for statistical sanity checks."""

from __future__ import annotations

import csv
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

FIELDS = ["algorithm", "operation", "parameter_set", "implementation", "board", "profile", "metric", "statistic", "value", "unit", "source"]


class StatisticalSanityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pqcp-stats-"))
        self.api = ProductEvidenceApi(REPO_ROOT)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_csv(self, values: list[float]) -> Path:
        path = self.tmp / "stats.csv"
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            for index, value in enumerate(values):
                writer.writerow(
                    {
                        "algorithm": "ML-KEM",
                        "operation": "encaps",
                        "parameter_set": "768",
                        "implementation": "native",
                        "board": "qemu_x86_64",
                        "profile": "release",
                        "metric": "cycles",
                        "statistic": f"sample{index}",
                        "value": str(value),
                        "unit": "cycles",
                        "source": "unit-fixture",
                    }
                )
        return path

    def test_computes_summary_statistics(self) -> None:
        result = self.api.statistical_sanity(csv_paths=[self.write_csv([10, 12, 14, 16])], output_root=self.tmp / "out")
        group = result["groups"][0]
        self.assertEqual(group["count"], 4)
        self.assertEqual(group["min"], 10.0)
        self.assertEqual(group["max"], 16.0)
        self.assertEqual(group["median"], 13.0)

    def test_low_sample_count_marks_rerun(self) -> None:
        result = self.api.statistical_sanity(csv_paths=[self.write_csv([10, 11])], output_root=self.tmp / "out", min_samples=3)
        self.assertEqual(result["status"], "WARN")
        self.assertTrue(result["groups"][0]["rerun_required"])

    def test_high_variance_warns(self) -> None:
        result = self.api.statistical_sanity(csv_paths=[self.write_csv([10, 100, 1000, 2000])], output_root=self.tmp / "out", cv_warn_threshold=0.01)
        self.assertEqual(result["status"], "WARN")
        self.assertTrue(result["groups"][0]["high_variance"])

    def test_cli_smoke(self) -> None:
        csv_path = self.write_csv([10, 11, 12])
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "pqcp_tool.py"),
                "stats-summary",
                "--csv",
                str(csv_path),
                "--output-root",
                str(self.tmp / "cli"),
            ],
            cwd=str(REPO_ROOT),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertTrue((self.tmp / "cli" / "statistical-sanity-report.json").exists())


if __name__ == "__main__":
    unittest.main()
