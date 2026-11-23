#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for CSV result quality validation."""

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
CORE = [
    ("ML-KEM", "keygen"),
    ("ML-KEM", "encaps"),
    ("ML-KEM", "decaps"),
    ("ML-DSA", "keygen"),
    ("ML-DSA", "sign"),
    ("ML-DSA", "verify"),
]


class ResultQualityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pqcp-quality-"))
        self.api = ProductEvidenceApi(REPO_ROOT)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_csv(self, rows: list[dict[str, str]]) -> Path:
        path = self.tmp / "results.csv"
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        return path

    def row(self, algorithm: str, operation: str, value: str = "100", statistic: str = "median", metric: str = "cycles") -> dict[str, str]:
        return {
            "algorithm": algorithm,
            "operation": operation,
            "parameter_set": "768" if algorithm == "ML-KEM" else "65",
            "implementation": "native",
            "board": "qemu_x86_64",
            "profile": "release",
            "metric": metric,
            "statistic": statistic,
            "value": value,
            "unit": "cycles",
            "source": "unit-fixture",
        }

    def valid_rows(self) -> list[dict[str, str]]:
        return [self.row(alg, op, str(100 + index)) for index, (alg, op) in enumerate(CORE)]

    def test_valid_csv_passes(self) -> None:
        result = self.api.validate_results(csv_paths=[self.write_csv(self.valid_rows())], output_root=self.tmp / "out")
        self.assertEqual(result["status"], "PASS", result)

    def test_bad_numbers_fail(self) -> None:
        rows = self.valid_rows()
        rows[0]["value"] = "NaN"
        result = self.api.validate_results(csv_paths=[self.write_csv(rows)], output_root=self.tmp / "out")
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any(d["code"] == "quality_bad_number" for d in result["diagnostics"]))

    def test_zero_warns_and_can_fail(self) -> None:
        rows = self.valid_rows()
        rows[0]["value"] = "0"
        result = self.api.validate_results(csv_paths=[self.write_csv(rows)], output_root=self.tmp / "warn")
        self.assertEqual(result["status"], "WARN")
        result = self.api.validate_results(csv_paths=[self.write_csv(rows)], output_root=self.tmp / "fail", zero_is_fail=True)
        self.assertEqual(result["status"], "FAIL")

    def test_duplicate_row_fails(self) -> None:
        rows = self.valid_rows()
        rows.append(dict(rows[0]))
        result = self.api.validate_results(csv_paths=[self.write_csv(rows)], output_root=self.tmp / "out")
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any(d["code"] == "quality_duplicate_row" for d in result["diagnostics"]))

    def test_missing_core_combo_fails(self) -> None:
        result = self.api.validate_results(csv_paths=[self.write_csv(self.valid_rows()[:-1])], output_root=self.tmp / "out")
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any(d["code"] == "quality_missing_combo" for d in result["diagnostics"]))

    def test_distribution_order_fails(self) -> None:
        rows = self.valid_rows()
        rows.extend(
            [
                self.row("ML-KEM", "encaps", "100", "min", "cycles_min"),
                self.row("ML-KEM", "encaps", "90", "median", "cycles_median"),
            ]
        )
        result = self.api.validate_results(csv_paths=[self.write_csv(rows)], output_root=self.tmp / "out")
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any(d["code"] == "quality_distribution_order" for d in result["diagnostics"]))

    def test_cli_smoke(self) -> None:
        csv_path = self.write_csv(self.valid_rows())
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "pqcp_tool.py"),
                "validate-results",
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
        self.assertTrue((self.tmp / "cli" / "result-quality-report.json").exists())


if __name__ == "__main__":
    unittest.main()
