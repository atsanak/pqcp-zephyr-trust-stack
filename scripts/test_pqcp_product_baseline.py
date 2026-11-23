#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
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

FIELDS = ["algorithm", "operation", "parameter_set", "implementation", "board", "profile", "metric", "statistic", "value", "unit", "source"]


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def row(value: str, operation: str = "sign") -> dict[str, str]:
    return {
        "algorithm": "ML-DSA",
        "operation": operation,
        "parameter_set": "65",
        "implementation": "native",
        "board": "qemu_x86_64",
        "profile": "release",
        "metric": "cycles",
        "statistic": "median",
        "value": value,
        "unit": "cycles",
        "source": "synthetic-unit-test",
    }


class ProductBaselineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = ProductEvidenceApi(REPO_ROOT)
        self.tmp = Path(tempfile.mkdtemp(prefix="pqcp-baseline-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_comparison_passes_within_threshold(self) -> None:
        baseline = self.tmp / "baseline.csv"
        candidate = self.tmp / "candidate.csv"
        write_csv(baseline, [row("100")])
        write_csv(candidate, [row("103")])
        report = self.api.compare_baselines(candidate_csv=candidate, baseline_csv=baseline, output_root=self.tmp / "out", threshold=1.05)
        self.assertTrue(report.passed(), report.to_dict())
        self.assertEqual(report.results[0].status, "pass")

    def test_comparison_detects_regression(self) -> None:
        baseline = self.tmp / "baseline.csv"
        candidate = self.tmp / "candidate.csv"
        write_csv(baseline, [row("100")])
        write_csv(candidate, [row("120")])
        report = self.api.compare_baselines(candidate_csv=candidate, baseline_csv=baseline, output_root=self.tmp / "out", threshold=1.05)
        self.assertFalse(report.passed())
        self.assertEqual(report.results[0].status, "regression")

    def test_missing_pair_fails_loudly(self) -> None:
        baseline = self.tmp / "baseline.csv"
        candidate = self.tmp / "candidate.csv"
        write_csv(baseline, [row("100", operation="sign")])
        write_csv(candidate, [row("99", operation="verify")])
        report = self.api.compare_baselines(candidate_csv=candidate, baseline_csv=baseline, output_root=self.tmp / "out", threshold=1.05)
        self.assertFalse(report.passed())
        statuses = {item.status for item in report.results}
        self.assertIn("missing_baseline", statuses)
        self.assertIn("missing_candidate", statuses)

    def test_invalid_numeric_value_fails(self) -> None:
        baseline = self.tmp / "baseline.csv"
        candidate = self.tmp / "candidate.csv"
        write_csv(baseline, [row("100")])
        write_csv(candidate, [row("not-a-number")])
        report = self.api.compare_baselines(candidate_csv=candidate, baseline_csv=baseline, output_root=self.tmp / "out", threshold=1.05)
        self.assertFalse(report.passed())
        self.assertTrue(any(diag.code == "csv_value" for diag in report.diagnostics))


if __name__ == "__main__":
    unittest.main()
