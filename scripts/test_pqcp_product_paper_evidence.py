#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for compact paper evidence report aggregation."""

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


class PaperEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pqcp-paper-"))
        self.api = ProductEvidenceApi(REPO_ROOT)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_report(self, name: str, status: str) -> Path:
        path = self.tmp / f"{name}.json"
        path.write_text(json.dumps({"schema_version": 1, "status": status, "passed": status != "FAIL", "row_count": 3}) + "\n", encoding="utf-8")
        return path

    def test_aggregates_reports(self) -> None:
        reports = {
            "reproducibility": self.write_report("repro", "PASS"),
            "coverage": self.write_report("coverage", "PASS"),
            "quality": self.write_report("quality", "PASS"),
            "statistics": self.write_report("stats", "PASS"),
        }
        result = self.api.paper_evidence_report(output_root=self.tmp / "out", reports=reports)
        self.assertEqual(result["status"], "WARN")
        self.assertTrue(any(section["reason"] == "not_available" for section in result["sections"]))
        self.assertTrue((self.tmp / "out" / "paper-evidence-report.md").exists())

    def test_failing_required_section_fails_report(self) -> None:
        result = self.api.paper_evidence_report(
            output_root=self.tmp / "out",
            reports={"coverage": self.write_report("coverage", "FAIL")},
        )
        self.assertEqual(result["status"], "FAIL")

    def test_does_not_invent_absent_metrics(self) -> None:
        result = self.api.paper_evidence_report(output_root=self.tmp / "out", reports={"coverage": self.write_report("coverage", "PASS")})
        coverage = next(section for section in result["sections"] if section["name"] == "coverage")
        self.assertNotIn("mean", coverage["summary"])
        self.assertNotIn("median", coverage["summary"])

    def test_cli_smoke(self) -> None:
        repro = self.write_report("repro", "PASS")
        coverage = self.write_report("coverage", "PASS")
        quality = self.write_report("quality", "PASS")
        stats = self.write_report("stats", "PASS")
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "pqcp_tool.py"),
                "paper-report",
                "--output-root",
                str(self.tmp / "cli"),
                "--reproducibility-report",
                str(repro),
                "--coverage-report",
                str(coverage),
                "--quality-report",
                str(quality),
                "--statistics-report",
                str(stats),
            ],
            cwd=str(REPO_ROOT),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertTrue((self.tmp / "cli" / "paper-evidence-report.json").exists())


if __name__ == "__main__":
    unittest.main()
