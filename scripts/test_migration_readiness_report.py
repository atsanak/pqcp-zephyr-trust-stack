#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Regression tests for migration-readiness report generation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import generate_migration_readiness_report


def cbom_fixture() -> dict:
    return {
        "components": [
            {
                "name": "ML-KEM-768",
                "properties": [
                    {"name": "pqcp:trace_asset_id", "value": "crypto.mlkem_768"},
                    {"name": "pqcp:lifecycle_status", "value": "default"},
                    {"name": "pqcp:production_allowed", "value": "true"},
                    {"name": "pqcp:profile_support", "value": "gateway,mcu_minimal,qemu_release"},
                    {"name": "pqcp:validation_scope", "value": "kat,benchmark,ct_smoke"},
                ],
            },
            {
                "name": "Deterministic test RNG",
                "properties": [
                    {"name": "pqcp:trace_asset_id", "value": "rng.deterministic_test"},
                    {"name": "pqcp:lifecycle_status", "value": "test_only"},
                    {"name": "pqcp:production_allowed", "value": "false"},
                    {"name": "pqcp:profile_support", "value": "native_lab"},
                    {"name": "pqcp:validation_scope", "value": "kat"},
                ],
            },
        ]
    }


class MigrationReadinessReportTests(unittest.TestCase):
    def test_report_json_and_markdown_share_asset_names(self) -> None:
        profile = {"passed": True, "summary": {"profiles": 4}, "failures": []}
        quality = {"passed": True, "summary": {"quality_entries": 3}, "failures": []}
        report = generate_migration_readiness_report.build_report(profile, quality, cbom_fixture())
        markdown = generate_migration_readiness_report.render_markdown(report)
        self.assertTrue(report["passed"])
        for asset in report["assets"]:
            self.assertIn(asset["name"], markdown)

    def test_failed_profile_becomes_blocking_condition(self) -> None:
        profile = {"passed": False, "summary": {}, "failures": ["profile failure"]}
        quality = {"passed": True, "summary": {}, "failures": []}
        report = generate_migration_readiness_report.build_report(profile, quality, cbom_fixture())
        self.assertFalse(report["passed"])
        self.assertEqual(report["blocked_conditions"][0]["source"], "profile")

    def test_cli_writes_both_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "profile.json"
            quality = root / "quality.json"
            cbom = root / "cbom.json"
            output_json = root / "readiness.json"
            output_md = root / "readiness.md"
            profile.write_text(json.dumps({"passed": True, "summary": {}, "failures": []}), encoding="utf-8")
            quality.write_text(json.dumps({"passed": True, "summary": {}, "failures": []}), encoding="utf-8")
            cbom.write_text(json.dumps(cbom_fixture()), encoding="utf-8")
            args = [
                "--profile-result",
                str(profile),
                "--quality-result",
                str(quality),
                "--cbom",
                str(cbom),
                "--output-json",
                str(output_json),
                "--output-md",
                str(output_md),
            ]
            import subprocess
            import sys

            proc = subprocess.run(
                [sys.executable, str(Path(__file__).resolve().parent / "generate_migration_readiness_report.py"), *args],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(output_json.exists())
            self.assertTrue(output_md.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
