#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Regression tests for paper-comparison benchmark export."""

from __future__ import annotations

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import run_paper_comparison_campaign


def campaign_payload() -> dict:
    return {
        "schema_version": 1,
        "passed": True,
        "comparison_context": {
            "source_dataset": "local-smoke",
            "source_ecosystem": "pqcp",
            "board_class": "qemu_x86_64",
            "environment_type": "qemu",
            "clock_source": "virtual",
            "clock_mhz": "0",
            "compiler": "gcc",
            "toolchain": "zephyr-sdk",
            "optimization_flags": "-Os",
            "backend_family": "mlkem-native/mldsa-native",
            "statistic_type": "cycles",
        },
        "statistics": [
            {
                "parameter_set": "ML-KEM-768",
                "implementation": "pqcp",
                "backend": "auto",
                "operation": "encaps",
                "sample_count": 5,
                "min": 10,
                "median": 11,
                "p90": 12,
                "p99": 13,
                "mad": 1,
                "rom_bytes": 1024,
                "ram_bytes": 256,
            }
        ],
    }


class PaperComparisonCampaignTests(unittest.TestCase):
    def run_export(self, root: Path, payload: dict) -> dict:
        campaign = root / "benchmark_campaign_result.json"
        campaign.write_text(json.dumps(payload), encoding="utf-8")
        args = Namespace(
            benchmark_campaign=campaign,
            output_csv=root / "paper_comparison_campaign.csv",
            output_json=root / "paper_comparison_campaign.json",
        )
        rows, failures = run_paper_comparison_campaign.build_rows(payload)
        run_paper_comparison_campaign.write_csv(args.output_csv, rows)
        result = {
            "passed": not failures and payload.get("passed") is True,
            "failures": failures,
            "rows": rows,
        }
        return result

    def test_export_contains_required_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = self.run_export(root, campaign_payload())
            csv_body = (root / "paper_comparison_campaign.csv").read_text(encoding="utf-8")
        self.assertTrue(result["passed"], result["failures"])
        self.assertIn("transcript_sha256", csv_body)
        self.assertIn("qemu_x86_64", csv_body)

    def test_missing_context_fails(self) -> None:
        payload = campaign_payload()
        payload["comparison_context"].pop("compiler")
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_export(Path(tmp), payload)
        self.assertFalse(result["passed"])
        self.assertTrue(any("compiler" in failure for failure in result["failures"]))

    def test_local_qemu_context_accepts_clock_assumption_and_zero_mad(self) -> None:
        payload = campaign_payload()
        payload["comparison_context"].pop("clock_source")
        payload["comparison_context"].pop("clock_mhz")
        payload["comparison_context"]["source_ecosystem"] = "pqcp-zephyr-trust-stack"
        payload["comparison_context"]["board_class"] = "qemu"
        payload["comparison_context"]["clock_assumption"] = "runner clock"
        payload["statistics"][0]["mad"] = 0.0
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = self.run_export(root, payload)
            csv_body = (root / "paper_comparison_campaign.csv").read_text(encoding="utf-8")
        self.assertTrue(result["passed"], result["failures"])
        self.assertIn("runner clock", csv_body)
        self.assertIn("not_applicable_qemu", csv_body)
        self.assertIn(",0.0,", csv_body)

    def test_external_context_still_requires_clock_metadata(self) -> None:
        payload = campaign_payload()
        payload["comparison_context"].pop("clock_source")
        payload["comparison_context"].pop("clock_mhz")
        payload["comparison_context"]["source_ecosystem"] = "pqm4"
        payload["comparison_context"]["board_class"] = "cortex-m4"
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_export(Path(tmp), payload)
        self.assertFalse(result["passed"])
        self.assertTrue(any("clock_source" in failure for failure in result["failures"]))
        self.assertTrue(any("clock_mhz" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
