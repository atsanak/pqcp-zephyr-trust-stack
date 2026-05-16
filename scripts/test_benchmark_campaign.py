#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for benchmark campaign replay."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import verify_benchmark_campaign
import run_benchmark_campaign


class BenchmarkCampaignTests(unittest.TestCase):
    def write_campaign(self, root: Path, *, context: bool = True) -> Path:
        payload = {
            "schema_version": 1,
            "passed": True,
            "comparison_context": {
                "source_dataset": "qemu",
                "source_ecosystem": "pqcp-local",
                "board_class": "qemu",
                "statistic_type": "single_or_distribution",
                "environment_type": "qemu",
            } if context else {},
            "statistics": [
                {
                    "parameter_set": "ML-KEM-768",
                    "implementation": "pqcp",
                    "operation": "decaps",
                    "sample_count": 1,
                    "min": 10,
                    "median": 10,
                    "p90": 10,
                    "p99": 10,
                    "mad": 0,
                }
            ],
            "pairwise_ratios": [
                {
                    "parameter_set": "ML-KEM-768",
                    "operation": "decaps",
                    "candidate_implementation": "pqcp",
                    "baseline_implementation": "baseline",
                    "candidate_backend": "auto",
                    "baseline_backend": "clean",
                    "candidate_median_cycles": 10,
                    "baseline_median_cycles": 20,
                    "ratio": 0.5,
                }
            ],
            "summary": {
                "pairwise_comparisons": {
                    "comparison_count": 1,
                    "numeric_ratio_count": 1,
                    "geomean_ratio": 0.5,
                }
            },
        }
        path = root / "campaign.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_campaign_replay_passes_with_context_and_stats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = verify_benchmark_campaign.verify(self.write_campaign(Path(tmp)))
        self.assertTrue(result["passed"], result["failures"])

    def test_campaign_replay_fails_without_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = verify_benchmark_campaign.verify(self.write_campaign(Path(tmp), context=False))
        self.assertFalse(result["passed"])
        self.assertTrue(any("comparison_context" in failure for failure in result["failures"]))

    def test_pairwise_ratio_summary_prefers_median_cycles(self) -> None:
        summaries = [
            {
                "parameter_set": "ML-KEM-768",
                "implementation": "pqcp",
                "backend": "auto",
                "operation": "decaps",
                "sample_count": 3,
                "median": 100.0,
            },
            {
                "parameter_set": "ML-KEM-768",
                "implementation": "baseline",
                "backend": "clean",
                "operation": "decaps",
                "sample_count": 3,
                "median": 200.0,
            },
            {
                "parameter_set": "ML-DSA-65",
                "implementation": "pqcp",
                "backend": "auto",
                "operation": "verify",
                "sample_count": 3,
                "median": 80.0,
            },
            {
                "parameter_set": "ML-DSA-65",
                "implementation": "baseline",
                "backend": "clean",
                "operation": "verify",
                "sample_count": 3,
                "median": 320.0,
            },
        ]
        ratios = run_benchmark_campaign.build_pairwise_ratios(summaries)
        summary = run_benchmark_campaign.comparison_summary(ratios)
        self.assertEqual(len(ratios), 2)
        self.assertAlmostEqual(summary["geomean_ratio"], (0.5 * 0.25) ** 0.5)
        self.assertEqual(summary["pqcp_faster_count"], 2)

    def test_backend_rankings_keep_auto_and_force_native_separate(self) -> None:
        summaries = [
            {
                "parameter_set": "ML-KEM-768",
                "implementation": "pqcp",
                "backend": "auto",
                "operation": "decaps",
                "sample_count": 3,
                "median": 100.0,
            },
            {
                "parameter_set": "ML-KEM-768",
                "implementation": "pqcp",
                "backend": "force_native",
                "operation": "decaps",
                "sample_count": 3,
                "median": 90.0,
            },
            {
                "parameter_set": "ML-KEM-768",
                "implementation": "baseline",
                "backend": "clean",
                "operation": "decaps",
                "sample_count": 3,
                "median": 200.0,
            },
        ]
        ratios = run_benchmark_campaign.build_pairwise_ratios(summaries)
        rankings = run_benchmark_campaign.build_backend_rankings(summaries)
        self.assertEqual(ratios[0]["candidate_backend"], "auto")
        self.assertEqual(rankings[0]["fastest_backend"], "force_native")
        self.assertFalse(rankings[0]["auto_is_fastest"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
