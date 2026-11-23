#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for benchmark confidence replay."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import verify_benchmark_confidence


def campaign_payload(
    *,
    sample_count: int = 20,
    p90: float = 112.0,
    p99: float = 118.0,
    max_value: float = 125.0,
    candidate_samples: int | None = None,
    baseline_samples: int | None = None,
) -> dict[str, object]:
    if candidate_samples is None:
        candidate_samples = sample_count
    if baseline_samples is None:
        baseline_samples = sample_count
    return {
        "schema_version": 1,
        "passed": True,
        "statistics": [
            {
                "parameter_set": "ML-KEM-768",
                "implementation": "pqcp",
                "backend": "auto",
                "operation": "decaps",
                "sample_count": sample_count,
                "min": 95.0,
                "median": 100.0,
                "p90": p90,
                "p99": p99,
                "max": max_value,
                "mad": 4.0,
            },
            {
                "parameter_set": "ML-KEM-768",
                "implementation": "baseline",
                "backend": "clean",
                "operation": "decaps",
                "sample_count": baseline_samples,
                "min": 180.0,
                "median": 200.0,
                "p90": 220.0,
                "p99": 230.0,
                "max": 240.0,
                "mad": 7.0,
            },
        ],
        "pairwise_ratios": [
            {
                "parameter_set": "ML-KEM-768",
                "operation": "decaps",
                "candidate_implementation": "pqcp",
                "baseline_implementation": "baseline",
                "candidate_backend": "auto",
                "baseline_backend": "clean",
                "candidate_median_cycles": 100.0,
                "baseline_median_cycles": 200.0,
                "ratio": 0.5,
                "candidate_sample_count": candidate_samples,
                "baseline_sample_count": baseline_samples,
            }
        ],
    }


class BenchmarkConfidenceTests(unittest.TestCase):
    def write_campaign(self, payload: dict[str, object]) -> Path:
        root = Path(self.tmp.name)
        path = root / "campaign.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_paper_comparable_campaign_passes(self) -> None:
        result = verify_benchmark_confidence.verify(self.write_campaign(campaign_payload()))
        self.assertTrue(result["passed"], result["failures"])
        self.assertEqual(result["summary"]["paper_comparable_rows"], 2)
        self.assertEqual(result["summary"]["single_observation_rows"], 0)

    def test_single_observation_passes_with_warning_by_default(self) -> None:
        result = verify_benchmark_confidence.verify(self.write_campaign(campaign_payload(sample_count=1)))
        self.assertTrue(result["passed"], result["failures"])
        self.assertEqual(result["summary"]["paper_comparable_rows"], 0)
        self.assertGreaterEqual(result["summary"]["single_observation_rows"], 1)
        self.assertTrue(any("single observation" in warning for warning in result["warnings"]))

    def test_single_observation_fails_when_paper_comparable_is_required(self) -> None:
        result = verify_benchmark_confidence.verify(
            self.write_campaign(campaign_payload(sample_count=1)),
            require_paper_comparable=True,
        )
        self.assertFalse(result["passed"])
        self.assertTrue(any("paper-comparable" in failure for failure in result["failures"]))

    def test_non_monotonic_distribution_fails(self) -> None:
        result = verify_benchmark_confidence.verify(self.write_campaign(campaign_payload(p90=90.0, p99=110.0)))
        self.assertFalse(result["passed"])
        self.assertTrue(any("median <= p90" in failure for failure in result["failures"]))

    def test_max_must_bound_p99(self) -> None:
        result = verify_benchmark_confidence.verify(self.write_campaign(campaign_payload(max_value=100.0)))
        self.assertFalse(result["passed"])
        self.assertTrue(any("p99 <= max" in failure for failure in result["failures"]))

    def test_outlier_max_warns_without_failing_smoke(self) -> None:
        result = verify_benchmark_confidence.verify(self.write_campaign(campaign_payload(max_value=700.0)))
        self.assertTrue(result["passed"], result["failures"])
        self.assertEqual(result["summary"]["paper_comparable_rows"], 1)
        self.assertAlmostEqual(result["summary"]["max_outlier_spread_ratio"], 7.0)
        self.assertTrue(any("max/median outlier spread" in warning for warning in result["warnings"]))

    def test_outlier_max_blocks_required_paper_comparable_mode(self) -> None:
        result = verify_benchmark_confidence.verify(
            self.write_campaign(campaign_payload(max_value=700.0)),
            require_paper_comparable=True,
        )
        self.assertFalse(result["passed"])
        self.assertTrue(any("paper-comparable" in failure for failure in result["failures"]))

    def test_zero_sample_count_fails(self) -> None:
        result = verify_benchmark_confidence.verify(self.write_campaign(campaign_payload(sample_count=0)))
        self.assertFalse(result["passed"])
        self.assertTrue(any("sample_count" in failure for failure in result["failures"]))

    def test_pairwise_sample_mismatch_fails(self) -> None:
        result = verify_benchmark_confidence.verify(
            self.write_campaign(campaign_payload(candidate_samples=20, baseline_samples=10))
        )
        self.assertFalse(result["passed"])
        self.assertTrue(any("mismatched sample counts" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
