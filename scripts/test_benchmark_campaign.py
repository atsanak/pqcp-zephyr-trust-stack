#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for benchmark campaign replay."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import verify_benchmark_campaign


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
