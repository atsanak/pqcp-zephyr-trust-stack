#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for metric-by-metric optimization campaign decisions."""

from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path

import optimize_metric_campaign


def stat(parameter_set: str, operation: str, median: float, p90: float | None = None, p99: float | None = None) -> dict[str, object]:
    return {
        "parameter_set": parameter_set,
        "implementation": "pqcp",
        "backend": "auto",
        "operation": operation,
        "sample_count": 5,
        "min": median,
        "median": median,
        "p90": p90 if p90 is not None else median,
        "p99": p99 if p99 is not None else median,
        "mad": 1.0,
        "rom_bytes": 1000,
        "ram_bytes": 500,
    }


def campaign(*stats: dict[str, object], backend_rankings: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "schema_version": 1,
        "passed": True,
        "comparison_context": {
            "source_dataset": "qemu",
            "source_ecosystem": "pqcp-local",
            "board_class": "qemu",
            "statistic_type": "distribution",
            "environment_type": "qemu",
        },
        "statistics": list(stats),
        "pairwise_ratios": [
            {
                "parameter_set": "ML-DSA-87",
                "operation": "sign",
                "candidate_backend": "auto",
                "baseline_backend": "clean",
                "ratio": 1.9,
            }
        ],
        "backend_rankings": backend_rankings or [],
    }


class OptimizeMetricCampaignTests(unittest.TestCase):
    def write_json(self, root: Path, name: str, payload: dict[str, object]) -> Path:
        path = root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def args(self, baseline: Path, candidates: list[str], output: Path) -> argparse.Namespace:
        return argparse.Namespace(
            baseline_campaign=baseline,
            candidate_campaign=candidates,
            cost_evidence=None,
            hardware_result=None,
            emit_overlays=None,
            target=["mldsa.sign"],
            output=output,
            min_median_improvement=0.05,
            max_tail_regression=0.03,
            max_resource_regression=0.0,
            require_kept=False,
        )

    def test_accepts_candidate_with_median_win_and_clean_tail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = self.write_json(root, "baseline.json", campaign(stat("ML-DSA-87", "sign", 100.0, 110.0, 115.0)))
            candidate = self.write_json(root, "candidate.json", campaign(stat("ML-DSA-87", "sign", 90.0, 111.0, 116.0)))
            result = optimize_metric_campaign.run(self.args(baseline, [f"native={candidate}"], root / "out.json"))
        self.assertTrue(result["passed"], result["failures"])
        self.assertEqual(result["candidate_results"][0]["decision"], "keep")

    def test_rejects_candidate_with_tail_regression(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = self.write_json(root, "baseline.json", campaign(stat("ML-DSA-87", "sign", 100.0, 110.0, 115.0)))
            candidate = self.write_json(root, "candidate.json", campaign(stat("ML-DSA-87", "sign", 90.0, 130.0, 140.0)))
            result = optimize_metric_campaign.run(self.args(baseline, [f"bad_tail={candidate}"], root / "out.json"))
        self.assertTrue(result["passed"], result["failures"])
        self.assertEqual(result["candidate_results"][0]["decision"], "reject")
        comparison = result["candidate_results"][0]["target_results"][0]["comparisons"][0]
        self.assertIn("p90 regressed", comparison["failure_reason"])

    def test_missing_candidate_metric_fails_loudly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = self.write_json(root, "baseline.json", campaign(stat("ML-DSA-87", "sign", 100.0)))
            candidate = self.write_json(root, "candidate.json", campaign(stat("ML-KEM-512", "encaps", 90.0)))
            result = optimize_metric_campaign.run(self.args(baseline, [f"missing={candidate}"], root / "out.json"))
        self.assertFalse(result["passed"])
        self.assertTrue(any("missing mldsa.sign" in failure for failure in result["failures"]))

    def test_backend_selection_flags_auto_not_fastest(self) -> None:
        rankings = [
            {
                "parameter_set": "ML-KEM-768",
                "operation": "decaps",
                "fastest_backend": "force_native",
                "auto_is_fastest": False,
                "candidates": [
                    {"backend": "force_native", "median_cycles": 90.0},
                    {"backend": "auto", "median_cycles": 100.0},
                ],
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = self.write_json(root, "baseline.json", campaign(stat("ML-DSA-87", "sign", 100.0), backend_rankings=rankings))
            result = optimize_metric_campaign.run(self.args(baseline, [], root / "out.json"))
        self.assertEqual(result["backend_selection"]["status"], "evaluated")
        self.assertEqual(result["backend_selection"]["auto_not_fastest_count"], 1)

    def test_hardware_absence_is_recorded_not_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = self.write_json(root, "baseline.json", campaign(stat("ML-DSA-87", "sign", 100.0)))
            result = optimize_metric_campaign.run(self.args(baseline, [], root / "out.json"))
        self.assertTrue(result["passed"])
        self.assertEqual(result["hardware_promotion"]["status"], "not_available")

    def test_can_emit_safe_candidate_overlay_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = self.write_json(root, "baseline.json", campaign(stat("ML-DSA-87", "sign", 100.0)))
            args = self.args(baseline, [], root / "out.json")
            args.emit_overlays = root / "overlays"
            result = optimize_metric_campaign.run(args)
        self.assertTrue(result["passed"], result["failures"])
        emitted_names = {Path(row["path"]).name for row in result["emitted_overlays"]}
        self.assertIn("force_native.conf", emitted_names)
        self.assertIn("single_level.conf.template", emitted_names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
