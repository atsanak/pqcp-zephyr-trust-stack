#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for CT campaign replay."""

from __future__ import annotations

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import run_ct_campaign


class CtCampaignTests(unittest.TestCase):
    def write_inputs(self, root: Path, *, duplicate: bool = False) -> tuple[Path, Path]:
        algorithms = []
        analysis_algs = []
        for alg in ("MLKEM-512", "MLKEM-768", "MLKEM-1024"):
            valid = [0, 1, 1] if duplicate and alg == "MLKEM-768" else [0, 1, 2]
            algorithms.append(
                {
                    "algorithm": alg,
                    "valid_count": 3,
                    "invalid_count": 3,
                    "valid_indexes": valid,
                    "invalid_indexes": [0, 1, 2],
                    "passed": True,
                }
            )
            analysis_algs.append({"algorithm": alg, "valid_count": 3, "invalid_count": 3, "passed": True})
        analysis = root / "analysis.json"
        manifest = root / "manifest.json"
        analysis.write_text(json.dumps({"schema_version": 1, "passed": True, "algorithms": analysis_algs}), encoding="utf-8")
        manifest.write_text(json.dumps({"schema_version": 1, "algorithms": algorithms}), encoding="utf-8")
        return analysis, manifest

    def test_campaign_passes_balanced_contiguous_samples(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            analysis, manifest = self.write_inputs(Path(tmp))
            result = run_ct_campaign.run(Namespace(analysis=analysis, manifest=manifest, output=Path(tmp) / "out.json", min_algorithms=3))
        self.assertTrue(result["passed"], result["failures"])

    def test_duplicate_indexes_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            analysis, manifest = self.write_inputs(Path(tmp), duplicate=True)
            result = run_ct_campaign.run(Namespace(analysis=analysis, manifest=manifest, output=Path(tmp) / "out.json", min_algorithms=3))
        self.assertFalse(result["passed"])
        self.assertTrue(any("not contiguous" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
