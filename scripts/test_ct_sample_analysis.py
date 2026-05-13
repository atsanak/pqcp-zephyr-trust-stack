#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Regression tests for CT sample transcript analysis."""

from __future__ import annotations

import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import analyze_ct_samples


class CtSampleAnalysisTests(unittest.TestCase):
    def run_analysis(self, body: str, *, min_samples: int = 4) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transcript = root / "ct.log"
            transcript.write_text(body, encoding="utf-8")
            return analyze_ct_samples.analyze(
                Namespace(
                    transcript=[transcript],
                    transcript_dir=None,
                    output=root / "result.json",
                    min_samples=min_samples,
                    relative_bound_percent=50.0,
                    t2_bound=10000.0,
                )
            )

    def test_clean_distribution_passes(self) -> None:
        lines = []
        for i in range(8):
            lines.append(f"PQCP_CT_SAMPLE alg=MLKEM-768 class=valid idx={i} cycles={100 + i % 2}")
            lines.append(f"PQCP_CT_SAMPLE alg=MLKEM-768 class=invalid idx={i} cycles={101 + i % 2}")
        self.assertTrue(self.run_analysis("\n".join(lines))["passed"])

    def test_missing_samples_fail(self) -> None:
        self.assertFalse(self.run_analysis("PROJECT EXECUTION SUCCESSFUL\n")["passed"])

    def test_obvious_bifurcation_fails(self) -> None:
        lines = []
        for i in range(8):
            lines.append(f"PQCP_CT_SAMPLE alg=MLKEM-768 class=valid idx={i} cycles=100")
            lines.append(f"PQCP_CT_SAMPLE alg=MLKEM-768 class=invalid idx={i} cycles=300")
        self.assertFalse(self.run_analysis("\n".join(lines))["passed"])

    def test_insufficient_sample_count_fails(self) -> None:
        lines = []
        for i in range(2):
            lines.append(f"PQCP_CT_SAMPLE alg=MLKEM-768 class=valid idx={i} cycles=100")
            lines.append(f"PQCP_CT_SAMPLE alg=MLKEM-768 class=invalid idx={i} cycles=101")
        self.assertFalse(self.run_analysis("\n".join(lines), min_samples=4)["passed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
