#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for the mutation runner's own edit and staleness logic."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_mutation_checks as mut  # noqa: E402


class ApplyEdit(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tree = Path(self.tmp.name)
        (self.tree / "f.c").write_text("if (a != 0) {\nif (b != 0) {\n")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_unique_match_is_replaced(self) -> None:
        self.assertIsNone(
            mut.apply_edit(self.tree, "f.c", r"if \(a != 0\) \{", "if (0) {"))
        self.assertIn("if (0) {", (self.tree / "f.c").read_text())

    def test_missing_pattern_is_reported_stale(self) -> None:
        problem = mut.apply_edit(self.tree, "f.c", r"no such text", "x")
        self.assertIn("matched 0 times", problem)

    def test_ambiguous_pattern_is_reported_stale(self) -> None:
        problem = mut.apply_edit(self.tree, "f.c", r"if \(\w != 0\) \{", "x")
        self.assertIn("matched 2 times", problem)
        self.assertIn("if (a != 0)", (self.tree / "f.c").read_text())

    def test_every_listed_mutant_matches_the_real_sources_once(self) -> None:
        """A rotted mutant list would otherwise surface only in CI."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mut.build_base(base)
            for mutant in mut.MUTANTS:
                for path, pattern, _ in ((mutant.path, mutant.pattern,
                                          mutant.replacement), *mutant.extra):
                    text = (base / path).read_text()
                    hits = mut.re.findall(pattern, text, flags=mut.re.S)
                    self.assertEqual(len(hits), 1, (mutant.name, path))


class SuiteSelection(unittest.TestCase):
    def test_every_mutant_names_a_known_suite(self) -> None:
        for mutant in mut.MUTANTS:
            self.assertIn(mutant.suite, mut.SUITES, mutant.name)

    def test_receipt_mutants_are_judged_by_the_appraisal_driver(self) -> None:
        receipt = [m for m in mut.MUTANTS
                   if m.path.endswith("receipt_verify.c")]
        self.assertGreaterEqual(len(receipt), 5)
        for mutant in receipt:
            self.assertEqual(mutant.suite, "appraisal", mutant.name)

    def test_existing_mutants_keep_the_verifier_suite(self) -> None:
        legacy = [m for m in mut.MUTANTS
                  if not m.path.endswith("receipt_verify.c")]
        self.assertEqual(len(legacy), 14)
        for mutant in legacy:
            self.assertEqual(mutant.suite, "verifier", mutant.name)


if __name__ == "__main__":
    unittest.main()
