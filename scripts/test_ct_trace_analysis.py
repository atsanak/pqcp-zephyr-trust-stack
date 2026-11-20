#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for ct_trace_analysis: each case can fail if the analyzer is wrong."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ct_trace_analysis as cta  # noqa: E402


def line(i, label=0, pc="a", addr="b", ln="c", div="d", ndiv=0, insns=100):
    f = lambda c: c * 16  # noqa: E731
    return (f"PQCP_CT_TRACE region={i} label={label} insns={insns} "
            f"loads=5 stores=3 ndiv={ndiv} h_pc={f(pc)} h_addr={f(addr)} "
            f"h_line={f(ln)} h_div={f(div)}")


def trace(*lines):
    return "\n".join(lines) + f"\nPQCP_CT_TRACE done regions={len(lines)}\n"


class TraceAnalysis(unittest.TestCase):
    def test_identical_regions_are_clean_with_zero_bits(self):
        a = cta.analyze(cta.parse_trace(trace(
            *[line(i, label=i % 2) for i in range(8)])))
        self.assertTrue(a.clean)
        self.assertEqual(a.worst_bits, 0.0)
        self.assertAlmostEqual(a.miss_bound_95, 3 / 8)
        self.assertEqual(a.labels, {0: 4, 1: 4})

    def test_one_divergent_region_on_one_channel_fails(self):
        for ch, kw in (("pc", {"pc": "e"}), ("addr", {"addr": "e"}),
                       ("line", {"ln": "e"}), ("div", {"div": "e"})):
            lines = [line(i) for i in range(6)]
            lines[3] = line(3, **kw)
            a = cta.analyze(cta.parse_trace(trace(*lines)))
            self.assertFalse(a.clean, ch)
            self.assertEqual(a.distinct[ch], 2)
            self.assertEqual(a.bits[ch], 1.0)
            self.assertIsNone(a.miss_bound_95)
            self.assertEqual([d[:2] for d in a.divergent], [(ch, 3)])

    def test_bits_grow_with_distinct_fingerprints(self):
        lines = [line(i, pc="abcd"[i % 4]) for i in range(8)]
        a = cta.analyze(cta.parse_trace(trace(*lines)))
        self.assertEqual(a.distinct["pc"], 4)
        self.assertEqual(a.bits["pc"], 2.0)

    def test_marker_formats_pass_and_fail(self):
        ok = cta.analyze(cta.parse_trace(trace(*[line(i) for i in range(4)])))
        self.assertIn("PQCP_CT_TRACE PASS alg=MLKEM-768 opt=Os regions=4",
                      cta.format_marker(ok, "MLKEM-768", "Os"))
        bad = cta.analyze(cta.parse_trace(trace(line(0), line(1, pc="e"))))
        self.assertIn("PQCP_CT_TRACE FAIL",
                      cta.format_marker(bad, "MLKEM-768", "Os"))

    def test_div_count_and_instruction_drift_are_reported(self):
        a = cta.analyze(cta.parse_trace(trace(
            line(0, ndiv=0), line(1, ndiv=2, insns=105))))
        self.assertEqual(a.ndiv, {0, 2})
        self.assertEqual(a.instructions, {100, 105})

    def test_malformed_input_is_an_error_not_a_pass(self):
        with self.assertRaises(cta.TraceError):
            cta.parse_trace("PQCP_CT_TRACE region=0 garbage\n")
        with self.assertRaises(cta.TraceError):
            cta.parse_trace(line(0) + "\n")  # no done line
        with self.assertRaises(cta.TraceError):
            cta.parse_trace(line(0) + "\nPQCP_CT_TRACE done regions=2\n")
        with self.assertRaises(cta.TraceError):
            cta.parse_trace(trace(line(1), line(0)))  # order
        with self.assertRaises(cta.TraceError):
            cta.analyze([])

    def test_a_reject_everything_analyzer_would_be_caught(self):
        """Control: identical data must pass; the suite fails if it did not."""
        a = cta.analyze(cta.parse_trace(trace(*[line(i) for i in range(3)])))
        self.assertTrue(a.clean)

    def test_variation_across_groups_is_allowed_within_a_group_is_not(self):
        # Two keys (label >> 8): public-data-dependent traces may differ
        # between them; ciphertext classes inside one key may not.
        lines = [line(0, label=0x000), line(1, label=0x001),
                 line(2, label=0x100, pc="e"), line(3, label=0x101, pc="e")]
        a = cta.analyze(cta.parse_trace(trace(*lines)))
        self.assertTrue(a.clean)
        self.assertEqual(a.groups, 2)
        self.assertEqual(a.cross_group_distinct["pc"], 2)
        lines[3] = line(3, label=0x101, pc="f")
        b = cta.analyze(cta.parse_trace(trace(*lines)))
        self.assertFalse(b.clean)
        self.assertEqual([d[:2] for d in b.divergent], [("pc", 3)])

    def test_non_trace_lines_are_ignored(self):
        text = "boot banner\n" + trace(line(0)) + "tail noise\n"
        self.assertEqual(len(cta.parse_trace(text)), 1)


if __name__ == "__main__":
    unittest.main()
