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


def seg(region, seq, site, length=4, cls=0, pc="a", addr="b", ln="c",
        div="d"):
    f = lambda c: c * 16  # noqa: E731
    return (f"PQCP_CT_SEG region={region} seq={seq} site={site} len={length} "
            f"cls={cls} insns=10 loads=1 stores=1 ndiv=0 h_pc={f(pc)} "
            f"h_addr={f(addr)} h_line={f(ln)} h_div={f(div)}")


def declass(regions):
    """regions: {label: [(site, length, cls, pc), ...]} -> (regions, segs)."""
    lines, seglines = [], []
    for idx, (label, events) in enumerate(regions.items()):
        lines.append(line(idx, label=label))
        for n, (site, length, cls, pc) in enumerate(events):
            seglines.append(seg(idx, n, site, length, cls, pc=pc))
        seglines.append(seg(idx, len(events), 0, 0, 0))
    text = trace(*lines) + "\n".join(seglines) + "\n"
    return cta.parse_trace(text), cta.parse_segments(text)


class DeclassifiedAnalysis(unittest.TestCase):
    def test_runs_that_agree_on_declassified_values_must_match(self):
        same = {0: [(100, 8, 7, "a"), (200, 4, 0, "a")],
                1: [(100, 8, 7, "a"), (200, 4, 0, "a")]}
        a = cta.analyze_declassified(*declass(same))
        self.assertTrue(a.clean)
        self.assertEqual(a.testable, a.segments)

    def test_a_trace_difference_with_equal_declassified_prefix_is_a_leak(self):
        leak = {0: [(100, 8, 7, "a"), (200, 4, 0, "a")],
                1: [(100, 8, 7, "a"), (200, 4, 0, "e")]}
        a = cta.analyze_declassified(*declass(leak))
        self.assertFalse(a.clean)
        self.assertEqual({v[0] for v in a.violations}, {"pc"})

    def test_a_declassified_outcome_may_change_what_runs_next(self):
        # Iteration 0 rejects in one run (flag=1) and accepts in the other
        # (flag=0): the following segments have different prefixes, so they
        # are not compared and the divergence is not a violation.
        ok = {0: [(100, 8, 7, "a"), (200, 4, 1, "a"), (100, 8, 9, "b")],
              1: [(100, 8, 7, "a"), (200, 4, 0, "a"), (300, 4, 0, "c")]}
        a = cta.analyze_declassified(*declass(ok))
        self.assertTrue(a.clean)

    def test_unexplained_control_flow_divergence_is_reported(self):
        # Same prefix, but the next event is reached at different sites.
        leak = {0: [(100, 8, 7, "a"), (200, 4, 0, "a")],
                1: [(100, 8, 7, "a"), (999, 4, 0, "a")]}
        a = cta.analyze_declassified(*declass(leak))
        self.assertIn("control", {v[0] for v in a.violations})

    def test_groups_are_independent(self):
        two = {0x000: [(1, 4, 0, "a")], 0x001: [(1, 4, 0, "a")],
               0x100: [(1, 4, 0, "e")], 0x101: [(1, 4, 0, "e")]}
        self.assertTrue(cta.analyze_declassified(*declass(two)).clean)

    def test_all_singletons_is_not_a_pass(self):
        solo = {0: [(1, 4, 0, "a")], 0x100: [(1, 4, 0, "e")]}
        a = cta.analyze_declassified(*declass(solo))
        self.assertEqual(a.testable, 0)
        self.assertFalse(a.clean)

    def test_malformed_segment_lines_are_rejected(self):
        with self.assertRaises(cta.TraceError):
            cta.parse_segments("PQCP_CT_SEG region=0 nonsense\n")
        with self.assertRaises(cta.TraceError):  # no tail segment
            cta.parse_segments(seg(0, 0, 5) + "\n")
        with self.assertRaises(cta.TraceError):  # seq gap
            cta.parse_segments(seg(0, 1, 0) + "\n")

    def test_marker_format(self):
        a = cta.analyze_declassified(*declass(
            {0: [(1, 4, 0, "a")], 1: [(1, 4, 0, "a")]}))
        marker = cta.format_declass_marker(a, "MLDSA-65", "default")
        self.assertTrue(marker.startswith(
            "PQCP_CT_TRACE_DECLASS PASS alg=MLDSA-65 opt=default"))
        self.assertIn("violations=0", marker)


if __name__ == "__main__":
    unittest.main()
