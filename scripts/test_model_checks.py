#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for the edge model-check runner's parser, verdicts and defect list.

These use synthetic marker transcripts; they never build firmware.
"""

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_model_checks as mc  # noqa: E402

EXEC_OK = "PROJECT EXECUTION SUCCESSFUL\n"


def check_line(module: str, seeds: int = 64, ops: int = 1000,
               violations: int = 0, status: str = "PASS") -> str:
    return (f"PQCP_MODEL_CHECK module={module} seeds={seeds} ops={ops} "
            f"violations={violations} status={status}\n")


def cex_line(module: str, violation: str = "3", ops: int = 4,
             trace_ops: int | None = None) -> str:
    trace = "01020304050607" * (ops if trace_ops is None else trace_ops)
    return (f"PQCP_MODEL_COUNTEREXAMPLE module={module} "
            f"seed=00000000deadbeef violation={violation} ops={ops} "
            f"trace={trace}\n")


def summary_line(traces: int = 256, ops: int = 4000, violations: int = 0,
                 status: str = "PASS", modules: int = 4) -> str:
    return (f"PQCP_MODEL_SUMMARY modules={modules} traces={traces} "
            f"ops={ops} violations={violations} status={status}\n")


def good_transcript() -> str:
    return ("".join(check_line(m) for m in mc.MODULES) +
            summary_line(traces=256, ops=4000) + EXEC_OK)


def problems_of(text: str, **kwargs) -> list[str]:
    return mc.assess_conformance(mc.parse_transcript(text), **kwargs)


class ParserTests(unittest.TestCase):
    def test_pass_transcript_is_clean(self) -> None:
        parsed = mc.parse_transcript(good_transcript())
        self.assertEqual(len(parsed.checks), 4)
        self.assertEqual(parsed.summaries[0].traces, 256)
        self.assertTrue(parsed.execution_ok)
        self.assertEqual(mc.assess_conformance(parsed), [])

    def test_missing_summary_fails(self) -> None:
        text = "".join(check_line(m) for m in mc.MODULES) + EXEC_OK
        self.assertTrue(any("PQCP_MODEL_SUMMARY" in p for p in problems_of(text)))

    def test_missing_module_fails(self) -> None:
        text = ("".join(check_line(m) for m in mc.MODULES[:3]) +
                summary_line(traces=192, ops=3000) + EXEC_OK)
        found = problems_of(text)
        self.assertTrue(any("missing CHECK marker for module policy" in p
                            for p in found), found)

    def test_violations_fail(self) -> None:
        text = ("".join(check_line(m) for m in mc.MODULES[:3]) +
                check_line("policy", violations=2, status="FAIL") +
                summary_line(violations=2, status="FAIL") + EXEC_OK)
        found = problems_of(text)
        self.assertTrue(any("policy reports status=FAIL" in p for p in found))
        self.assertTrue(any("summary reports status=FAIL" in p for p in found))

    def test_counterexample_in_plain_run_fails(self) -> None:
        found = problems_of(good_transcript() + cex_line("session"))
        self.assertTrue(any("counterexample for module session" in p
                            for p in found), found)

    def test_zero_ops_module_fails(self) -> None:
        text = (check_line("principal", ops=0) +
                "".join(check_line(m) for m in mc.MODULES[1:]) +
                summary_line(ops=3000) + EXEC_OK)
        self.assertTrue(any("ran no traces" in p for p in problems_of(text)))

    def test_duplicate_and_unknown_module_fail(self) -> None:
        text = good_transcript() + check_line("principal") + check_line("bogus")
        found = problems_of(text)
        self.assertTrue(any("duplicate CHECK" in p for p in found))
        self.assertTrue(any("unknown module" in p for p in found))

    def test_summary_totals_must_match_modules(self) -> None:
        text = ("".join(check_line(m) for m in mc.MODULES) +
                summary_line(traces=255, ops=4000) + EXEC_OK)
        self.assertTrue(any("trace count" in p for p in problems_of(text)))
        text = ("".join(check_line(m) for m in mc.MODULES) +
                summary_line(traces=256, ops=1) + EXEC_OK)
        self.assertTrue(any("op count" in p for p in problems_of(text)))

    def test_summary_module_count_is_pinned(self) -> None:
        text = ("".join(check_line(m) for m in mc.MODULES) +
                summary_line(modules=3) + EXEC_OK)
        self.assertTrue(any("covers 3 modules" in p for p in problems_of(text)))

    def test_execution_failure_marker_fails(self) -> None:
        text = good_transcript().replace(
            "PROJECT EXECUTION SUCCESSFUL", "PROJECT EXECUTION FAILED")
        self.assertTrue(any("PROJECT EXECUTION" in p for p in problems_of(text)))
        self.assertEqual(problems_of(text, require_execution=False), [])

    def test_malformed_counterexample_is_ignored(self) -> None:
        bad = ("PQCP_MODEL_COUNTEREXAMPLE module=policy seed=xyz violation=1 "
               "ops=2 trace=zz\n")
        self.assertEqual(mc.parse_transcript(bad).counterexamples, [])


class ClassificationTests(unittest.TestCase):
    def classify(self, module: str, text: str) -> tuple:
        return mc.classify_defect(module, mc.parse_transcript(text))

    def test_counterexample_for_expected_module_is_rediscovery(self) -> None:
        text = (cex_line("credential") + check_line("credential", violations=1,
                status="FAIL") + summary_line(violations=1, status="FAIL") +
                "PROJECT EXECUTION FAILED\n")
        status, note = self.classify("credential", text)
        self.assertEqual(status, "rediscovered")
        self.assertIn("cex_module=credential", note)

    def test_counterexample_for_wrong_module_does_not_count(self) -> None:
        status, note = self.classify(
            "principal", cex_line("session") + "PROJECT EXECUTION FAILED\n")
        self.assertEqual(status, "missed")
        self.assertIn("not principal", note)

    def test_counterexample_with_inconsistent_trace_does_not_count(self) -> None:
        status, _ = self.classify(
            "policy", cex_line("policy", ops=4, trace_ops=3) +
            "PROJECT EXECUTION FAILED\n")
        self.assertEqual(status, "missed")
        status, _ = self.classify(
            "policy", cex_line("policy", ops=0, trace_ops=0).replace(
                "trace=", "trace=00") + "PROJECT EXECUTION FAILED\n")
        self.assertEqual(status, "missed")

    def test_wrong_module_alongside_right_module_counts(self) -> None:
        text = cex_line("session") + cex_line("principal")
        self.assertEqual(self.classify("principal", text)[0], "rediscovered")

    def test_passing_run_is_missed(self) -> None:
        status, note = self.classify("policy", good_transcript())
        self.assertEqual(status, "missed")
        self.assertIn("passed", note)

    def test_failure_without_marker_is_not_a_rediscovery(self) -> None:
        status, note = self.classify(
            "policy", "ASSERTION FAIL\nPROJECT EXECUTION FAILED\n")
        self.assertEqual(status, "missed")
        self.assertIn("without a counterexample marker", note)

    def test_counterexample_with_pass_summary_is_inconsistent(self) -> None:
        status, _ = self.classify("policy",
                                  cex_line("policy") + summary_line())
        self.assertEqual(status, "ERROR")

    def test_empty_output_is_missed_not_rediscovered(self) -> None:
        self.assertEqual(self.classify("policy", "")[0], "missed")


def defect(ident: str = "H1", allowance: str = "") -> mc.HistoricalDefect:
    return mc._defect(ident, "policy", "synthetic", "src/x.c", "a", "b",
                      allowance)


class VerdictTests(unittest.TestCase):
    baseline = {"rediscovered_min": 2, "defects_total": 3}

    def outcomes(self, *statuses: str):
        return [(defect(f"H{i}"), s, "note") for i, s in enumerate(statuses)]

    def test_pass_marker_format(self) -> None:
        problems, marker = mc.judge_rediscovery(
            self.outcomes("rediscovered", "rediscovered", "rediscovered"),
            self.baseline)
        self.assertEqual(problems, [])
        self.assertEqual(
            marker, "PQCP_MODEL_REDISCOVERY PASS rediscovered=3/3 allowed=0")
        self.assertRegex(marker, mc.REDISCOVERY_RE)

    def test_allowed_miss_is_counted_and_visible(self) -> None:
        problems, marker = mc.judge_rediscovery(
            self.outcomes("rediscovered", "rediscovered", "allowed"),
            self.baseline)
        self.assertEqual(problems, [])
        self.assertIn("rediscovered=2/3 allowed=1", marker)

    def test_miss_without_allowance_fails(self) -> None:
        problems, marker = mc.judge_rediscovery(
            self.outcomes("rediscovered", "rediscovered", "missed"),
            self.baseline)
        self.assertTrue(any("missed without an allowance" in p
                            for p in problems))
        self.assertIn("FAIL", marker)
        self.assertNotRegex(marker, mc.REDISCOVERY_RE)

    def test_stale_pattern_fails(self) -> None:
        problems, marker = mc.judge_rediscovery(
            self.outcomes("rediscovered", "rediscovered", "STALE"),
            self.baseline)
        self.assertTrue(any("STALE" in p for p in problems))
        self.assertNotRegex(marker, mc.REDISCOVERY_RE)

    def test_build_error_fails(self) -> None:
        problems, _ = mc.judge_rediscovery(
            self.outcomes("rediscovered", "rediscovered", "ERROR"),
            self.baseline)
        self.assertTrue(any("ERROR" in p for p in problems))

    def test_baseline_regression_fails_even_with_allowances(self) -> None:
        problems, marker = mc.judge_rediscovery(
            self.outcomes("rediscovered", "allowed", "allowed"),
            self.baseline)
        self.assertTrue(any("below the baseline 2" in p for p in problems))
        self.assertNotRegex(marker, mc.REDISCOVERY_RE)

    def test_shrinking_the_defect_list_fails(self) -> None:
        problems, _ = mc.judge_rediscovery(
            self.outcomes("rediscovered", "rediscovered"), self.baseline)
        self.assertTrue(any("shrank" in p for p in problems))

    def test_defect_line_matches_grammar(self) -> None:
        line = mc.defect_line(defect("H7"), "rediscovered")
        self.assertRegex(line, mc.DEFECT_LINE_RE)


class BaselineTests(unittest.TestCase):
    def test_committed_baseline_is_valid_and_matches_defect_count(self) -> None:
        baseline = mc.load_baseline()
        self.assertLessEqual(baseline["rediscovered_min"],
                             len(mc.HISTORICAL_DEFECTS))
        self.assertEqual(baseline["defects_total"],
                         len(mc.HISTORICAL_DEFECTS))

    def test_malformed_baseline_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            for bad in ({"rediscovered_min": -1}, {"rediscovered_min": "8"},
                        {"rediscovered_min": True},
                        {"rediscovered_min": 1, "defects_total": 0}, {}):
                path.write_text(json.dumps(bad))
                with self.assertRaises(ValueError, msg=bad):
                    mc.load_baseline(path)


class DefectListTests(unittest.TestCase):
    def test_ids_are_unique_and_modules_known(self) -> None:
        ids = [d.ident for d in mc.HISTORICAL_DEFECTS]
        self.assertEqual(len(ids), len(set(ids)))
        for d in mc.HISTORICAL_DEFECTS:
            self.assertIn(d.module, mc.MODULES, d.ident)

    def test_every_module_has_a_defect(self) -> None:
        self.assertEqual({d.module for d in mc.HISTORICAL_DEFECTS},
                         set(mc.MODULES))

    def test_every_allowance_states_a_reason(self) -> None:
        for d in mc.HISTORICAL_DEFECTS:
            if d.mutant.allowance:
                self.assertGreater(len(d.mutant.allowance), 40, d.ident)

    def test_every_pattern_matches_the_current_source_exactly_once(self) -> None:
        for d in mc.HISTORICAL_DEFECTS:
            text = (mc.MODULE_ROOT / d.mutant.path).read_text(encoding="utf-8")
            hits = re.findall(d.mutant.pattern, text, flags=re.S)
            self.assertEqual(len(hits), 1, d.ident)

    def test_check_patterns_accepts_the_real_sources(self) -> None:
        self.assertEqual(mc.check_patterns(mc.MODULE_ROOT), [])

    def test_check_patterns_reports_stale_and_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src/x.c").write_text("a a\n")
            ambiguous = mc._defect("HA", "policy", "n", "src/x.c", "a", "b")
            self.assertTrue(any("matched 2 times" in p for p in
                                mc.check_patterns(root, (ambiguous,))))
            stale = mc._defect("HS", "policy", "n", "src/x.c", "zzz", "b")
            self.assertTrue(any("matched 0 times" in p for p in
                                mc.check_patterns(root, (stale,))))
            noop = mc._defect("HN", "policy", "n", "src/x.c", "a a", "a a")
            self.assertTrue(any("unchanged" in p for p in
                                mc.check_patterns(root, (noop,))))

    def test_check_patterns_does_not_modify_the_tree(self) -> None:
        before = {d.mutant.path: (mc.MODULE_ROOT / d.mutant.path).read_bytes()
                  for d in mc.HISTORICAL_DEFECTS}
        mc.check_patterns(mc.MODULE_ROOT)
        for path, data in before.items():
            self.assertEqual((mc.MODULE_ROOT / path).read_bytes(), data)


if __name__ == "__main__":
    unittest.main()
