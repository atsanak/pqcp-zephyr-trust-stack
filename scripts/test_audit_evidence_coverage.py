#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for scripts/audit_evidence_coverage.py on a synthetic module tree."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit_evidence_coverage as cov  # noqa: E402


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build_tree(root: Path) -> None:
    # alpha: tested + gated + claimed (L3)
    write(root, "src/alpha.c", "int alpha_run(void)\n{\n\treturn 0;\n}\n")
    write(root, "tests/ztest_alpha/src/main.c",
          "void t(void) { alpha_run(); }\n")
    write(root, "scripts/run_extended_checks.py", '"tests/ztest_alpha"\n')
    write(root, "scripts/assurance_claims.json",
          json.dumps({"claims": [{"id": "x.alpha", "claim": "alpha works"}]}))
    # beta: tested + gated, no claim (L2)
    write(root, "src/beta.c", "int beta_run(void)\n{\n\treturn 0;\n}\n")
    write(root, "tests/ztest_beta/src/main.c",
          "void t(void) { beta_run(); }\n")
    write(root, "scripts/release_check.py", '"tests/ztest_beta"\n')
    # gamma: tested, not wired into any gate (L1)
    write(root, "src/gamma.c", "int gamma_run(void)\n{\n\treturn 0;\n}\n")
    write(root, "tests/ztest_gamma/src/main.c",
          "void t(void) { gamma_run(); }\n")
    # delta: no test, but alpha calls it (L0, reached transitively)
    write(root, "src/delta.c", "int delta_helper(void)\n{\n\treturn 1;\n}\n")
    write(root, "src/alpha.c",
          "int alpha_run(void)\n{\n\treturn delta_helper();\n}\n")
    # eps: nothing touches it (L0, unreachable)
    write(root, "src/eps.c", "int eps_orphan(void)\n{\n\treturn 2;\n}\n")
    write(root, "src/static_only.c",
          "static int hidden(void)\n{\n\treturn 3;\n}\n")


class CoverageLevels(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        build_tree(self.root)
        self.report = cov.build_report(self.root)
        self.by_name = {m["module"]: m for m in self.report["modules"]}

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_levels_are_assigned_by_evidence(self) -> None:
        self.assertEqual(self.by_name["alpha"]["level"], 3)
        self.assertEqual(self.by_name["beta"]["level"], 2)
        self.assertEqual(self.by_name["gamma"]["level"], 1)
        self.assertEqual(self.by_name["delta"]["level"], 0)
        self.assertEqual(self.by_name["eps"]["level"], 0)

    def test_transitive_reach_separates_delta_from_eps(self) -> None:
        self.assertEqual(self.by_name["delta"]["reach"], "transitive")
        self.assertEqual(self.by_name["eps"]["reach"], "none")
        self.assertEqual(self.by_name["alpha"]["reach"], "direct")
        summary = self.report["summary"]
        self.assertEqual(summary["L0_reached_transitively"], 1)
        # eps and static_only are unreachable
        self.assertEqual(summary["L0_unreachable_from_tests"], 2)

    def test_static_functions_do_not_count_as_public_symbols(self) -> None:
        self.assertEqual(self.by_name["static_only"]["defined_symbols"], 0)
        self.assertEqual(self.by_name["static_only"]["level"], 0)

    def test_summary_counts_add_up(self) -> None:
        summary = self.report["summary"]
        total = (summary["L0_untested"] + summary["L1_tested"] +
                 summary["L2_gated"] + summary["L3_claimed"])
        self.assertEqual(total, summary["modules"])
        self.assertEqual(summary["modules"], 6)


class CmakeConfigParsing(unittest.TestCase):
    def test_nested_if_frames_are_collected(self) -> None:
        text = (
            "if(CONFIG_PQCP)\n"
            "  if(CONFIG_PQCP_FOO)\n"
            "    zephyr_library_sources(${PQCP_SRC}/foo.c)\n"
            "  endif()\n"
            "  zephyr_library_sources(${PQCP_SRC}/bar.c)\n"
            "endif()\n"
            "zephyr_library_sources(${PQCP_SRC}/baz.c)\n")
        configs = cov.parse_cmake_configs(text)
        self.assertEqual(configs["foo"], ["CONFIG_PQCP", "CONFIG_PQCP_FOO"])
        self.assertEqual(configs["bar"], ["CONFIG_PQCP"])
        self.assertEqual(configs["baz"], [])


class Ratchet(unittest.TestCase):
    @staticmethod
    def report(levels: dict[str, int]) -> dict:
        return {"modules": [{"module": n, "level": lv}
                            for n, lv in levels.items()]}

    def test_regression_is_detected(self) -> None:
        regressions, orphans, improved = cov.check_ratchet(
            self.report({"a": 1, "b": 3}), {"a": 2, "b": 3})
        self.assertEqual(regressions, [("a", 2, 1)])
        self.assertEqual(orphans, [])
        self.assertEqual(improved, [])

    def test_new_untested_module_is_rejected(self) -> None:
        _, orphans, _ = cov.check_ratchet(
            self.report({"a": 2, "fresh": 0}), {"a": 2})
        self.assertEqual(orphans, ["fresh"])

    def test_new_tested_module_is_accepted(self) -> None:
        regressions, orphans, _ = cov.check_ratchet(
            self.report({"a": 2, "fresh": 1}), {"a": 2})
        self.assertEqual((regressions, orphans), ([], []))

    def test_known_untested_module_stays_allowed(self) -> None:
        regressions, orphans, _ = cov.check_ratchet(
            self.report({"legacy": 0}), {"legacy": 0})
        self.assertEqual((regressions, orphans), ([], []))

    def test_improvement_is_reported_not_failed(self) -> None:
        _, _, improved = cov.check_ratchet(
            self.report({"a": 3}), {"a": 1})
        self.assertEqual(improved, [("a", 1, 3)])


if __name__ == "__main__":
    unittest.main()
