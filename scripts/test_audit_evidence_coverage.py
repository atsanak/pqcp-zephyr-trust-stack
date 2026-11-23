#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
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


class TwisterGating(unittest.TestCase):
    RUN = ('      - run: |\n          west twister \\\n'
           '            -T "$GITHUB_WORKSPACE/tests" \\\n'
           '            -p qemu_x86_64 \\\n'
           '            --outdir out\n')
    BUILD_ONLY = RUN.replace("--outdir", "--build-only \\\n            --outdir")

    def test_run_mode_sweep_over_tests_is_detected(self) -> None:
        self.assertTrue(cov.twister_runs_all_tests({"workflow:ci.yml": self.RUN}))

    def test_build_only_sweep_does_not_count(self) -> None:
        self.assertFalse(
            cov.twister_runs_all_tests({"workflow:ci.yml": self.BUILD_ONLY}))

    def test_non_workflow_surfaces_are_ignored(self) -> None:
        self.assertFalse(
            cov.twister_runs_all_tests({"release_check": self.RUN}))

    def test_registered_suite_is_gated_only_when_sweep_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "src/zed.c", "int zed_run(void)\n{\n\treturn 0;\n}\n")
            write(root, "tests/ztest_zed/src/main.c",
                  "void t(void) { zed_run(); }\n")
            write(root, "tests/ztest_zed/testcase.yaml", "tests: {}\n")
            write(root, ".github/workflows/ci.yml", self.BUILD_ONLY)
            before = cov.build_report(root)["modules"][0]["level"]
            write(root, ".github/workflows/ci.yml", self.RUN)
            after = cov.build_report(root)["modules"][0]["level"]
            self.assertEqual((before, after), (1, 2))


class CSourceEvidence(unittest.TestCase):
    FALSE_REFERENCES = (
        "// victim_run();\n",
        "/* documentation\n victim_run(); */\n",
        'const char *s = "victim_run()";\n',
        "int c = 'victim_run';\n",
        "int victim_run(void);\n",
        "extern int\nvictim_run(void);\n",
        "int register_cb(int (*victim_run)(void));\n",
        "#define UNUSED() victim_run()\n",
        "#define UNUSED() \\\n victim_run()\n",
        "// continued comment \\\n victim_run();\n",
        "victim_/* token boundary */run();\n",
    )

    def test_noncode_and_declarations_cannot_promote_evidence(self) -> None:
        for fake in self.FALSE_REFERENCES:
            with self.subTest(fake=fake), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                write(root, "src/victim.c",
                      "int victim_run(void) { return 0; }\n")
                write(root, "src/driver.c",
                      fake + "int driver_run(void) { return 0; }\n")
                write(root, "tests/ztest_driver/src/main.c",
                      fake + "void test(void) { driver_run(); }\n")
                report = cov.build_report(root)
                victim = next(m for m in report["modules"]
                              if m["module"] == "victim")
                self.assertEqual(victim["level"], 0)
                self.assertEqual(victim["reach"], "none")
                self.assertEqual(victim["exercised_by"], [])
                _, orphans, _ = cov.check_ratchet(report, {"driver": 1})
                self.assertEqual(orphans, ["victim"])

    def test_only_real_external_definitions_are_owned(self) -> None:
        source = '''
/* int commented(void) { return 0; } */
const char *s = "int quoted(void) { return 0; }";
int prototype(void);
static int hidden(void) { return 0; }
static\nint\nhidden_split(void) { return 0; }
static inline int also_hidden(void) { return 0; }
int ordinary(void) { return 0; }
const char *\nname_first(int code) { return s; }
int with_callback(int (*callback)(void)) { return callback(); }
'''
        self.assertEqual(cov.defined_symbols(source),
                         {"ordinary", "name_first", "with_callback"})

    def test_test_function_definition_is_not_an_exerciser(self) -> None:
        self.assertNotIn("victim_run", cov.referenced_symbols(
            "int victim_run(void) { return 0; }\n"))

    def test_real_calls_and_callback_values_are_references(self) -> None:
        for code in (
                "void test(void) { victim_run(); }",
                "void test(void) { int (*cb)(void) = victim_run; cb(); }",
                "void test(void) { register_cb(&victim_run); }",
                "int (*callbacks[])(void) = { victim_run };",
                "int driver_run(void) { return victim_run(); }"):
            with self.subTest(code=code):
                self.assertIn("victim_run", cov.referenced_symbols(code))

    def test_escaped_literals_do_not_expose_fake_code(self) -> None:
        code = r'''const char *s = "escaped \" victim_run() /*";
char quote = '\'';
char slash = '\\';
void test(void) { real_run(); }
'''
        refs = cov.referenced_symbols(code)
        self.assertNotIn("victim_run", refs)
        self.assertIn("real_run", refs)


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
