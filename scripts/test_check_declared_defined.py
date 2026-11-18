#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for scripts/check_declared_defined.py on a synthetic tree."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_declared_defined as chk  # noqa: E402

HEADER = """\
#ifndef X_H_
#define X_H_
struct ctx { int (*cb)(void *p); int member; };
typedef int (*handler_fn)(void *p);
/** doc comment mentioning fake_in_comment(int x); */
int api_one(struct ctx *c);
int api_two(
	struct ctx *c,
	int value);
const char *api_name_first(int code);
int api_missing(struct ctx *c);
int api_also_missing(void);
static inline int api_inline(int a) { return a; }
#define api_macro(x) ((x) + 1)
#endif
"""

SOURCE = """\
int api_one(struct ctx *c)
{
	return 0;
}

int api_two(struct ctx *c, int value)
{
	return value;
}

const char *
api_name_first(int code)
{
	return "x";
}
"""


class DeclaredDefined(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / "include" / "pqcp_zephyr").mkdir(parents=True)
        (root / "src").mkdir()
        (root / "include" / "pqcp_zephyr" / "x.h").write_text(HEADER)
        (root / "src" / "x.c").write_text(SOURCE)
        self.saved = (chk.HEADERS, chk.SOURCES)
        chk.HEADERS = root / "include" / "pqcp_zephyr"
        chk.SOURCES = root / "src"

    def tearDown(self) -> None:
        chk.HEADERS, chk.SOURCES = self.saved
        self.tmp.cleanup()

    def test_consecutive_declarations_are_all_seen(self) -> None:
        declared = chk.declared_functions(chk.HEADERS / "x.h")
        # Regression: every other declaration used to be skipped.
        for name in ("api_one", "api_two", "api_name_first",
                     "api_missing", "api_also_missing"):
            self.assertIn(name, declared)

    def test_non_functions_are_not_declarations(self) -> None:
        declared = chk.declared_functions(chk.HEADERS / "x.h")
        self.assertNotIn("cb", declared)
        self.assertNotIn("handler_fn", declared)
        self.assertNotIn("fake_in_comment", declared)

    def test_only_truly_undefined_functions_are_reported(self) -> None:
        report = chk.build_report()
        self.assertEqual(report, {"x.h": ["api_also_missing", "api_missing"]})

    def test_name_first_definition_style_counts_as_defined(self) -> None:
        # Regression: return type on the previous line used to be missed.
        self.assertIn("api_name_first", chk.defined_functions())

    def test_inline_and_macro_definitions_count_as_defined(self) -> None:
        defined = chk.defined_functions()
        self.assertIn("api_inline", defined)
        self.assertIn("api_macro", defined)


if __name__ == "__main__":
    unittest.main()
