#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Regression tests for backend-currency verification."""

from __future__ import annotations

import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import verify_backend_currency


MLKEM_SHA = "e07bff537f38b457601e524038f2395e235b011b"
MLDSA_SHA = "0f8b8e074b2525eb844b022b03b962bf888d51aa"


def write_repo(root: Path, *, mlkem_revision: str = MLKEM_SHA) -> None:
    (root / "west.yml").write_text(
        f"""manifest:
  self:
    path: pqcp-zephyr-trust-stack
  remotes:
    - name: pqcp
      url-base: https://github.com/pq-code-package
  projects:
    - name: mlkem-native
      remote: pqcp
      revision: {mlkem_revision}
      path: modules/crypto/mlkem-native
    - name: mldsa-native
      remote: pqcp
      revision: {MLDSA_SHA}
      path: modules/crypto/mldsa-native
""",
        encoding="utf-8",
    )
    (root / ".gitmodules").write_text(
        """[submodule "ext/mlkem-native"]
	path = ext/mlkem-native
	url = https://github.com/pq-code-package/mlkem-native
[submodule "ext/mldsa-native"]
	path = ext/mldsa-native
	url = https://github.com/pq-code-package/mldsa-native
""",
        encoding="utf-8",
    )


class BackendCurrencyTests(unittest.TestCase):
    def test_offline_pin_metadata_passes_with_west_and_gitmodules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root)
            result = verify_backend_currency.verify(
                Namespace(
                    module_path=root,
                    west_manifest=root / "west.yml",
                    output=root / "result.json",
                    check_upstream=False,
                    require_initialized_submodules=False,
                )
            )
        self.assertTrue(result["passed"])
        self.assertEqual(len(result["backends"]), 2)
        self.assertTrue(all(row["west_revision"] for row in result["backends"]))

    def test_non_sha_revision_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root, mlkem_revision="main")
            result = verify_backend_currency.verify(
                Namespace(
                    module_path=root,
                    west_manifest=root / "west.yml",
                    output=root / "result.json",
                    check_upstream=False,
                    require_initialized_submodules=False,
                )
            )
        self.assertFalse(result["passed"])
        self.assertTrue(any("not a pinned" in failure for failure in result["failures"]))

    def test_missing_gitmodules_entry_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root)
            (root / ".gitmodules").write_text("", encoding="utf-8")
            result = verify_backend_currency.verify(
                Namespace(
                    module_path=root,
                    west_manifest=root / "west.yml",
                    output=root / "result.json",
                    check_upstream=False,
                    require_initialized_submodules=False,
                )
            )
        self.assertFalse(result["passed"])
        self.assertTrue(any("missing from .gitmodules" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
