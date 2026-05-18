#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Regression tests for backend-contract verification."""

from __future__ import annotations

import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import verify_backend_contract

MLKEM_SHA = "e07bff537f38b457601e524038f2395e235b011b"
MLDSA_SHA = "0f8b8e074b2525eb844b022b03b962bf888d51aa"


def write_repo(root: Path) -> None:
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
      revision: {MLKEM_SHA}
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


class BackendContractTests(unittest.TestCase):
    def verify(self, root: Path) -> dict:
        return verify_backend_contract.verify_contract(
            Namespace(
                module_path=root,
                west_manifest=root / "west.yml",
                backend_currency_result=None,
                output=root / "backend_contract_result.json",
                require_initialized_submodules=False,
            )
        )

    def test_native_backend_contract_passes_with_pinned_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root)
            result = self.verify(root)
        self.assertTrue(result["passed"])
        self.assertEqual(result["native_backend_shas"]["mlkem-native"], MLKEM_SHA)
        self.assertEqual(result["native_backend_shas"]["mldsa-native"], MLDSA_SHA)

    def test_external_provider_for_native_family_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root)
            (root / "src").mkdir()
            provider = "lib" + "oqs"
            native_family = "ML-" + "KEM"
            (root / "src" / "backend.c").write_text(
                f"/* {provider} {native_family} accidental provider path */\n",
                encoding="utf-8",
            )
            result = self.verify(root)
        self.assertFalse(result["passed"])
        self.assertTrue(any("implementation policy" in failure for failure in result["failures"]))

    def test_missing_native_backend_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root)
            west = (root / "west.yml").read_text(encoding="utf-8")
            west = west.replace("    - name: mldsa-native\n      remote: pqcp\n      revision: " + MLDSA_SHA + "\n      path: modules/crypto/mldsa-native\n", "")
            (root / "west.yml").write_text(west, encoding="utf-8")
            result = self.verify(root)
        self.assertFalse(result["passed"])
        self.assertTrue(any("mldsa-native" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
