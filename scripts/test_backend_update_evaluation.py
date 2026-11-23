#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for backend update evaluation."""

from __future__ import annotations

import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import evaluate_backend_update


WEST = """
manifest:
  remotes:
    - name: pq-code-package
      url-base: https://github.com/pq-code-package
  projects:
    - name: mlkem-native
      remote: pq-code-package
      path: modules/crypto/mlkem-native
      revision: 1111111111111111111111111111111111111111
    - name: mldsa-native
      remote: pq-code-package
      path: modules/crypto/mldsa-native
      revision: 2222222222222222222222222222222222222222
"""


GITMODULES = """
[submodule "ext/mlkem-native"]
	path = ext/mlkem-native
	url = https://github.com/pq-code-package/mlkem-native
[submodule "ext/mldsa-native"]
	path = ext/mldsa-native
	url = https://github.com/pq-code-package/mldsa-native
"""


class BackendUpdateEvaluationTests(unittest.TestCase):
    def make_module(self, root: Path, *, missing_license: bool = False) -> Path:
        (root / "west.yml").write_text(WEST, encoding="utf-8")
        (root / ".gitmodules").write_text(GITMODULES, encoding="utf-8")
        for backend in ("mlkem-native", "mldsa-native"):
            base = root / "ext" / backend
            base.mkdir(parents=True)
            if not missing_license or backend != "mlkem-native":
                (base / "LICENSE").write_text("license\n", encoding="utf-8")
            (base / "META.yml").write_text("name: backend\nimplementations:\n  - name: clean\n", encoding="utf-8")
        return root

    def test_local_metadata_passes_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module = self.make_module(Path(tmp))
            result = evaluate_backend_update.evaluate(
                Namespace(module_path=module, output=module / "out.json", backend="all", check_upstream=False, clone_upstream=False, work_dir=None)
            )
        self.assertTrue(result["passed"], result["failures"])
        self.assertFalse(result["vendored_code_added"])

    def test_missing_license_metadata_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module = self.make_module(Path(tmp), missing_license=True)
            result = evaluate_backend_update.evaluate(
                Namespace(module_path=module, output=module / "out.json", backend="all", check_upstream=False, clone_upstream=False, work_dir=None)
            )
        self.assertFalse(result["passed"])
        self.assertTrue(any("LICENSE" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
