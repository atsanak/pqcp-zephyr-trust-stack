#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Regression tests for backend-currency verification."""

from __future__ import annotations

import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

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


def write_backend_meta(root: Path) -> None:
    backend = root / "ext" / "mlkem-native"
    (backend / "mlkem" / "src").mkdir(parents=True)
    (backend / "META.yml").write_text(
        """name: ML-KEM
type: kem
implementations:
  - name: ML-KEM-768
    claimed-nist-level: 3
    length-public-key: 1184
    kat-sha256: 8cff42556667edbd0fec7d0b2666d7710d80db71b684f8b4852a37ece2a4c844
""",
        encoding="utf-8",
    )
    (backend / "LICENSE").write_text("backend license\n", encoding="utf-8")
    (backend / "mlkem" / "src" / "kem.c").write_text("int kem(void) { return 0; }\n",
                                                       encoding="utf-8")


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

    def test_upstream_drift_is_warned_but_not_failed(self) -> None:
        upstream_sha = "1111111111111111111111111111111111111111"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root)
            with patch.object(verify_backend_currency, "upstream_head", return_value=upstream_sha):
                result = verify_backend_currency.verify(
                    Namespace(
                        module_path=root,
                        west_manifest=root / "west.yml",
                        output=root / "result.json",
                        check_upstream=True,
                        require_initialized_submodules=False,
                    )
                )
        self.assertTrue(result["passed"])
        self.assertTrue(any("differs from pinned revision" in warning for warning in result["warnings"]))
        self.assertTrue(all(row["upstream_checked"] for row in result["backends"]))
        self.assertTrue(all(not row["upstream_matches_pin"] for row in result["backends"]))

    def test_backend_metadata_records_meta_kat_and_source_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root)
            write_backend_meta(root)
            result = verify_backend_currency.verify(
                Namespace(
                    module_path=root,
                    west_manifest=root / "west.yml",
                    output=root / "result.json",
                    check_upstream=False,
                    require_initialized_submodules=False,
                )
            )
        mlkem = next(row for row in result["backends"] if row["name"] == "mlkem-native")
        metadata = mlkem["backend_metadata"]
        self.assertTrue(metadata["available"])
        self.assertEqual(metadata["metadata"]["name"], "ML-KEM")
        self.assertEqual(metadata["metadata"]["type"], "kem")
        self.assertEqual(metadata["metadata"]["implementations"][0]["name"], "ML-KEM-768")
        self.assertIn("kat-sha256", metadata["metadata"]["implementations"][0])
        self.assertEqual(metadata["source_file_count"], 1)
        self.assertRegex(metadata["meta_sha256"], r"^[0-9a-f]{64}$")

    def test_repo_owned_forbidden_backend_reference_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root)
            (root / "src").mkdir()
            forbidden_name = "OQ" + "Clean"
            (root / "src" / "backend.c").write_text(
                f"/* accidental {forbidden_name} ML-KEM backend selection */\n",
                encoding="utf-8",
            )
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
        self.assertFalse(result["implementation_policy"]["passed"])
        self.assertEqual(result["implementation_policy"]["forbidden_reference_count"], 1)
        self.assertTrue(any("implementation policy" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
