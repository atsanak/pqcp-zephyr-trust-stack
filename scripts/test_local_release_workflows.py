#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Focused tests for local release and consumer workflow helpers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import consumer_smoke
import prepare_release_bundle


class PrepareReleaseBundleTests(unittest.TestCase):
    def test_parse_release_date_requires_dated_version_section(self) -> None:
        text = "## [Unreleased]\n\n## [1.2.3] - 2026-04-28\n\n- shipped\n"
        self.assertEqual(
            prepare_release_bundle.parse_release_date(text, "1.2.3"),
            "2026-04-28",
        )
        with self.assertRaisesRegex(RuntimeError, "missing an ISO release date"):
            prepare_release_bundle.parse_release_date("## [1.2.3]\n\n- shipped\n", "1.2.3")

    def test_parse_west_dependencies_reads_pinned_revisions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "west.yml").write_text(
                "\n".join(
                    [
                        "manifest:",
                        "  projects:",
                        "    - name: zephyr",
                        "      revision: abc123",
                        "    - name: mlkem-native",
                        "      revision: def456",
                        "      path: modules/crypto/mlkem-native",
                        "    - name: mldsa-native",
                        "      revision: 789abc",
                        "      path: modules/crypto/mldsa-native",
                    ]
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                prepare_release_bundle.parse_west_dependencies(root),
                {
                    "zephyr": "abc123",
                    "mlkem-native": "def456",
                    "mldsa-native": "789abc",
                },
            )

    def test_prepare_bundle_dir_removes_stale_generated_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle_dir = Path(tmp) / "v1.0.0"
            bundle_dir.mkdir()
            stale = bundle_dir / "stale.txt"
            stale.write_text("old", encoding="utf-8")

            prepare_release_bundle.prepare_bundle_dir(
                bundle_dir,
                "v1.0.0",
                keep_existing=False,
            )

            self.assertTrue(bundle_dir.exists())
            self.assertFalse(stale.exists())

    def test_prepare_bundle_dir_rejects_unsafe_tag_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "unsafe bundle path"):
                prepare_release_bundle.prepare_bundle_dir(
                    Path(tmp) / "not-the-tag",
                    "v1.0.0",
                    keep_existing=True,
                )


class ConsumerSmokeTests(unittest.TestCase):
    def test_manifest_mode_omits_extra_module_injection(self) -> None:
        cmd = consumer_smoke.west_build_command(
            ["west"],
            board="qemu_x86_64",
            target=Path("/workspace/pqcp/tests/ztest_rng"),
            build_dir=Path("/workspace/build"),
            module_path=Path("/workspace/pqcp"),
            module_mode="manifest",
        )
        self.assertNotIn("-DZEPHYR_EXTRA_MODULES=/workspace/pqcp", cmd)
        self.assertNotIn("--", cmd)

    def test_extra_module_mode_adds_explicit_module_injection(self) -> None:
        cmd = consumer_smoke.west_build_command(
            ["west"],
            board="qemu_x86_64",
            target=Path("/workspace/pqcp/tests/ztest_rng"),
            build_dir=Path("/workspace/build"),
            module_path=Path("/workspace/pqcp"),
            module_mode="extra-module",
        )
        self.assertIn("--", cmd)
        self.assertIn("-DZEPHYR_EXTRA_MODULES=/workspace/pqcp", cmd)


if __name__ == "__main__":
    unittest.main()
