#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for release environment metadata verification."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import verify_release_environment


ZEPHYR_SHA = "a" * 40
MLKEM_SHA = "b" * 40
MLDSA_SHA = "c" * 40


def write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


class ReleaseEnvironmentTests(unittest.TestCase):
    def make_module(self, root: Path) -> tuple[Path, Path, Path]:
        module = root / "module"
        (module / ".github/workflows").mkdir(parents=True)
        module.mkdir(exist_ok=True)
        (module / "west.yml").write_text(
            "\n".join(
                [
                    "manifest:",
                    "  projects:",
                    "    - name: zephyr",
                    f"      revision: {ZEPHYR_SHA}",
                    "    - name: mlkem-native",
                    f"      revision: {MLKEM_SHA}",
                    "    - name: mldsa-native",
                    f"      revision: {MLDSA_SHA}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (module / ".github/workflows/ci.yml").write_text(
            'env:\n  ZEPHYR_REF: v4.4.0\n  ZEPHYR_SDK_VERSION: "1.0.1"\n',
            encoding="utf-8",
        )
        manifest = write_json(
            root / "release-manifest-v1.0.0.json",
            {
                "schema_version": 1,
                "dependencies": {
                    "zephyr": ZEPHYR_SHA,
                    "mlkem-native": MLKEM_SHA,
                    "mldsa-native": MLDSA_SHA,
                },
            },
        )
        cbom = write_json(
            root / "pqc_cbom.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {"name": "Zephyr RTOS", "version": ZEPHYR_SHA},
                    {"name": "Zephyr SDK", "version": "1.0.1"},
                    {"name": "mlkem-native", "version": MLKEM_SHA},
                    {"name": "mldsa-native", "version": MLDSA_SHA},
                ],
            },
        )
        return module, manifest, cbom

    def test_environment_metadata_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, manifest, cbom = self.make_module(Path(tmp))
            result = verify_release_environment.verify_environment(
                module_path=module,
                release_manifest_path=manifest,
                cbom_path=cbom,
            )
            self.assertTrue(result["passed"], result["failures"])

    def test_non_pinned_zephyr_revision_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, manifest, cbom = self.make_module(Path(tmp))
            (module / "west.yml").write_text(
                "manifest:\n  projects:\n    - name: zephyr\n      revision: v4.4.0\n",
                encoding="utf-8",
            )
            result = verify_release_environment.verify_environment(
                module_path=module,
                release_manifest_path=manifest,
                cbom_path=cbom,
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("pinned" in failure for failure in result["failures"]))

    def test_workflow_sdk_disagreement_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, manifest, cbom = self.make_module(Path(tmp))
            (module / ".github/workflows/release.yml").write_text(
                'env:\n  ZEPHYR_REF: v4.4.0\n  ZEPHYR_SDK_VERSION: "1.0.2"\n',
                encoding="utf-8",
            )
            result = verify_release_environment.verify_environment(
                module_path=module,
                release_manifest_path=manifest,
                cbom_path=cbom,
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("ZEPHYR_SDK_VERSION" in failure for failure in result["failures"]))

    def test_workflow_expression_fallback_is_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, manifest, cbom = self.make_module(Path(tmp))
            (module / ".github/workflows/extended-checks.yml").write_text(
                "env:\n"
                "  ZEPHYR_REF: ${{ github.event_name == 'workflow_dispatch' && inputs.zephyr_ref || 'v4.4.0' }}\n"
                "  ZEPHYR_SDK_VERSION: \"1.0.1\"\n",
                encoding="utf-8",
            )
            result = verify_release_environment.verify_environment(
                module_path=module,
                release_manifest_path=manifest,
                cbom_path=cbom,
            )
            self.assertTrue(result["passed"], result["failures"])

    def test_cbom_sdk_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, manifest, cbom = self.make_module(Path(tmp))
            payload = json.loads(cbom.read_text(encoding="utf-8"))
            for component in payload["components"]:
                if component["name"] == "Zephyr SDK":
                    component["version"] = "1.0.2"
            cbom.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            result = verify_release_environment.verify_environment(
                module_path=module,
                release_manifest_path=manifest,
                cbom_path=cbom,
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("Zephyr SDK" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
