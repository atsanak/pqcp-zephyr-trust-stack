#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression tests for provider-bound reference-value replay."""

from __future__ import annotations

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import verify_release_reference_values


def write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


class ReleaseReferenceValuesTests(unittest.TestCase):
    def fixture(self, root: Path) -> Namespace:
        cbom = write_json(
            root / "pqc_cbom.cdx.json",
            {
                "components": [
                    {"name": "ML-KEM-768", "bom-ref": "pqcp:crypto:ml-kem-768"},
                    {"name": "ML-DSA-65", "bom-ref": "pqcp:crypto:ml-dsa-65"},
                ]
            },
        )
        reference = write_json(
            root / "pqc_reference_values.json",
            {
                "schema_version": 1,
                "version": "1.0.0",
                "tag": "v1.0.0",
                "head_sha": "a" * 40,
                "artifact_hashes": {
                    "backend_contract_result.json": {"sha256": "1" * 64},
                    "provider_scope_result.json": {"sha256": "2" * 64},
                    "pqc_cbom.cdx.json": {"sha256": "3" * 64},
                },
                "cbom_component_ids": [
                    "ML-KEM-768",
                    "ML-DSA-65",
                    "pqcp:crypto:ml-kem-768",
                    "pqcp:crypto:ml-dsa-65",
                ],
            },
        )
        manifest = write_json(root / "release-manifest-v1.0.0.json", {"version": "1.0.0", "tag": "v1.0.0", "source_commit": "a" * 40})
        contract = write_json(root / "backend_contract_result.json", {"schema_version": 1, "passed": True})
        provider = write_json(root / "provider_scope_result.json", {"schema_version": 1, "passed": True})
        return Namespace(
            reference_values=reference,
            release_manifest=manifest,
            backend_contract=contract,
            provider_scope_result=provider,
            cbom=cbom,
            output=root / "release_reference_values_result.json",
        )

    def test_reference_values_replay_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = verify_release_reference_values.verify(self.fixture(Path(tmp)))
        self.assertTrue(result["passed"], result["failures"])

    def test_stale_head_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.fixture(root)
            manifest = json.loads(args.release_manifest.read_text(encoding="utf-8"))
            manifest["source_commit"] = "b" * 40
            args.release_manifest.write_text(json.dumps(manifest), encoding="utf-8")
            result = verify_release_reference_values.verify(args)
        self.assertFalse(result["passed"])
        self.assertTrue(any("head_sha" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
