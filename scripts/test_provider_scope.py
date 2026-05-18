#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Regression tests for provider-scope verification."""

from __future__ import annotations

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import verify_provider_scope


def prop(name: str, value: object) -> dict[str, str]:
    return {"name": name, "value": str(value).lower() if isinstance(value, bool) else str(value)}


def component(name: str, provider: str, *, native_required: bool, external_allowed: bool, production_allowed: bool, source: str = "native") -> dict:
    return {
        "type": "cryptographic-asset",
        "name": name,
        "bom-ref": "test:" + name,
        "properties": [
            prop("pqcp:provider_family", provider),
            prop("pqcp:native_required", native_required),
            prop("pqcp:liboqs_allowed", external_allowed),
            prop("pqcp:production_allowed", production_allowed),
            prop("pqcp:implementation_source", source),
        ],
    }


def write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


class ProviderScopeTests(unittest.TestCase):
    def base_paths(self, root: Path) -> Namespace:
        provider = "lib" + "oqs"
        cbom = write_json(
            root / "pqc_cbom.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [
                    component("ML-" + "KEM-768", "mlkem-native", native_required=True, external_allowed=False, production_allowed=True, source="mlkem-native"),
                    component("ML-" + "DSA-65", "mldsa-native", native_required=True, external_allowed=False, production_allowed=True, source="mldsa-native"),
                    component("SLH-DSA", provider, native_required=False, external_allowed=True, production_allowed=False, source="external_inventory"),
                ],
            },
        )
        contract = write_json(root / "backend_contract_result.json", {"schema_version": 1, "passed": True})
        inventory = write_json(
            root / "liboqs_non_native_inventory.json",
            {
                "schema_version": 1,
                "passed": True,
                "schemes": [{"name": "SLH-DSA", "native_family_overlap": False, "production_allowed": False}],
            },
        )
        return Namespace(cbom=cbom, backend_contract=contract, liboqs_inventory=inventory, output=root / "provider_scope_result.json")

    def test_valid_provider_scope_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.base_paths(Path(tmp))
            result = verify_provider_scope.verify_scope(args)
        self.assertTrue(result["passed"], result["failures"])

    def test_external_provider_for_native_component_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.base_paths(root)
            cbom = json.loads(args.cbom.read_text(encoding="utf-8"))
            provider = "lib" + "oqs"
            cbom["components"][0]["properties"][0]["value"] = provider
            cbom["components"][0]["properties"][2]["value"] = "true"
            args.cbom.write_text(json.dumps(cbom), encoding="utf-8")
            result = verify_provider_scope.verify_scope(args)
        self.assertFalse(result["passed"])
        self.assertTrue(any("mlkem-native" in failure for failure in result["failures"]))

    def test_inventory_production_enabled_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.base_paths(root)
            inventory = json.loads(args.liboqs_inventory.read_text(encoding="utf-8"))
            inventory["schemes"][0]["production_allowed"] = True
            args.liboqs_inventory.write_text(json.dumps(inventory), encoding="utf-8")
            result = verify_provider_scope.verify_scope(args)
        self.assertFalse(result["passed"])
        self.assertTrue(any("production" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
