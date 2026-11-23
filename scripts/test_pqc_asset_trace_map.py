#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression tests for the PQC asset trace map verifier."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import verify_pqc_asset_trace_map


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent


def load_map() -> dict:
    return json.loads((SCRIPT_DIR / "pqc_asset_trace_map.json").read_text(encoding="utf-8"))


class PQCAssetTraceMapTests(unittest.TestCase):
    def write_trace_map(self, root: Path, payload: dict) -> Path:
        path = root / "trace_map.json"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return path

    def make_ledger(self, root: Path, trace_map: dict) -> Path:
        claim_ids: set[str] = set()
        for asset in trace_map["assets"]:
            claim_ids.update(asset.get("claim_ids") or [])
        ledger = {
            "schema_version": 4,
            "claims": [{"id": claim_id, "status": "pass"} for claim_id in sorted(claim_ids)],
        }
        path = root / "assurance_ledger.json"
        path.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")
        return path

    def make_cbom(self, root: Path, trace_map: dict) -> Path:
        components = [
            {"name": asset["cbom_component"]}
            for asset in trace_map["assets"]
            if asset.get("cbom_component")
        ]
        path = root / "pqc_cbom.cdx.json"
        path.write_text(json.dumps({"components": components}, indent=2) + "\n", encoding="utf-8")
        return path

    def test_current_trace_map_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace_map = load_map()
            ledger = self.make_ledger(root, trace_map)
            cbom = self.make_cbom(root, trace_map)
            result = verify_pqc_asset_trace_map.verify_trace_map(
                trace_map_path=SCRIPT_DIR / "pqc_asset_trace_map.json",
                module_path=REPO_ROOT,
                ledger_path=ledger,
                cbom_path=cbom,
            )
            self.assertTrue(result["passed"], result["failures"])

    def test_missing_source_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace_map = load_map()
            trace_map["assets"][0]["source_files"].append("src/not-a-real-file.c")
            path = self.write_trace_map(root, trace_map)
            result = verify_pqc_asset_trace_map.verify_trace_map(
                trace_map_path=path,
                module_path=REPO_ROOT,
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("not-a-real-file.c" in failure for failure in result["failures"]))

    def test_duplicate_asset_id_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace_map = load_map()
            trace_map["assets"][1]["id"] = trace_map["assets"][0]["id"]
            path = self.write_trace_map(root, trace_map)
            result = verify_pqc_asset_trace_map.verify_trace_map(
                trace_map_path=path,
                module_path=REPO_ROOT,
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("duplicate asset id" in failure for failure in result["failures"]))

    def test_missing_ledger_claim_fails_when_ledger_supplied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace_map = load_map()
            ledger = self.make_ledger(root, trace_map)
            data = json.loads(ledger.read_text(encoding="utf-8"))
            data["claims"] = [claim for claim in data["claims"] if claim["id"] != "kat.mlkem_768"]
            ledger.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            result = verify_pqc_asset_trace_map.verify_trace_map(
                trace_map_path=SCRIPT_DIR / "pqc_asset_trace_map.json",
                module_path=REPO_ROOT,
                ledger_path=ledger,
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("kat.mlkem_768" in failure for failure in result["failures"]))

    def test_missing_cbom_component_fails_when_cbom_supplied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace_map = load_map()
            cbom = self.make_cbom(root, trace_map)
            data = json.loads(cbom.read_text(encoding="utf-8"))
            data["components"] = [
                component for component in data["components"] if component["name"] != "ML-KEM-768"
            ]
            cbom.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            result = verify_pqc_asset_trace_map.verify_trace_map(
                trace_map_path=SCRIPT_DIR / "pqc_asset_trace_map.json",
                module_path=REPO_ROOT,
                cbom_path=cbom,
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("ML-KEM-768" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
