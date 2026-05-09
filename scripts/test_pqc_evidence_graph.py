#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Regression tests for the PQC evidence graph generator."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import generate_pqc_evidence_graph


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent


class PQCEvidenceGraphTests(unittest.TestCase):
    def make_ledger(self, root: Path, trace_map: dict) -> Path:
        claim_ids: set[str] = set()
        for asset in trace_map["assets"]:
            claim_ids.update(asset.get("claim_ids") or [])
        ledger = {
            "schema_version": 4,
            "project": "pqcp-zephyr-trust-stack",
            "version": "1.0.0",
            "tag": "v1.0.0",
            "head_sha": "abc123",
            "dirty": False,
            "claims": [{"id": claim_id, "status": "pass"} for claim_id in sorted(claim_ids)],
        }
        path = root / "assurance_ledger.json"
        path.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")
        return path

    def make_cbom(self, root: Path, trace_map: dict) -> Path:
        cbom = {
            "components": [
                {"name": asset["cbom_component"]}
                for asset in trace_map["assets"]
                if asset.get("cbom_component")
            ]
        }
        path = root / "pqc_cbom.cdx.json"
        path.write_text(json.dumps(cbom, indent=2) + "\n", encoding="utf-8")
        return path

    def load_trace_map(self) -> dict:
        return json.loads((SCRIPT_DIR / "pqc_asset_trace_map.json").read_text(encoding="utf-8"))

    def test_current_trace_map_generates_graph(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace_map = self.load_trace_map()
            ledger = self.make_ledger(root, trace_map)
            cbom = self.make_cbom(root, trace_map)
            graph = generate_pqc_evidence_graph.build_graph(
                trace_map_path=SCRIPT_DIR / "pqc_asset_trace_map.json",
                ledger_path=ledger,
                cbom_path=cbom,
                module_path=REPO_ROOT,
            )
            self.assertFalse(graph["failures"], graph["failures"])
            asset_ids = {node["id"] for node in graph["nodes"] if node["type"] == "asset"}
            self.assertIn("asset:crypto.mlkem_768", asset_ids)
            self.assertIn("asset:validation.acvp_serial", asset_ids)
            markdown = generate_pqc_evidence_graph.render_markdown(graph)
            self.assertIn("crypto.mlkem_768", markdown)
            self.assertIn("acvp.negative_scenarios_replay", markdown)

    def test_missing_claim_edge_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace_map = self.load_trace_map()
            ledger = self.make_ledger(root, trace_map)
            data = json.loads(ledger.read_text(encoding="utf-8"))
            data["claims"] = [claim for claim in data["claims"] if claim["id"] != "security.ct_smoke"]
            ledger.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            cbom = self.make_cbom(root, trace_map)
            graph = generate_pqc_evidence_graph.build_graph(
                trace_map_path=SCRIPT_DIR / "pqc_asset_trace_map.json",
                ledger_path=ledger,
                cbom_path=cbom,
                module_path=REPO_ROOT,
            )
            self.assertTrue(any("security.ct_smoke" in failure for failure in graph["failures"]))

    def test_missing_cbom_component_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace_map = self.load_trace_map()
            ledger = self.make_ledger(root, trace_map)
            cbom = self.make_cbom(root, trace_map)
            data = json.loads(cbom.read_text(encoding="utf-8"))
            data["components"] = [
                component for component in data["components"] if component["name"] != "ML-DSA-65"
            ]
            cbom.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            graph = generate_pqc_evidence_graph.build_graph(
                trace_map_path=SCRIPT_DIR / "pqc_asset_trace_map.json",
                ledger_path=ledger,
                cbom_path=cbom,
                module_path=REPO_ROOT,
            )
            self.assertTrue(any("ML-DSA-65" in failure for failure in graph["failures"]))

    def test_json_and_markdown_share_claim_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace_map = self.load_trace_map()
            ledger = self.make_ledger(root, trace_map)
            cbom = self.make_cbom(root, trace_map)
            output_json = root / "pqc_evidence_graph.json"
            output_md = root / "pqc_evidence_graph.md"
            graph = generate_pqc_evidence_graph.build_graph(
                trace_map_path=SCRIPT_DIR / "pqc_asset_trace_map.json",
                ledger_path=ledger,
                cbom_path=cbom,
                module_path=REPO_ROOT,
            )
            output_json.write_text(json.dumps(graph, indent=2) + "\n", encoding="utf-8")
            output_md.write_text(generate_pqc_evidence_graph.render_markdown(graph), encoding="utf-8")
            json_claims = {
                node["label"] for node in graph["nodes"] if node.get("type") == "claim"
            }
            markdown = output_md.read_text(encoding="utf-8")
            self.assertIn("kat.mlkem_768", json_claims)
            self.assertIn("kat.mlkem_768", markdown)


if __name__ == "__main__":
    unittest.main(verbosity=2)
