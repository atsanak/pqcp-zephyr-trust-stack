#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Regression tests for PQC assurance profile verification."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import export_pqc_cbom
import verify_pqc_assurance_profile


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent


def write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


class PQCAssuranceProfileTests(unittest.TestCase):
    def make_ledger(self, root: Path) -> Path:
        claims_catalog = json.loads((SCRIPT_DIR / "assurance_claims.json").read_text(encoding="utf-8"))
        claims = [
            {
                "id": claim["id"],
                "category": claim["category"],
                "claim": claim["claim"],
                "required": claim.get("required", True),
                "status": "pass",
                "validators": ["synthetic"],
                "evidence_artifacts": [],
                "commands": [],
                "failure_reason": None,
                "details": {"is_smoke_test_only": claim["id"] == "security.ct_smoke"},
            }
            for claim in claims_catalog["claims"]
        ]
        return write_json(
            root / "assurance_ledger.json",
            {
                "schema_version": 5,
                "version": "1.0.0",
                "tag": "v1.0.0",
                "head_sha": "abc123",
                "dirty": False,
                "summary": {"pass": len(claims), "fail": 0, "not_applicable": 0},
                "claims": claims,
            },
        )

    def make_cbom(self, root: Path, ledger_path: Path) -> Path:
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        manifest = {
            "version": "1.0.0",
            "tag": "v1.0.0",
            "source_commit": "abc123",
            "working_tree_dirty": False,
            "dependencies": {"zephyr": "zephyr-sha"},
        }
        cbom = export_pqc_cbom.build_cbom(REPO_ROOT, ledger, manifest)
        return write_json(root / "pqc_cbom.cdx.json", cbom)

    def test_current_profile_passes_with_generated_cbom(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = self.make_ledger(root)
            cbom = self.make_cbom(root, ledger)
            result = verify_pqc_assurance_profile.verify_profile(
                profile_path=SCRIPT_DIR / "pqc_assurance_profile.json",
                ledger_path=ledger,
                cbom_path=cbom,
                trace_map_path=SCRIPT_DIR / "pqc_asset_trace_map.json",
            )
            self.assertTrue(result["passed"], result["failures"])

    def test_missing_mlkem_asset_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = self.make_ledger(root)
            cbom = self.make_cbom(root, ledger)
            payload = json.loads(cbom.read_text(encoding="utf-8"))
            payload["components"] = [
                component for component in payload["components"] if component["name"] != "ML-KEM-768"
            ]
            write_json(cbom, payload)
            result = verify_pqc_assurance_profile.verify_profile(
                profile_path=SCRIPT_DIR / "pqc_assurance_profile.json",
                ledger_path=ledger,
                cbom_path=cbom,
                trace_map_path=SCRIPT_DIR / "pqc_asset_trace_map.json",
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("ML-KEM-768" in failure for failure in result["failures"]))

    def test_deterministic_rng_production_violation_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = json.loads((SCRIPT_DIR / "pqc_assurance_profile.json").read_text(encoding="utf-8"))
            for asset in profile["asset_lifecycle"]:
                if asset["asset_id"] == "rng.deterministic_test":
                    asset["production_allowed"] = True
            profile_path = write_json(root / "profile.json", profile)
            ledger = self.make_ledger(root)
            cbom = self.make_cbom(root, ledger)
            result = verify_pqc_assurance_profile.verify_profile(
                profile_path=profile_path,
                ledger_path=ledger,
                cbom_path=cbom,
                trace_map_path=SCRIPT_DIR / "pqc_asset_trace_map.json",
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("rng.deterministic_test" in failure for failure in result["failures"]))

    def test_stale_cbom_profile_metadata_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = self.make_ledger(root)
            cbom = self.make_cbom(root, ledger)
            payload = json.loads(cbom.read_text(encoding="utf-8"))
            for component in payload["components"]:
                if component["name"] == "ML-KEM-768":
                    for prop in component["properties"]:
                        if prop["name"] == "pqcp:lifecycle_status":
                            prop["value"] = "stale"
            write_json(cbom, payload)
            result = verify_pqc_assurance_profile.verify_profile(
                profile_path=SCRIPT_DIR / "pqc_assurance_profile.json",
                ledger_path=ledger,
                cbom_path=cbom,
                trace_map_path=SCRIPT_DIR / "pqc_asset_trace_map.json",
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("pqcp:lifecycle_status" in failure for failure in result["failures"]))

    def test_missing_profile_required_claim_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = self.make_ledger(root)
            payload = json.loads(ledger.read_text(encoding="utf-8"))
            payload["claims"] = [
                claim for claim in payload["claims"] if claim["id"] != "release.version_consistency"
            ]
            write_json(ledger, payload)
            cbom = self.make_cbom(root, ledger)
            result = verify_pqc_assurance_profile.verify_profile(
                profile_path=SCRIPT_DIR / "pqc_assurance_profile.json",
                ledger_path=ledger,
                cbom_path=cbom,
                trace_map_path=SCRIPT_DIR / "pqc_asset_trace_map.json",
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("release.version_consistency" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
