#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression tests for PQC evidence quality verification."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import verify_pqc_evidence_quality


SCRIPT_DIR = Path(__file__).resolve().parent


def write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


class PQCEvidenceQualityTests(unittest.TestCase):
    def make_ledger(self, root: Path) -> Path:
        marker = root / "evidence.txt"
        marker.write_text("evidence\n", encoding="utf-8")
        catalog = json.loads((SCRIPT_DIR / "assurance_claims.json").read_text(encoding="utf-8"))
        claims = []
        for claim in catalog["claims"]:
            claims.append(
                {
                    "id": claim["id"],
                    "category": claim["category"],
                    "claim": claim["claim"],
                    "required": claim.get("required", True),
                    "status": "pass",
                    "validators": ["synthetic"],
                    "evidence_artifacts": [
                        {
                            "path": str(marker),
                            "exists": True,
                            "sha256": "unused",
                        }
                    ],
                    "commands": [],
                    "failure_reason": None,
                    "details": {"is_smoke_test_only": claim["id"] == "security.ct_smoke"},
                }
            )
        return write_json(
            root / "assurance_ledger.json",
            {
                "schema_version": 5,
                "summary": {"pass": len(claims), "fail": 0, "not_applicable": 0},
                "claims": claims,
            },
        )

    def make_graph(self, root: Path) -> Path:
        return write_json(
            root / "pqc_evidence_graph.json",
            {
                "schema_version": 1,
                "failures": [],
                "nodes": [{"type": "claim", "label": "security.ct_smoke"}],
                "edges": [],
            },
        )

    def test_current_quality_index_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = verify_pqc_evidence_quality.verify_quality(
                quality_path=SCRIPT_DIR / "pqc_evidence_quality.json",
                ledger_path=self.make_ledger(root),
                graph_path=self.make_graph(root),
            )
            self.assertTrue(result["passed"], result["failures"])

    def test_tag_integrity_is_optional_only_for_untagged_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = self.make_ledger(root)
            payload = json.loads(ledger.read_text(encoding="utf-8"))
            claim = next(c for c in payload["claims"] if c["id"] == "release.tag_integrity")
            graph = self.make_graph(root)
            for status, passed in (("not_applicable", True), ("fail", False)):
                with self.subTest(status=status):
                    claim["status"] = status
                    write_json(ledger, payload)
                    result = verify_pqc_evidence_quality.verify_quality(
                        quality_path=SCRIPT_DIR / "pqc_evidence_quality.json",
                        ledger_path=ledger,
                        graph_path=graph,
                    )
                    self.assertEqual(result["passed"], passed, result["failures"])

    def test_missing_quality_entry_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            quality = json.loads((SCRIPT_DIR / "pqc_evidence_quality.json").read_text(encoding="utf-8"))
            quality["claims"] = [
                entry for entry in quality["claims"] if entry["id"] != "release.version_consistency"
            ]
            quality_path = write_json(root / "quality.json", quality)
            result = verify_pqc_evidence_quality.verify_quality(
                quality_path=quality_path,
                ledger_path=self.make_ledger(root),
                graph_path=self.make_graph(root),
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("release.version_consistency" in failure for failure in result["failures"]))

    def test_failed_claim_fails_quality(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = self.make_ledger(root)
            payload = json.loads(ledger.read_text(encoding="utf-8"))
            payload["claims"][0]["status"] = "fail"
            payload["claims"][0]["failure_reason"] = "synthetic"
            write_json(ledger, payload)
            result = verify_pqc_evidence_quality.verify_quality(
                quality_path=SCRIPT_DIR / "pqc_evidence_quality.json",
                ledger_path=ledger,
                graph_path=self.make_graph(root),
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("not accepted" in failure for failure in result["failures"]))

    def test_ct_smoke_must_be_labeled_as_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = self.make_ledger(root)
            payload = json.loads(ledger.read_text(encoding="utf-8"))
            for claim in payload["claims"]:
                if claim["id"] == "security.ct_smoke":
                    claim["details"] = {}
            write_json(ledger, payload)
            result = verify_pqc_evidence_quality.verify_quality(
                quality_path=SCRIPT_DIR / "pqc_evidence_quality.json",
                ledger_path=ledger,
                graph_path=self.make_graph(root),
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("smoke-only" in failure for failure in result["failures"]))

    def test_unknown_quality_claim_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            quality = json.loads((SCRIPT_DIR / "pqc_evidence_quality.json").read_text(encoding="utf-8"))
            quality["claims"].append(
                {
                    "id": "missing.claim",
                    "evidence_class": "replay",
                    "environment": "host_python",
                    "requires_artifact": False,
                }
            )
            quality_path = write_json(root / "quality.json", quality)
            result = verify_pqc_evidence_quality.verify_quality(
                quality_path=quality_path,
                ledger_path=self.make_ledger(root),
                graph_path=self.make_graph(root),
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("missing.claim" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
