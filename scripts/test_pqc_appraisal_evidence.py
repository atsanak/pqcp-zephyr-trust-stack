#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for PQC appraisal evidence generation and replay."""

from __future__ import annotations

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import generate_pqc_appraisal_evidence
import verify_pqc_appraisal_evidence


SCRIPT_DIR = Path(__file__).resolve().parent


class PQCAppraisalEvidenceTests(unittest.TestCase):
    def write_json(self, path: Path, payload: dict) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def make_pack(self, root: Path) -> tuple[Path, Path]:
        policy = self.write_json(root / "pqc_appraisal_policy.json", json.loads((SCRIPT_DIR / "pqc_appraisal_policy.json").read_text()))
        claims = [
            {"id": "release.evidence_appraisal_profile", "status": "not_applicable"},
            {"id": "supply_chain.backend_update_evaluation", "status": "not_applicable"},
            {"id": "benchmark.campaign_reproducibility", "status": "not_applicable"},
            {"id": "benchmark.external_reference_context", "status": "not_applicable"},
            {"id": "security.ct_campaign_analysis", "status": "not_applicable"},
            {"id": "acvp.json_schema_coverage", "status": "not_applicable"},
            {"id": "firmware.device_evidence_token", "status": "not_applicable"},
            {"id": "release.strict_partner_policy", "status": "not_applicable"},
        ]
        ledger = self.write_json(root / "assurance_ledger.json", {"schema_version": 7, "claims": claims})
        for filename in (
            "pqc_policy_result.json",
            "backend_update_evaluation.json",
            "benchmark_campaign_result.json",
            "ct_campaign_result.json",
            "acvp_json_schema_result.json",
            "device_evidence_token_result.json",
        ):
            self.write_json(root / filename, {"schema_version": 1, "passed": True, "checks": [], "summary": {}})
        return policy, ledger

    def test_partner_review_accepts_post_ledger_evidence_closure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy, ledger = self.make_pack(root)
            evidence = root / "pqc_appraisal_evidence.json"
            generated = generate_pqc_appraisal_evidence.generate(
                Namespace(
                    output_root=root,
                    policy=policy,
                    ledger=ledger,
                    policy_result=root / "pqc_policy_result.json",
                    backend_update=root / "backend_update_evaluation.json",
                    benchmark_campaign=root / "benchmark_campaign_result.json",
                    ct_campaign=root / "ct_campaign_result.json",
                    acvp_schema_result=root / "acvp_json_schema_result.json",
                    device_evidence_result=root / "device_evidence_token_result.json",
                    output=evidence,
                )
            )
            evidence.write_text(json.dumps(generated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            result = verify_pqc_appraisal_evidence.verify(
                Namespace(policy=policy, appraisal_evidence=evidence, ledger=ledger, mode="partner_review", output=root / "result.json")
            )
        self.assertTrue(result["passed"], result["failures"])

    def test_missing_artifact_fails_partner_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy, ledger = self.make_pack(root)
            (root / "ct_campaign_result.json").unlink()
            evidence = root / "pqc_appraisal_evidence.json"
            generated = generate_pqc_appraisal_evidence.generate(
                Namespace(
                    output_root=root,
                    policy=policy,
                    ledger=ledger,
                    policy_result=root / "pqc_policy_result.json",
                    backend_update=root / "backend_update_evaluation.json",
                    benchmark_campaign=root / "benchmark_campaign_result.json",
                    ct_campaign=root / "ct_campaign_result.json",
                    acvp_schema_result=root / "acvp_json_schema_result.json",
                    device_evidence_result=root / "device_evidence_token_result.json",
                    output=evidence,
                )
            )
            evidence.write_text(json.dumps(generated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            result = verify_pqc_appraisal_evidence.verify(
                Namespace(policy=policy, appraisal_evidence=evidence, ledger=ledger, mode="partner_review", output=root / "result.json")
            )
        self.assertFalse(result["passed"])
        self.assertTrue(any("ct_campaign" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
