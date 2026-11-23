#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression tests for partner review scorecard generation."""

from __future__ import annotations

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import generate_partner_review_scorecard
import verify_partner_review_scorecard


class PartnerReviewScorecardTests(unittest.TestCase):
    def write_json(self, path: Path, payload: dict) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def cbom(self, *, deterministic_rng_production: bool = False, mlkem_provider: str = "mlkem-native") -> dict:
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "components": [
                {
                    "type": "cryptographic-asset",
                    "name": "ML-KEM-768",
                    "properties": [
                        {"name": "pqcp:trace_asset_id", "value": "mlkem.768"},
                        {"name": "pqcp:provider_family", "value": mlkem_provider},
                        {"name": "pqcp:lifecycle_status", "value": "supported"},
                        {"name": "pqcp:production_allowed", "value": "true"},
                    ],
                },
                {
                    "type": "cryptographic-asset",
                    "name": "ML-DSA-65",
                    "properties": [
                        {"name": "pqcp:trace_asset_id", "value": "mldsa.65"},
                        {"name": "pqcp:provider_family", "value": "mldsa-native"},
                        {"name": "pqcp:lifecycle_status", "value": "supported"},
                        {"name": "pqcp:production_allowed", "value": "true"},
                    ],
                },
                {
                    "type": "cryptographic-asset",
                    "name": "deterministic test RNG",
                    "properties": [
                        {"name": "pqcp:trace_asset_id", "value": "rng.deterministic_test"},
                        {"name": "pqcp:provider_family", "value": "test-rng"},
                        {"name": "pqcp:lifecycle_status", "value": "test_only"},
                        {"name": "pqcp:production_allowed", "value": str(deterministic_rng_production).lower()},
                    ],
                },
            ],
        }

    def make_pack(self, root: Path, *, backend_passed: bool = True, deterministic_rng_production: bool = False) -> Namespace:
        ledger = self.write_json(
            root / "assurance_ledger.json",
            {
                "schema_version": 7,
                "version": "1.0.0",
                "tag": "v1.0.0",
                "head_sha": "abc123",
                "dirty": False,
                "summary": {"pass": 2, "fail": 0, "not_applicable": 0},
                "claims": [
                    {"id": "release.version_consistency", "required": True, "status": "pass"},
                    {"id": "supply_chain.backend_contract", "required": True, "status": "pass"},
                ],
            },
        )
        cbom = self.write_json(root / "pqc_cbom.cdx.json", self.cbom(deterministic_rng_production=deterministic_rng_production))
        for filename in (
            "pqc_policy_result.json",
            "pqc_assurance_profile_result.json",
            "pqc_evidence_quality_result.json",
            "pqc_migration_readiness.json",
            "provider_scope_result.json",
            "ct_campaign_result.json",
            "acvp_json_schema_result.json",
            "device_evidence_token_result.json",
        ):
            self.write_json(root / filename, {"schema_version": 1, "passed": True, "summary": {}, "failures": []})
        self.write_json(
            root / "benchmark_campaign_result.json",
            {
                "schema_version": 1,
                "passed": True,
                "summary": {},
                "failures": [],
                "comparison_context": {"environment_type": "qemu", "board_class": "qemu_x86_64"},
            },
        )
        self.write_json(
            root / "backend_contract_result.json",
            {"schema_version": 1, "passed": backend_passed, "summary": {}, "failures": [] if backend_passed else ["native backend mismatch"]},
        )
        self.write_json(root / "pqc_reference_values.json", {"schema_version": 1, "version": "1.0.0"})
        self.write_json(root / "pqc_appraisal_result.json", {"schema_version": 1, "passed": True, "summary": {}, "failures": []})
        return Namespace(
            ledger=ledger,
            cbom=cbom,
            policy_result=root / "pqc_policy_result.json",
            profile_result=root / "pqc_assurance_profile_result.json",
            quality_result=root / "pqc_evidence_quality_result.json",
            migration_readiness=root / "pqc_migration_readiness.json",
            backend_contract=root / "backend_contract_result.json",
            provider_scope_result=root / "provider_scope_result.json",
            benchmark_campaign=root / "benchmark_campaign_result.json",
            ct_campaign=root / "ct_campaign_result.json",
            acvp_schema_result=root / "acvp_json_schema_result.json",
            device_evidence_result=root / "device_evidence_token_result.json",
            reference_values=root / "pqc_reference_values.json",
            appraisal_result=root / "pqc_appraisal_result.json",
            output_json=root / "partner_review_scorecard.json",
            output_md=root / "partner_review_scorecard.md",
        )

    def test_clean_pack_passes_with_hardware_warning_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.make_pack(root)
            result = generate_partner_review_scorecard.build_scorecard(args)
            markdown = generate_partner_review_scorecard.render_markdown(result)
        self.assertTrue(result["passed"], result["findings"])
        self.assertEqual(result["summary"]["blockers"], 0)
        self.assertIn("hardware_promotion_not_completed", {item["id"] for item in result["findings"]})
        self.assertIn("partner_review_scorecard", json.dumps(result))
        self.assertIn("PQCP Partner Review Scorecard", markdown)

    def test_failed_backend_contract_is_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.make_pack(root, backend_passed=False)
            result = generate_partner_review_scorecard.build_scorecard(args)
        self.assertFalse(result["passed"])
        self.assertTrue(any(item["category"] == "backend" and item["severity"] == "blocker" for item in result["findings"]))

    def test_deterministic_rng_marked_production_is_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.make_pack(root, deterministic_rng_production=True)
            result = generate_partner_review_scorecard.build_scorecard(args)
        self.assertFalse(result["passed"])
        self.assertTrue(any(item["id"] == "deterministic_rng_production" for item in result["findings"]))

    def test_mlkem_provider_must_be_native(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.make_pack(root)
            (root / "pqc_cbom.cdx.json").write_text(
                json.dumps(self.cbom(mlkem_provider="lib" + "o" + "qs"), indent=2) + "\n",
                encoding="utf-8",
            )
            result = generate_partner_review_scorecard.build_scorecard(args)
        self.assertFalse(result["passed"])
        self.assertTrue(any(item["id"] == "mlkem_not_native" for item in result["findings"]))

    def test_failed_required_claim_is_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.make_pack(root)
            ledger = json.loads(args.ledger.read_text(encoding="utf-8"))
            ledger["claims"][0]["status"] = "fail"
            ledger["claims"][0]["failure_reason"] = "version mismatch"
            args.ledger.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")
            result = generate_partner_review_scorecard.build_scorecard(args)
        self.assertFalse(result["passed"])
        self.assertTrue(any(item["id"] == "failed_claim_release_version_consistency" for item in result["findings"]))

    def write_scorecard(self, args: Namespace) -> dict:
        result = generate_partner_review_scorecard.build_scorecard(args)
        args.output_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        args.output_md.write_text(generate_partner_review_scorecard.render_markdown(result), encoding="utf-8")
        return result

    def verify_args(self, args: Namespace) -> Namespace:
        return Namespace(
            scorecard=args.output_json,
            markdown=args.output_md,
            ledger=args.ledger,
            cbom=args.cbom,
            policy_result=args.policy_result,
            profile_result=args.profile_result,
            quality_result=args.quality_result,
            migration_readiness=args.migration_readiness,
            backend_contract=args.backend_contract,
            provider_scope_result=args.provider_scope_result,
            benchmark_campaign=args.benchmark_campaign,
            ct_campaign=args.ct_campaign,
            acvp_schema_result=args.acvp_schema_result,
            device_evidence_result=args.device_evidence_result,
            reference_values=args.reference_values,
            appraisal_result=args.appraisal_result,
            output=args.output_json.with_name("partner_review_scorecard_result.json"),
        )

    def test_scorecard_replay_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.make_pack(root)
            self.write_scorecard(args)
            result = verify_partner_review_scorecard.verify(self.verify_args(args))
        self.assertTrue(result["passed"], result["failures"])

    def test_scorecard_replay_fails_on_stale_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.make_pack(root)
            payload = self.write_scorecard(args)
            payload["summary"]["blockers"] = 99
            args.output_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            result = verify_partner_review_scorecard.verify(self.verify_args(args))
        self.assertFalse(result["passed"])
        self.assertTrue(any("summary" in failure for failure in result["failures"]))

    def test_scorecard_replay_fails_on_tampered_artifact_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.make_pack(root)
            payload = self.write_scorecard(args)
            payload["input_artifacts"][0]["sha256"] = "0" * 64
            args.output_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            result = verify_partner_review_scorecard.verify(self.verify_args(args))
        self.assertFalse(result["passed"])
        self.assertTrue(any("hash/status drift" in failure for failure in result["failures"]))

    def test_scorecard_replay_fails_when_markdown_loses_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.make_pack(root)
            self.write_scorecard(args)
            body = args.output_md.read_text(encoding="utf-8")
            args.output_md.write_text(body.replace("hardware_promotion_not_completed", "hardware-redacted"), encoding="utf-8")
            result = verify_partner_review_scorecard.verify(self.verify_args(args))
        self.assertFalse(result["passed"])
        self.assertTrue(any("Markdown missing finding" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
