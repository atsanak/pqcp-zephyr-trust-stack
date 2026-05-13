#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Regression tests for PQC reference values."""

from __future__ import annotations

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import generate_pqc_reference_values
import verify_pqc_reference_values


class ReferenceValuesTests(unittest.TestCase):
    def write_json(self, path: Path, payload: dict) -> Path:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def fixtures(self, root: Path) -> Namespace:
        ledger = self.write_json(
            root / "assurance_ledger.json",
            {
                "schema_version": 6,
                "project": "pqcp-zephyr-trust-stack",
                "version": "1.0.0",
                "tag": "v1.0.0",
                "head_sha": "abc123",
                "dirty": False,
                "claims": [{"id": "release.version_consistency", "required": True}],
            },
        )
        cbom = self.write_json(
            root / "pqc_cbom.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [{"bom-ref": "crypto:mlkem768", "name": "ML-KEM-768"}],
            },
        )
        attestation = self.write_json(
            root / "pqc_attestation.intoto.json",
            {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "x", "digest": {"sha256": "0" * 64}}]},
        )
        digest = self.write_json(
            root / "pqc_assurance_digest.json",
            {"schema_version": 1, "digest_algorithm": "sha256", "artifacts": [{"path": "assurance_ledger.json", "sha256": "1" * 64}]},
        )
        manifest = self.write_json(
            root / "release-manifest-v1.0.0.json",
            {
                "schema_version": 1,
                "version": "1.0.0",
                "tag": "v1.0.0",
                "source_commit": "abc123",
                "working_tree_dirty": False,
                "zephyr_revision": "zephyr-sha",
                "dependencies": {"zephyr": "zephyr-sha"},
            },
        )
        policy = self.write_json(root / "pqc_policy_result.json", {"schema_version": 4, "passed": True})
        profile = self.write_json(root / "pqc_assurance_profile_result.json", {"schema_version": 1, "passed": True, "profiles": {"qemu_release": {}}})
        transcript = self.write_json(root / "evidence_transcript_manifest.json", {"schema_version": 1, "transcripts": [{"name": "x"}]})
        return Namespace(
            module_path=root,
            ledger=ledger,
            cbom=cbom,
            attestation=attestation,
            assurance_digest=digest,
            release_manifest=manifest,
            policy_result=policy,
            profile_result=profile,
            transcript_manifest=transcript,
            output=root / "pqc_reference_values.json",
        )

    def verify_args(self, args: Namespace, root: Path) -> Namespace:
        values = vars(args).copy()
        values.pop("output", None)
        return Namespace(**values, reference_values=args.output, output=root / "result.json")

    def test_reference_values_generate_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixtures(Path(tmp))
            reference = generate_pqc_reference_values.build_reference(args)
            args.output.write_text(json.dumps(reference, indent=2) + "\n", encoding="utf-8")
            verify_args = self.verify_args(args, Path(tmp))
            result = verify_pqc_reference_values.verify_reference(verify_args)
            self.assertTrue(result["passed"], result["failures"])

    def test_stale_head_sha_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixtures(Path(tmp))
            reference = generate_pqc_reference_values.build_reference(args)
            reference["head_sha"] = "stale"
            args.output.write_text(json.dumps(reference, indent=2) + "\n", encoding="utf-8")
            verify_args = self.verify_args(args, Path(tmp))
            result = verify_pqc_reference_values.verify_reference(verify_args)
            self.assertFalse(result["passed"])
            self.assertTrue(any("head_sha" in item for item in result["failures"]))

    def test_corrupted_artifact_hash_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixtures(Path(tmp))
            reference = generate_pqc_reference_values.build_reference(args)
            reference["artifact_hashes"]["pqc_cbom.cdx.json"]["sha256"] = "f" * 64
            args.output.write_text(json.dumps(reference, indent=2) + "\n", encoding="utf-8")
            verify_args = self.verify_args(args, Path(tmp))
            result = verify_pqc_reference_values.verify_reference(verify_args)
            self.assertFalse(result["passed"])

    def test_stale_digest_root_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixtures(Path(tmp))
            reference = generate_pqc_reference_values.build_reference(args)
            reference["expected_firmware_digest_root"] = "0" * 64
            args.output.write_text(json.dumps(reference, indent=2) + "\n", encoding="utf-8")
            result = verify_pqc_reference_values.verify_reference(self.verify_args(args, Path(tmp)))
            self.assertFalse(result["passed"])

    def test_missing_required_claim_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixtures(Path(tmp))
            reference = generate_pqc_reference_values.build_reference(args)
            reference["required_claim_ids"] = []
            args.output.write_text(json.dumps(reference, indent=2) + "\n", encoding="utf-8")
            result = verify_pqc_reference_values.verify_reference(self.verify_args(args, Path(tmp)))
            self.assertFalse(result["passed"])

    def test_missing_cbom_asset_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixtures(Path(tmp))
            reference = generate_pqc_reference_values.build_reference(args)
            reference["cbom_component_ids"] = []
            args.output.write_text(json.dumps(reference, indent=2) + "\n", encoding="utf-8")
            result = verify_pqc_reference_values.verify_reference(self.verify_args(args, Path(tmp)))
            self.assertFalse(result["passed"])

    def test_dirty_and_environment_metadata_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixtures(Path(tmp))
            reference = generate_pqc_reference_values.build_reference(args)
            reference["dirty"] = True
            reference["zephyr_revision"] = "old"
            reference["sdk_version"] = "old-sdk"
            args.output.write_text(json.dumps(reference, indent=2) + "\n", encoding="utf-8")
            result = verify_pqc_reference_values.verify_reference(self.verify_args(args, Path(tmp)))
            self.assertFalse(result["passed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
