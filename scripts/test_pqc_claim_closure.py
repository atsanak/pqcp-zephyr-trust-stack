#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure-Python tests for post-ledger PQC Passport claim closure."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import verify_pqc_claim_closure


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


class PQCClaimClosureTests(unittest.TestCase):
    def make_pack(self, root: Path) -> Namespace:
        claims = [
            {
                "id": claim_id,
                "category": claim_id.split(".", 1)[0],
                "claim": f"{claim_id} synthetic post-ledger claim",
                "required": True,
                "status": "not_applicable",
                "validators": [],
                "evidence_artifacts": [],
                "commands": [],
                "failure_reason": None,
                "details": {},
            }
            for claim_id in verify_pqc_claim_closure.POST_LEDGER_CLAIMS
        ]
        ledger = write_json(
            root / "assurance_ledger.json",
            {
                "schema_version": 5,
                "project": "pqcp-zephyr-trust-stack",
                "version": "1.0.0",
                "tag": "v1.0.0",
                "head_sha": "abc123",
                "dirty": False,
                "summary": {"pass": 0, "fail": 0, "not_applicable": len(claims)},
                "claims": claims,
            },
        )
        cbom = write_json(root / "pqc_cbom.cdx.json", {"bomFormat": "CycloneDX", "components": []})
        attestation = write_json(
            root / "pqc_attestation.intoto.json",
            {
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": "https://github.com/atsanak/pqcp-zephyr-trust-stack/attestations/pqc-assurance/v1",
                "subject": [{"name": "assurance_ledger.json", "digest": {"sha256": sha256(ledger)}}],
                "predicate": {},
            },
        )
        policy = write_json(root / "pqc_policy_result.json", {"schema_version": 3, "passed": True, "failures": []})
        profile = write_json(root / "pqc_assurance_profile_result.json", {"schema_version": 1, "passed": True})
        environment = write_json(root / "pqc_environment_result.json", {"schema_version": 1, "passed": True})
        quality = write_json(root / "pqc_evidence_quality_result.json", {"schema_version": 1, "passed": True})
        readiness = write_json(
            root / "pqc_migration_readiness.json",
            {
                "schema_version": 1,
                "passed": True,
                "assets": [{"name": "ML-KEM-768"}],
                "summary": {"asset_count": 1},
            },
        )
        readiness_md = root / "pqc_migration_readiness.md"
        readiness_md.write_text("# PQC Migration Readiness\n\nML-KEM-768\n", encoding="utf-8")
        header = root / "generated" / "pqcp_assurance_digest_generated.h"
        header.parent.mkdir()
        header.write_text(
            "#define PQCP_ASSURANCE_DIGEST_ROOT_SHA256 \"abc\"\n"
            "#define PQCP_ASSURANCE_DIGEST_ARTIFACT_COUNT 8\n",
            encoding="utf-8",
        )
        manifest = write_json(root / "release-manifest-v1.0.0.json", {"schema_version": 1})
        digest_artifacts = [
            ledger,
            cbom,
            attestation,
            environment,
            profile,
            quality,
            readiness,
            readiness_md,
            manifest,
        ]
        digest = write_json(
            root / "pqc_assurance_digest.json",
            {
                "schema_version": 1,
                "digest_algorithm": "sha256",
                "artifacts": [
                    {
                        "path": path.name,
                        "sha256": sha256(path),
                        "size_bytes": path.stat().st_size,
                    }
                    for path in digest_artifacts
                ],
            },
        )
        return Namespace(
            ledger=ledger,
            attestation=attestation,
            assurance_digest=digest,
            policy_result=policy,
            assurance_profile_result=profile,
            evidence_quality_result=quality,
            migration_readiness_json=readiness,
            migration_readiness_md=readiness_md,
            firmware_digest_header=header,
            output=root / "pqc_claim_closure_result.json",
        )

    def test_claim_closure_passes_for_synthetic_pack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = verify_pqc_claim_closure.verify_closure(self.make_pack(Path(tmp)))
            self.assertTrue(result["passed"], result["failures"])

    def test_missing_profile_result_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.make_pack(Path(tmp))
            args.assurance_profile_result.unlink()
            result = verify_pqc_claim_closure.verify_closure(args)
            self.assertFalse(result["passed"])
            self.assertTrue(any("profile" in failure for failure in result["failures"]))

    def test_corrupted_digest_hash_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.make_pack(Path(tmp))
            digest = json.loads(args.assurance_digest.read_text(encoding="utf-8"))
            digest["artifacts"][0]["sha256"] = "0" * 64
            args.assurance_digest.write_text(json.dumps(digest, indent=2) + "\n", encoding="utf-8")
            result = verify_pqc_claim_closure.verify_closure(args)
            self.assertFalse(result["passed"])
            self.assertTrue(any("hash mismatch" in failure for failure in result["failures"]))

    def test_missing_post_ledger_claim_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.make_pack(Path(tmp))
            ledger = json.loads(args.ledger.read_text(encoding="utf-8"))
            ledger["claims"] = [
                claim
                for claim in ledger["claims"]
                if claim["id"] != "security.production_rng_policy"
            ]
            args.ledger.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")
            result = verify_pqc_claim_closure.verify_closure(args)
            self.assertFalse(result["passed"])
            self.assertTrue(any("security.production_rng_policy" in failure for failure in result["failures"]))

    def test_migration_markdown_missing_asset_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.make_pack(Path(tmp))
            args.migration_readiness_md.write_text("# PQC Migration Readiness\n", encoding="utf-8")
            result = verify_pqc_claim_closure.verify_closure(args)
            self.assertFalse(result["passed"])
            self.assertTrue(any("Markdown missing asset" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
