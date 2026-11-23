#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression tests for firmware assurance status verification."""

from __future__ import annotations

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import verify_firmware_assurance_status


class FirmwareStatusTests(unittest.TestCase):
    def verify(self, transcript: str, *, digest: str = "a" * 64, count: int = 2) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = {
                "schema_version": 1,
                "version": "1.0.0",
                "expected_firmware_digest_root": digest,
                "firmware_digest_artifact_count": count,
            }
            ref_path = root / "pqc_reference_values.json"
            ref_path.write_text(json.dumps(reference), encoding="utf-8")
            transcript_path = root / "run.log"
            transcript_path.write_text(transcript, encoding="utf-8")
            args = Namespace(reference_values=ref_path, transcript=transcript_path, transcript_dir=None, output=root / "result.json")
            return verify_firmware_assurance_status.verify_status(args)

    def test_good_transcript_passes(self) -> None:
        transcript = "\n".join(
            [
                "PQCP_ASSURANCE_STATUS version=1.0.0 digest=" + "a" * 64 + " artifact_count=2 schema=1",
                "PQCP_ASSURANCE_ARTIFACT name=assurance_ledger.json sha256=" + "b" * 64,
                "PQCP_ASSURANCE_ARTIFACT name=pqc_cbom.cdx.json sha256=" + "c" * 64,
            ]
        )
        self.assertTrue(self.verify(transcript)["passed"])

    def test_wrong_digest_fails(self) -> None:
        transcript = "PQCP_ASSURANCE_STATUS version=1.0.0 digest=" + "d" * 64 + " artifact_count=2 schema=1\n"
        result = self.verify(transcript)
        self.assertFalse(result["passed"])
        self.assertIn("firmware assurance digest mismatch", result["failures"])

    def test_missing_marker_fails(self) -> None:
        self.assertFalse(self.verify("PROJECT EXECUTION SUCCESSFUL\n")["passed"])

    def test_artifact_count_mismatch_fails(self) -> None:
        transcript = "PQCP_ASSURANCE_STATUS version=1.0.0 digest=" + "a" * 64 + " artifact_count=1 schema=1\n"
        self.assertFalse(self.verify(transcript)["passed"])

    def test_malformed_hash_fails(self) -> None:
        transcript = "PQCP_ASSURANCE_STATUS version=1.0.0 digest=not-a-sha artifact_count=2 schema=1\n"
        self.assertFalse(self.verify(transcript)["passed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
