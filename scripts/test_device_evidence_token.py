#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for firmware device-evidence token replay."""

from __future__ import annotations

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import verify_device_evidence_token


DIGEST = "a" * 64


class DeviceEvidenceTokenTests(unittest.TestCase):
    def write_inputs(self, root: Path, *, wrong_digest: bool = False) -> tuple[Path, Path]:
        reference = root / "reference.json"
        reference.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "expected_firmware_digest_root": DIGEST,
                    "firmware_digest_artifact_count": 3,
                }
            ),
            encoding="utf-8",
        )
        transcripts = root / "transcripts"
        transcripts.mkdir()
        observed = "b" * 64 if wrong_digest else DIGEST
        (transcripts / "status.log").write_text(
            f"PQCP_DEVICE_EVIDENCE nonce={DIGEST[:32]} digest={observed} artifact_count=3 schema=1 transcript_sha256={DIGEST}\n",
            encoding="utf-8",
        )
        return reference, transcripts

    def test_token_passes_matching_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reference, transcripts = self.write_inputs(Path(tmp))
            _token, result = verify_device_evidence_token.verify(
                Namespace(reference_values=reference, transcript_dir=transcripts, token_output=Path(tmp) / "token.json", output=Path(tmp) / "result.json")
            )
        self.assertTrue(result["passed"], result["failures"])

    def test_wrong_digest_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reference, transcripts = self.write_inputs(Path(tmp), wrong_digest=True)
            _token, result = verify_device_evidence_token.verify(
                Namespace(reference_values=reference, transcript_dir=transcripts, token_output=Path(tmp) / "token.json", output=Path(tmp) / "result.json")
            )
        self.assertFalse(result["passed"])
        self.assertTrue(any("digest" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
