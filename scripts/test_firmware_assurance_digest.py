#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Regression tests for firmware assurance digest header export."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import export_firmware_assurance_digest


GOOD_SHA = "0" * 64


class FirmwareAssuranceDigestTests(unittest.TestCase):
    def write_digest(self, root: Path, *, sha: str = GOOD_SHA) -> Path:
        payload = {
            "schema_version": 1,
            "digest_algorithm": "sha256",
            "artifacts": [
                {"path": "assurance_ledger.json", "sha256": sha, "size_bytes": 10},
                {"path": "pqc_cbom.cdx.json", "sha256": "1" * 64, "size_bytes": 20},
            ],
        }
        path = root / "pqc_assurance_digest.json"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return path

    def test_header_export_contains_root_and_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            digest = self.write_digest(root)
            output = root / "pqcp_assurance_digest_generated.h"
            result = export_firmware_assurance_digest.export_header(digest, output)
            header = output.read_text(encoding="utf-8")
            self.assertIn("PQCP_ASSURANCE_DIGEST_ROOT_SHA256", header)
            self.assertIn("PQCP_ASSURANCE_DIGEST_ARTIFACT_COUNT 2", header)
            self.assertIn("PQCP_ASSURANCE_DEVICE_EVIDENCE_NONCE", header)
            self.assertIn("PQCP_ASSURANCE_DEVICE_EVIDENCE_TRANSCRIPT_SHA256", header)
            self.assertIn(result["root_sha256"], header)

    def test_invalid_artifact_hash_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            digest = self.write_digest(root, sha="not-a-sha")
            output = root / "pqcp_assurance_digest_generated.h"
            with self.assertRaises(RuntimeError):
                export_firmware_assurance_digest.export_header(digest, output)

    def test_empty_artifact_list_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            digest = root / "pqc_assurance_digest.json"
            digest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "digest_algorithm": "sha256",
                        "artifacts": [],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(RuntimeError):
                export_firmware_assurance_digest.export_header(
                    digest,
                    root / "pqcp_assurance_digest_generated.h",
                )

    def test_canonical_root_changes_when_digest_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = json.loads(self.write_digest(root, sha="2" * 64).read_text(encoding="utf-8"))
            second = json.loads(self.write_digest(root, sha="3" * 64).read_text(encoding="utf-8"))
            self.assertNotEqual(
                export_firmware_assurance_digest.canonical_digest_root(first),
                export_firmware_assurance_digest.canonical_digest_root(second),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
