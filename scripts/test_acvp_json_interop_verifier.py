#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Regression tests for ACVP JSON interop artifact replay verification."""

from __future__ import annotations

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import run_acvp_json_vectors
import verify_acvp_json_interop


class AcvpJsonInteropVerifierTests(unittest.TestCase):
    def make_artifacts(self, root: Path) -> tuple[Path, Path]:
        vectors = root / "vectors.json"
        vectors.write_text(
            json.dumps(
                {
                    "testGroups": [
                        {
                            "tgId": 1,
                            "parameterSet": "ML-KEM-768",
                            "function": "keyGen",
                            "tests": [{"tcId": 1}],
                        }
                    ]
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        result = root / "acvp_json_interop_result.json"
        manifest = root / "acvp_json_transcript_manifest.json"
        results, transcripts = run_acvp_json_vectors.process_file(vectors, "mlkem")
        result.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "passed": True,
                    "summary": {"test_cases": len(results), "negative_cases": 0, "failures": 0},
                    "results": results,
                    "failures": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        manifest.write_text(
            json.dumps({"schema_version": 1, "transcripts": transcripts}, indent=2) + "\n",
            encoding="utf-8",
        )
        return result, manifest

    def verify(self, result: Path, manifest: Path) -> dict:
        return verify_acvp_json_interop.verify(
            Namespace(
                result=result,
                transcript_manifest=manifest,
                output=result.with_name("verify-result.json"),
            )
        )

    def test_valid_artifacts_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, manifest = self.make_artifacts(Path(tmp))
            self.assertTrue(self.verify(result, manifest)["passed"])

    def test_corrupted_result_hash_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, manifest = self.make_artifacts(Path(tmp))
            payload = json.loads(result.read_text(encoding="utf-8"))
            payload["results"][0]["transcript_sha256"] = "0" * 64
            result.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            check = self.verify(result, manifest)
            self.assertFalse(check["passed"])
            self.assertTrue(any("hash mismatch" in item for item in check["failures"]))

    def test_missing_manifest_row_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, manifest = self.make_artifacts(Path(tmp))
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["transcripts"] = []
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            check = self.verify(result, manifest)
            self.assertFalse(check["passed"])
            self.assertTrue(any("manifest" in item for item in check["failures"]))

    def test_negative_class_requires_error_response(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, manifest = self.make_artifacts(Path(tmp))
            payload = json.loads(result.read_text(encoding="utf-8"))
            payload["results"][0]["expected_result_class"] = "negative"
            result.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            check = self.verify(result, manifest)
            self.assertFalse(check["passed"])
            self.assertTrue(any("non-error response" in item for item in check["failures"]))

    def test_extra_manifest_row_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, manifest = self.make_artifacts(Path(tmp))
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            extra = dict(payload["transcripts"][0])
            extra["tcId"] = 99
            payload["transcripts"].append(extra)
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            check = self.verify(result, manifest)
            self.assertFalse(check["passed"])
            self.assertTrue(any("unreferenced" in item for item in check["failures"]))

    def test_duplicate_result_row_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, manifest = self.make_artifacts(Path(tmp))
            payload = json.loads(result.read_text(encoding="utf-8"))
            payload["results"].append(dict(payload["results"][0]))
            payload["summary"]["test_cases"] = 2
            result.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            check = self.verify(result, manifest)
            self.assertFalse(check["passed"])
            self.assertTrue(any("duplicates" in item for item in check["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
