#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Regression tests for ACVP JSON interop translation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import run_acvp_json_vectors


class AcvpJsonInteropTests(unittest.TestCase):
    def write(self, root: Path, payload: dict) -> Path:
        path = root / "vectors.json"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return path

    def test_valid_keygen_translates_to_success_class(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                Path(tmp),
                {"testGroups": [{"tgId": 1, "parameterSet": "ML-KEM-768", "function": "keyGen", "tests": [{"tcId": 1}]}]},
            )
            results, transcripts = run_acvp_json_vectors.process_file(path, "mlkem")
            self.assertEqual(results[0]["response"], "RESULT:OK")
            self.assertEqual(results[0]["expected_result_class"], "success")
            self.assertEqual(results[0]["transcript_sha256"], transcripts[0]["sha256"])

    def test_odd_length_hex_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                Path(tmp),
                {"testGroups": [{"tgId": 1, "parameterSet": "ML-KEM-768", "function": "encapDecap", "tests": [{"tcId": 1, "pk": "ABC"}]}]},
            )
            results, _ = run_acvp_json_vectors.process_file(path, "mlkem")
            self.assertEqual(results[0]["response"], "ERROR:INVALID_HEX")

    def test_unsupported_parameter_set_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                Path(tmp),
                {"testGroups": [{"tgId": 1, "parameterSet": "ML-DSA-99", "function": "sigGen", "tests": [{"tcId": 1}]}]},
            )
            results, _ = run_acvp_json_vectors.process_file(path, "mldsa")
            self.assertEqual(results[0]["response"], "ERROR:INVALID_LEVEL")

    def test_wrong_size_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                Path(tmp),
                {"testGroups": [{"tgId": 1, "parameterSet": "ML-KEM-768", "function": "encaps", "tests": [{"tcId": 1, "pk": "AA"}]}]},
            )
            results, _ = run_acvp_json_vectors.process_file(path, "mlkem")
            self.assertEqual(results[0]["response"], "ERROR:WRONG_SIZE")

    def test_mldsa_invalid_signature_hex_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                Path(tmp),
                {
                    "testGroups": [
                        {
                            "tgId": 1,
                            "parameterSet": "ML-DSA-65",
                            "function": "sigVer",
                            "tests": [{"tcId": 1, "pk": "AA", "message": "ABCD", "signature": "XYZ"}],
                        }
                    ]
                },
            )
            results, _ = run_acvp_json_vectors.process_file(path, "mldsa")
            self.assertIn(results[0]["response"], {"ERROR:INVALID_HEX", "ERROR:WRONG_SIZE"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
