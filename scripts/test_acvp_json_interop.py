#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
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
            self.assertEqual(results[0]["operation_class"], "keyGen")
            self.assertEqual(results[0]["transcript_sha256"], transcripts[0]["sha256"])

    def test_explicit_mlkem_encap_and_decap_operation_classes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            encap = self.write(
                root,
                {
                    "testGroups": [
                        {
                            "tgId": 1,
                            "parameterSet": "ML-KEM-512",
                            "function": "encap",
                            "tests": [{"tcId": 1, "pk": "AA" * 800}],
                        }
                    ]
                },
            )
            results, _ = run_acvp_json_vectors.process_file(encap, "mlkem")
            self.assertEqual(results[0]["operation_class"], "encap")
            self.assertEqual(results[0]["response"], "RESULT:OK")

            decap_payload = {
                "testGroups": [
                    {
                        "tgId": 1,
                        "parameterSet": "ML-KEM-512",
                        "function": "decap",
                        "tests": [{"tcId": 1, "ct": "BB" * 768, "sk": "CC" * 1632}],
                    }
                ]
            }
            decap = root / "decap.json"
            decap.write_text(json.dumps(decap_payload), encoding="utf-8")
            results, _ = run_acvp_json_vectors.process_file(decap, "mlkem")
            self.assertEqual(results[0]["operation_class"], "decap")
            self.assertEqual(results[0]["response"], "RESULT:OK")

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
            self.assertEqual(results[0]["operation_class"], "sigVer")

    def test_explicit_mldsa_siggen_operation_class(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                Path(tmp),
                {
                    "testGroups": [
                        {
                            "tgId": 1,
                            "parameterSet": "ML-DSA-44",
                            "function": "sigGen",
                            "tests": [{"tcId": 1, "sk": "AA" * 2560, "message": "ABCD"}],
                        }
                    ]
                },
            )
            results, _ = run_acvp_json_vectors.process_file(path, "mldsa")
            self.assertEqual(results[0]["operation_class"], "sigGen")
            self.assertEqual(results[0]["response"], "RESULT:OK")

    def test_valid_case_after_malformed_case_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                Path(tmp),
                {
                    "testGroups": [
                        {
                            "tgId": 1,
                            "parameterSet": "ML-KEM-768",
                            "function": "encapDecap",
                            "tests": [{"tcId": 1, "pk": "ABC"}],
                        },
                        {
                            "tgId": 2,
                            "parameterSet": "ML-KEM-768",
                            "function": "keyGen",
                            "tests": [{"tcId": 2}],
                        },
                    ]
                },
            )
            results, _ = run_acvp_json_vectors.process_file(path, "mlkem")
            self.assertEqual(results[0]["response"], "ERROR:INVALID_HEX")
            self.assertEqual(results[1]["response"], "RESULT:OK")
            self.assertEqual(results[1]["expected_result_class"], "success")


if __name__ == "__main__":
    unittest.main(verbosity=2)
