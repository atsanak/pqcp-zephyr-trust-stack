#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for ACVP JSON schema coverage replay."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import validate_acvp_json_schema


def digest(command: str, response: str) -> str:
    return hashlib.sha256(f"{command}\n{response}\n".encode("utf-8")).hexdigest()


class AcvpJsonSchemaTests(unittest.TestCase):
    def write_inputs(self, root: Path, *, omit_decap: bool = False) -> tuple[Path, Path]:
        rows = []
        for idx, op in enumerate(("keyGen", "encap", "decap", "sigGen", "sigVer"), start=1):
            if omit_decap and op == "decap":
                continue
            response = "ERROR:INVALID_HEX" if op == "encap" else "RESULT:OK"
            if op == "decap":
                response = "RESULT:OK"
            command = f"{op}:cmd"
            rows.append(
                {
                    "source": "fixture.json",
                    "mode": "mlkem" if op in {"keyGen", "encap", "decap"} else "mldsa",
                    "operation_class": op,
                    "tgId": idx,
                    "tcId": idx,
                    "command": command,
                    "response": response,
                    "expected_result_class": "negative" if response.startswith("ERROR") else "success",
                    "transcript_sha256": digest(command, response),
                }
            )
        result = root / "result.json"
        manifest = root / "manifest.json"
        result.write_text(json.dumps({"schema_version": 1, "results": rows}), encoding="utf-8")
        manifest.write_text(json.dumps({"schema_version": 1, "transcripts": [{"source": r["source"], "operation_class": r["operation_class"], "tgId": r["tgId"], "tcId": r["tcId"], "command": r["command"], "response": r["response"], "sha256": r["transcript_sha256"]} for r in rows]}), encoding="utf-8")
        return result, manifest

    def test_schema_coverage_passes_all_operations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result_path, manifest = self.write_inputs(Path(tmp))
            result = validate_acvp_json_schema.validate(Namespace(result=result_path, transcript_manifest=manifest, output=Path(tmp) / "out.json"))
        self.assertTrue(result["passed"], result["failures"])

    def test_missing_operation_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result_path, manifest = self.write_inputs(Path(tmp), omit_decap=True)
            result = validate_acvp_json_schema.validate(Namespace(result=result_path, transcript_manifest=manifest, output=Path(tmp) / "out.json"))
        self.assertFalse(result["passed"])
        self.assertTrue(any("decap" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
