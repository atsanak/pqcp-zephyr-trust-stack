#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Focused tests for the release evidence tamper drill."""

from __future__ import annotations

import json
import tempfile
import textwrap
import unittest
from argparse import Namespace
from pathlib import Path

import run_evidence_tamper_drill as drill


SHA_A = "a" * 64
SHA_B = "b" * 64


class EvidenceTamperDrillTests(unittest.TestCase):
    def make_pack(self, root: Path) -> Path:
        pack = root / "pack"
        pack.mkdir()
        (pack / "benchmark_results.csv").write_text("suite,operation\nML-KEM,keygen\n", encoding="utf-8")
        (pack / "pqc_assurance_digest.json").write_text(
            json.dumps({"artifacts": [{"path": "benchmark_results.csv", "sha256": SHA_A}]}) + "\n",
            encoding="utf-8",
        )
        (pack / "pqc_reference_values.json").write_text(
            json.dumps({"head_sha": "f" * 40}) + "\n",
            encoding="utf-8",
        )
        (pack / "pqc_build_provenance.slsa.json").write_text(
            json.dumps({"subject": [{"name": "assurance_ledger.json", "digest": {"sha256": SHA_A}}]}) + "\n",
            encoding="utf-8",
        )
        (pack / "partner_review_scorecard.json").write_text(
            json.dumps({"input_artifacts": [{"name": "benchmark_results.csv", "sha256": SHA_A}]}) + "\n",
            encoding="utf-8",
        )
        return pack

    def make_policy(self, root: Path, *, expected_fragment: str = "tamper detected") -> Path:
        policy = root / "policy.json"
        policy.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "scenarios": [
                        {
                            "id": "csv",
                            "artifact": "benchmark_results.csv",
                            "required": True,
                            "mutation": {"type": "append_text", "text": "tamper\n"},
                            "expected_failure_contains": [expected_fragment],
                        },
                        {
                            "id": "json",
                            "artifact": "pqc_assurance_digest.json",
                            "required": True,
                            "mutation": {
                                "type": "set_json_pointer",
                                "pointer": "/artifacts/0/sha256",
                                "value": SHA_B,
                            },
                            "expected_failure_contains": [expected_fragment],
                        },
                    ],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return policy

    def make_verifier(self, root: Path, *, detects: bool = True) -> Path:
        verifier = root / "verifier.py"
        if detects:
            body = """
                #!/usr/bin/env python3
                import json
                import sys
                from pathlib import Path

                pack = Path(sys.argv[1])
                failures = []
                if "tamper" in (pack / "benchmark_results.csv").read_text(encoding="utf-8"):
                    failures.append("tamper detected: benchmark provenance")
                digest = json.loads((pack / "pqc_assurance_digest.json").read_text(encoding="utf-8"))
                if digest["artifacts"][0]["sha256"] != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":
                    failures.append("tamper detected: digest hash")
                if failures:
                    print("\\n".join(failures))
                    raise SystemExit(1)
                print("pack ok")
            """
        else:
            body = """
                #!/usr/bin/env python3
                print("pack ok")
            """
        verifier.write_text(textwrap.dedent(body).strip() + "\n", encoding="utf-8")
        verifier.chmod(0o755)
        return verifier

    def args(self, root: Path, pack: Path, policy: Path, verifier: Path) -> Namespace:
        return Namespace(
            output_root=pack,
            module_path=root,
            policy=policy,
            tag=None,
            verifier=verifier,
            output=pack / "evidence_tamper_drill_result.json",
            keep_workdir=False,
        )

    def test_tamper_drill_passes_when_mutations_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pack = self.make_pack(root)
            policy = self.make_policy(root)
            verifier = self.make_verifier(root)
            result = drill.run_drill(self.args(root, pack, policy, verifier))
        self.assertTrue(result["passed"])
        self.assertEqual(result["summary"]["detected_count"], 2)

    def test_tamper_drill_fails_when_verifier_accepts_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pack = self.make_pack(root)
            policy = self.make_policy(root)
            verifier = self.make_verifier(root, detects=False)
            result = drill.run_drill(self.args(root, pack, policy, verifier))
        self.assertFalse(result["passed"])
        self.assertIn("unexpectedly passed", result["failures"][0])

    def test_tamper_drill_fails_when_expected_failure_fragment_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pack = self.make_pack(root)
            policy = self.make_policy(root, expected_fragment="different failure")
            verifier = self.make_verifier(root)
            result = drill.run_drill(self.args(root, pack, policy, verifier))
        self.assertFalse(result["passed"])
        self.assertIn("expected failure", result["failures"][0])

    def test_missing_required_artifact_fails_setup(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pack = self.make_pack(root)
            policy = root / "missing-policy.json"
            policy.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "scenarios": [
                            {
                                "id": "missing",
                                "artifact": "missing_required_artifact.json",
                                "required": True,
                                "mutation": {"type": "append_text", "text": "tamper\n"},
                                "expected_failure_contains": ["tamper detected"],
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            verifier = self.make_verifier(root)
            result = drill.run_drill(self.args(root, pack, policy, verifier))
        self.assertFalse(result["passed"])
        self.assertIn("required artifact not found", result["failures"][0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
