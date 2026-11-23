#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure-Python tests for the PQC Assurance Passport tooling."""

from __future__ import annotations

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import export_pqc_cbom
import generate_pqc_attestation
import verify_assurance_policy


def sha(path: Path) -> str:
    return generate_pqc_attestation.sha256_file(path)


class PQCAssurancePassportTests(unittest.TestCase):
    def make_module(self, root: Path) -> Path:
        module = root / "module"
        (module / "include/pqcp_zephyr").mkdir(parents=True)
        (module / ".github/workflows").mkdir(parents=True)
        (module / "include/pqcp_zephyr/version.h").write_text(
            '#define PQCP_VERSION_STRING "1.0.0"\n',
            encoding="utf-8",
        )
        (module / "CMakeLists.txt").write_text(
            'set(PQCP_PROJECT_VERSION "1.0.0")\n',
            encoding="utf-8",
        )
        (module / "west.yml").write_text(
            "\n".join(
                [
                    "manifest:",
                    "  projects:",
                    "    - name: zephyr",
                    "      revision: zephyr-sha",
                    "    - name: mlkem-native",
                    "      revision: mlkem-sha",
                    "    - name: mldsa-native",
                    "      revision: mldsa-sha",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (module / ".github/workflows/ci.yml").write_text(
            'env:\n  ZEPHYR_SDK_VERSION: "1.0.1"\n',
            encoding="utf-8",
        )
        return module

    def make_ledger(self, root: Path) -> Path:
        required = json.loads((Path(__file__).resolve().parent / "pqc_assurance_policy.json").read_text(encoding="utf-8"))["required_claim_ids"]
        claims = [
            {
                "id": claim_id,
                "category": claim_id.split(".", 1)[0],
                "claim": f"{claim_id} synthetic pass",
                "required": True,
                "status": "pass",
                "validators": [],
                "evidence_artifacts": [],
                "commands": [],
                "failure_reason": None,
                "details": {},
            }
            for claim_id in required
        ]
        ledger = {
            "schema_version": 3,
            "generated_at": "2026-05-09T00:00:00+00:00",
            "project": "pqcp-zephyr-trust-stack",
            "version": "1.0.0",
            "tag": "v1.0.0",
            "head_sha": "abc123",
            "dirty": False,
            "summary": {"pass": len(claims), "fail": 0, "not_applicable": 0},
            "claims": claims,
        }
        path = root / "assurance_ledger.json"
        path.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")
        (root / "assurance_ledger.md").write_text(
            "\n".join(claim["id"] for claim in claims) + "\n",
            encoding="utf-8",
        )
        return path

    def make_release_manifest(self, root: Path) -> Path:
        manifest = {
            "schema_version": 1,
            "project": "pqcp-zephyr-trust-stack",
            "version": "1.0.0",
            "tag": "v1.0.0",
            "source_commit": "abc123",
            "working_tree_dirty": False,
            "dependencies": {
                "zephyr": "zephyr-sha",
                "mlkem-native": "mlkem-sha",
                "mldsa-native": "mldsa-sha",
            },
            "release_notes": {"path": "release-notes-v1.0.0.md", "sha256": "unused"},
        }
        path = root / "release-manifest-v1.0.0.json"
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        return path

    def make_required_subject_files(self, root: Path, release_manifest: Path) -> None:
        (root / "assurance_report.html").write_text("<html>claims</html>\n", encoding="utf-8")
        (root / "benchmark_results.csv").write_text("suite,parameter_set\n", encoding="utf-8")
        (root / "benchmark_provenance.json").write_text("{}\n", encoding="utf-8")
        (root / "cost_of_assurance_evidence.json").write_text("{}\n", encoding="utf-8")
        (root / "ct_instruction_policy_result.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "passed": True,
                    "target_symbol_count": 1,
                    "target_symbols": ["pqcp_mlkem_decapsulate"],
                    "finding_count": 0,
                    "findings": [],
                    "failures": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "acvp_negative_scenario_floor_result.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "passed": True,
                    "scenario_count": 1,
                    "floor_count": 1,
                    "failures": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "pqc_asset_trace_result.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "passed": True,
                    "asset_count": 1,
                    "failures": [],
                    "checks": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "pqc_evidence_graph.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "summary": {"assets": 1, "nodes": 1, "edges": 0, "failures": 0},
                    "failures": [],
                    "nodes": [],
                    "edges": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "pqc_evidence_graph.md").write_text("# graph\n", encoding="utf-8")
        (root / "pqc_assurance_profile_result.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "passed": True,
                    "summary": {"profiles": 4, "assets": 13},
                    "failures": [],
                    "checks": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "pqc_evidence_quality_result.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "passed": True,
                    "summary": {"ledger_claims": 38, "quality_entries": 38},
                    "failures": [],
                    "checks": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "pqc_migration_readiness.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "passed": True,
                    "summary": {"asset_count": 1, "blocked_condition_count": 0},
                    "blocked_conditions": [],
                    "assets": [{"name": "ML-KEM-768"}],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "pqc_migration_readiness.md").write_text(
            "# PQC Migration Readiness\n\nML-KEM-768\n",
            encoding="utf-8",
        )
        (root / "generated").mkdir()
        (root / "generated/pqcp_assurance_digest_generated.h").write_text(
            "#define PQCP_ASSURANCE_DIGEST_ROOT_SHA256 "
            "\"0000000000000000000000000000000000000000000000000000000000000000\"\n"
            "#define PQCP_ASSURANCE_DIGEST_ARTIFACT_COUNT 1\n",
            encoding="utf-8",
        )
        (root / "transcripts").mkdir()
        (root / "transcripts/evidence_transcript_manifest.json").write_text("{}\n", encoding="utf-8")
        # The attestation uses the normalized subject name release-manifest.json.
        self.assertTrue(release_manifest.exists())

    def generate_passport(self, root: Path) -> tuple[Path, Path, Path, Path]:
        module = self.make_module(root)
        ledger_path = self.make_ledger(root)
        release_manifest = self.make_release_manifest(root)
        self.make_required_subject_files(root, release_manifest)

        cbom_path = root / "pqc_cbom.cdx.json"
        cbom = export_pqc_cbom.build_cbom(
            module,
            json.loads(ledger_path.read_text(encoding="utf-8")),
            json.loads(release_manifest.read_text(encoding="utf-8")),
        )
        cbom_path.write_text(json.dumps(cbom, indent=2) + "\n", encoding="utf-8")

        attestation_path = root / "pqc_attestation.intoto.json"
        digest_path = root / "pqc_assurance_digest.json"
        args = Namespace(
            module_path=module,
            ledger=ledger_path,
            ledger_md=root / "assurance_ledger.md",
            assurance_report=root / "assurance_report.html",
            cbom=cbom_path,
            release_manifest=release_manifest,
            transcript_manifest=root / "transcripts/evidence_transcript_manifest.json",
            benchmark_csv=root / "benchmark_results.csv",
            benchmark_provenance=root / "benchmark_provenance.json",
            cost_of_assurance_evidence=root / "cost_of_assurance_evidence.json",
            ct_instruction_policy_result=root / "ct_instruction_policy_result.json",
            evidence_graph=root / "pqc_evidence_graph.json",
            asset_trace_result=root / "pqc_asset_trace_result.json",
            assurance_profile_result=root / "pqc_assurance_profile_result.json",
            evidence_quality_result=root / "pqc_evidence_quality_result.json",
            migration_readiness_json=root / "pqc_migration_readiness.json",
            migration_readiness_md=root / "pqc_migration_readiness.md",
            output=attestation_path,
            digest_output=digest_path,
        )
        attestation = generate_pqc_attestation.build_attestation(args)
        attestation_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
        generate_pqc_attestation.write_digest(
            digest_path,
            [
                ledger_path,
                cbom_path,
                root / "transcripts/evidence_transcript_manifest.json",
                root / "benchmark_provenance.json",
                root / "ct_instruction_policy_result.json",
                root / "pqc_evidence_graph.json",
                root / "pqc_asset_trace_result.json",
                root / "pqc_assurance_profile_result.json",
                root / "pqc_evidence_quality_result.json",
                root / "pqc_migration_readiness.json",
                root / "pqc_migration_readiness.md",
                release_manifest,
            ],
            attestation_path=attestation_path,
        )
        return ledger_path, cbom_path, attestation_path, release_manifest

    def test_cbom_contains_required_crypto_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _ledger, cbom_path, _att, _manifest = self.generate_passport(root)
            cbom = json.loads(cbom_path.read_text(encoding="utf-8"))
            names = {component["name"] for component in cbom["components"]}
            self.assertIn("ML-KEM-768", names)
            self.assertIn("ML-KEM-1024", names)
            self.assertIn("ML-DSA-65", names)
            self.assertIn("ML-DSA-87", names)
            self.assertIn("mlkem-native", names)
            self.assertIn("mldsa-native", names)

    def test_policy_passes_for_generated_passport(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger, cbom, attestation, manifest = self.generate_passport(root)
            result = verify_assurance_policy.verify_policy(
                policy_path=Path(__file__).resolve().parent / "pqc_assurance_policy.json",
                ledger_path=ledger,
                cbom_path=cbom,
                attestation_path=attestation,
                release_manifest_path=manifest,
                asset_trace_result_path=root / "pqc_asset_trace_result.json",
                ct_instruction_policy_result_path=root / "ct_instruction_policy_result.json",
                evidence_graph_path=root / "pqc_evidence_graph.json",
                assurance_digest_path=root / "pqc_assurance_digest.json",
                firmware_digest_header_path=root / "generated/pqcp_assurance_digest_generated.h",
                assurance_profile_result_path=root / "pqc_assurance_profile_result.json",
                evidence_quality_result_path=root / "pqc_evidence_quality_result.json",
                migration_readiness_json_path=root / "pqc_migration_readiness.json",
                migration_readiness_md_path=root / "pqc_migration_readiness.md",
            )
            self.assertTrue(result["passed"], result["failures"])

    def test_policy_fails_when_required_crypto_asset_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger, cbom_path, attestation, manifest = self.generate_passport(root)
            cbom = json.loads(cbom_path.read_text(encoding="utf-8"))
            cbom["components"] = [
                component for component in cbom["components"] if component["name"] != "ML-KEM-768"
            ]
            cbom_path.write_text(json.dumps(cbom, indent=2) + "\n", encoding="utf-8")
            result = verify_assurance_policy.verify_policy(
                policy_path=Path(__file__).resolve().parent / "pqc_assurance_policy.json",
                ledger_path=ledger,
                cbom_path=cbom_path,
                attestation_path=attestation,
                release_manifest_path=manifest,
                asset_trace_result_path=root / "pqc_asset_trace_result.json",
                ct_instruction_policy_result_path=root / "ct_instruction_policy_result.json",
                evidence_graph_path=root / "pqc_evidence_graph.json",
                assurance_digest_path=root / "pqc_assurance_digest.json",
                firmware_digest_header_path=root / "generated/pqcp_assurance_digest_generated.h",
                assurance_profile_result_path=root / "pqc_assurance_profile_result.json",
                evidence_quality_result_path=root / "pqc_evidence_quality_result.json",
                migration_readiness_json_path=root / "pqc_migration_readiness.json",
                migration_readiness_md_path=root / "pqc_migration_readiness.md",
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("ML-KEM-768" in failure for failure in result["failures"]))

    def test_policy_fails_when_attestation_hash_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger, cbom, attestation, manifest = self.generate_passport(root)
            (root / "assurance_ledger.md").write_text("tampered\n", encoding="utf-8")
            result = verify_assurance_policy.verify_policy(
                policy_path=Path(__file__).resolve().parent / "pqc_assurance_policy.json",
                ledger_path=ledger,
                cbom_path=cbom,
                attestation_path=attestation,
                release_manifest_path=manifest,
                asset_trace_result_path=root / "pqc_asset_trace_result.json",
                ct_instruction_policy_result_path=root / "ct_instruction_policy_result.json",
                evidence_graph_path=root / "pqc_evidence_graph.json",
                assurance_digest_path=root / "pqc_assurance_digest.json",
                firmware_digest_header_path=root / "generated/pqcp_assurance_digest_generated.h",
                assurance_profile_result_path=root / "pqc_assurance_profile_result.json",
                evidence_quality_result_path=root / "pqc_evidence_quality_result.json",
                migration_readiness_json_path=root / "pqc_migration_readiness.json",
                migration_readiness_md_path=root / "pqc_migration_readiness.md",
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("hash mismatch" in failure for failure in result["failures"]))

    def test_policy_fails_when_deterministic_rng_marked_production(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger, cbom_path, attestation, manifest = self.generate_passport(root)
            cbom = json.loads(cbom_path.read_text(encoding="utf-8"))
            for component in cbom["components"]:
                if component["name"] == "Deterministic test RNG":
                    for prop in component["properties"]:
                        if prop["name"] == "pqcp:production_status":
                            prop["value"] = "supported"
            cbom_path.write_text(json.dumps(cbom, indent=2) + "\n", encoding="utf-8")
            result = verify_assurance_policy.verify_policy(
                policy_path=Path(__file__).resolve().parent / "pqc_assurance_policy.json",
                ledger_path=ledger,
                cbom_path=cbom_path,
                attestation_path=attestation,
                release_manifest_path=manifest,
                asset_trace_result_path=root / "pqc_asset_trace_result.json",
                ct_instruction_policy_result_path=root / "ct_instruction_policy_result.json",
                evidence_graph_path=root / "pqc_evidence_graph.json",
                assurance_digest_path=root / "pqc_assurance_digest.json",
                firmware_digest_header_path=root / "generated/pqcp_assurance_digest_generated.h",
                assurance_profile_result_path=root / "pqc_assurance_profile_result.json",
                evidence_quality_result_path=root / "pqc_evidence_quality_result.json",
                migration_readiness_json_path=root / "pqc_migration_readiness.json",
                migration_readiness_md_path=root / "pqc_migration_readiness.md",
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("Deterministic test RNG" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
