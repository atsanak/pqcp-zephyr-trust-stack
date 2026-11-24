#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Focused tests for the local assurance ledger generator."""

from __future__ import annotations

import csv
import hashlib
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import generate_assurance_ledger as ledger
import verify_assurance_ledger as ledger_verify
from export_results import (
    CSV_FIELDNAMES,
    EXPECTED_PRIMITIVE_ROWS,
    REQUIRED_BENCHMARK_METADATA_KEYS,
    add_single_observation_distribution_rows,
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AssuranceLedgerTests(unittest.TestCase):
    def make_module(self, root: Path) -> None:
        (root / "include/pqcp_zephyr").mkdir(parents=True)
        (root / "include/pqcp_zephyr/version.h").write_text(
            '#define PQCP_VERSION_STRING "1.2.3"\n',
            encoding="utf-8",
        )
        (root / "CMakeLists.txt").write_text(
            'set(PQCP_PROJECT_VERSION "1.2.3")\n',
            encoding="utf-8",
        )
        (root / "CHANGELOG.md").write_text(
            "## [Unreleased]\n\n## [1.2.3] - 2026-04-28\n\n- shipped\n",
            encoding="utf-8",
        )

    def make_claims(self, root: Path, claim_ids: list[str], *, schema_version: int = 1) -> Path:
        all_claims = json.loads((ledger.DEFAULT_CLAIMS).read_text(encoding="utf-8"))["claims"]
        selected = [claim for claim in all_claims if claim["id"] in claim_ids]
        path = root / "claims.json"
        path.write_text(
            json.dumps({"schema_version": schema_version, "claims": selected}, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def make_benchmark_csv(self, root: Path) -> Path:
        path = root / "benchmark_results.csv"
        rows: list[dict[str, object]] = []
        for parameter_set, operations in EXPECTED_PRIMITIVE_ROWS.items():
            suite = parameter_set.split("-")[1]
            for operation in operations:
                for implementation in ("pqcp", "baseline"):
                    rows.append(
                        {
                            "suite": suite,
                            "parameter_set": parameter_set,
                            "implementation": implementation,
                            "backend": "auto" if implementation == "pqcp" else "clean",
                            "operation": operation,
                            "cycles": 1000,
                            "time_us": 100,
                            "rom_bytes": 2000,
                            "ram_bytes": 3000,
                            "platform": "qemu_x86_64",
                            "timestamp": "2026-04-28T00:00:00+00:00",
                        }
                    )
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_FIELDNAMES)
            writer.writeheader()
            writer.writerows(rows)
        return path

    def make_provenance(self, csv_path: Path) -> Path:
        path = csv_path.with_name("benchmark_provenance.json")
        metadata = {
            "row_count": len(REQUIRED_BENCHMARK_METADATA_KEYS),
            "keys": list(REQUIRED_BENCHMARK_METADATA_KEYS),
            "required_keys": list(REQUIRED_BENCHMARK_METADATA_KEYS),
            "by_key": {
                key: ["synthetic"] for key in REQUIRED_BENCHMARK_METADATA_KEYS
            },
            "run_ids": ["synthetic-run"],
        }
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "csv": {
                        "path": csv_path.name,
                        "sha256": sha256(csv_path),
                        "distribution_row_count": 1,
                    },
                    "benchmark_metadata": metadata,
                    "comparison_context": {
                        "source_dataset": "synthetic",
                        "source_ecosystem": "pqcp-zephyr-trust-stack",
                        "board_class": "qemu",
                        "clock_assumption": "synthetic test values",
                        "backend_family": "synthetic",
                        "statistic_type": "single",
                        "environment_type": "qemu",
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def make_cost_evidence(self, root: Path, *, metric: bool = True) -> Path:
        path = root / "cost_of_assurance_evidence.json"
        metrics = [
            {
                "metric": "handshake_time",
                "candidate_value": 10.0,
                "baseline_value": 8.0,
                "ratio": 1.25,
                "threshold": {"max_ratio": 6.0},
                "passed": True,
                "failure_reason": None,
            }
        ] if metric else []
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "comparisons": [
                        {
                            "name": "comparison-a",
                            "passed": True,
                            "failure_reason": None,
                            "metrics": metrics,
                        }
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def make_release_bundle(self, root: Path) -> Path:
        bundle = root / "bundle" / "v1.2.3"
        bundle.mkdir(parents=True)
        notes = bundle / "release-notes-v1.2.3.md"
        notes.write_text("- shipped\n", encoding="utf-8")
        (bundle / "release-manifest-v1.2.3.json").write_text(
            json.dumps(
                {
                    "version": "1.2.3",
                    "tag": "v1.2.3",
                    "release_notes": {
                        "path": notes.name,
                        "sha256": sha256(notes),
                    },
                    "tag_points_to_head": False,
                    "working_tree_dirty": False,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return root / "bundle"

    def make_transcript_manifest(
        self,
        root: Path,
        *,
        required_steps: list[str] | None = None,
        omit_step: str | None = None,
    ) -> Path:
        manifest = root / "transcripts" / "evidence_transcript_manifest.json"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        steps = required_steps or [
            "ACVP serial ztest run",
            "ACVP KAT ztest run",
            "benchmark_csv",
        ]
        transcripts: list[dict[str, object]] = []
        for index, step in enumerate(steps, start=1):
            if step == omit_step:
                continue
            path = manifest.parent / f"{index:02d}-{step.lower().replace(' ', '-')}.log"
            path.write_text(f"{step}\nPROJECT EXECUTION SUCCESSFUL\n", encoding="utf-8")
            transcripts.append(
                {
                    "step": step,
                    "command": ["true"],
                    "command_text": "true",
                    "cwd": str(root),
                    "returncode": 0,
                    "duration_seconds": 0.1,
                    "transcript_path": path.name,
                    "sha256": sha256(path),
                    "size_bytes": path.stat().st_size,
                }
            )
        qemu_log = root / "cost_of_assurance_smoke" / "runs" / "qemu-smoke" / "run.log"
        qemu_log.parent.mkdir(parents=True, exist_ok=True)
        qemu_log.write_text("PQCP_METRIC layer=primitive operation=KEYGEN cycles=123 us=4\n", encoding="utf-8")
        manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "generated_at": "2026-04-28T00:00:00+00:00",
                    "generator": "scripts/release_check.py",
                    "required_steps": steps,
                    "transcripts": transcripts,
                    "qemu_stdout_transcripts": [
                        {
                            "label": "qemu stdout: qemu-smoke",
                            "transcript_path": "../cost_of_assurance_smoke/runs/qemu-smoke/run.log",
                            "sha256": sha256(qemu_log),
                            "size_bytes": qemu_log.stat().st_size,
                        }
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return manifest

    def make_args(
        self,
        root: Path,
        claims: Path,
        csv_path: Path,
        provenance: Path,
        cost_evidence: Path,
        bundle: Path,
        *,
        tag: str | None = None,
    ) -> Namespace:
        return Namespace(
            module_path=root,
            claims=claims,
            version=None,
            tag=tag,
            benchmark_csv=csv_path,
            benchmark_provenance=provenance,
            cost_of_assurance_evidence=cost_evidence,
            release_bundle_root=bundle,
            transcript_manifest=self.make_transcript_manifest(root),
            kat_header=root / "missing_kat_vectors.h",
            kat_vectors_dir=root / "missing_nist_vectors",
            negative_scenarios=root / "missing_acvp_negative_scenarios.json",
            output_json=root / "assurance_ledger.json",
            output_md=root / "assurance_ledger.md",
        )

    def write_ledger_pair(self, root: Path, result: dict[str, object]) -> tuple[Path, Path]:
        json_path = root / "assurance_ledger.json"
        md_path = root / "assurance_ledger.md"
        json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        md_path.write_text(ledger.render_markdown(result), encoding="utf-8")
        return json_path, md_path

    def test_passing_ledger_from_synthetic_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            provenance = self.make_provenance(csv_path)
            cost = self.make_cost_evidence(root)
            bundle = self.make_release_bundle(root)
            claims = self.make_claims(
                root,
                [
                    "release.version_consistency",
                    "benchmark.csv_validity",
                    "benchmark.provenance_binding",
                    "cost_of_assurance.guardrails",
                    "release.local_bundle",
                ],
            )
            result = ledger.build_ledger(
                self.make_args(root, claims, csv_path, provenance, cost, bundle, tag="v1.2.3")
            )
            self.assertEqual(result["summary"]["fail"], 0)

    def test_missing_benchmark_provenance_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            claims = self.make_claims(root, ["benchmark.provenance_binding"])
            result = ledger.build_ledger(
                self.make_args(
                    root,
                    claims,
                    csv_path,
                    root / "missing-provenance.json",
                    self.make_cost_evidence(root),
                    self.make_release_bundle(root),
                )
            )
            self.assertEqual(result["claims"][0]["status"], "fail")

    def test_corrupted_csv_hash_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            provenance = self.make_provenance(csv_path)
            with csv_path.open("a", encoding="utf-8") as handle:
                handle.write("# corrupt\n")
            claims = self.make_claims(root, ["benchmark.provenance_binding"])
            result = ledger.build_ledger(
                self.make_args(
                    root,
                    claims,
                    csv_path,
                    provenance,
                    self.make_cost_evidence(root),
                    self.make_release_bundle(root),
                )
            )
            self.assertEqual(result["claims"][0]["status"], "fail")

    def test_missing_cost_metric_evidence_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            claims = self.make_claims(root, ["cost_of_assurance.guardrails"])
            result = ledger.build_ledger(
                self.make_args(
                    root,
                    claims,
                    csv_path,
                    self.make_provenance(csv_path),
                    self.make_cost_evidence(root, metric=False),
                    self.make_release_bundle(root),
                )
            )
            self.assertEqual(result["claims"][0]["status"], "fail")

    def test_transcript_binding_passes_with_hashed_required_steps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            claims = self.make_claims(root, ["release.transcript_binding"])
            result = ledger.build_ledger(
                self.make_args(
                    root,
                    claims,
                    csv_path,
                    self.make_provenance(csv_path),
                    self.make_cost_evidence(root),
                    self.make_release_bundle(root),
                )
            )
            self.assertEqual(result["claims"][0]["status"], "pass")

    def test_transcript_binding_fails_when_required_step_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            claims = self.make_claims(root, ["release.transcript_binding"])
            args = self.make_args(
                root,
                claims,
                csv_path,
                self.make_provenance(csv_path),
                self.make_cost_evidence(root),
                self.make_release_bundle(root),
            )
            args.transcript_manifest = self.make_transcript_manifest(
                root,
                required_steps=["ACVP serial ztest run", "ACVP KAT ztest run"],
                omit_step="ACVP KAT ztest run",
            )
            result = ledger.build_ledger(args)
            self.assertEqual(result["claims"][0]["status"], "fail")
            self.assertIn("required transcript step missing", result["claims"][0]["failure_reason"])

    def test_transcript_binding_fails_on_hash_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            claims = self.make_claims(root, ["release.transcript_binding"])
            args = self.make_args(
                root,
                claims,
                csv_path,
                self.make_provenance(csv_path),
                self.make_cost_evidence(root),
                self.make_release_bundle(root),
            )
            manifest = args.transcript_manifest
            first_log = next(manifest.parent.glob("*.log"))
            first_log.write_text("tampered\n", encoding="utf-8")
            result = ledger.build_ledger(args)
            self.assertEqual(result["claims"][0]["status"], "fail")
            self.assertIn("transcript sha256 mismatch", result["claims"][0]["failure_reason"])

    def test_transcript_binding_fails_on_qemu_stdout_hash_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            claims = self.make_claims(root, ["release.transcript_binding"])
            args = self.make_args(
                root,
                claims,
                csv_path,
                self.make_provenance(csv_path),
                self.make_cost_evidence(root),
                self.make_release_bundle(root),
            )
            qemu_log = root / "cost_of_assurance_smoke" / "runs" / "qemu-smoke" / "run.log"
            qemu_log.write_text("tampered qemu stdout\n", encoding="utf-8")
            result = ledger.build_ledger(args)
            self.assertEqual(result["claims"][0]["status"], "fail")
            self.assertIn("qemu stdout", result["claims"][0]["failure_reason"])
            self.assertIn("sha256 mismatch", result["claims"][0]["failure_reason"])

    def test_tag_claim_is_not_applicable_without_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            claims = self.make_claims(root, ["release.tag_integrity"])
            result = ledger.build_ledger(
                self.make_args(
                    root,
                    claims,
                    csv_path,
                    self.make_provenance(csv_path),
                    self.make_cost_evidence(root),
                    self.make_release_bundle(root),
                )
            )
            self.assertEqual(result["claims"][0]["status"], "not_applicable")

    def test_markdown_and_json_include_same_claim_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            claims = self.make_claims(
                root,
                ["release.version_consistency", "benchmark.csv_validity"],
            )
            result = ledger.build_ledger(
                self.make_args(
                    root,
                    claims,
                    csv_path,
                    self.make_provenance(csv_path),
                    self.make_cost_evidence(root),
                    self.make_release_bundle(root),
                )
            )
            markdown = ledger.render_markdown(result)
            for claim in result["claims"]:
                self.assertIn(claim["id"], markdown)

    def test_verify_generated_ledger_pair_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            claims = self.make_claims(
                root,
                [
                    "release.version_consistency",
                    "benchmark.csv_validity",
                    "benchmark.provenance_binding",
                    "cost_of_assurance.guardrails",
                    "release.local_bundle",
                ],
            )
            result = ledger.build_ledger(
                self.make_args(
                    root,
                    claims,
                    csv_path,
                    self.make_provenance(csv_path),
                    self.make_cost_evidence(root),
                    self.make_release_bundle(root),
                    tag="v1.2.3",
                )
            )
            json_path, md_path = self.write_ledger_pair(root, result)
            failures = ledger_verify.verify_ledger(
                json_path,
                markdown=md_path,
                claims_path=claims,
                module_path=root,
            )
            self.assertEqual(failures, [])

    def test_verify_ledger_detects_artifact_hash_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            provenance = self.make_provenance(csv_path)
            claims = self.make_claims(root, ["benchmark.provenance_binding"])
            result = ledger.build_ledger(
                self.make_args(
                    root,
                    claims,
                    csv_path,
                    provenance,
                    self.make_cost_evidence(root),
                    self.make_release_bundle(root),
                )
            )
            json_path, md_path = self.write_ledger_pair(root, result)
            provenance.write_text("tampered\n", encoding="utf-8")
            failures = ledger_verify.verify_ledger(
                json_path,
                markdown=md_path,
                claims_path=claims,
                module_path=root,
            )
            self.assertTrue(any("sha256 mismatch" in failure for failure in failures))

    def test_verify_ledger_detects_markdown_claim_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            claims = self.make_claims(root, ["benchmark.csv_validity"])
            result = ledger.build_ledger(
                self.make_args(
                    root,
                    claims,
                    csv_path,
                    self.make_provenance(csv_path),
                    self.make_cost_evidence(root),
                    self.make_release_bundle(root),
                )
            )
            json_path, md_path = self.write_ledger_pair(root, result)
            md_path.write_text("# stale ledger\n", encoding="utf-8")
            failures = ledger_verify.verify_ledger(
                json_path,
                markdown=md_path,
                claims_path=claims,
                module_path=root,
            )
            self.assertTrue(any("markdown is missing claim id" in failure for failure in failures))

    def test_verify_ledger_detects_summary_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            claims = self.make_claims(root, ["benchmark.csv_validity"])
            result = ledger.build_ledger(
                self.make_args(
                    root,
                    claims,
                    csv_path,
                    self.make_provenance(csv_path),
                    self.make_cost_evidence(root),
                    self.make_release_bundle(root),
                )
            )
            result["summary"]["pass"] = 0
            json_path, md_path = self.write_ledger_pair(root, result)
            failures = ledger_verify.verify_ledger(
                json_path,
                markdown=md_path,
                claims_path=claims,
                module_path=root,
            )
            self.assertTrue(any("summary.pass" in failure for failure in failures))

    def _write_acvp_serial_transcript(
        self,
        root: Path,
        body: str,
        *,
        manifest_extra_steps: list[str] | None = None,
    ) -> Path:
        manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path = manifest_path.parent / "01-acvp-serial-ztest-run.log"
        transcript_path.write_text(body, encoding="utf-8")
        transcripts = [
            {
                "step": "ACVP serial ztest run",
                "command": ["true"],
                "command_text": "true",
                "cwd": str(root),
                "returncode": 0,
                "duration_seconds": 0.1,
                "transcript_path": transcript_path.name,
                "sha256": sha256(transcript_path),
                "size_bytes": transcript_path.stat().st_size,
            }
        ]
        for step in manifest_extra_steps or []:
            transcripts.append(
                {
                    "step": step,
                    "command": ["true"],
                    "command_text": "true",
                    "cwd": str(root),
                    "returncode": 0,
                    "duration_seconds": 0.1,
                    "transcript_path": transcript_path.name,
                    "sha256": sha256(transcript_path),
                    "size_bytes": transcript_path.stat().st_size,
                }
            )
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "generated_at": "2026-04-28T00:00:00+00:00",
                    "generator": "scripts/release_check.py",
                    "required_steps": ["ACVP serial ztest run"],
                    "transcripts": transcripts,
                    "qemu_stdout_transcripts": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return manifest_path

    def test_acvp_negative_path_claim_passes_with_required_ztest_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            transcript_body = (
                "test_rejects_malformed_commands\n"
                "test_rejects_invalid_hex_and_wrong_sizes\n"
                "test_serial_line_garbage_rejected_and_recovered\n"
                "TESTSUITE pqcp_acvp_serial succeeded\n"
            )
            manifest = self._write_acvp_serial_transcript(root, transcript_body)
            scenarios_path = ledger.DEFAULT_NEGATIVE_SCENARIOS
            spec = {
                "id": "acvp.negative_path_rejection",
                "category": "acvp",
                "claim": "x",
                "required": True,
            }
            result = ledger.evaluate_acvp_negative_paths(
                spec,
                scenarios_path=scenarios_path,
                transcript_manifest=manifest,
            )
            self.assertEqual(result["status"], "pass", result.get("failure_reason"))
            self.assertIn("expected_error_responses", result["details"])

    def test_acvp_negative_path_claim_fails_when_marker_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            manifest = self._write_acvp_serial_transcript(
                root,
                "TESTSUITE pqcp_acvp_serial succeeded\n",  # missing test_rejects_* markers
            )
            spec = {
                "id": "acvp.negative_path_rejection",
                "category": "acvp",
                "claim": "x",
                "required": True,
            }
            result = ledger.evaluate_acvp_negative_paths(
                spec,
                scenarios_path=ledger.DEFAULT_NEGATIVE_SCENARIOS,
                transcript_manifest=manifest,
            )
            self.assertEqual(result["status"], "fail")
            self.assertIn("test_rejects_malformed_commands", result["failure_reason"])

    def test_acvp_timeout_recovery_claim_fails_when_marker_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            manifest = self._write_acvp_serial_transcript(
                root,
                "TESTSUITE pqcp_acvp_serial succeeded\n",  # no timeout ztest marker
            )
            spec = {
                "id": "acvp.timeout_recovery",
                "category": "acvp",
                "claim": "x",
                "required": True,
            }
            result = ledger.evaluate_acvp_timeout_recovery(
                spec,
                transcript_manifest=manifest,
            )
            self.assertEqual(result["status"], "fail")
            self.assertIn("test_readline_timeout", result["failure_reason"])

    def test_acvp_timeout_recovery_claim_passes_with_required_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            manifest = self._write_acvp_serial_transcript(
                root,
                "test_readline_timeout\nTESTSUITE pqcp_acvp_serial succeeded\n",
            )
            spec = {
                "id": "acvp.timeout_recovery",
                "category": "acvp",
                "claim": "x",
                "required": True,
            }
            result = ledger.evaluate_acvp_timeout_recovery(
                spec,
                transcript_manifest=manifest,
            )
            self.assertEqual(result["status"], "pass", result.get("failure_reason"))
            self.assertEqual(result["details"]["wire_response_asserted_by_ztest"], "ERROR:TIMEOUT")
            self.assertFalse(result["details"]["wire_response_literal_present"])

    def test_per_primitive_kat_claim_passes_against_real_fixtures(self) -> None:
        spec = {
            "id": "kat.mlkem_512",
            "category": "kat",
            "claim": "x",
            "required": True,
        }
        result = ledger.evaluate_kat_per_primitive(
            spec,
            header=ledger.DEFAULT_KAT_HEADER,
            vectors_dir=ledger.DEFAULT_VECTORS_DIR,
            parameter_set="ML-KEM-512",
        )
        self.assertEqual(result["status"], "pass", result.get("failure_reason"))
        self.assertEqual(result["details"]["parameter_set"], "ML-KEM-512")

    def test_per_primitive_benchmark_passes_with_complete_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            csv_path = self.make_benchmark_csv(root)
            spec = {
                "id": "benchmark.mlkem_throughput",
                "category": "benchmark",
                "claim": "x",
                "required": True,
            }
            result = ledger.evaluate_benchmark_per_primitive(
                spec,
                csv_path=csv_path,
                algorithm="ML-KEM",
                parameter_levels=("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"),
            )
            self.assertEqual(result["status"], "pass", result.get("failure_reason"))

    def test_per_primitive_benchmark_ignores_additive_distribution_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            csv_path = self.make_benchmark_csv(root)
            with csv_path.open("a", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=CSV_FIELDNAMES)
                writer.writerow(
                    {
                        "suite": "KEM",
                        "parameter_set": "ML-KEM-768",
                        "implementation": "pqcp",
                        "backend": "auto",
                        "operation": "keygen_cycles_mad",
                        "cycles": 0,
                        "time_us": "",
                        "rom_bytes": "",
                        "ram_bytes": "",
                        "platform": "qemu_x86_64",
                        "timestamp": "2026-04-28T00:00:00+00:00",
                    }
                )
                writer.writerow(
                    {
                        "suite": "KEM",
                        "parameter_set": "ML-KEM-768",
                        "implementation": "pqcp",
                        "backend": "auto",
                        "operation": "keygen_sample_count",
                        "cycles": 1,
                        "time_us": "",
                        "rom_bytes": "",
                        "ram_bytes": "",
                        "platform": "qemu_x86_64",
                        "timestamp": "2026-04-28T00:00:00+00:00",
                    }
                )
            spec = {
                "id": "benchmark.mlkem_throughput",
                "category": "benchmark",
                "claim": "x",
                "required": True,
            }
            result = ledger.evaluate_benchmark_per_primitive(
                spec,
                csv_path=csv_path,
                algorithm="ML-KEM",
                parameter_levels=("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"),
            )
            self.assertEqual(result["status"], "pass", result.get("failure_reason"))

    def test_distribution_quality_requires_build_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            csv_path = self.make_benchmark_csv(root)
            with csv_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            rows = add_single_observation_distribution_rows(rows)
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=CSV_FIELDNAMES)
                writer.writeheader()
                writer.writerows(rows)

            provenance = csv_path.with_name("benchmark_provenance.json")
            provenance.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "csv": {
                            "path": csv_path.name,
                            "sha256": sha256(csv_path),
                            "distribution_row_count": 1,
                        },
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            spec = {
                "id": "benchmark.distribution_quality",
                "category": "benchmark",
                "claim": "x",
                "required": True,
            }
            result = ledger.evaluate_benchmark_distribution_quality(
                spec,
                csv_path=csv_path,
                provenance_path=provenance,
            )
            self.assertEqual(result["status"], "fail")
            self.assertIn("benchmark_metadata", result["failure_reason"])

    def test_per_primitive_benchmark_fails_when_level_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            csv_path = self.make_benchmark_csv(root)
            spec = {
                "id": "benchmark.mldsa_throughput",
                "category": "benchmark",
                "claim": "x",
                "required": True,
            }
            result = ledger.evaluate_benchmark_per_primitive(
                spec,
                csv_path=csv_path,
                algorithm="ML-DSA",
                parameter_levels=("ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ML-DSA-999"),
            )
            self.assertEqual(result["status"], "fail")
            self.assertIn("ML-DSA-999", result["failure_reason"])

    def test_v2_schema_load_does_not_warn(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            claims = self.make_claims(root, ["release.version_consistency"], schema_version=2)
            specs = ledger.load_claim_specs(claims)
            self.assertEqual(len(specs), 1)
            self.assertEqual(specs[0]["id"], "release.version_consistency")

    def _write_negative_transcript_manifest(self, root: Path, body: str) -> Path:
        manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path = manifest_path.parent / "01-acvp-serial-negative-ztest-run.log"
        transcript_path.write_text(body, encoding="utf-8")
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "generated_at": "2026-04-28T00:00:00+00:00",
                    "generator": "scripts/release_check.py",
                    "required_steps": ["ACVP serial negative ztest run"],
                    "transcripts": [
                        {
                            "step": "ACVP serial negative ztest run",
                            "command": ["true"],
                            "command_text": "true",
                            "cwd": str(root),
                            "returncode": 0,
                            "duration_seconds": 0.1,
                            "transcript_path": transcript_path.name,
                            "sha256": sha256(transcript_path),
                            "size_bytes": transcript_path.stat().st_size,
                        }
                    ],
                    "qemu_stdout_transcripts": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return manifest_path

    def test_acvp_negative_replay_passes_with_suite_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                "PQCP_ACVP_NEG case=INVALID_MLKEM_ENCAPS_HEX "
                "command=ENCAPS:MLKEM:768:zz response=ERROR:INVALID_HEX\n"
                "PQCP_ACVP_NEG case=WRONG_SIZE_SIGN "
                "command=SIGN:MLDSA:65:00 response=ERROR:WRONG_SIZE\n"
                "TESTSUITE pqcp_acvp_serial_negative succeeded\n"
                "PROJECT EXECUTION SUCCESSFUL\n"
            )
            manifest = self._write_negative_transcript_manifest(root, body)
            spec = {
                "id": "acvp.negative_scenarios_replay",
                "category": "acvp",
                "claim": "x",
                "required": True,
            }
            result = ledger.evaluate_acvp_negative_replay(
                spec,
                scenarios_path=ledger.DEFAULT_NEGATIVE_SCENARIOS,
                transcript_manifest=manifest,
            )
            self.assertEqual(result["status"], "pass", result.get("failure_reason"))

    def test_acvp_mlkem_negative_paths_fail_when_marker_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                # Only MLDSA cases in the transcript -> mlkem claim must fail.
                "PQCP_ACVP_NEG case=WRONG_SIZE_SIGN "
                "command=SIGN:MLDSA:65:00 response=ERROR:WRONG_SIZE\n"
                "TESTSUITE pqcp_acvp_serial_negative succeeded\n"
                "PROJECT EXECUTION SUCCESSFUL\n"
            )
            manifest = self._write_negative_transcript_manifest(root, body)
            spec = {
                "id": "acvp.mlkem_negative_paths",
                "category": "acvp",
                "claim": "x",
                "required": True,
            }
            result = ledger.evaluate_acvp_negative_replay(
                spec,
                scenarios_path=ledger.DEFAULT_NEGATIVE_SCENARIOS,
                transcript_manifest=manifest,
                required_response_substrings=("MLKEM",),
                label="ML-KEM negative paths",
            )
            self.assertEqual(result["status"], "fail")
            self.assertIn("MLKEM", result["failure_reason"])

    def test_acvp_negative_replay_fails_when_suite_marker_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = "PROJECT EXECUTION SUCCESSFUL\n"  # missing TESTSUITE pqcp_acvp_serial_negative succeeded
            manifest = self._write_negative_transcript_manifest(root, body)
            spec = {
                "id": "acvp.negative_scenarios_replay",
                "category": "acvp",
                "claim": "x",
                "required": True,
            }
            result = ledger.evaluate_acvp_negative_replay(
                spec,
                scenarios_path=ledger.DEFAULT_NEGATIVE_SCENARIOS,
                transcript_manifest=manifest,
            )
            self.assertEqual(result["status"], "fail")
            self.assertIn("pqcp_acvp_serial_negative", result["failure_reason"])

    def _write_sanitizers_transcript(self, root: Path, body: str) -> Path:
        manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path = manifest_path.parent / "01-sanitizers.log"
        transcript_path.write_text(body, encoding="utf-8")
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "generated_at": "2026-04-28T00:00:00+00:00",
                    "generator": "scripts/release_check.py",
                    "required_steps": ["sanitizers"],
                    "transcripts": [
                        {
                            "step": "sanitizers",
                            "command": ["true"],
                            "command_text": "true",
                            "cwd": str(root),
                            "returncode": 0,
                            "duration_seconds": 0.1,
                            "transcript_path": transcript_path.name,
                            "sha256": sha256(transcript_path),
                            "size_bytes": transcript_path.stat().st_size,
                        }
                    ],
                    "qemu_stdout_transcripts": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return manifest_path

    def test_asan_clean_passes_when_transcript_has_no_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                "PQCP Sanitizer Checks\n"
                "[ztest_acvp_serial] Run OK (logs/ztest_acvp_serial.run.log)\n"
                "[ztest_primitive] Run OK (logs/ztest_primitive.run.log)\n"
                "[ztest_tls_selftest] Run OK (logs/ztest_tls_selftest.run.log)\n"
            )
            manifest = self._write_sanitizers_transcript(root, body)
            spec = {"id": "security.asan_clean", "category": "security", "claim": "x", "required": True}
            result = ledger.evaluate_asan_clean(spec, transcript_manifest=manifest)
            self.assertEqual(result["status"], "pass", result.get("failure_reason"))

    def test_asan_clean_fails_when_marker_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                "PQCP Sanitizer Checks\n"
                "==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...\n"
            )
            manifest = self._write_sanitizers_transcript(root, body)
            spec = {"id": "security.asan_clean", "category": "security", "claim": "x", "required": True}
            result = ledger.evaluate_asan_clean(spec, transcript_manifest=manifest)
            self.assertEqual(result["status"], "fail")
            self.assertIn("AddressSanitizer", result["failure_reason"])

    def test_ubsan_clean_fails_on_runtime_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                "PQCP Sanitizer Checks\n"
                "src/foo.c:42:7: runtime error: signed integer overflow\n"
            )
            manifest = self._write_sanitizers_transcript(root, body)
            spec = {"id": "security.ubsan_clean", "category": "security", "claim": "x", "required": True}
            result = ledger.evaluate_ubsan_clean(spec, transcript_manifest=manifest)
            self.assertEqual(result["status"], "fail")
            self.assertIn("runtime error", result["failure_reason"])

    def test_sanitizer_clean_skips_when_host_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                "PQCP Sanitizer Checks\n"
                "Non-CI host: skipping sanitizer execution. Set PQCP_STRICT_SANITIZERS=1\n"
            )
            manifest = self._write_sanitizers_transcript(root, body)
            spec = {"id": "security.asan_clean", "category": "security", "claim": "x", "required": True}
            result = ledger.evaluate_asan_clean(spec, transcript_manifest=manifest)
            self.assertEqual(result["status"], "not_applicable")

    def test_sanitizer_clean_skips_when_host_unsupported_without_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                "Sanitizer checks for native_sim/native/64 require a Linux host.\n"
                "Non-CI host: skipping sanitizer execution. Set PQCP_STRICT_SANITIZERS=1\n"
            )
            manifest = self._write_sanitizers_transcript(root, body)
            spec = {"id": "security.asan_clean", "category": "security", "claim": "x", "required": True}
            result = ledger.evaluate_asan_clean(spec, transcript_manifest=manifest)
            self.assertEqual(result["status"], "not_applicable")

    def _write_boot_verify_transcript(self, root: Path, body: str) -> Path:
        manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path = manifest_path.parent / "01-boot-kat.log"
        transcript_path.write_text(body, encoding="utf-8")
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "generated_at": "2026-04-28T00:00:00+00:00",
                    "generator": "scripts/release_check.py",
                    "required_steps": ["boot KAT self-verify ztest run"],
                    "transcripts": [
                        {
                            "step": "boot KAT self-verify ztest run",
                            "command": ["true"],
                            "command_text": "true",
                            "cwd": str(root),
                            "returncode": 0,
                            "duration_seconds": 0.1,
                            "transcript_path": transcript_path.name,
                            "sha256": sha256(transcript_path),
                            "size_bytes": transcript_path.stat().st_size,
                        }
                    ],
                    "qemu_stdout_transcripts": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return manifest_path

    def test_boot_kat_self_verify_passes_with_all_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                "PQCP_KAT_BOOT_VERIFY: starting power-on self-test\n"
                "PQCP_KAT_BOOT_VERIFY: all enabled primitives passed\n"
                "PQCP_KAT_BOOT_VERIFY: ztest reached main without panic\n"
                "TESTSUITE pqcp_kat_boot_verify succeeded\n"
                "PROJECT EXECUTION SUCCESSFUL\n"
            )
            manifest = self._write_boot_verify_transcript(root, body)
            spec = {"id": "boot.kat_self_verify", "category": "boot", "claim": "x", "required": True}
            result = ledger.evaluate_boot_kat_self_verify(spec, transcript_manifest=manifest)
            self.assertEqual(result["status"], "pass", result.get("failure_reason"))

    def test_boot_kat_self_verify_fails_when_no_post_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                "TESTSUITE pqcp_kat_boot_verify succeeded\n"
                "PROJECT EXECUTION SUCCESSFUL\n"  # missing PQCP_KAT_BOOT_VERIFY:* lines
            )
            manifest = self._write_boot_verify_transcript(root, body)
            spec = {"id": "boot.kat_self_verify", "category": "boot", "claim": "x", "required": True}
            result = ledger.evaluate_boot_kat_self_verify(spec, transcript_manifest=manifest)
            self.assertEqual(result["status"], "fail")
            self.assertIn("PQCP_KAT_BOOT_VERIFY", result["failure_reason"])

    def _write_evidence_chain_transcript(self, root: Path, body: str) -> Path:
        manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path = manifest_path.parent / "01-evidence-chain.log"
        transcript_path.write_text(body, encoding="utf-8")
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "generated_at": "2026-06-10T00:00:00+00:00",
                    "generator": "scripts/release_check.py",
                    "required_steps": ["evidence chain host replay"],
                    "transcripts": [
                        {
                            "step": "evidence chain host replay",
                            "command": ["true"],
                            "command_text": "true",
                            "cwd": str(root),
                            "returncode": 0,
                            "duration_seconds": 0.1,
                            "transcript_path": transcript_path.name,
                            "sha256": sha256(transcript_path),
                            "size_bytes": transcript_path.stat().st_size,
                        }
                    ],
                    "qemu_stdout_transcripts": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return manifest_path

    def test_evidence_chain_replay_passes_with_all_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                "PQCP_DEPLOYMENT_EVIDENCE_VERDICT schema=1 status=FAIL\n"
                "PQCP_DEPLOYMENT_EVIDENCE_SEAL schema=1 status=FAIL\n"
                "PQCP_DEPLOYMENT_ASSURANCE_PASSPORT schema=1 status=FAIL\n"
                "PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY schema=1 passed=PASS\n"
                "PROJECT EXECUTION SUCCESSFUL\n"
                "pqcp-evidence-verify: CHAIN OK\n"
                "  verdict->seal_binding=true seal->passport_binding=true\n"
                "[evidence-chain] PASS: device evidence chain replayed on host\n"
            )
            manifest = self._write_evidence_chain_transcript(root, body)
            spec = {
                "id": "firmware.evidence_chain_replay",
                "category": "firmware",
                "claim": "x",
                "required": True,
            }
            result = ledger.evaluate_firmware_evidence_chain_replay(
                spec, transcript_manifest=manifest
            )
            self.assertEqual(result["status"], "pass", result.get("failure_reason"))

    def test_evidence_chain_replay_fails_without_chain_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                "PQCP_DEPLOYMENT_EVIDENCE_VERDICT schema=1 status=FAIL\n"
                "PQCP_DEPLOYMENT_EVIDENCE_SEAL schema=1 status=FAIL\n"
                "PQCP_DEPLOYMENT_ASSURANCE_PASSPORT schema=1 status=FAIL\n"
                "PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY schema=1 passed=PASS\n"
                "PROJECT EXECUTION SUCCESSFUL\n"
                "pqcp-evidence-verify: CHAIN BROKEN\n"
            )
            manifest = self._write_evidence_chain_transcript(root, body)
            spec = {
                "id": "firmware.evidence_chain_replay",
                "category": "firmware",
                "claim": "x",
                "required": True,
            }
            result = ledger.evaluate_firmware_evidence_chain_replay(
                spec, transcript_manifest=manifest
            )
            self.assertEqual(result["status"], "fail")
            self.assertIn("CHAIN OK", result["failure_reason"])

    def test_evidence_chain_replay_fails_without_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "transcripts" / "evidence_transcript_manifest.json"
            spec = {
                "id": "firmware.evidence_chain_replay",
                "category": "firmware",
                "claim": "x",
                "required": True,
            }
            result = ledger.evaluate_firmware_evidence_chain_replay(
                spec, transcript_manifest=manifest
            )
            self.assertEqual(result["status"], "fail")
            self.assertIn("missing or empty", result["failure_reason"])

    def _write_ct_instr_transcript(self, root: Path, body: str) -> Path:
        manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path = manifest_path.parent / "01-ct-instr.log"
        transcript_path.write_text(body, encoding="utf-8")
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "generated_at": "2026-06-10T00:00:00+00:00",
                    "generator": "scripts/release_check.py",
                    "required_steps": ["ct instruction-count"],
                    "transcripts": [
                        {
                            "step": "ct instruction-count",
                            "command": ["true"],
                            "command_text": "true",
                            "cwd": str(root),
                            "returncode": 0,
                            "duration_seconds": 0.1,
                            "transcript_path": transcript_path.name,
                            "sha256": sha256(transcript_path),
                            "size_bytes": transcript_path.stat().st_size,
                        }
                    ],
                    "qemu_stdout_transcripts": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return manifest_path

    def test_ct_instruction_count_passes_with_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                "PQCP_CT_INSTR alg=MLKEM-768 iterations=8 regions=16\n"
                "PQCP_CT_INSTRUCTION_COUNT PASS regions=16 insns_per_region=814304 loads_per_region=133443 stores_per_region=106992 alg=MLKEM-768\n"
                "[ct-insn] PASS: valid and corrupted decapsulation execute an identical guest-instruction count and an identical guest memory-access count\n"
                "[ct-insn] PASS: valid and corrupted decapsulation execute an identical guest-instruction count\n"
            )
            manifest = self._write_ct_instr_transcript(root, body)
            spec = {
                "id": "security.ct_instruction_count",
                "category": "security",
                "claim": "x",
                "required": True,
            }
            result = ledger.evaluate_ct_instruction_count(
                spec, transcript_manifest=manifest
            )
            self.assertEqual(result["status"], "pass", result.get("failure_reason"))

    def test_ct_instruction_count_fails_without_pass_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                "PQCP_CT_INSTR alg=MLKEM-768 iterations=8 regions=16\n"
                "[ct-insn] FAIL: instruction counts differ across regions\n"
            )
            manifest = self._write_ct_instr_transcript(root, body)
            spec = {
                "id": "security.ct_instruction_count",
                "category": "security",
                "claim": "x",
                "required": True,
            }
            result = ledger.evaluate_ct_instruction_count(
                spec, transcript_manifest=manifest
            )
            self.assertEqual(result["status"], "fail")

    CLEAN_TRACE = "".join(
        f"PQCP_CT_TRACE PASS alg=MLKEM-768 opt={opt} regions=48 groups=8 "
        "channels=pc,addr,line,div distinct=1 bits=0.00 miss_bound_95=0.062\n"
        for opt in ("default", "speed", "debug")
    ) + "[ct-trace] PASS: every region is indistinguishable\n"
    REDISCOVERY = (
        "PQCP_CT_TRACE_REDISCOVERY PASS leaks=5/5 benign_flagged=0/3 "
        "missed_by_counts_only=2/5\n"
    )

    def _write_ct_trace_transcripts(self, root: Path, clean: str, redis: str) -> Path:
        manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        entries = []
        for step, body, name in (
            ("ct trace relational", clean, "01-ct-trace.log"),
            ("ct leak rediscovery", redis, "02-ct-leak.log"),
        ):
            path = manifest_path.parent / name
            path.write_text(body, encoding="utf-8")
            entries.append({
                "step": step, "transcript_path": name,
                "sha256": hashlib.sha256(body.encode()).hexdigest(),
                "size_bytes": len(body.encode()), "returncode": 0,
            })
        manifest_path.write_text(
            json.dumps({"schema_version": 1, "transcripts": entries}) + "\n",
            encoding="utf-8")
        return manifest_path

    def _eval_ct_trace(self, clean: str, redis: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = self._write_ct_trace_transcripts(Path(tmp), clean, redis)
            spec = {"id": "security.ct_trace_relational", "category": "security",
                    "claim": "x", "required": True}
            return ledger.evaluate_ct_trace_relational(
                spec, transcript_manifest=manifest)

    def test_ct_trace_relational_passes_with_both_markers(self) -> None:
        result = self._eval_ct_trace(self.CLEAN_TRACE, self.REDISCOVERY)
        self.assertEqual(result["status"], "pass", result.get("failure_reason"))
        self.assertEqual(result["details"]["leaks_rediscovered"], "5/5")

    def test_ct_trace_relational_fails_when_a_leak_is_missed(self) -> None:
        for redis in (
            self.REDISCOVERY.replace("leaks=5/5", "leaks=4/5"),
            self.REDISCOVERY.replace("benign_flagged=0/3", "benign_flagged=1/3"),
            self.REDISCOVERY.replace("PASS", "FAIL"),
            "",
        ):
            result = self._eval_ct_trace(self.CLEAN_TRACE, redis or "noise\n")
            self.assertEqual(result["status"], "fail", redis)

    def test_ct_trace_relational_fails_without_clean_run_evidence(self) -> None:
        for clean in (
            self.CLEAN_TRACE.replace("distinct=1", "distinct=2"),
            self.CLEAN_TRACE.replace("PASS", "FAIL"),
            self.CLEAN_TRACE.replace("groups=8", "groups=1"),
            self.CLEAN_TRACE.replace("channels=pc,addr,line,div", "channels=pc"),
            self.CLEAN_TRACE.replace("opt=debug", "opt=default"),
            self.CLEAN_TRACE.replace("opt=speed", "opt=default"),
        ):
            result = self._eval_ct_trace(clean, self.REDISCOVERY)
            self.assertEqual(result["status"], "fail", clean)

    DECL_CLEAN = "".join(
        f"PQCP_CT_TRACE_DECLASS PASS alg=MLDSA-65 opt={opt} regions=18 "
        "groups=3 segments=600 testable=546 classes=91 sites=8 violations=0 "
        "coverage_pct=91.0\n" for opt in ("default", "speed", "debug")
    ) + "[ct-trace] PASS: every comparable segment is identical\n"
    DECL_REDIS = (
        "PQCP_CT_TRACE_DECLASS_REDISCOVERY PASS leaks=4/4 "
        "benign_flagged=0/3 missed_by_counts_only=2/4\n"
    )

    def _eval_declass(self, clean: str, redis: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            entries = []
            for step, body, name in (
                ("ct trace declassified", clean, "01.log"),
                ("ct leak rediscovery declassified", redis, "02.log"),
            ):
                (manifest_path.parent / name).write_text(body, encoding="utf-8")
                entries.append({
                    "step": step, "transcript_path": name,
                    "sha256": hashlib.sha256(body.encode()).hexdigest(),
                    "size_bytes": len(body.encode()), "returncode": 0})
            manifest_path.write_text(
                json.dumps({"schema_version": 1, "transcripts": entries}) + "\n",
                encoding="utf-8")
            spec = {"id": "security.ct_trace_declassified",
                    "category": "security", "claim": "x", "required": True}
            return ledger.evaluate_ct_trace_declassified(
                spec, transcript_manifest=manifest_path)

    def test_ct_trace_declassified_passes_with_both_markers(self) -> None:
        result = self._eval_declass(self.DECL_CLEAN, self.DECL_REDIS)
        self.assertEqual(result["status"], "pass", result.get("failure_reason"))
        self.assertEqual(result["details"]["leaks_rediscovered"], "4/4")

    def test_ct_trace_declassified_fails_on_weak_or_missing_evidence(self) -> None:
        for clean, redis in (
            (self.DECL_CLEAN.replace("violations=0", "violations=3"), self.DECL_REDIS),
            (self.DECL_CLEAN.replace("opt=debug", "opt=default"), self.DECL_REDIS),
            (self.DECL_CLEAN.replace("testable=546", "testable=100"), self.DECL_REDIS),
            (self.DECL_CLEAN.replace("groups=3", "groups=1"), self.DECL_REDIS),
            (self.DECL_CLEAN, self.DECL_REDIS.replace("leaks=4/4", "leaks=3/4")),
            (self.DECL_CLEAN, self.DECL_REDIS.replace("benign_flagged=0/3", "benign_flagged=1/3")),
            (self.DECL_CLEAN, self.DECL_REDIS.replace("PASS", "FAIL")),
            (self.DECL_CLEAN, "noise\n"),
        ):
            result = self._eval_declass(clean, redis)
            self.assertEqual(result["status"], "fail", (clean, redis))

    VLAT_CLEAN = "".join(
        f"PQCP_CT_TRACE_VLAT PASS alg=MLKEM-768 target=cortex-m3 opt={opt} "
        "regions=48 sites=1 div_sites=0 mul_sites=1 fail_sites=0 "
        "candidate_sites=1 base=clean\n"
        for opt in ("default", "speed", "debug")
    ) + "[ct-trace] PASS: no secret-dependent operand latency\n"
    VLAT_REDIS = (
        "PQCP_CT_TRACE_VLAT_REDISCOVERY PASS leaks=3/3 benign_flagged=0/3 "
        "missed_by_address_channels=3/3\n"
    )

    def _eval_vlat(self, clean: str, redis: str, baseline_max: int = 1) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            entries = []
            for step, body, name in (
                ("ct trace cortex-m latency", clean, "01.log"),
                ("ct leak rediscovery cortex-m latency", redis, "02.log"),
            ):
                (manifest_path.parent / name).write_text(body, encoding="utf-8")
                entries.append({
                    "step": step, "transcript_path": name,
                    "sha256": hashlib.sha256(body.encode()).hexdigest(),
                    "size_bytes": len(body.encode()), "returncode": 0})
            manifest_path.write_text(
                json.dumps({"schema_version": 1, "transcripts": entries}) + "\n",
                encoding="utf-8")
            baseline = root / "baseline.json"
            baseline.write_text(json.dumps({"candidate_sites_max": baseline_max}))
            spec = {"id": "security.ct_trace_cortex_m_latency",
                    "category": "security", "claim": "x", "required": True}
            return ledger.evaluate_ct_trace_cortex_m_latency(
                spec, transcript_manifest=manifest_path,
                inventory_baseline=baseline)

    def test_cortex_m_latency_passes_with_both_markers(self) -> None:
        result = self._eval_vlat(self.VLAT_CLEAN, self.VLAT_REDIS)
        self.assertEqual(result["status"], "pass", result.get("failure_reason"))
        self.assertEqual(result["details"]["leaks_rediscovered"], "3/3")
        self.assertEqual(result["details"]["candidate_sites"], 1)

    def test_cortex_m_latency_fails_on_weak_or_missing_evidence(self) -> None:
        for clean, redis, base in (
            (self.VLAT_CLEAN.replace("fail_sites=0", "fail_sites=1"), self.VLAT_REDIS, 1),
            (self.VLAT_CLEAN.replace("base=clean", "base=diverged"), self.VLAT_REDIS, 1),
            (self.VLAT_CLEAN.replace("opt=debug", "opt=default"), self.VLAT_REDIS, 1),
            (self.VLAT_CLEAN.replace("regions=48", "regions=4"), self.VLAT_REDIS, 1),
            (self.VLAT_CLEAN, self.VLAT_REDIS, 0),  # inventory grew past baseline
            (self.VLAT_CLEAN, self.VLAT_REDIS.replace("leaks=3/3", "leaks=2/3"), 1),
            (self.VLAT_CLEAN, self.VLAT_REDIS.replace("benign_flagged=0/3", "benign_flagged=1/3"), 1),
            (self.VLAT_CLEAN, self.VLAT_REDIS.replace("PASS", "FAIL"), 1),
            (self.VLAT_CLEAN, "noise\n", 1),
        ):
            result = self._eval_vlat(clean, redis, base)
            self.assertEqual(result["status"], "fail", (clean, redis, base))

    M4_SIGN = "".join(
        f"PQCP_CT_TRACE_VLAT_DECLASS PASS alg=MLDSA-65 target=cortex-m4 "
        f"opt={opt} regions=18 segments=600 testable=546 violations=0 "
        "vdiv_violations=0 vmul_violations=0 other_violations=0 "
        "candidate_segments=370 attributed_sites=0\n"
        for opt in ("default", "speed", "debug")
    ) + "[ct-trace] PASS: every comparable segment is identical\n"
    M3_SIGN = "".join(
        f"PQCP_CT_TRACE_VLAT_DECLASS FAIL alg=MLDSA-65 target=cortex-m3 "
        f"opt={opt} regions=18 segments=600 testable=546 violations=370 "
        f"vdiv_violations=0 vmul_violations=370 other_violations=0 "
        f"candidate_segments=0 attributed_sites={n}\n"
        for opt, n in (("default", 8), ("speed", 12), ("debug", 4))
    ) + "[ct-trace] MEASURED: cortex-m3 signing leaks only through multiplies\n"

    def _eval_signing(self, m4: str, m3: str, sites=None) -> dict:
        sites = sites or {"default": 8, "speed": 12, "debug": 4}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            entries = []
            for step, body, name in (
                ("ct trace cortex-m4 signing", m4, "01.log"),
                ("ct trace cortex-m3 signing inventory", m3, "02.log"),
            ):
                (manifest_path.parent / name).write_text(body, encoding="utf-8")
                entries.append({
                    "step": step, "transcript_path": name,
                    "sha256": hashlib.sha256(body.encode()).hexdigest(),
                    "size_bytes": len(body.encode()), "returncode": 0})
            manifest_path.write_text(
                json.dumps({"schema_version": 1, "transcripts": entries}) + "\n",
                encoding="utf-8")
            baseline = root / "baseline.json"
            baseline.write_text(json.dumps({"m3_attributed_sites_max": sites}))
            spec = {"id": "security.ct_trace_cortex_m_signing",
                    "category": "security", "claim": "x", "required": True}
            return ledger.evaluate_ct_trace_cortex_m_signing(
                spec, transcript_manifest=manifest_path,
                signing_baseline=baseline)

    def test_cortex_m_signing_passes_and_records_inventory(self) -> None:
        result = self._eval_signing(self.M4_SIGN, self.M3_SIGN)
        self.assertEqual(result["status"], "pass", result.get("failure_reason"))
        self.assertEqual(result["details"]["m3_leaking_sites"]["speed"], 12)

    def test_cortex_m_signing_fails_on_weak_or_missing_evidence(self) -> None:
        shrunk = {"default": 8, "speed": 11, "debug": 4}
        for m4, m3, sites in (
            (self.M4_SIGN.replace("violations=0 vdiv", "violations=2 vdiv"), self.M3_SIGN, None),
            (self.M4_SIGN.replace("opt=debug", "opt=default"), self.M3_SIGN, None),
            (self.M4_SIGN.replace("testable=546", "testable=100"), self.M3_SIGN, None),
            (self.M4_SIGN.replace("PASS alg", "FAIL alg"), self.M3_SIGN, None),
            (self.M4_SIGN, self.M3_SIGN.replace("other_violations=0", "other_violations=3"), None),
            (self.M4_SIGN, self.M3_SIGN.replace("vdiv_violations=0", "vdiv_violations=1"), None),
            (self.M4_SIGN, self.M3_SIGN.replace("vmul_violations=370", "vmul_violations=0").replace("violations=370", "violations=0"), None),
            (self.M4_SIGN, self.M3_SIGN.replace("[ct-trace] MEASURED", "[ct-trace] noise"), None),
            (self.M4_SIGN, self.M3_SIGN, shrunk),  # site count above a shrunk baseline
            (self.M4_SIGN, "noise\n", None),
        ):
            result = self._eval_signing(m4, m3, sites)
            self.assertEqual(result["status"], "fail", (m4, m3, sites))

    MITIGATION_SELFTEST = "PQCP_MLDSA_FIXED_MUL_SELFTEST PASS products=20000676\n"
    MITIGATION = "".join(
        f"PQCP_CT_TRACE_VLAT_MITIGATION PASS alg=MLDSA-65 target=cortex-m3 "
        f"opt={opt} stock_vmul_violations=370 stock_sites=8 "
        f"patched_violations=0 patched_sites=0 patched_testable=546 "
        f"sig_digest_match=1 insn_overhead_pct={pct}\n"
        for opt, pct in (("default", 75.1), ("speed", 80.0), ("debug", 60.0))
    )

    def _eval_mitigation(self, selftest: str, body: str, ceiling=None) -> dict:
        ceiling = ceiling or {"default": 90.0, "speed": 95.0, "debug": 75.0}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            entries = []
            for step, text, name in (
                ("mldsa fixed-latency multiply selftest", selftest, "01.log"),
                ("ct trace cortex-m3 signing mitigation", body, "02.log"),
            ):
                (manifest_path.parent / name).write_text(text, encoding="utf-8")
                entries.append({
                    "step": step, "transcript_path": name,
                    "sha256": hashlib.sha256(text.encode()).hexdigest(),
                    "size_bytes": len(text.encode()), "returncode": 0})
            manifest_path.write_text(
                json.dumps({"schema_version": 1, "transcripts": entries}) + "\n",
                encoding="utf-8")
            baseline = root / "baseline.json"
            baseline.write_text(json.dumps({"insn_overhead_pct_max": ceiling}))
            spec = {"id": "security.ct_trace_cortex_m_mitigation",
                    "category": "security", "claim": "x", "required": True}
            return ledger.evaluate_ct_trace_cortex_m_mitigation(
                spec, transcript_manifest=manifest_path,
                mitigation_baseline=baseline)

    def test_cortex_m_mitigation_passes_and_records_overhead(self) -> None:
        result = self._eval_mitigation(self.MITIGATION_SELFTEST, self.MITIGATION)
        self.assertEqual(result["status"], "pass", result.get("failure_reason"))
        self.assertEqual(result["details"]["insn_overhead_pct"]["speed"], 80.0)

    def test_cortex_m_mitigation_fails_on_weak_or_missing_evidence(self) -> None:
        good, st = self.MITIGATION, self.MITIGATION_SELFTEST
        for selftest, body, ceiling in (
            (st, good.replace("patched_violations=0", "patched_violations=2"), None),
            (st, good.replace("patched_sites=0", "patched_sites=1"), None),
            (st, good.replace("stock_vmul_violations=370", "stock_vmul_violations=0"), None),
            (st, good.replace("stock_sites=8", "stock_sites=0"), None),
            (st, good.replace("sig_digest_match=1", "sig_digest_match=0"), None),
            (st, good.replace("patched_testable=546", "patched_testable=100"), None),
            (st, good.replace("opt=debug", "opt=default"), None),
            (st, good.replace("PASS alg", "FAIL alg"), None),
            (st, good, {"default": 70.0, "speed": 95.0, "debug": 75.0}),
            (st, "noise\n", None),
            ("noise\n", good, None),
            ("PQCP_MLDSA_FIXED_MUL_SELFTEST PASS products=10\n", good, None),
        ):
            result = self._eval_mitigation(selftest, body, ceiling)
            self.assertEqual(result["status"], "fail", (selftest, body, ceiling))

    MODELS_CROSS = "PQCP_CT_LATENCY_MODEL_CROSSCHECK PASS cases=315678\n"
    MODELS_KEM = "".join(
        f"PQCP_CT_TRACE_LATENCY_MODELS alg=MLKEM-768 target=cortex-m3 "
        f"opt={opt} documented_sites=0 cmemu_sites=1 both=0 "
        "documented_only=0 cmemu_only=1 "
        "cmemu_only_functions=mlk_poly_compress_d10_c\n"
        for opt in ("default", "speed", "debug"))
    MODELS_DSA = "".join(
        f"PQCP_CT_TRACE_LATENCY_MODELS alg=MLDSA-65 target=cortex-m3 "
        f"opt={opt}-stock documented_sites={n} cmemu_sites={n} both={n} "
        f"documented_only=0 cmemu_only=0 doc_violations=370 "
        f"cmemu_violations=370 cmemu_only_functions=none\n"
        f"PQCP_CT_TRACE_LATENCY_MODELS alg=MLDSA-65 target=cortex-m3 "
        f"opt={opt}-patched documented_sites=0 cmemu_sites=0 both=0 "
        f"documented_only=0 cmemu_only=0 doc_violations=0 "
        f"cmemu_violations=0 cmemu_only_functions=none\n"
        for opt, n in (("default", 8), ("speed", 12), ("debug", 4)))

    def _eval_models(self, cross: str, kem: str, dsa: str, only=None) -> dict:
        only = only or {"default": 1, "speed": 1, "debug": 1}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            entries = []
            for step, text, name in (
                ("ct latency model crosscheck", cross, "01.log"),
                ("ct trace cortex-m latency", kem, "02.log"),
                ("ct trace cortex-m3 signing mitigation", dsa, "03.log"),
            ):
                (manifest_path.parent / name).write_text(text, encoding="utf-8")
                entries.append({
                    "step": step, "transcript_path": name,
                    "sha256": hashlib.sha256(text.encode()).hexdigest(),
                    "size_bytes": len(text.encode()), "returncode": 0})
            manifest_path.write_text(
                json.dumps({"schema_version": 1, "transcripts": entries}) + "\n",
                encoding="utf-8")
            baseline = root / "baseline.json"
            baseline.write_text(json.dumps({"mlkem_cmemu_only_max": only}))
            spec = {"id": "security.ct_trace_cortex_m_latency_models",
                    "category": "security", "claim": "x", "required": True}
            return ledger.evaluate_ct_trace_cortex_m_latency_models(
                spec, transcript_manifest=manifest_path,
                models_baseline=baseline)

    def test_latency_models_passes_and_records_the_disagreement(self) -> None:
        result = self._eval_models(self.MODELS_CROSS, self.MODELS_KEM,
                                   self.MODELS_DSA)
        self.assertEqual(result["status"], "pass", result.get("failure_reason"))
        self.assertEqual(result["details"]["mlkem_cmemu_only_sites"]["debug"], 1)

    def test_latency_models_fails_on_weak_or_missing_evidence(self) -> None:
        c, k, d = self.MODELS_CROSS, self.MODELS_KEM, self.MODELS_DSA
        for cross, kem, dsa, only in (
            (c.replace("315678", "10"), k, d, None),
            ("noise\n", k, d, None),
            (c, k.replace("opt=debug", "opt=default"), d, None),
            (c, k.replace("cmemu_only=1", "cmemu_only=2"), d, None),
            (c, k, d.replace("opt=speed-patched documented_sites=0 cmemu_sites=0",
                             "opt=speed-patched documented_sites=0 cmemu_sites=1"), None),
            (c, k, d.replace("cmemu_violations=0", "cmemu_violations=3"), None),
            (c, k, d.replace("doc_violations=0", "doc_violations=3"), None),
            (c, k, d.replace("opt=debug-stock documented_sites=4 cmemu_sites=4",
                             "opt=debug-stock documented_sites=4 cmemu_sites=0"), None),
            (c, k, "noise\n", None),
            (c, k, d, {"default": 0, "speed": 1, "debug": 1}),  # shrunk baseline
        ):
            result = self._eval_models(cross, kem, dsa, only)
            self.assertEqual(result["status"], "fail", (cross, kem, dsa, only))

    KEM_SELFTEST = ("PQCP_MLKEM_FIXED_LATENCY_SELFTEST PASS domain=3329 "
                    "stock_cmemu_classes=2 fixed_cmemu_classes=1 variants=2\n")
    KEM_FIX = "".join(
        f"PQCP_CT_TRACE_VLAT_MITIGATION_KEM PASS alg=MLKEM-{lv} "
        f"target=cortex-m3 opt={opt} stock_cmemu_only=1 "
        f"patched_documented_sites=0 patched_cmemu_sites=0 "
        f"ss_digest_match=1 insn_overhead_pct={pct}\n"
        for lv in (512, 768, 1024)
        for opt, pct in (("default", 0.03), ("speed", 0.06), ("debug", 0.12))
    ) + "".join(
        f"PQCP_CT_TRACE_MODELLED_CYCLES alg=MLKEM-{lv} target=cortex-m3 "
        f"opt={opt}-{variant} groups=8 max_spread={sp} distinct_totals=2 "
        f"variable_cycles_min=100 variable_cycles_max=101 insns_min=1000000 "
        f"relative_amplitude=1.00e-06\n"
        for lv in (512, 768, 1024) for opt in ("default", "speed", "debug")
        for variant, sp in (("stock", 1), ("patched", 0)))

    def _eval_kem(self, selftest: str, body: str, ceiling=None) -> dict:
        ceiling = ceiling or {"default": 0.1, "speed": 0.2, "debug": 0.3}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            entries = []
            for step, text, name in (
                ("mlkem fixed-latency selftest", selftest, "01.log"),
                ("ct trace cortex-m3 kem mitigation", body, "02.log"),
            ):
                (manifest_path.parent / name).write_text(text, encoding="utf-8")
                entries.append({
                    "step": step, "transcript_path": name,
                    "sha256": hashlib.sha256(text.encode()).hexdigest(),
                    "size_bytes": len(text.encode()), "returncode": 0})
            manifest_path.write_text(
                json.dumps({"schema_version": 1, "transcripts": entries}) + "\n",
                encoding="utf-8")
            baseline = root / "baseline.json"
            baseline.write_text(json.dumps({"insn_overhead_pct_max": ceiling}))
            spec = {"id": "security.ct_trace_cortex_m_kem_mitigation",
                    "category": "security", "claim": "x", "required": True}
            return ledger.evaluate_ct_trace_cortex_m_kem_mitigation(
                spec, transcript_manifest=manifest_path, kem_baseline=baseline)

    def test_kem_mitigation_passes_and_records_overhead(self) -> None:
        result = self._eval_kem(self.KEM_SELFTEST, self.KEM_FIX)
        self.assertEqual(result["status"], "pass", result.get("failure_reason"))
        self.assertEqual(
            result["details"]["insn_overhead_pct"]["MLKEM-1024/debug"], 0.12)

    def test_kem_mitigation_fails_on_weak_or_missing_evidence(self) -> None:
        st, g = self.KEM_SELFTEST, self.KEM_FIX
        for selftest, body, ceiling in (
            (st.replace("3329", "100"), g, None),
            (st.replace("stock_cmemu_classes=2", "stock_cmemu_classes=1"), g, None),
            ("noise\n", g, None),
            (st, g.replace("patched_cmemu_sites=0", "patched_cmemu_sites=1"), None),
            (st, g.replace("patched_documented_sites=0", "patched_documented_sites=2"), None),
            (st, g.replace("stock_cmemu_only=1", "stock_cmemu_only=0"), None),
            (st, g.replace("ss_digest_match=1", "ss_digest_match=0"), None),
            (st, g.replace("alg=MLKEM-1024", "alg=MLKEM-768"), None),
            (st, g.replace("opt=default-patched groups=8 max_spread=0", "opt=default-patched groups=8 max_spread=1"), None),
            (st, g.replace("opt=default-stock groups=8 max_spread=1", "opt=default-stock groups=8 max_spread=0"), None),
            (st, g.replace("max_spread=1 distinct", "max_spread=12 distinct"), None),
            (st, "\n".join(l for l in g.splitlines() if "MODELLED" not in l) + "\n", None),
            (st, g.replace("PASS alg", "FAIL alg"), None),
            (st.replace(" variants=2", ""), g, None),
            (st, "noise\n", None),
            (st, g, {"default": 0.01, "speed": 0.2, "debug": 0.3}),
        ):
            result = self._eval_kem(selftest, body, ceiling)
            self.assertEqual(result["status"], "fail", (selftest, body, ceiling))

    REJ_SELF = "PQCP_MLDSA_REJECTION_SELFTEST PASS p_same=0.299 p_diff=0\n"
    REJ_STUDY = ("PQCP_MLDSA_REJECTION_STUDY CONSISTENT_WITH_INDEPENDENT "
                 "keys=60 msgs=3000 pooled_mean=5.1443 key_mean_sd=0.1 "
                 "relative_sd=0.0194 chi2=1500.0 dof=1500 p=0.4 r_s1=0.05 "
                 "r_s2=0.0 r_t0=0.1\n")

    def _eval_rej(self, selftest: str, study: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            entries = []
            for step, text, name in (
                ("mldsa rejection selftest", selftest, "01.log"),
                ("mldsa rejection study", study, "02.log"),
            ):
                (manifest_path.parent / name).write_text(text, encoding="utf-8")
                entries.append({
                    "step": step, "transcript_path": name,
                    "sha256": hashlib.sha256(text.encode()).hexdigest(),
                    "size_bytes": len(text.encode()), "returncode": 0})
            manifest_path.write_text(
                json.dumps({"schema_version": 1, "transcripts": entries}) + "\n",
                encoding="utf-8")
            spec = {"id": "security.mldsa_rejection_independence",
                    "category": "security", "claim": "x", "required": True}
            return ledger.evaluate_mldsa_rejection_independence(
                spec, transcript_manifest=manifest_path)

    def test_rejection_study_passes(self) -> None:
        result = self._eval_rej(self.REJ_SELF, self.REJ_STUDY)
        self.assertEqual(result["status"], "pass", result.get("failure_reason"))
        self.assertEqual(result["details"]["keys"], 60)

    def test_rejection_study_fails_on_weak_or_dependent_evidence(self) -> None:
        st = self.REJ_STUDY
        for selftest, study in (
            ("noise\n", st),
            (self.REJ_SELF, "noise\n"),
            (self.REJ_SELF, st.replace("CONSISTENT_WITH_INDEPENDENT", "DEPENDENT")),
            (self.REJ_SELF, st.replace("p=0.4", "p=0.0001")),
            (self.REJ_SELF, st.replace("keys=60", "keys=5")),
            (self.REJ_SELF, st.replace("msgs=3000", "msgs=100")),
            (self.REJ_SELF, st.replace("dof=1500", "dof=10")),
            (self.REJ_SELF, st.replace("pooled_mean=5.1443", "pooled_mean=2.0")),
            (self.REJ_SELF, st.replace("relative_sd=0.0194", "relative_sd=0.2")),
        ):
            result = self._eval_rej(selftest, study)
            self.assertEqual(result["status"], "fail", (selftest, study))

    M33_KEM = "".join(
        f"PQCP_CT_TRACE_VLAT PASS alg=MLKEM-768 target=cortex-m33 opt={o} "
        "regions=48 sites=1 div_sites=0 mul_sites=1 fail_sites=0 "
        "candidate_sites=1 base=clean\n" for o in ("default", "speed", "debug"))
    M33_DSA = "".join(
        f"PQCP_CT_TRACE_VLAT_DECLASS PASS alg=MLDSA-65 target=cortex-m33 "
        f"opt={o} regions=18 segments=600 testable=546 violations=0 "
        "vdiv_violations=0 vmul_violations=0 other_violations=0 "
        "candidate_segments=370 attributed_sites=0\n"
        for o in ("default", "speed", "debug"))

    def _eval_m33(self, kem: str, dsa: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            entries = []
            for step, text, name in (
                ("ct trace cortex-m33 decapsulation", kem, "01.log"),
                ("ct trace cortex-m33 signing", dsa, "02.log"),
            ):
                (manifest_path.parent / name).write_text(text, encoding="utf-8")
                entries.append({
                    "step": step, "transcript_path": name,
                    "sha256": hashlib.sha256(text.encode()).hexdigest(),
                    "size_bytes": len(text.encode()), "returncode": 0})
            manifest_path.write_text(
                json.dumps({"schema_version": 1, "transcripts": entries}) + "\n",
                encoding="utf-8")
            spec = {"id": "security.ct_trace_cortex_m33",
                    "category": "security", "claim": "x", "required": True}
            return ledger.evaluate_ct_trace_cortex_m33(
                spec, transcript_manifest=manifest_path)

    def test_cortex_m33_passes_and_fails(self) -> None:
        ok = self._eval_m33(self.M33_KEM, self.M33_DSA)
        self.assertEqual(ok["status"], "pass", ok.get("failure_reason"))
        for kem, dsa in (
            (self.M33_KEM.replace("fail_sites=0", "fail_sites=1"), self.M33_DSA),
            (self.M33_KEM.replace("opt=debug", "opt=default"), self.M33_DSA),
            (self.M33_KEM, self.M33_DSA.replace("violations=0 vdiv", "violations=2 vdiv")),
            (self.M33_KEM, self.M33_DSA.replace("testable=546", "testable=100")),
            (self.M33_KEM, self.M33_DSA.replace("cortex-m33", "cortex-m4")),
            ("noise\n", self.M33_DSA),
            (self.M33_KEM, "noise\n"),
        ):
            self.assertEqual(self._eval_m33(kem, dsa)["status"], "fail", (kem, dsa))

    RES_BODY = "".join(
        f"PQCP_CT_TRACE_RESIDUE_VERIFY PASS alg={a} target=cortex-m4 opt={o} "
        f"stock_ss_hits={320 if a == 'MLKEM-768' else 0} scrub_ss_hits=0 "
        f"stock_nonzero=300 scrub_nonzero=100 scrub_violations=0 "
        f"insn_overhead_pct=1.25\n"
        for a in ("MLKEM-768", "MLDSA-65") for o in ("default", "speed", "debug"))

    def _eval_res(self, body: str, ceiling: float = 3.0) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            (manifest_path.parent / "01.log").write_text(body, encoding="utf-8")
            manifest_path.write_text(json.dumps({"schema_version": 1, "transcripts": [{
                "step": "ct residue stack wipe cortex-m4", "transcript_path": "01.log",
                "sha256": hashlib.sha256(body.encode()).hexdigest(),
                "size_bytes": len(body.encode()), "returncode": 0}]}) + "\n",
                encoding="utf-8")
            base = root / "baseline.json"
            base.write_text(json.dumps({"insn_overhead_pct_max": ceiling}))
            spec = {"id": "security.ct_residue_scrub", "category": "security",
                    "claim": "x", "required": True}
            return ledger.evaluate_ct_residue_scrub(
                spec, transcript_manifest=manifest_path, baseline=base)

    def test_residue_scrub_passes_and_fails(self) -> None:
        ok = self._eval_res(self.RES_BODY)
        self.assertEqual(ok["status"], "pass", ok.get("failure_reason"))
        b = self.RES_BODY
        for body, ceiling in (
            (b.replace("scrub_ss_hits=0", "scrub_ss_hits=8", 1), 3.0),
            (b.replace("stock_ss_hits=320", "stock_ss_hits=0"), 3.0),
            (b.replace("scrub_nonzero=100", "scrub_nonzero=200", 1), 3.0),
            (b.replace("stock_nonzero=300", "stock_nonzero=50", 1), 3.0),
            (b.replace("scrub_violations=0", "scrub_violations=2", 1), 3.0),
            (b.replace("opt=debug", "opt=default"), 3.0),
            (b.replace("PASS alg", "FAIL alg", 1), 3.0),
            (b, 1.0),
            ("noise\n", 3.0),
        ):
            self.assertEqual(self._eval_res(body, ceiling)["status"], "fail",
                             (body[:80], ceiling))

    FAULT_BODY = (
        "PQCP_FAULT_CAMPAIGN variant=boot sites=388 kem_fo_bypass=3 "
        "sig_verify_bypass=5 detected_boot=111 fail_safe=1 corrupt=16 "
        "no_effect=117 crash=133 timeout=2 controls_ok=6/6\n"
        "PQCP_FAULT_CAMPAIGN variant=boot-negative sites=388 kem_fo_bypass=0 "
        "sig_verify_bypass=0 detected_boot=121 fail_safe=1 corrupt=15 "
        "no_effect=117 crash=132 timeout=2 controls_ok=6/6\n"
        "PQCP_FAULT_GATE PASS sites=388 exploitable_boot=8 "
        "exploitable_boot_negative=0 detected_boot=111 "
        "detected_boot_negative=121\n"
    )

    def _eval_fault(self, body: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "transcripts" / "evidence_transcript_manifest.json"
            manifest.parent.mkdir(parents=True)
            (manifest.parent / "01-fault.log").write_text(body, encoding="utf-8")
            manifest.write_text(json.dumps({"schema_version": 1, "transcripts": [{
                "step": "fault campaign", "transcript_path": "01-fault.log",
                "sha256": hashlib.sha256(body.encode()).hexdigest(),
                "size_bytes": len(body.encode()), "returncode": 0}]}) + "\n",
                encoding="utf-8")
            spec = {"id": "security.fault_campaign_boot_selftest",
                    "category": "security", "claim": "x", "required": True}
            return ledger.evaluate_fault_campaign_boot_selftest(
                spec, transcript_manifest=manifest)

    def test_fault_campaign_passes_with_calibrated_measured_gate(self) -> None:
        result = self._eval_fault(self.FAULT_BODY)
        self.assertEqual(result["status"], "pass", result.get("failure_reason"))
        self.assertEqual(result["details"]["exploitable_negative_boot"], 0)

    def test_fault_campaign_fails_when_weakened(self) -> None:
        for body in (
            self.FAULT_BODY.replace("exploitable_boot_negative=0", "exploitable_boot_negative=1"),
            self.FAULT_BODY.replace("exploitable_boot=8", "exploitable_boot=0"),
            self.FAULT_BODY.replace("sites=388 exploitable", "sites=20 exploitable"),
            self.FAULT_BODY.replace("detected_boot_negative=121", "detected_boot_negative=111"),
            self.FAULT_BODY.replace("controls_ok=6/6", "controls_ok=5/6"),
            self.FAULT_BODY.replace("PASS", "FAIL"),
            "noise\n",
        ):
            self.assertEqual(self._eval_fault(body)["status"], "fail", body[-120:])

    TIMING_BODY = "".join(
        f"PQCP_FAULT_CAMPAIGN variant={v} sites={n} kem_fo_bypass={k} "
        f"sig_verify_bypass={g} detected_boot=0 detected_runtime=5 "
        f"fail_safe=1 corrupt=2 no_effect=100 crash=100 timeout=2 "
        f"harness_error=0 controls_ok=6/6 timing={t} exploitable_sites={e}\n"
        for v, t, n, k, g, e in (
            ("boot-negative", "post-boot", 350, 3, 6, 9),
            ("hardened", "post-boot", 593, 0, 0, 0),
            ("boot-negative", "transient", 932, 5, 17, 9),
            ("hardened", "transient", 1530, 0, 0, 0))
    ) + ("PQCP_FAULT_TIMING_GATE PASS sites_postboot=593 sites_transient=1530 "
         "base_postboot=9 base_transient=9 hardened_postboot=0 "
         "hardened_transient=0\n")

    def _eval_timing(self, body: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "transcripts" / "evidence_transcript_manifest.json"
            manifest.parent.mkdir(parents=True)
            (manifest.parent / "01-timing.log").write_text(body, encoding="utf-8")
            manifest.write_text(json.dumps({"schema_version": 1, "transcripts": [{
                "step": "fault timing campaign", "transcript_path": "01-timing.log",
                "sha256": hashlib.sha256(body.encode()).hexdigest(),
                "size_bytes": len(body.encode()), "returncode": 0}]}) + "\n",
                encoding="utf-8")
            spec = {"id": "security.fault_timing_countermeasure",
                    "category": "security", "claim": "x", "required": True}
            return ledger.evaluate_fault_timing_countermeasure(
                spec, transcript_manifest=manifest)

    def test_fault_timing_passes_with_measured_ablation(self) -> None:
        result = self._eval_timing(self.TIMING_BODY)
        self.assertEqual(result["status"], "pass", result.get("failure_reason"))
        self.assertEqual(result["details"]["hardened_exploitable_transient"], 0)

    def test_fault_timing_fails_when_weakened(self) -> None:
        for body in (
            self.TIMING_BODY.replace("hardened_transient=0\n", "hardened_transient=1\n"),
            self.TIMING_BODY.replace("hardened_postboot=0 ", "hardened_postboot=2 "),
            self.TIMING_BODY.replace("base_transient=9", "base_transient=0"),
            self.TIMING_BODY.replace("base_postboot=9", "base_postboot=0"),
            self.TIMING_BODY.replace("sites_transient=1530", "sites_transient=20"),
            self.TIMING_BODY.replace("harness_error=0", "harness_error=3", 1),
            self.TIMING_BODY.replace("controls_ok=6/6", "controls_ok=4/6", 1),
            self.TIMING_BODY.replace("timing=transient", "timing=post-boot"),
            self.TIMING_BODY.replace("PASS", "FAIL"),
            "noise\n",
        ):
            self.assertEqual(self._eval_timing(body)["status"], "fail", body[-110:])

    def _write_fuzz_transcript(self, root: Path, body: str) -> Path:
        manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path = manifest_path.parent / "01-evidence-fuzz.log"
        transcript_path.write_text(body, encoding="utf-8")
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "generated_at": "2026-06-10T00:00:00+00:00",
                    "generator": "scripts/release_check.py",
                    "required_steps": ["evidence parser fuzz"],
                    "transcripts": [
                        {
                            "step": "evidence parser fuzz",
                            "command": ["true"],
                            "command_text": "true",
                            "cwd": str(root),
                            "returncode": 0,
                            "duration_seconds": 0.1,
                            "transcript_path": transcript_path.name,
                            "sha256": sha256(transcript_path),
                            "size_bytes": transcript_path.stat().st_size,
                        }
                    ],
                    "qemu_stdout_transcripts": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return manifest_path

    FUZZ_ACCEPTED = (
        "PQCP_FUZZ BINARY_ACCEPTED cbor=4454 cose_sign1=1494 cose_key=2340 "
        "policy=2424 policy_verified=143 policy_vm_decided=73\n"
    )
    FUZZ_AGGREGATE = (
        "[fuzz] PASS: 1 campaign(s) x 200000 iterations, no sanitizer findings\n"
    )

    def _fuzz_spec(self) -> dict:
        return {
            "id": "security.evidence_parser_fuzzed",
            "category": "security",
            "claim": "x",
            "required": True,
        }

    def test_evidence_parser_fuzzed_passes_with_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                self.FUZZ_ACCEPTED
                + "PQCP_FUZZ PASS targets=10 corpus_lines=247 evolved=183 "
                "binary_seeds=80 binary_evolved=188 edges_covered=1391 "
                "edge_guards=4037 iterations=200000 seed=0x1\n"
                + self.FUZZ_ACCEPTED
                + "PQCP_FUZZ PASS targets=10 corpus_lines=247 evolved=186 "
                "binary_seeds=80 binary_evolved=182 edges_covered=1381 "
                "edge_guards=4037 iterations=200000 seed=0xdeadbeef\n"
                "[fuzz] PASS: 2 campaign(s) x 200000 iterations, no sanitizer findings\n"
            )
            manifest = self._write_fuzz_transcript(root, body)
            result = ledger.evaluate_evidence_parser_fuzzed(
                self._fuzz_spec(), transcript_manifest=manifest
            )
            self.assertEqual(result["status"], "pass", result.get("failure_reason"))
            self.assertEqual(result["details"]["fuzz_pass_markers"], 2)
            self.assertEqual(result["details"]["fuzz_target_counts"], [10, 10])

    def test_evidence_parser_fuzzed_fails_without_aggregate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                self.FUZZ_ACCEPTED
                + "PQCP_FUZZ PASS targets=10 iterations=200000 seed=0x1\n"
            )
            manifest = self._write_fuzz_transcript(root, body)
            result = ledger.evaluate_evidence_parser_fuzzed(
                self._fuzz_spec(), transcript_manifest=manifest
            )
            self.assertEqual(result["status"], "fail")

    def test_evidence_parser_fuzzed_fails_when_targets_dropped(self) -> None:
        for marker in (
            "PQCP_FUZZ PASS targets=6 iterations=200000 seed=0x1\n",
            "PQCP_FUZZ PASS iterations=200000 seed=0x1\n",
        ):
            with tempfile.TemporaryDirectory() as tmp:
                manifest = self._write_fuzz_transcript(
                    Path(tmp),
                    self.FUZZ_ACCEPTED + marker + self.FUZZ_AGGREGATE,
                )
                result = ledger.evaluate_evidence_parser_fuzzed(
                    self._fuzz_spec(), transcript_manifest=manifest
                )
                self.assertEqual(result["status"], "fail", marker)
                self.assertIn("targets>=10", result["failure_reason"])

    def test_evidence_parser_fuzzed_fails_without_binary_acceptance(self) -> None:
        marker = "PQCP_FUZZ PASS targets=10 iterations=200000 seed=0x1\n"
        zero = (
            "PQCP_FUZZ BINARY_ACCEPTED cbor=10 cose_sign1=0 cose_key=5 "
            "policy=3 policy_verified=3 policy_vm_decided=2\n"
        )
        for accepted in ("", zero):
            with tempfile.TemporaryDirectory() as tmp:
                manifest = self._write_fuzz_transcript(
                    Path(tmp), accepted + marker + self.FUZZ_AGGREGATE
                )
                result = ledger.evaluate_evidence_parser_fuzzed(
                    self._fuzz_spec(), transcript_manifest=manifest
                )
                self.assertEqual(result["status"], "fail")
                self.assertIn("BINARY_ACCEPTED", result["failure_reason"])

    def _write_coverage_transcript(self, root: Path, body: str) -> Path:
        manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path = manifest_path.parent / "01-evidence-coverage.log"
        transcript_path.write_text(body, encoding="utf-8")
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "generated_at": "2026-11-17T00:00:00+00:00",
                    "generator": "scripts/release_check.py",
                    "required_steps": ["evidence coverage audit"],
                    "transcripts": [
                        {
                            "step": "evidence coverage audit",
                            "command": ["true"],
                            "command_text": "true",
                            "cwd": str(root),
                            "returncode": 0,
                            "duration_seconds": 0.1,
                            "transcript_path": transcript_path.name,
                            "sha256": sha256(transcript_path),
                            "size_bytes": transcript_path.stat().st_size,
                        }
                    ],
                    "qemu_stdout_transcripts": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return manifest_path

    _COVERAGE_SPEC = {
        "id": "release.evidence_coverage_ratchet",
        "category": "release",
        "claim": "x",
        "required": True,
    }

    def test_evidence_coverage_ratchet_passes_and_records_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            body = (
                "PQCP_EVIDENCE_COVERAGE PASS modules=350 L0=225 L1=76 "
                "L2=34 L3=15 new_untested=0 regressions=0\n"
                "[coverage] PASS: no module lost evidence and no new "
                "module is untested\n"
            )
            manifest = self._write_coverage_transcript(Path(tmp), body)
            result = ledger.evaluate_evidence_coverage_ratchet(
                dict(self._COVERAGE_SPEC), transcript_manifest=manifest)
            self.assertEqual(result["status"], "pass", result.get("failure_reason"))
            self.assertEqual(result["details"]["L0_untested"], 225)
            self.assertEqual(result["details"]["modules"], 350)

    def test_evidence_coverage_ratchet_fails_on_violation_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            body = (
                "[coverage] REGRESSION runtime_lease: L1 -> L0\n"
                "[coverage] FAIL: evidence coverage ratchet violated\n"
            )
            manifest = self._write_coverage_transcript(Path(tmp), body)
            result = ledger.evaluate_evidence_coverage_ratchet(
                dict(self._COVERAGE_SPEC), transcript_manifest=manifest)
            self.assertEqual(result["status"], "fail")
            self.assertIn("PQCP_EVIDENCE_COVERAGE PASS", result["failure_reason"])

    def test_evidence_coverage_ratchet_rejects_inconsistent_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            body = (
                "PQCP_EVIDENCE_COVERAGE PASS modules=350 L0=1 L1=1 "
                "L2=1 L3=1 new_untested=0 regressions=0\n"
                "[coverage] PASS: ok\n"
            )
            manifest = self._write_coverage_transcript(Path(tmp), body)
            result = ledger.evaluate_evidence_coverage_ratchet(
                dict(self._COVERAGE_SPEC), transcript_manifest=manifest)
            self.assertEqual(result["status"], "fail")
            self.assertIn("sum", result["failure_reason"])

    def test_evidence_coverage_ratchet_fails_without_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "transcripts" / "evidence_transcript_manifest.json"
            result = ledger.evaluate_evidence_coverage_ratchet(
                dict(self._COVERAGE_SPEC), transcript_manifest=manifest)
            self.assertEqual(result["status"], "fail")
            self.assertIn("missing or empty", result["failure_reason"])

    def _write_appraisal_transcript(self, root: Path, body: str) -> Path:
        manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path = manifest_path.parent / "01-transparent-appraisal.log"
        transcript_path.write_text(body, encoding="utf-8")
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "generated_at": "2026-11-18T00:00:00+00:00",
                    "generator": "scripts/release_check.py",
                    "required_steps": ["transparent appraisal receipt"],
                    "transcripts": [
                        {
                            "step": "transparent appraisal receipt",
                            "command": ["true"],
                            "command_text": "true",
                            "cwd": str(root),
                            "returncode": 0,
                            "duration_seconds": 0.1,
                            "transcript_path": transcript_path.name,
                            "sha256": sha256(transcript_path),
                            "size_bytes": transcript_path.stat().st_size,
                        }
                    ],
                    "qemu_stdout_transcripts": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return manifest_path

    _APPRAISAL_SPEC = {
        "id": "supply_chain.transparent_appraisal_receipt",
        "category": "supply_chain",
        "claim": "x",
        "required": True,
    }

    def _appraisal_marker(self, diff: str = "169/169", forgeries: str = "156/156",
                          controls: str = "11/11") -> str:
        return (
            "PQCP_APPRAISAL_RECEIPT PASS consistency=ok "
            f"differential_agree={diff} forgeries_rejected={forgeries} "
            f"controls={controls}\n"
        )

    def _evaluate_appraisal(self, body: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = self._write_appraisal_transcript(Path(tmp), body)
            return ledger.evaluate_transparent_appraisal_receipt(
                dict(self._APPRAISAL_SPEC), transcript_manifest=manifest)

    def test_transparent_appraisal_receipt_passes_and_records_counts(self) -> None:
        result = self._evaluate_appraisal(self._appraisal_marker())
        self.assertEqual(result["status"], "pass", result.get("failure_reason"))
        self.assertEqual(result["details"]["forgeries_rejected"], 156)
        self.assertEqual(result["details"]["differential_total"], 169)
        self.assertEqual(result["details"]["controls_ok"], 11)

    def test_transparent_appraisal_receipt_fails_on_short_forgery_count(self) -> None:
        result = self._evaluate_appraisal(
            self._appraisal_marker(forgeries="150/150"))
        self.assertEqual(result["status"], "fail")
        self.assertIn("forgery list has 150", result["failure_reason"])

    def test_transparent_appraisal_receipt_fails_on_unrejected_forgery(self) -> None:
        result = self._evaluate_appraisal(
            self._appraisal_marker(forgeries="155/156"))
        self.assertEqual(result["status"], "fail")
        self.assertIn("not all rejected", result["failure_reason"])

    def test_transparent_appraisal_receipt_fails_on_missing_differential(self) -> None:
        body = (
            "PQCP_APPRAISAL_RECEIPT PASS consistency=ok "
            "forgeries_rejected=156/156 controls=11/11\n"
        )
        result = self._evaluate_appraisal(body)
        self.assertEqual(result["status"], "fail")
        self.assertIn("differential_agree=N/N", result["failure_reason"])

    def test_transparent_appraisal_receipt_fails_on_differential_disagreement(
            self) -> None:
        result = self._evaluate_appraisal(
            self._appraisal_marker(diff="168/169"))
        self.assertEqual(result["status"], "fail")
        self.assertIn("differential disagreement", result["failure_reason"])

    def test_transparent_appraisal_receipt_fails_on_shrunk_differential(self) -> None:
        result = self._evaluate_appraisal(
            self._appraisal_marker(diff="100/100"))
        self.assertEqual(result["status"], "fail")
        self.assertIn("differential covers 100", result["failure_reason"])

    def test_transparent_appraisal_receipt_fails_without_controls(self) -> None:
        result = self._evaluate_appraisal(
            self._appraisal_marker(controls="0/0"))
        self.assertEqual(result["status"], "fail")
        self.assertIn("positive controls", result["failure_reason"])

    def test_transparent_appraisal_receipt_fails_on_driver_fail_marker(self) -> None:
        result = self._evaluate_appraisal(
            "PQCP_APPRAISAL_RECEIPT FAIL consistency=ok "
            "differential_agree=167/169 forgeries_rejected=153/156 "
            "controls=11/11\n")
        self.assertEqual(result["status"], "fail")

    def test_transparent_appraisal_receipt_fails_without_consistency_ok(self) -> None:
        body = self._appraisal_marker().replace("consistency=ok ", "")
        result = self._evaluate_appraisal(body)
        self.assertEqual(result["status"], "fail")

    def test_transparent_appraisal_receipt_fails_without_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "transcripts" / "evidence_transcript_manifest.json"
            result = ledger.evaluate_transparent_appraisal_receipt(
                dict(self._APPRAISAL_SPEC), transcript_manifest=manifest)
            self.assertEqual(result["status"], "fail")
            self.assertIn("missing or empty", result["failure_reason"])

    def _write_model_transcript(self, root: Path, body: str) -> Path:
        manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path = manifest_path.parent / "01-edge-model.log"
        transcript_path.write_text(body, encoding="utf-8")
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "generated_at": "2026-11-18T00:00:00+00:00",
                    "generator": "scripts/release_check.py",
                    "required_steps": ["edge model conformance"],
                    "transcripts": [
                        {
                            "step": "edge model conformance",
                            "command": ["true"],
                            "command_text": "true",
                            "cwd": str(root),
                            "returncode": 0,
                            "duration_seconds": 0.1,
                            "transcript_path": transcript_path.name,
                            "sha256": sha256(transcript_path),
                            "size_bytes": transcript_path.stat().st_size,
                        }
                    ],
                    "qemu_stdout_transcripts": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return manifest_path

    _MODEL_SPEC = {
        "id": "security.state_machine_model_conformance",
        "category": "security",
        "claim": "x",
        "required": True,
    }
    _MODEL_MODULES = ("principal", "session", "credential", "policy")

    def _model_body(self, *, seeds: int = 64, ops: int = 1000,
                    violations: int = 0, summary_violations: int = 0,
                    cex: str = "", rediscovered: int = 8, allowed: int = 2,
                    total: int = 10, marker: str | None = None,
                    defect_statuses: list[str] | None = None,
                    summary: bool = True) -> str:
        lines = []
        for module in self._MODEL_MODULES:
            status = "PASS" if violations == 0 else "FAIL"
            lines.append(
                f"PQCP_MODEL_CHECK module={module} seeds={seeds} ops={ops} "
                f"violations={violations} status={status}")
        if cex:
            lines.append(cex)
        if summary:
            lines.append(
                f"PQCP_MODEL_SUMMARY modules=4 traces={4 * seeds} "
                f"ops={4 * ops} violations={summary_violations} "
                f"status={'PASS' if summary_violations == 0 else 'FAIL'}")
        lines.append("PROJECT EXECUTION SUCCESSFUL")
        if defect_statuses is None:
            defect_statuses = (["rediscovered"] * rediscovered +
                               ["allowed"] * allowed)
        for index, status in enumerate(defect_statuses):
            lines.append(
                f"PQCP_MODEL_DEFECT id=H{index + 1} module=policy "
                f"status={status}")
        if marker is None:
            marker = (f"PQCP_MODEL_REDISCOVERY PASS "
                      f"rediscovered={rediscovered}/{total} allowed={allowed}")
        if marker:
            lines.append(marker)
        return "\n".join(lines) + "\n"

    def _evaluate_model(self, body: str, *, minimum: int = 8,
                        total: int | None = 10) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = self._write_model_transcript(root, body)
            baseline = root / "baseline.json"
            data = {"rediscovered_min": minimum}
            if total is not None:
                data["defects_total"] = total
            baseline.write_text(json.dumps(data), encoding="utf-8")
            return ledger.evaluate_state_machine_model_conformance(
                dict(self._MODEL_SPEC), transcript_manifest=manifest,
                baseline_path=baseline)

    def test_state_machine_model_conformance_passes_and_records_counts(self) -> None:
        result = self._evaluate_model(self._model_body())
        self.assertEqual(result["status"], "pass", result.get("failure_reason"))
        details = result["details"]
        self.assertEqual(details["modules"], 4)
        self.assertEqual(details["traces"], 256)
        self.assertEqual(details["rediscovered"], 8)
        self.assertEqual(details["defects_total"], 10)
        self.assertEqual(details["allowed_misses"], 2)
        self.assertEqual(details["baseline_rediscovered_min"], 8)

    def test_state_machine_model_conformance_fails_on_violations(self) -> None:
        result = self._evaluate_model(
            self._model_body(violations=1, summary_violations=1))
        self.assertEqual(result["status"], "fail")
        self.assertIn("status=FAIL", result["failure_reason"])

    def test_state_machine_model_conformance_fails_on_clean_run_counterexample(
            self) -> None:
        cex = ("PQCP_MODEL_COUNTEREXAMPLE module=policy seed=00000000deadbeef "
               "violation=2 ops=3 trace=010203")
        result = self._evaluate_model(self._model_body(cex=cex))
        self.assertEqual(result["status"], "fail")
        self.assertIn("counterexample for module policy",
                      result["failure_reason"])

    def test_state_machine_model_conformance_fails_without_summary(self) -> None:
        result = self._evaluate_model(self._model_body(summary=False))
        self.assertEqual(result["status"], "fail")
        self.assertIn("PQCP_MODEL_SUMMARY", result["failure_reason"])

    def test_state_machine_model_conformance_fails_on_reduced_seeds(self) -> None:
        result = self._evaluate_model(self._model_body(seeds=8))
        self.assertEqual(result["status"], "fail")
        self.assertIn("ran 8 seeds", result["failure_reason"])

    def test_state_machine_model_conformance_fails_without_rediscovery_marker(
            self) -> None:
        result = self._evaluate_model(self._model_body(marker=""))
        self.assertEqual(result["status"], "fail")
        self.assertIn("PQCP_MODEL_REDISCOVERY PASS", result["failure_reason"])

    def test_state_machine_model_conformance_fails_on_rediscovery_fail_marker(
            self) -> None:
        marker = "PQCP_MODEL_REDISCOVERY FAIL rediscovered=6/10 allowed=0"
        result = self._evaluate_model(self._model_body(marker=marker))
        self.assertEqual(result["status"], "fail")

    def test_state_machine_model_conformance_fails_below_baseline(self) -> None:
        result = self._evaluate_model(
            self._model_body(rediscovered=7, allowed=3))
        self.assertEqual(result["status"], "fail")
        self.assertIn("below the baseline 8", result["failure_reason"])

    def test_state_machine_model_conformance_fails_when_defect_list_shrinks(
            self) -> None:
        result = self._evaluate_model(
            self._model_body(rediscovered=8, allowed=0, total=8))
        self.assertEqual(result["status"], "fail")
        self.assertIn("shrank to 8", result["failure_reason"])

    def test_state_machine_model_conformance_fails_on_marker_defect_mismatch(
            self) -> None:
        statuses = ["rediscovered"] * 7 + ["allowed"] * 3
        result = self._evaluate_model(
            self._model_body(defect_statuses=statuses))
        self.assertEqual(result["status"], "fail")
        self.assertIn("defect lines are rediscovered",
                      result["failure_reason"])

    def test_state_machine_model_conformance_fails_on_unresolved_defect(
            self) -> None:
        statuses = ["rediscovered"] * 8 + ["allowed", "missed"]
        result = self._evaluate_model(
            self._model_body(defect_statuses=statuses))
        self.assertEqual(result["status"], "fail")
        self.assertIn("unresolved historical defects",
                      result["failure_reason"])

    def test_state_machine_model_conformance_fails_without_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "transcripts" / "evidence_transcript_manifest.json"
            result = ledger.evaluate_state_machine_model_conformance(
                dict(self._MODEL_SPEC), transcript_manifest=manifest)
            self.assertEqual(result["status"], "fail")
            self.assertIn("missing or empty", result["failure_reason"])

    def test_state_machine_model_conformance_fails_on_bad_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = self._write_model_transcript(root, self._model_body())
            baseline = root / "baseline.json"
            baseline.write_text(json.dumps({"rediscovered_min": "x"}))
            result = ledger.evaluate_state_machine_model_conformance(
                dict(self._MODEL_SPEC), transcript_manifest=manifest,
                baseline_path=baseline)
            self.assertEqual(result["status"], "fail")
            self.assertIn("baseline unusable", result["failure_reason"])

    def _write_ct_smoke_transcript(self, root: Path, body: str) -> Path:
        manifest_path = root / "transcripts" / "evidence_transcript_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path = manifest_path.parent / "01-ct-smoke.log"
        transcript_path.write_text(body, encoding="utf-8")
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "generated_at": "2026-04-28T00:00:00+00:00",
                    "generator": "scripts/release_check.py",
                    "required_steps": ["ct smoke ztest run"],
                    "transcripts": [
                        {
                            "step": "ct smoke ztest run",
                            "command": ["true"],
                            "command_text": "true",
                            "cwd": str(root),
                            "returncode": 0,
                            "duration_seconds": 0.1,
                            "transcript_path": transcript_path.name,
                            "sha256": sha256(transcript_path),
                            "size_bytes": transcript_path.stat().st_size,
                        }
                    ],
                    "qemu_stdout_transcripts": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return manifest_path

    def test_ct_smoke_passes_when_within_bound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                "PQCP_CT_SMOKE alg=MLKEM-512 iters=32 median_valid=25100 "
                "median_invalid=25300 delta=200 relative_pct=0 bound_pct=50\n"
                "PQCP_CT_SMOKE alg=MLKEM-768 iters=32 median_valid=35100 "
                "median_invalid=35500 delta=400 relative_pct=1 bound_pct=50\n"
                "PQCP_CT_SMOKE alg=MLKEM-1024 iters=32 median_valid=55100 "
                "median_invalid=55800 delta=700 relative_pct=1 bound_pct=50\n"
                "PQCP_CT_TTEST alg=MLKEM-512 iters=32 mean_valid=25100 "
                "mean_invalid=25300 t2_x1000=12\n"
                "PQCP_CT_TTEST alg=MLKEM-768 iters=32 mean_valid=35100 "
                "mean_invalid=35500 t2_x1000=18\n"
                "PQCP_CT_TTEST alg=MLKEM-1024 iters=32 mean_valid=55100 "
                "mean_invalid=55800 t2_x1000=21\n"
                "TESTSUITE pqcp_ct_smoke succeeded\n"
                "PROJECT EXECUTION SUCCESSFUL\n"
            )
            manifest = self._write_ct_smoke_transcript(root, body)
            spec = {"id": "security.ct_smoke", "category": "security", "claim": "x", "required": True}
            result = ledger.evaluate_ct_smoke(spec, transcript_manifest=manifest)
            self.assertEqual(result["status"], "pass", result.get("failure_reason"))
            self.assertEqual(result["details"]["algorithms"], ["MLKEM-1024", "MLKEM-512", "MLKEM-768"])
            self.assertEqual(result["details"]["measurements"][1]["relative_variance_pct"], 1)
            self.assertEqual(result["details"]["measurements"][1]["smoke_bound_pct"], 50)
            self.assertEqual(len(result["details"]["ttest_measurements"]), 3)
            self.assertTrue(result["details"]["is_smoke_test_only"])

    def test_ct_smoke_fails_when_variance_exceeds_bound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                "PQCP_CT_SMOKE alg=MLKEM-512 iters=32 median_valid=25100 "
                "median_invalid=25300 delta=200 relative_pct=0 bound_pct=50\n"
                "PQCP_CT_SMOKE alg=MLKEM-768 iters=32 median_valid=35100 "
                "median_invalid=70200 delta=35100 relative_pct=100 bound_pct=50\n"
                "PQCP_CT_SMOKE alg=MLKEM-1024 iters=32 median_valid=55100 "
                "median_invalid=55800 delta=700 relative_pct=1 bound_pct=50\n"
                "TESTSUITE pqcp_ct_smoke succeeded\n"
                "PROJECT EXECUTION SUCCESSFUL\n"
            )
            manifest = self._write_ct_smoke_transcript(root, body)
            spec = {"id": "security.ct_smoke", "category": "security", "claim": "x", "required": True}
            result = ledger.evaluate_ct_smoke(spec, transcript_manifest=manifest)
            self.assertEqual(result["status"], "fail")
            self.assertIn("100%", result["failure_reason"])

    def test_ct_smoke_fails_when_marker_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                "TESTSUITE pqcp_ct_smoke succeeded\n"
                "PROJECT EXECUTION SUCCESSFUL\n"  # no PQCP_CT_SMOKE line
            )
            manifest = self._write_ct_smoke_transcript(root, body)
            spec = {"id": "security.ct_smoke", "category": "security", "claim": "x", "required": True}
            result = ledger.evaluate_ct_smoke(spec, transcript_manifest=manifest)
            self.assertEqual(result["status"], "fail")
            self.assertIn("PQCP_CT_SMOKE", result["failure_reason"])

    def test_unsupported_schema_version_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            claims = self.make_claims(root, ["release.version_consistency"], schema_version=99)
            with self.assertRaises(RuntimeError) as cm:
                ledger.load_claim_specs(claims)
            self.assertIn("schema_version=99", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
