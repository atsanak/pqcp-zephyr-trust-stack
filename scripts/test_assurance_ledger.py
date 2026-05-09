#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
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
from export_results import CSV_FIELDNAMES, EXPECTED_PRIMITIVE_ROWS


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
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "csv": {
                        "path": csv_path.name,
                        "sha256": sha256(csv_path),
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
