#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
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

    def make_claims(self, root: Path, claim_ids: list[str]) -> Path:
        all_claims = json.loads((ledger.DEFAULT_CLAIMS).read_text(encoding="utf-8"))["claims"]
        selected = [claim for claim in all_claims if claim["id"] in claim_ids]
        path = root / "claims.json"
        path.write_text(
            json.dumps({"schema_version": 1, "claims": selected}, indent=2) + "\n",
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


if __name__ == "__main__":
    unittest.main()
