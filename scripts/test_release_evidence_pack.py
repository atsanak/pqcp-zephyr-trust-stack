#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Focused tests for release evidence pack verification."""

from __future__ import annotations

import csv
import hashlib
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import generate_assurance_ledger as ledger
import export_pqc_cbom
import generate_pqc_attestation
import verify_assurance_policy
import verify_release_evidence_pack as pack_verify
from export_results import CSV_FIELDNAMES, EXPECTED_PRIMITIVE_ROWS


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseEvidencePackTests(unittest.TestCase):
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
        (root / "west.yml").write_text(
            "manifest:\n"
            "  projects:\n"
            "    - name: zephyr\n"
            "      revision: zephyr-sha\n"
            "    - name: mlkem-native\n"
            "      revision: mlkem-sha\n"
            "    - name: mldsa-native\n"
            "      revision: mldsa-sha\n",
            encoding="utf-8",
        )
        (root / "CHANGELOG.md").write_text(
            "## [Unreleased]\n\n## [1.2.3] - 2026-04-28\n\n- shipped\n",
            encoding="utf-8",
        )

    def make_claims(self, root: Path) -> Path:
        all_claims = json.loads((ledger.DEFAULT_CLAIMS).read_text(encoding="utf-8"))["claims"]
        keep = {
            "release.version_consistency",
            "benchmark.csv_validity",
            "benchmark.provenance_binding",
            "cost_of_assurance.guardrails",
            "release.local_bundle",
            "release.transcript_binding",
        }
        path = root / "claims.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "claims": [claim for claim in all_claims if claim["id"] in keep],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def make_benchmark_csv(self, output_root: Path) -> Path:
        path = output_root / "benchmark_results.csv"
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

    def make_cost_evidence(self, output_root: Path) -> Path:
        path = output_root / "cost_of_assurance_evidence.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "comparisons": [
                        {
                            "name": "comparison-a",
                            "passed": True,
                            "failure_reason": None,
                            "metrics": [
                                {
                                    "metric": "handshake_time",
                                    "candidate_value": 10.0,
                                    "baseline_value": 8.0,
                                    "ratio": 1.25,
                                    "threshold": {"max_ratio": 6.0},
                                    "passed": True,
                                    "failure_reason": None,
                                }
                            ],
                        }
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def make_release_bundle(self, output_root: Path) -> Path:
        bundle = output_root / "local_release_bundle" / "v1.2.3"
        bundle.mkdir(parents=True)
        notes = bundle / "release-notes-v1.2.3.md"
        notes.write_text("- shipped\n", encoding="utf-8")
        (bundle / "release-manifest-v1.2.3.json").write_text(
            json.dumps(
                {
                    "version": "1.2.3",
                    "tag": "v1.2.3",
                    "source_commit": None,
                    "working_tree_dirty": False,
                    "release_notes": {
                        "path": notes.name,
                        "sha256": sha256(notes),
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return output_root / "local_release_bundle"

    def make_mcu_footprint(self, output_root: Path) -> Path:
        path = output_root / "mcu_protocol_footprint" / "cost_of_assurance_protocols_mcu.csv"
        path.parent.mkdir(parents=True)
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["board", "suite", "implementation", "rom_bytes", "ram_bytes"],
            )
            writer.writeheader()
            writer.writerow(
                {
                    "board": "nucleo_h743zi",
                    "suite": "ML-KEM-768+ML-DSA-65",
                    "implementation": "pqcp",
                    "rom_bytes": "61144",
                    "ram_bytes": "175259",
                }
            )
        return path

    def make_transcript_manifest(self, output_root: Path) -> Path:
        manifest = output_root / "transcripts" / "evidence_transcript_manifest.json"
        manifest.parent.mkdir(parents=True)
        steps = ["ACVP serial ztest run", "ACVP KAT ztest run", "benchmark_csv"]
        transcripts: list[dict[str, object]] = []
        for index, step in enumerate(steps, start=1):
            path = manifest.parent / f"{index:02d}-{step.lower().replace(' ', '-')}.log"
            path.write_text(f"{step}\nPROJECT EXECUTION SUCCESSFUL\n", encoding="utf-8")
            transcripts.append(
                {
                    "step": step,
                    "command": ["true"],
                    "command_text": "true",
                    "cwd": str(output_root),
                    "returncode": 0,
                    "duration_seconds": 0.1,
                    "transcript_path": path.name,
                    "sha256": sha256(path),
                    "size_bytes": path.stat().st_size,
                }
            )
        qemu_log = output_root / "cost_of_assurance_smoke" / "runs" / "qemu-smoke" / "run.log"
        qemu_log.parent.mkdir(parents=True)
        qemu_log.write_text("PQCP_METRIC layer=protocol operation=HANDSHAKE cycles=456 us=7\n", encoding="utf-8")
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

    def make_pack(self, root: Path) -> tuple[Path, Path, Path]:
        module = root / "module"
        output = root / "release-output"
        module.mkdir()
        output.mkdir()
        self.make_module(module)
        claims = self.make_claims(root)
        csv_path = self.make_benchmark_csv(output)
        provenance = self.make_provenance(csv_path)
        cost = self.make_cost_evidence(output)
        bundle = self.make_release_bundle(output)
        transcript_manifest = self.make_transcript_manifest(output)
        self.make_mcu_footprint(output)
        (output / "benchmark_summary.md").write_text("| summary |\n", encoding="utf-8")

        args = Namespace(
            module_path=module,
            claims=claims,
            version=None,
            tag="v1.2.3",
            benchmark_csv=csv_path,
            benchmark_provenance=provenance,
            cost_of_assurance_evidence=cost,
            release_bundle_root=bundle,
            transcript_manifest=transcript_manifest,
            kat_header=module / "missing_kat_vectors.h",
            kat_vectors_dir=module / "missing_nist_vectors",
            negative_scenarios=module / "missing_acvp_negative_scenarios.json",
            output_json=output / "assurance_ledger.json",
            output_md=output / "assurance_ledger.md",
        )
        result = ledger.build_ledger(args)
        policy_required = json.loads(
            (Path(__file__).resolve().parent / "pqc_assurance_policy.json").read_text(
                encoding="utf-8"
            )
        )["required_claim_ids"]
        existing = {claim["id"] for claim in result["claims"]}
        for claim_id in policy_required:
            if claim_id in existing:
                continue
            result["claims"].append(
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
            )
        result["summary"] = {
            "pass": sum(1 for claim in result["claims"] if claim["status"] == "pass"),
            "fail": sum(1 for claim in result["claims"] if claim["status"] == "fail"),
            "not_applicable": sum(
                1 for claim in result["claims"] if claim["status"] == "not_applicable"
            ),
        }
        args.output_json.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        args.output_md.write_text(ledger.render_markdown(result), encoding="utf-8")
        import render_assurance_report
        report_html = render_assurance_report.render_report(result)
        (output / "assurance_report.html").write_text(report_html, encoding="utf-8")
        self.make_passport(module, output, args.output_json, transcript_manifest)
        return module, output, claims

    def make_passport(
        self,
        module: Path,
        output: Path,
        ledger_path: Path,
        transcript_manifest: Path,
    ) -> None:
        manifest = output / "local_release_bundle" / "v1.2.3" / "release-manifest-v1.2.3.json"
        cbom_path = output / "pqc_cbom.cdx.json"
        cbom = export_pqc_cbom.build_cbom(
            module,
            json.loads(ledger_path.read_text(encoding="utf-8")),
            json.loads(manifest.read_text(encoding="utf-8")),
        )
        cbom_path.write_text(json.dumps(cbom, indent=2) + "\n", encoding="utf-8")
        attestation_path = output / "pqc_attestation.intoto.json"
        digest_path = output / "pqc_assurance_digest.json"
        attestation_args = Namespace(
            module_path=module,
            ledger=ledger_path,
            ledger_md=output / "assurance_ledger.md",
            assurance_report=output / "assurance_report.html",
            cbom=cbom_path,
            release_manifest=manifest,
            transcript_manifest=transcript_manifest,
            benchmark_csv=output / "benchmark_results.csv",
            benchmark_provenance=output / "benchmark_provenance.json",
            cost_of_assurance_evidence=output / "cost_of_assurance_evidence.json",
            output=attestation_path,
            digest_output=digest_path,
        )
        attestation = generate_pqc_attestation.build_attestation(attestation_args)
        attestation_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
        generate_pqc_attestation.write_digest(
            digest_path,
            [
                ledger_path,
                cbom_path,
                transcript_manifest,
                output / "benchmark_provenance.json",
                manifest,
            ],
            attestation_path=attestation_path,
        )
        policy = verify_assurance_policy.verify_policy(
            policy_path=Path(__file__).resolve().parent / "pqc_assurance_policy.json",
            ledger_path=ledger_path,
            cbom_path=cbom_path,
            attestation_path=attestation_path,
            release_manifest_path=manifest,
        )
        (output / "pqc_policy_result.json").write_text(
            json.dumps(policy, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_valid_synthetic_pack_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, output, claims = self.make_pack(Path(tmp))
            failures = pack_verify.verify_pack(
                output,
                module_path=module,
                tag="v1.2.3",
                claims_path=claims,
            )
            self.assertEqual(failures, [])

    def test_missing_mcu_footprint_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, output, claims = self.make_pack(Path(tmp))
            (output / "mcu_protocol_footprint" / "cost_of_assurance_protocols_mcu.csv").unlink()
            failures = pack_verify.verify_pack(
                output,
                module_path=module,
                tag="v1.2.3",
                claims_path=claims,
            )
            self.assertTrue(any("MCU protocol footprint CSV not found" in item for item in failures))

    def test_tampered_release_notes_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, output, claims = self.make_pack(Path(tmp))
            notes = output / "local_release_bundle" / "v1.2.3" / "release-notes-v1.2.3.md"
            notes.write_text("tampered\n", encoding="utf-8")
            failures = pack_verify.verify_pack(
                output,
                module_path=module,
                tag="v1.2.3",
                claims_path=claims,
            )
            self.assertTrue(any("release notes sha256 mismatch" in item for item in failures))

    def test_manifest_and_ledger_source_commit_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, output, claims = self.make_pack(Path(tmp))
            manifest = output / "local_release_bundle" / "v1.2.3" / "release-manifest-v1.2.3.json"
            data = json.loads(manifest.read_text(encoding="utf-8"))
            data["source_commit"] = "unexpected"
            manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            failures = pack_verify.verify_pack(
                output,
                module_path=module,
                tag="v1.2.3",
                claims_path=claims,
            )
            self.assertTrue(any("source_commit" in item for item in failures))

    def test_missing_assurance_report_html_fails_for_v2_pack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, output, claims = self.make_pack(Path(tmp))
            (output / "assurance_report.html").unlink()
            failures = pack_verify.verify_pack(
                output,
                module_path=module,
                tag="v1.2.3",
                claims_path=claims,
            )
            self.assertTrue(
                any("assurance report HTML not found" in item for item in failures),
                f"unexpected failures: {failures}",
            )

    def test_assurance_report_html_must_contain_every_claim_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, output, claims = self.make_pack(Path(tmp))
            report_path = output / "assurance_report.html"
            ledger_json = json.loads(
                (output / "assurance_ledger.json").read_text(encoding="utf-8")
            )
            claim_ids = [c["id"] for c in ledger_json["claims"]]
            body = report_path.read_text(encoding="utf-8")
            for claim_id in claim_ids:
                self.assertIn(claim_id, body)
            # Drop one claim id from the HTML and confirm the verifier catches it.
            tampered = body.replace(claim_ids[0], "REDACTED-CLAIM-ID")
            report_path.write_text(tampered, encoding="utf-8")
            failures = pack_verify.verify_pack(
                output,
                module_path=module,
                tag="v1.2.3",
                claims_path=claims,
            )
            self.assertTrue(
                any("missing claim id" in item for item in failures),
                f"unexpected failures: {failures}",
            )


if __name__ == "__main__":
    unittest.main()
