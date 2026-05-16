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
import generate_pqc_build_provenance
import generate_pqc_reference_values
import export_firmware_assurance_digest
import verify_assurance_policy
import verify_pqc_build_provenance
import verify_pqc_claim_closure
import verify_release_evidence_pack as pack_verify
import run_acvp_json_vectors
from export_results import (
    CSV_FIELDNAMES,
    EXPECTED_PRIMITIVE_ROWS,
    REQUIRED_BENCHMARK_METADATA_KEYS,
)


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
                    "schema_version": 6,
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
        (output / "acvp_negative_scenario_floor_result.json").write_text(
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
        (output / "pqc_asset_trace_result.json").write_text(
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
        (output / "ct_instruction_policy_result.json").write_text(
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
        (output / "pqc_evidence_graph.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "summary": {"assets": 1, "nodes": 1, "edges": 0, "failures": 0},
                    "failures": [],
                    "nodes": [
                        {
                            "id": "claim:release.version_consistency",
                            "type": "claim",
                            "label": "release.version_consistency",
                            "metadata": {},
                        }
                    ],
                    "edges": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (output / "pqc_evidence_graph.md").write_text(
            "# graph\n\n- `release.version_consistency`\n",
            encoding="utf-8",
        )
        (output / "pqc_environment_result.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "passed": True,
                    "summary": {"checks": 1, "failures": 0},
                    "failures": [],
                    "checks": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (output / "pqc_assurance_profile_result.json").write_text(
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
        (output / "pqc_evidence_quality_result.json").write_text(
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
        (output / "pqc_migration_readiness.json").write_text(
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
        (output / "pqc_migration_readiness.md").write_text(
            "# PQC Migration Readiness\n\nML-KEM-768\n",
            encoding="utf-8",
        )
        (output / "ct_sample_manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "algorithms": [
                        {
                            "algorithm": "MLKEM-768",
                            "valid_count": 8,
                            "invalid_count": 8,
                            "valid_indexes": list(range(8)),
                            "invalid_indexes": list(range(8)),
                            "passed": True,
                            "sources": [],
                        }
                    ],
                    "summary": {"algorithms": 1, "total_samples": 16},
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (output / "backend_currency_result.json").write_text(
            json.dumps({"schema_version": 1, "passed": True, "backends": [], "failures": []}, indent=2) + "\n",
            encoding="utf-8",
        )
        (output / "external_reference_import").mkdir()
        (output / "external_reference_import" / "hardware_benchmark_report.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "mode": "import-reference",
                    "passed": True,
                    "execution": {"passed": True, "failures": []},
                    "comparison_context": {
                        "source_dataset": "synthetic-reference",
                        "source_ecosystem": "pqm4",
                        "board_class": "cortex-m4",
                        "clock_mhz": 168,
                        "statistic_type": "median_cycles",
                        "environment_type": "external_reference",
                    },
                    "summary": {"metric_count": 1},
                    "metrics": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
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
            ct_instruction_policy_result=output / "ct_instruction_policy_result.json",
            evidence_graph=output / "pqc_evidence_graph.json",
            asset_trace_result=output / "pqc_asset_trace_result.json",
            assurance_profile_result=output / "pqc_assurance_profile_result.json",
            evidence_quality_result=output / "pqc_evidence_quality_result.json",
            migration_readiness_json=output / "pqc_migration_readiness.json",
            migration_readiness_md=output / "pqc_migration_readiness.md",
            environment_result=output / "pqc_environment_result.json",
            ct_sample_manifest=output / "ct_sample_manifest.json",
            backend_currency_result=output / "backend_currency_result.json",
            external_reference_result=output / "external_reference_import" / "hardware_benchmark_report.json",
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
                output / "ct_instruction_policy_result.json",
                output / "pqc_evidence_graph.json",
                output / "pqc_asset_trace_result.json",
                output / "pqc_environment_result.json",
                output / "pqc_assurance_profile_result.json",
                output / "pqc_evidence_quality_result.json",
                output / "pqc_migration_readiness.json",
                output / "pqc_migration_readiness.md",
                output / "ct_sample_manifest.json",
                output / "backend_currency_result.json",
                output / "external_reference_import" / "hardware_benchmark_report.json",
                manifest,
            ],
            attestation_path=attestation_path,
        )
        generated = output / "generated" / "pqcp_assurance_digest_generated.h"
        export_firmware_assurance_digest.export_header(digest_path, generated)
        policy = verify_assurance_policy.verify_policy(
            policy_path=Path(__file__).resolve().parent / "pqc_assurance_policy.json",
            ledger_path=ledger_path,
            cbom_path=cbom_path,
            attestation_path=attestation_path,
            release_manifest_path=manifest,
            asset_trace_result_path=output / "pqc_asset_trace_result.json",
            ct_instruction_policy_result_path=output / "ct_instruction_policy_result.json",
            evidence_graph_path=output / "pqc_evidence_graph.json",
            assurance_digest_path=digest_path,
            firmware_digest_header_path=generated,
            assurance_profile_result_path=output / "pqc_assurance_profile_result.json",
            evidence_quality_result_path=output / "pqc_evidence_quality_result.json",
            migration_readiness_json_path=output / "pqc_migration_readiness.json",
            migration_readiness_md_path=output / "pqc_migration_readiness.md",
        )
        (output / "pqc_policy_result.json").write_text(
            json.dumps(policy, indent=2) + "\n",
            encoding="utf-8",
        )
        reference_args = Namespace(
            module_path=module,
            ledger=ledger_path,
            cbom=cbom_path,
            attestation=attestation_path,
            assurance_digest=digest_path,
            release_manifest=manifest,
            policy_result=output / "pqc_policy_result.json",
            profile_result=output / "pqc_assurance_profile_result.json",
            transcript_manifest=transcript_manifest,
            output=output / "pqc_reference_values.json",
        )
        reference_values = generate_pqc_reference_values.build_reference(reference_args)
        (output / "pqc_reference_values.json").write_text(
            json.dumps(reference_values, indent=2) + "\n",
            encoding="utf-8",
        )
        (output / "pqc_reference_values_result.json").write_text(
            json.dumps({"schema_version": 1, "passed": True, "checks": [], "failures": []}, indent=2) + "\n",
            encoding="utf-8",
        )
        digest_payload = json.loads(digest_path.read_text(encoding="utf-8"))
        status_lines = [
            "PQCP_ASSURANCE_STATUS "
            f"version=1.2.3 "
            f"digest={reference_values['expected_firmware_digest_root']} "
            f"artifact_count={reference_values['firmware_digest_artifact_count']} "
            "schema=1"
        ]
        for item in digest_payload.get("artifacts") or []:
            status_lines.append(
                f"PQCP_ASSURANCE_ARTIFACT name={Path(str(item['path'])).name} "
                f"sha256={item['sha256']}"
            )
        (output / "transcripts" / "99-firmware-assurance-status.log").write_text(
            "\n".join(status_lines) + "\n",
            encoding="utf-8",
        )
        (output / "firmware_assurance_status_result.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "passed": True,
                    "status": {
                        "version": "1.2.3",
                        "digest": reference_values["expected_firmware_digest_root"],
                        "artifact_count": reference_values["firmware_digest_artifact_count"],
                        "schema": 1,
                    },
                    "checks": [],
                    "failures": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        acvp_command = "KEYGEN:MLKEM:768"
        acvp_response = "RESULT:OK"
        acvp_hash = run_acvp_json_vectors.transcript_hash(acvp_command, acvp_response)
        acvp_result_row = {
            "source": "synthetic-acvp.json",
            "mode": "mlkem",
            "tgId": 1,
            "tcId": 1,
            "command": acvp_command,
            "response": acvp_response,
            "expected_result_class": "success",
            "transcript_sha256": acvp_hash,
        }
        (output / "acvp_json_interop_result.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "passed": True,
                    "summary": {"test_cases": 1, "negative_cases": 0, "failures": 0},
                    "results": [acvp_result_row],
                    "failures": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (output / "acvp_json_transcript_manifest.json").write_text(
            json.dumps({"schema_version": 1, "transcripts": [{**acvp_result_row, "sha256": acvp_hash}]}, indent=2) + "\n",
            encoding="utf-8",
        )
        (output / "ct_sample_analysis_result.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "passed": True,
                    "algorithms": [
                        {
                            "algorithm": "MLKEM-768",
                            "valid_count": 8,
                            "invalid_count": 8,
                            "passed": True,
                        }
                    ],
                    "checks": [],
                    "failures": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        provenance_path = output / "pqc_build_provenance.slsa.json"
        provenance_subjects = [
            ledger_path,
            output / "pqc_reference_values.json",
            cbom_path,
            attestation_path,
        ]
        provenance_byproducts = [
            output / "benchmark_results.csv",
            output / "cost_of_assurance_evidence.json",
            output / "acvp_json_interop_result.json",
            output / "ct_sample_analysis_result.json",
            output / "ct_sample_manifest.json",
            output / "backend_currency_result.json",
            output / "external_reference_import" / "hardware_benchmark_report.json",
        ]
        provenance = generate_pqc_build_provenance.build_statement(
            Namespace(
                module_path=module,
                release_manifest=manifest,
                claims=Path(__file__).resolve().parent / "assurance_claims.json",
                policy=Path(__file__).resolve().parent / "pqc_assurance_policy.json",
                profile=Path(__file__).resolve().parent / "pqc_assurance_profile.json",
                subject=provenance_subjects,
                byproduct=provenance_byproducts,
                output=provenance_path,
            )
        )
        provenance_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
        provenance_result = verify_pqc_build_provenance.verify(
            Namespace(
                provenance=provenance_path,
                subject=provenance_subjects,
                byproduct=provenance_byproducts,
                release_manifest=manifest,
                output=output / "pqc_build_provenance_result.json",
            )
        )
        (output / "pqc_build_provenance_result.json").write_text(
            json.dumps(provenance_result, indent=2) + "\n",
            encoding="utf-8",
        )
        closure = verify_pqc_claim_closure.verify_closure(
            Namespace(
                ledger=ledger_path,
                attestation=attestation_path,
                assurance_digest=digest_path,
                ct_instruction_policy_result=output / "ct_instruction_policy_result.json",
                policy_result=output / "pqc_policy_result.json",
                assurance_profile_result=output / "pqc_assurance_profile_result.json",
                evidence_quality_result=output / "pqc_evidence_quality_result.json",
                migration_readiness_json=output / "pqc_migration_readiness.json",
                migration_readiness_md=output / "pqc_migration_readiness.md",
                firmware_digest_header=generated,
                reference_values=output / "pqc_reference_values.json",
                firmware_status_result=output / "firmware_assurance_status_result.json",
                acvp_json_interop_result=output / "acvp_json_interop_result.json",
                build_provenance_result=output / "pqc_build_provenance_result.json",
                ct_sample_analysis_result=output / "ct_sample_analysis_result.json",
                backend_currency_result=output / "backend_currency_result.json",
            )
        )
        (output / "pqc_claim_closure_result.json").write_text(
            json.dumps(closure, indent=2) + "\n",
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

    def test_missing_passport_v2_asset_trace_result_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, output, claims = self.make_pack(Path(tmp))
            (output / "pqc_asset_trace_result.json").unlink()
            failures = pack_verify.verify_pack(
                output,
                module_path=module,
                tag="v1.2.3",
                claims_path=claims,
            )
            self.assertTrue(
                any("PQC asset trace result not found" in item for item in failures),
                f"unexpected failures: {failures}",
            )

    def test_stale_reference_values_fail_even_when_result_file_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, output, claims = self.make_pack(Path(tmp))
            reference = output / "pqc_reference_values.json"
            payload = json.loads(reference.read_text(encoding="utf-8"))
            payload["expected_firmware_digest_root"] = "0" * 64
            reference.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            failures = pack_verify.verify_pack(
                output,
                module_path=module,
                tag="v1.2.3",
                claims_path=claims,
            )
            self.assertTrue(
                any("PQC reference values replay" in item for item in failures),
                f"unexpected failures: {failures}",
            )

    def test_firmware_status_transcript_is_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, output, claims = self.make_pack(Path(tmp))
            transcript = output / "transcripts" / "99-firmware-assurance-status.log"
            body = transcript.read_text(encoding="utf-8")
            transcript.write_text(body.replace("digest=", "digest=" + "0" * 64 + "\nBROKEN="), encoding="utf-8")
            failures = pack_verify.verify_pack(
                output,
                module_path=module,
                tag="v1.2.3",
                claims_path=claims,
            )
            self.assertTrue(
                any("firmware assurance status replay" in item for item in failures),
                f"unexpected failures: {failures}",
            )

    def test_build_provenance_byproduct_hash_is_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, output, claims = self.make_pack(Path(tmp))
            provenance = output / "pqc_build_provenance.slsa.json"
            payload = json.loads(provenance.read_text(encoding="utf-8"))
            byproducts = payload["predicate"]["runDetails"]["byproducts"]
            self.assertTrue(byproducts)
            byproducts[-1]["digest"]["sha256"] = "0" * 64
            provenance.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            failures = pack_verify.verify_pack(
                output,
                module_path=module,
                tag="v1.2.3",
                claims_path=claims,
            )
            self.assertTrue(
                any("PQC build provenance replay" in item for item in failures),
                f"unexpected failures: {failures}",
            )

    def test_acvp_json_transcript_hash_is_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, output, claims = self.make_pack(Path(tmp))
            manifest = output / "acvp_json_transcript_manifest.json"
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["transcripts"][0]["sha256"] = "0" * 64
            manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            failures = pack_verify.verify_pack(
                output,
                module_path=module,
                tag="v1.2.3",
                claims_path=claims,
            )
            self.assertTrue(
                any("ACVP JSON interop replay" in item for item in failures),
                f"unexpected failures: {failures}",
            )


if __name__ == "__main__":
    unittest.main()
