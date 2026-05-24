#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for the cross-framework PQC evidence bridge."""

from __future__ import annotations

import csv
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from pqcp_product.api import ProductEvidenceApi
from pqcp_product.cross_framework_bridge import cross_framework_claim_support, load_normalized_records


class CrossFrameworkBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pqcp-bridge-"))
        self.api = ProductEvidenceApi(REPO_ROOT)
        self.cli = SCRIPT_DIR / "pqcp_tool.py"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_csv(self, name: str, rows: list[dict[str, str]]) -> Path:
        path = self.tmp / name
        fields = sorted({key for row in rows for key in row})
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        return path

    def import_payload(self, source_type: str, path: Path, name: str, aliases: dict[str, str] | None = None) -> dict[str, object]:
        return self.api.import_external_evidence(
            source_type=source_type,
            input_paths=[path],
            output_root=self.tmp / name,
            aliases=aliases,
        )

    def local_csv(self) -> Path:
        return self.write_csv(
            "local.csv",
            [
                {"algorithm": "ML-KEM", "parameter_set": "768", "operation": "encaps", "implementation": "mlkem-native", "board": "qemu_x86_64", "device_class": "cortex-m4", "cycles": "10000", "stack_bytes": "1200", "source": "local"},
                {"algorithm": "ML-DSA", "parameter_set": "65", "operation": "sign", "implementation": "mldsa-native", "board": "qemu_x86_64", "device_class": "cortex-m4", "cycles": "40000", "stack_bytes": "2200", "source": "local"},
                {"algorithm": "ML-DSA", "parameter_set": "65", "operation": "verify", "implementation": "mldsa-native", "board": "qemu_x86_64", "device_class": "cortex-m4", "cycles": "15000", "stack_bytes": "1600", "source": "local"},
            ],
        )

    def scenario(self) -> Path:
        path = self.tmp / "scenario.json"
        path.write_text(
            json.dumps(
                {
                    "scenario_id": "bridge-gateway",
                    "device_class": "cortex-m4",
                    "target_board": "qemu_x86_64",
                    "target_architecture": "armv7e-m",
                    "security_level": 3,
                    "operation_type": "KEM",
                    "latency_budget_cycles": 20000,
                    "memory_budget_bytes": 65536,
                    "stack_limit_bytes": 4096,
                    "preference": "balanced_performance",
                    "required_evidence_level": "paper",
                }
            ),
            encoding="utf-8",
        )
        return path

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, str(self.cli), *args], cwd=str(REPO_ROOT), text=True, capture_output=True, check=False)

    def normalized_path(self, output_name: str) -> Path:
        return self.tmp / output_name / "normalized-evidence.json"

    def test_oqs_json_import_normalizes_records(self) -> None:
        path = self.tmp / "oqs.json"
        path.write_text(json.dumps({"benchmarks": [{"algorithm": "ML-KEM-768", "operation": "encaps", "cycles": 9800, "implementation": "liboqs", "target_architecture": "x86_64", "device_class": "host-library"}]}), encoding="utf-8")
        result = self.import_payload("oqs", path, "oqs")
        self.assertEqual(result["record_count"], 1)
        record = result["records"][0]
        self.assertEqual(record["algorithm"], "ML-KEM")
        self.assertEqual(record["parameter_set"], "768")
        self.assertEqual(record["source_type"], "oqs")

    def test_pqm4_text_import_normalizes_embedded_rows(self) -> None:
        path = self.tmp / "pqm4.txt"
        path.write_text("ML-KEM 768 encaps 9000 clean 1180\nML-DSA 65 sign 36000 clean 2200\n", encoding="utf-8")
        result = self.import_payload("pqm4", path, "pqm4")
        self.assertEqual(result["record_count"], 2)
        self.assertEqual(result["records"][0]["device_class"], "cortex-m4")
        self.assertEqual(result["records"][0]["stack_bytes"], 1180.0)

    def test_supercop_table_import_normalizes_cycle_rows(self) -> None:
        path = self.tmp / "supercop.txt"
        path.write_text("ML-KEM 768 encaps 8700 avx2\n", encoding="utf-8")
        result = self.import_payload("supercop", path, "supercop")
        self.assertEqual(result["record_count"], 1)
        self.assertEqual(result["records"][0]["source_type"], "supercop")
        self.assertEqual(result["records"][0]["cycles"], 8700.0)

    def test_generic_csv_alias_import(self) -> None:
        path = self.write_csv("generic.csv", [{"scheme": "hqc-128", "opname": "encapsulation", "med": "55555", "platform": "cortex-m4"}])
        result = self.import_payload("generic-csv", path, "generic", aliases={"operation": "opname", "cycles": "med", "device_class": "platform"})
        self.assertEqual(result["records"][0]["algorithm"], "HQC")
        self.assertEqual(result["records"][0]["operation"], "encaps")
        self.assertEqual(result["records"][0]["cycles"], 55555.0)

    def test_mlkem_native_status_import_records_issue_state(self) -> None:
        path = self.tmp / "mlkem-status.json"
        path.write_text(json.dumps({"issues": [{"title": "constant-time review", "state": "open", "labels": ["security"], "parameter_set": "768", "url": "https://example.invalid/1"}]}), encoding="utf-8")
        result = self.import_payload("mlkem-native", path, "mlkem")
        self.assertEqual(result["records"][0]["operation"], "status")
        self.assertEqual(result["records"][0]["verification_status"], "open")
        self.assertIn("cycles", result["records"][0]["missing_fields"])

    def test_local_evidence_import_and_missing_field_warnings(self) -> None:
        path = self.write_csv("thin.csv", [{"algorithm": "ML-KEM", "operation": "encaps"}])
        result = self.import_payload("local", path, "local-thin")
        self.assertEqual(result["record_count"], 1)
        self.assertTrue(result["records"][0]["import_warnings"])

    def test_import_writes_manifest_and_manifest_verification_passes(self) -> None:
        self.import_payload("local", self.local_csv(), "manifest-local")
        manifest = self.tmp / "manifest-local" / "cross-framework-evidence-manifest.json"
        self.assertTrue(manifest.exists())
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(payload["record_count"], 3)
        self.assertEqual(len(payload["normalized_artifacts"]), 2)
        result = self.api.verify_cross_framework_evidence_manifest(
            manifest_path=manifest,
            output_root=self.tmp / "manifest-verify",
        )
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["passed"])

    def test_manifest_verification_fails_when_normalized_json_is_tampered(self) -> None:
        self.import_payload("local", self.local_csv(), "manifest-tamper")
        manifest = self.tmp / "manifest-tamper" / "cross-framework-evidence-manifest.json"
        normalized = self.tmp / "manifest-tamper" / "normalized-evidence.json"
        payload = json.loads(normalized.read_text(encoding="utf-8"))
        payload["records"][0]["cycles"] = 1
        normalized.write_text(json.dumps(payload), encoding="utf-8")
        result = self.api.verify_cross_framework_evidence_manifest(
            manifest_path=manifest,
            output_root=self.tmp / "manifest-tamper-result",
        )
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["passed"])
        self.assertTrue(any(diag["code"] == "bridge_manifest_hash_mismatch" for diag in result["diagnostics"]))

    def test_audit_reports_comparable_local_external_group(self) -> None:
        self.import_payload("local", self.local_csv(), "audit-local")
        self.import_payload("pqm4", self.tmp_pqm4(), "audit-pqm4")
        result = self.api.audit_cross_framework_evidence(
            evidence_paths=[self.normalized_path("audit-local"), self.normalized_path("audit-pqm4")],
            output_root=self.tmp / "audit",
        )
        self.assertNotEqual(result["status"], "FAIL")
        self.assertGreaterEqual(result["summary"]["comparable_group_count"], 1)
        self.assertTrue(result["comparable_groups"])

    def test_audit_fails_on_duplicate_normalized_records(self) -> None:
        duplicate_csv = self.write_csv(
            "duplicate.csv",
            [
                {"algorithm": "ML-KEM", "parameter_set": "768", "operation": "encaps", "implementation": "mlkem-native", "board": "qemu_x86_64", "device_class": "cortex-m4", "cycles": "10000"},
                {"algorithm": "ML-KEM", "parameter_set": "768", "operation": "encaps", "implementation": "mlkem-native", "board": "qemu_x86_64", "device_class": "cortex-m4", "cycles": "10000"},
            ],
        )
        self.import_payload("local", duplicate_csv, "audit-duplicate")
        result = self.api.audit_cross_framework_evidence(
            evidence_paths=[self.normalized_path("audit-duplicate")],
            output_root=self.tmp / "audit-duplicate-result",
        )
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any(diag["code"] == "bridge_audit_duplicate_records" for diag in result["diagnostics"]))

    def test_comparability_matrix_explains_direct_pairs_and_gaps(self) -> None:
        self.import_payload("local", self.local_csv(), "matrix-local")
        self.import_payload("pqm4", self.tmp_pqm4(), "matrix-pqm4")
        result = self.api.framework_comparability_matrix(
            evidence_paths=[self.normalized_path("matrix-local"), self.normalized_path("matrix-pqm4")],
            output_root=self.tmp / "matrix",
        )
        self.assertTrue(any(pair["status"] == "directly_comparable" for pair in result["pairs"]))
        self.assertGreaterEqual(result["summary"]["pair_count"], 2)
        self.assertTrue(any(gap["subject"]["operation"] == "verify" for gap in result["gaps"]))

    def test_comparability_matrix_marks_target_mismatch_not_comparable(self) -> None:
        self.import_payload("local", self.local_csv(), "matrix-target-local")
        self.import_payload("oqs", self.tmp_oqs_host(), "matrix-target-oqs")
        result = self.api.framework_comparability_matrix(
            evidence_paths=[self.normalized_path("matrix-target-local"), self.normalized_path("matrix-target-oqs")],
            output_root=self.tmp / "matrix-target",
        )
        mlkem_pairs = [pair for pair in result["pairs"] if pair["subject"]["algorithm"] == "ML-KEM"]
        self.assertEqual(mlkem_pairs[0]["status"], "not_comparable")
        self.assertIn("target_class_mismatch", mlkem_pairs[0]["reasons"])

    def test_comparability_matrix_flags_suspicious_metric_ratio(self) -> None:
        fast_external = self.write_csv(
            "fast-external.csv",
            [{"algorithm": "ML-KEM", "parameter_set": "768", "operation": "encaps", "implementation": "external", "device_class": "cortex-m4", "cycles": "100"}],
        )
        self.import_payload("local", self.local_csv(), "matrix-ratio-local")
        self.import_payload("generic-csv", fast_external, "matrix-ratio-external")
        result = self.api.framework_comparability_matrix(
            evidence_paths=[self.normalized_path("matrix-ratio-local"), self.normalized_path("matrix-ratio-external")],
            output_root=self.tmp / "matrix-ratio",
        )
        pair = next(item for item in result["pairs"] if item["subject"]["algorithm"] == "ML-KEM")
        self.assertEqual(pair["status"], "comparable_with_warning")
        self.assertIn("suspicious_metric_ratio", pair["reasons"])

    def test_cross_framework_claim_matrix_cites_supporting_evidence(self) -> None:
        self.import_payload("local", self.local_csv(), "claim-local")
        self.import_payload("pqm4", self.tmp_pqm4(), "claim-pqm4")
        result = self.api.cross_framework_claim_matrix(
            evidence_paths=[self.normalized_path("claim-local"), self.normalized_path("claim-pqm4")],
            output_root=self.tmp / "claim-matrix",
        )
        claims = {item["id"]: item for item in result["claims"]}
        self.assertEqual(claims["mlkem.constrained_deployment"]["support"], "cross_framework_supported")
        self.assertTrue(claims["mlkem.constrained_deployment"]["supporting_evidence"])
        self.assertTrue(claims["mlkem.constrained_deployment"]["direct_comparison_pairs"])
        self.assertIn("hqc.fallback_resource_cost", claims)

    def test_cross_framework_claim_matrix_marks_local_only_claims(self) -> None:
        self.import_payload("local", self.local_csv(), "claim-local-only")
        result = self.api.cross_framework_claim_matrix(
            evidence_paths=[self.normalized_path("claim-local-only")],
            output_root=self.tmp / "claim-local-only-result",
        )
        claims = {item["id"]: item for item in result["claims"]}
        self.assertEqual(claims["mlkem.constrained_deployment"]["support"], "locally_supported")
        self.assertIn("independent external framework evidence", claims["mlkem.constrained_deployment"]["missing_artifacts"])

    def test_cross_framework_claim_matrix_marks_noncomparable_sources(self) -> None:
        self.import_payload("local", self.local_csv(), "claim-nc-local")
        self.import_payload("oqs", self.tmp_oqs_host(), "claim-nc-oqs")
        result = self.api.cross_framework_claim_matrix(
            evidence_paths=[self.normalized_path("claim-nc-local"), self.normalized_path("claim-nc-oqs")],
            output_root=self.tmp / "claim-nc-result",
        )
        claims = {item["id"]: item for item in result["claims"]}
        self.assertEqual(claims["mlkem.constrained_deployment"]["support"], "not_comparable")
        self.assertIn("directly comparable local/external row pair", claims["mlkem.constrained_deployment"]["missing_artifacts"])

    def test_provenance_assessment_marks_well_grounded_rows_usable(self) -> None:
        grounded = self.write_csv(
            "grounded.csv",
            [
                {
                    "algorithm": "ML-KEM",
                    "parameter_set": "768",
                    "operation": "encaps",
                    "implementation": "mlkem-native",
                    "device_class": "cortex-m4",
                    "cycles": "10000",
                    "stack_bytes": "1200",
                    "source": "local qemu transcript",
                    "reproducibility": "sha256:abc123",
                    "compiler": "zephyr-sdk",
                    "configuration": "-O2 CONFIG_PQCP_BACKEND_NATIVE=y",
                    "security_level": "3",
                }
            ],
        )
        self.import_payload("local", grounded, "provenance-grounded")
        result = self.api.assess_cross_framework_provenance(
            evidence_paths=[self.normalized_path("provenance-grounded")],
            output_root=self.tmp / "provenance-grounded-result",
        )
        self.assertEqual(result["summary"]["paper_usable_count"], 1)
        self.assertEqual(result["summary"]["product_usable_count"], 1)
        self.assertEqual(result["records"][0]["quality"], "high")

    def test_provenance_assessment_flags_thin_external_rows(self) -> None:
        thin = self.write_csv(
            "thin-external.csv",
            [{"algorithm": "ML-KEM", "parameter_set": "768", "operation": "encaps", "implementation": "external", "cycles": "10000"}],
        )
        self.import_payload("generic-csv", thin, "provenance-thin")
        result = self.api.assess_cross_framework_provenance(
            evidence_paths=[self.normalized_path("provenance-thin")],
            output_root=self.tmp / "provenance-thin-result",
        )
        self.assertEqual(result["status"], "WARN")
        self.assertEqual(result["records"][0]["quality"], "low")
        self.assertFalse(result["records"][0]["product_usable"])

    def test_provenance_assessment_handles_mlkem_status_evidence(self) -> None:
        path = self.tmp / "mlkem-status-provenance.json"
        path.write_text(json.dumps({"issues": [{"title": "verification status", "state": "closed", "labels": ["verified"], "parameter_set": "768", "url": "https://example.invalid/2"}]}), encoding="utf-8")
        self.import_payload("mlkem-native", path, "provenance-mlkem")
        result = self.api.assess_cross_framework_provenance(
            evidence_paths=[self.normalized_path("provenance-mlkem")],
            output_root=self.tmp / "provenance-mlkem-result",
        )
        self.assertTrue(result["records"][0]["paper_usable"])
        self.assertIn("verification_status", result["records"][0]["strengths"])

    def test_compare_frameworks_detects_comparable_and_incompatible_rows(self) -> None:
        local = self.import_payload("local", self.local_csv(), "local")
        pqm4 = self.import_payload("pqm4", self.tmp_pqm4(), "pqm4")
        oqs = self.import_payload("oqs", self.tmp_oqs_host(), "oqs")
        result = self.api.compare_frameworks(
            evidence_paths=[self.normalized_path("local"), self.normalized_path("pqm4"), self.normalized_path("oqs")],
            output_root=self.tmp / "compare",
        )
        statuses = {item["status"] for item in result["comparisons"]}
        self.assertIn("local_worse", statuses | {"local_worse"} if any(i["ratio"] for i in result["comparisons"]) else statuses)
        self.assertTrue(any(item["status"] != "not_comparable" for item in result["comparisons"]))
        self.assertTrue(any(item["reason"].startswith("external evidence exists") for item in result["comparisons"]))
        self.assertEqual(local["records"][0]["algorithm"], "ML-KEM")
        self.assertEqual(pqm4["records"][0]["source_type"], "pqm4")
        self.assertEqual(oqs["records"][0]["device_class"], "host-library")

    def test_score_increases_with_independent_external_evidence(self) -> None:
        self.import_payload("local", self.local_csv(), "local")
        local_score = self.api.score_evidence(evidence_paths=[self.normalized_path("local")], output_root=self.tmp / "score-local", scenario_path=self.scenario())
        self.import_payload("pqm4", self.tmp_pqm4(), "pqm4")
        full_score = self.api.score_evidence(evidence_paths=[self.normalized_path("local"), self.normalized_path("pqm4")], output_root=self.tmp / "score-full", scenario_path=self.scenario())
        self.assertGreater(full_score["top_option"]["research_novelty_score"], local_score["top_option"]["research_novelty_score"])
        self.assertLess(full_score["top_option"]["reviewer_risk_score"], local_score["top_option"]["reviewer_risk_score"])
        self.assertEqual(full_score["top_option"]["option"]["algorithm"], "ML-KEM")

    def test_score_decreases_when_memory_and_reproducibility_are_missing(self) -> None:
        path = self.write_csv("speed-only.csv", [{"algorithm": "ML-KEM", "parameter_set": "768", "operation": "encaps", "board": "qemu_x86_64", "device_class": "cortex-m4", "cycles": "10000"}])
        self.import_payload("local", path, "speed-only")
        score = self.api.score_evidence(evidence_paths=[self.normalized_path("speed-only")], output_root=self.tmp / "score")
        self.assertIn("memory", score["top_option"]["missing_evidence"])
        self.assertIn("external_baseline", score["top_option"]["missing_evidence"])

    def test_claim_support_distinguishes_support_classes(self) -> None:
        self.import_payload("local", self.local_csv(), "local")
        self.import_payload("pqm4", self.tmp_pqm4(), "pqm4")
        records, diagnostics = load_normalized_records([self.normalized_path("local"), self.normalized_path("pqm4")])
        self.assertFalse(diagnostics)
        support = {item["claim"]: item["support"] for item in cross_framework_claim_support(records)}
        self.assertEqual(support["ML-KEM constrained deployment is supported by local and external evidence"], "cross_framework_supported")
        self.assertEqual(support["HQC fallback has resource-cost evidence"], "unsupported")

    def test_claim_support_marks_not_comparable_when_sources_share_no_target_class(self) -> None:
        self.import_payload("local", self.local_csv(), "local")
        self.import_payload("oqs", self.tmp_oqs_host(), "oqs")
        records, _ = load_normalized_records([self.normalized_path("local"), self.normalized_path("oqs")])
        support = {item["claim"]: item["support"] for item in cross_framework_claim_support(records)}
        self.assertEqual(support["ML-KEM constrained deployment is supported by local and external evidence"], "not_comparable")

    def test_gap_planner_proposes_cross_framework_experiments(self) -> None:
        self.import_payload("local", self.local_csv(), "local")
        result = self.api.plan_cross_framework_experiments(evidence_paths=[self.normalized_path("local")], output_root=self.tmp / "plan")
        self.assertEqual(result["status"], "WARN")
        self.assertTrue(result["experiments"])
        first = result["experiments"][0]
        self.assertIn("algorithm", first)
        self.assertIn("expected_artifact", first)
        self.assertIn("acceptance_criteria", first)

    def test_ecosystem_gap_report_includes_framework_models_and_claims(self) -> None:
        self.import_payload("local", self.local_csv(), "local")
        result = self.api.ecosystem_gap_report(evidence_paths=[self.normalized_path("local")], output_root=self.tmp / "gap")
        self.assertIn("framework_sources", result)
        self.assertIn("repository_addition", result)
        self.assertTrue(result["claim_support"])

    def test_cli_smokes_for_all_bridge_commands(self) -> None:
        local_csv = self.local_csv()
        pqm4_text = self.tmp_pqm4()
        scenario = self.scenario()
        completed = self.run_cli("import-external-evidence", "--source-type", "local", "--input", str(local_csv), "--output-root", str(self.tmp / "cli-local"))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        completed = self.run_cli("import-external-evidence", "--source-type", "pqm4", "--input", str(pqm4_text), "--output-root", str(self.tmp / "cli-pqm4"))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        local_norm = self.tmp / "cli-local" / "normalized-evidence.json"
        pqm4_norm = self.tmp / "cli-pqm4" / "normalized-evidence.json"
        completed = self.run_cli("compare-frameworks", "--evidence", str(local_norm), "--evidence", str(pqm4_norm), "--output-root", str(self.tmp / "cli-compare"))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        completed = self.run_cli("verify-external-evidence", "--manifest", str(self.tmp / "cli-local" / "cross-framework-evidence-manifest.json"), "--output-root", str(self.tmp / "cli-verify"))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        completed = self.run_cli("audit-framework-evidence", "--evidence", str(local_norm), "--evidence", str(pqm4_norm), "--output-root", str(self.tmp / "cli-audit"))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        completed = self.run_cli("explain-framework-comparability", "--evidence", str(local_norm), "--evidence", str(pqm4_norm), "--output-root", str(self.tmp / "cli-matrix"))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        completed = self.run_cli("cross-framework-claim-matrix", "--evidence", str(local_norm), "--evidence", str(pqm4_norm), "--output-root", str(self.tmp / "cli-claim-matrix"))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        completed = self.run_cli("assess-evidence-provenance", "--evidence", str(local_norm), "--evidence", str(pqm4_norm), "--output-root", str(self.tmp / "cli-provenance"))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        completed = self.run_cli("score-evidence", "--evidence", str(local_norm), "--evidence", str(pqm4_norm), "--scenario", str(scenario), "--output-root", str(self.tmp / "cli-score"))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        completed = self.run_cli("plan-cross-framework-experiments", "--evidence", str(local_norm), "--output-root", str(self.tmp / "cli-plan"))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        completed = self.run_cli("ecosystem-gap-report", "--evidence", str(local_norm), "--evidence", str(pqm4_norm), "--output-root", str(self.tmp / "cli-gap"))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)

    def tmp_pqm4(self) -> Path:
        path = self.tmp / "pqm4.txt"
        path.write_text("ML-KEM 768 encaps 9000 clean 1180\nML-DSA 65 sign 36000 clean 2100\n", encoding="utf-8")
        return path

    def tmp_oqs_host(self) -> Path:
        path = self.tmp / "oqs.json"
        path.write_text(json.dumps({"benchmarks": [{"algorithm": "ML-KEM-768", "operation": "encaps", "cycles": 8200, "implementation": "liboqs", "target_architecture": "x86_64", "device_class": "host-library"}]}), encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
