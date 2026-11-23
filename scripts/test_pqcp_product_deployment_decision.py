#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for deployment decision and experiment recommendation tooling."""

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
from pqcp_product.deployment_decision import DeploymentScenario

FIELDS = [
    "algorithm",
    "operation",
    "parameter_set",
    "implementation",
    "board",
    "profile",
    "metric",
    "statistic",
    "value",
    "unit",
    "source",
]


class DeploymentDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pqcp-decision-"))
        self.api = ProductEvidenceApi(REPO_ROOT)
        self.cli = SCRIPT_DIR / "pqcp_tool.py"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def scenario(self, **overrides: object) -> Path:
        payload: dict[str, object] = {
            "scenario_id": "gateway-kem",
            "device_class": "iot_gateway",
            "target_board": "qemu_x86_64",
            "target_architecture": "x86_64",
            "security_level": 3,
            "operation_type": "KEM",
            "latency_budget_us": 200,
            "memory_budget_bytes": 65536,
            "stack_limit_bytes": 4096,
            "preference": "balanced_performance",
            "required_evidence_level": "paper",
        }
        payload.update(overrides)
        path = self.tmp / f"{payload['scenario_id']}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def yaml_scenario(self) -> Path:
        path = self.tmp / "scenario.yaml"
        path.write_text(
            "\n".join(
                [
                    "scenario_id: yaml-kem",
                    "device_class: sensor_gateway",
                    "target_board: qemu_x86_64",
                    "target_architecture: x86_64",
                    "security_level: 3",
                    "operation_type: KEM",
                    "latency_budget_us: 200",
                    "memory_budget_bytes: 65536",
                    "stack_limit_bytes: 4096",
                    "preference: balanced_performance",
                    "required_evidence_level: paper",
                    "preferred_algorithms:",
                    "  - ML-KEM",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def write_csv(self, rows: list[dict[str, str]] | None = None) -> Path:
        path = self.tmp / "results.csv"
        rows = rows or self.default_rows()
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        return path

    def default_rows(self) -> list[dict[str, str]]:
        return [
            self.row("ML-KEM", "keygen", "768", "80", "time", "us"),
            self.row("ML-KEM", "encaps", "768", "90", "time", "us"),
            self.row("ML-KEM", "decaps", "768", "95", "time", "us"),
            self.row("ML-KEM", "encaps", "768", "18000", "ram", "B"),
            self.row("ML-KEM", "decaps", "768", "1024", "stack", "B"),
            self.row("ML-KEM", "encaps", "1024", "160", "time", "us"),
            self.row("ML-DSA", "keygen", "65", "140", "time", "us"),
            self.row("ML-DSA", "sign", "65", "400", "time", "us"),
            self.row("ML-DSA", "verify", "65", "180", "time", "us"),
        ]

    def row(self, algorithm: str, operation: str, parameter: str, value: str, metric: str, unit: str) -> dict[str, str]:
        return {
            "algorithm": algorithm,
            "operation": operation,
            "parameter_set": parameter,
            "implementation": "native",
            "board": "qemu_x86_64",
            "profile": "paper",
            "metric": metric,
            "statistic": "median",
            "value": value,
            "unit": unit,
            "source": "synthetic-fixture",
        }

    def write_report(self, name: str, status: str = "PASS") -> Path:
        path = self.tmp / name
        path.write_text(json.dumps({"schema_version": 1, "status": status, "passed": status != "FAIL"}), encoding="utf-8")
        return path

    def write_pack(self) -> Path:
        root = self.tmp / "pack"
        root.mkdir()
        for name in ("assurance_ledger.json", "pqc_policy_result.json"):
            (root / name).write_text("{}", encoding="utf-8")
        manifest = {
            "schema_version": 1,
            "pack_id": "fixture",
            "profile": "product",
            "tag": "v-fixture",
            "artifacts": [
                {"artifact_id": "assurance_ledger_json", "relative_path": "assurance_ledger.json", "sha256": "0" * 64, "media_type": "application/json", "required": True},
                {"artifact_id": "pqc_policy_result_json", "relative_path": "pqc_policy_result.json", "sha256": "1" * 64, "media_type": "application/json", "required": True},
            ],
        }
        (root / "evidence-pack-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return root

    def full_reports(self) -> list[Path]:
        return [
            self.write_report("baseline-comparison.json"),
            self.write_report("cross-run-reproducibility-report.json"),
            self.write_report("result-quality-report.json"),
            self.write_report("statistical-sanity-report.json"),
        ]

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, str(self.cli), *args], cwd=str(REPO_ROOT), text=True, capture_output=True, check=False)

    def test_valid_json_scenario_parses(self) -> None:
        scenario = DeploymentScenario.from_path(self.scenario())
        self.assertEqual(scenario.scenario_id, "gateway-kem")
        self.assertEqual(scenario.security_level, 3)
        self.assertEqual(scenario.operation_type, "KEM")

    def test_valid_yaml_subset_scenario_parses(self) -> None:
        scenario = DeploymentScenario.from_path(self.yaml_scenario())
        self.assertEqual(scenario.scenario_id, "yaml-kem")
        self.assertEqual(scenario.preferred_algorithms, ("ML-KEM",))

    def test_invalid_scenario_fields_fail(self) -> None:
        with self.assertRaises(ValueError):
            DeploymentScenario.from_path(self.scenario(operation_type="VPN"))
        with self.assertRaises(ValueError):
            DeploymentScenario.from_path(self.scenario(memory_budget_bytes=-1))

    def test_mlkem_768_is_recommended_for_realistic_kem_case(self) -> None:
        result = self.api.recommend_deployment(
            scenario_path=self.scenario(),
            output_root=self.tmp / "recommend",
            packs=[self.write_pack()],
            csv_paths=[self.write_csv()],
            validation_reports=self.full_reports(),
        )
        self.assertIn(result["status"], {"PASS", "WARN"})
        top = result["top_recommendation"]
        self.assertIsNotNone(top)
        self.assertEqual(top["candidate"]["algorithm"], "ML-KEM")
        self.assertEqual(top["candidate"]["parameter_set"], "768")
        self.assertFalse(top["rejected"])

    def test_candidate_rejected_by_latency_and_memory_constraints(self) -> None:
        result = self.api.recommend_deployment(
            scenario_path=self.scenario(latency_budget_us=50, memory_budget_bytes=1000),
            output_root=self.tmp / "reject",
            csv_paths=[self.write_csv()],
            validation_reports=self.full_reports(),
        )
        mlkem_768 = next(item for item in result["recommendations"] if item["candidate"]["parameter_set"] == "768")
        self.assertTrue(mlkem_768["rejected"])
        self.assertTrue(any("latency" in reason or "memory" in reason for reason in mlkem_768["blocking_reasons"]))

    def test_missing_evidence_reduces_confidence(self) -> None:
        full = self.api.recommend_deployment(
            scenario_path=self.scenario(),
            output_root=self.tmp / "full",
            packs=[self.write_pack()],
            csv_paths=[self.write_csv()],
            validation_reports=self.full_reports(),
        )
        thin = self.api.recommend_deployment(
            scenario_path=self.scenario(),
            output_root=self.tmp / "thin",
            csv_paths=[self.write_csv()],
            validation_reports=[],
        )
        self.assertGreater(full["top_recommendation"]["confidence"], thin["top_recommendation"]["confidence"])
        self.assertIn("baseline_missing", thin["top_recommendation"]["evidence_gaps"])

    def test_evidence_gap_plan_contains_required_fields(self) -> None:
        result = self.api.plan_evidence(
            scenario_path=self.scenario(required_evidence_level="product"),
            output_root=self.tmp / "plan",
            csv_paths=[self.write_csv()],
            validation_reports=[],
        )
        self.assertEqual(result["status"], "WARN")
        self.assertTrue(result["experiments"])
        first = result["experiments"][0]
        for field in ("purpose", "expected_artifact", "claim_supported", "acceptance_criteria", "required_for"):
            self.assertIn(field, first)

    def test_claim_matrix_reports_supported_partial_and_unsupported_claims(self) -> None:
        result = self.api.claim_matrix(
            output_root=self.tmp / "claims",
            packs=[self.write_pack()],
            csv_paths=[self.write_csv()],
            validation_reports=self.full_reports(),
        )
        by_claim = {item["claim"]: item for item in result["claims"]}
        self.assertEqual(by_claim["Kyber768/ML-KEM-768 is a balanced operating point"]["support"], "supported")
        self.assertEqual(by_claim["HQC is a fallback but has resource cost"]["support"], "unsupported")
        self.assertIn(by_claim["ML-DSA signing is the bottleneck"]["support"], {"supported", "partially_supported"})

    def test_claim_matrix_can_say_not_enough_evidence(self) -> None:
        result = self.api.claim_matrix(output_root=self.tmp / "empty")
        unsupported = [item for item in result["claims"] if item["support"] == "unsupported"]
        self.assertTrue(unsupported)
        self.assertTrue(any(item["missing_artifacts"] for item in unsupported))

    def test_compare_scenarios_marks_supportable_and_unsupportable(self) -> None:
        good = self.scenario(scenario_id="good")
        impossible = self.scenario(scenario_id="impossible", security_level=5, latency_budget_us=10)
        result = self.api.compare_scenarios(
            scenario_paths=[good, impossible],
            output_root=self.tmp / "compare",
            csv_paths=[self.write_csv()],
            validation_reports=self.full_reports(),
        )
        by_id = {item["scenario_id"]: item for item in result["scenarios"]}
        self.assertTrue(by_id["good"]["supportable"])
        self.assertFalse(by_id["impossible"]["supportable"])

    def test_cli_smokes_for_all_decision_commands(self) -> None:
        scenario = self.scenario()
        csv_path = self.write_csv()
        reports = self.full_reports()
        pack = self.write_pack()
        common = ["--scenario", str(scenario), "--pack", str(pack), "--csv", str(csv_path)]
        for report in reports:
            common.extend(["--validation-report", str(report)])

        completed = self.run_cli("recommend-deployment", *common, "--output-root", str(self.tmp / "cli-recommend"))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertTrue((self.tmp / "cli-recommend" / "deployment-recommendations.json").exists())

        completed = self.run_cli("plan-evidence", *common, "--output-root", str(self.tmp / "cli-plan"))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertTrue((self.tmp / "cli-plan" / "evidence-gap-plan.json").exists())

        matrix_args = ["--pack", str(pack), "--csv", str(csv_path)]
        for report in reports:
            matrix_args.extend(["--validation-report", str(report)])
        completed = self.run_cli("claim-matrix", *matrix_args, "--output-root", str(self.tmp / "cli-claims"))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertTrue((self.tmp / "cli-claims" / "claim-support-matrix.json").exists())

        completed = self.run_cli("compare-scenarios", *common, "--output-root", str(self.tmp / "cli-compare"))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertTrue((self.tmp / "cli-compare" / "scenario-comparison.json").exists())


if __name__ == "__main__":
    unittest.main()
