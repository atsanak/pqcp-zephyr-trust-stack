#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for performance-methodology and CT-policy helper tooling."""

from __future__ import annotations

import csv
import os
import sys
import tempfile
import unittest
from pathlib import Path

import export_results
import parse_logs
import release_check
import run_benchmarks
import run_hardware_benchmarks
import verify_ct_instruction_policy


class PQCPerformanceHardeningTests(unittest.TestCase):
    def test_parse_logs_accepts_distribution_and_metadata_metrics(self) -> None:
        distribution = parse_logs.parse_pqcp_metric_line(
            "PQCP_METRIC,primitive,decaps,MLKEM,768,cycles_p99,123456,cyc"
        )
        self.assertIsNotNone(distribution)
        self.assertEqual(distribution["metric"], "cycles_p99")
        self.assertEqual(distribution["unit"], "cyc")

        metadata = parse_logs.parse_pqcp_metric_line(
            "PQCP_METRIC,build,metadata,zephyr,0,version,4.4.2,"
        )
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata["component"], "build")
        self.assertEqual(metadata["value"], "4.4.2")

    def test_benchmark_validation_ignores_additive_distribution_rows(self) -> None:
        rows = []
        for parameter_set, operations in export_results.EXPECTED_PRIMITIVE_ROWS.items():
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
                            "cycles": "1000",
                            "time_us": "100",
                            "rom_bytes": "2000",
                            "ram_bytes": "3000",
                            "platform": "qemu_x86_64",
                            "timestamp": "2026-05-09T00:00:00+00:00",
                        }
                    )
                    rows.append(
                        {
                            "suite": suite,
                            "parameter_set": parameter_set,
                            "implementation": implementation,
                            "backend": "auto" if implementation == "pqcp" else "clean",
                            "operation": f"{operation}_cycles_median",
                            "cycles": "950",
                            "time_us": "",
                            "rom_bytes": "2000",
                            "ram_bytes": "3000",
                            "platform": "qemu_x86_64",
                            "timestamp": "2026-05-09T00:00:00+00:00",
                        }
                    )
        self.assertEqual(export_results.validate_benchmark_rows(rows), [])

    def test_export_synthesizes_single_observation_distribution_rows(self) -> None:
        rows = [
            {
                "suite": "ML-KEM",
                "parameter_set": "ML-KEM-768",
                "implementation": "pqcp",
                "backend": "auto",
                "operation": "decaps",
                "cycles": "1234",
                "time_us": "12",
                "rom_bytes": "2000",
                "ram_bytes": "3000",
                "platform": "qemu_x86_64",
                "timestamp": "2026-05-09T00:00:00+00:00",
            }
        ]
        expanded = export_results.add_single_observation_distribution_rows(rows)
        operations = {row["operation"] for row in expanded}
        self.assertIn("decaps_cycles_median", operations)
        self.assertIn("decaps_sample_count", operations)
        sample_count = next(row for row in expanded if row["operation"] == "decaps_sample_count")
        self.assertEqual(sample_count["cycles"], 1)

    def test_benchmark_provenance_records_required_metadata(self) -> None:
        metric_rows = [
            {
                "component": "build",
                "operation": "metadata",
                "algorithm": "compiler",
                "metric": "id",
                "value": "clang",
                "unit": "",
                "run_id": "run-1",
            },
            {
                "component": "build",
                "operation": "metadata",
                "algorithm": "zephyr",
                "metric": "version",
                "value": "4.4.0",
                "unit": "",
                "run_id": "run-1",
            },
            {
                "component": "build",
                "operation": "metadata",
                "algorithm": "board",
                "metric": "name",
                "value": "qemu_x86_64",
                "unit": "",
                "run_id": "run-1",
            },
            {
                "component": "build",
                "operation": "metadata",
                "algorithm": "profile",
                "metric": "flags",
                "value": "258",
                "unit": "mask",
                "run_id": "run-1",
            },
            {
                "component": "build",
                "operation": "metadata",
                "algorithm": "backend",
                "metric": "selector",
                "value": "0",
                "unit": "id",
                "run_id": "run-1",
            },
            {
                "component": "build",
                "operation": "metadata",
                "algorithm": "distribution",
                "metric": "sample_cap",
                "value": "128",
                "unit": "count",
                "run_id": "run-1",
            },
        ]
        metadata = export_results.collect_benchmark_metadata(metric_rows)
        self.assertEqual(
            set(metadata["keys"]),
            set(export_results.REQUIRED_BENCHMARK_METADATA_KEYS),
        )
        self.assertEqual(
            export_results.validate_benchmark_metadata_document(metadata),
            [],
        )

    def test_metadata_validation_fails_without_required_build_keys(self) -> None:
        failures = export_results.validate_benchmark_metadata_document(
            {
                "row_count": 1,
                "keys": ["compiler.id"],
                "by_key": {"compiler.id": ["clang"]},
            }
        )
        self.assertTrue(
            any(failure["check"] == "provenance_metadata" for failure in failures)
        )

    def test_instruction_policy_passes_without_division_in_target_symbol(self) -> None:
        text = """
00000000 <pqcp_mlkem_decapsulate>:
   0:  48 31 c0    xor %rax,%rax
   3:  c3          ret
"""
        result = verify_ct_instruction_policy.build_result(
            source=Path("synthetic.S"),
            disassembly=text,
            patterns=("decapsulate",),
            allow_missing_targets=False,
        )
        self.assertTrue(result["passed"])
        self.assertEqual(result["finding_count"], 0)

    def test_instruction_policy_fails_on_division_in_target_symbol(self) -> None:
        text = """
00000000 <pqcp_mlkem_decapsulate>:
   0:  48 f7 f1    div %rcx
   3:  c3          ret
"""
        result = verify_ct_instruction_policy.build_result(
            source=Path("synthetic.S"),
            disassembly=text,
            patterns=("decapsulate",),
            allow_missing_targets=False,
        )
        self.assertFalse(result["passed"])
        self.assertIn("variable-latency division", result["failures"][0])

    def test_hardware_reference_import_normalizes_common_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "reference.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["scheme", "op", "median_cycles", "board"],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "scheme": "ML-KEM-768",
                        "op": "decaps",
                        "median_cycles": "12345",
                        "board": "cortex-m4-reference",
                    }
                )
            rows = run_hardware_benchmarks.normalize_reference_csv(
                csv_path, "paper-reference"
            )
        self.assertEqual(rows[0]["source"], "paper-reference")
        self.assertEqual(rows[0]["algorithm"], "ML-KEM-768")
        self.assertEqual(rows[0]["operation"], "decaps")
        self.assertEqual(rows[0]["cycles"], "12345")

    def test_hardware_reference_comparison_pairs_candidate_rows(self) -> None:
        candidate = [
            {
                "source": "candidate",
                "algorithm": "ML-KEM-768",
                "operation": "decaps",
                "cycles": "200",
            }
        ]
        reference = [
            {
                "source": "paper-reference",
                "algorithm": "ML-KEM-768",
                "operation": "decaps",
                "cycles": "100",
            }
        ]
        comparison = run_hardware_benchmarks.compare_candidate_to_reference(
            candidate, reference
        )
        self.assertTrue(comparison[0]["passed"])
        self.assertEqual(comparison[0]["ratio"], 2.0)

    def test_benchmark_runner_stops_after_success_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner = run_benchmarks.BenchmarkRunner(
                west_root=root,
                module_path=root,
                output_dir=root / "out",
                west_cmd=["west"],
                build_only=False,
                default_timeout=5,
                verbose=False,
            )
            result = runner._run_command(
                [
                    sys.executable,
                    "-c",
                    (
                        "import sys, time; "
                        "print('PROJECT EXECUTION SUCCESSFUL', flush=True); "
                        "time.sleep(30)"
                    ),
                ],
                cwd=root,
                timeout=5,
                success_markers=("PROJECT EXECUTION SUCCESSFUL",),
            )
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.timed_out)
        self.assertIn("PROJECT EXECUTION SUCCESSFUL", result.stdout)

    def test_release_step_runner_stops_after_success_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            step = release_check.Step(
                name="synthetic marker step",
                cmd=[
                    sys.executable,
                    "-c",
                    (
                        "import time; "
                        "print('PROJECT EXECUTION SUCCESSFUL', flush=True); "
                        "time.sleep(30)"
                    ),
                ],
                cwd=root,
                timeout=5,
                success_markers=("PROJECT EXECUTION SUCCESSFUL",),
            )
            result = release_check.run_step(step, env=os.environ.copy(), verbose=False)
        self.assertEqual(result.returncode, 0)
        self.assertIn("PROJECT EXECUTION SUCCESSFUL", result.output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
