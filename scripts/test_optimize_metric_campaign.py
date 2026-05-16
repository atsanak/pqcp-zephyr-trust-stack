#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for metric-by-metric optimization campaign decisions."""

from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path

import optimize_metric_campaign


def stat(parameter_set: str, operation: str, median: float, p90: float | None = None, p99: float | None = None) -> dict[str, object]:
    return {
        "parameter_set": parameter_set,
        "implementation": "pqcp",
        "backend": "auto",
        "operation": operation,
        "sample_count": 5,
        "min": median,
        "median": median,
        "p90": p90 if p90 is not None else median,
        "p99": p99 if p99 is not None else median,
        "mad": 1.0,
        "rom_bytes": 1000,
        "ram_bytes": 500,
    }


def campaign(*stats: dict[str, object], backend_rankings: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "schema_version": 1,
        "passed": True,
        "comparison_context": {
            "source_dataset": "qemu",
            "source_ecosystem": "pqcp-local",
            "board_class": "qemu",
            "statistic_type": "distribution",
            "environment_type": "qemu",
        },
        "statistics": list(stats),
        "pairwise_ratios": [
            {
                "parameter_set": "ML-DSA-87",
                "operation": "sign",
                "candidate_backend": "auto",
                "baseline_backend": "clean",
                "ratio": 1.9,
            }
        ],
        "backend_rankings": backend_rankings or [],
    }


class OptimizeMetricCampaignTests(unittest.TestCase):
    def write_json(self, root: Path, name: str, payload: dict[str, object]) -> Path:
        path = root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def args(self, baseline: Path, candidates: list[str], output: Path) -> argparse.Namespace:
        return argparse.Namespace(
            baseline_campaign=baseline,
            candidate_campaign=candidates,
            cost_evidence=None,
            hardware_result=None,
            emit_overlays=None,
            target=["mldsa.sign"],
            output=output,
            min_median_improvement=0.05,
            max_tail_regression=0.03,
            max_resource_regression=0.0,
            require_kept=False,
            run_target=None,
            run_candidate=None,
            run_output_root=output.parent / "runs",
            west_root=Path.cwd().parent,
            module_path=Path.cwd(),
            west=None,
            timeout=180,
            run_repetitions=1,
        )

    def test_accepts_candidate_with_median_win_and_clean_tail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = self.write_json(root, "baseline.json", campaign(stat("ML-DSA-87", "sign", 100.0, 110.0, 115.0)))
            candidate = self.write_json(root, "candidate.json", campaign(stat("ML-DSA-87", "sign", 90.0, 111.0, 116.0)))
            result = optimize_metric_campaign.run(self.args(baseline, [f"native={candidate}"], root / "out.json"))
        self.assertTrue(result["passed"], result["failures"])
        self.assertEqual(result["candidate_results"][0]["decision"], "keep")

    def test_rejects_candidate_with_tail_regression(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = self.write_json(root, "baseline.json", campaign(stat("ML-DSA-87", "sign", 100.0, 110.0, 115.0)))
            candidate = self.write_json(root, "candidate.json", campaign(stat("ML-DSA-87", "sign", 90.0, 130.0, 140.0)))
            result = optimize_metric_campaign.run(self.args(baseline, [f"bad_tail={candidate}"], root / "out.json"))
        self.assertTrue(result["passed"], result["failures"])
        self.assertEqual(result["candidate_results"][0]["decision"], "reject")
        comparison = result["candidate_results"][0]["target_results"][0]["comparisons"][0]
        self.assertIn("p90 regressed", comparison["failure_reason"])

    def test_missing_candidate_metric_fails_loudly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = self.write_json(root, "baseline.json", campaign(stat("ML-DSA-87", "sign", 100.0)))
            candidate = self.write_json(root, "candidate.json", campaign(stat("ML-KEM-512", "encaps", 90.0)))
            result = optimize_metric_campaign.run(self.args(baseline, [f"missing={candidate}"], root / "out.json"))
        self.assertFalse(result["passed"])
        self.assertTrue(any("missing mldsa.sign" in failure for failure in result["failures"]))

    def test_backend_selection_flags_auto_not_fastest(self) -> None:
        rankings = [
            {
                "parameter_set": "ML-KEM-768",
                "operation": "decaps",
                "fastest_backend": "force_native",
                "auto_is_fastest": False,
                "candidates": [
                    {"backend": "force_native", "median_cycles": 90.0},
                    {"backend": "auto", "median_cycles": 100.0},
                ],
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = self.write_json(root, "baseline.json", campaign(stat("ML-DSA-87", "sign", 100.0), backend_rankings=rankings))
            result = optimize_metric_campaign.run(self.args(baseline, [], root / "out.json"))
        self.assertEqual(result["backend_selection"]["status"], "evaluated")
        self.assertEqual(result["backend_selection"]["auto_not_fastest_count"], 1)

    def test_hardware_absence_is_recorded_not_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = self.write_json(root, "baseline.json", campaign(stat("ML-DSA-87", "sign", 100.0)))
            result = optimize_metric_campaign.run(self.args(baseline, [], root / "out.json"))
        self.assertTrue(result["passed"])
        self.assertEqual(result["hardware_promotion"]["status"], "not_available")

    def test_can_emit_safe_candidate_overlay_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = self.write_json(root, "baseline.json", campaign(stat("ML-DSA-87", "sign", 100.0)))
            args = self.args(baseline, [], root / "out.json")
            args.emit_overlays = root / "overlays"
            result = optimize_metric_campaign.run(args)
        self.assertTrue(result["passed"], result["failures"])
        emitted_names = {Path(row["path"]).name for row in result["emitted_overlays"]}
        self.assertIn("force_native.conf", emitted_names)
        self.assertIn("single_level.conf.template", emitted_names)

    def test_consolidated_metrics_can_seed_candidate_campaign(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metrics = root / "consolidated_metrics.csv"
            metrics.write_text(
                "\n".join(
                    [
                        "timestamp,run_id,board,profile,sample,implementation,backend,app_path,overlays,extra_kconfig,run_mode,build_only,component,operation,algorithm,level,metric,value,unit,log_path",
                        "t,r,qemu_x86_64,COA_QEMU_SINGLE_LEVEL,pqcp_basic_sig,pqcp,auto,samples/pqcp_basic_sig,,,run,False,primitive,sign,MLDSA,87,cycles,100,cyc,run.log",
                        "t,r,qemu_x86_64,COA_QEMU_SINGLE_LEVEL,pqcp_basic_sig,pqcp,auto,samples/pqcp_basic_sig,,,run,False,build,artifact,zephyr,0,rom_bytes,1000,B,run.log",
                        "t,r,qemu_x86_64,COA_QEMU_SINGLE_LEVEL,pqcp_basic_sig,pqcp,auto,samples/pqcp_basic_sig,,,run,False,build,artifact,zephyr,0,ram_bytes,500,B,run.log",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            campaign = optimize_metric_campaign.campaign_from_consolidated_metrics(metrics, label="synthetic")
        self.assertTrue(campaign["passed"])
        self.assertEqual(campaign["statistics"][0]["parameter_set"], "ML-DSA-87")
        self.assertEqual(campaign["statistics"][0]["operation"], "sign")
        self.assertEqual(campaign["statistics"][0]["rom_bytes"], 1000.0)

    def test_measurement_candidate_is_not_production_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = self.write_json(root, "baseline.json", campaign(stat("ML-DSA-87", "sign", 100.0, 100.0, 100.0)))
            candidate = self.write_json(root, "candidate.json", campaign(stat("ML-DSA-87", "sign", 90.0, 90.0, 90.0)))
            result = optimize_metric_campaign.run(
                self.args(baseline, [f"reduced_distribution_samples={candidate}"], root / "out.json")
            )
        self.assertTrue(result["passed"], result["failures"])
        self.assertEqual(result["candidate_results"][0]["decision"], "keep")
        self.assertFalse(result["candidate_results"][0]["production_promotion_allowed"])
        self.assertEqual(result["candidate_results"][0]["promotion_scope"], "measurement_only")

    def test_targeted_candidate_command_uses_backend_policy(self) -> None:
        target = optimize_metric_campaign.RUN_TARGETS["mldsa87-sign"]
        cmd = optimize_metric_campaign.benchmark_command(
            module_path=Path("/repo"),
            west_root=Path("/west"),
            west="west",
            target=target,
            output_dir=Path("/tmp/out"),
            backend_policy=optimize_metric_campaign.backend_policy_for_candidate("force_native"),
            extra_kconfig=list(target["extra_kconfig"]) + optimize_metric_campaign.kconfig_for_candidate("force_native"),
            timeout=120,
        )
        self.assertIn("--backend-policy", cmd)
        self.assertEqual(cmd[cmd.index("--backend-policy") + 1], "force_native")
        self.assertIn("CONFIG_PQCP_MLDSA_LEVEL_87=y", cmd)

    def test_targeted_run_records_include_hash_bound_metadata(self) -> None:
        original_runner = optimize_metric_campaign.run_subprocess

        def fake_runner(cmd: list[str], *, cwd: Path, timeout: int) -> dict[str, object]:
            output_dir = Path(cmd[cmd.index("--output") + 1])
            output_dir.mkdir(parents=True, exist_ok=True)
            backend = cmd[cmd.index("--backend-policy") + 1]
            metrics = output_dir / "consolidated_metrics.csv"
            metrics.write_text(
                "\n".join(
                    [
                        "timestamp,run_id,board,profile,sample,implementation,backend,app_path,overlays,extra_kconfig,run_mode,build_only,component,operation,algorithm,level,metric,value,unit,log_path",
                        f"t,r,qemu_x86_64,COA_QEMU_SINGLE_LEVEL,pqcp_basic_sig,pqcp,{backend},samples/pqcp_basic_sig,,,run,False,primitive,sign,MLDSA,87,cycles,100,cyc,run.log",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            return {"command": cmd, "started_at": "t", "returncode": 0, "timed_out": False, "stdout_tail": ""}

        try:
            optimize_metric_campaign.run_subprocess = fake_runner
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args = argparse.Namespace(
                    run_target="mldsa87-sign",
                    run_candidate=["force_native"],
                    run_output_root=root / "runs",
                    west_root=root / "west",
                    module_path=root / "module",
                    west=None,
                    timeout=30,
                    run_repetitions=1,
                )
                args.module_path.mkdir()
                _baseline, _candidates, records, failures = optimize_metric_campaign.run_target_candidates(args)
        finally:
            optimize_metric_campaign.run_subprocess = original_runner
        self.assertFalse(failures)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["candidate_id"], "baseline_auto")
        self.assertEqual(records[1]["candidate_id"], "force_native")
        self.assertEqual(records[1]["backend_policy"], "force_native")
        self.assertEqual(records[1]["target_id"], "mldsa.sign")
        self.assertRegex(str(records[1]["metrics_sha256"]), r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main(verbosity=2)
