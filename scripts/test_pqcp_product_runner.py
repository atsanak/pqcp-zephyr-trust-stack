#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression tests for PQCP product evidence tooling."""

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
from pqcp_product.models import ExperimentSelection, ExperimentSpec


def synthetic_experiment(command: str) -> ExperimentSpec:
    return ExperimentSpec(
        id="synthetic.runner",
        category="artifact_schema",
        objective="Run a synthetic command to prove transcript capture works.",
        repository_inputs=("scripts/research_experiment_catalog.json",),
        commands=(command,),
        expected_outputs=("run-manifest.json",),
        positive_control="The command exits zero and writes a transcript.",
        negative_control="Change the command to exit non-zero and confirm failure is reported.",
        acceptance_criteria=("manifest exists", "transcript hash exists", "status is captured"),
        research_value="This makes command execution replayable in artifact evaluation.",
        product_value="This gives maintainers a deterministic dry-run and run path.",
        status="synthetic test fixture",
    )


class ProductRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = ProductEvidenceApi(REPO_ROOT)
        self.tmp = Path(tempfile.mkdtemp(prefix="pqcp-runner-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dry_run_writes_manifest_and_transcript(self) -> None:
        selection = self.api.select_experiments(profile="fast", limit=2)
        manifest = self.api.run_experiments(selection=selection, output_root=self.tmp, dry_run=True, timeout_seconds=30)
        self.assertTrue(manifest.passed(), manifest.to_dict())
        self.assertTrue((self.tmp / "run-manifest.json").exists())
        self.assertEqual(len(manifest.results), len(manifest.plans))
        for result in manifest.results:
            self.assertEqual(result.status, "planned")
            self.assertEqual(len(result.transcript_sha256), 64)

    def test_execute_success_command(self) -> None:
        selection = ExperimentSelection((synthetic_experiment("python3 -c 'print(42)'"),), {"fixture": True})
        manifest = self.api.run_experiments(selection=selection, output_root=self.tmp / "success", dry_run=False, timeout_seconds=30)
        self.assertTrue(manifest.passed(), manifest.to_dict())
        self.assertEqual(manifest.results[0].returncode, 0)
        self.assertEqual(manifest.results[0].status, "pass")

    def test_execute_failure_command_reports_error(self) -> None:
        selection = ExperimentSelection((synthetic_experiment("python3 -c 'raise SystemExit(7)'"),), {"fixture": True})
        manifest = self.api.run_experiments(selection=selection, output_root=self.tmp / "fail", dry_run=False, timeout_seconds=30)
        self.assertFalse(manifest.passed())
        self.assertEqual(manifest.results[0].returncode, 7)
        self.assertEqual(manifest.results[0].status, "fail")

    def test_missing_input_becomes_manifest_diagnostic(self) -> None:
        experiment = synthetic_experiment("python3 -c 'print(1)'")
        broken = ExperimentSpec(
            id=experiment.id,
            category=experiment.category,
            objective=experiment.objective,
            repository_inputs=("does/not/exist.txt",),
            commands=experiment.commands,
            expected_outputs=experiment.expected_outputs,
            positive_control=experiment.positive_control,
            negative_control=experiment.negative_control,
            acceptance_criteria=experiment.acceptance_criteria,
            research_value=experiment.research_value,
            product_value=experiment.product_value,
            status=experiment.status,
        )
        manifest = self.api.run_experiments(selection=ExperimentSelection((broken,), {}), output_root=self.tmp / "missing", dry_run=True)
        self.assertFalse(manifest.passed())
        self.assertTrue(any(diag.code == "experiment_missing_input" for diag in manifest.diagnostics))


if __name__ == "__main__":
    unittest.main()
