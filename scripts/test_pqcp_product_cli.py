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



class ProductCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pqcp-cli-test-"))
        self.cli = SCRIPT_DIR / "pqcp_tool.py"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, str(self.cli), *args], cwd=str(REPO_ROOT), text=True, capture_output=True, check=False)

    def test_validate_catalog_cli(self) -> None:
        out = self.tmp / "catalog.json"
        completed = self.run_cli("validate-catalog", "--output", str(out))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        payload = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(payload["passed"])

    def test_list_experiments_json_cli(self) -> None:
        completed = self.run_cli("list-experiments", "--profile", "fast", "--limit", "3", "--json")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["count"], 3)

    def test_plan_experiments_cli_writes_manifest(self) -> None:
        out = self.tmp / "plan"
        completed = self.run_cli("plan-experiments", "--profile", "fast", "--limit", "2", "--output-root", str(out))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertTrue((out / "run-manifest.json").exists())
        payload = json.loads((out / "run-manifest.json").read_text(encoding="utf-8"))
        self.assertTrue(payload["passed"])

    def test_environment_cli(self) -> None:
        out = self.tmp / "environment.json"
        completed = self.run_cli("environment", "--output", str(out))
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        payload = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(payload["passed"])


if __name__ == "__main__":
    unittest.main()
