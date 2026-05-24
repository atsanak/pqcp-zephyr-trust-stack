#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
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


from pqcp_product.reproducibility import capture_reproducibility_snapshot, validate_manifest_replay


class ProductReproducibilityTests(unittest.TestCase):
    def test_snapshot_records_required_scripts(self) -> None:
        snapshot = capture_reproducibility_snapshot(REPO_ROOT)
        self.assertTrue(snapshot.passed(), snapshot.to_dict())
        self.assertIn("scripts/release_check.py", snapshot.required_scripts)
        self.assertIsNotNone(snapshot.python_version)

    def test_manifest_replay_validator_accepts_minimal_manifest(self) -> None:
        payload = {
            "schema_version": 1,
            "run_id": "fixture",
            "output_root": "/tmp/fixture",
            "selection": {},
            "plans": [],
            "results": [{"transcript_sha256": "a" * 64, "status": "planned"}],
        }
        self.assertEqual(validate_manifest_replay(payload), [])

    def test_manifest_replay_validator_rejects_missing_hash(self) -> None:
        payload = {
            "schema_version": 1,
            "run_id": "fixture",
            "output_root": "/tmp/fixture",
            "selection": {},
            "plans": [],
            "results": [{"status": "planned"}],
        }
        failures = validate_manifest_replay(payload)
        self.assertTrue(any("transcript_sha256" in item for item in failures))


if __name__ == "__main__":
    unittest.main()
