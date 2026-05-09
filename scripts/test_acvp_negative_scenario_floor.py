#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for ACVP negative-scenario floor validation."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import validate_acvp_negative_scenarios as validator


class ACVPNegativeScenarioFloorTests(unittest.TestCase):
    def write_json(self, path: Path, payload: dict) -> Path:
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return path

    def test_current_fixture_satisfies_floor(self) -> None:
        result = validator.validate(validator.DEFAULT_SCENARIOS, validator.DEFAULT_FLOOR)
        self.assertTrue(result["passed"], result["failures"])
        self.assertEqual(result["scenario_count"], result["case_count"])
        self.assertGreaterEqual(result["scenario_count"], result["floor_count"])

    def test_removing_timeout_partial_frame_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scenarios = json.loads(validator.DEFAULT_SCENARIOS.read_text(encoding="utf-8"))
            for scenario in scenarios["scenarios"]:
                scenario["expected_errors"] = [
                    item
                    for item in scenario["expected_errors"]
                    if item.get("name") != "timeout_partial_frame"
                ]
            result = validator.validate(
                self.write_json(root / "scenarios.json", scenarios),
                validator.DEFAULT_FLOOR,
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("timeout_partial_frame" in item for item in result["failures"]))

    def test_weakened_response_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scenarios = json.loads(validator.DEFAULT_SCENARIOS.read_text(encoding="utf-8"))
            changed = copy.deepcopy(scenarios)
            changed["scenarios"][0]["expected_errors"][0]["response"] = "ERROR:INVALID_CMD"
            result = validator.validate(
                self.write_json(root / "scenarios.json", changed),
                validator.DEFAULT_FLOOR,
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("INVALID_SEED_HEX" in item for item in result["failures"]))

    def test_duplicate_names_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scenarios = json.loads(validator.DEFAULT_SCENARIOS.read_text(encoding="utf-8"))
            duplicate = copy.deepcopy(scenarios["scenarios"][0]["expected_errors"][0])
            scenarios["scenarios"][0]["expected_errors"].append(duplicate)
            result = validator.validate(
                self.write_json(root / "scenarios.json", scenarios),
                validator.DEFAULT_FLOOR,
            )
            self.assertFalse(result["passed"])
            self.assertTrue(any("duplicate" in item for item in result["failures"]))

    def test_repeat_hex_expands_boundary_commands(self) -> None:
        case = {"name": "x", "command": "VERIFY:MLDSA:65:", "repeat_hex": {"byte": "00", "count": 3}}
        self.assertEqual(validator.expand_command(case), "VERIFY:MLDSA:65:000000")


if __name__ == "__main__":
    unittest.main(verbosity=2)
