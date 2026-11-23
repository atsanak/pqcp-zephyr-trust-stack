#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate ACVP negative-scenario coverage against a compatibility floor."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_SCENARIOS = SCRIPT_DIR / "acvp_negative_scenarios.json"
DEFAULT_FLOOR = SCRIPT_DIR / "acvp_negative_scenario_floor.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail if ACVP negative scenarios are removed, weakened, or malformed."
    )
    parser.add_argument("--scenarios", type=Path, default=DEFAULT_SCENARIOS)
    parser.add_argument("--floor", type=Path, default=DEFAULT_FLOOR)
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON validation result for release evidence packs.",
    )
    return parser.parse_args()


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"{label} not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise RuntimeError(f"{label} root must be a JSON object: {path}")
    return raw


def expand_command(case: dict[str, Any]) -> str:
    """Return the wire command, supporting compact repeated-hex fixtures."""
    command = case.get("command")
    if not isinstance(command, str) or not command:
        raise RuntimeError(f"case {case.get('name', '<unnamed>')} must include a command")

    repeat = case.get("repeat_hex")
    if repeat is None:
        return command
    if not isinstance(repeat, dict):
        raise RuntimeError(f"case {case.get('name')} repeat_hex must be an object")
    byte = repeat.get("byte", "00")
    count = repeat.get("count")
    if not isinstance(byte, str) or len(byte) != 2:
        raise RuntimeError(f"case {case.get('name')} repeat_hex.byte must be two hex chars")
    try:
        int(byte, 16)
    except ValueError as exc:
        raise RuntimeError(f"case {case.get('name')} repeat_hex.byte must be hex") from exc
    if not isinstance(count, int) or count < 0:
        raise RuntimeError(f"case {case.get('name')} repeat_hex.count must be a non-negative integer")
    return command + (byte.lower() * count)


def iter_expected_errors(scenarios: dict[str, Any]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    raw_scenarios = scenarios.get("scenarios")
    if not isinstance(raw_scenarios, list) or not raw_scenarios:
        raise RuntimeError("scenarios must contain a non-empty 'scenarios' list")
    for scenario_index, scenario in enumerate(raw_scenarios, start=1):
        if not isinstance(scenario, dict):
            raise RuntimeError(f"scenarios[{scenario_index}] must be an object")
        expected_errors = scenario.get("expected_errors")
        if not isinstance(expected_errors, list) or not expected_errors:
            raise RuntimeError(f"scenarios[{scenario_index}].expected_errors must be a non-empty list")
        for case in expected_errors:
            if not isinstance(case, dict):
                raise RuntimeError(f"scenarios[{scenario_index}].expected_errors contains a non-object case")
            cases.append(case)
    return cases


def validate(scenarios_path: Path, floor_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    scenarios = load_json(scenarios_path, "ACVP negative scenarios")
    floor = load_json(floor_path, "ACVP negative scenario floor")
    cases = iter_expected_errors(scenarios)

    by_name: dict[str, dict[str, Any]] = {}
    for case in cases:
        name = case.get("name")
        response = case.get("response")
        if not isinstance(name, str) or not name:
            failures.append("negative scenario case missing non-empty name")
            continue
        if name in by_name:
            failures.append(f"duplicate negative scenario name: {name}")
            continue
        by_name[name] = case
        if not isinstance(response, str) or not response:
            failures.append(f"{name}: missing response")
        elif not (
            response.startswith("ERROR:")
            or response == "RESULT:INVALID"
            or (case.get("kind") == "recovery" and response == "RESULT:OK")
        ):
            failures.append(
                f"{name}: response must be ERROR:* or RESULT:INVALID "
                f"(RESULT:OK is allowed only for kind=recovery), got {response!r}"
            )
        try:
            expanded = expand_command(case)
            if not expanded:
                failures.append(f"{name}: expanded command is empty")
        except RuntimeError as exc:
            failures.append(str(exc))

    required_cases = floor.get("required_cases")
    if not isinstance(required_cases, list) or not required_cases:
        failures.append("floor required_cases must be a non-empty list")
    else:
        for required in required_cases:
            if not isinstance(required, dict):
                failures.append("floor required case must be an object")
                continue
            name = required.get("name")
            expected_response = required.get("response")
            case = by_name.get(str(name))
            if case is None:
                failures.append(f"floor scenario missing: {name}")
                continue
            if case.get("response") != expected_response:
                failures.append(
                    f"{name}: response weakened or changed: {case.get('response')!r} != {expected_response!r}"
                )
            if required.get("append_newline") is False:
                if case.get("append_newline") is not False:
                    failures.append(f"{name}: timeout floor case must keep append_newline=false")
                if case.get("response") != "ERROR:TIMEOUT":
                    failures.append(f"{name}: timeout floor case must keep ERROR:TIMEOUT")

    categories = floor.get("required_categories")
    if isinstance(categories, dict):
        for category, names in categories.items():
            if not isinstance(names, list) or not names:
                failures.append(f"floor category {category} must contain at least one case")
                continue
            present = [name for name in names if name in by_name]
            if not present:
                failures.append(f"floor category {category} has no surviving scenarios")

    return {
        "schema_version": 1,
        "scenarios": str(scenarios_path),
        "floor": str(floor_path),
        "passed": not failures,
        "scenario_count": len(by_name),
        "case_count": len(by_name),
        "floor_count": len(floor.get("required_cases") or []),
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    try:
        result = validate(args.scenarios.resolve(), args.floor.resolve())
    except RuntimeError as exc:
        result = {
            "schema_version": 1,
            "scenarios": str(args.scenarios),
            "floor": str(args.floor),
            "passed": False,
            "scenario_count": 0,
            "case_count": 0,
            "floor_count": 0,
            "failures": [str(exc)],
        }

    if args.output:
        args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
        args.output.resolve().write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if result["passed"]:
        print(
            f"ACVP negative scenario floor passed: {result['case_count']} cases, "
            f"{result['floor_count']} floor cases"
        )
        return 0

    print("ACVP negative scenario floor failed:", file=sys.stderr)
    for failure in result["failures"]:
        print(f"  - {failure}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
