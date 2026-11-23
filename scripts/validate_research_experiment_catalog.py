#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate the research/product experiment catalog.

The catalog is the bridge between the long-form audit and executable evidence.
Each entry must name a concrete repository input, an experiment objective, a
positive control, a negative control, expected outputs, and acceptance
criteria. This keeps the research roadmap grounded in runnable repository
work instead of becoming a prose-only wish list.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_CATALOG = SCRIPT_DIR / "research_experiment_catalog.json"

EXPERIMENT_ID_RE = re.compile(r"^[a-z][a-z0-9_]*(?:[.-][a-z0-9_]+)*$")
ALLOWED_CATEGORIES = {
    "claim_replay",
    "asset_traceability",
    "artifact_schema",
    "benchmark_methodology",
    "acvp_interop",
    "side_channel_smoke",
    "hardware_promotion",
    "product_packaging",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate the PQCP research/product experiment catalog."
    )
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT)
    parser.add_argument("--output", type=Path, help="Optional JSON validation result.")
    return parser.parse_args()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"missing catalog: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON in {path}: {exc}") from exc


def is_safe_relative(path: str) -> bool:
    parsed = Path(path)
    return not parsed.is_absolute() and ".." not in parsed.parts


def validate_string_list(
    *,
    value: Any,
    location: str,
    min_items: int,
    failures: list[str],
) -> list[str]:
    if not isinstance(value, list):
        failures.append(f"{location} must be a list")
        return []
    if len(value) < min_items:
        failures.append(f"{location} must contain at least {min_items} item(s)")
    out: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            failures.append(f"{location}[{index}] must be a non-empty string")
            continue
        out.append(item)
    return out


def validate_repository_inputs(
    *,
    module_path: Path,
    experiment_id: str,
    inputs: list[str],
    failures: list[str],
) -> None:
    for item in inputs:
        if not is_safe_relative(item):
            failures.append(f"{experiment_id}: repository input is not a safe relative path: {item}")
            continue
        resolved = module_path / item
        if not resolved.exists():
            failures.append(f"{experiment_id}: repository input does not exist: {item}")


def validate_experiment(
    *,
    module_path: Path,
    experiment: dict[str, Any],
    index: int,
    seen_ids: set[str],
    failures: list[str],
    warnings: list[str],
) -> None:
    location = f"experiments[{index}]"
    experiment_id = experiment.get("id")
    if not isinstance(experiment_id, str) or not EXPERIMENT_ID_RE.match(experiment_id):
        failures.append(f"{location}.id must be a stable experiment identifier")
        experiment_id = f"<invalid-{index}>"
    elif experiment_id in seen_ids:
        failures.append(f"{location}.id duplicates {experiment_id}")
    else:
        seen_ids.add(experiment_id)

    category = experiment.get("category")
    if category not in ALLOWED_CATEGORIES:
        failures.append(f"{experiment_id}: category {category!r} is not allowed")

    for key in (
        "objective",
        "research_value",
        "product_value",
        "positive_control",
        "negative_control",
        "status",
    ):
        value = experiment.get(key)
        if not isinstance(value, str) or len(value.split()) < 4:
            failures.append(f"{experiment_id}: {key} must be a meaningful sentence")

    inputs = validate_string_list(
        value=experiment.get("repository_inputs"),
        location=f"{experiment_id}.repository_inputs",
        min_items=1,
        failures=failures,
    )
    validate_repository_inputs(
        module_path=module_path,
        experiment_id=experiment_id,
        inputs=inputs,
        failures=failures,
    )
    commands = validate_string_list(
        value=experiment.get("commands"),
        location=f"{experiment_id}.commands",
        min_items=1,
        failures=failures,
    )
    validate_string_list(
        value=experiment.get("expected_outputs"),
        location=f"{experiment_id}.expected_outputs",
        min_items=1,
        failures=failures,
    )
    validate_string_list(
        value=experiment.get("acceptance_criteria"),
        location=f"{experiment_id}.acceptance_criteria",
        min_items=3,
        failures=failures,
    )

    if commands and not any("python3" in command or "west " in command for command in commands):
        warnings.append(f"{experiment_id}: no explicit python3/west command listed")
    if "remove" not in str(experiment.get("negative_control", "")).lower() and "corrupt" not in str(
        experiment.get("negative_control", "")
    ).lower() and "tamper" not in str(experiment.get("negative_control", "")).lower():
        warnings.append(f"{experiment_id}: negative control should name remove/corrupt/tamper action")


def validate_catalog(catalog: dict[str, Any], module_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    warnings: list[str] = []
    if catalog.get("schema_version") != 1:
        failures.append("schema_version must be 1")
    experiments = catalog.get("experiments")
    if not isinstance(experiments, list) or not experiments:
        failures.append("experiments must be a non-empty list")
        experiments = []
    seen_ids: set[str] = set()
    category_counts: dict[str, int] = {}
    for index, item in enumerate(experiments):
        if not isinstance(item, dict):
            failures.append(f"experiments[{index}] must be an object")
            continue
        validate_experiment(
            module_path=module_path,
            experiment=item,
            index=index,
            seen_ids=seen_ids,
            failures=failures,
            warnings=warnings,
        )
        category = item.get("category")
        if isinstance(category, str):
            category_counts[category] = category_counts.get(category, 0) + 1
    missing_categories = sorted(ALLOWED_CATEGORIES - set(category_counts))
    for category in missing_categories:
        warnings.append(f"category has no experiments: {category}")
    return {
        "schema_version": 1,
        "status": "pass" if not failures else "fail",
        "passed": not failures,
        "experiment_count": len(experiments),
        "category_counts": category_counts,
        "failure_count": len(failures),
        "warning_count": len(warnings),
        "failures": failures,
        "warnings": warnings,
    }


def main() -> int:
    args = parse_args()
    module_path = args.module_path.resolve()
    catalog_path = args.catalog if args.catalog.is_absolute() else module_path / args.catalog
    raw = load_json(catalog_path)
    if not isinstance(raw, dict):
        raise RuntimeError("catalog root must be a JSON object")
    result = validate_catalog(raw, module_path)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for failure in result["failures"]:
        print(f"ERROR: {failure}")
    for warning in result["warnings"]:
        print(f"WARN: {warning}")
    if result["passed"]:
        print(
            "PASS: research experiment catalog validated "
            f"({result['experiment_count']} experiment(s))"
        )
        return 0
    print(
        "FAIL: research experiment catalog validation failed "
        f"({result['failure_count']} failure(s), {result['warning_count']} warning(s))"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
