#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Verify release environment metadata across west, workflows, manifest, and CBOM."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from prepare_release_bundle import parse_west_dependencies


ENV_RE = re.compile(r"^\s*(ZEPHYR_REF|ZEPHYR_SDK_VERSION):\s*(?P<value>.+?)\s*(?:#.*)?$", re.MULTILINE)
QUOTED_VALUE_RE = re.compile(r"[\"']([^\"']+)[\"']")
PINNED_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check Zephyr/SDK release metadata consistency without running builds."
    )
    parser.add_argument("--module-path", type=Path, required=True)
    parser.add_argument("--release-manifest", type=Path)
    parser.add_argument("--cbom", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def load_json(path: Path, label: str, failures: list[str]) -> dict[str, Any]:
    if not path.exists():
        failures.append(f"{label} not found: {path}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        failures.append(f"{label} is not valid JSON: {exc}")
        return {}
    if not isinstance(payload, dict):
        failures.append(f"{label} root must be a JSON object")
        return {}
    return payload


def workflow_environment(module_path: Path) -> dict[str, list[dict[str, str]]]:
    values: dict[str, list[dict[str, str]]] = {"ZEPHYR_REF": [], "ZEPHYR_SDK_VERSION": []}
    workflow_dir = module_path / ".github" / "workflows"
    for path in sorted(workflow_dir.glob("*.yml")) + sorted(workflow_dir.glob("*.yaml")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in ENV_RE.finditer(text):
            key = match.group(1)
            value = normalize_workflow_value(match.group("value"))
            values[key].append({"path": str(path.relative_to(module_path)), "value": value})
    return values


def normalize_workflow_value(raw: str) -> str:
    value = raw.strip()
    if value.startswith("${{"):
        quoted = QUOTED_VALUE_RE.findall(value)
        if quoted:
            return quoted[-1].strip()
        return value
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1].strip()
    return value.strip()


def unique_values(entries: list[dict[str, str]]) -> set[str]:
    return {entry["value"] for entry in entries}


def cbom_component_versions(cbom: dict[str, Any]) -> dict[str, str]:
    versions: dict[str, str] = {}
    for component in cbom.get("components") or []:
        if isinstance(component, dict) and isinstance(component.get("name"), str):
            versions[component["name"]] = str(component.get("version", ""))
    return versions


def verify_environment(
    *,
    module_path: Path,
    release_manifest_path: Path | None,
    cbom_path: Path | None,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    module_path = module_path.resolve()

    west_dependencies = parse_west_dependencies(module_path)
    workflow_values = workflow_environment(module_path)
    manifest: dict[str, Any] = {}
    cbom: dict[str, Any] = {}
    if release_manifest_path is not None:
        manifest = load_json(release_manifest_path.resolve(), "release manifest", failures)
    if cbom_path is not None:
        cbom = load_json(cbom_path.resolve(), "PQC CBOM", failures)

    zephyr_revision = west_dependencies.get("zephyr", "")
    zephyr_pinned = bool(PINNED_SHA_RE.match(zephyr_revision))
    checks.append({"check": "west_zephyr_revision_pinned_sha", "value": zephyr_revision, "passed": zephyr_pinned})
    if not zephyr_pinned:
        failures.append(f"west.yml Zephyr revision must be a pinned 40-character SHA, got {zephyr_revision!r}")

    for name in ("mlkem-native", "mldsa-native"):
        revision = west_dependencies.get(name, "")
        pinned = bool(PINNED_SHA_RE.match(revision))
        checks.append({"check": "west_dependency_pinned_sha", "dependency": name, "value": revision, "passed": pinned})
        if not pinned:
            failures.append(f"west.yml {name} revision must be a pinned 40-character SHA, got {revision!r}")

    for key in ("ZEPHYR_REF", "ZEPHYR_SDK_VERSION"):
        values = unique_values(workflow_values[key])
        present = bool(values)
        consistent = len(values) == 1
        checks.append({"check": "workflow_env_present", "key": key, "passed": present})
        checks.append({"check": "workflow_env_consistent", "key": key, "values": sorted(values), "passed": consistent})
        if not present:
            failures.append(f"no workflow defines {key}")
        elif not consistent:
            failures.append(f"workflow {key} values disagree: {', '.join(sorted(values))}")

    manifest_deps = manifest.get("dependencies") if isinstance(manifest.get("dependencies"), dict) else {}
    for name, revision in west_dependencies.items():
        manifest_revision = str(manifest_deps.get(name, ""))
        if not manifest:
            continue
        ok = manifest_revision == revision
        checks.append(
            {
                "check": "release_manifest_dependency_matches_west",
                "dependency": name,
                "west": revision,
                "manifest": manifest_revision,
                "passed": ok,
            }
        )
        if not ok:
            failures.append(f"release manifest dependency {name}={manifest_revision!r} does not match west.yml {revision!r}")

    components = cbom_component_versions(cbom) if cbom else {}
    if cbom:
        for component, dependency in (
            ("Zephyr RTOS", "zephyr"),
            ("mlkem-native", "mlkem-native"),
            ("mldsa-native", "mldsa-native"),
        ):
            expected = west_dependencies.get(dependency, "")
            actual = components.get(component, "")
            ok = actual == expected
            checks.append(
                {
                    "check": "cbom_dependency_matches_west",
                    "component": component,
                    "expected": expected,
                    "actual": actual,
                    "passed": ok,
                }
            )
            if not ok:
                failures.append(f"CBOM component {component} version {actual!r} does not match west.yml {expected!r}")
        sdk_values = unique_values(workflow_values["ZEPHYR_SDK_VERSION"])
        if len(sdk_values) == 1:
            expected_sdk = next(iter(sdk_values))
            actual_sdk = components.get("Zephyr SDK", "")
            ok = actual_sdk == expected_sdk
            checks.append(
                {
                    "check": "cbom_sdk_matches_workflow",
                    "expected": expected_sdk,
                    "actual": actual_sdk,
                    "passed": ok,
                }
            )
            if not ok:
                failures.append(f"CBOM Zephyr SDK version {actual_sdk!r} does not match workflow {expected_sdk!r}")

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": not failures,
        "summary": {
            "west_dependencies": len(west_dependencies),
            "workflow_zephyr_refs": sorted(unique_values(workflow_values["ZEPHYR_REF"])),
            "workflow_sdk_versions": sorted(unique_values(workflow_values["ZEPHYR_SDK_VERSION"])),
            "checks": len(checks),
            "failures": len(failures),
        },
        "west_dependencies": west_dependencies,
        "workflow_environment": workflow_values,
        "checks": checks,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    result = verify_environment(
        module_path=args.module_path,
        release_manifest_path=args.release_manifest,
        cbom_path=args.cbom,
    )
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: release environment metadata is consistent")
        print(f"  output: {output}")
        return 0
    print("FAIL: release environment metadata is inconsistent")
    for failure in result["failures"]:
        print(f"  - {failure}")
    print(f"  output: {output}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
