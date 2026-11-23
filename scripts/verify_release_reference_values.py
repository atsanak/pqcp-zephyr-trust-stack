#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay-check release reference values against provider-scope evidence."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-values", type=Path, required=True)
    parser.add_argument("--release-manifest", type=Path, required=True)
    parser.add_argument("--backend-contract", type=Path, required=True)
    parser.add_argument("--provider-scope-result", type=Path, required=True)
    parser.add_argument("--cbom", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def load_json(path: Path, label: str, failures: list[str]) -> dict[str, Any]:
    if not path.exists():
        failures.append(f"{label} not found: {path}")
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        failures.append(f"{label} is not valid JSON: {exc}")
        return {}
    if not isinstance(raw, dict):
        failures.append(f"{label} root must be a JSON object")
        return {}
    return raw


def verify(args: argparse.Namespace) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    reference = load_json(args.reference_values.resolve(), "PQC reference values", failures)
    manifest = load_json(args.release_manifest.resolve(), "release manifest", failures)
    contract = load_json(args.backend_contract.resolve(), "backend contract result", failures)
    provider_scope = load_json(args.provider_scope_result.resolve(), "provider scope result", failures)
    cbom = load_json(args.cbom.resolve(), "PQC CBOM", failures)

    for field, manifest_field in (("version", "version"), ("tag", "tag"), ("head_sha", "source_commit")):
        expected = reference.get(field)
        observed = manifest.get(manifest_field)
        ok = expected == observed
        checks.append({"check": "release_metadata", "field": field, "expected": expected, "observed": observed, "passed": ok})
        if not ok:
            failures.append(f"reference {field} {expected!r} != manifest {manifest_field} {observed!r}")

    for label, payload in (("backend contract", contract), ("provider scope", provider_scope)):
        ok = payload.get("passed") is True
        checks.append({"check": "artifact_passed", "artifact": label, "passed": ok})
        if not ok:
            failures.append(f"{label} result did not pass")

    artifact_hashes = reference.get("artifact_hashes") if isinstance(reference.get("artifact_hashes"), dict) else {}
    for required in ("backend_contract_result.json", "provider_scope_result.json", "pqc_cbom.cdx.json"):
        ok = required in artifact_hashes
        checks.append({"check": "reference_artifact_hash", "artifact": required, "passed": ok})
        if not ok:
            failures.append(f"reference values missing artifact hash for {required}")

    component_ids = set(reference.get("cbom_component_ids") or [])
    cbom_ids = {
        value
        for component in cbom.get("components") or []
        if isinstance(component, dict)
        for value in (component.get("bom-ref"), component.get("name"))
        if isinstance(value, str) and value
    }
    missing = sorted(item for item in cbom_ids if item not in component_ids)
    checks.append({"check": "cbom_component_id_coverage", "missing": missing, "passed": not missing})
    if missing:
        failures.append("reference values missing CBOM component id(s): " + ", ".join(missing))

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/verify_release_reference_values.py",
        "passed": not failures,
        "checks": checks,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    result = verify(args)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: release reference values replay verified")
        print(f"  output: {output}")
        return 0
    print("FAIL: release reference values replay failed", file=sys.stderr)
    for failure in result["failures"]:
        print(f"  - {failure}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
