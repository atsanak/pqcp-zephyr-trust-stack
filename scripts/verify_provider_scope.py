#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Verify provider-scope metadata across CBOM and backend-contract artifacts."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LIBOQS_PROVIDER = "lib" + "oqs"
MLKEM_RE = re.compile(r"ML[-_ ]?KEM|MLKEM|Kyber", re.IGNORECASE)
MLDSA_RE = re.compile(r"ML[-_ ]?DSA|MLDSA|Dilithium", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cbom", type=Path, required=True)
    parser.add_argument("--backend-contract", type=Path, required=True)
    parser.add_argument("--liboqs-inventory", type=Path)
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


def properties_map(component: dict[str, Any]) -> dict[str, str]:
    props: dict[str, str] = {}
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and isinstance(prop.get("name"), str):
            props[prop["name"]] = str(prop.get("value", ""))
    return props


def component_rows(cbom: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in cbom.get("components") or [] if isinstance(item, dict)]


def bool_prop(props: dict[str, str], key: str) -> bool:
    return props.get(key, "").strip().lower() == "true"


def verify_scope(args: argparse.Namespace) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    cbom = load_json(args.cbom.resolve(), "PQC CBOM", failures)
    contract = load_json(args.backend_contract.resolve(), "backend contract result", failures)
    inventory = load_json(args.liboqs_inventory.resolve(), "liboqs inventory", failures) if args.liboqs_inventory else {}

    if contract and contract.get("passed") is not True:
        failures.append("backend contract result did not pass")
    if inventory and inventory.get("passed") is not True:
        failures.append("liboqs inventory did not pass")

    for component in component_rows(cbom):
        name = str(component.get("name") or "")
        component_type = str(component.get("type") or "")
        props = properties_map(component)
        provider = props.get("pqcp:provider_family", "")
        implementation_source = props.get("pqcp:implementation_source", "")
        production_allowed = bool_prop(props, "pqcp:production_allowed")
        native_required = bool_prop(props, "pqcp:native_required")
        external_allowed = bool_prop(props, "pqcp:liboqs_allowed")
        if component_type != "cryptographic-asset":
            checks.append({"check": "non_crypto_component_skipped", "component": name, "type": component_type, "passed": True})
            continue

        if MLKEM_RE.search(name):
            ok = provider == "mlkem-native" and native_required and not external_allowed
            checks.append({"check": "native_kem_scope", "component": name, "provider_family": provider, "passed": ok})
            if not ok:
                failures.append(f"{name} must use provider_family=mlkem-native with native_required=true")
        elif MLDSA_RE.search(name):
            ok = provider == "mldsa-native" and native_required and not external_allowed
            checks.append({"check": "native_signature_scope", "component": name, "provider_family": provider, "passed": ok})
            if not ok:
                failures.append(f"{name} must use provider_family=mldsa-native with native_required=true")
        elif provider == LIBOQS_PROVIDER:
            ok = external_allowed and not production_allowed and implementation_source == "external_inventory"
            checks.append({"check": "external_provider_scope", "component": name, "passed": ok})
            if not ok:
                failures.append(f"{name} external provider component must be inventory-only and non-production")

    if inventory:
        for scheme in inventory.get("schemes") or []:
            if not isinstance(scheme, dict):
                failures.append("liboqs inventory scheme entry must be an object")
                continue
            name = str(scheme.get("name") or "")
            overlap = bool(scheme.get("native_family_overlap"))
            ok = not overlap and scheme.get("production_allowed") is False
            checks.append({"check": "inventory_scheme_scope", "scheme": name, "passed": ok})
            if not ok:
                failures.append(f"liboqs inventory scheme {name!r} overlaps native families or is production-enabled")

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/verify_provider_scope.py",
        "passed": not failures,
        "summary": {
            "checks": len(checks),
            "failures": len(failures),
            "cbom_components": len(component_rows(cbom)),
            "inventory_schemes": len(inventory.get("schemes") or []) if inventory else 0,
        },
        "checks": checks,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    result = verify_scope(args)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: provider scope verified")
        print(f"  output: {output}")
        return 0
    print("FAIL: provider scope verification failed", file=sys.stderr)
    for failure in result["failures"]:
        print(f"  - {failure}", file=sys.stderr)
    print(f"  output: {output}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
