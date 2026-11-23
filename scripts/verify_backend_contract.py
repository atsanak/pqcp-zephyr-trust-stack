#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify the release backend contract for native and experimental providers."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import verify_backend_currency  # noqa: E402

NATIVE_BACKENDS = {
    "mlkem-native": {
        "family": "ML-" + "KEM",
        "provider_family": "mlkem-native",
    },
    "mldsa-native": {
        "family": "ML-" + "DSA",
        "provider_family": "mldsa-native",
    },
}
LIBOQS_PROVIDER = "lib" + "oqs"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT)
    parser.add_argument("--west-manifest", type=Path)
    parser.add_argument(
        "--backend-currency-result",
        type=Path,
        help="Existing backend_currency_result.json to consume instead of re-running the scan.",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--require-initialized-submodules",
        action="store_true",
        help="Require ext/mlkem-native and ext/mldsa-native to be initialized local submodules.",
    )
    return parser.parse_args()


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"{label} not found: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"{label} root must be a JSON object")
    return raw


def backend_currency_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.backend_currency_result:
        return load_json(args.backend_currency_result.resolve(), "backend currency result")
    return verify_backend_currency.verify(
        argparse.Namespace(
            module_path=args.module_path.resolve(),
            west_manifest=args.west_manifest.resolve() if args.west_manifest else None,
            output=args.output.resolve(),
            check_upstream=False,
            require_initialized_submodules=args.require_initialized_submodules,
        )
    )


def backend_by_name(currency: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for row in currency.get("backends") or []:
        if isinstance(row, dict) and isinstance(row.get("name"), str):
            rows[row["name"]] = row
    return rows


def verify_contract(args: argparse.Namespace) -> dict[str, Any]:
    failures: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, Any]] = []
    currency = backend_currency_from_args(args)
    rows = backend_by_name(currency)
    implementation_policy = currency.get("implementation_policy")

    if currency.get("passed") is not True:
        failures.append("backend currency verification did not pass")
    if not isinstance(implementation_policy, dict):
        failures.append("backend currency result is missing implementation_policy")
    elif implementation_policy.get("passed") is not True:
        failures.append("implementation policy scan did not pass")

    pinned_native_shas: dict[str, str] = {}
    for backend_name, contract in NATIVE_BACKENDS.items():
        row = rows.get(backend_name)
        if row is None:
            failures.append(f"required native backend missing: {backend_name}")
            checks.append({"check": "native_backend_present", "backend": backend_name, "passed": False})
            continue
        revision = str(row.get("west_revision") or "")
        path = str(row.get("submodule_path") or "")
        row_failures = row.get("failures") if isinstance(row.get("failures"), list) else []
        passed = row.get("passed") is True and bool(revision)
        checks.append(
            {
                "check": "native_backend_pin",
                "backend": backend_name,
                "family": contract["family"],
                "provider_family": contract["provider_family"],
                "revision": revision,
                "submodule_path": path,
                "passed": passed,
            }
        )
        if not passed:
            failures.append(f"{backend_name} backend pin is not release-ready")
        if row_failures:
            failures.extend(f"{backend_name}: {failure}" for failure in row_failures)
        if revision:
            pinned_native_shas[backend_name] = revision

    denied = []
    if isinstance(implementation_policy, dict):
        denied = [
            item
            for item in implementation_policy.get("forbidden_references") or []
            if isinstance(item, dict)
        ]
    checks.append(
        {
            "check": "forbidden_provider_reference_scan",
            "scanned_files": (implementation_policy or {}).get("scanned_files"),
            "denied_reference_count": len(denied),
            "passed": len(denied) == 0,
        }
    )
    if denied:
        failures.append(f"forbidden provider references found: {len(denied)}")

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/verify_backend_contract.py",
        "module_path": str(args.module_path.resolve()),
        "passed": not failures,
        "contract": {
            "native_families": [
                {
                    "family": item["family"],
                    "required_provider_family": item["provider_family"],
                    "implementation_source": name,
                }
                for name, item in NATIVE_BACKENDS.items()
            ],
            "forbidden_provider_policy": "repo-owned implementation paths must not reference disallowed provider families",
            "liboqs_policy": {
                "provider_family": LIBOQS_PROVIDER,
                "allowed_scope": "schemes outside the native ML-KEM and ML-DSA families",
                "production_default": False,
            },
        },
        "native_backend_shas": pinned_native_shas,
        "implementation_policy": implementation_policy,
        "scanned_file_count": (implementation_policy or {}).get("scanned_files", 0),
        "denied_references": denied,
        "warnings": warnings + list(currency.get("warnings") or []),
        "failures": failures,
        "checks": checks,
    }


def main() -> int:
    args = parse_args()
    try:
        result = verify_contract(args)
    except (OSError, RuntimeError, json.JSONDecodeError) as exc:
        result = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "scripts/verify_backend_contract.py",
            "passed": False,
            "failures": [str(exc)],
            "checks": [],
        }
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result.get("passed"):
        print("PASS: backend contract verified")
        print(f"  output: {output}")
        return 0
    print("FAIL: backend contract verification failed", file=sys.stderr)
    for failure in result.get("failures", []):
        print(f"  - {failure}", file=sys.stderr)
    print(f"  output: {output}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
