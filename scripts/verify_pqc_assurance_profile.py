#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Verify profile-specific PQC asset policy against Passport artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_PROFILE = SCRIPT_DIR / "pqc_assurance_profile.json"
DEFAULT_TRACE_MAP = SCRIPT_DIR / "pqc_asset_trace_map.json"

POST_LEDGER_CLAIMS = {
    "release.policy_pass",
    "release.migration_readiness",
    "supply_chain.cbom_crypto_inventory",
    "supply_chain.pqc_assurance_attestation",
    "supply_chain.crypto_asset_traceability",
    "supply_chain.evidence_graph_integrity",
    "supply_chain.assurance_profile_policy",
    "supply_chain.evidence_quality_index",
    "crypto_agility.profile_separation",
    "firmware.assurance_digest_manifest",
    "firmware.assurance_digest_embeddable",
    "security.production_rng_policy",
}

PRODUCTION_PROFILES = {"mcu_minimal", "gateway"}
PRODUCTION_FORBIDDEN_LIFECYCLE = {"lab_only", "smoke_only", "test_only"}
ALLOWED_LIFECYCLE = {
    "default",
    "supported",
    "lab_only",
    "validation_only",
    "test_only",
    "smoke_only",
    "experimental_inventory",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--cbom", type=Path, required=True)
    parser.add_argument("--trace-map", type=Path, default=DEFAULT_TRACE_MAP)
    parser.add_argument("--policy-result", type=Path)
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


def string_list(value: Any, *, label: str, failures: list[str]) -> list[str]:
    if not isinstance(value, list) or not value:
        failures.append(f"{label} must be a non-empty list")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            failures.append(f"{label}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


def properties_map(component: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and isinstance(prop.get("name"), str):
            result[prop["name"]] = str(prop.get("value", ""))
    return result


def cbom_components(cbom: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(component.get("name")): component
        for component in cbom.get("components") or []
        if isinstance(component, dict) and isinstance(component.get("name"), str)
    }


def trace_assets(trace_map: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(asset.get("id")): asset
        for asset in trace_map.get("assets") or []
        if isinstance(asset, dict) and isinstance(asset.get("id"), str)
    }


def ledger_claims(ledger: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(claim.get("id")): claim
        for claim in ledger.get("claims") or []
        if isinstance(claim, dict) and isinstance(claim.get("id"), str)
    }


def csv_set(raw: str | None) -> set[str]:
    if not raw:
        return set()
    return {item.strip() for item in raw.split(",") if item.strip()}


def check_lifecycle_assets(
    *,
    profile: dict[str, Any],
    cbom_by_name: dict[str, dict[str, Any]],
    trace_by_id: dict[str, dict[str, Any]],
    failures: list[str],
    checks: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    lifecycle: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(profile.get("asset_lifecycle") or []):
        if not isinstance(item, dict):
            failures.append(f"asset_lifecycle[{index}] must be an object")
            continue
        asset_id = item.get("asset_id")
        if not isinstance(asset_id, str) or not asset_id:
            failures.append(f"asset_lifecycle[{index}] missing asset_id")
            continue
        if asset_id in lifecycle:
            failures.append(f"duplicate lifecycle asset_id: {asset_id}")
        lifecycle[asset_id] = item

        lifecycle_status = item.get("lifecycle_status")
        production_allowed = item.get("production_allowed")
        profile_support = string_list(
            item.get("profile_support"),
            label=f"{asset_id}.profile_support",
            failures=failures,
        )
        validation_scope = string_list(
            item.get("validation_scope"),
            label=f"{asset_id}.validation_scope",
            failures=failures,
        )
        if lifecycle_status not in ALLOWED_LIFECYCLE:
            failures.append(f"{asset_id} lifecycle_status {lifecycle_status!r} is unsupported")
        if not isinstance(production_allowed, bool):
            failures.append(f"{asset_id} production_allowed must be boolean")
        if lifecycle_status == "test_only" and production_allowed is True:
            failures.append(f"{asset_id} is test_only but production_allowed=true")

        trace_ok = asset_id in trace_by_id
        checks.append({"check": "trace_asset", "asset_id": asset_id, "passed": trace_ok})
        if not trace_ok:
            failures.append(f"{asset_id} not found in PQC asset trace map")

        component_name = item.get("cbom_component")
        if component_name is None:
            continue
        if not isinstance(component_name, str) or not component_name:
            failures.append(f"{asset_id} cbom_component must be null or non-empty string")
            continue
        component = cbom_by_name.get(component_name)
        component_ok = component is not None
        checks.append(
            {
                "check": "cbom_component",
                "asset_id": asset_id,
                "component": component_name,
                "passed": component_ok,
            }
        )
        if component is None:
            failures.append(f"{asset_id} CBOM component missing: {component_name}")
            continue
        props = properties_map(component)
        expected = {
            "pqcp:trace_asset_id": asset_id,
            "pqcp:lifecycle_status": str(lifecycle_status),
            "pqcp:production_allowed": str(bool(production_allowed)).lower(),
            "pqcp:profile_support": ",".join(profile_support),
            "pqcp:validation_scope": ",".join(validation_scope),
        }
        for prop_name, expected_value in expected.items():
            observed = props.get(prop_name)
            if prop_name in {"pqcp:profile_support", "pqcp:validation_scope"}:
                ok = csv_set(observed) == csv_set(expected_value)
            else:
                ok = observed == expected_value
            checks.append(
                {
                    "check": "cbom_profile_property",
                    "asset_id": asset_id,
                    "component": component_name,
                    "property": prop_name,
                    "expected": expected_value,
                    "observed": observed,
                    "passed": ok,
                }
            )
            if not ok:
                failures.append(
                    f"{component_name} {prop_name}={observed!r}, expected {expected_value!r}"
                )

    if not lifecycle:
        failures.append("asset_lifecycle must contain at least one asset")
    return lifecycle


def check_profiles(
    *,
    profile: dict[str, Any],
    lifecycle: dict[str, dict[str, Any]],
    claims: dict[str, dict[str, Any]],
    failures: list[str],
    checks: list[dict[str, Any]],
) -> None:
    seen_profiles: set[str] = set()
    profiles = profile.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        failures.append("profiles must be a non-empty list")
        return

    for entry in profiles:
        if not isinstance(entry, dict):
            failures.append("profile entry must be an object")
            continue
        profile_id = entry.get("id")
        if not isinstance(profile_id, str) or not profile_id:
            failures.append("profile entry missing id")
            continue
        if profile_id in seen_profiles:
            failures.append(f"duplicate profile id: {profile_id}")
        seen_profiles.add(profile_id)

        allowed = set(string_list(entry.get("allowed_asset_ids"), label=f"{profile_id}.allowed_asset_ids", failures=failures))
        forbidden = set(entry.get("forbidden_asset_ids") or [])
        test_only = set(entry.get("test_only_asset_ids") or [])
        required_claims = string_list(
            entry.get("required_claim_ids"),
            label=f"{profile_id}.required_claim_ids",
            failures=failures,
        )
        accepted_env = string_list(
            entry.get("accepted_environments"),
            label=f"{profile_id}.accepted_environments",
            failures=failures,
        )
        if not accepted_env:
            failures.append(f"{profile_id} must name at least one accepted environment")

        overlap = sorted(allowed & forbidden)
        if overlap:
            failures.append(f"{profile_id} assets both allowed and forbidden: {', '.join(overlap)}")

        for asset_id in sorted(allowed | forbidden | test_only):
            ok = asset_id in lifecycle
            checks.append({"check": "profile_asset_known", "profile": profile_id, "asset_id": asset_id, "passed": ok})
            if not ok:
                failures.append(f"{profile_id} references unknown asset {asset_id}")

        for asset_id in sorted(allowed):
            asset = lifecycle.get(asset_id)
            if not asset:
                continue
            supported_profiles = set(asset.get("profile_support") or [])
            supported = profile_id in supported_profiles
            checks.append({"check": "profile_support", "profile": profile_id, "asset_id": asset_id, "passed": supported})
            if not supported:
                failures.append(f"{asset_id} is allowed by {profile_id} but does not list that profile")
            if profile_id in PRODUCTION_PROFILES and asset.get("lifecycle_status") in PRODUCTION_FORBIDDEN_LIFECYCLE:
                failures.append(
                    f"{profile_id} allows {asset.get('lifecycle_status')} asset {asset_id}"
                )

        if profile_id in PRODUCTION_PROFILES and "rng.deterministic_test" not in forbidden:
            failures.append(f"{profile_id} must explicitly forbid rng.deterministic_test")

        for claim_id in required_claims:
            claim = claims.get(claim_id)
            if claim is None:
                checks.append({"check": "profile_required_claim", "profile": profile_id, "claim_id": claim_id, "passed": False})
                failures.append(f"{profile_id} required claim missing from ledger: {claim_id}")
                continue
            status = claim.get("status")
            ok = status == "pass" or (status == "not_applicable" and claim_id in POST_LEDGER_CLAIMS)
            checks.append(
                {
                    "check": "profile_required_claim",
                    "profile": profile_id,
                    "claim_id": claim_id,
                    "status": status,
                    "passed": ok,
                }
            )
            if not ok:
                failures.append(f"{profile_id} required claim {claim_id} has status {status!r}")


def verify_profile(
    *,
    profile_path: Path = DEFAULT_PROFILE,
    ledger_path: Path,
    cbom_path: Path,
    trace_map_path: Path = DEFAULT_TRACE_MAP,
    policy_result_path: Path | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    profile = load_json(profile_path, "assurance profile", failures)
    ledger = load_json(ledger_path, "assurance ledger", failures)
    cbom = load_json(cbom_path, "PQC CBOM", failures)
    trace_map = load_json(trace_map_path, "PQC asset trace map", failures)
    policy_result = (
        load_json(policy_result_path, "PQC policy result", failures)
        if policy_result_path is not None and policy_result_path.exists()
        else None
    )
    if not profile or not ledger or not cbom or not trace_map:
        return {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "passed": False,
            "failures": failures,
            "checks": checks,
        }

    if profile.get("schema_version") != 1:
        failures.append(f"unsupported assurance profile schema_version={profile.get('schema_version')!r}")
    if trace_map.get("schema_version") != 1:
        failures.append(f"unsupported trace map schema_version={trace_map.get('schema_version')!r}")
    if cbom.get("bomFormat") != "CycloneDX":
        failures.append("CBOM bomFormat must be CycloneDX")

    lifecycle = check_lifecycle_assets(
        profile=profile,
        cbom_by_name=cbom_components(cbom),
        trace_by_id=trace_assets(trace_map),
        failures=failures,
        checks=checks,
    )
    check_profiles(
        profile=profile,
        lifecycle=lifecycle,
        claims=ledger_claims(ledger),
        failures=failures,
        checks=checks,
    )

    deterministic = lifecycle.get("rng.deterministic_test")
    if deterministic and deterministic.get("production_allowed") is not False:
        failures.append("rng.deterministic_test must never be production_allowed")

    if policy_result is not None:
        ok = policy_result.get("passed") is True
        checks.append({"check": "policy_result_passed", "passed": ok})
        if not ok:
            failures.append("provided policy result did not pass")

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profile": str(profile_path),
        "passed": not failures,
        "summary": {
            "profiles": len(profile.get("profiles") or []),
            "assets": len(lifecycle),
            "checks": len(checks),
            "failures": len(failures),
        },
        "failures": failures,
        "checks": checks,
    }


def main() -> int:
    args = parse_args()
    result = verify_profile(
        profile_path=args.profile.resolve(),
        ledger_path=args.ledger.resolve(),
        cbom_path=args.cbom.resolve(),
        trace_map_path=args.trace_map.resolve(),
        policy_result_path=args.policy_result.resolve() if args.policy_result else None,
    )
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PQC assurance profile passed")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("PQC assurance profile failed:", file=sys.stderr)
    for failure in result["failures"]:
        print(f"  - {failure}", file=sys.stderr)
    print(f"  output: {args.output.resolve()}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
