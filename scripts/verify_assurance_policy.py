#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Verify a PQC Assurance Passport against a partner-review policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_POLICY = SCRIPT_DIR / "pqc_assurance_policy.json"
PREDICATE_TYPE = (
    "https://github.com/atsana01/pqcp-zephyr-trust-stack/"
    "attestations/pqc-assurance/v1"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify PQC assurance ledger, CBOM, and attestation policy."
    )
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--cbom", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--release-manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    result: dict[str, str] = {}
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and isinstance(prop.get("name"), str):
            result[prop["name"]] = str(prop.get("value", ""))
    return result


def subject_map(attestation: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for subject in attestation.get("subject") or []:
        if not isinstance(subject, dict):
            continue
        name = subject.get("name")
        digest = subject.get("digest")
        if isinstance(name, str) and isinstance(digest, dict):
            sha = digest.get("sha256")
            if isinstance(sha, str):
                result[name] = sha
    return result


def check_required_claims(
    *,
    policy: dict[str, Any],
    ledger: dict[str, Any],
    failures: list[str],
    checks: list[dict[str, Any]],
) -> None:
    claims = {
        claim.get("id"): claim
        for claim in ledger.get("claims") or []
        if isinstance(claim, dict) and isinstance(claim.get("id"), str)
    }
    allowed_na = set(policy.get("allow_not_applicable_claim_ids") or [])
    for claim_id in policy.get("required_claim_ids") or []:
        claim = claims.get(claim_id)
        if claim is None:
            failures.append(f"required claim missing: {claim_id}")
            checks.append({"check": "claim", "id": claim_id, "passed": False})
            continue
        status = claim.get("status")
        ok = status == "pass" or (status == "not_applicable" and claim_id in allowed_na)
        checks.append({"check": "claim", "id": claim_id, "status": status, "passed": ok})
        if not ok:
            failures.append(f"required claim {claim_id} has status {status!r}")


def check_cbom(
    *,
    policy: dict[str, Any],
    cbom: dict[str, Any],
    failures: list[str],
    checks: list[dict[str, Any]],
) -> None:
    if cbom.get("bomFormat") != "CycloneDX":
        failures.append("CBOM bomFormat must be CycloneDX")
    if cbom.get("specVersion") != "1.7":
        failures.append(f"CBOM specVersion {cbom.get('specVersion')!r} != '1.7'")
    components = [
        component
        for component in cbom.get("components") or []
        if isinstance(component, dict)
    ]
    by_name = {str(component.get("name")): component for component in components}
    for name in policy.get("required_cbom_components") or []:
        ok = name in by_name
        checks.append({"check": "cbom_component", "name": name, "passed": ok})
        if not ok:
            failures.append(f"required CBOM component missing: {name}")

    for name in policy.get("forbidden_production_rng_components") or []:
        component = by_name.get(name)
        if component is None:
            continue
        props = properties_map(component)
        status = props.get("pqcp:production_status", "")
        ok = status == "test_only"
        checks.append(
            {
                "check": "deterministic_rng_not_production",
                "name": name,
                "production_status": status,
                "passed": ok,
            }
        )
        if not ok:
            failures.append(
                f"{name} must be marked pqcp:production_status=test_only, found {status!r}"
            )


def check_consistency(
    *,
    ledger: dict[str, Any],
    cbom: dict[str, Any],
    attestation: dict[str, Any],
    manifest: dict[str, Any] | None,
    failures: list[str],
    checks: list[dict[str, Any]],
) -> None:
    metadata_component = (cbom.get("metadata") or {}).get("component") or {}
    cbom_props = properties_map(metadata_component)
    predicate = attestation.get("predicate") or {}
    assurance = predicate.get("pqcAssurance") or {}

    def norm(value: object) -> object:
        return None if value == "" else value

    expected = {
        "version": ledger.get("version"),
        "tag": ledger.get("tag"),
        "head_sha": norm(ledger.get("head_sha")),
        "dirty": str(ledger.get("dirty")).lower(),
    }
    observed = {
        "version": assurance.get("version") or metadata_component.get("version"),
        "tag": assurance.get("tag") or cbom_props.get("pqcp:tag"),
        "head_sha": norm(assurance.get("headSha") or cbom_props.get("pqcp:head_sha")),
        "dirty": str(assurance.get("dirty")).lower(),
    }
    if cbom_props.get("pqcp:dirty") is not None:
        observed["dirty"] = cbom_props.get("pqcp:dirty")

    if manifest:
        if manifest.get("version") != expected["version"]:
            failures.append(
                f"release manifest version {manifest.get('version')!r} != ledger {expected['version']!r}"
            )
        if manifest.get("tag") != expected["tag"]:
            failures.append(
                f"release manifest tag {manifest.get('tag')!r} != ledger {expected['tag']!r}"
            )
        if manifest.get("source_commit") != expected["head_sha"]:
            failures.append(
                f"release manifest source_commit {manifest.get('source_commit')!r} != ledger {expected['head_sha']!r}"
            )

    for key, expected_value in expected.items():
        observed_value = observed.get(key)
        ok = str(observed_value) == str(expected_value)
        checks.append(
            {
                "check": "metadata_consistency",
                "field": key,
                "expected": expected_value,
                "observed": observed_value,
                "passed": ok,
            }
        )
        if not ok:
            failures.append(
                f"metadata mismatch for {key}: observed {observed_value!r}, expected {expected_value!r}"
            )


def check_attestation_subjects(
    *,
    policy: dict[str, Any],
    attestation: dict[str, Any],
    known_paths: dict[str, Path],
    failures: list[str],
    checks: list[dict[str, Any]],
) -> None:
    if attestation.get("_type") != "https://in-toto.io/Statement/v1":
        failures.append(f"attestation _type {attestation.get('_type')!r} is not in-toto Statement/v1")
    if attestation.get("predicateType") != PREDICATE_TYPE:
        failures.append(f"attestation predicateType {attestation.get('predicateType')!r} != {PREDICATE_TYPE}")

    subjects = subject_map(attestation)
    for name in policy.get("required_attestation_subjects") or []:
        if name not in subjects:
            failures.append(f"attestation subject missing: {name}")
            checks.append({"check": "attestation_subject", "name": name, "passed": False})
            continue
        path = known_paths.get(name)
        if path is None:
            checks.append({"check": "attestation_subject", "name": name, "passed": True})
            continue
        actual = sha256_file(path)
        ok = actual == subjects[name]
        checks.append(
            {
                "check": "attestation_subject_hash",
                "name": name,
                "expected": subjects[name],
                "actual": actual,
                "passed": ok,
            }
        )
        if not ok:
            failures.append(f"attestation subject hash mismatch for {name}")


def verify_policy(
    *,
    policy_path: Path,
    ledger_path: Path,
    cbom_path: Path,
    attestation_path: Path,
    release_manifest_path: Path | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    policy = load_json(policy_path, "policy", failures)
    ledger = load_json(ledger_path, "assurance ledger", failures)
    cbom = load_json(cbom_path, "PQC CBOM", failures)
    attestation = load_json(attestation_path, "PQC attestation", failures)
    manifest = (
        load_json(release_manifest_path, "release manifest", failures)
        if release_manifest_path is not None
        else None
    )
    if not policy or not ledger or not cbom or not attestation:
        return {"schema_version": 1, "passed": False, "failures": failures, "checks": checks}

    if policy.get("schema_version") != 1:
        failures.append(f"unsupported policy schema_version={policy.get('schema_version')!r}")
    check_required_claims(policy=policy, ledger=ledger, failures=failures, checks=checks)
    check_cbom(policy=policy, cbom=cbom, failures=failures, checks=checks)
    check_consistency(
        ledger=ledger,
        cbom=cbom,
        attestation=attestation,
        manifest=manifest,
        failures=failures,
        checks=checks,
    )
    known_paths = {
        "assurance_ledger.json": ledger_path,
        "pqc_cbom.cdx.json": cbom_path,
        "pqc_attestation.intoto.json": attestation_path,
    }
    base = ledger_path.parent
    for name in policy.get("required_attestation_subjects") or []:
        if name == "release-manifest.json" and release_manifest_path is not None:
            known_paths[name] = release_manifest_path
        else:
            candidate = base / name
            if candidate.exists():
                known_paths[name] = candidate
    check_attestation_subjects(
        policy=policy,
        attestation=attestation,
        known_paths=known_paths,
        failures=failures,
        checks=checks,
    )
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy": str(policy_path),
        "passed": not failures,
        "failures": failures,
        "checks": checks,
    }


def main() -> int:
    args = parse_args()
    result = verify_policy(
        policy_path=args.policy.resolve(),
        ledger_path=args.ledger.resolve(),
        cbom_path=args.cbom.resolve(),
        attestation_path=args.attestation.resolve(),
        release_manifest_path=args.release_manifest.resolve() if args.release_manifest else None,
    )
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PQC assurance policy passed")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("PQC assurance policy failed:", file=sys.stderr)
    for failure in result["failures"]:
        print(f"  - {failure}", file=sys.stderr)
    print(f"  output: {args.output.resolve()}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
