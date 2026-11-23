#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay-check PQC reference values against a release evidence pack."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from generate_pqc_reference_values import canonical_digest_root, cbom_component_ids, required_claim_ids


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-values", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--cbom", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--assurance-digest", type=Path, required=True)
    parser.add_argument("--release-manifest", type=Path, required=True)
    parser.add_argument("--policy-result", type=Path, required=True)
    parser.add_argument("--profile-result", type=Path, required=True)
    parser.add_argument("--transcript-manifest", type=Path, required=True)
    parser.add_argument("--backend-contract", type=Path)
    parser.add_argument("--provider-scope-result", type=Path)
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
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        failures.append(f"{label} is not valid JSON: {exc}")
        return {}
    if not isinstance(payload, dict):
        failures.append(f"{label} root must be a JSON object")
        return {}
    return payload


def verify_reference(args: argparse.Namespace) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    reference = load_json(args.reference_values, "PQC reference values", failures)
    ledger = load_json(args.ledger, "assurance ledger", failures)
    cbom = load_json(args.cbom, "PQC CBOM", failures)
    attestation = load_json(args.attestation, "PQC attestation", failures)
    digest = load_json(args.assurance_digest, "PQC assurance digest", failures)
    manifest = load_json(args.release_manifest, "release manifest", failures)
    policy = load_json(args.policy_result, "PQC policy result", failures)
    profile = load_json(args.profile_result, "PQC assurance profile result", failures)
    transcript_manifest = load_json(args.transcript_manifest, "transcript manifest", failures)
    if not all((reference, ledger, cbom, attestation, digest, manifest, policy, profile, transcript_manifest)):
        return {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "passed": False,
            "checks": checks,
            "failures": failures,
        }

    if reference.get("schema_version") != 1:
        failures.append(f"unsupported reference schema_version={reference.get('schema_version')!r}")

    expected_fields = {
        "version": str(ledger.get("version") or manifest.get("version") or ""),
        "tag": str(ledger.get("tag") or manifest.get("tag") or ""),
        "head_sha": str(ledger.get("head_sha") or manifest.get("source_commit") or ""),
        "dirty": bool(ledger.get("dirty")),
        "zephyr_revision": manifest.get("zephyr_revision")
        or (manifest.get("dependencies") or {}).get("zephyr"),
        "sdk_version": manifest.get("sdk_version") or "unknown",
    }
    for field, expected in expected_fields.items():
        observed = reference.get(field)
        ok = observed == expected
        checks.append({"check": "metadata", "field": field, "expected": expected, "observed": observed, "passed": ok})
        if not ok:
            failures.append(f"reference {field} mismatch: {observed!r} != {expected!r}")

    expected_root = canonical_digest_root(digest)
    ok = reference.get("expected_firmware_digest_root") == expected_root
    checks.append({"check": "firmware_digest_root", "passed": ok})
    if not ok:
        failures.append("reference firmware digest root is stale")

    artifact_inputs = {
        "assurance_ledger.json": args.ledger,
        "pqc_cbom.cdx.json": args.cbom,
        "pqc_attestation.intoto.json": args.attestation,
        "pqc_assurance_digest.json": args.assurance_digest,
        "release_manifest.json": args.release_manifest,
        "pqc_policy_result.json": args.policy_result,
        "pqc_assurance_profile_result.json": args.profile_result,
        "transcripts/evidence_transcript_manifest.json": args.transcript_manifest,
    }
    backend_contract = getattr(args, "backend_contract", None)
    provider_scope_result = getattr(args, "provider_scope_result", None)
    if backend_contract:
        artifact_inputs["backend_contract_result.json"] = backend_contract
    if provider_scope_result:
        artifact_inputs["provider_scope_result.json"] = provider_scope_result
    artifact_hashes = reference.get("artifact_hashes") if isinstance(reference.get("artifact_hashes"), dict) else {}
    for name, path in artifact_inputs.items():
        entry = artifact_hashes.get(name)
        if not isinstance(entry, dict):
            failures.append(f"reference artifact hash missing: {name}")
            checks.append({"check": "artifact_hash", "name": name, "passed": False})
            continue
        actual = sha256_file(path)
        ok = entry.get("sha256") == actual
        checks.append({"check": "artifact_hash", "name": name, "passed": ok})
        if not ok:
            failures.append(f"reference artifact hash mismatch: {name}")

    actual_claims = set(required_claim_ids(ledger))
    ref_claims = set(str(item) for item in reference.get("required_claim_ids") or [])
    missing_claims = sorted(actual_claims - ref_claims)
    checks.append({"check": "required_claim_ids", "missing": missing_claims, "passed": not missing_claims})
    if missing_claims:
        failures.append("reference missing required claim id(s): " + ", ".join(missing_claims))

    actual_components = set(cbom_component_ids(cbom))
    ref_components = set(str(item) for item in reference.get("cbom_component_ids") or [])
    missing_components = sorted(actual_components - ref_components)
    checks.append({"check": "cbom_component_ids", "missing": missing_components, "passed": not missing_components})
    if missing_components:
        failures.append("reference missing CBOM component id(s): " + ", ".join(missing_components))

    for label, payload in (("policy result", policy), ("profile result", profile)):
        ok = payload.get("passed") is True
        checks.append({"check": "source_result_passed", "label": label, "passed": ok})
        if not ok:
            failures.append(f"{label} did not pass")

    ok = len(attestation.get("subject") or []) >= int(reference.get("attestation_subject_count") or 0)
    checks.append({"check": "attestation_subject_count", "passed": ok})
    if not ok:
        failures.append("attestation subject count is lower than the reference value")

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": not failures,
        "checks": checks,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    result = verify_reference(args)
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: PQC reference values verified")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("FAIL: PQC reference values verification failed", file=sys.stderr)
    for failure in result["failures"]:
        print(f"  - {failure}", file=sys.stderr)
    print(f"  output: {args.output.resolve()}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
