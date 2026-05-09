#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Verify that post-ledger Passport claims are closed by generated artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


POST_LEDGER_CLAIMS = {
    "supply_chain.pqc_assurance_attestation": "PQC assurance attestation",
    "release.policy_pass": "PQC assurance policy result",
    "firmware.assurance_digest_manifest": "PQC assurance digest manifest",
    "firmware.assurance_digest_embeddable": "firmware assurance digest header",
    "supply_chain.assurance_profile_policy": "PQC assurance profile result",
    "supply_chain.evidence_quality_index": "PQC evidence quality result",
    "crypto_agility.profile_separation": "PQC assurance profile result",
    "release.migration_readiness": "PQC migration readiness report",
    "security.production_rng_policy": "PQC assurance profile result",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify post-ledger PQC Passport claim closure and digest consistency."
    )
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--assurance-digest", type=Path, required=True)
    parser.add_argument("--policy-result", type=Path, required=True)
    parser.add_argument("--assurance-profile-result", type=Path, required=True)
    parser.add_argument("--evidence-quality-result", type=Path, required=True)
    parser.add_argument("--migration-readiness-json", type=Path, required=True)
    parser.add_argument("--migration-readiness-md", type=Path, required=True)
    parser.add_argument("--firmware-digest-header", type=Path, required=True)
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


def require_file(path: Path, label: str, checks: list[dict[str, Any]], failures: list[str]) -> bool:
    ok = path.exists() and path.is_file() and path.stat().st_size > 0
    checks.append({"check": "artifact_exists", "label": label, "path": str(path), "passed": ok})
    if not ok:
        failures.append(f"{label} missing or empty: {path}")
    return ok


def ledger_claims(ledger: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(claim.get("id")): claim
        for claim in ledger.get("claims") or []
        if isinstance(claim, dict) and isinstance(claim.get("id"), str)
    }


def check_json_passed(
    payload: dict[str, Any],
    *,
    label: str,
    checks: list[dict[str, Any]],
    failures: list[str],
) -> None:
    ok = payload.get("passed") is True
    checks.append({"check": "json_passed", "label": label, "passed": ok})
    if not ok:
        failures.append(f"{label} did not pass")


def check_attestation(payload: dict[str, Any], checks: list[dict[str, Any]], failures: list[str]) -> None:
    ok = (
        payload.get("_type") == "https://in-toto.io/Statement/v1"
        and isinstance(payload.get("subject"), list)
        and bool(payload.get("subject"))
        and isinstance(payload.get("predicate"), dict)
    )
    checks.append({"check": "attestation_shape", "passed": ok})
    if not ok:
        failures.append("PQC assurance attestation has an unsupported shape")


def check_digest(
    digest: dict[str, Any],
    *,
    digest_path: Path,
    required_names: set[str],
    checks: list[dict[str, Any]],
    failures: list[str],
) -> None:
    artifacts = digest.get("artifacts")
    if digest.get("schema_version") != 1 or not isinstance(artifacts, list):
        failures.append("PQC assurance digest must be schema_version=1 with artifact entries")
        checks.append({"check": "digest_shape", "passed": False})
        return
    checks.append({"check": "digest_shape", "passed": True})

    seen: set[str] = set()
    base = digest_path.resolve().parent
    for item in artifacts:
        if not isinstance(item, dict):
            failures.append("PQC assurance digest artifact entry must be an object")
            checks.append({"check": "digest_artifact_entry", "passed": False})
            continue
        raw_path = item.get("path")
        expected_hash = item.get("sha256")
        if not isinstance(raw_path, str) or not raw_path:
            failures.append("PQC assurance digest artifact missing path")
            checks.append({"check": "digest_artifact_path", "passed": False})
            continue
        seen.add(Path(raw_path).name if Path(raw_path).is_absolute() else raw_path)
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = base / candidate
        if not candidate.exists() or not candidate.is_file():
            failures.append(f"PQC assurance digest artifact not found: {raw_path}")
            checks.append({"check": "digest_artifact_exists", "path": raw_path, "passed": False})
            continue
        actual_hash = sha256_file(candidate)
        ok = actual_hash == expected_hash
        checks.append({"check": "digest_artifact_hash", "path": raw_path, "passed": ok})
        if not ok:
            failures.append(
                f"PQC assurance digest hash mismatch for {raw_path}: "
                f"expected {expected_hash}, got {actual_hash}"
            )

    missing = sorted(required_names - seen)
    checks.append({"check": "digest_required_artifacts", "missing": missing, "passed": not missing})
    if missing:
        failures.append("PQC assurance digest missing required artifact(s): " + ", ".join(missing))


def verify_closure(args: argparse.Namespace) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    args.ledger = args.ledger.resolve()
    args.attestation = args.attestation.resolve()
    args.assurance_digest = args.assurance_digest.resolve()
    args.policy_result = args.policy_result.resolve()
    args.assurance_profile_result = args.assurance_profile_result.resolve()
    args.evidence_quality_result = args.evidence_quality_result.resolve()
    args.migration_readiness_json = args.migration_readiness_json.resolve()
    args.migration_readiness_md = args.migration_readiness_md.resolve()
    args.firmware_digest_header = args.firmware_digest_header.resolve()

    artifacts = {
        "PQC assurance attestation": args.attestation,
        "PQC assurance digest manifest": args.assurance_digest,
        "PQC assurance policy result": args.policy_result,
        "PQC assurance profile result": args.assurance_profile_result,
        "PQC evidence quality result": args.evidence_quality_result,
        "PQC migration readiness JSON": args.migration_readiness_json,
        "PQC migration readiness Markdown": args.migration_readiness_md,
        "firmware assurance digest header": args.firmware_digest_header,
    }
    for label, path in artifacts.items():
        require_file(path, label, checks, failures)

    ledger = load_json(args.ledger, "assurance ledger", failures)
    attestation = load_json(args.attestation, "PQC assurance attestation", failures)
    digest = load_json(args.assurance_digest, "PQC assurance digest manifest", failures)
    policy = load_json(args.policy_result, "PQC assurance policy result", failures)
    profile = load_json(args.assurance_profile_result, "PQC assurance profile result", failures)
    quality = load_json(args.evidence_quality_result, "PQC evidence quality result", failures)
    readiness = load_json(args.migration_readiness_json, "PQC migration readiness", failures)

    claims = ledger_claims(ledger)
    closed_claims: list[dict[str, Any]] = []
    for claim_id, label in POST_LEDGER_CLAIMS.items():
        claim = claims.get(claim_id)
        status = claim.get("status") if claim else None
        ok = claim is not None and status in ("pass", "not_applicable")
        checks.append({"check": "post_ledger_claim_present", "claim_id": claim_id, "status": status, "passed": ok})
        if not ok:
            failures.append(f"post-ledger claim is missing or failed in ledger: {claim_id}")
        closed_claims.append({"id": claim_id, "ledger_status": status, "evidence": label, "closed": ok})

    if attestation:
        check_attestation(attestation, checks, failures)
    if policy:
        check_json_passed(policy, label="PQC assurance policy result", checks=checks, failures=failures)
    if profile:
        check_json_passed(profile, label="PQC assurance profile result", checks=checks, failures=failures)
    if quality:
        check_json_passed(quality, label="PQC evidence quality result", checks=checks, failures=failures)
    if readiness:
        check_json_passed(readiness, label="PQC migration readiness", checks=checks, failures=failures)
        if args.migration_readiness_md.exists():
            body = args.migration_readiness_md.read_text(encoding="utf-8", errors="replace")
            missing_assets = [
                str(asset.get("name"))
                for asset in readiness.get("assets") or []
                if isinstance(asset, dict) and str(asset.get("name")) not in body
            ]
            checks.append({"check": "migration_markdown_assets", "missing": missing_assets, "passed": not missing_assets})
            if missing_assets:
                failures.append("migration readiness Markdown missing asset(s): " + ", ".join(sorted(missing_assets)))

    if args.firmware_digest_header.exists():
        header = args.firmware_digest_header.read_text(encoding="utf-8", errors="replace")
        for macro in ("PQCP_ASSURANCE_DIGEST_ROOT_SHA256", "PQCP_ASSURANCE_DIGEST_ARTIFACT_COUNT"):
            ok = macro in header
            checks.append({"check": "firmware_digest_header_macro", "macro": macro, "passed": ok})
            if not ok:
                failures.append(f"firmware assurance digest header missing {macro}")

    if digest:
        check_digest(
            digest,
            digest_path=args.assurance_digest,
            required_names={
                "assurance_ledger.json",
                "pqc_cbom.cdx.json",
                "pqc_attestation.intoto.json",
                "pqc_environment_result.json",
                "pqc_assurance_profile_result.json",
                "pqc_evidence_quality_result.json",
                "pqc_migration_readiness.json",
                "pqc_migration_readiness.md",
            },
            checks=checks,
            failures=failures,
        )

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": not failures,
        "summary": {
            "closed_claims": sum(1 for claim in closed_claims if claim["closed"]),
            "post_ledger_claims": len(closed_claims),
            "checks": len(checks),
            "failures": len(failures),
        },
        "closed_claims": closed_claims,
        "checks": checks,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    result = verify_closure(args)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: PQC Passport claim closure verified")
        print(f"  output: {output}")
        return 0
    print("FAIL: PQC Passport claim closure failed")
    for failure in result["failures"]:
        print(f"  - {failure}")
    print(f"  output: {output}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
