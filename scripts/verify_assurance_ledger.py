#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify a generated PQCP assurance ledger without rerunning Zephyr builds."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

VALID_STATUSES = {"pass", "fail", "not_applicable"}
SUPPORTED_LEDGER_SCHEMA_VERSIONS = (1, 2, 3, 4, 5, 6, 7)
SUPPORTED_CLAIMS_SCHEMA_VERSIONS = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20)
POST_LEDGER_CLAIMS = {
    "release.reference_values",
    "firmware.assurance_status_report",
    "supply_chain.slsa_build_provenance",
    "release.evidence_appraisal_profile",
    "firmware.device_evidence_token",
    "release.strict_partner_policy",
    "release.reference_provider_scope",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Replay-check a generated assurance_ledger.json/assurance_ledger.md "
            "pair by validating schema, claim coverage, artifact existence, and "
            "recorded SHA-256 values."
        )
    )
    parser.add_argument("ledger_json", type=Path, help="Path to assurance_ledger.json")
    parser.add_argument(
        "--markdown",
        type=Path,
        help="Path to assurance_ledger.md. Defaults to the JSON path with .md suffix.",
    )
    parser.add_argument(
        "--claims",
        type=Path,
        default=SCRIPT_DIR / "assurance_claims.json",
        help="Claim catalog used to check required claim coverage.",
    )
    parser.add_argument(
        "--module-path",
        type=Path,
        default=REPO_ROOT,
        help="Repository root used to resolve relative artifact paths.",
    )
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


def resolve_artifact_path(raw_path: object, *, ledger_path: Path, module_path: Path) -> Path | None:
    if not isinstance(raw_path, str) or not raw_path:
        return None
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate

    ledger_relative = (ledger_path.parent / candidate).resolve()
    if ledger_relative.exists():
        return ledger_relative
    return (module_path / candidate).resolve()


def load_required_claim_ids(
    path: Path,
    failures: list[str],
    *,
    max_schema_version: int | None = None,
) -> set[str]:
    catalog = load_json(path, "claim catalog", failures)
    if not catalog:
        return set()
    schema_version = catalog.get("schema_version")
    if schema_version not in SUPPORTED_CLAIMS_SCHEMA_VERSIONS:
        failures.append(
            f"claim catalog has unsupported schema_version={schema_version!r} "
            f"(supported: {list(SUPPORTED_CLAIMS_SCHEMA_VERSIONS)})"
        )
        return set()
    if schema_version == 1:
        print(
            f"[warn] {path} uses claims schema_version=1; this is the legacy claim "
            "set without per-primitive KAT/benchmark or ACVP negative/timeout claims. "
            "Replays of older evidence packs will pass with reduced coverage.",
            file=sys.stderr,
        )
    claims = catalog.get("claims")
    if not isinstance(claims, list):
        failures.append("claim catalog 'claims' must be a list")
        return set()
    required: set[str] = set()
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            failures.append(f"claim catalog entry {index} must be an object")
            continue
        claim_id = claim.get("id")
        if not isinstance(claim_id, str) or not claim_id:
            failures.append(f"claim catalog entry {index} is missing a string id")
            continue
        added_in = claim.get("schema_version_added", 1)
        if (
            max_schema_version is not None
            and isinstance(added_in, int)
            and added_in > max_schema_version
        ):
            continue
        if claim.get("required", True):
            required.add(claim_id)
    return required


def verify_summary(ledger: dict[str, Any], claims: list[dict[str, Any]], failures: list[str]) -> None:
    summary = ledger.get("summary")
    if not isinstance(summary, dict):
        failures.append("ledger summary must be an object")
        return
    actual = {
        "pass": sum(1 for claim in claims if claim.get("status") == "pass"),
        "fail": sum(1 for claim in claims if claim.get("status") == "fail"),
        "not_applicable": sum(
            1 for claim in claims if claim.get("status") == "not_applicable"
        ),
    }
    for key, expected in actual.items():
        if summary.get(key) != expected:
            failures.append(
                f"summary.{key}={summary.get(key)!r} does not match actual count {expected}"
            )


def verify_markdown(markdown_path: Path, claim_ids: set[str], failures: list[str]) -> None:
    if not markdown_path.exists():
        failures.append(f"ledger markdown not found: {markdown_path}")
        return
    markdown = markdown_path.read_text(encoding="utf-8")
    missing = sorted(claim_id for claim_id in claim_ids if claim_id not in markdown)
    if missing:
        failures.append(
            "ledger markdown is missing claim id(s): " + ", ".join(missing)
        )


def verify_artifacts(
    claims: list[dict[str, Any]],
    *,
    ledger_path: Path,
    module_path: Path,
    failures: list[str],
    allow_post_ledger_artifact_drift: bool = False,
) -> None:
    for claim in claims:
        claim_id = claim.get("id", "<unknown>")
        artifacts = claim.get("evidence_artifacts")
        if artifacts is None:
            failures.append(f"{claim_id}: missing evidence_artifacts list")
            continue
        if not isinstance(artifacts, list):
            failures.append(f"{claim_id}: evidence_artifacts must be a list")
            continue
        for index, item in enumerate(artifacts):
            if not isinstance(item, dict):
                failures.append(f"{claim_id}: artifact {index} must be an object")
                continue
            path = resolve_artifact_path(
                item.get("path"),
                ledger_path=ledger_path,
                module_path=module_path,
            )
            if path is None:
                failures.append(f"{claim_id}: artifact {index} is missing a path")
                continue
            recorded_exists = item.get("exists")
            actual_exists = path.exists()
            if recorded_exists is not actual_exists:
                if (
                    allow_post_ledger_artifact_drift
                    and claim_id in POST_LEDGER_CLAIMS
                    and recorded_exists is False
                    and actual_exists is True
                ):
                    continue
                failures.append(
                    f"{claim_id}: artifact {path} recorded exists={recorded_exists!r} "
                    f"but actual exists={actual_exists}"
                )
                continue
            if not actual_exists:
                continue
            expected_sha = item.get("sha256")
            if expected_sha is None:
                continue
            if not path.is_file():
                failures.append(f"{claim_id}: artifact {path} records sha256 but is not a file")
                continue
            actual_sha = sha256_file(path)
            if expected_sha != actual_sha:
                failures.append(
                    f"{claim_id}: artifact {path} sha256 mismatch: "
                    f"ledger={expected_sha} actual={actual_sha}"
                )


def verify_ledger(
    ledger_json: Path,
    *,
    markdown: Path | None = None,
    claims_path: Path = SCRIPT_DIR / "assurance_claims.json",
    module_path: Path = REPO_ROOT,
    allow_post_ledger_artifact_drift: bool = False,
) -> list[str]:
    failures: list[str] = []
    ledger_json = ledger_json.resolve()
    markdown_path = markdown.resolve() if markdown else ledger_json.with_suffix(".md")
    module_path = module_path.resolve()
    ledger = load_json(ledger_json, "assurance ledger", failures)
    if not ledger:
        return failures

    ledger_schema = ledger.get("schema_version")
    if ledger_schema not in SUPPORTED_LEDGER_SCHEMA_VERSIONS:
        failures.append(
            f"ledger has unsupported schema_version={ledger_schema!r} "
            f"(supported: {list(SUPPORTED_LEDGER_SCHEMA_VERSIONS)})"
        )
    elif ledger_schema == 1:
        print(
            f"[warn] {ledger_json} is a legacy schema_version=1 ledger; replay-only "
            "compatibility verification — re-generate with the current "
            "generate_assurance_ledger.py to capture per-primitive and ACVP claims.",
            file=sys.stderr,
        )
    required_claim_ids = load_required_claim_ids(
        claims_path.resolve(),
        failures,
        max_schema_version=ledger_schema if isinstance(ledger_schema, int) else None,
    )
    claims = ledger.get("claims")
    if not isinstance(claims, list) or not claims:
        failures.append("ledger claims must be a non-empty list")
        return failures

    typed_claims: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            failures.append(f"ledger claim {index} must be an object")
            continue
        typed_claims.append(claim)
        claim_id = claim.get("id")
        if not isinstance(claim_id, str) or not claim_id:
            failures.append(f"ledger claim {index} is missing a string id")
            continue
        if claim_id in seen:
            failures.append(f"ledger contains duplicate claim id {claim_id}")
        seen.add(claim_id)
        status = claim.get("status")
        if status not in VALID_STATUSES:
            failures.append(f"{claim_id}: invalid status {status!r}")
        if claim.get("required", True) and status == "fail":
            failures.append(f"{claim_id}: required claim failed: {claim.get('failure_reason')}")
        if status == "fail" and not claim.get("failure_reason"):
            failures.append(f"{claim_id}: failed claim must include failure_reason")
        if status == "pass" and claim.get("failure_reason") not in (None, ""):
            failures.append(f"{claim_id}: passing claim must not include failure_reason")
        for list_key in ("validators", "commands"):
            if not isinstance(claim.get(list_key), list):
                failures.append(f"{claim_id}: {list_key} must be a list")

    missing_required = sorted(required_claim_ids - seen)
    if missing_required:
        failures.append("ledger is missing required claim id(s): " + ", ".join(missing_required))
    verify_summary(ledger, typed_claims, failures)
    verify_markdown(markdown_path, seen, failures)
    verify_artifacts(
        typed_claims,
        ledger_path=ledger_json,
        module_path=module_path,
        failures=failures,
        allow_post_ledger_artifact_drift=allow_post_ledger_artifact_drift,
    )
    return failures


def main() -> int:
    args = parse_args()
    failures = verify_ledger(
        args.ledger_json,
        markdown=args.markdown,
        claims_path=args.claims,
        module_path=args.module_path,
    )
    if failures:
        print("Assurance ledger verification failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("Assurance ledger verification passed")
    print(f"  json: {args.ledger_json.resolve()}")
    print(f"  md  : {(args.markdown or args.ledger_json.with_suffix('.md')).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
