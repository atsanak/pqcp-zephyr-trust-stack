#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay-check PQC appraisal evidence against a mode-specific policy."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--appraisal-evidence", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--mode", choices=("ci_fast", "local_release", "partner_review", "hardware_review"))
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
        failures.append(f"{label} root must be an object")
        return {}
    return raw


def claim_statuses(ledger: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for claim in ledger.get("claims") or []:
        if isinstance(claim, dict) and isinstance(claim.get("id"), str):
            result[claim["id"]] = str(claim.get("status", "unknown"))
    return result


def verify(args: argparse.Namespace) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    policy = load_json(args.policy, "appraisal policy", failures)
    evidence = load_json(args.appraisal_evidence, "appraisal evidence", failures)
    ledger = load_json(args.ledger, "assurance ledger", failures)
    if not policy or not evidence or not ledger:
        return {"schema_version": 1, "passed": False, "failures": failures, "checks": checks}

    if policy.get("schema_version") != 1:
        failures.append(f"unsupported appraisal policy schema_version={policy.get('schema_version')!r}")
    if evidence.get("schema_version") != 1:
        failures.append(f"unsupported appraisal evidence schema_version={evidence.get('schema_version')!r}")
    mode = args.mode or str(policy.get("default_mode") or "partner_review")
    modes = policy.get("modes") if isinstance(policy.get("modes"), dict) else {}
    mode_policy = modes.get(mode)
    if not isinstance(mode_policy, dict):
        failures.append(f"appraisal policy mode not found: {mode}")
        mode_policy = {}

    artifacts = {
        str(item.get("path")): item
        for item in evidence.get("artifacts") or []
        if isinstance(item, dict)
    }
    by_name = {
        str(item.get("name")): item
        for item in evidence.get("artifacts") or []
        if isinstance(item, dict)
    }
    root = args.appraisal_evidence.resolve().parent
    for required in mode_policy.get("required_artifacts") or []:
        if required == "pqc_appraisal_evidence.json":
            ok = args.appraisal_evidence.exists() and args.appraisal_evidence.is_file()
            checks.append({"check": "required_artifact", "path": required, "passed": ok})
            if not ok:
                failures.append(f"required appraisal artifact missing from evidence: {required}")
            continue
        item = artifacts.get(required)
        if item is None:
            item = by_name.get(required.replace(".json", "").replace("-", "_"))
        ok = bool(item and item.get("exists") and item.get("sha256"))
        checks.append({"check": "required_artifact", "path": required, "passed": ok})
        if not ok:
            failures.append(f"required appraisal artifact missing from evidence: {required}")
            continue
        path = root / str(item.get("path"))
        if not path.exists():
            failures.append(f"required appraisal artifact file missing: {item.get('path')}")
            continue
        actual = sha256_file(path)
        if actual != item.get("sha256"):
            failures.append(f"appraisal artifact hash mismatch: {item.get('path')}")
        if item.get("requires_pass") and item.get("passed") is not True:
            failures.append(f"required appraisal artifact did not pass: {item.get('path')}")

    statuses = claim_statuses(ledger)
    allowed_na = set(mode_policy.get("allow_not_applicable_claim_ids") or [])
    evidence_passes = {
        "release.evidence_appraisal_profile": evidence.get("passed") is True,
        "supply_chain.backend_update_evaluation": bool(by_name.get("backend_update_evaluation", {}).get("passed")),
        "benchmark.campaign_reproducibility": bool(by_name.get("benchmark_campaign", {}).get("passed")),
        "benchmark.external_reference_context": bool(by_name.get("benchmark_campaign", {}).get("passed")),
        "security.ct_campaign_analysis": bool(by_name.get("ct_campaign", {}).get("passed")),
        "acvp.json_schema_coverage": bool(by_name.get("acvp_json_schema", {}).get("passed")),
        "firmware.device_evidence_token": bool(by_name.get("device_evidence_token", {}).get("passed")),
        "release.strict_partner_policy": True,
    }
    for claim_id in mode_policy.get("required_claim_evidence") or []:
        ledger_status = statuses.get(claim_id)
        has_evidence = evidence_passes.get(claim_id) is True
        ok = (ledger_status == "pass") or has_evidence or (ledger_status == "not_applicable" and claim_id in allowed_na)
        checks.append(
            {
                "check": "required_claim_evidence",
                "claim_id": claim_id,
                "ledger_status": ledger_status,
                "evidence_passed": has_evidence,
                "passed": ok,
            }
        )
        if not ok:
            failures.append(f"claim {claim_id} is not closed by ledger status or appraisal evidence")

    if mode_policy.get("requires_physical_hardware_context"):
        campaign = by_name.get("benchmark_campaign") or {}
        summary = campaign.get("summary") or {}
        context = summary.get("comparison_context") if isinstance(summary, dict) else None
        ok = isinstance(context, dict) and context.get("environment_type") == "physical_hardware"
        checks.append({"check": "physical_hardware_context", "passed": ok})
        if not ok:
            failures.append("hardware_review mode requires physical_hardware comparison context")

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "passed": not failures,
        "summary": {"checks": len(checks), "failures": len(failures)},
        "checks": checks,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    result = verify(args)
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: PQC appraisal evidence verified")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("FAIL: PQC appraisal evidence verification failed")
    for failure in result["failures"]:
        print(f"  - {failure}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
