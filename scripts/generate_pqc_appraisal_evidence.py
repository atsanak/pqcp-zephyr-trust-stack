#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate a compact appraisal index over post-Passport evidence artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_ARTIFACTS = (
    ("pqc_appraisal_policy", "pqc_appraisal_policy.json", None),
    ("assurance_ledger", "assurance_ledger.json", None),
    ("pqc_policy_result", "pqc_policy_result.json", True),
    ("backend_update_evaluation", "backend_update_evaluation.json", True),
    ("benchmark_campaign", "benchmark_campaign_result.json", True),
    ("ct_campaign", "ct_campaign_result.json", True),
    ("acvp_json_schema", "acvp_json_schema_result.json", True),
    ("device_evidence_token", "device_evidence_token_result.json", True),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--policy-result", type=Path, required=True)
    parser.add_argument("--backend-update", type=Path, required=True)
    parser.add_argument("--benchmark-campaign", type=Path, required=True)
    parser.add_argument("--ct-campaign", type=Path, required=True)
    parser.add_argument("--acvp-schema-result", type=Path, required=True)
    parser.add_argument("--device-evidence-result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"{path} root must be a JSON object")
    return raw


def relpath(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def artifact_record(
    *,
    name: str,
    path: Path,
    root: Path,
    requires_pass: bool | None,
) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    record: dict[str, Any] = {
        "name": name,
        "path": relpath(path, root),
        "exists": path.exists() and path.is_file(),
        "requires_pass": requires_pass,
    }
    if not record["exists"]:
        failures.append(f"{name} missing: {path}")
        return record, failures
    record["sha256"] = sha256_file(path)
    record["size_bytes"] = path.stat().st_size
    if path.suffix == ".json" or path.name.endswith(".json"):
        try:
            payload = load_json(path)
        except (OSError, json.JSONDecodeError, RuntimeError) as exc:
            failures.append(f"{name} is not valid JSON: {exc}")
            return record, failures
        record["schema_version"] = payload.get("schema_version")
        if "passed" in payload:
            record["passed"] = payload.get("passed") is True
            if requires_pass and payload.get("passed") is not True:
                failures.append(f"{name} did not pass")
        if "summary" in payload:
            record["summary"] = payload.get("summary")
    return record, failures


def generate(args: argparse.Namespace) -> dict[str, Any]:
    output_root = args.output_root.resolve()
    mapping = {
        "pqc_appraisal_policy.json": args.policy.resolve(),
        "assurance_ledger.json": args.ledger.resolve(),
        "pqc_policy_result.json": args.policy_result.resolve(),
        "backend_update_evaluation.json": args.backend_update.resolve(),
        "benchmark_campaign_result.json": args.benchmark_campaign.resolve(),
        "ct_campaign_result.json": args.ct_campaign.resolve(),
        "acvp_json_schema_result.json": args.acvp_schema_result.resolve(),
        "device_evidence_token_result.json": args.device_evidence_result.resolve(),
    }
    failures: list[str] = []
    artifacts: list[dict[str, Any]] = []
    for name, filename, requires_pass in DEFAULT_ARTIFACTS:
        record, record_failures = artifact_record(
            name=name,
            path=mapping[filename],
            root=output_root,
            requires_pass=requires_pass,
        )
        artifacts.append(record)
        failures.extend(record_failures)

    ledger_claim_status: dict[str, str] = {}
    if args.ledger.exists():
        try:
            ledger = load_json(args.ledger)
            for claim in ledger.get("claims") or []:
                if isinstance(claim, dict) and isinstance(claim.get("id"), str):
                    ledger_claim_status[claim["id"]] = str(claim.get("status", "unknown"))
        except (OSError, json.JSONDecodeError, RuntimeError) as exc:
            failures.append(f"unable to read ledger claim status: {exc}")

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/generate_pqc_appraisal_evidence.py",
        "output_root": str(output_root),
        "passed": not failures,
        "summary": {
            "artifact_count": len(artifacts),
            "present_artifacts": sum(1 for item in artifacts if item.get("exists")),
            "failures": len(failures),
        },
        "ledger_claim_status": ledger_claim_status,
        "artifacts": artifacts,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    result = generate(args)
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: PQC appraisal evidence generated")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("FAIL: PQC appraisal evidence has failures")
    for failure in result["failures"]:
        print(f"  - {failure}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
