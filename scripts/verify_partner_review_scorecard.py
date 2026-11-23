#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay-check a generated partner review scorecard."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import generate_partner_review_scorecard


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scorecard", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--cbom", type=Path, required=True)
    parser.add_argument("--policy-result", type=Path, required=True)
    parser.add_argument("--profile-result", type=Path, required=True)
    parser.add_argument("--quality-result", type=Path, required=True)
    parser.add_argument("--migration-readiness", type=Path, required=True)
    parser.add_argument("--backend-contract", type=Path, required=True)
    parser.add_argument("--provider-scope-result", type=Path, required=True)
    parser.add_argument("--benchmark-campaign", type=Path, required=True)
    parser.add_argument("--ct-campaign", type=Path, required=True)
    parser.add_argument("--acvp-schema-result", type=Path, required=True)
    parser.add_argument("--device-evidence-result", type=Path, required=True)
    parser.add_argument("--reference-values", type=Path, required=True)
    parser.add_argument("--appraisal-result", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def load_json(path: Path, label: str, failures: list[str]) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
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


def stable_artifact_index(scorecard: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in scorecard.get("input_artifacts") or []:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            result[item["name"]] = {
                key: item.get(key)
                for key in ("exists", "sha256", "size_bytes", "schema_version", "passed")
                if key in item
            }
    return result


def finding_index(scorecard: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in scorecard.get("findings") or []:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            result[item["id"]] = {
                key: item.get(key)
                for key in (
                    "severity",
                    "category",
                    "title",
                    "detail",
                    "evidence",
                    "recommended_action",
                )
            }
    return result


def scorecard_args(args: argparse.Namespace) -> argparse.Namespace:
    return argparse.Namespace(
        ledger=args.ledger,
        cbom=args.cbom,
        policy_result=args.policy_result,
        profile_result=args.profile_result,
        quality_result=args.quality_result,
        migration_readiness=args.migration_readiness,
        backend_contract=args.backend_contract,
        provider_scope_result=args.provider_scope_result,
        benchmark_campaign=args.benchmark_campaign,
        ct_campaign=args.ct_campaign,
        acvp_schema_result=args.acvp_schema_result,
        device_evidence_result=args.device_evidence_result,
        reference_values=args.reference_values,
        appraisal_result=args.appraisal_result,
        output_json=args.scorecard,
        output_md=args.markdown,
    )


def verify(args: argparse.Namespace) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    actual = load_json(args.scorecard, "partner review scorecard", failures)
    if not actual:
        return {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "passed": False,
            "summary": {"checks": 0, "failures": len(failures)},
            "checks": checks,
            "failures": failures,
        }

    expected = generate_partner_review_scorecard.build_scorecard(scorecard_args(args))
    if actual.get("schema_version") != 1:
        failures.append(f"scorecard schema_version={actual.get('schema_version')!r}, expected 1")
    if actual.get("generator") != "scripts/generate_partner_review_scorecard.py":
        failures.append("scorecard generator marker is incorrect")

    for key in ("passed", "summary"):
        ok = actual.get(key) == expected.get(key)
        checks.append({"check": key, "passed": ok})
        if not ok:
            failures.append(f"scorecard {key} does not match replayed evidence")

    actual_findings = finding_index(actual)
    expected_findings = finding_index(expected)
    ok = actual_findings == expected_findings
    checks.append({"check": "findings", "passed": ok})
    if not ok:
        missing = sorted(set(expected_findings) - set(actual_findings))
        extra = sorted(set(actual_findings) - set(expected_findings))
        if missing:
            failures.append("scorecard missing finding id(s): " + ", ".join(missing))
        if extra:
            failures.append("scorecard has stale finding id(s): " + ", ".join(extra))
        changed = sorted(
            finding_id
            for finding_id in set(actual_findings) & set(expected_findings)
            if actual_findings[finding_id] != expected_findings[finding_id]
        )
        if changed:
            failures.append("scorecard finding content drift: " + ", ".join(changed))

    actual_artifacts = stable_artifact_index(actual)
    expected_artifacts = stable_artifact_index(expected)
    ok = actual_artifacts == expected_artifacts
    checks.append({"check": "input_artifacts", "passed": ok})
    if not ok:
        missing = sorted(set(expected_artifacts) - set(actual_artifacts))
        extra = sorted(set(actual_artifacts) - set(expected_artifacts))
        if missing:
            failures.append("scorecard missing input artifact(s): " + ", ".join(missing))
        if extra:
            failures.append("scorecard has unexpected input artifact(s): " + ", ".join(extra))
        changed = sorted(
            name
            for name in set(actual_artifacts) & set(expected_artifacts)
            if actual_artifacts[name] != expected_artifacts[name]
        )
        if changed:
            failures.append("scorecard input artifact hash/status drift: " + ", ".join(changed))

    if not args.markdown.exists() or not args.markdown.is_file():
        failures.append(f"partner review scorecard Markdown not found: {args.markdown}")
        checks.append({"check": "markdown_exists", "passed": False})
    else:
        body = args.markdown.read_text(encoding="utf-8", errors="replace")
        missing_ids = sorted(finding_id for finding_id in actual_findings if finding_id not in body)
        missing_artifacts = sorted(name for name in actual_artifacts if name not in body)
        ok = not missing_ids and not missing_artifacts
        checks.append({"check": "markdown_bindings", "passed": ok})
        if missing_ids:
            failures.append("scorecard Markdown missing finding id(s): " + ", ".join(missing_ids))
        if missing_artifacts:
            failures.append("scorecard Markdown missing artifact name(s): " + ", ".join(missing_artifacts))

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
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
        print("PASS: partner review scorecard replay verified")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("FAIL: partner review scorecard replay failed", file=sys.stderr)
    for failure in result["failures"]:
        print(f"  - {failure}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
