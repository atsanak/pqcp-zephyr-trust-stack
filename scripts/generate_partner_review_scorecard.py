#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Generate a partner-facing release evidence scorecard.

The scorecard is intentionally a derived artifact: it does not replace the
ledger, CBOM, policy result, or replay verifiers. It reads those artifacts and
turns them into a small set of review findings a partner can act on.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BLOCKER_PENALTY = 15
WARNING_PENALTY = 5


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
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
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-md", type=Path, required=True)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path, label: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        findings.append(
            finding(
                "missing_artifact_" + label.replace(" ", "_"),
                "blocker",
                "release",
                f"Missing {label}",
                f"Required scorecard input was not found: {path}",
                str(path),
                "Regenerate the full local release evidence pack.",
            )
        )
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        findings.append(
            finding(
                "invalid_json_" + label.replace(" ", "_"),
                "blocker",
                "release",
                f"Invalid JSON in {label}",
                str(exc),
                str(path),
                "Fix the generator or regenerate the artifact.",
            )
        )
        return {}
    if not isinstance(raw, dict):
        findings.append(
            finding(
                "invalid_root_" + label.replace(" ", "_"),
                "blocker",
                "release",
                f"Invalid root object in {label}",
                "Artifact root must be a JSON object.",
                str(path),
                "Fix the generator output shape.",
            )
        )
        return {}
    return raw


def artifact_record(name: str, path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    record: dict[str, Any] = {
        "name": name,
        "path": str(path),
        "exists": path.exists() and path.is_file(),
    }
    if record["exists"]:
        record["sha256"] = sha256_file(path)
        record["size_bytes"] = path.stat().st_size
    if payload:
        record["schema_version"] = payload.get("schema_version")
        if "passed" in payload:
            record["passed"] = payload.get("passed") is True
        if "summary" in payload:
            record["summary"] = payload.get("summary")
    return record


def finding(
    finding_id: str,
    severity: str,
    category: str,
    title: str,
    detail: str,
    evidence: str,
    action: str,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "category": category,
        "title": title,
        "detail": detail,
        "evidence": evidence,
        "recommended_action": action,
    }


def properties_map(component: dict[str, Any]) -> dict[str, str]:
    props: dict[str, str] = {}
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and isinstance(prop.get("name"), str):
            props[prop["name"]] = str(prop.get("value", ""))
    return props


def component_provider(component: dict[str, Any], props: dict[str, str]) -> str:
    for key in (
        "pqcp:provider_family",
        "pqcp:implementation_source",
        "pqcp:provider",
        "pqcp:backend",
    ):
        if props.get(key):
            return props[key]
    return str(component.get("publisher") or component.get("supplier", {}).get("name") or "")


def check_passed_artifact(
    payload: dict[str, Any],
    *,
    label: str,
    category: str,
    evidence: str,
    findings: list[dict[str, Any]],
    blocker: bool = True,
) -> None:
    if not payload:
        return
    if payload.get("passed") is True:
        return
    severity = "blocker" if blocker else "warning"
    failures = payload.get("failures") or payload.get("blocked_conditions") or []
    detail = "; ".join(map(str, failures[:5])) if isinstance(failures, list) else str(failures)
    if not detail:
        detail = f"{label} did not report passed=true."
    findings.append(
        finding(
            f"{category}_{label.lower().replace(' ', '_')}_failed",
            severity,
            category,
            f"{label} did not pass",
            detail,
            evidence,
            f"Inspect and fix {label}; then regenerate the release pack.",
        )
    )


def check_ledger(ledger: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    claims = [claim for claim in ledger.get("claims") or [] if isinstance(claim, dict)]
    failed_required = [
        claim for claim in claims
        if claim.get("required", True) and claim.get("status") == "fail"
    ]
    not_applicable_required = [
        claim for claim in claims
        if claim.get("required", True) and claim.get("status") == "not_applicable"
    ]
    for claim in failed_required:
        findings.append(
            finding(
                "failed_claim_" + str(claim.get("id", "unknown")).replace(".", "_"),
                "blocker",
                "claims",
                f"Required claim failed: {claim.get('id')}",
                str(claim.get("failure_reason") or claim.get("claim") or ""),
                "assurance_ledger.json",
                "Fix the failing validator or evidence artifact before partner review.",
            )
        )
    for claim in not_applicable_required:
        findings.append(
            finding(
                "not_applicable_claim_" + str(claim.get("id", "unknown")).replace(".", "_"),
                "warning",
                "claims",
                f"Required claim is not applicable: {claim.get('id')}",
                str(claim.get("claim") or ""),
                "assurance_ledger.json",
                "Confirm the partner-review mode allows this claim to be not applicable.",
            )
        )
    return {
        "claim_count": len(claims),
        "failed_required_claims": len(failed_required),
        "not_applicable_required_claims": len(not_applicable_required),
        "summary": ledger.get("summary", {}),
    }


def check_cbom(cbom: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    components = [item for item in cbom.get("components") or [] if isinstance(item, dict)]
    crypto_components = 0
    production_components = 0
    provider_families: dict[str, int] = {}
    for component in components:
        props = properties_map(component)
        trace_asset = props.get("pqcp:trace_asset_id")
        name = str(component.get("name") or "")
        provider = component_provider(component, props)
        if trace_asset or "ML-KEM" in name or "ML-DSA" in name:
            crypto_components += 1
        if provider:
            provider_families[provider] = provider_families.get(provider, 0) + 1
        production_allowed = props.get("pqcp:production_allowed", "").lower() == "true"
        lifecycle = props.get("pqcp:lifecycle_status", "")
        if production_allowed:
            production_components += 1
        lower_source = " ".join([name, provider, trace_asset or ""]).lower()
        forbidden_clean_provider = "pq" + "clean"
        if forbidden_clean_provider in lower_source:
            findings.append(
                finding(
                    "forbidden_clean_provider_reference",
                    "blocker",
                    "backend",
                    "Forbidden clean-reference provider appears in a crypto asset",
                    f"Component {name!r} resolves to provider/source {provider!r}.",
                    "pqc_cbom.cdx.json",
                    "Remove the forbidden provider from ML-KEM/ML-DSA paths and regenerate CBOM.",
                )
            )
        if "ML-KEM" in name and provider and "mlkem-native" not in provider:
            findings.append(
                finding(
                    "mlkem_not_native",
                    "blocker",
                    "backend",
                    "ML-KEM is not bound to mlkem-native",
                    f"Component {name!r} provider/source is {provider!r}.",
                    "pqc_cbom.cdx.json",
                    "Force ML-KEM assets to mlkem-native.",
                )
            )
        if "ML-DSA" in name and provider and "mldsa-native" not in provider:
            findings.append(
                finding(
                    "mldsa_not_native",
                    "blocker",
                    "backend",
                    "ML-DSA is not bound to mldsa-native",
                    f"Component {name!r} provider/source is {provider!r}.",
                    "pqc_cbom.cdx.json",
                    "Force ML-DSA assets to mldsa-native.",
                )
            )
        if production_allowed and lifecycle in {"test_only", "validation_only", "lab_only", "smoke_only"}:
            findings.append(
                finding(
                    "test_asset_marked_production_" + (trace_asset or name).replace(".", "_").replace(" ", "_"),
                    "blocker",
                    "profile",
                    "Test or validation asset marked production-allowed",
                    f"{name} has lifecycle_status={lifecycle!r} and production_allowed=true.",
                    "pqc_cbom.cdx.json",
                    "Mark validation/test assets as production_allowed=false.",
                )
            )
        if "deterministic" in lower_source and production_allowed:
            findings.append(
                finding(
                    "deterministic_rng_production",
                    "blocker",
                    "rng",
                    "Deterministic RNG is production-allowed",
                    f"{name} is marked production_allowed=true.",
                    "pqc_cbom.cdx.json",
                    "Keep deterministic RNG confined to KAT/ACVP test profiles.",
                )
            )
    return {
        "component_count": len(components),
        "crypto_component_count": crypto_components,
        "production_component_count": production_components,
        "provider_families": provider_families,
    }


def check_hardware_status(
    benchmark_campaign: dict[str, Any],
    migration_readiness: dict[str, Any],
    findings: list[dict[str, Any]],
) -> None:
    context = benchmark_campaign.get("comparison_context") or {}
    environment_type = context.get("environment_type") or context.get("environment")
    if not environment_type:
        findings.append(
            finding(
                "hardware_context_missing",
                "warning",
                "benchmark",
                "Benchmark campaign does not state hardware context",
                "comparison_context.environment_type is missing.",
                "benchmark_campaign_result.json",
                "Regenerate the benchmark campaign with explicit QEMU, host, external-reference, or physical-hardware context.",
            )
        )
    elif environment_type not in {"physical_hardware", "hardware"}:
        findings.append(
            finding(
                "hardware_promotion_not_completed",
                "warning",
                "benchmark",
                "Benchmark evidence is not physical-hardware evidence",
                f"comparison_context environment_type={environment_type!r}.",
                "benchmark_campaign_result.json",
                "Run the hardware promotion lane before making physical performance claims.",
            )
        )
    summary = migration_readiness.get("summary") or {}
    if summary.get("blocked_condition_count", 0):
        findings.append(
            finding(
                "migration_readiness_blocked",
                "blocker",
                "readiness",
                "Migration readiness has blocked conditions",
                str(migration_readiness.get("blocked_conditions") or []),
                "pqc_migration_readiness.json",
                "Resolve blocked conditions before partner distribution.",
            )
        )


def readiness_class(score: int, blocker_count: int, warning_count: int) -> str:
    if blocker_count:
        return "blocked"
    if score >= 95 and warning_count == 0:
        return "partner-review-ready"
    if score >= 85:
        return "reviewable-with-followups"
    return "needs-hardening"


def build_scorecard(args: argparse.Namespace) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    inputs = [
        ("assurance_ledger", args.ledger),
        ("pqc_cbom", args.cbom),
        ("pqc_policy_result", args.policy_result),
        ("pqc_assurance_profile_result", args.profile_result),
        ("pqc_evidence_quality_result", args.quality_result),
        ("pqc_migration_readiness", args.migration_readiness),
        ("backend_contract_result", args.backend_contract),
        ("provider_scope_result", args.provider_scope_result),
        ("benchmark_campaign_result", args.benchmark_campaign),
        ("ct_campaign_result", args.ct_campaign),
        ("acvp_json_schema_result", args.acvp_schema_result),
        ("device_evidence_token_result", args.device_evidence_result),
        ("pqc_reference_values", args.reference_values),
    ]
    if args.appraisal_result:
        inputs.append(("pqc_appraisal_result", args.appraisal_result))

    payloads: dict[str, dict[str, Any]] = {}
    artifacts: list[dict[str, Any]] = []
    for name, path in inputs:
        payload = load_json(path, name, findings)
        payloads[name] = payload
        artifacts.append(artifact_record(name, path, payload))

    claim_summary = check_ledger(payloads.get("assurance_ledger", {}), findings)
    cbom_summary = check_cbom(payloads.get("pqc_cbom", {}), findings)
    for name, label, category in (
        ("pqc_policy_result", "PQC assurance policy", "policy"),
        ("pqc_assurance_profile_result", "PQC assurance profile", "profile"),
        ("pqc_evidence_quality_result", "PQC evidence quality", "quality"),
        ("pqc_migration_readiness", "PQC migration readiness", "readiness"),
        ("backend_contract_result", "Backend contract", "backend"),
        ("provider_scope_result", "Provider scope", "backend"),
        ("benchmark_campaign_result", "Benchmark campaign", "benchmark"),
        ("ct_campaign_result", "CT campaign", "security"),
        ("acvp_json_schema_result", "ACVP JSON schema coverage", "acvp"),
        ("device_evidence_token_result", "Device evidence token", "firmware"),
    ):
        check_passed_artifact(
            payloads.get(name, {}),
            label=label,
            category=category,
            evidence=f"{name}.json",
            findings=findings,
        )
    if args.appraisal_result:
        check_passed_artifact(
            payloads.get("pqc_appraisal_result", {}),
            label="PQC appraisal replay",
            category="appraisal",
            evidence="pqc_appraisal_result.json",
            findings=findings,
        )
    check_hardware_status(
        payloads.get("benchmark_campaign_result", {}),
        payloads.get("pqc_migration_readiness", {}),
        findings,
    )

    blocker_count = sum(1 for item in findings if item["severity"] == "blocker")
    warning_count = sum(1 for item in findings if item["severity"] == "warning")
    score = max(0, 100 - blocker_count * BLOCKER_PENALTY - warning_count * WARNING_PENALTY)
    summary = {
        "score": score,
        "readiness": readiness_class(score, blocker_count, warning_count),
        "blockers": blocker_count,
        "warnings": warning_count,
        "findings": len(findings),
        "artifact_count": len(artifacts),
        "claim_summary": claim_summary,
        "cbom_summary": cbom_summary,
    }
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/generate_partner_review_scorecard.py",
        "passed": blocker_count == 0,
        "summary": summary,
        "input_artifacts": artifacts,
        "findings": sorted(findings, key=lambda item: (item["severity"] != "blocker", item["category"], item["id"])),
    }


def render_markdown(scorecard: dict[str, Any]) -> str:
    summary = scorecard["summary"]
    lines = [
        "# PQCP Partner Review Scorecard",
        "",
        f"- Generated: `{scorecard['generated_at']}`",
        f"- Status: `{'pass' if scorecard['passed'] else 'fail'}`",
        f"- Readiness: `{summary['readiness']}`",
        f"- Score: `{summary['score']}`",
        f"- Blockers: `{summary['blockers']}`",
        f"- Warnings: `{summary['warnings']}`",
        "",
        "## Review Findings",
        "",
        "| ID | Severity | Category | Finding | Action |",
        "|---|---|---|---|---|",
    ]
    if not scorecard["findings"]:
        lines.append("| `none` | `info` | `release` | No scorecard findings. | Continue normal review. |")
    for item in scorecard["findings"]:
        lines.append(
            "| `{id}` | `{severity}` | `{category}` | {title} | {action} |".format(
                id=item["id"],
                severity=item["severity"],
                category=item["category"],
                title=str(item["title"]).replace("|", "\\|"),
                action=str(item["recommended_action"]).replace("|", "\\|"),
            )
        )
    lines.extend(
        [
            "",
            "## Input Artifacts",
            "",
            "| Artifact | Present | Passed | SHA-256 |",
            "|---|---:|---:|---|",
        ]
    )
    for artifact in scorecard["input_artifacts"]:
        lines.append(
            "| `{name}` | `{exists}` | `{passed}` | `{sha}` |".format(
                name=artifact["name"],
                exists=str(artifact.get("exists", False)).lower(),
                passed=str(artifact.get("passed", "n/a")).lower(),
                sha=artifact.get("sha256", "n/a"),
            )
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    scorecard = build_scorecard(args)
    args.output_json.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output_md.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output_json.resolve().write_text(json.dumps(scorecard, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output_md.resolve().write_text(render_markdown(scorecard), encoding="utf-8")
    print("Partner review scorecard generated")
    print(f"  json: {args.output_json.resolve()}")
    print(f"  md  : {args.output_md.resolve()}")
    print(f"  readiness={scorecard['summary']['readiness']} score={scorecard['summary']['score']}")
    return 0 if scorecard["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
