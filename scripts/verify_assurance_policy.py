#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
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
    parser.add_argument("--asset-trace-result", type=Path)
    parser.add_argument("--ct-instruction-policy-result", type=Path)
    parser.add_argument("--evidence-graph", type=Path)
    parser.add_argument("--assurance-digest", type=Path)
    parser.add_argument("--firmware-digest-header", type=Path)
    parser.add_argument("--assurance-profile-result", type=Path)
    parser.add_argument("--evidence-quality-result", type=Path)
    parser.add_argument("--migration-readiness-json", type=Path)
    parser.add_argument("--migration-readiness-md", type=Path)
    parser.add_argument("--reference-values", type=Path)
    parser.add_argument("--reference-values-result", type=Path)
    parser.add_argument("--firmware-status-result", type=Path)
    parser.add_argument("--acvp-json-interop-result", type=Path)
    parser.add_argument("--acvp-json-transcript-manifest", type=Path)
    parser.add_argument("--build-provenance", type=Path)
    parser.add_argument("--build-provenance-result", type=Path)
    parser.add_argument("--ct-sample-analysis-result", type=Path)
    parser.add_argument("--ct-sample-manifest", type=Path)
    parser.add_argument("--backend-currency-result", type=Path)
    parser.add_argument("--external-reference-result", type=Path)
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

    required_profile_props = policy.get("required_cbom_profile_properties") or []
    if required_profile_props:
        for name in policy.get("required_cbom_components") or []:
            component = by_name.get(name)
            if component is None:
                continue
            if component.get("type") != "cryptographic-asset":
                continue
            props = properties_map(component)
            for prop_name in required_profile_props:
                ok = bool(props.get(prop_name))
                checks.append(
                    {
                        "check": "cbom_profile_property",
                        "name": name,
                        "property": prop_name,
                        "passed": ok,
                    }
                )
                if not ok:
                    failures.append(f"required CBOM component {name} missing {prop_name}")


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


def default_passport_v2_paths(base: Path) -> dict[str, Path]:
    return {
        "acvp_negative_scenario_floor_result.json": base / "acvp_negative_scenario_floor_result.json",
        "ct_instruction_policy_result.json": base / "ct_instruction_policy_result.json",
        "pqc_asset_trace_result.json": base / "pqc_asset_trace_result.json",
        "pqc_evidence_graph.json": base / "pqc_evidence_graph.json",
        "pqc_evidence_graph.md": base / "pqc_evidence_graph.md",
        "pqc_assurance_digest.json": base / "pqc_assurance_digest.json",
        "generated/pqcp_assurance_digest_generated.h": base / "generated/pqcp_assurance_digest_generated.h",
    }


def default_passport_v3_paths(base: Path) -> dict[str, Path]:
    return {
        "pqc_assurance_profile_result.json": base / "pqc_assurance_profile_result.json",
        "pqc_evidence_quality_result.json": base / "pqc_evidence_quality_result.json",
        "pqc_migration_readiness.json": base / "pqc_migration_readiness.json",
        "pqc_migration_readiness.md": base / "pqc_migration_readiness.md",
    }


def default_passport_v4_paths(base: Path) -> dict[str, Path]:
    return {
        "pqc_reference_values.json": base / "pqc_reference_values.json",
        "pqc_reference_values_result.json": base / "pqc_reference_values_result.json",
        "firmware_assurance_status_result.json": base / "firmware_assurance_status_result.json",
        "acvp_json_interop_result.json": base / "acvp_json_interop_result.json",
        "acvp_json_transcript_manifest.json": base / "acvp_json_transcript_manifest.json",
        "pqc_build_provenance.slsa.json": base / "pqc_build_provenance.slsa.json",
        "pqc_build_provenance_result.json": base / "pqc_build_provenance_result.json",
        "ct_sample_analysis_result.json": base / "ct_sample_analysis_result.json",
        "ct_sample_manifest.json": base / "ct_sample_manifest.json",
        "backend_currency_result.json": base / "backend_currency_result.json",
        "external_reference_import/hardware_benchmark_report.json": base / "external_reference_import" / "hardware_benchmark_report.json",
    }


def check_passport_v2_artifacts(
    *,
    policy: dict[str, Any],
    base: Path,
    asset_trace_result_path: Path | None,
    ct_instruction_policy_result_path: Path | None,
    evidence_graph_path: Path | None,
    assurance_digest_path: Path | None,
    firmware_digest_header_path: Path | None,
    failures: list[str],
    checks: list[dict[str, Any]],
) -> None:
    defaults = default_passport_v2_paths(base)
    explicit = {
        "ct_instruction_policy_result.json": ct_instruction_policy_result_path,
        "pqc_asset_trace_result.json": asset_trace_result_path,
        "pqc_evidence_graph.json": evidence_graph_path,
        "pqc_assurance_digest.json": assurance_digest_path,
        "generated/pqcp_assurance_digest_generated.h": firmware_digest_header_path,
    }
    for rel_path in policy.get("required_passport_v2_artifacts") or []:
        path = explicit.get(rel_path) or defaults.get(rel_path) or (base / rel_path)
        ok = path.exists() and path.is_file() and path.stat().st_size > 0
        checks.append({"check": "passport_v2_artifact", "path": rel_path, "passed": ok})
        if not ok:
            failures.append(f"required Passport v2 artifact missing or empty: {rel_path}")

    floor_result = load_json(defaults["acvp_negative_scenario_floor_result.json"], "ACVP negative scenario floor result", failures)
    if floor_result:
        ok = floor_result.get("passed") is True
        checks.append({"check": "negative_scenario_floor_result", "passed": ok})
        if not ok:
            failures.append("ACVP negative scenario floor result did not pass")

    trace_path = asset_trace_result_path or defaults["pqc_asset_trace_result.json"]
    trace_result = load_json(trace_path, "PQC asset trace result", failures)
    if trace_result:
        ok = trace_result.get("passed") is True
        checks.append({"check": "asset_trace_result", "passed": ok})
        if not ok:
            failures.append("PQC asset trace result did not pass")

    ct_policy_path = ct_instruction_policy_result_path or defaults["ct_instruction_policy_result.json"]
    ct_policy = load_json(ct_policy_path, "ML-KEM decapsulation instruction policy result", failures)
    if ct_policy:
        ok = ct_policy.get("passed") is True
        checks.append({"check": "ct_instruction_policy_result", "passed": ok})
        if not ok:
            failures.append("ML-KEM decapsulation instruction policy result did not pass")

    graph_path = evidence_graph_path or defaults["pqc_evidence_graph.json"]
    graph = load_json(graph_path, "PQC evidence graph", failures)
    if graph:
        failures_field = graph.get("failures")
        ok = graph.get("schema_version") == 1 and isinstance(failures_field, list) and not failures_field
        checks.append({"check": "evidence_graph_integrity", "passed": ok})
        if not ok:
            failures.append("PQC evidence graph contains failures or has unsupported schema")

    digest_path = assurance_digest_path or defaults["pqc_assurance_digest.json"]
    digest = load_json(digest_path, "PQC assurance digest", failures)
    if digest:
        artifacts = digest.get("artifacts")
        ok = digest.get("schema_version") == 1 and isinstance(artifacts, list) and bool(artifacts)
        checks.append({"check": "assurance_digest_manifest", "passed": ok})
        if not ok:
            failures.append("PQC assurance digest manifest is malformed")

    header_path = firmware_digest_header_path or defaults["generated/pqcp_assurance_digest_generated.h"]
    if header_path.exists() and header_path.is_file():
        header = header_path.read_text(encoding="utf-8", errors="replace")
        required = (
            "PQCP_ASSURANCE_DIGEST_ROOT_SHA256",
            "PQCP_ASSURANCE_DIGEST_ARTIFACT_COUNT",
        )
        ok = all(text in header for text in required)
        checks.append({"check": "firmware_digest_header", "passed": ok})
        if not ok:
            failures.append("generated firmware digest header is missing required macros")


def check_passport_v3_artifacts(
    *,
    policy: dict[str, Any],
    base: Path,
    assurance_profile_result_path: Path | None,
    evidence_quality_result_path: Path | None,
    migration_readiness_json_path: Path | None,
    migration_readiness_md_path: Path | None,
    failures: list[str],
    checks: list[dict[str, Any]],
) -> None:
    defaults = default_passport_v3_paths(base)
    explicit = {
        "pqc_assurance_profile_result.json": assurance_profile_result_path,
        "pqc_evidence_quality_result.json": evidence_quality_result_path,
        "pqc_migration_readiness.json": migration_readiness_json_path,
        "pqc_migration_readiness.md": migration_readiness_md_path,
    }
    for rel_path in policy.get("required_passport_v3_artifacts") or []:
        path = explicit.get(rel_path) or defaults.get(rel_path) or (base / rel_path)
        ok = path.exists() and path.is_file() and path.stat().st_size > 0
        checks.append({"check": "passport_v3_artifact", "path": rel_path, "passed": ok})
        if not ok:
            failures.append(f"required Passport v3 artifact missing or empty: {rel_path}")

    profile_path = assurance_profile_result_path or defaults["pqc_assurance_profile_result.json"]
    profile = load_json(profile_path, "PQC assurance profile result", failures)
    if profile:
        ok = profile.get("schema_version") == 1 and profile.get("passed") is True
        checks.append({"check": "assurance_profile_result", "passed": ok})
        if not ok:
            failures.append("PQC assurance profile result did not pass")

    quality_path = evidence_quality_result_path or defaults["pqc_evidence_quality_result.json"]
    quality = load_json(quality_path, "PQC evidence quality result", failures)
    if quality:
        ok = quality.get("schema_version") == 1 and quality.get("passed") is True
        checks.append({"check": "evidence_quality_result", "passed": ok})
        if not ok:
            failures.append("PQC evidence quality result did not pass")

    readiness_path = migration_readiness_json_path or defaults["pqc_migration_readiness.json"]
    readiness = load_json(readiness_path, "PQC migration readiness", failures)
    if readiness:
        ok = readiness.get("schema_version") == 1 and readiness.get("passed") is True
        checks.append({"check": "migration_readiness", "passed": ok})
        if not ok:
            failures.append("PQC migration readiness report did not pass")

    readiness_md = migration_readiness_md_path or defaults["pqc_migration_readiness.md"]
    if readiness_md.exists() and readiness_md.is_file() and readiness:
        body = readiness_md.read_text(encoding="utf-8", errors="replace")
        missing_assets = [
            str(asset.get("name"))
            for asset in readiness.get("assets") or []
            if isinstance(asset, dict) and str(asset.get("name")) not in body
        ]
        if missing_assets:
            failures.append(
                "PQC migration readiness Markdown missing asset(s): "
                + ", ".join(sorted(missing_assets))
            )


def check_passport_v4_artifacts(
    *,
    policy: dict[str, Any],
    base: Path,
    explicit_paths: dict[str, Path | None],
    failures: list[str],
    checks: list[dict[str, Any]],
) -> None:
    defaults = default_passport_v4_paths(base)
    for rel_path in policy.get("required_passport_v4_artifacts") or []:
        path = explicit_paths.get(rel_path) or defaults.get(rel_path) or (base / rel_path)
        ok = path.exists() and path.is_file() and path.stat().st_size > 0
        checks.append({"check": "passport_v4_artifact", "path": rel_path, "passed": ok})
        if not ok:
            failures.append(f"required Passport v4 artifact missing or empty: {rel_path}")
            continue
        if rel_path.endswith("_result.json"):
            payload = load_json(path, rel_path, failures)
            if payload:
                passed = payload.get("passed") is True
                checks.append({"check": "passport_v4_result_passed", "path": rel_path, "passed": passed})
                if not passed:
                    failures.append(f"Passport v4 result did not pass: {rel_path}")


def verify_policy(
    *,
    policy_path: Path,
    ledger_path: Path,
    cbom_path: Path,
    attestation_path: Path,
    release_manifest_path: Path | None = None,
    asset_trace_result_path: Path | None = None,
    ct_instruction_policy_result_path: Path | None = None,
    evidence_graph_path: Path | None = None,
    assurance_digest_path: Path | None = None,
    firmware_digest_header_path: Path | None = None,
    assurance_profile_result_path: Path | None = None,
    evidence_quality_result_path: Path | None = None,
    migration_readiness_json_path: Path | None = None,
    migration_readiness_md_path: Path | None = None,
    reference_values_path: Path | None = None,
    reference_values_result_path: Path | None = None,
    firmware_status_result_path: Path | None = None,
    acvp_json_interop_result_path: Path | None = None,
    acvp_json_transcript_manifest_path: Path | None = None,
    build_provenance_path: Path | None = None,
    build_provenance_result_path: Path | None = None,
    ct_sample_analysis_result_path: Path | None = None,
    ct_sample_manifest_path: Path | None = None,
    backend_currency_result_path: Path | None = None,
    external_reference_result_path: Path | None = None,
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

    if policy.get("schema_version") not in (1, 2, 3, 4):
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
        elif name == "ct_instruction_policy_result.json" and ct_instruction_policy_result_path is not None:
            known_paths[name] = ct_instruction_policy_result_path
        elif name == "pqc_assurance_profile_result.json" and assurance_profile_result_path is not None:
            known_paths[name] = assurance_profile_result_path
        elif name == "pqc_evidence_quality_result.json" and evidence_quality_result_path is not None:
            known_paths[name] = evidence_quality_result_path
        elif name == "pqc_migration_readiness.json" and migration_readiness_json_path is not None:
            known_paths[name] = migration_readiness_json_path
        elif name == "pqc_migration_readiness.md" and migration_readiness_md_path is not None:
            known_paths[name] = migration_readiness_md_path
        elif name == "pqc_reference_values.json" and reference_values_path is not None:
            known_paths[name] = reference_values_path
        elif name == "pqc_build_provenance.slsa.json" and build_provenance_path is not None:
            known_paths[name] = build_provenance_path
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
    if policy.get("schema_version") in (2, 3, 4):
        check_passport_v2_artifacts(
            policy=policy,
            base=ledger_path.parent,
            asset_trace_result_path=asset_trace_result_path,
            ct_instruction_policy_result_path=ct_instruction_policy_result_path,
            evidence_graph_path=evidence_graph_path,
            assurance_digest_path=assurance_digest_path,
            firmware_digest_header_path=firmware_digest_header_path,
            failures=failures,
            checks=checks,
        )
    if policy.get("schema_version") in (3, 4):
        check_passport_v3_artifacts(
            policy=policy,
            base=ledger_path.parent,
            assurance_profile_result_path=assurance_profile_result_path,
            evidence_quality_result_path=evidence_quality_result_path,
            migration_readiness_json_path=migration_readiness_json_path,
            migration_readiness_md_path=migration_readiness_md_path,
            failures=failures,
            checks=checks,
        )
    if policy.get("schema_version") == 4:
        check_passport_v4_artifacts(
            policy=policy,
            base=ledger_path.parent,
            explicit_paths={
                "pqc_reference_values.json": reference_values_path,
                "pqc_reference_values_result.json": reference_values_result_path,
                "firmware_assurance_status_result.json": firmware_status_result_path,
                "acvp_json_interop_result.json": acvp_json_interop_result_path,
                "acvp_json_transcript_manifest.json": acvp_json_transcript_manifest_path,
                "pqc_build_provenance.slsa.json": build_provenance_path,
                "pqc_build_provenance_result.json": build_provenance_result_path,
                "ct_sample_analysis_result.json": ct_sample_analysis_result_path,
                "ct_sample_manifest.json": ct_sample_manifest_path,
                "backend_currency_result.json": backend_currency_result_path,
                "external_reference_import/hardware_benchmark_report.json": external_reference_result_path,
            },
            failures=failures,
            checks=checks,
        )
    return {
        "schema_version": 4,
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
        asset_trace_result_path=args.asset_trace_result.resolve() if args.asset_trace_result else None,
        ct_instruction_policy_result_path=args.ct_instruction_policy_result.resolve() if args.ct_instruction_policy_result else None,
        evidence_graph_path=args.evidence_graph.resolve() if args.evidence_graph else None,
        assurance_digest_path=args.assurance_digest.resolve() if args.assurance_digest else None,
        firmware_digest_header_path=args.firmware_digest_header.resolve() if args.firmware_digest_header else None,
        assurance_profile_result_path=args.assurance_profile_result.resolve() if args.assurance_profile_result else None,
        evidence_quality_result_path=args.evidence_quality_result.resolve() if args.evidence_quality_result else None,
        migration_readiness_json_path=args.migration_readiness_json.resolve() if args.migration_readiness_json else None,
        migration_readiness_md_path=args.migration_readiness_md.resolve() if args.migration_readiness_md else None,
        reference_values_path=args.reference_values.resolve() if args.reference_values else None,
        reference_values_result_path=args.reference_values_result.resolve() if args.reference_values_result else None,
        firmware_status_result_path=args.firmware_status_result.resolve() if args.firmware_status_result else None,
        acvp_json_interop_result_path=args.acvp_json_interop_result.resolve() if args.acvp_json_interop_result else None,
        acvp_json_transcript_manifest_path=args.acvp_json_transcript_manifest.resolve() if args.acvp_json_transcript_manifest else None,
        build_provenance_path=args.build_provenance.resolve() if args.build_provenance else None,
        build_provenance_result_path=args.build_provenance_result.resolve() if args.build_provenance_result else None,
        ct_sample_analysis_result_path=args.ct_sample_analysis_result.resolve() if args.ct_sample_analysis_result else None,
        ct_sample_manifest_path=args.ct_sample_manifest.resolve() if args.ct_sample_manifest else None,
        backend_currency_result_path=args.backend_currency_result.resolve() if args.backend_currency_result else None,
        external_reference_result_path=args.external_reference_result.resolve() if args.external_reference_result else None,
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
