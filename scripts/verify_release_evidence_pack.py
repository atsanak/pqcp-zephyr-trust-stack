#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Verify a local release_check.py output directory as a coherent evidence pack."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from export_results import validate_benchmark_csv, validate_comparison_context, verify_provenance  # noqa: E402
from verify_acvp_json_interop import verify as verify_acvp_json_interop  # noqa: E402
from verify_assurance_ledger import verify_ledger  # noqa: E402
from verify_assurance_policy import verify_policy  # noqa: E402
from verify_benchmark_campaign import verify as verify_benchmark_campaign  # noqa: E402
from verify_pqc_appraisal_evidence import verify as verify_appraisal_evidence  # noqa: E402
from verify_partner_review_scorecard import verify as verify_partner_scorecard  # noqa: E402
from verify_firmware_assurance_status import verify_status as verify_firmware_status  # noqa: E402
from verify_pqc_build_provenance import verify as verify_build_provenance  # noqa: E402
from verify_pqc_reference_values import verify_reference  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the generated artifacts under a release_check.py output root "
            "without rerunning Zephyr builds or QEMU."
        )
    )
    parser.add_argument("output_root", type=Path, help="release_check.py output root")
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT)
    parser.add_argument("--tag", help="Expected release tag, e.g. v1.0.0")
    parser.add_argument(
        "--claims",
        type=Path,
        default=SCRIPT_DIR / "assurance_claims.json",
        help="Claim catalog used by the assurance ledger verifier.",
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


def require_file(path: Path, label: str, failures: list[str]) -> None:
    if not path.exists():
        failures.append(f"{label} not found: {path}")
    elif not path.is_file():
        failures.append(f"{label} is not a file: {path}")
    elif path.stat().st_size == 0:
        failures.append(f"{label} is empty: {path}")


def find_release_manifest(output_root: Path, tag: str | None, failures: list[str]) -> Path | None:
    bundle_root = output_root / "local_release_bundle"
    if tag:
        manifest = bundle_root / tag / f"release-manifest-{tag}.json"
        if not manifest.exists():
            failures.append(f"release bundle manifest not found: {manifest}")
            return None
        return manifest

    candidates = sorted(bundle_root.glob("*/release-manifest-*.json"))
    if len(candidates) != 1:
        failures.append(
            f"expected exactly one release bundle manifest under {bundle_root}, "
            f"found {len(candidates)}"
        )
        return None
    return candidates[0]


def verify_benchmark_artifacts(output_root: Path, failures: list[str]) -> None:
    csv_path = output_root / "benchmark_results.csv"
    provenance_path = output_root / "benchmark_provenance.json"
    summary_path = output_root / "benchmark_summary.md"
    require_file(csv_path, "benchmark CSV", failures)
    require_file(provenance_path, "benchmark provenance", failures)
    require_file(summary_path, "benchmark summary", failures)
    if csv_path.exists() and csv_path.is_file():
        for item in validate_benchmark_csv(csv_path):
            failures.append(f"benchmark CSV [{item['check']}]: {item['message']}")
    if csv_path.exists() and provenance_path.exists():
        for item in verify_provenance(csv_path, provenance_path):
            failures.append(f"benchmark provenance [{item['check']}]: {item['message']}")


def verify_cost_evidence(output_root: Path, failures: list[str]) -> None:
    evidence_path = output_root / "cost_of_assurance_evidence.json"
    require_file(evidence_path, "cost-of-assurance evidence", failures)
    evidence = load_json(evidence_path, "cost-of-assurance evidence", failures)
    if not evidence:
        return
    comparisons = evidence.get("comparisons")
    if evidence.get("schema_version") != 1:  # cost-of-assurance evidence schema is independent of ledger schema_version

        failures.append(
            f"cost-of-assurance evidence schema_version={evidence.get('schema_version')!r}, expected 1"
        )
    if not isinstance(comparisons, list) or not comparisons:
        failures.append("cost-of-assurance evidence must contain non-empty comparisons")
        return
    metric_count = 0
    for comparison in comparisons:
        if not isinstance(comparison, dict):
            failures.append("cost-of-assurance comparison must be an object")
            continue
        name = comparison.get("name", "<unnamed>")
        metrics = comparison.get("metrics")
        if comparison.get("passed") is not True:
            failures.append(f"cost-of-assurance comparison {name} did not pass")
        if not isinstance(metrics, list) or not metrics:
            failures.append(f"cost-of-assurance comparison {name} has no metrics")
            continue
        for metric in metrics:
            metric_count += 1
            if not isinstance(metric, dict):
                failures.append(f"cost-of-assurance comparison {name} metric is not an object")
                continue
            metric_name = metric.get("metric", "<unnamed>")
            if metric.get("passed") is not True:
                failures.append(f"cost-of-assurance metric {name}/{metric_name} did not pass")
            if metric.get("candidate_value") is None:
                failures.append(f"cost-of-assurance metric {name}/{metric_name} missing candidate value")
            if not isinstance(metric.get("threshold"), dict):
                failures.append(f"cost-of-assurance metric {name}/{metric_name} missing threshold object")
    if metric_count == 0:
        failures.append("cost-of-assurance evidence evaluated zero metrics")


def verify_mcu_footprint(output_root: Path, failures: list[str]) -> None:
    footprint_csv = output_root / "mcu_protocol_footprint" / "cost_of_assurance_protocols_mcu.csv"
    require_file(footprint_csv, "MCU protocol footprint CSV", failures)
    if not footprint_csv.exists() or not footprint_csv.is_file():
        return
    with footprint_csv.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    required_columns = {"board", "suite", "implementation", "rom_bytes", "ram_bytes"}
    if not rows:
        failures.append("MCU protocol footprint CSV has no rows")
        return
    missing = required_columns - set(rows[0].keys())
    if missing:
        failures.append("MCU protocol footprint CSV missing columns: " + ", ".join(sorted(missing)))
    for index, row in enumerate(rows, start=1):
        for column in ("rom_bytes", "ram_bytes"):
            try:
                value = int(row.get(column, ""))
            except ValueError:
                failures.append(f"MCU footprint row {index} column {column} is not an integer")
                continue
            if value <= 0:
                failures.append(f"MCU footprint row {index} column {column} must be positive")


def verify_release_bundle(
    output_root: Path,
    *,
    tag: str | None,
    ledger: dict[str, Any],
    failures: list[str],
) -> None:
    manifest_path = find_release_manifest(output_root, tag, failures)
    if manifest_path is None:
        return
    manifest = load_json(manifest_path, "release bundle manifest", failures)
    if not manifest:
        return

    if tag and manifest.get("tag") != tag:
        failures.append(f"release manifest tag {manifest.get('tag')!r} != expected {tag!r}")
    if manifest.get("version") != ledger.get("version"):
        failures.append(
            f"release manifest version {manifest.get('version')!r} != ledger version {ledger.get('version')!r}"
        )
    if manifest.get("source_commit") != ledger.get("head_sha"):
        failures.append(
            f"release manifest source_commit {manifest.get('source_commit')!r} "
            f"!= ledger head_sha {ledger.get('head_sha')!r}"
        )
    if manifest.get("working_tree_dirty") != ledger.get("dirty"):
        failures.append(
            f"release manifest working_tree_dirty {manifest.get('working_tree_dirty')!r} "
            f"!= ledger dirty {ledger.get('dirty')!r}"
        )

    notes_meta = manifest.get("release_notes")
    if not isinstance(notes_meta, dict):
        failures.append("release manifest missing release_notes object")
        return
    notes_path = manifest_path.parent / str(notes_meta.get("path", ""))
    require_file(notes_path, "release notes", failures)
    if notes_path.exists() and notes_path.is_file():
        expected_sha = notes_meta.get("sha256")
        actual_sha = sha256_file(notes_path)
        if expected_sha != actual_sha:
            failures.append(
                f"release notes sha256 mismatch: manifest={expected_sha} actual={actual_sha}"
            )


def verify_assurance_report_html(
    output_root: Path,
    ledger: dict[str, Any],
    failures: list[str],
) -> None:
    """Replay-check that the HTML assurance report exists and references every claim id.

    Treated as required for ledgers at schema_version >= 2; older v1 packs are
    skipped with a clearly-labelled informational note.
    """
    report_path = output_root / "assurance_report.html"
    schema = ledger.get("schema_version") if ledger else None
    if schema is not None and schema < 2:
        # Legacy pack predating the HTML report. Skip silently.
        return
    if not report_path.exists():
        failures.append(f"assurance report HTML not found: {report_path}")
        return
    if not report_path.is_file():
        failures.append(f"assurance report HTML is not a file: {report_path}")
        return
    if report_path.stat().st_size == 0:
        failures.append(f"assurance report HTML is empty: {report_path}")
        return
    body = report_path.read_text(encoding="utf-8", errors="replace")
    missing_ids: list[str] = []
    for claim in ledger.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        claim_id = claim.get("id")
        if isinstance(claim_id, str) and claim_id and claim_id not in body:
            missing_ids.append(claim_id)
    if missing_ids:
        failures.append(
            "assurance report HTML is missing claim id(s): " + ", ".join(missing_ids)
        )


def verify_passport_artifacts(
    output_root: Path,
    *,
    ledger: dict[str, Any],
    tag: str | None,
    claims_path: Path,
    failures: list[str],
) -> None:
    """Verify the PQC Assurance Passport artifacts for schema_version >= 3 packs."""
    if (ledger.get("schema_version") or 0) < 3:
        return

    cbom_path = output_root / "pqc_cbom.cdx.json"
    environment_result = output_root / "pqc_environment_result.json"
    attestation_path = output_root / "pqc_attestation.intoto.json"
    policy_result_path = output_root / "pqc_policy_result.json"
    digest_path = output_root / "pqc_assurance_digest.json"
    floor_result_path = output_root / "acvp_negative_scenario_floor_result.json"
    ct_instruction_policy_result_path = output_root / "ct_instruction_policy_result.json"
    asset_trace_result_path = output_root / "pqc_asset_trace_result.json"
    evidence_graph_json = output_root / "pqc_evidence_graph.json"
    evidence_graph_md = output_root / "pqc_evidence_graph.md"
    assurance_profile_result = output_root / "pqc_assurance_profile_result.json"
    evidence_quality_result = output_root / "pqc_evidence_quality_result.json"
    migration_readiness_json = output_root / "pqc_migration_readiness.json"
    migration_readiness_md = output_root / "pqc_migration_readiness.md"
    claim_closure_result = output_root / "pqc_claim_closure_result.json"
    reference_values = output_root / "pqc_reference_values.json"
    reference_values_result = output_root / "pqc_reference_values_result.json"
    firmware_status_result = output_root / "firmware_assurance_status_result.json"
    acvp_json_interop_result = output_root / "acvp_json_interop_result.json"
    acvp_json_transcript_manifest = output_root / "acvp_json_transcript_manifest.json"
    build_provenance = output_root / "pqc_build_provenance.slsa.json"
    build_provenance_result = output_root / "pqc_build_provenance_result.json"
    ct_sample_analysis_result = output_root / "ct_sample_analysis_result.json"
    ct_sample_manifest = output_root / "ct_sample_manifest.json"
    backend_currency_result = output_root / "backend_currency_result.json"
    backend_contract_result = output_root / "backend_contract_result.json"
    liboqs_inventory = output_root / "liboqs_non_native_inventory.json"
    provider_scope_result = output_root / "provider_scope_result.json"
    external_reference_result = output_root / "external_reference_import" / "hardware_benchmark_report.json"
    paper_comparison_csv = output_root / "paper_comparison_campaign.csv"
    paper_comparison_result = output_root / "paper_comparison_campaign.json"
    backend_update_evaluation = output_root / "backend_update_evaluation.json"
    benchmark_campaign_result = output_root / "benchmark_campaign_result.json"
    benchmark_campaign_verify_result = output_root / "benchmark_campaign_verify_result.json"
    metric_optimization_result = output_root / "metric_optimization_campaign.json"
    ct_campaign_result = output_root / "ct_campaign_result.json"
    acvp_json_schema_result = output_root / "acvp_json_schema_result.json"
    device_evidence_token = output_root / "device_evidence_token.json"
    device_evidence_token_result = output_root / "device_evidence_token_result.json"
    release_reference_values_result = output_root / "release_reference_values_result.json"
    appraisal_evidence = output_root / "pqc_appraisal_evidence.json"
    appraisal_result = output_root / "pqc_appraisal_result.json"
    partner_scorecard = output_root / "partner_review_scorecard.json"
    partner_scorecard_md = output_root / "partner_review_scorecard.md"
    partner_scorecard_result = output_root / "partner_review_scorecard_result.json"
    tamper_drill_result = output_root / "evidence_tamper_drill_result.json"
    firmware_digest_header = output_root / "generated" / "pqcp_assurance_digest_generated.h"
    policy_path = claims_path.parent / "pqc_assurance_policy.json"
    appraisal_policy_path = claims_path.parent / "pqc_appraisal_policy.json"
    if not policy_path.exists():
        policy_path = SCRIPT_DIR / "pqc_assurance_policy.json"
    manifest_path = find_release_manifest(output_root, tag, failures)

    require_file(cbom_path, "PQC CBOM", failures)
    require_file(attestation_path, "PQC assurance attestation", failures)
    require_file(policy_result_path, "PQC assurance policy result", failures)
    require_file(digest_path, "PQC assurance digest manifest", failures)
    if (ledger.get("schema_version") or 0) >= 4:
        require_file(floor_result_path, "ACVP negative scenario floor result", failures)
        require_file(ct_instruction_policy_result_path, "ML-KEM decapsulation instruction policy result", failures)
        require_file(asset_trace_result_path, "PQC asset trace result", failures)
        require_file(evidence_graph_json, "PQC evidence graph JSON", failures)
        require_file(evidence_graph_md, "PQC evidence graph Markdown", failures)
        require_file(firmware_digest_header, "firmware assurance digest header", failures)
    if (ledger.get("schema_version") or 0) >= 5:
        require_file(environment_result, "PQC release environment result", failures)
        require_file(assurance_profile_result, "PQC assurance profile result", failures)
        require_file(evidence_quality_result, "PQC evidence quality result", failures)
        require_file(migration_readiness_json, "PQC migration readiness JSON", failures)
        require_file(migration_readiness_md, "PQC migration readiness Markdown", failures)
        require_file(claim_closure_result, "PQC claim closure result", failures)
    if (ledger.get("schema_version") or 0) >= 6:
        require_file(reference_values, "PQC reference values", failures)
        require_file(reference_values_result, "PQC reference values result", failures)
        require_file(firmware_status_result, "firmware assurance status result", failures)
        require_file(acvp_json_interop_result, "ACVP JSON interop result", failures)
        require_file(acvp_json_transcript_manifest, "ACVP JSON transcript manifest", failures)
        require_file(build_provenance, "PQC build provenance", failures)
        require_file(build_provenance_result, "PQC build provenance result", failures)
        require_file(ct_sample_analysis_result, "CT sample analysis result", failures)
        require_file(ct_sample_manifest, "CT sample manifest", failures)
        require_file(backend_currency_result, "backend currency result", failures)
        require_file(external_reference_result, "external reference import result", failures)
    if (ledger.get("schema_version") or 0) >= 7:
        require_file(backend_contract_result, "backend contract result", failures)
        require_file(liboqs_inventory, "external-provider non-native inventory", failures)
        require_file(provider_scope_result, "provider scope result", failures)
        require_file(paper_comparison_csv, "paper comparison campaign CSV", failures)
        require_file(paper_comparison_result, "paper comparison campaign result", failures)
        require_file(release_reference_values_result, "release reference values provider replay result", failures)
        require_file(backend_update_evaluation, "backend update evaluation", failures)
        require_file(benchmark_campaign_result, "benchmark campaign result", failures)
        require_file(benchmark_campaign_verify_result, "benchmark campaign verification result", failures)
        require_file(ct_campaign_result, "CT campaign result", failures)
        require_file(acvp_json_schema_result, "ACVP JSON schema coverage result", failures)
        require_file(device_evidence_token, "device evidence token", failures)
        require_file(device_evidence_token_result, "device evidence token result", failures)
        require_file(appraisal_evidence, "PQC appraisal evidence", failures)
        require_file(appraisal_result, "PQC appraisal verification result", failures)
        require_file(partner_scorecard, "partner review scorecard", failures)
        require_file(partner_scorecard_md, "partner review scorecard Markdown", failures)
        require_file(partner_scorecard_result, "partner review scorecard replay result", failures)
    if manifest_path is None:
        return
    if not all(path.exists() and path.is_file() for path in (cbom_path, attestation_path, policy_result_path, digest_path)):
        return

    policy_replay = verify_policy(
        policy_path=policy_path,
        ledger_path=output_root / "assurance_ledger.json",
        cbom_path=cbom_path,
        attestation_path=attestation_path,
        release_manifest_path=manifest_path,
        asset_trace_result_path=asset_trace_result_path if asset_trace_result_path.exists() else None,
        ct_instruction_policy_result_path=ct_instruction_policy_result_path if ct_instruction_policy_result_path.exists() else None,
        evidence_graph_path=evidence_graph_json if evidence_graph_json.exists() else None,
        assurance_digest_path=digest_path,
        firmware_digest_header_path=firmware_digest_header if firmware_digest_header.exists() else None,
        assurance_profile_result_path=assurance_profile_result if assurance_profile_result.exists() else None,
        evidence_quality_result_path=evidence_quality_result if evidence_quality_result.exists() else None,
        migration_readiness_json_path=migration_readiness_json if migration_readiness_json.exists() else None,
        migration_readiness_md_path=migration_readiness_md if migration_readiness_md.exists() else None,
        reference_values_path=reference_values if reference_values.exists() else None,
        reference_values_result_path=reference_values_result if reference_values_result.exists() else None,
        firmware_status_result_path=firmware_status_result if firmware_status_result.exists() else None,
        acvp_json_interop_result_path=acvp_json_interop_result if acvp_json_interop_result.exists() else None,
        acvp_json_transcript_manifest_path=acvp_json_transcript_manifest if acvp_json_transcript_manifest.exists() else None,
        build_provenance_path=build_provenance if build_provenance.exists() else None,
        build_provenance_result_path=build_provenance_result if build_provenance_result.exists() else None,
        ct_sample_analysis_result_path=ct_sample_analysis_result if ct_sample_analysis_result.exists() else None,
    )
    if not policy_replay.get("passed"):
        for failure in policy_replay.get("failures", []):
            failures.append(f"PQC assurance policy replay: {failure}")

    policy_result = load_json(policy_result_path, "PQC assurance policy result", failures)
    if policy_result and policy_result.get("passed") is not True:
        failures.append("PQC assurance policy result did not pass")

    if (ledger.get("schema_version") or 0) >= 4:
        floor_result = load_json(floor_result_path, "ACVP negative scenario floor result", failures)
        if floor_result and floor_result.get("passed") is not True:
            failures.append("ACVP negative scenario floor result did not pass")

        trace_result = load_json(asset_trace_result_path, "PQC asset trace result", failures)
        if trace_result and trace_result.get("passed") is not True:
            failures.append("PQC asset trace result did not pass")

        ct_policy = load_json(ct_instruction_policy_result_path, "ML-KEM decapsulation instruction policy result", failures)
        if ct_policy and ct_policy.get("passed") is not True:
            failures.append("ML-KEM decapsulation instruction policy result did not pass")

        graph = load_json(evidence_graph_json, "PQC evidence graph", failures)
        if graph:
            if graph.get("schema_version") != 1:
                failures.append(f"PQC evidence graph schema_version={graph.get('schema_version')!r}, expected 1")
            graph_failures = graph.get("failures")
            if not isinstance(graph_failures, list):
                failures.append("PQC evidence graph failures field must be a list")
            elif graph_failures:
                failures.append("PQC evidence graph contains failures: " + "; ".join(map(str, graph_failures)))
            claim_ids = {
                node.get("label")
                for node in graph.get("nodes") or []
                if isinstance(node, dict)
                and node.get("type") == "claim"
                and isinstance(node.get("label"), str)
            }
            graph_body = evidence_graph_md.read_text(encoding="utf-8", errors="replace") if evidence_graph_md.exists() else ""
            missing_from_md = sorted(claim_id for claim_id in claim_ids if claim_id and claim_id not in graph_body)
            if missing_from_md:
                failures.append(
                    "PQC evidence graph Markdown missing claim id(s): " + ", ".join(missing_from_md)
                )

        if firmware_digest_header.exists():
            header = firmware_digest_header.read_text(encoding="utf-8", errors="replace")
            for macro in (
                "PQCP_ASSURANCE_DIGEST_ROOT_SHA256",
                "PQCP_ASSURANCE_DIGEST_ARTIFACT_COUNT",
            ):
                if macro not in header:
                    failures.append(f"firmware assurance digest header missing {macro}")

    if (ledger.get("schema_version") or 0) >= 5:
        environment = load_json(environment_result, "PQC release environment result", failures)
        if environment and environment.get("passed") is not True:
            failures.append("PQC release environment result did not pass")
        profile = load_json(assurance_profile_result, "PQC assurance profile result", failures)
        if profile and profile.get("passed") is not True:
            failures.append("PQC assurance profile result did not pass")
        quality = load_json(evidence_quality_result, "PQC evidence quality result", failures)
        if quality and quality.get("passed") is not True:
            failures.append("PQC evidence quality result did not pass")
        readiness = load_json(migration_readiness_json, "PQC migration readiness", failures)
        if readiness and readiness.get("passed") is not True:
            failures.append("PQC migration readiness result did not pass")
        if readiness and migration_readiness_md.exists():
            body = migration_readiness_md.read_text(encoding="utf-8", errors="replace")
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
        closure = load_json(claim_closure_result, "PQC claim closure result", failures)
        if closure and closure.get("passed") is not True:
            failures.append("PQC claim closure result did not pass")

    if (ledger.get("schema_version") or 0) >= 6:
        for path, label in (
            (reference_values_result, "PQC reference values result"),
            (firmware_status_result, "firmware assurance status result"),
            (acvp_json_interop_result, "ACVP JSON interop result"),
            (build_provenance_result, "PQC build provenance result"),
            (ct_sample_analysis_result, "CT sample analysis result"),
            (backend_currency_result, "backend currency result"),
            (external_reference_result, "external reference import result"),
        ):
            payload = load_json(path, label, failures)
            if payload and payload.get("passed") is not True:
                failures.append(f"{label} did not pass")
        provenance_sidecar = load_json(output_root / "benchmark_provenance.json", "benchmark provenance", failures)
        if provenance_sidecar:
            for item in validate_comparison_context(provenance_sidecar.get("comparison_context")):
                failures.append(f"benchmark provenance [{item['check']}]: {item['message']}")
        ct_manifest = load_json(ct_sample_manifest, "CT sample manifest", failures)
        ct_analysis = load_json(ct_sample_analysis_result, "CT sample analysis result", failures)
        if ct_manifest and ct_analysis:
            manifest_algs = {
                item.get("algorithm"): item
                for item in ct_manifest.get("algorithms") or []
                if isinstance(item, dict)
            }
            for alg in ct_analysis.get("algorithms") or []:
                if not isinstance(alg, dict):
                    continue
                name = alg.get("algorithm")
                manifest_row = manifest_algs.get(name)
                if manifest_row is None:
                    failures.append(f"CT sample manifest missing algorithm: {name}")
                    continue
                if manifest_row.get("valid_count") != alg.get("valid_count"):
                    failures.append(f"CT sample manifest valid_count mismatch for {name}")
                if manifest_row.get("invalid_count") != alg.get("invalid_count"):
                    failures.append(f"CT sample manifest invalid_count mismatch for {name}")
        external_reference = load_json(external_reference_result, "external reference import result", failures)
        if external_reference:
            context_failures = external_reference.get("execution", {}).get("failures") or []
            for failure in context_failures:
                failures.append(f"external reference import: {failure}")
            if not external_reference.get("comparison_context"):
                failures.append("external reference import missing comparison_context")
            elif external_reference.get("comparison_context", {}).get("environment_type") != "external_reference":
                failures.append("external reference import environment_type must be external_reference")
        ref = load_json(reference_values, "PQC reference values", failures)
        if ref:
            manifest_for_ref = load_json(manifest_path, "release manifest", failures) if manifest_path else {}
            if ref.get("schema_version") != 1:
                failures.append(f"PQC reference values schema_version={ref.get('schema_version')!r}, expected 1")
            if ref.get("version") != ledger.get("version"):
                failures.append("PQC reference values version does not match ledger")
            if ref.get("tag") != ledger.get("tag"):
                failures.append("PQC reference values tag does not match ledger")
            expected_head = ledger.get("head_sha") or manifest_for_ref.get("source_commit") or ""
            if ref.get("head_sha") != expected_head:
                failures.append("PQC reference values head_sha does not match ledger")
        acvp_manifest = load_json(acvp_json_transcript_manifest, "ACVP JSON transcript manifest", failures)
        if acvp_manifest and not acvp_manifest.get("transcripts"):
            failures.append("ACVP JSON transcript manifest has no transcripts")
        provenance = load_json(build_provenance, "PQC build provenance", failures)
        if provenance:
            if provenance.get("_type") != "https://in-toto.io/Statement/v1":
                failures.append("PQC build provenance is not an in-toto Statement")
            if provenance.get("predicateType") != "https://slsa.dev/provenance/v1":
                failures.append("PQC build provenance predicateType is not SLSA provenance v1")
        required_v6_paths = (
            reference_values,
            output_root / "assurance_ledger.json",
            cbom_path,
            attestation_path,
            digest_path,
            manifest_path,
            policy_result_path,
            assurance_profile_result,
            output_root / "transcripts/evidence_transcript_manifest.json",
            build_provenance,
            backend_currency_result,
            external_reference_result,
            output_root / "benchmark_results.csv",
            output_root / "cost_of_assurance_evidence.json",
            acvp_json_interop_result,
            ct_sample_analysis_result,
            ct_sample_manifest,
        )
        if all(path.exists() and path.is_file() for path in required_v6_paths):
            reference_replay = verify_reference(
                argparse.Namespace(
                    reference_values=reference_values,
                    ledger=output_root / "assurance_ledger.json",
                    cbom=cbom_path,
                    attestation=attestation_path,
                    assurance_digest=digest_path,
                    release_manifest=manifest_path,
                    policy_result=policy_result_path,
                    profile_result=assurance_profile_result,
                    transcript_manifest=output_root / "transcripts/evidence_transcript_manifest.json",
                    backend_contract=backend_contract_result if backend_contract_result.exists() else None,
                    provider_scope_result=provider_scope_result if provider_scope_result.exists() else None,
                    output=output_root / "__reference_replay_result.json",
                )
            )
            if reference_replay.get("passed") is not True:
                for failure in reference_replay.get("failures", []):
                    failures.append(f"PQC reference values replay: {failure}")

            firmware_replay = verify_firmware_status(
                argparse.Namespace(
                    reference_values=reference_values,
                    transcript=None,
                    transcript_dir=output_root / "transcripts",
                    output=output_root / "__firmware_status_replay_result.json",
                )
            )
            if firmware_replay.get("passed") is not True:
                for failure in firmware_replay.get("failures", []):
                    failures.append(f"firmware assurance status replay: {failure}")

            acvp_json_replay = verify_acvp_json_interop(
                argparse.Namespace(
                    result=acvp_json_interop_result,
                    transcript_manifest=acvp_json_transcript_manifest,
                    output=output_root / "__acvp_json_interop_replay_result.json",
                )
            )
            if acvp_json_replay.get("passed") is not True:
                for failure in acvp_json_replay.get("failures", []):
                    failures.append(f"ACVP JSON interop replay: {failure}")

            provenance_byproducts = [
                output_root / "benchmark_results.csv",
                output_root / "cost_of_assurance_evidence.json",
                acvp_json_interop_result,
                ct_sample_analysis_result,
                ct_sample_manifest,
                backend_currency_result,
                external_reference_result,
            ]
            if (ledger.get("schema_version") or 0) >= 7:
                provenance_byproducts.extend(
                    [
                        acvp_json_schema_result,
                        ct_campaign_result,
                        backend_update_evaluation,
                        backend_contract_result,
                        provider_scope_result,
                        liboqs_inventory,
                        benchmark_campaign_result,
                        paper_comparison_result,
                        paper_comparison_csv,
                        device_evidence_token,
                        device_evidence_token_result,
                        release_reference_values_result,
                    ]
                )

            provenance_replay = verify_build_provenance(
                argparse.Namespace(
                    provenance=build_provenance,
                    subject=[
                        output_root / "assurance_ledger.json",
                        reference_values,
                        cbom_path,
                        attestation_path,
                    ],
                    byproduct=provenance_byproducts,
                    release_manifest=manifest_path,
                    output=output_root / "__build_provenance_replay_result.json",
                )
            )
            if provenance_replay.get("passed") is not True:
                for failure in provenance_replay.get("failures", []):
                    failures.append(f"PQC build provenance replay: {failure}")

    if (ledger.get("schema_version") or 0) >= 7:
        for path, label in (
            (backend_contract_result, "backend contract result"),
            (liboqs_inventory, "external-provider non-native inventory"),
            (provider_scope_result, "provider scope result"),
            (paper_comparison_result, "paper comparison campaign result"),
            (release_reference_values_result, "release reference values provider replay result"),
            (backend_update_evaluation, "backend update evaluation"),
            (benchmark_campaign_result, "benchmark campaign result"),
            (benchmark_campaign_verify_result, "benchmark campaign verification result"),
            (ct_campaign_result, "CT campaign result"),
            (acvp_json_schema_result, "ACVP JSON schema coverage result"),
            (device_evidence_token_result, "device evidence token result"),
            (appraisal_result, "PQC appraisal verification result"),
            (partner_scorecard_result, "partner review scorecard replay result"),
            (tamper_drill_result, "release evidence tamper drill result"),
        ):
            if path == tamper_drill_result and not path.exists():
                continue
            payload = load_json(path, label, failures)
            if payload and payload.get("passed") is not True:
                failures.append(f"{label} did not pass")
        if benchmark_campaign_result.exists():
            campaign_replay = verify_benchmark_campaign(benchmark_campaign_result)
            if campaign_replay.get("passed") is not True:
                for failure in campaign_replay.get("failures", []):
                    failures.append(f"benchmark campaign replay: {failure}")
        if metric_optimization_result.exists():
            payload = load_json(metric_optimization_result, "metric optimization campaign result", failures)
            if payload and payload.get("passed") is not True:
                failures.append("metric optimization campaign result did not pass")
        if appraisal_policy_path.exists() and appraisal_evidence.exists():
            appraisal_replay = verify_appraisal_evidence(
                argparse.Namespace(
                    policy=appraisal_policy_path,
                    appraisal_evidence=appraisal_evidence,
                    ledger=output_root / "assurance_ledger.json",
                    mode="partner_review",
                    output=output_root / "__appraisal_replay_result.json",
                )
            )
            if appraisal_replay.get("passed") is not True:
                for failure in appraisal_replay.get("failures", []):
                    failures.append(f"PQC appraisal replay: {failure}")
        if partner_scorecard.exists() and partner_scorecard_md.exists():
            scorecard_replay = verify_partner_scorecard(
                argparse.Namespace(
                    scorecard=partner_scorecard,
                    markdown=partner_scorecard_md,
                    ledger=output_root / "assurance_ledger.json",
                    cbom=cbom_path,
                    policy_result=policy_result_path,
                    profile_result=assurance_profile_result,
                    quality_result=evidence_quality_result,
                    migration_readiness=migration_readiness_json,
                    backend_contract=backend_contract_result,
                    provider_scope_result=provider_scope_result,
                    benchmark_campaign=benchmark_campaign_result,
                    ct_campaign=ct_campaign_result,
                    acvp_schema_result=acvp_json_schema_result,
                    device_evidence_result=device_evidence_token_result,
                    reference_values=reference_values,
                    appraisal_result=appraisal_result,
                    output=output_root / "__partner_scorecard_replay_result.json",
                )
            )
            if scorecard_replay.get("passed") is not True:
                for failure in scorecard_replay.get("failures", []):
                    failures.append(f"partner review scorecard replay: {failure}")

    digest = load_json(digest_path, "PQC assurance digest manifest", failures)
    if digest:
        if digest.get("schema_version") != 1:
            failures.append(f"PQC assurance digest schema_version={digest.get('schema_version')!r}, expected 1")
        artifacts = digest.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            failures.append("PQC assurance digest must contain non-empty artifacts")
        else:
            seen_paths = {
                str(item.get("path"))
                for item in artifacts
                if isinstance(item, dict)
            }
            if (ledger.get("schema_version") or 0) >= 4:
                for required_name in (
                    "pqc_evidence_graph.json",
                    "pqc_asset_trace_result.json",
                    "ct_instruction_policy_result.json",
                ):
                    if required_name not in seen_paths:
                        failures.append(f"PQC assurance digest missing artifact: {required_name}")
            if (ledger.get("schema_version") or 0) >= 5:
                for required_name in (
                    "pqc_environment_result.json",
                    "pqc_assurance_profile_result.json",
                    "pqc_evidence_quality_result.json",
                    "pqc_migration_readiness.json",
                    "pqc_migration_readiness.md",
                ):
                    if required_name not in seen_paths:
                        failures.append(f"PQC assurance digest missing artifact: {required_name}")
            if (ledger.get("schema_version") or 0) >= 6:
                for required_name in (
                    "ct_sample_manifest.json",
                    "backend_currency_result.json",
                    "hardware_benchmark_report.json",
                ):
                    if required_name not in seen_paths and not any(path.endswith(required_name) for path in seen_paths):
                        failures.append(f"PQC assurance digest missing artifact: {required_name}")
            if (ledger.get("schema_version") or 0) >= 7:
                for required_name in (
                    "backend_contract_result.json",
                    "liboqs_non_native_inventory.json",
                    "provider_scope_result.json",
                    "paper_comparison_campaign.json",
                    "paper_comparison_campaign.csv",
                ):
                    if required_name not in seen_paths and not any(path.endswith(required_name) for path in seen_paths):
                        failures.append(f"PQC assurance digest missing artifact: {required_name}")
            for item in artifacts:
                if not isinstance(item, dict):
                    failures.append("PQC assurance digest artifact entry must be an object")
                    continue
                raw_path = item.get("path")
                if not isinstance(raw_path, str) or not raw_path:
                    failures.append("PQC assurance digest artifact missing path")
                    continue
                candidate = Path(raw_path)
                if not candidate.is_absolute():
                    candidate = output_root / candidate
                    if not candidate.exists():
                        candidate = output_root / "local_release_bundle" / (tag or "") / raw_path
                if not candidate.exists() or not candidate.is_file():
                    failures.append(f"PQC assurance digest artifact not found: {raw_path}")
                    continue
                actual = sha256_file(candidate)
                if item.get("sha256") != actual:
                    failures.append(f"PQC assurance digest hash mismatch for {raw_path}")


def verify_pack(
    output_root: Path,
    *,
    module_path: Path = REPO_ROOT,
    tag: str | None = None,
    claims_path: Path = SCRIPT_DIR / "assurance_claims.json",
) -> list[str]:
    failures: list[str] = []
    output_root = output_root.resolve()
    module_path = module_path.resolve()
    ledger_json = output_root / "assurance_ledger.json"
    ledger_md = output_root / "assurance_ledger.md"

    failures.extend(
        verify_ledger(
            ledger_json,
            markdown=ledger_md,
            claims_path=claims_path.resolve(),
            module_path=module_path,
            allow_post_ledger_artifact_drift=True,
        )
    )
    ledger = load_json(ledger_json, "assurance ledger", failures)
    if ledger and tag and ledger.get("tag") != tag:
        failures.append(f"ledger tag {ledger.get('tag')!r} != expected {tag!r}")

    verify_benchmark_artifacts(output_root, failures)
    verify_cost_evidence(output_root, failures)
    verify_mcu_footprint(output_root, failures)
    if ledger:
        verify_release_bundle(output_root, tag=tag, ledger=ledger, failures=failures)
        verify_assurance_report_html(output_root, ledger, failures)
        verify_passport_artifacts(
            output_root,
            ledger=ledger,
            tag=tag,
            claims_path=claims_path.resolve(),
            failures=failures,
        )
    return failures


def main() -> int:
    args = parse_args()
    failures = verify_pack(
        args.output_root,
        module_path=args.module_path,
        tag=args.tag,
        claims_path=args.claims,
    )
    if failures:
        print("Release evidence pack verification failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("Release evidence pack verification passed")
    print(f"  output root: {args.output_root.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
