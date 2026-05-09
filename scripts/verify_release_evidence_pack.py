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

from export_results import validate_benchmark_csv, verify_provenance  # noqa: E402
from verify_assurance_ledger import verify_ledger  # noqa: E402
from verify_assurance_policy import verify_policy  # noqa: E402


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
    attestation_path = output_root / "pqc_attestation.intoto.json"
    policy_result_path = output_root / "pqc_policy_result.json"
    digest_path = output_root / "pqc_assurance_digest.json"
    floor_result_path = output_root / "acvp_negative_scenario_floor_result.json"
    asset_trace_result_path = output_root / "pqc_asset_trace_result.json"
    evidence_graph_json = output_root / "pqc_evidence_graph.json"
    evidence_graph_md = output_root / "pqc_evidence_graph.md"
    firmware_digest_header = output_root / "generated" / "pqcp_assurance_digest_generated.h"
    policy_path = claims_path.parent / "pqc_assurance_policy.json"
    if not policy_path.exists():
        policy_path = SCRIPT_DIR / "pqc_assurance_policy.json"
    manifest_path = find_release_manifest(output_root, tag, failures)

    require_file(cbom_path, "PQC CBOM", failures)
    require_file(attestation_path, "PQC assurance attestation", failures)
    require_file(policy_result_path, "PQC assurance policy result", failures)
    require_file(digest_path, "PQC assurance digest manifest", failures)
    if (ledger.get("schema_version") or 0) >= 4:
        require_file(floor_result_path, "ACVP negative scenario floor result", failures)
        require_file(asset_trace_result_path, "PQC asset trace result", failures)
        require_file(evidence_graph_json, "PQC evidence graph JSON", failures)
        require_file(evidence_graph_md, "PQC evidence graph Markdown", failures)
        require_file(firmware_digest_header, "firmware assurance digest header", failures)
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
        evidence_graph_path=evidence_graph_json if evidence_graph_json.exists() else None,
        assurance_digest_path=digest_path,
        firmware_digest_header_path=firmware_digest_header if firmware_digest_header.exists() else None,
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
                ):
                    if required_name not in seen_paths:
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
