#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
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
