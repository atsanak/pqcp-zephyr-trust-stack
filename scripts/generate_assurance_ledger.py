#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Generate a local release assurance ledger from validated artifacts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from check_version_consistency import (  # noqa: E402
    normalize_tag,
    parse_cmake_version,
    parse_header_version,
    validate_changelog,
)
from export_results import validate_benchmark_csv, verify_provenance  # noqa: E402
from verify_kat_provenance import (  # noqa: E402
    DEFAULT_HEADER as DEFAULT_KAT_HEADER,
    DEFAULT_VECTORS_DIR,
    VECTOR_SPECS,
    fixture_constants,
    load_all_fixture_constants,
    load_header_constants,
    verify_vectors,
)

LEDGER_SCHEMA_VERSION = 4
SUPPORTED_CLAIMS_SCHEMA_VERSIONS = (1, 2, 3, 4)
DEFAULT_CLAIMS = SCRIPT_DIR / "assurance_claims.json"
DEFAULT_NEGATIVE_SCENARIOS = SCRIPT_DIR / "acvp_negative_scenarios.json"

PER_PRIMITIVE_KAT_CLAIMS = {
    "kat.mlkem_512": "ML-KEM-512",
    "kat.mlkem_768": "ML-KEM-768",
    "kat.mlkem_1024": "ML-KEM-1024",
    "kat.mldsa_44": "ML-DSA-44",
    "kat.mldsa_65": "ML-DSA-65",
    "kat.mldsa_87": "ML-DSA-87",
}

PER_PRIMITIVE_BENCH_CLAIMS = {
    "benchmark.mlkem_throughput": (
        "ML-KEM",
        ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"),
    ),
    "benchmark.mldsa_throughput": (
        "ML-DSA",
        ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"),
    ),
}
REQUIRED_TRANSCRIPT_STEPS = (
    "Extended Checks (strict cost-of-assurance smoke)",
    "ACVP serial ztest run",
    "ACVP KAT ztest run",
    "benchmark_csv",
    "benchmark_csv_validate",
    "resource_budgets",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a machine-readable PQCP release assurance ledger."
    )
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT)
    parser.add_argument("--claims", type=Path, default=DEFAULT_CLAIMS)
    parser.add_argument("--version", help="Expected release version. Defaults to version.h")
    parser.add_argument("--tag", help="Optional release tag to verify, e.g. v1.0.0")
    parser.add_argument("--benchmark-csv", type=Path, required=True)
    parser.add_argument("--benchmark-provenance", type=Path, required=True)
    parser.add_argument("--cost-of-assurance-evidence", type=Path, required=True)
    parser.add_argument("--release-bundle-root", type=Path, required=True)
    parser.add_argument("--transcript-manifest", type=Path, required=True)
    parser.add_argument("--kat-header", type=Path, default=DEFAULT_KAT_HEADER)
    parser.add_argument("--kat-vectors-dir", type=Path, default=DEFAULT_VECTORS_DIR)
    parser.add_argument(
        "--negative-scenarios",
        type=Path,
        default=DEFAULT_NEGATIVE_SCENARIOS,
        help="ACVP negative-scenario fixture used by acvp.negative_path_rejection.",
    )
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-md", type=Path, required=True)
    parser.add_argument("--cbom", type=Path, help="Optional pqc_cbom.cdx.json artifact")
    parser.add_argument("--attestation", type=Path, help="Optional pqc_attestation.intoto.json artifact")
    parser.add_argument("--policy-result", type=Path, help="Optional pqc_policy_result.json artifact")
    parser.add_argument("--assurance-digest", type=Path, help="Optional pqc_assurance_digest.json artifact")
    parser.add_argument(
        "--negative-scenario-floor-result",
        type=Path,
        help="Optional ACVP negative scenario floor validation result JSON.",
    )
    parser.add_argument("--asset-trace-result", type=Path, help="Optional PQC asset trace validation result JSON.")
    parser.add_argument("--evidence-graph", type=Path, help="Optional PQC evidence graph JSON artifact.")
    parser.add_argument("--firmware-digest-header", type=Path, help="Optional generated firmware digest header.")
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def git_optional(module_path: Path, *args: str) -> str | None:
    result = subprocess.run(
        ["git", *args],
        cwd=str(module_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def artifact(path: Path, *, label: str) -> dict[str, object]:
    exists = path.exists()
    data: dict[str, object] = {
        "label": label,
        "path": str(path),
        "exists": exists,
    }
    if exists and path.is_file():
        data["sha256"] = sha256_file(path)
    return data


def pass_claim(
    spec: dict[str, Any],
    *,
    validators: list[str],
    evidence_artifacts: list[dict[str, object]],
    commands: list[str],
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        **base_claim(spec),
        "status": "pass",
        "validators": validators,
        "evidence_artifacts": evidence_artifacts,
        "commands": commands,
        "failure_reason": None,
        "details": details or {},
    }


def fail_claim(
    spec: dict[str, Any],
    *,
    reason: str,
    validators: list[str],
    evidence_artifacts: list[dict[str, object]],
    commands: list[str],
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        **base_claim(spec),
        "status": "fail",
        "validators": validators,
        "evidence_artifacts": evidence_artifacts,
        "commands": commands,
        "failure_reason": reason,
        "details": details or {},
    }


def not_applicable_claim(
    spec: dict[str, Any],
    *,
    reason: str,
    validators: list[str],
    evidence_artifacts: list[dict[str, object]],
    commands: list[str],
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        **base_claim(spec),
        "status": "not_applicable",
        "validators": validators,
        "evidence_artifacts": evidence_artifacts,
        "commands": commands,
        "failure_reason": reason,
        "details": details or {},
    }


def base_claim(spec: dict[str, Any]) -> dict[str, object]:
    return {
        "id": spec["id"],
        "category": spec["category"],
        "claim": spec["claim"],
        "required": bool(spec.get("required", True)),
    }


def resolve_path(path: Path, module_path: Path) -> Path:
    return path if path.is_absolute() else (module_path / path).resolve()


def load_claim_specs(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    schema_version = raw.get("schema_version")
    if schema_version not in SUPPORTED_CLAIMS_SCHEMA_VERSIONS:
        raise RuntimeError(
            f"unsupported assurance claims schema_version={schema_version!r} in {path}; "
            f"supported versions: {list(SUPPORTED_CLAIMS_SCHEMA_VERSIONS)}"
        )
    if schema_version == 1:
        print(
            f"[warn] {path} uses claims schema_version=1; per-primitive KAT and "
            "benchmark claims and the ACVP negative/timeout claims will not be "
            "populated. Update the catalog to schema_version=4 for the full set.",
            file=sys.stderr,
        )
    claims = raw.get("claims")
    if not isinstance(claims, list) or not claims:
        raise RuntimeError(f"{path} does not define any claims")
    seen: set[str] = set()
    for claim in claims:
        claim_id = claim.get("id")
        if not isinstance(claim_id, str) or not claim_id:
            raise RuntimeError(f"{path} contains a claim without an id")
        if claim_id in seen:
            raise RuntimeError(f"{path} contains duplicate claim id {claim_id}")
        seen.add(claim_id)
        for key in ("category", "claim"):
            if not isinstance(claim.get(key), str) or not claim[key]:
                raise RuntimeError(f"{path} claim {claim_id} is missing {key}")
    return claims


def find_release_manifest(bundle_root: Path, tag: str | None) -> Path | None:
    candidates = sorted(bundle_root.glob("*/release-manifest-*.json"))
    if tag:
        tagged = [
            path
            for path in candidates
            if path.parent.name == tag and path.name == f"release-manifest-{tag}.json"
        ]
        return tagged[0] if tagged else None
    if len(candidates) == 1:
        return candidates[0]
    return None


def evaluate_version_consistency(
    spec: dict[str, Any],
    *,
    module_path: Path,
    version: str,
    tag: str | None,
) -> dict[str, object]:
    changelog = module_path / "CHANGELOG.md"
    artifacts = [
        artifact(module_path / "include/pqcp_zephyr/version.h", label="version header"),
        artifact(module_path / "CMakeLists.txt", label="CMake version"),
        artifact(changelog, label="changelog"),
    ]
    validators = ["scripts/check_version_consistency.py"]
    commands = [
        "python3 scripts/check_version_consistency.py --changelog CHANGELOG.md"
        + (f" --tag {tag}" if tag else "")
    ]
    failures: list[str] = []
    header_version = parse_header_version(module_path)
    cmake_version = parse_cmake_version(module_path)
    if version != header_version:
        failures.append(f"requested version={version} does not match version.h={header_version}")
    if header_version != cmake_version:
        failures.append(f"version.h={header_version} does not match CMakeLists.txt={cmake_version}")
    if tag and normalize_tag(tag) != header_version:
        failures.append(f"tag={normalize_tag(tag)} does not match version.h={header_version}")
    failures.extend(validate_changelog(changelog, header_version))
    details = {
        "version": version,
        "version_h": header_version,
        "cmake": cmake_version,
        "tag": tag,
    }
    if failures:
        return fail_claim(
            spec,
            reason="; ".join(failures),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details=details,
    )


def evaluate_tag_integrity(
    spec: dict[str, Any],
    *,
    module_path: Path,
    tag: str | None,
) -> dict[str, object]:
    validators = ["git rev-parse", "git cat-file -t"]
    commands = [
        f"git rev-parse refs/tags/{tag}" if tag else "git rev-parse refs/tags/<tag>",
        f"git rev-parse refs/tags/{tag}^{{}}" if tag else "git rev-parse refs/tags/<tag>^{}",
    ]
    if not tag:
        return not_applicable_claim(
            spec,
            reason="no --tag supplied; release tag integrity is not applicable",
            validators=validators,
            evidence_artifacts=[],
            commands=commands,
        )
    tag_ref = f"refs/tags/{tag}"
    tag_object = git_optional(module_path, "rev-parse", tag_ref)
    tag_commit = git_optional(module_path, "rev-parse", f"{tag_ref}^{{}}")
    tag_type = git_optional(module_path, "cat-file", "-t", tag_ref)
    details = {
        "tag": tag,
        "tag_object": tag_object,
        "tag_commit": tag_commit,
        "tag_type": tag_type,
    }
    if not tag_object or not tag_commit:
        return fail_claim(
            spec,
            reason=f"local tag {tag} was not found",
            validators=validators,
            evidence_artifacts=[],
            commands=commands,
            details=details,
        )
    if tag_type != "tag":
        return fail_claim(
            spec,
            reason=f"local tag {tag} is not annotated (git object type: {tag_type})",
            validators=validators,
            evidence_artifacts=[],
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=[],
        commands=commands,
        details=details,
    )


def evaluate_kat_provenance(
    spec: dict[str, Any],
    *,
    header: Path,
    vectors_dir: Path,
) -> dict[str, object]:
    artifacts = [
        artifact(header, label="KAT header"),
        artifact(vectors_dir, label="vendored NIST ACVP fixtures"),
    ]
    validators = ["scripts/verify_kat_provenance.py"]
    commands = [f"python3 scripts/verify_kat_provenance.py --header {header}"]
    try:
        fixture_strings, fixture_numeric, _metadata = load_all_fixture_constants(vectors_dir)
        header_strings, header_numeric = load_header_constants(header)
        mismatches = verify_vectors(
            header_strings,
            header_numeric,
            fixture_strings,
            fixture_numeric,
        )
    except Exception as exc:  # noqa: BLE001 - render exact validation defect.
        return fail_claim(
            spec,
            reason=str(exc),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    if mismatches:
        return fail_claim(
            spec,
            reason="; ".join(mismatches),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details={"fixture_count": len(list(vectors_dir.glob("*.json")))},
    )


def evaluate_kat_per_primitive(
    spec: dict[str, Any],
    *,
    header: Path,
    vectors_dir: Path,
    parameter_set: str,
) -> dict[str, object]:
    """Verify the subset of NIST ACVP fixtures for a single parameter set."""
    relevant_specs = [s for s in VECTOR_SPECS if s.parameter_set == parameter_set]
    fixture_paths = [vectors_dir / s.fixture for s in relevant_specs]
    artifacts = [artifact(header, label="KAT header")]
    artifacts.extend(
        artifact(path, label=f"{parameter_set} fixture: {path.name}") for path in fixture_paths
    )
    validators = ["scripts/verify_kat_provenance.py"]
    commands = [f"python3 scripts/verify_kat_provenance.py --header {header}"]

    if not relevant_specs:
        return fail_claim(
            spec,
            reason=f"no VECTOR_SPECS configured for {parameter_set}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )

    try:
        header_strings, header_numeric = load_header_constants(header)
        fixture_strings: dict[str, str] = {}
        fixture_numeric: dict[str, int] = {}
        for vec_spec in relevant_specs:
            strings, numeric, _meta = fixture_constants(vec_spec, vectors_dir)
            fixture_strings.update(strings)
            fixture_numeric.update(numeric)
        mismatches = verify_vectors(
            header_strings,
            header_numeric,
            fixture_strings,
            fixture_numeric,
        )
    except Exception as exc:  # noqa: BLE001 - render exact validation defect.
        return fail_claim(
            spec,
            reason=f"{parameter_set}: {exc}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )

    details = {
        "parameter_set": parameter_set,
        "fixtures": [s.fixture for s in relevant_specs],
        "operations": [s.operation for s in relevant_specs],
    }
    if mismatches:
        return fail_claim(
            spec,
            reason=f"{parameter_set}: " + "; ".join(mismatches),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details=details,
    )


def evaluate_benchmark_per_primitive(
    spec: dict[str, Any],
    *,
    csv_path: Path,
    algorithm: str,
    parameter_levels: tuple[str, ...],
) -> dict[str, object]:
    """Verify per-parameter-set rows for ML-KEM or ML-DSA in the benchmark CSV."""
    artifacts = [artifact(csv_path, label="benchmark CSV")]
    validators = ["scripts/export_results.py --validate-only"]
    commands = [f"python3 scripts/export_results.py --validate-only {csv_path}"]
    if not csv_path.exists():
        return fail_claim(
            spec,
            reason=f"benchmark CSV not found: {csv_path}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )

    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    expected_levels = set(parameter_levels)
    rows_per_level: dict[str, int] = {}
    failures: list[str] = []
    matched_total = 0
    for row in rows:
        parameter_set = str(row.get("parameter_set", "")).strip()
        if parameter_set not in expected_levels:
            continue
        matched_total += 1
        rows_per_level[parameter_set] = rows_per_level.get(parameter_set, 0) + 1
        for column in ("cycles", "time_us"):
            raw = row.get(column, "")
            try:
                value = float(raw) if raw not in ("", None) else 0.0
            except ValueError:
                failures.append(
                    f"{parameter_set} row has non-numeric {column}={raw!r}"
                )
                continue
            if value <= 0.0:
                failures.append(
                    f"{parameter_set} row has non-positive {column}={value}"
                )

    missing_levels = [level for level in parameter_levels if level not in rows_per_level]
    if missing_levels:
        failures.append(
            f"missing benchmark rows for {algorithm} parameter sets: {', '.join(missing_levels)}"
        )

    details = {
        "algorithm": algorithm,
        "expected_parameter_sets": list(parameter_levels),
        "rows_per_parameter_set": rows_per_level,
        "matched_row_count": matched_total,
    }
    if failures:
        return fail_claim(
            spec,
            reason="; ".join(failures),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details=details,
    )


def _read_acvp_serial_transcript(manifest_path: Path) -> tuple[Path | None, str | None, str]:
    """Return (transcript_path, sha256, body) for the ACVP serial ztest run."""
    return _read_named_transcript(manifest_path, "ACVP serial ztest run")


def _read_named_transcript(
    manifest_path: Path, step_name: str
) -> tuple[Path | None, str | None, str]:
    if not manifest_path.exists():
        return None, None, ""
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None, None, ""
    for entry in manifest.get("transcripts", []) or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("step") != step_name:
            continue
        path = resolve_transcript_path(manifest_path, entry.get("transcript_path"))
        if path is None or not path.exists() or not path.is_file():
            return None, entry.get("sha256"), ""
        return path, entry.get("sha256"), path.read_text(encoding="utf-8", errors="replace")
    return None, None, ""


def evaluate_acvp_negative_replay(
    spec: dict[str, Any],
    *,
    scenarios_path: Path,
    transcript_manifest: Path,
    required_response_substrings: tuple[str, ...] = (),
    label: str = "ACVP negative replay",
) -> dict[str, object]:
    """Bind tests/ztest_acvp_serial_negative output to the given claim.

    The C-side test iterates every replay-eligible case from
    scripts/acvp_negative_scenarios.json and asserts the produced wire
    response matches the documented ERROR:* string. This evaluator does
    not re-run the test; it verifies the captured transcript reports
    suite success and (optionally) that a category-specific marker — for
    example "MLKEM" or "MLDSA" in a case name — actually appeared in the
    test output.
    """
    artifacts = [
        artifact(scenarios_path, label="ACVP negative scenarios fixture"),
        artifact(transcript_manifest, label="release-check transcript manifest"),
    ]
    validators = ["tests/ztest_acvp_serial_negative::test_every_negative_scenario_rejected"]
    commands = ["west build -b qemu_x86_64 tests/ztest_acvp_serial_negative -t run"]

    if not scenarios_path.exists():
        return fail_claim(
            spec,
            reason=f"ACVP negative scenarios fixture not found: {scenarios_path}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )

    transcript_path, transcript_sha, transcript_body = _read_named_transcript(
        transcript_manifest, "ACVP serial negative ztest run"
    )
    if transcript_path is None or not transcript_body:
        return fail_claim(
            spec,
            reason=(
                "ACVP serial negative ztest run transcript missing or empty in "
                f"transcript manifest {transcript_manifest}"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    artifacts.append(artifact(transcript_path, label="ACVP serial negative ztest transcript"))

    required_markers = (
        "TESTSUITE pqcp_acvp_serial_negative succeeded",
        "PROJECT EXECUTION SUCCESSFUL",
    )
    missing_markers = [m for m in required_markers if m not in transcript_body]
    missing_substrings = [
        sub for sub in required_response_substrings if sub not in transcript_body
    ]
    details = {
        "scenarios_path": str(scenarios_path),
        "transcript_path": str(transcript_path),
        "transcript_sha256": transcript_sha,
        "label": label,
        "required_response_substrings": list(required_response_substrings),
    }
    failures: list[str] = []
    if missing_markers:
        failures.append(
            "missing required suite marker(s): " + ", ".join(missing_markers)
        )
    if missing_substrings:
        failures.append(
            "missing required category substring(s): "
            + ", ".join(missing_substrings)
        )
    if failures:
        return fail_claim(
            spec,
            reason="; ".join(failures),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details=details,
    )


def evaluate_acvp_negative_paths(
    spec: dict[str, Any],
    *,
    scenarios_path: Path,
    transcript_manifest: Path,
) -> dict[str, object]:
    artifacts = [
        artifact(scenarios_path, label="ACVP negative scenarios fixture"),
        artifact(transcript_manifest, label="release-check transcript manifest"),
    ]
    validators = [
        "tests/ztest_acvp_serial::test_rejects_malformed_commands",
        "tests/ztest_acvp_serial::test_rejects_invalid_hex_and_wrong_sizes",
        "tests/ztest_acvp_serial::test_serial_line_garbage_rejected_and_recovered",
    ]
    commands = [
        "west build -b qemu_x86_64 tests/ztest_acvp_serial -t run",
    ]

    if not scenarios_path.exists():
        return fail_claim(
            spec,
            reason=f"ACVP negative scenarios fixture not found: {scenarios_path}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    try:
        scenarios = json.loads(scenarios_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return fail_claim(
            spec,
            reason=f"invalid ACVP negative scenarios JSON: {exc}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )

    expected_errors = []
    for scenario in scenarios.get("scenarios", []) or []:
        if not isinstance(scenario, dict):
            continue
        for case in scenario.get("expected_errors", []) or []:
            if isinstance(case, dict) and isinstance(case.get("response"), str):
                expected_errors.append(case["response"])
    expected_error_set = sorted(set(expected_errors))
    if not expected_error_set:
        return fail_claim(
            spec,
            reason="ACVP negative scenarios fixture defines no expected_errors",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )

    transcript_path, transcript_sha, transcript_body = _read_acvp_serial_transcript(
        transcript_manifest
    )
    if transcript_path is None or not transcript_body:
        return fail_claim(
            spec,
            reason=(
                "ACVP serial ztest run transcript missing or empty in transcript manifest "
                f"{transcript_manifest}"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    artifacts.append(artifact(transcript_path, label="ACVP serial ztest run transcript"))

    required_markers = (
        "test_rejects_malformed_commands",
        "test_rejects_invalid_hex_and_wrong_sizes",
        "test_serial_line_garbage_rejected_and_recovered",
        "TESTSUITE pqcp_acvp_serial succeeded",
    )
    missing_markers = [m for m in required_markers if m not in transcript_body]
    details = {
        "expected_error_responses": expected_error_set,
        "scenarios_path": str(scenarios_path),
        "transcript_path": str(transcript_path),
        "transcript_sha256": transcript_sha,
    }
    if missing_markers:
        return fail_claim(
            spec,
            reason=(
                "ACVP serial transcript missing expected ztest markers: "
                + ", ".join(missing_markers)
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details=details,
    )


def evaluate_acvp_timeout_recovery(
    spec: dict[str, Any],
    *,
    transcript_manifest: Path,
) -> dict[str, object]:
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = ["tests/ztest_acvp_serial::test_readline_timeout"]
    commands = ["west build -b qemu_x86_64 tests/ztest_acvp_serial -t run"]

    transcript_path, transcript_sha, transcript_body = _read_acvp_serial_transcript(
        transcript_manifest
    )
    if transcript_path is None or not transcript_body:
        return fail_claim(
            spec,
            reason=(
                "ACVP serial ztest run transcript missing or empty in transcript manifest "
                f"{transcript_manifest}"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    artifacts.append(artifact(transcript_path, label="ACVP serial ztest run transcript"))

    required_markers = (
        "test_readline_timeout",
        "TESTSUITE pqcp_acvp_serial succeeded",
    )
    missing = [m for m in required_markers if m not in transcript_body]
    details = {
        "transcript_path": str(transcript_path),
        "transcript_sha256": transcript_sha,
        "required_markers": list(required_markers),
        "wire_response_asserted_by_ztest": "ERROR:TIMEOUT",
        "wire_response_literal_present": "ERROR:TIMEOUT" in transcript_body,
    }
    if missing:
        return fail_claim(
            spec,
            reason=(
                "ACVP serial transcript missing expected timeout-recovery markers: "
                + ", ".join(missing)
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details=details,
    )


SANITIZER_ASAN_MARKERS = (
    "ERROR: AddressSanitizer",
    "AddressSanitizer:",
    "ASAN:DEADLYSIGNAL",
)
SANITIZER_UBSAN_MARKERS = (
    "runtime error:",
    "UndefinedBehaviorSanitizer",
)


def _evaluate_sanitizer_clean(
    spec: dict[str, Any],
    *,
    transcript_manifest: Path,
    forbidden_markers: tuple[str, ...],
    label: str,
) -> dict[str, object]:
    """Bind a sanitizer-clean assertion to the captured 'sanitizers' transcript.

    The release_check.py 'sanitizers' step shells out to
    scripts/run_sanitizer_checks.py, which builds and runs every
    sanitizer-enabled ztest under native_sim/native/64. The full per-case
    log lives next to the assurance pack; the consolidated step
    transcript is captured by release_check.py and listed in
    REQUIRED_EVIDENCE_TRANSCRIPT_STEPS. This evaluator re-checks that
    transcript for the documented sanitizer error markers and reports
    whichever lines (if any) tripped.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = ["scripts/run_sanitizer_checks.py"]
    commands = [
        "python3 scripts/run_sanitizer_checks.py "
        "--west-root <west-root> --module-path <module>",
    ]

    transcript_path, transcript_sha, transcript_body = _read_named_transcript(
        transcript_manifest, "sanitizers"
    )
    if transcript_path is None or not transcript_body:
        return fail_claim(
            spec,
            reason=(
                "sanitizers step transcript missing or empty in transcript "
                f"manifest {transcript_manifest} (re-run release_check.py)"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    artifacts.append(artifact(transcript_path, label="sanitizers step transcript"))

    skipped_pattern = "Non-CI host: skipping sanitizer execution"
    if skipped_pattern in transcript_body:
        return not_applicable_claim(
            spec,
            reason=(
                "sanitizers step skipped on this host (set PQCP_STRICT_SANITIZERS=1 "
                "or run on a Linux host to exercise native_sim)"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )

    if "PQCP Sanitizer Checks" not in transcript_body:
        return fail_claim(
            spec,
            reason=(
                "sanitizers transcript does not contain the 'PQCP Sanitizer Checks' "
                "header — release_check.py likely skipped the step"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )

    offending: list[str] = []
    for line in transcript_body.splitlines():
        for marker in forbidden_markers:
            if marker in line:
                offending.append(line.strip())
                break
        if len(offending) >= 5:
            break

    details = {
        "transcript_path": str(transcript_path),
        "transcript_sha256": transcript_sha,
        "label": label,
        "forbidden_markers": list(forbidden_markers),
    }
    if offending:
        details["sample_offending_lines"] = offending
        return fail_claim(
            spec,
            reason=(
                f"{label}: sanitizer transcript contains {len(offending)} offending "
                "line(s); first: " + offending[0]
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details=details,
    )


_CT_SMOKE_RE = __import__("re").compile(
    r"PQCP_CT_SMOKE\s+alg=(?P<alg>\S+)\s+iters=(?P<iters>\d+)\s+"
    r"median_valid=(?P<median_valid>\d+)\s+median_invalid=(?P<median_invalid>\d+)\s+"
    r"delta=(?P<delta>\d+)\s+relative_pct=(?P<relative_pct>\d+)\s+"
    r"bound_pct=(?P<bound_pct>\d+)"
)


def evaluate_ct_smoke(
    spec: dict[str, Any], *, transcript_manifest: Path
) -> dict[str, object]:
    """Bind security.ct_smoke to the captured tests/ztest_ct_smoke transcript.

    The C-side ztest already enforces the variance bound with zassert; this
    evaluator additionally re-parses the PQCP_CT_SMOKE marker line so the
    measured numbers (medians, delta, relative_pct, bound_pct) land in the
    ledger details and the HTML report. That makes the ct-smoke output a
    citable, replayable artifact rather than a one-off log line.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = ["tests/ztest_ct_smoke::test_mlkem_decap_timing_profile_does_not_bifurcate"]
    commands = ["west build -b qemu_x86_64 tests/ztest_ct_smoke -t run"]

    transcript_path, transcript_sha, transcript_body = _read_named_transcript(
        transcript_manifest, "ct smoke ztest run"
    )
    if transcript_path is None or not transcript_body:
        return fail_claim(
            spec,
            reason=(
                "ct smoke ztest transcript missing or empty in transcript "
                f"manifest {transcript_manifest}"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    artifacts.append(artifact(transcript_path, label="ct smoke ztest transcript"))

    if "TESTSUITE pqcp_ct_smoke succeeded" not in transcript_body:
        return fail_claim(
            spec,
            reason="ct smoke transcript missing TESTSUITE pqcp_ct_smoke succeeded marker",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )

    match = _CT_SMOKE_RE.search(transcript_body)
    if not match:
        return fail_claim(
            spec,
            reason=(
                "ct smoke transcript missing the PQCP_CT_SMOKE measurement line "
                "(stable format: alg=<NAME> iters=<N> median_valid=<C> ...)"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    relative_pct = int(match.group("relative_pct"))
    bound_pct = int(match.group("bound_pct"))
    details = {
        "transcript_path": str(transcript_path),
        "transcript_sha256": transcript_sha,
        "algorithm": match.group("alg"),
        "iterations": int(match.group("iters")),
        "median_valid_cycles": int(match.group("median_valid")),
        "median_invalid_cycles": int(match.group("median_invalid")),
        "delta_cycles": int(match.group("delta")),
        "relative_variance_pct": relative_pct,
        "smoke_bound_pct": bound_pct,
        "is_smoke_test_only": True,
    }
    if relative_pct > bound_pct:
        return fail_claim(
            spec,
            reason=(
                f"ct smoke {match.group('alg')} relative variance "
                f"{relative_pct}% exceeds documented bound {bound_pct}%"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details=details,
    )


def evaluate_boot_kat_self_verify(
    spec: dict[str, Any], *, transcript_manifest: Path
) -> dict[str, object]:
    """Bind boot.kat_self_verify to the captured tests/ztest_kat_boot_verify run.

    The C-side SYS_INIT hook in src/kat_boot_verify.c calls k_panic() on
    any failure, so simply observing the suite-success marker plus the
    "all enabled primitives passed" log line in the captured transcript
    is sufficient to prove the boot self-test ran and every enabled
    primitive completed its keygen/encaps/decaps or keygen/sign/verify
    roundtrip.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = ["tests/ztest_kat_boot_verify::test_boot_self_verify_did_not_panic"]
    commands = ["west build -b qemu_x86_64 tests/ztest_kat_boot_verify -t run"]

    transcript_path, transcript_sha, transcript_body = _read_named_transcript(
        transcript_manifest, "boot KAT self-verify ztest run"
    )
    if transcript_path is None or not transcript_body:
        return fail_claim(
            spec,
            reason=(
                "boot KAT self-verify transcript missing or empty in transcript "
                f"manifest {transcript_manifest}"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    artifacts.append(artifact(transcript_path, label="boot KAT self-verify transcript"))

    required_markers = (
        "PQCP_KAT_BOOT_VERIFY: starting power-on self-test",
        "PQCP_KAT_BOOT_VERIFY: all enabled primitives passed",
        "PQCP_KAT_BOOT_VERIFY: ztest reached main without panic",
        "TESTSUITE pqcp_kat_boot_verify succeeded",
    )
    missing = [m for m in required_markers if m not in transcript_body]
    details = {
        "transcript_path": str(transcript_path),
        "transcript_sha256": transcript_sha,
        "required_markers": list(required_markers),
    }
    if missing:
        return fail_claim(
            spec,
            reason=(
                "boot KAT self-verify transcript missing required marker(s): "
                + ", ".join(missing)
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details=details,
    )


def evaluate_asan_clean(
    spec: dict[str, Any], *, transcript_manifest: Path
) -> dict[str, object]:
    return _evaluate_sanitizer_clean(
        spec,
        transcript_manifest=transcript_manifest,
        forbidden_markers=SANITIZER_ASAN_MARKERS,
        label="ASan",
    )


def evaluate_ubsan_clean(
    spec: dict[str, Any], *, transcript_manifest: Path
) -> dict[str, object]:
    return _evaluate_sanitizer_clean(
        spec,
        transcript_manifest=transcript_manifest,
        forbidden_markers=SANITIZER_UBSAN_MARKERS,
        label="UBSan",
    )


def evaluate_benchmark_csv(
    spec: dict[str, Any],
    *,
    csv_path: Path,
) -> dict[str, object]:
    artifacts = [artifact(csv_path, label="benchmark CSV")]
    validators = ["scripts/export_results.py --validate-only"]
    commands = [f"python3 scripts/export_results.py --validate-only {csv_path}"]
    if not csv_path.exists():
        return fail_claim(
            spec,
            reason=f"benchmark CSV not found: {csv_path}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    failures = validate_benchmark_csv(csv_path)
    details: dict[str, object] = {}
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    details["row_count"] = len(rows)
    if failures:
        return fail_claim(
            spec,
            reason="; ".join(f"[{item['check']}] {item['message']}" for item in failures),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details=details,
    )


def evaluate_benchmark_provenance(
    spec: dict[str, Any],
    *,
    csv_path: Path,
    provenance_path: Path,
) -> dict[str, object]:
    artifacts = [
        artifact(csv_path, label="benchmark CSV"),
        artifact(provenance_path, label="benchmark provenance"),
    ]
    validators = ["scripts/export_results.py --validate-only --verify-provenance"]
    commands = [
        f"python3 scripts/export_results.py --validate-only {csv_path} --verify-provenance"
    ]
    if not csv_path.exists():
        return fail_claim(
            spec,
            reason=f"benchmark CSV not found: {csv_path}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    if not provenance_path.exists():
        return fail_claim(
            spec,
            reason=f"benchmark provenance sidecar not found: {provenance_path}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    failures = verify_provenance(csv_path, provenance_path)
    if failures:
        return fail_claim(
            spec,
            reason="; ".join(f"[{item['check']}] {item['message']}" for item in failures),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
    )


def evaluate_cost_guardrails(
    spec: dict[str, Any],
    *,
    evidence_path: Path,
) -> dict[str, object]:
    artifacts = [artifact(evidence_path, label="cost-of-assurance regression evidence")]
    validators = ["scripts/run_extended_checks.py --run-cost-of-assurance-smoke"]
    commands = [
        "python3 scripts/run_extended_checks.py --strict "
        "--run-cost-of-assurance-smoke --cost-of-assurance-evidence "
        f"{evidence_path}"
    ]
    if not evidence_path.exists():
        return fail_claim(
            spec,
            reason=f"cost-of-assurance evidence not found: {evidence_path}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return fail_claim(
            spec,
            reason=f"invalid cost-of-assurance evidence JSON: {exc}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    comparisons = evidence.get("comparisons")
    if evidence.get("schema_version") != 1 or not isinstance(comparisons, list) or not comparisons:
        return fail_claim(
            spec,
            reason="cost-of-assurance evidence has no schema_version=1 comparisons",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    failures: list[str] = []
    metric_count = 0
    for comparison in comparisons:
        name = comparison.get("name", "<unnamed>")
        metrics = comparison.get("metrics")
        if not isinstance(metrics, list) or not metrics:
            failures.append(f"{name} evaluated no metrics")
            continue
        if not comparison.get("passed", False):
            failures.append(f"{name} failed: {comparison.get('failure_reason')}")
        for metric in metrics:
            metric_count += 1
            if not metric.get("passed", False):
                failures.append(
                    f"{name}/{metric.get('metric')}: {metric.get('failure_reason')}"
                )
            if metric.get("candidate_value") is None:
                failures.append(f"{name}/{metric.get('metric')}: candidate value missing")
    details = {
        "comparison_count": len(comparisons),
        "metric_count": metric_count,
    }
    if failures:
        return fail_claim(
            spec,
            reason="; ".join(failures),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details=details,
    )


def evaluate_local_bundle(
    spec: dict[str, Any],
    *,
    bundle_root: Path,
    version: str,
    tag: str | None,
) -> dict[str, object]:
    manifest_path = find_release_manifest(bundle_root, tag)
    artifacts = [
        artifact(bundle_root, label="release bundle root"),
    ]
    if manifest_path is not None:
        artifacts.append(artifact(manifest_path, label="release bundle manifest"))
    validators = ["scripts/prepare_release_bundle.py"]
    commands = [
        "python3 scripts/prepare_release_bundle.py"
        + (f" --tag {tag}" if tag else "")
        + f" --output-dir {bundle_root}"
    ]
    if manifest_path is None:
        return fail_claim(
            spec,
            reason=f"release manifest not found under {bundle_root}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return fail_claim(
            spec,
            reason=f"invalid release manifest JSON: {exc}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    failures: list[str] = []
    if manifest.get("version") != version:
        failures.append(f"manifest version {manifest.get('version')!r} != {version!r}")
    if tag and manifest.get("tag") != tag:
        failures.append(f"manifest tag {manifest.get('tag')!r} != {tag!r}")
    notes_meta = manifest.get("release_notes") or {}
    notes_path = manifest_path.parent / str(notes_meta.get("path", ""))
    artifacts.append(artifact(notes_path, label="release notes"))
    if not notes_path.exists():
        failures.append(f"release notes path missing: {notes_path}")
    elif notes_meta.get("sha256") != sha256_file(notes_path):
        failures.append("release notes sha256 does not match manifest")
    details = {
        "manifest": manifest_path.name,
        "tag_points_to_head": manifest.get("tag_points_to_head"),
        "working_tree_dirty": manifest.get("working_tree_dirty"),
    }
    if failures:
        return fail_claim(
            spec,
            reason="; ".join(failures),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details=details,
    )


def resolve_transcript_path(manifest_path: Path, raw_path: object) -> Path | None:
    if not isinstance(raw_path, str) or not raw_path:
        return None
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate
    return (manifest_path.parent / candidate).resolve()


def evaluate_transcript_binding(
    spec: dict[str, Any],
    *,
    manifest_path: Path,
) -> dict[str, object]:
    artifacts = [artifact(manifest_path, label="release-check transcript manifest")]
    validators = ["scripts/release_check.py transcript capture"]
    commands = ["python3 scripts/release_check.py --tag <tag> --output-root <output-root>"]
    if not manifest_path.exists():
        return fail_claim(
            spec,
            reason=f"transcript manifest not found: {manifest_path}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return fail_claim(
            spec,
            reason=f"invalid transcript manifest JSON: {exc}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )

    transcripts = manifest.get("transcripts")
    qemu_stdout_transcripts = manifest.get("qemu_stdout_transcripts")
    required_steps = manifest.get("required_steps", list(REQUIRED_TRANSCRIPT_STEPS))
    failures: list[str] = []
    transcript_artifacts: list[dict[str, object]] = []
    if manifest.get("schema_version") != 1:
        failures.append(f"unsupported schema_version={manifest.get('schema_version')!r}")
    if not isinstance(required_steps, list) or not all(isinstance(item, str) for item in required_steps):
        failures.append("required_steps must be a list of strings")
        required_steps = list(REQUIRED_TRANSCRIPT_STEPS)
    if not isinstance(transcripts, list) or not transcripts:
        failures.append("transcripts must be a non-empty list")
        transcripts = []
    if not isinstance(qemu_stdout_transcripts, list) or not qemu_stdout_transcripts:
        failures.append("qemu_stdout_transcripts must be a non-empty list")
        qemu_stdout_transcripts = []

    by_step: dict[str, dict[str, Any]] = {}
    for item in transcripts:
        if not isinstance(item, dict):
            failures.append("transcript entry must be an object")
            continue
        step_name = item.get("step")
        if not isinstance(step_name, str) or not step_name:
            failures.append("transcript entry missing step name")
            continue
        by_step[step_name] = item

    for step_name in required_steps:
        entry = by_step.get(step_name)
        if entry is None:
            failures.append(f"required transcript step missing: {step_name}")
            continue
        transcript_path = resolve_transcript_path(manifest_path, entry.get("transcript_path"))
        if transcript_path is None:
            failures.append(f"{step_name}: transcript path missing")
            continue
        transcript_artifacts.append(artifact(transcript_path, label=f"transcript: {step_name}"))
        if entry.get("returncode") != 0:
            failures.append(f"{step_name}: returncode {entry.get('returncode')} != 0")
        if not transcript_path.exists():
            failures.append(f"{step_name}: transcript file missing: {transcript_path}")
            continue
        if not transcript_path.is_file():
            failures.append(f"{step_name}: transcript path is not a file: {transcript_path}")
            continue
        size_bytes = transcript_path.stat().st_size
        if size_bytes <= 0:
            failures.append(f"{step_name}: transcript file is empty")
        if entry.get("size_bytes") != size_bytes:
            failures.append(
                f"{step_name}: size_bytes {entry.get('size_bytes')!r} != actual {size_bytes}"
            )
        actual_sha = sha256_file(transcript_path)
        if entry.get("sha256") != actual_sha:
            failures.append(f"{step_name}: transcript sha256 mismatch")

    for index, entry in enumerate(qemu_stdout_transcripts, start=1):
        if not isinstance(entry, dict):
            failures.append(f"qemu stdout transcript entry {index} must be an object")
            continue
        label = entry.get("label")
        if not isinstance(label, str) or not label:
            label = f"qemu stdout transcript {index}"
        transcript_path = resolve_transcript_path(manifest_path, entry.get("transcript_path"))
        if transcript_path is None:
            failures.append(f"{label}: transcript path missing")
            continue
        transcript_artifacts.append(artifact(transcript_path, label=label))
        if not transcript_path.exists():
            failures.append(f"{label}: transcript file missing: {transcript_path}")
            continue
        if not transcript_path.is_file():
            failures.append(f"{label}: transcript path is not a file: {transcript_path}")
            continue
        size_bytes = transcript_path.stat().st_size
        if size_bytes <= 0:
            failures.append(f"{label}: transcript file is empty")
        if entry.get("size_bytes") != size_bytes:
            failures.append(
                f"{label}: size_bytes {entry.get('size_bytes')!r} != actual {size_bytes}"
            )
        actual_sha = sha256_file(transcript_path)
        if entry.get("sha256") != actual_sha:
            failures.append(f"{label}: transcript sha256 mismatch")

    details = {
        "required_steps": required_steps,
        "transcript_count": len(transcripts),
        "qemu_stdout_transcript_count": len(qemu_stdout_transcripts),
    }
    all_artifacts = artifacts + transcript_artifacts
    if failures:
        return fail_claim(
            spec,
            reason="; ".join(failures),
            validators=validators,
            evidence_artifacts=all_artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=all_artifacts,
        commands=commands,
        details=details,
    )


def evaluate_json_artifact_claim(
    spec: dict[str, Any],
    *,
    path: Path | None,
    label: str,
    expected_schema_version: int = 1,
    required_keys: tuple[str, ...] = (),
    success_field: str | None = None,
) -> dict[str, object]:
    validators = [label]
    commands = [f"generate {label}"]
    if path is None:
        return not_applicable_claim(
            spec,
            reason=f"{label} path was not supplied to generate_assurance_ledger.py",
            validators=validators,
            evidence_artifacts=[],
            commands=commands,
        )
    artifacts = [artifact(path, label=label)]
    if not path.exists():
        return not_applicable_claim(
            spec,
            reason=f"{label} has not been generated yet: {path}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return fail_claim(
            spec,
            reason=f"{label} is not valid JSON: {exc}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    failures: list[str] = []
    if expected_schema_version is not None and payload.get("schema_version") != expected_schema_version:
        # CycloneDX and in-toto use different schema markers; accept them below.
        if not (label == "PQC CBOM" and payload.get("bomFormat") == "CycloneDX"):
            if not (label == "PQC assurance attestation" and payload.get("_type") == "https://in-toto.io/Statement/v1"):
                failures.append(
                    f"schema marker mismatch for {label}: {payload.get('schema_version')!r}"
                )
    for key in required_keys:
        if key not in payload:
            failures.append(f"{label} missing required key {key!r}")
    if success_field is not None and payload.get(success_field) is not True:
        failures.append(f"{label} field {success_field!r} is not true")
    details = {
        "path": str(path),
        "size_bytes": path.stat().st_size if path.exists() else 0,
    }
    if failures:
        return fail_claim(
            spec,
            reason="; ".join(failures),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details=details,
    )


def evaluate_file_artifact_claim(
    spec: dict[str, Any],
    *,
    path: Path | None,
    label: str,
    required_substrings: tuple[str, ...] = (),
) -> dict[str, object]:
    validators = [label]
    commands = [f"generate {label}"]
    if path is None:
        return not_applicable_claim(
            spec,
            reason=f"{label} path was not supplied to generate_assurance_ledger.py",
            validators=validators,
            evidence_artifacts=[],
            commands=commands,
        )
    artifacts = [artifact(path, label=label)]
    if not path.exists():
        return not_applicable_claim(
            spec,
            reason=f"{label} has not been generated yet: {path}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    if not path.is_file():
        return fail_claim(
            spec,
            reason=f"{label} is not a file: {path}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    body = path.read_text(encoding="utf-8", errors="replace")
    missing = [text for text in required_substrings if text not in body]
    if missing:
        return fail_claim(
            spec,
            reason=f"{label} missing required text: {', '.join(missing)}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details={"size_bytes": path.stat().st_size},
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details={"size_bytes": path.stat().st_size},
    )


def build_claim_evaluators(args: argparse.Namespace, version: str) -> dict[str, Callable[[dict[str, Any]], dict[str, object]]]:
    module_path = args.module_path.resolve()
    benchmark_csv = resolve_path(args.benchmark_csv, module_path)
    benchmark_provenance = resolve_path(args.benchmark_provenance, module_path)
    cost_evidence = resolve_path(args.cost_of_assurance_evidence, module_path)
    release_bundle_root = resolve_path(args.release_bundle_root, module_path)
    transcript_manifest = resolve_path(args.transcript_manifest, module_path)
    kat_header = resolve_path(args.kat_header, module_path)
    kat_vectors_dir = resolve_path(args.kat_vectors_dir, module_path)
    negative_scenarios = resolve_path(args.negative_scenarios, module_path)
    cbom_arg = getattr(args, "cbom", None)
    attestation_arg = getattr(args, "attestation", None)
    policy_result_arg = getattr(args, "policy_result", None)
    assurance_digest_arg = getattr(args, "assurance_digest", None)
    negative_floor_result_arg = getattr(args, "negative_scenario_floor_result", None)
    asset_trace_result_arg = getattr(args, "asset_trace_result", None)
    evidence_graph_arg = getattr(args, "evidence_graph", None)
    firmware_digest_header_arg = getattr(args, "firmware_digest_header", None)
    cbom = resolve_path(cbom_arg, module_path) if cbom_arg else None
    attestation = resolve_path(attestation_arg, module_path) if attestation_arg else None
    policy_result = resolve_path(policy_result_arg, module_path) if policy_result_arg else None
    assurance_digest = resolve_path(assurance_digest_arg, module_path) if assurance_digest_arg else None
    negative_floor_result = resolve_path(negative_floor_result_arg, module_path) if negative_floor_result_arg else None
    asset_trace_result = resolve_path(asset_trace_result_arg, module_path) if asset_trace_result_arg else None
    evidence_graph = resolve_path(evidence_graph_arg, module_path) if evidence_graph_arg else None
    firmware_digest_header = resolve_path(firmware_digest_header_arg, module_path) if firmware_digest_header_arg else None
    tag = args.tag

    evaluators: dict[str, Callable[[dict[str, Any]], dict[str, object]]] = {
        "release.version_consistency": lambda spec: evaluate_version_consistency(
            spec,
            module_path=module_path,
            version=version,
            tag=tag,
        ),
        "release.tag_integrity": lambda spec: evaluate_tag_integrity(
            spec,
            module_path=module_path,
            tag=tag,
        ),
        "kat.offline_provenance": lambda spec: evaluate_kat_provenance(
            spec,
            header=kat_header,
            vectors_dir=kat_vectors_dir,
        ),
        "benchmark.csv_validity": lambda spec: evaluate_benchmark_csv(
            spec,
            csv_path=benchmark_csv,
        ),
        "benchmark.provenance_binding": lambda spec: evaluate_benchmark_provenance(
            spec,
            csv_path=benchmark_csv,
            provenance_path=benchmark_provenance,
        ),
        "cost_of_assurance.guardrails": lambda spec: evaluate_cost_guardrails(
            spec,
            evidence_path=cost_evidence,
        ),
        "release.local_bundle": lambda spec: evaluate_local_bundle(
            spec,
            bundle_root=release_bundle_root,
            version=version,
            tag=tag,
        ),
        "release.transcript_binding": lambda spec: evaluate_transcript_binding(
            spec,
            manifest_path=transcript_manifest,
        ),
        "acvp.negative_path_rejection": lambda spec: evaluate_acvp_negative_paths(
            spec,
            scenarios_path=negative_scenarios,
            transcript_manifest=transcript_manifest,
        ),
        "acvp.timeout_recovery": lambda spec: evaluate_acvp_timeout_recovery(
            spec,
            transcript_manifest=transcript_manifest,
        ),
        "acvp.negative_scenarios_replay": lambda spec: evaluate_acvp_negative_replay(
            spec,
            scenarios_path=negative_scenarios,
            transcript_manifest=transcript_manifest,
            label="full negative scenario replay",
        ),
        "acvp.mlkem_negative_paths": lambda spec: evaluate_acvp_negative_replay(
            spec,
            scenarios_path=negative_scenarios,
            transcript_manifest=transcript_manifest,
            required_response_substrings=("MLKEM",),
            label="ML-KEM negative paths",
        ),
        "acvp.mldsa_negative_paths": lambda spec: evaluate_acvp_negative_replay(
            spec,
            scenarios_path=negative_scenarios,
            transcript_manifest=transcript_manifest,
            required_response_substrings=("MLDSA",),
            label="ML-DSA negative paths",
        ),
        "acvp.negative_scenario_floor": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=negative_floor_result,
            label="ACVP negative scenario floor result",
            required_keys=("schema_version", "passed", "scenario_count", "floor_count"),
            success_field="passed",
        ),
        "security.asan_clean": lambda spec: evaluate_asan_clean(
            spec, transcript_manifest=transcript_manifest,
        ),
        "security.ubsan_clean": lambda spec: evaluate_ubsan_clean(
            spec, transcript_manifest=transcript_manifest,
        ),
        "boot.kat_self_verify": lambda spec: evaluate_boot_kat_self_verify(
            spec, transcript_manifest=transcript_manifest,
        ),
        "security.ct_smoke": lambda spec: evaluate_ct_smoke(
            spec, transcript_manifest=transcript_manifest,
        ),
        "supply_chain.cbom_crypto_inventory": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=cbom,
            label="PQC CBOM",
            required_keys=("bomFormat", "specVersion", "components"),
        ),
        "supply_chain.pqc_assurance_attestation": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=attestation,
            label="PQC assurance attestation",
            required_keys=("_type", "predicateType", "subject", "predicate"),
        ),
        "supply_chain.crypto_asset_traceability": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=asset_trace_result,
            label="PQC asset trace validation result",
            required_keys=("schema_version", "passed", "asset_count", "checks"),
            success_field="passed",
        ),
        "supply_chain.evidence_graph_integrity": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=evidence_graph,
            label="PQC evidence graph",
            required_keys=("schema_version", "summary", "nodes", "edges", "failures"),
        ),
        "release.policy_pass": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=policy_result,
            label="PQC assurance policy result",
            expected_schema_version=2,
            required_keys=("schema_version", "passed", "checks"),
            success_field="passed",
        ),
        "firmware.assurance_digest_manifest": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=assurance_digest,
            label="PQC assurance digest manifest",
            required_keys=("schema_version", "digest_algorithm", "artifacts"),
        ),
        "firmware.assurance_digest_embeddable": lambda spec: evaluate_file_artifact_claim(
            spec,
            path=firmware_digest_header,
            label="firmware assurance digest header",
            required_substrings=(
                "PQCP_ASSURANCE_DIGEST_ROOT_SHA256",
                "PQCP_ASSURANCE_DIGEST_ARTIFACT_COUNT",
            ),
        ),
    }
    for claim_id, parameter_set in PER_PRIMITIVE_KAT_CLAIMS.items():
        evaluators[claim_id] = (
            lambda spec, _ps=parameter_set: evaluate_kat_per_primitive(
                spec,
                header=kat_header,
                vectors_dir=kat_vectors_dir,
                parameter_set=_ps,
            )
        )
    for claim_id, (algorithm, levels) in PER_PRIMITIVE_BENCH_CLAIMS.items():
        evaluators[claim_id] = (
            lambda spec, _alg=algorithm, _lv=levels: evaluate_benchmark_per_primitive(
                spec,
                csv_path=benchmark_csv,
                algorithm=_alg,
                parameter_levels=_lv,
            )
        )
    return evaluators


def render_markdown(ledger: dict[str, object]) -> str:
    claims = ledger["claims"]
    lines = [
        f"# Assurance Ledger: {ledger['project']} {ledger['version']}",
        "",
        f"- Generated: `{ledger['generated_at']}`",
        f"- Tag: `{ledger.get('tag') or 'not supplied'}`",
        f"- HEAD: `{ledger.get('head_sha') or 'unknown'}`",
        f"- Dirty tree: `{ledger['dirty']}`",
        "",
        "## Summary",
        "",
    ]
    summary = ledger["summary"]
    for key in ("pass", "fail", "not_applicable"):
        lines.append(f"- {key}: {summary[key]}")
    lines.extend(
        [
            "",
            "## Claims",
            "",
            "| Claim ID | Category | Status | Evidence |",
            "|----------|----------|--------|----------|",
        ]
    )
    for claim in claims:
        artifacts = [
            Path(str(item["path"])).name
            for item in claim.get("evidence_artifacts", [])
            if item.get("exists")
        ]
        evidence = ", ".join(artifacts) if artifacts else "n/a"
        lines.append(
            "| {id} | {category} | {status} | {evidence} |".format(
                id=claim["id"],
                category=claim["category"],
                status=claim["status"],
                evidence=evidence,
            )
        )
    lines.append("")
    failures = [
        claim for claim in claims
        if claim["status"] == "fail" and claim.get("failure_reason")
    ]
    if failures:
        lines.extend(["## Failures", ""])
        for claim in failures:
            lines.append(f"- `{claim['id']}`: {claim['failure_reason']}")
        lines.append("")
    return "\n".join(lines)


def build_ledger(args: argparse.Namespace) -> dict[str, object]:
    module_path = args.module_path.resolve()
    version = args.version or parse_header_version(module_path)
    claims_path = resolve_path(args.claims, module_path)
    claim_specs = load_claim_specs(claims_path)
    evaluators = build_claim_evaluators(args, version)
    claims: list[dict[str, object]] = []
    for spec in claim_specs:
        evaluator = evaluators.get(spec["id"])
        if evaluator is None:
            claims.append(
                fail_claim(
                    spec,
                    reason=f"unsupported assurance claim id {spec['id']}",
                    validators=[],
                    evidence_artifacts=[],
                    commands=[],
                )
            )
            continue
        claims.append(evaluator(spec))

    summary = {
        "pass": sum(1 for claim in claims if claim["status"] == "pass"),
        "fail": sum(1 for claim in claims if claim["status"] == "fail"),
        "not_applicable": sum(1 for claim in claims if claim["status"] == "not_applicable"),
    }
    return {
        "schema_version": LEDGER_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": "pqcp-zephyr-trust-stack",
        "version": version,
        "tag": args.tag,
        "head_sha": git_optional(module_path, "rev-parse", "HEAD"),
        "dirty": bool(git_optional(module_path, "status", "--porcelain")),
        "summary": summary,
        "claims": claims,
    }


def main() -> int:
    args = parse_args()
    ledger = build_ledger(args)
    output_json = args.output_json.resolve()
    output_md = args.output_md.resolve()
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output_md.write_text(render_markdown(ledger), encoding="utf-8")

    print("Assurance ledger generated")
    print(f"  json : {output_json}")
    print(f"  md   : {output_md}")
    print(
        "  summary: "
        f"pass={ledger['summary']['pass']} "
        f"fail={ledger['summary']['fail']} "
        f"not_applicable={ledger['summary']['not_applicable']}"
    )
    failures = [
        claim for claim in ledger["claims"]
        if claim["status"] == "fail" and claim.get("required", True)
    ]
    if failures:
        print("Assurance ledger failures:", file=sys.stderr)
        for claim in failures:
            print(f"  - {claim['id']}: {claim['failure_reason']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
