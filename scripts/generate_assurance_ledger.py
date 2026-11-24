#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate a local release assurance ledger from validated artifacts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
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
import run_model_checks as model_checks  # noqa: E402
from export_results import (  # noqa: E402
    validate_benchmark_csv,
    validate_benchmark_metadata_document,
    verify_provenance,
)
from verify_kat_provenance import (  # noqa: E402
    DEFAULT_HEADER as DEFAULT_KAT_HEADER,
    DEFAULT_VECTORS_DIR,
    VECTOR_SPECS,
    fixture_constants,
    load_all_fixture_constants,
    load_header_constants,
    verify_vectors,
)

LEDGER_SCHEMA_VERSION = 7
SUPPORTED_CLAIMS_SCHEMA_VERSIONS = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22)
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
BENCHMARK_BASE_OPERATIONS = {
    "ML-KEM": {"keygen", "encaps", "decaps"},
    "ML-DSA": {"keygen", "sign", "verify"},
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
    parser.add_argument("--assurance-profile-result", type=Path, help="Optional PQC assurance profile result JSON.")
    parser.add_argument("--evidence-quality-result", type=Path, help="Optional PQC evidence quality result JSON.")
    parser.add_argument("--migration-readiness", type=Path, help="Optional PQC migration readiness JSON artifact.")
    parser.add_argument("--reference-values", type=Path, help="Optional PQC reference values JSON artifact.")
    parser.add_argument("--firmware-status-result", type=Path, help="Optional firmware assurance status result JSON.")
    parser.add_argument("--acvp-json-interop-result", type=Path, help="Optional ACVP JSON interop result JSON.")
    parser.add_argument("--build-provenance-result", type=Path, help="Optional SLSA build provenance verification result JSON.")
    parser.add_argument("--ct-sample-analysis-result", type=Path, help="Optional CT sample analysis result JSON.")
    parser.add_argument("--backend-update-evaluation", type=Path, help="Optional backend update evaluation result JSON.")
    parser.add_argument("--backend-contract-result", type=Path, help="Optional backend contract result JSON.")
    parser.add_argument("--liboqs-inventory", type=Path, help="Optional non-native external-provider inventory JSON.")
    parser.add_argument("--benchmark-campaign-result", type=Path, help="Optional benchmark campaign result JSON.")
    parser.add_argument("--paper-comparison-result", type=Path, help="Optional paper-comparison campaign result JSON.")
    parser.add_argument("--ct-campaign-result", type=Path, help="Optional CT campaign result JSON.")
    parser.add_argument("--acvp-json-schema-result", type=Path, help="Optional ACVP JSON schema coverage result JSON.")
    parser.add_argument("--device-evidence-result", type=Path, help="Optional device evidence token result JSON.")
    parser.add_argument("--appraisal-result", type=Path, help="Optional PQC appraisal verification result JSON.")
    parser.add_argument("--provider-scope-result", type=Path, help="Optional provider scope verification result JSON.")
    parser.add_argument("--release-reference-values-result", type=Path, help="Optional release reference-values replay result JSON.")
    parser.add_argument(
        "--ct-instruction-policy-result",
        type=Path,
        help="Optional ML-KEM decapsulation instruction-policy result JSON.",
    )
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


def ledger_schema_for_claims(path: Path) -> int:
    raw = json.loads(path.read_text(encoding="utf-8"))
    schema_version = raw.get("schema_version")
    if not isinstance(schema_version, int):
        return LEDGER_SCHEMA_VERSION
    return min(schema_version, LEDGER_SCHEMA_VERSION)


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
    base_operations = BENCHMARK_BASE_OPERATIONS.get(algorithm, set())
    for row in rows:
        parameter_set = str(row.get("parameter_set", "")).strip()
        if parameter_set not in expected_levels:
            continue
        operation = str(row.get("operation", "")).strip()
        if base_operations and operation not in base_operations:
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
    suite success and (optionally) that a category-specific marker, for
    example "MLKEM" or "MLDSA" in a case name, actually appeared in the
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
                "header, release_check.py likely skipped the step"
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
_CT_TTEST_RE = __import__("re").compile(
    r"PQCP_CT_TTEST\s+alg=(?P<alg>\S+)\s+iters=(?P<iters>\d+)\s+"
    r"mean_valid=(?P<mean_valid>\d+)\s+mean_invalid=(?P<mean_invalid>\d+)\s+"
    r"t2_x1000=(?P<t2_x1000>\d+)"
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

    matches = list(_CT_SMOKE_RE.finditer(transcript_body))
    ttest_matches = list(_CT_TTEST_RE.finditer(transcript_body))
    if not matches:
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
    required_algs = {"MLKEM-512", "MLKEM-768", "MLKEM-1024"}
    observed_algs = {match.group("alg") for match in matches}
    observed_ttest_algs = {match.group("alg") for match in ttest_matches}
    missing_algs = sorted(required_algs - observed_algs)
    missing_ttest_algs = sorted(required_algs - observed_ttest_algs)
    measurements = []
    ttest_measurements = []
    failures: list[str] = []
    for match in matches:
        relative_pct = int(match.group("relative_pct"))
        bound_pct = int(match.group("bound_pct"))
        if relative_pct > bound_pct:
            failures.append(
                f"{match.group('alg')} relative variance {relative_pct}% exceeds "
                f"documented bound {bound_pct}%"
            )
        measurements.append(
            {
                "algorithm": match.group("alg"),
                "iterations": int(match.group("iters")),
                "median_valid_cycles": int(match.group("median_valid")),
                "median_invalid_cycles": int(match.group("median_invalid")),
                "delta_cycles": int(match.group("delta")),
                "relative_variance_pct": relative_pct,
                "smoke_bound_pct": bound_pct,
            }
        )
    for match in ttest_matches:
        ttest_measurements.append(
            {
                "algorithm": match.group("alg"),
                "iterations": int(match.group("iters")),
                "mean_valid_cycles": int(match.group("mean_valid")),
                "mean_invalid_cycles": int(match.group("mean_invalid")),
                "welch_t2_x1000": int(match.group("t2_x1000")),
            }
        )
    if missing_algs:
        failures.append("missing PQCP_CT_SMOKE measurement(s): " + ", ".join(missing_algs))
    if missing_ttest_algs:
        failures.append("missing PQCP_CT_TTEST measurement(s): " + ", ".join(missing_ttest_algs))
    details = {
        "transcript_path": str(transcript_path),
        "transcript_sha256": transcript_sha,
        "algorithms": sorted(observed_algs),
        "measurements": measurements,
        "ttest_measurements": ttest_measurements,
        "is_smoke_test_only": True,
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


def evaluate_firmware_evidence_chain_replay(
    spec: dict[str, Any], *, transcript_manifest: Path
) -> dict[str, object]:
    """Bind firmware.evidence_chain_replay to the captured host replay step.

    scripts/run_evidence_chain_replay.py echoes the full captured device
    transcript into its own stdout and then prints the host verifier
    verdict, so one hash-bound step transcript carries both the device
    evidence markers and the independent host CHAIN OK decision made by
    the firmware verifier C compiled for host.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = [
        "tools/evidence_verifier::pqcp-evidence-verify",
        "scripts/run_evidence_chain_replay.py",
    ]
    commands = [
        "python3 scripts/run_evidence_chain_replay.py",
    ]

    transcript_path, transcript_sha, transcript_body = _read_named_transcript(
        transcript_manifest, "evidence chain host replay"
    )
    if transcript_path is None or not transcript_body:
        return fail_claim(
            spec,
            reason=(
                "evidence chain host replay transcript missing or empty in "
                f"transcript manifest {transcript_manifest}"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    artifacts.append(artifact(transcript_path, label="evidence chain host replay transcript"))

    required_markers = (
        "PQCP_DEPLOYMENT_EVIDENCE_VERDICT schema=",
        "PQCP_DEPLOYMENT_EVIDENCE_SEAL schema=",
        "PQCP_DEPLOYMENT_ASSURANCE_PASSPORT schema=",
        "PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY",
        "PROJECT EXECUTION SUCCESSFUL",
        "pqcp-evidence-verify: CHAIN OK",
        "verdict->seal_binding=true seal->passport_binding=true",
        "[evidence-chain] PASS: device evidence chain replayed on host",
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
                "evidence chain host replay transcript missing required "
                "marker(s): " + ", ".join(missing)
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


# Exact counts printed by scripts/run_transparent_appraisal.py with its
# default seed and sweep size. They are pinned here so a driver that silently
# drops cases (a shorter forgery list, a differential over fewer inputs, a
# missing positive control) fails the claim instead of passing with a smaller
# denominator. Update together with the driver's case list.
APPRAISAL_EXPECTED_DIFFERENTIAL = 169
APPRAISAL_EXPECTED_FORGERIES = 156
APPRAISAL_EXPECTED_CONTROLS = 11
APPRAISAL_MARKER_RE = re.compile(
    r"PQCP_APPRAISAL_RECEIPT PASS consistency=ok "
    r"differential_agree=(\d+)/(\d+) forgeries_rejected=(\d+)/(\d+) "
    r"controls=(\d+)/(\d+)"
)


def evaluate_transparent_appraisal_receipt(
    spec: dict[str, Any], *, transcript_manifest: Path
) -> dict[str, object]:
    """Bind supply_chain.transparent_appraisal_receipt to the driver step.

    The driver exits nonzero unless every forgery is rejected, every control
    is accepted and the C and python verifiers agree on every comparable
    case, so the PASS marker is only printed when all of that held. The
    evaluator re-parses the marker and pins the exact counts so the claim
    cannot be satisfied by a weakened (smaller) case list.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = [
        "tools/evidence_verifier::pqcp-evidence-verify",
        "tools/evidence_register::pqcp-evidence-register",
        "scripts/rfc9162_reference.py",
        "scripts/run_transparent_appraisal.py",
    ]
    commands = ["python3 scripts/run_transparent_appraisal.py"]

    transcript_path, transcript_sha, transcript_body = _read_named_transcript(
        transcript_manifest, "transparent appraisal receipt"
    )
    if transcript_path is None or not transcript_body:
        return fail_claim(
            spec,
            reason=(
                "transparent appraisal receipt transcript missing or empty in "
                f"transcript manifest {transcript_manifest}"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    artifacts.append(artifact(transcript_path, label="transparent appraisal receipt transcript"))

    details: dict[str, Any] = {
        "transcript_path": str(transcript_path),
        "transcript_sha256": transcript_sha,
        "expected_differential": APPRAISAL_EXPECTED_DIFFERENTIAL,
        "expected_forgeries": APPRAISAL_EXPECTED_FORGERIES,
        "expected_controls": APPRAISAL_EXPECTED_CONTROLS,
    }
    marker = APPRAISAL_MARKER_RE.search(transcript_body)
    if marker is None:
        return fail_claim(
            spec,
            reason=(
                "transparent appraisal receipt transcript lacks the "
                "PQCP_APPRAISAL_RECEIPT PASS marker with consistency=ok, "
                "differential_agree=N/N, forgeries_rejected=K/K and "
                "controls=C/C"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    agree, diff_total, rejected, forgery_total, ok, control_total = (
        int(g) for g in marker.groups()
    )
    details.update({
        "differential_agree": agree,
        "differential_total": diff_total,
        "forgeries_rejected": rejected,
        "forgeries_total": forgery_total,
        "controls_ok": ok,
        "controls_total": control_total,
    })
    problems = []
    if agree != diff_total:
        problems.append(f"differential disagreement {agree}/{diff_total}")
    if rejected != forgery_total:
        problems.append(f"forgeries not all rejected {rejected}/{forgery_total}")
    if ok != control_total:
        problems.append(f"positive controls not all accepted {ok}/{control_total}")
    if diff_total != APPRAISAL_EXPECTED_DIFFERENTIAL:
        problems.append(
            f"differential covers {diff_total} cases, expected "
            f"{APPRAISAL_EXPECTED_DIFFERENTIAL}"
        )
    if forgery_total != APPRAISAL_EXPECTED_FORGERIES:
        problems.append(
            f"forgery list has {forgery_total} cases, expected "
            f"{APPRAISAL_EXPECTED_FORGERIES}"
        )
    if control_total != APPRAISAL_EXPECTED_CONTROLS:
        problems.append(
            f"{control_total} positive controls, expected "
            f"{APPRAISAL_EXPECTED_CONTROLS}"
        )
    if problems:
        return fail_claim(
            spec,
            reason="transparent appraisal receipt: " + "; ".join(problems),
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


# Floor on the seeded traces each model module must run. Pinned here so a
# harness that quietly drops to a handful of seeds cannot satisfy the claim.
# Update together with tests/ztest_edge_model.
MODEL_MIN_SEEDS_PER_MODULE = 64
DEFAULT_MODEL_BASELINE = SCRIPT_DIR / "model_rediscovery_baseline.json"


def evaluate_state_machine_model_conformance(
    spec: dict[str, Any],
    *,
    transcript_manifest: Path,
    baseline_path: Path = DEFAULT_MODEL_BASELINE,
) -> dict[str, object]:
    """Bind security.state_machine_model_conformance to the model step.

    Two facts must both be in the captured transcript: the unmutated edge
    firmware conformed to its abstract models on every seeded trace (one PASS
    CHECK marker per module, a clean SUMMARY, no counterexample), and the
    same models rediscovered at least the baseline number of historical
    defects re-injected into private source copies. The second fact is the
    measure of the first: a model that cannot find known bugs proves little.
    Parsing is shared with scripts/run_model_checks.py, which is the only
    producer of the PQCP_MODEL_REDISCOVERY and PQCP_MODEL_DEFECT lines.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = [
        "tests/ztest_edge_model",
        "scripts/run_model_checks.py",
        "scripts/model_rediscovery_baseline.json",
    ]
    commands = ["python3 scripts/run_model_checks.py --rediscover"]

    transcript_path, transcript_sha, transcript_body = _read_named_transcript(
        transcript_manifest, "edge model conformance"
    )
    if transcript_path is None or not transcript_body:
        return fail_claim(
            spec,
            reason=(
                "edge model conformance transcript missing or empty in "
                f"transcript manifest {transcript_manifest}"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    artifacts.append(artifact(transcript_path, label="edge model conformance transcript"))
    artifacts.append(artifact(baseline_path, label="model rediscovery baseline"))

    details: dict[str, Any] = {
        "transcript_path": str(transcript_path),
        "transcript_sha256": transcript_sha,
        "min_seeds_per_module": MODEL_MIN_SEEDS_PER_MODULE,
    }
    try:
        baseline = model_checks.load_baseline(baseline_path)
    except (OSError, ValueError) as exc:
        return fail_claim(
            spec,
            reason=f"model rediscovery baseline unusable: {exc}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    details["baseline_rediscovered_min"] = baseline["rediscovered_min"]
    details["baseline_defects_total"] = baseline.get("defects_total")

    parsed = model_checks.parse_transcript(transcript_body)
    problems = model_checks.assess_conformance(parsed)
    for check in parsed.checks:
        if check.seeds < MODEL_MIN_SEEDS_PER_MODULE:
            problems.append(
                f"module {check.module} ran {check.seeds} seeds, expected at "
                f"least {MODEL_MIN_SEEDS_PER_MODULE}"
            )
    if parsed.summaries:
        summary = parsed.summaries[0]
        details.update({
            "modules": summary.modules,
            "traces": summary.traces,
            "ops": summary.ops,
            "violations": summary.violations,
        })

    marker = model_checks.REDISCOVERY_RE.search(transcript_body)
    defect_lines = model_checks.DEFECT_LINE_RE.findall(transcript_body)
    if marker is None:
        problems.append(
            "transcript lacks the PQCP_MODEL_REDISCOVERY PASS marker "
            "(rediscovered=K/N allowed=A)"
        )
    else:
        rediscovered, total, allowed = (int(g) for g in marker.groups())
        details.update({
            "rediscovered": rediscovered,
            "defects_total": total,
            "allowed_misses": allowed,
        })
        if rediscovered < baseline["rediscovered_min"]:
            problems.append(
                f"rediscovered {rediscovered} is below the baseline "
                f"{baseline['rediscovered_min']}"
            )
        expected_total = baseline.get("defects_total")
        if expected_total is not None and total < expected_total:
            problems.append(
                f"historical defect list shrank to {total} "
                f"(baseline {expected_total})"
            )
        statuses = [status for _, _, status in defect_lines]
        if len(defect_lines) != total:
            problems.append(
                f"{len(defect_lines)} PQCP_MODEL_DEFECT lines but the marker "
                f"reports {total} defects"
            )
        if statuses.count("rediscovered") != rediscovered:
            problems.append(
                f"{statuses.count('rediscovered')} defect lines are "
                f"rediscovered but the marker reports {rediscovered}"
            )
        if statuses.count("allowed") != allowed:
            problems.append(
                f"{statuses.count('allowed')} defect lines are allowed but "
                f"the marker reports {allowed}"
            )
        bad = [f"{i}={s}" for i, _, s in defect_lines
               if s not in ("rediscovered", "allowed")]
        if bad:
            problems.append("unresolved historical defects: " + ", ".join(bad))
        if rediscovered + allowed != total:
            problems.append("rediscovered plus allowed misses does not equal "
                            "the defect count")

    if problems:
        return fail_claim(
            spec,
            reason="edge model conformance: " + "; ".join(problems),
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


# Text replay parsers (verdict, seal, passport, tamper matrix, trail,
# signature reassembler) plus fleet CBOR, COSE_Sign1, COSE_Key and the
# policy module codec. Keep in sync with tools/evidence_fuzzer.
EVIDENCE_FUZZ_MIN_TARGETS = 10


def evaluate_evidence_parser_fuzzed(
    spec: dict[str, Any], *, transcript_manifest: Path
) -> dict[str, object]:
    """Bind security.evidence_parser_fuzzed to the captured fuzz step.

    The fuzzer aborts under ASan/UBSan on any finding, so the step
    transcript containing the per-seed PQCP_FUZZ PASS markers plus the
    final aggregate PASS line proves every campaign completed clean.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = [
        "tools/evidence_fuzzer::pqcp-evidence-fuzz",
        "scripts/run_fuzz_checks.py",
    ]
    commands = [
        "python3 scripts/run_fuzz_checks.py",
    ]

    transcript_path, transcript_sha, transcript_body = _read_named_transcript(
        transcript_manifest, "evidence parser fuzz"
    )
    if transcript_path is None or not transcript_body:
        return fail_claim(
            spec,
            reason=(
                "evidence parser fuzz transcript missing or empty in "
                f"transcript manifest {transcript_manifest}"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    artifacts.append(artifact(transcript_path, label="evidence parser fuzz transcript"))

    pass_markers = transcript_body.count("PQCP_FUZZ PASS")
    target_counts = [
        int(match)
        for match in re.findall(
            r"PQCP_FUZZ PASS targets=(\d+)\b", transcript_body
        )
    ]
    accepted_lines = re.findall(
        r"PQCP_FUZZ BINARY_ACCEPTED ((?:[a-z_0-9]+=\d+ ?)+)",
        transcript_body,
    )
    details = {
        "transcript_path": str(transcript_path),
        "transcript_sha256": transcript_sha,
        "fuzz_pass_markers": pass_markers,
        "fuzz_target_counts": target_counts,
        "fuzz_min_targets_required": EVIDENCE_FUZZ_MIN_TARGETS,
        "fuzz_binary_accepted_lines": len(accepted_lines),
    }
    if pass_markers < 1 or "[fuzz] PASS:" not in transcript_body:
        return fail_claim(
            spec,
            reason=(
                "evidence parser fuzz transcript lacks PQCP_FUZZ PASS "
                "markers or the aggregate [fuzz] PASS line"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    # Every campaign must report the full target set: a marker without a
    # targets= field, or one below the floor, means parsers were dropped
    # from the harness.
    if (
        len(target_counts) != pass_markers
        or min(target_counts) < EVIDENCE_FUZZ_MIN_TARGETS
    ):
        return fail_claim(
            spec,
            reason=(
                "evidence parser fuzz markers must each report "
                f"targets>={EVIDENCE_FUZZ_MIN_TARGETS} (text replay parsers "
                "plus the fleet CBOR, COSE_Sign1, COSE_Key and policy codec "
                f"targets); saw {target_counts}"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    # The binary campaigns must have gotten past the rejection gates: each
    # BINARY_ACCEPTED line needs a positive count for every binary parser.
    accepted_ok = len(accepted_lines) == pass_markers and all(
        len(fields) == 6 and all(int(v) > 0 for v in fields)
        for fields in (
            re.findall(r"=(\d+)", line) for line in accepted_lines
        )
    )
    if not accepted_ok:
        return fail_claim(
            spec,
            reason=(
                "evidence parser fuzz transcript lacks a BINARY_ACCEPTED "
                "line with positive counts for every binary parser per "
                "campaign"
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


def evaluate_ct_instruction_count(
    spec: dict[str, Any], *, transcript_manifest: Path
) -> dict[str, object]:
    """Bind security.ct_instruction_count to the captured TCG-plugin run.

    The runner fails unless every bracketed decapsulation region shares
    one guest-instruction count, so the PQCP_CT_INSTRUCTION_COUNT PASS
    marker in the step transcript proves valid and corrupted ciphertexts
    are instruction-count-indistinguishable.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = [
        "tools/tcg_ct_plugin::pqcp_ct_insn",
        "scripts/run_ct_instruction_checks.py",
    ]
    commands = ["python3 scripts/run_ct_instruction_checks.py"]

    transcript_path, transcript_sha, transcript_body = _read_named_transcript(
        transcript_manifest, "ct instruction-count"
    )
    if transcript_path is None or not transcript_body:
        return fail_claim(
            spec,
            reason=(
                "ct instruction-count transcript missing or empty in "
                f"transcript manifest {transcript_manifest}"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    artifacts.append(artifact(transcript_path, label="ct instruction-count transcript"))

    details = {
        "transcript_path": str(transcript_path),
        "transcript_sha256": transcript_sha,
    }
    if ("PQCP_CT_INSTRUCTION_COUNT PASS" not in transcript_body or
            "loads_per_region=" not in transcript_body or
            "stores_per_region=" not in transcript_body or
            "identical guest memory-access count" not in transcript_body or
            "[ct-insn] PASS:" not in transcript_body):
        return fail_claim(
            spec,
            reason=(
                "ct instruction-count transcript lacks the "
                "PQCP_CT_INSTRUCTION_COUNT PASS / [ct-insn] PASS markers"
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


def evaluate_ct_trace_relational(
    spec: dict[str, Any], *, transcript_manifest: Path
) -> dict[str, object]:
    """Bind security.ct_trace_relational to the clean run AND the rediscovery.

    The clean run must show one fingerprint per channel within every key
    group; the rediscovery run must show every injected leak found and no
    benign change flagged, so the detector's sensitivity and specificity are
    part of the evidence, not assumed.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = [
        "tools/tcg_ct_plugin::pqcp_ct_trace",
        "scripts/run_ct_trace_checks.py",
        "scripts/ct_leak_rediscovery.py",
    ]
    commands = [
        "python3 scripts/run_ct_trace_checks.py --opt default",
        "python3 scripts/run_ct_trace_checks.py --rediscover --opt default",
    ]
    details: dict[str, object] = {}
    bodies = {}
    for step in ("ct trace relational", "ct leak rediscovery"):
        path, sha, body = _read_named_transcript(transcript_manifest, step)
        if path is None or not body:
            return fail_claim(
                spec,
                reason=f"{step} transcript missing or empty in {transcript_manifest}",
                validators=validators, evidence_artifacts=artifacts,
                commands=commands)
        artifacts.append(artifact(path, label=f"{step} transcript"))
        details[f"{step} transcript_sha256"] = sha
        bodies[step] = body

    clean_opts = set()
    clean_regions = 0
    clean_groups = 0
    for m in re.finditer(
            r"PQCP_CT_TRACE PASS alg=MLKEM-768 opt=(\S+) regions=(\d+) "
            r"groups=(\d+) channels=pc,addr,line,div distinct=1 "
            r"bits=0\.00", bodies["ct trace relational"]):
        clean_opts.add(m.group(1))
        clean_regions = max(clean_regions, int(m.group(2)))
        clean_groups = max(clean_groups, int(m.group(3)))
    redis = re.search(
        r"PQCP_CT_TRACE_REDISCOVERY PASS leaks=(\d+)/(\d+) "
        r"benign_flagged=0/(\d+) missed_by_counts_only=(\d+)/(\d+)",
        bodies["ct leak rediscovery"])
    problems = []
    required_opts = {"default", "speed", "debug"}
    if not clean_opts:
        problems.append("no clean-run PQCP_CT_TRACE PASS marker with "
                        "distinct=1 on all four channels")
    elif not required_opts <= clean_opts:
        problems.append("clean run lacks optimisation level(s): "
                        + ", ".join(sorted(required_opts - clean_opts)))
    elif clean_groups < 2 or clean_regions < 12:
        problems.append("clean run covered too few keys or regions")
    if redis is None:
        problems.append("no PQCP_CT_TRACE_REDISCOVERY PASS marker with "
                        "every leak found and no benign change flagged")
    else:
        found, total, benign = (int(redis.group(i)) for i in (1, 2, 3))
        if found != total or total < 5 or benign < 3:
            problems.append(
                f"rediscovery incomplete: leaks={found}/{total}, "
                f"benign controls={benign}")
        details["leaks_rediscovered"] = f"{found}/{total}"
        details["missed_by_counts_only"] = (
            f"{redis.group(4)}/{redis.group(5)}")
    if clean_opts:
        details["regions"] = clean_regions
        details["key_groups"] = clean_groups
        details["optimisation_levels"] = sorted(clean_opts)
    if problems:
        return fail_claim(
            spec, reason="; ".join(problems), validators=validators,
            evidence_artifacts=artifacts, commands=commands, details=details)
    return pass_claim(
        spec, validators=validators, evidence_artifacts=artifacts,
        commands=commands, details=details)


def evaluate_ct_trace_declassified(
    spec: dict[str, Any], *, transcript_manifest: Path
) -> dict[str, object]:
    """Bind security.ct_trace_declassified to the clean run AND rediscovery.

    The clean run must compare a substantial share of the signing trace at
    three optimisation levels with zero violations; the rediscovery run must
    find every injected ML-DSA leak and flag no benign change.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = [
        "tools/tcg_ct_plugin::pqcp_ct_trace",
        "scripts/run_ct_trace_checks.py",
        "scripts/ct_trace_analysis.py::analyze_declassified",
        "scripts/ct_leak_rediscovery_mldsa.py",
    ]
    commands = [
        "python3 scripts/run_ct_trace_checks.py --alg mldsa",
        "python3 scripts/run_ct_trace_checks.py --alg mldsa --rediscover",
    ]
    details: dict[str, object] = {}
    bodies = {}
    for step in ("ct trace declassified", "ct leak rediscovery declassified"):
        path, sha, body = _read_named_transcript(transcript_manifest, step)
        if path is None or not body:
            return fail_claim(
                spec,
                reason=f"{step} transcript missing or empty in {transcript_manifest}",
                validators=validators, evidence_artifacts=artifacts,
                commands=commands)
        artifacts.append(artifact(path, label=f"{step} transcript"))
        details[f"{step} transcript_sha256"] = sha
        bodies[step] = body

    clean_opts = set()
    segments = testable = 0
    for m in re.finditer(
            r"PQCP_CT_TRACE_DECLASS PASS alg=MLDSA-65 opt=(\S+) "
            r"regions=(\d+) groups=(\d+) segments=(\d+) testable=(\d+) "
            r"classes=(\d+) sites=(\d+) violations=0 coverage_pct=\S+",
            bodies["ct trace declassified"]):
        clean_opts.add(m.group(1))
        if int(m.group(2)) >= 12 and int(m.group(3)) >= 2:
            segments = max(segments, int(m.group(4)))
            testable = max(testable, int(m.group(5)))
    redis = re.search(
        r"PQCP_CT_TRACE_DECLASS_REDISCOVERY PASS leaks=(\d+)/(\d+) "
        r"benign_flagged=0/(\d+) missed_by_counts_only=(\d+)/(\d+)",
        bodies["ct leak rediscovery declassified"])
    problems = []
    required_opts = {"default", "speed", "debug"}
    if not clean_opts:
        problems.append("no clean PQCP_CT_TRACE_DECLASS PASS marker with "
                        "zero violations")
    elif not required_opts <= clean_opts:
        problems.append("clean run lacks optimisation level(s): "
                        + ", ".join(sorted(required_opts - clean_opts)))
    elif segments == 0 or testable * 10 < segments * 7:
        problems.append(
            f"too little of the trace was comparable: {testable}/{segments}")
    if redis is None:
        problems.append("no PQCP_CT_TRACE_DECLASS_REDISCOVERY PASS marker "
                        "with every leak found and no benign change flagged")
    else:
        found, total, benign = (int(redis.group(i)) for i in (1, 2, 3))
        if found != total or total < 4 or benign < 3:
            problems.append(
                f"rediscovery incomplete: leaks={found}/{total}, "
                f"benign controls={benign}")
        details["leaks_rediscovered"] = f"{found}/{total}"
        details["missed_by_counts_only"] = (
            f"{redis.group(4)}/{redis.group(5)}")
    if clean_opts:
        details["segments"] = segments
        details["comparable_segments"] = testable
        details["optimisation_levels"] = sorted(clean_opts)
    if problems:
        return fail_claim(
            spec, reason="; ".join(problems), validators=validators,
            evidence_artifacts=artifacts, commands=commands, details=details)
    return pass_claim(
        spec, validators=validators, evidence_artifacts=artifacts,
        commands=commands, details=details)


VLAT_INVENTORY_BASELINE = SCRIPT_DIR / "ct_vlat_inventory_baseline.json"


def evaluate_ct_trace_cortex_m_latency(
    spec: dict[str, Any], *, transcript_manifest: Path,
    inventory_baseline: Path | None = None,
) -> dict[str, object]:
    """Bind security.ct_trace_cortex_m_latency to the clean run AND rediscovery.

    The clean run must be PASS with zero failing sites and clean address-level
    channels at three optimisation levels; the candidate-site inventory (exact
    operands vary, documented model constant) may not exceed the committed
    baseline; the rediscovery run must find every injected operand-latency leak
    and flag no benign change.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = [
        "tools/tcg_ct_plugin::pqcp_ct_trace",
        "scripts/run_ct_trace_checks.py",
        "scripts/ct_trace_analysis.py::analyze_vlat",
        "scripts/ct_leak_rediscovery_m3.py",
    ]
    commands = [
        "python3 scripts/run_ct_trace_checks.py --target cortex-m3",
        "python3 scripts/run_ct_trace_checks.py --target cortex-m3 --rediscover",
    ]
    details: dict[str, object] = {}
    bodies = {}
    for step in ("ct trace cortex-m latency",
                 "ct leak rediscovery cortex-m latency"):
        path, sha, body = _read_named_transcript(transcript_manifest, step)
        if path is None or not body:
            return fail_claim(
                spec,
                reason=f"{step} transcript missing or empty in {transcript_manifest}",
                validators=validators, evidence_artifacts=artifacts,
                commands=commands)
        artifacts.append(artifact(path, label=f"{step} transcript"))
        details[f"{step} transcript_sha256"] = sha
        bodies[step] = body

    baseline_path = inventory_baseline or VLAT_INVENTORY_BASELINE
    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        candidate_max = int(baseline["candidate_sites_max"])
    except (OSError, ValueError, KeyError):
        return fail_claim(
            spec, reason=f"unreadable inventory baseline {baseline_path}",
            validators=validators, evidence_artifacts=artifacts,
            commands=commands)

    clean_opts = set()
    candidates = 0
    for m in re.finditer(
            r"PQCP_CT_TRACE_VLAT PASS alg=MLKEM-768 target=cortex-m3 "
            r"opt=(\S+) regions=(\d+) sites=(\d+) div_sites=(\d+) "
            r"mul_sites=(\d+) fail_sites=0 candidate_sites=(\d+) "
            r"base=clean",
            bodies["ct trace cortex-m latency"]):
        if int(m.group(2)) >= 12:
            clean_opts.add(m.group(1))
            candidates = max(candidates, int(m.group(6)))
    redis = re.search(
        r"PQCP_CT_TRACE_VLAT_REDISCOVERY PASS leaks=(\d+)/(\d+) "
        r"benign_flagged=0/(\d+) missed_by_address_channels=(\d+)/(\d+)",
        bodies["ct leak rediscovery cortex-m latency"])
    problems = []
    required_opts = {"default", "speed", "debug"}
    if not clean_opts:
        problems.append("no clean PQCP_CT_TRACE_VLAT PASS marker with zero "
                        "failing sites")
    elif not required_opts <= clean_opts:
        problems.append("clean run lacks optimisation level(s): "
                        + ", ".join(sorted(required_opts - clean_opts)))
    elif candidates > candidate_max:
        problems.append(
            f"candidate-site inventory grew: {candidates} > baseline "
            f"{candidate_max}")
    if redis is None:
        problems.append("no PQCP_CT_TRACE_VLAT_REDISCOVERY PASS marker with "
                        "every leak found and no benign change flagged")
    else:
        found, total, benign = (int(redis.group(i)) for i in (1, 2, 3))
        if found != total or total < 3 or benign < 3:
            problems.append(
                f"rediscovery incomplete: leaks={found}/{total}, "
                f"benign controls={benign}")
        details["leaks_rediscovered"] = f"{found}/{total}"
        details["missed_by_address_channels"] = (
            f"{redis.group(4)}/{redis.group(5)}")
    if clean_opts:
        details["candidate_sites"] = candidates
        details["candidate_sites_baseline_max"] = candidate_max
        details["optimisation_levels"] = sorted(clean_opts)
    if problems:
        return fail_claim(
            spec, reason="; ".join(problems), validators=validators,
            evidence_artifacts=artifacts, commands=commands, details=details)
    return pass_claim(
        spec, validators=validators, evidence_artifacts=artifacts,
        commands=commands, details=details)


VLAT_SIGNING_BASELINE = SCRIPT_DIR / "ct_vlat_signing_baseline.json"


def evaluate_ct_trace_cortex_m_signing(
    spec: dict[str, Any], *, transcript_manifest: Path,
    signing_baseline: Path | None = None,
) -> dict[str, object]:
    """Bind security.ct_trace_cortex_m_signing to the M4 run and M3 inventory.

    M4: clean at three optimisation levels with most segments comparable.
    M3: no violation on any channel but the long multiply, at least one such
    finding at every level (positive control), and no more leaking sites than
    the committed baseline.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = [
        "tools/tcg_ct_plugin::pqcp_ct_trace",
        "scripts/run_ct_trace_checks.py",
        "scripts/ct_trace_analysis.py::analyze_declassified",
        "scripts/ct_trace_analysis.py::analyze_vlat",
    ]
    commands = [
        "python3 scripts/run_ct_trace_checks.py --target cortex-m4 --alg mldsa",
        "python3 scripts/run_ct_trace_checks.py --target cortex-m3 --alg mldsa --measure",
    ]
    details: dict[str, object] = {}
    bodies = {}
    steps = ("ct trace cortex-m4 signing", "ct trace cortex-m3 signing inventory")
    for step in steps:
        path, sha, body = _read_named_transcript(transcript_manifest, step)
        if path is None or not body:
            return fail_claim(
                spec,
                reason=f"{step} transcript missing or empty in {transcript_manifest}",
                validators=validators, evidence_artifacts=artifacts,
                commands=commands)
        artifacts.append(artifact(path, label=f"{step} transcript"))
        details[f"{step} transcript_sha256"] = sha
        bodies[step] = body
    baseline_path = signing_baseline or VLAT_SIGNING_BASELINE
    try:
        site_max = {
            str(k): int(v) for k, v in json.loads(
                baseline_path.read_text(encoding="utf-8"))[
                    "m3_attributed_sites_max"].items()}
    except (OSError, ValueError, KeyError, AttributeError):
        return fail_claim(
            spec, reason=f"unreadable signing baseline {baseline_path}",
            validators=validators, evidence_artifacts=artifacts,
            commands=commands)

    required_opts = {"default", "speed", "debug"}
    problems = []
    m4_opts = set()
    for m in re.finditer(
            r"PQCP_CT_TRACE_VLAT_DECLASS PASS alg=MLDSA-65 target=cortex-m4 "
            r"opt=(\S+) regions=(\d+) segments=(\d+) testable=(\d+) "
            r"violations=0 ",
            bodies[steps[0]]):
        if int(m.group(2)) >= 12 and int(m.group(4)) * 10 >= int(m.group(3)) * 7:
            m4_opts.add(m.group(1))
    if not required_opts <= m4_opts:
        problems.append("Cortex-M4 signing not clean at: "
                        + ", ".join(sorted(required_opts - m4_opts)))
    m3_sites: dict[str, int] = {}
    for m in re.finditer(
            r"PQCP_CT_TRACE_VLAT_DECLASS FAIL alg=MLDSA-65 target=cortex-m3 "
            r"opt=(\S+) regions=(\d+) segments=(\d+) testable=(\d+) "
            r"violations=(\d+) vdiv_violations=0 vmul_violations=(\d+) "
            r"other_violations=0 candidate_segments=\d+ "
            r"attributed_sites=(\d+)",
            bodies[steps[1]]):
        if (int(m.group(2)) >= 12 and int(m.group(6)) >= 1 and
                int(m.group(5)) == int(m.group(6)) and
                int(m.group(4)) * 10 >= int(m.group(3)) * 7):
            m3_sites[m.group(1)] = int(m.group(7))
    if not required_opts <= set(m3_sites):
        problems.append("Cortex-M3 inventory incomplete or has violations on "
                        "a channel other than the long multiply at: "
                        + ", ".join(sorted(required_opts - set(m3_sites))))
    for opt, count in sorted(m3_sites.items()):
        if opt in site_max and count > site_max[opt]:
            problems.append(f"M3 leaking sites at {opt} grew: {count} > "
                            f"baseline {site_max[opt]}")
        if count < 1:
            problems.append(f"M3 inventory at {opt} has no attributed sites")
    if "[ct-trace] MEASURED:" not in bodies[steps[1]]:
        problems.append("no MEASURED line for the Cortex-M3 inventory")
    details["m4_clean_levels"] = sorted(m4_opts)
    details["m3_leaking_sites"] = dict(sorted(m3_sites.items()))
    if problems:
        return fail_claim(
            spec, reason="; ".join(problems), validators=validators,
            evidence_artifacts=artifacts, commands=commands, details=details)
    return pass_claim(
        spec, validators=validators, evidence_artifacts=artifacts,
        commands=commands, details=details)


VLAT_MITIGATION_BASELINE = SCRIPT_DIR / "ct_vlat_mitigation_baseline.json"


def evaluate_ct_trace_cortex_m_mitigation(
    spec: dict[str, Any], *, transcript_manifest: Path,
    mitigation_baseline: Path | None = None,
) -> dict[str, object]:
    """Bind security.ct_trace_cortex_m_mitigation to the closed-loop run.

    At every optimisation level the stock Cortex-M3 signing image must still
    show the long-multiply finding (positive control), the fixed-latency
    build must show no violation and no attributed site on any channel over
    most segments, both must produce the same signature digest, and the
    measured instruction overhead may not exceed the committed ceiling.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = [
        "tools/tcg_ct_plugin::pqcp_ct_trace",
        "scripts/run_ct_trace_checks.py::run_core_mldsa_mitigated",
        "scripts/mldsa_fixed_latency.py",
        "scripts/ct_trace_analysis.py::analyze_declassified",
        "scripts/ct_trace_analysis.py::analyze_vlat",
    ]
    commands = [
        "python3 scripts/mldsa_fixed_latency.py --selftest",
        "python3 scripts/run_ct_trace_checks.py --target cortex-m3 --alg mldsa --mitigated",
    ]
    steps = ("mldsa fixed-latency multiply selftest",
             "ct trace cortex-m3 signing mitigation")
    details: dict[str, object] = {}
    bodies = {}
    for step in steps:
        path, sha, body = _read_named_transcript(transcript_manifest, step)
        if path is None or not body:
            return fail_claim(
                spec,
                reason=f"{step} transcript missing or empty in {transcript_manifest}",
                validators=validators, evidence_artifacts=artifacts,
                commands=commands)
        artifacts.append(artifact(path, label=f"{step} transcript"))
        details[f"{step} transcript_sha256"] = sha
        bodies[step] = body
    baseline_path = mitigation_baseline or VLAT_MITIGATION_BASELINE
    try:
        ceiling = {
            str(k): float(v) for k, v in json.loads(
                baseline_path.read_text(encoding="utf-8"))[
                    "insn_overhead_pct_max"].items()}
    except (OSError, ValueError, KeyError, AttributeError):
        return fail_claim(
            spec, reason=f"unreadable mitigation baseline {baseline_path}",
            validators=validators, evidence_artifacts=artifacts,
            commands=commands)
    problems = []
    m = re.search(r"PQCP_MLDSA_FIXED_MUL_SELFTEST PASS products=(\d+)",
                  bodies[steps[0]])
    if not m or int(m.group(1)) < 1_000_000:
        problems.append("fixed-latency multiply selftest missing or too small")
    else:
        details["selftest_products"] = int(m.group(1))
    required_opts = {"default", "speed", "debug"}
    good: dict[str, float] = {}
    for m in re.finditer(
            r"PQCP_CT_TRACE_VLAT_MITIGATION PASS alg=MLDSA-65 "
            r"target=cortex-m3 opt=(\S+) stock_vmul_violations=(\d+) "
            r"stock_sites=(\d+) patched_violations=0 patched_sites=0 "
            r"patched_testable=(\d+) sig_digest_match=1 "
            r"insn_overhead_pct=(-?[0-9.]+)", bodies[steps[1]]):
        if (int(m.group(2)) >= 1 and int(m.group(3)) >= 1 and
                int(m.group(4)) >= 400):
            good[m.group(1)] = float(m.group(5))
    if not required_opts <= set(good):
        problems.append("mitigation not verified at: "
                        + ", ".join(sorted(required_opts - set(good))))
    for opt, pct in sorted(good.items()):
        if opt in ceiling and pct > ceiling[opt]:
            problems.append(f"instruction overhead at {opt} grew: {pct} > "
                            f"ceiling {ceiling[opt]}")
    details["insn_overhead_pct"] = dict(sorted(good.items()))
    if problems:
        return fail_claim(
            spec, reason="; ".join(problems), validators=validators,
            evidence_artifacts=artifacts, commands=commands, details=details)
    return pass_claim(
        spec, validators=validators, evidence_artifacts=artifacts,
        commands=commands, details=details)


VLAT_MODELS_BASELINE = SCRIPT_DIR / "ct_vlat_models_baseline.json"


def evaluate_ct_trace_cortex_m_latency_models(
    spec: dict[str, Any], *, transcript_manifest: Path,
    models_baseline: Path | None = None,
) -> dict[str, object]:
    """Bind security.ct_trace_cortex_m_latency_models to the model comparison.

    Requires the C/Python classifier cross-check, a live second channel (the
    stock ML-DSA image fails under the CMEmu model), the patched image clean
    under CMEmu at every level, and the ML-KEM CMEmu-only site count within
    the committed baseline.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = [
        "tools/tcg_ct_plugin/src/ct_latency_models.h",
        "scripts/ct_latency_models.py",
        "scripts/ct_trace_analysis.py::compare_latency_models",
        "scripts/run_ct_trace_checks.py::report_models",
    ]
    commands = [
        "python3 scripts/ct_latency_models.py --crosscheck",
        "python3 scripts/run_ct_trace_checks.py --target cortex-m3",
        "python3 scripts/run_ct_trace_checks.py --target cortex-m3 --alg mldsa --mitigated",
    ]
    steps = ("ct latency model crosscheck", "ct trace cortex-m latency",
             "ct trace cortex-m3 signing mitigation")
    details: dict[str, object] = {}
    bodies = {}
    for step in steps:
        path, sha, body = _read_named_transcript(transcript_manifest, step)
        if path is None or not body:
            return fail_claim(
                spec,
                reason=f"{step} transcript missing or empty in {transcript_manifest}",
                validators=validators, evidence_artifacts=artifacts,
                commands=commands)
        artifacts.append(artifact(path, label=f"{step} transcript"))
        details[f"{step} transcript_sha256"] = sha
        bodies[step] = body
    baseline_path = models_baseline or VLAT_MODELS_BASELINE
    try:
        only_max = {
            str(k): int(v) for k, v in json.loads(
                baseline_path.read_text(encoding="utf-8"))[
                    "mlkem_cmemu_only_max"].items()}
    except (OSError, ValueError, KeyError, AttributeError):
        return fail_claim(
            spec, reason=f"unreadable models baseline {baseline_path}",
            validators=validators, evidence_artifacts=artifacts,
            commands=commands)
    problems = []
    m = re.search(r"PQCP_CT_LATENCY_MODEL_CROSSCHECK PASS cases=(\d+)",
                  bodies[steps[0]])
    if not m or int(m.group(1)) < 100_000:
        problems.append("classifier cross-check missing or too small")
    else:
        details["crosscheck_cases"] = int(m.group(1))
    required_opts = {"default", "speed", "debug"}
    line = (r"PQCP_CT_TRACE_LATENCY_MODELS alg=%s target=cortex-m3 "
            r"opt=%s documented_sites=(\d+) cmemu_sites=(\d+) both=(\d+) "
            r"documented_only=(\d+) cmemu_only=(\d+)")
    kem_only: dict[str, int] = {}
    for opt in sorted(required_opts):
        m = re.search(line % ("MLKEM-768", re.escape(opt)), bodies[steps[1]])
        if m:
            kem_only[opt] = int(m.group(5))
    if set(kem_only) != required_opts:
        problems.append("ML-KEM model comparison missing at: "
                        + ", ".join(sorted(required_opts - set(kem_only))))
    for opt, count in sorted(kem_only.items()):
        if opt in only_max and count > only_max[opt]:
            problems.append(f"ML-KEM CMEmu-only sites at {opt} grew: "
                            f"{count} > baseline {only_max[opt]}")
    stock_live: dict[str, int] = {}
    patched_clean = set()
    for opt in sorted(required_opts):
        m = re.search(line % ("MLDSA-65", re.escape(opt + "-stock")),
                      bodies[steps[2]])
        if m and int(m.group(2)) >= 1:
            stock_live[opt] = int(m.group(2))
        m = re.search((line % ("MLDSA-65", re.escape(opt + "-patched"))) +
                      r" doc_violations=(\d+) cmemu_violations=(\d+)",
                      bodies[steps[2]])
        if (m and int(m.group(2)) == 0 and int(m.group(1)) == 0 and
                int(m.group(6)) == 0 and int(m.group(7)) == 0):
            patched_clean.add(opt)
    if set(stock_live) != required_opts:
        problems.append("second channel not live (stock ML-DSA shows no "
                        "CMEmu-failing site) at: "
                        + ", ".join(sorted(required_opts - set(stock_live))))
    if patched_clean != required_opts:
        problems.append("patched image not clean under both models at: "
                        + ", ".join(sorted(required_opts - patched_clean)))
    details["mlkem_cmemu_only_sites"] = dict(sorted(kem_only.items()))
    details["mldsa_stock_cmemu_sites"] = dict(sorted(stock_live.items()))
    details["patched_clean_levels"] = sorted(patched_clean)
    if problems:
        return fail_claim(
            spec, reason="; ".join(problems), validators=validators,
            evidence_artifacts=artifacts, commands=commands, details=details)
    return pass_claim(
        spec, validators=validators, evidence_artifacts=artifacts,
        commands=commands, details=details)


KEM_MITIGATION_BASELINE = SCRIPT_DIR / "ct_kem_mitigation_baseline.json"


def evaluate_ct_trace_cortex_m_kem_mitigation(
    spec: dict[str, Any], *, transcript_manifest: Path,
    kem_baseline: Path | None = None,
) -> dict[str, object]:
    """Bind security.ct_trace_cortex_m_kem_mitigation to the repair run.

    Per level: the stock image still shows the CMEmu-only site (positive
    control), the repaired image has no failing site under either model, the
    shared-secret digest is unchanged, and the instruction overhead stays
    under the committed ceiling. The host self-test must cover the whole
    compress_d10 input domain.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = [
        "scripts/mlkem_fixed_latency.py",
        "scripts/run_ct_trace_checks.py::run_core_mlkem_mitigated",
        "scripts/ct_latency_models.py",
        "scripts/ct_trace_analysis.py::compare_latency_models",
    ]
    commands = [
        "python3 scripts/mlkem_fixed_latency.py --selftest",
        "python3 scripts/run_ct_trace_checks.py --target cortex-m3 --alg mlkem --mitigated",
    ]
    steps = ("mlkem fixed-latency selftest",
             "ct trace cortex-m3 kem mitigation")
    details: dict[str, object] = {}
    bodies = {}
    for step in steps:
        path, sha, body = _read_named_transcript(transcript_manifest, step)
        if path is None or not body:
            return fail_claim(
                spec,
                reason=f"{step} transcript missing or empty in {transcript_manifest}",
                validators=validators, evidence_artifacts=artifacts,
                commands=commands)
        artifacts.append(artifact(path, label=f"{step} transcript"))
        details[f"{step} transcript_sha256"] = sha
        bodies[step] = body
    baseline_path = kem_baseline or KEM_MITIGATION_BASELINE
    try:
        ceiling = {
            str(k): float(v) for k, v in json.loads(
                baseline_path.read_text(encoding="utf-8"))[
                    "insn_overhead_pct_max"].items()}
    except (OSError, ValueError, KeyError, AttributeError):
        return fail_claim(
            spec, reason=f"unreadable baseline {baseline_path}",
            validators=validators, evidence_artifacts=artifacts,
            commands=commands)
    problems = []
    m = re.search(r"PQCP_MLKEM_FIXED_LATENCY_SELFTEST PASS domain=(\d+) "
                  r"stock_cmemu_classes=(\d+) fixed_cmemu_classes=1",
                  bodies[steps[0]])
    if (not m or int(m.group(1)) != 3329 or int(m.group(2)) < 2 or
            "variants=2" not in bodies[steps[0]]):
        problems.append("host self-test missing or does not cover the "
                        "whole domain with a live stock distinction")
    good: dict[str, float] = {}
    for m in re.finditer(
            r"PQCP_CT_TRACE_VLAT_MITIGATION_KEM PASS alg=(MLKEM-\d+) "
            r"target=cortex-m3 opt=(\S+) stock_cmemu_only=(\d+) "
            r"patched_documented_sites=0 patched_cmemu_sites=0 "
            r"ss_digest_match=1 insn_overhead_pct=(-?[0-9.]+)",
            bodies[steps[1]]):
        if int(m.group(3)) >= 1:
            good[f"{m.group(1)}/{m.group(2)}"] = float(m.group(4))
    required = {f"MLKEM-{lv}/{o}" for lv in (512, 768, 1024)
                for o in ("default", "speed", "debug")}
    if not required <= set(good):
        problems.append("repair not verified at: "
                        + ", ".join(sorted(required - set(good))))
    for key, pct in sorted(good.items()):
        opt = key.split("/")[1]
        if opt in ceiling and pct > ceiling[opt]:
            problems.append(f"instruction overhead at {key} grew: {pct} > "
                            f"ceiling {ceiling[opt]}")
    details["insn_overhead_pct"] = dict(sorted(good.items()))
    spreads: dict[str, int] = {}
    for key in sorted(required):
        alg, opt = key.split("/")
        pair = []
        for variant in ("stock", "patched"):
            m = re.search(
                r"PQCP_CT_TRACE_MODELLED_CYCLES alg=" + re.escape(alg) +
                r" target=cortex-m3 opt=" + re.escape(f"{opt}-{variant}") +
                r" groups=\d+ max_spread=(\d+) distinct_totals=\d+ "
                r"variable_cycles_min=\d+ variable_cycles_max=\d+ "
                r"insns_min=(\d+) relative_amplitude=\S+",
                bodies[steps[1]])
            pair.append((int(m.group(1)), int(m.group(2))) if m else None)
        if pair[0] is None or pair[1] is None:
            problems.append(f"modelled-cycle spread missing at {key}")
            continue
        (stock_spread, insns), (fixed_spread, _) = pair
        spreads[key] = stock_spread
        if stock_spread < 1:
            problems.append(f"stock modelled spread is 0 at {key} "
                            "(positive control lost)")
        if fixed_spread != 0:
            problems.append(f"repaired image still has a modelled spread of "
                            f"{fixed_spread} cycles at {key}")
        if stock_spread > 8 or stock_spread * 100000 > insns:
            problems.append(f"modelled spread at {key} grew to "
                            f"{stock_spread} cycles over {insns} instructions")
    details["stock_modelled_spread_cycles"] = dict(sorted(spreads.items()))
    if problems:
        return fail_claim(
            spec, reason="; ".join(problems), validators=validators,
            evidence_artifacts=artifacts, commands=commands, details=details)
    return pass_claim(
        spec, validators=validators, evidence_artifacts=artifacts,
        commands=commands, details=details)


def evaluate_mldsa_rejection_independence(
    spec: dict[str, Any], *, transcript_manifest: Path,
) -> dict[str, object]:
    """Bind security.mldsa_rejection_independence to the reduced study.

    The statistics self-test must pass and the homogeneity test over the
    per-key attempt histograms must not reject at p >= 1e-3, over a study big
    enough to mean something. A regression guard, not a proof.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = ["scripts/mldsa_rejection_study.py"]
    commands = ["python3 scripts/mldsa_rejection_study.py --selftest",
                "python3 scripts/mldsa_rejection_study.py --keys 60 --messages 3000"]
    steps = ("mldsa rejection selftest", "mldsa rejection study")
    details: dict[str, object] = {}
    bodies = {}
    for step in steps:
        path, sha, body = _read_named_transcript(transcript_manifest, step)
        if path is None or not body:
            return fail_claim(
                spec,
                reason=f"{step} transcript missing or empty in {transcript_manifest}",
                validators=validators, evidence_artifacts=artifacts,
                commands=commands)
        artifacts.append(artifact(path, label=f"{step} transcript"))
        details[f"{step} transcript_sha256"] = sha
        bodies[step] = body
    problems = []
    if "PQCP_MLDSA_REJECTION_SELFTEST PASS" not in bodies[steps[0]]:
        problems.append("statistics self-test did not pass")
    m = re.search(
        r"PQCP_MLDSA_REJECTION_STUDY CONSISTENT_WITH_INDEPENDENT keys=(\d+) "
        r"msgs=(\d+) pooled_mean=([0-9.]+) key_mean_sd=[0-9.]+ "
        r"relative_sd=([0-9.]+) chi2=[0-9.]+ dof=(\d+) p=([0-9.eE+-]+)",
        bodies[steps[1]])
    if not m:
        problems.append("study did not report CONSISTENT_WITH_INDEPENDENT")
    else:
        keys, msgs, mean, rsd, dof, p = (int(m.group(1)), int(m.group(2)),
                                          float(m.group(3)), float(m.group(4)),
                                          int(m.group(5)), float(m.group(6)))
        if keys < 50 or msgs < 2000 or dof < 100:
            problems.append(f"study too small: {keys} keys x {msgs} messages")
        if p < 1e-3:
            problems.append(f"attempt distributions differ between keys "
                            f"(p={p})")
        if not 4.0 <= mean <= 6.5 or rsd > 0.05:
            problems.append(f"implausible attempt statistics mean={mean} "
                            f"relative_sd={rsd}")
        details.update({"keys": keys, "messages": msgs, "pooled_mean": mean,
                        "relative_sd": rsd, "p": p})
    if problems:
        return fail_claim(
            spec, reason="; ".join(problems), validators=validators,
            evidence_artifacts=artifacts, commands=commands, details=details)
    return pass_claim(
        spec, validators=validators, evidence_artifacts=artifacts,
        commands=commands, details=details)


def evaluate_ct_trace_cortex_m33(
    spec: dict[str, Any], *, transcript_manifest: Path,
) -> dict[str, object]:
    """Bind security.ct_trace_cortex_m33 to the ML-KEM and ML-DSA M33 runs."""
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = ["tools/tcg_ct_plugin::pqcp_ct_trace",
                  "scripts/run_ct_trace_checks.py",
                  "scripts/ct_trace_analysis.py::CORE_CHANNELS"]
    commands = ["python3 scripts/run_ct_trace_checks.py --target cortex-m33",
                "python3 scripts/run_ct_trace_checks.py --target cortex-m33 --alg mldsa"]
    steps = ("ct trace cortex-m33 decapsulation", "ct trace cortex-m33 signing")
    bodies = {}
    details: dict[str, object] = {}
    for step in steps:
        path, sha, body = _read_named_transcript(transcript_manifest, step)
        if path is None or not body:
            return fail_claim(
                spec,
                reason=f"{step} transcript missing or empty in {transcript_manifest}",
                validators=validators, evidence_artifacts=artifacts,
                commands=commands)
        artifacts.append(artifact(path, label=f"{step} transcript"))
        details[f"{step} transcript_sha256"] = sha
        bodies[step] = body
    required = {"default", "speed", "debug"}
    kem = {m.group(1) for m in re.finditer(
        r"PQCP_CT_TRACE_VLAT PASS alg=MLKEM-768 target=cortex-m33 "
        r"opt=(\S+) regions=(\d+) sites=\d+ div_sites=\d+ mul_sites=\d+ "
        r"fail_sites=0 candidate_sites=\d+ base=clean", bodies[steps[0]])
        if int(m.group(2)) >= 12}
    dsa = {m.group(1) for m in re.finditer(
        r"PQCP_CT_TRACE_VLAT_DECLASS PASS alg=MLDSA-65 target=cortex-m33 "
        r"opt=(\S+) regions=(\d+) segments=(\d+) testable=(\d+) "
        r"violations=0 ", bodies[steps[1]])
        if int(m.group(2)) >= 12 and int(m.group(4)) * 10 >= int(m.group(3)) * 7}
    problems = []
    if not required <= kem:
        problems.append("ML-KEM not clean on Cortex-M33 at: "
                        + ", ".join(sorted(required - kem)))
    if not required <= dsa:
        problems.append("ML-DSA signing not clean on Cortex-M33 at: "
                        + ", ".join(sorted(required - dsa)))
    details.update({"mlkem_clean_levels": sorted(kem),
                    "mldsa_clean_levels": sorted(dsa)})
    if problems:
        return fail_claim(
            spec, reason="; ".join(problems), validators=validators,
            evidence_artifacts=artifacts, commands=commands, details=details)
    return pass_claim(
        spec, validators=validators, evidence_artifacts=artifacts,
        commands=commands, details=details)


def evaluate_fault_campaign_boot_selftest(
    spec: dict[str, Any], *, transcript_manifest: Path
) -> dict[str, object]:
    """Bind security.fault_campaign_boot_selftest to the fault gate step.

    The gate prints PQCP_FAULT_GATE PASS only when the campaign was calibrated,
    still found exploitable sites on the valid-only boot image, and found none
    once the boot self-test carries negative vectors; the evaluator re-parses
    the numbers so a weakened gate cannot pass silently.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = [
        "scripts/run_fault_campaign.py",
        "scripts/run_fault_gate.py",
        "scripts/fault_oracle.py",
        "scripts/fault_inject.py",
    ]
    commands = ["python3 scripts/run_fault_gate.py --output-dir <dir>"]
    path, sha, body = _read_named_transcript(transcript_manifest, "fault campaign")
    if path is None or not body:
        return fail_claim(
            spec, reason=f"fault campaign transcript missing or empty in {transcript_manifest}",
            validators=validators, evidence_artifacts=artifacts, commands=commands)
    artifacts.append(artifact(path, label="fault campaign transcript"))
    details: dict[str, object] = {"transcript_sha256": sha}
    gate = re.search(
        r"PQCP_FAULT_GATE PASS sites=(\d+) exploitable_boot=(\d+) "
        r"exploitable_boot_negative=(\d+) detected_boot=(\d+) "
        r"detected_boot_negative=(\d+)", body)
    problems = []
    if gate is None:
        problems.append("no PQCP_FAULT_GATE PASS marker")
    else:
        sites, boot, neg, det, det_neg = (int(g) for g in gate.groups())
        details.update({"sites": sites, "exploitable_valid_only_boot": boot,
                        "exploitable_negative_boot": neg,
                        "detected_valid_only_boot": det,
                        "detected_negative_boot": det_neg})
        if sites < 300:
            problems.append(f"campaign too small ({sites} sites)")
        if boot < 1:
            problems.append("campaign found no exploitable site on the "
                            "valid-only boot image (not sensitive)")
        if neg != 0:
            problems.append(f"{neg} exploitable site(s) survive negative vectors")
        if det_neg <= det:
            problems.append("negative vectors detect no more than valid-only")
    campaigns = re.findall(r"PQCP_FAULT_CAMPAIGN variant=(\S+) .*controls_ok=(\d+)/(\d+)", body)
    if {v for v, _, _ in campaigns} != {"boot", "boot-negative"} or any(
            ok != total or int(total) == 0 for _, ok, total in campaigns):
        problems.append("missing campaign marker or identity controls not clean")
    if problems:
        return fail_claim(
            spec, reason="; ".join(problems), validators=validators,
            evidence_artifacts=artifacts, commands=commands, details=details)
    return pass_claim(
        spec, validators=validators, evidence_artifacts=artifacts,
        commands=commands, details=details)


def evaluate_fault_timing_countermeasure(
    spec: dict[str, Any], *, transcript_manifest: Path
) -> dict[str, object]:
    """Bind security.fault_timing_countermeasure to the timing gate step.

    Re-parses the numbers: a weakened gate must not pass silently. The base
    image must show exploitable sites under both timings, the hardened image
    none, and every campaign must have been calibrated and error free.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = [
        "scripts/run_fault_timing_gate.py",
        "scripts/run_fault_campaign.py",
        "scripts/fault_gdb.py",
        "scripts/fault_oracle.py",
    ]
    commands = ["python3 scripts/run_fault_timing_gate.py --output-dir <dir>"]
    path, sha, body = _read_named_transcript(transcript_manifest, "fault timing campaign")
    if path is None or not body:
        return fail_claim(
            spec, reason=f"fault timing campaign transcript missing or empty in {transcript_manifest}",
            validators=validators, evidence_artifacts=artifacts, commands=commands)
    artifacts.append(artifact(path, label="fault timing campaign transcript"))
    details: dict[str, object] = {"transcript_sha256": sha}
    gate = re.search(
        r"PQCP_FAULT_TIMING_GATE PASS sites_postboot=(\d+) sites_transient=(\d+) "
        r"base_postboot=(\d+) base_transient=(\d+) hardened_postboot=(\d+) "
        r"hardened_transient=(\d+)", body)
    problems = []
    if gate is None:
        problems.append("no PQCP_FAULT_TIMING_GATE PASS marker")
    else:
        sp, st, bp, bt, hp, ht = (int(g) for g in gate.groups())
        details.update({"faults_postboot": sp, "faults_transient": st,
                        "base_exploitable_postboot": bp,
                        "base_exploitable_transient": bt,
                        "hardened_exploitable_postboot": hp,
                        "hardened_exploitable_transient": ht})
        if sp < 300 or st < 300:
            problems.append("campaign too small")
        if bp < 1 or bt < 1:
            problems.append("campaign not sensitive (base image shows no "
                            "exploitable site under both timings)")
        if hp != 0 or ht != 0:
            problems.append("exploitable site(s) survive on the hardened image")
    cells = re.findall(
        r"PQCP_FAULT_CAMPAIGN variant=(\S+) .*?harness_error=(\d+) "
        r"controls_ok=(\d+)/(\d+) timing=(\S+)", body)
    seen = {(v, t) for v, _, _, _, t in cells}
    needed = {("boot-negative", "post-boot"), ("hardened", "post-boot"),
              ("boot-negative", "transient"), ("hardened", "transient")}
    if not needed <= seen or any(
            int(h) != 0 or ok != total or int(total) == 0
            for _, h, ok, total, _ in cells):
        problems.append("missing campaign cell, harness errors, or identity "
                        "controls not clean")
    if problems:
        return fail_claim(
            spec, reason="; ".join(problems), validators=validators,
            evidence_artifacts=artifacts, commands=commands, details=details)
    return pass_claim(
        spec, validators=validators, evidence_artifacts=artifacts,
        commands=commands, details=details)


def evaluate_evidence_coverage_ratchet(
    spec: dict[str, Any], *, transcript_manifest: Path
) -> dict[str, object]:
    """Bind release.evidence_coverage_ratchet to the captured audit step.

    The audit exits nonzero on any regression or new untested module, so
    the PASS marker is only printed when the ratchet held. The evaluator
    additionally parses the marker so the measured level counts land in
    the ledger details instead of a bare pass.
    """
    artifacts = [artifact(transcript_manifest, label="release-check transcript manifest")]
    validators = [
        "scripts/audit_evidence_coverage.py",
        "scripts/evidence_coverage_baseline.json",
    ]
    commands = ["python3 scripts/audit_evidence_coverage.py --check"]

    transcript_path, transcript_sha, transcript_body = _read_named_transcript(
        transcript_manifest, "evidence coverage audit"
    )
    if transcript_path is None or not transcript_body:
        return fail_claim(
            spec,
            reason=(
                "evidence coverage audit transcript missing or empty in "
                f"transcript manifest {transcript_manifest}"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    artifacts.append(artifact(transcript_path, label="evidence coverage audit transcript"))

    marker = re.search(
        r"PQCP_EVIDENCE_COVERAGE PASS modules=(\d+) L0=(\d+) L1=(\d+) "
        r"L2=(\d+) L3=(\d+) new_untested=0 regressions=0",
        transcript_body,
    )
    details = {
        "transcript_path": str(transcript_path),
        "transcript_sha256": transcript_sha,
    }
    if marker is None or "[coverage] PASS:" not in transcript_body:
        return fail_claim(
            spec,
            reason=(
                "evidence coverage audit transcript lacks the "
                "PQCP_EVIDENCE_COVERAGE PASS marker (new_untested=0 "
                "regressions=0) or the aggregate [coverage] PASS line"
            ),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    modules, l0, l1, l2, l3 = (int(g) for g in marker.groups())
    if l0 + l1 + l2 + l3 != modules:
        return fail_claim(
            spec,
            reason="evidence coverage level counts do not sum to module count",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    details.update({
        "modules": modules,
        "L0_untested": l0,
        "L1_tested": l1,
        "L2_gated": l2,
        "L3_claimed": l3,
    })
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


def evaluate_benchmark_distribution_quality(
    spec: dict[str, Any],
    *,
    csv_path: Path,
    provenance_path: Path,
) -> dict[str, object]:
    artifacts = [
        artifact(csv_path, label="benchmark CSV"),
        artifact(provenance_path, label="benchmark provenance"),
    ]
    validators = ["scripts/export_results.py distribution metric export"]
    commands = [f"python3 scripts/export_results.py --validate-only {csv_path} --verify-provenance"]
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

    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    distribution_metrics = {
        "cycles_min",
        "cycles_median",
        "cycles_p90",
        "cycles_p99",
        "cycles_max",
        "cycles_mad",
        "sample_count",
    }
    expected_parameters = {
        str(row.get("parameter_set", ""))
        for row in rows
        if str(row.get("operation", "")) in {"keygen", "encaps", "decaps", "sign", "verify"}
        and str(row.get("parameter_set", "")).startswith(("ML-KEM-", "ML-DSA-"))
    }
    observed: dict[str, set[str]] = {name: set() for name in expected_parameters}
    failures: list[str] = []
    if not expected_parameters:
        failures.append("benchmark CSV has no primitive base rows to associate with distribution metrics")
    for row in rows:
        parameter_set = str(row.get("parameter_set", ""))
        operation = str(row.get("operation", ""))
        metric_name = next(
            (
                metric
                for metric in distribution_metrics
                if operation == metric or operation.endswith(f"_{metric}")
            ),
            None,
        )
        if parameter_set not in expected_parameters or metric_name is None:
            continue
        observed[parameter_set].add(metric_name)
        raw_value = row.get("cycles") or row.get("time_us") or ""
        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            failures.append(f"{parameter_set}/{operation} has non-numeric value {raw_value!r}")
            continue
        if value < 0:
            failures.append(f"{parameter_set}/{operation} has negative value {value}")

    missing: list[str] = []
    for parameter_set, metrics in sorted(observed.items()):
        absent = sorted(distribution_metrics - metrics)
        if absent:
            missing.append(f"{parameter_set}: {', '.join(absent)}")
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        failures.append(f"benchmark provenance is not valid JSON: {exc}")
        provenance = {}
    csv_meta = provenance.get("csv") if isinstance(provenance, dict) else {}
    distribution_row_count = csv_meta.get("distribution_row_count") if isinstance(csv_meta, dict) else None
    if not isinstance(distribution_row_count, int) or distribution_row_count <= 0:
        failures.append("benchmark provenance csv.distribution_row_count is missing or zero")
    metadata_failures = validate_benchmark_metadata_document(
        provenance.get("benchmark_metadata") if isinstance(provenance, dict) else None
    )
    failures.extend(failure["message"] for failure in metadata_failures)
    if missing:
        failures.append("missing distribution metrics: " + "; ".join(missing))
    details = {
        "expected_parameter_sets": sorted(expected_parameters),
        "required_distribution_metrics": sorted(distribution_metrics),
        "observed": {name: sorted(metrics) for name, metrics in sorted(observed.items())},
        "provenance_distribution_row_count": distribution_row_count,
        "required_benchmark_metadata_keys": (
            provenance.get("benchmark_metadata", {}).get("required_keys", [])
            if isinstance(provenance, dict) and isinstance(provenance.get("benchmark_metadata"), dict)
            else []
        ),
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
    assurance_profile_result_arg = getattr(args, "assurance_profile_result", None)
    evidence_quality_result_arg = getattr(args, "evidence_quality_result", None)
    migration_readiness_arg = getattr(args, "migration_readiness", None)
    reference_values_arg = getattr(args, "reference_values", None)
    firmware_status_result_arg = getattr(args, "firmware_status_result", None)
    acvp_json_interop_result_arg = getattr(args, "acvp_json_interop_result", None)
    build_provenance_result_arg = getattr(args, "build_provenance_result", None)
    ct_sample_analysis_result_arg = getattr(args, "ct_sample_analysis_result", None)
    backend_update_evaluation_arg = getattr(args, "backend_update_evaluation", None)
    backend_contract_result_arg = getattr(args, "backend_contract_result", None)
    liboqs_inventory_arg = getattr(args, "liboqs_inventory", None)
    benchmark_campaign_result_arg = getattr(args, "benchmark_campaign_result", None)
    paper_comparison_result_arg = getattr(args, "paper_comparison_result", None)
    ct_campaign_result_arg = getattr(args, "ct_campaign_result", None)
    acvp_json_schema_result_arg = getattr(args, "acvp_json_schema_result", None)
    device_evidence_result_arg = getattr(args, "device_evidence_result", None)
    appraisal_result_arg = getattr(args, "appraisal_result", None)
    provider_scope_result_arg = getattr(args, "provider_scope_result", None)
    release_reference_values_result_arg = getattr(args, "release_reference_values_result", None)
    ct_instruction_policy_result_arg = getattr(args, "ct_instruction_policy_result", None)
    cbom = resolve_path(cbom_arg, module_path) if cbom_arg else None
    attestation = resolve_path(attestation_arg, module_path) if attestation_arg else None
    policy_result = resolve_path(policy_result_arg, module_path) if policy_result_arg else None
    assurance_digest = resolve_path(assurance_digest_arg, module_path) if assurance_digest_arg else None
    negative_floor_result = resolve_path(negative_floor_result_arg, module_path) if negative_floor_result_arg else None
    asset_trace_result = resolve_path(asset_trace_result_arg, module_path) if asset_trace_result_arg else None
    evidence_graph = resolve_path(evidence_graph_arg, module_path) if evidence_graph_arg else None
    firmware_digest_header = resolve_path(firmware_digest_header_arg, module_path) if firmware_digest_header_arg else None
    assurance_profile_result = resolve_path(assurance_profile_result_arg, module_path) if assurance_profile_result_arg else None
    evidence_quality_result = resolve_path(evidence_quality_result_arg, module_path) if evidence_quality_result_arg else None
    migration_readiness = resolve_path(migration_readiness_arg, module_path) if migration_readiness_arg else None
    reference_values = resolve_path(reference_values_arg, module_path) if reference_values_arg else None
    firmware_status_result = resolve_path(firmware_status_result_arg, module_path) if firmware_status_result_arg else None
    acvp_json_interop_result = resolve_path(acvp_json_interop_result_arg, module_path) if acvp_json_interop_result_arg else None
    build_provenance_result = resolve_path(build_provenance_result_arg, module_path) if build_provenance_result_arg else None
    ct_sample_analysis_result = resolve_path(ct_sample_analysis_result_arg, module_path) if ct_sample_analysis_result_arg else None
    backend_update_evaluation = resolve_path(backend_update_evaluation_arg, module_path) if backend_update_evaluation_arg else None
    backend_contract_result = resolve_path(backend_contract_result_arg, module_path) if backend_contract_result_arg else None
    liboqs_inventory = resolve_path(liboqs_inventory_arg, module_path) if liboqs_inventory_arg else None
    benchmark_campaign_result = resolve_path(benchmark_campaign_result_arg, module_path) if benchmark_campaign_result_arg else None
    paper_comparison_result = resolve_path(paper_comparison_result_arg, module_path) if paper_comparison_result_arg else None
    ct_campaign_result = resolve_path(ct_campaign_result_arg, module_path) if ct_campaign_result_arg else None
    acvp_json_schema_result = resolve_path(acvp_json_schema_result_arg, module_path) if acvp_json_schema_result_arg else None
    device_evidence_result = resolve_path(device_evidence_result_arg, module_path) if device_evidence_result_arg else None
    appraisal_result = resolve_path(appraisal_result_arg, module_path) if appraisal_result_arg else None
    provider_scope_result = resolve_path(provider_scope_result_arg, module_path) if provider_scope_result_arg else None
    release_reference_values_result = (
        resolve_path(release_reference_values_result_arg, module_path)
        if release_reference_values_result_arg
        else None
    )
    ct_instruction_policy_result = (
        resolve_path(ct_instruction_policy_result_arg, module_path)
        if ct_instruction_policy_result_arg
        else None
    )
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
        "benchmark.distribution_quality": lambda spec: evaluate_benchmark_distribution_quality(
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
        "firmware.evidence_chain_replay": lambda spec: evaluate_firmware_evidence_chain_replay(
            spec, transcript_manifest=transcript_manifest,
        ),
        "release.evidence_coverage_ratchet": lambda spec: evaluate_evidence_coverage_ratchet(
            spec, transcript_manifest=transcript_manifest,
        ),
        "supply_chain.transparent_appraisal_receipt": lambda spec: evaluate_transparent_appraisal_receipt(
            spec, transcript_manifest=transcript_manifest,
        ),
        "security.state_machine_model_conformance": lambda spec: evaluate_state_machine_model_conformance(
            spec, transcript_manifest=transcript_manifest,
        ),
        "security.evidence_parser_fuzzed": lambda spec: evaluate_evidence_parser_fuzzed(
            spec, transcript_manifest=transcript_manifest,
        ),
        "security.fault_timing_countermeasure": lambda spec: evaluate_fault_timing_countermeasure(
            spec, transcript_manifest=transcript_manifest
        ),
        "security.fault_campaign_boot_selftest": lambda spec: evaluate_fault_campaign_boot_selftest(
            spec, transcript_manifest=transcript_manifest
        ),
        "security.ct_trace_relational": lambda spec: evaluate_ct_trace_relational(
            spec, transcript_manifest=transcript_manifest
        ),
        "security.ct_trace_declassified": lambda spec: evaluate_ct_trace_declassified(
            spec, transcript_manifest=transcript_manifest
        ),
        "security.ct_trace_cortex_m_latency": lambda spec: evaluate_ct_trace_cortex_m_latency(
            spec, transcript_manifest=transcript_manifest
        ),
        "security.ct_trace_cortex_m_signing": lambda spec: evaluate_ct_trace_cortex_m_signing(
            spec, transcript_manifest=transcript_manifest
        ),
        "security.ct_trace_cortex_m_mitigation": lambda spec: evaluate_ct_trace_cortex_m_mitigation(
            spec, transcript_manifest=transcript_manifest
        ),
        "security.ct_trace_cortex_m_latency_models": lambda spec: evaluate_ct_trace_cortex_m_latency_models(
            spec, transcript_manifest=transcript_manifest
        ),
        "security.ct_trace_cortex_m_kem_mitigation": lambda spec: evaluate_ct_trace_cortex_m_kem_mitigation(
            spec, transcript_manifest=transcript_manifest
        ),
        "security.ct_trace_cortex_m33": lambda spec: evaluate_ct_trace_cortex_m33(
            spec, transcript_manifest=transcript_manifest
        ),
        "security.mldsa_rejection_independence": lambda spec: evaluate_mldsa_rejection_independence(
            spec, transcript_manifest=transcript_manifest
        ),
        "security.ct_instruction_count": lambda spec: evaluate_ct_instruction_count(
            spec, transcript_manifest=transcript_manifest,
        ),
        "security.ct_smoke": lambda spec: evaluate_ct_smoke(
            spec, transcript_manifest=transcript_manifest,
        ),
        "security.mlkem_decap_instruction_policy": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=ct_instruction_policy_result,
            label="ML-KEM decapsulation instruction policy result",
            required_keys=("schema_version", "passed", "target_symbol_count", "findings", "failures"),
            success_field="passed",
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
            expected_schema_version=None,
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
        "supply_chain.assurance_profile_policy": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=assurance_profile_result,
            label="PQC assurance profile result",
            required_keys=("schema_version", "passed", "summary", "checks"),
            success_field="passed",
        ),
        "supply_chain.evidence_quality_index": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=evidence_quality_result,
            label="PQC evidence quality result",
            required_keys=("schema_version", "passed", "summary", "checks"),
            success_field="passed",
        ),
        "crypto_agility.profile_separation": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=assurance_profile_result,
            label="PQC assurance profile result",
            required_keys=("schema_version", "passed", "summary", "checks"),
            success_field="passed",
        ),
        "release.migration_readiness": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=migration_readiness,
            label="PQC migration readiness report",
            required_keys=("schema_version", "passed", "summary", "assets"),
            success_field="passed",
        ),
        "security.production_rng_policy": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=assurance_profile_result,
            label="PQC assurance profile result",
            required_keys=("schema_version", "passed", "summary", "checks"),
            success_field="passed",
        ),
        "release.reference_values": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=reference_values,
            label="PQC reference values",
            required_keys=(
                "schema_version",
                "version",
                "tag",
                "head_sha",
                "artifact_hashes",
                "expected_firmware_digest_root",
            ),
        ),
        "firmware.assurance_status_report": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=firmware_status_result,
            label="firmware assurance status verification result",
            required_keys=("schema_version", "passed", "status", "checks"),
            success_field="passed",
        ),
        "acvp.json_interop": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=acvp_json_interop_result,
            label="ACVP JSON interop result",
            required_keys=("schema_version", "passed", "summary", "results"),
            success_field="passed",
        ),
        "supply_chain.slsa_build_provenance": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=build_provenance_result,
            label="PQC build provenance verification result",
            required_keys=("schema_version", "passed", "checks"),
            success_field="passed",
        ),
        "security.ct_sample_analysis": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=ct_sample_analysis_result,
            label="CT sample analysis result",
            required_keys=("schema_version", "passed", "algorithms", "checks"),
            success_field="passed",
        ),
        "release.evidence_appraisal_profile": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=appraisal_result,
            label="PQC appraisal verification result",
            required_keys=("schema_version", "passed", "checks"),
            success_field="passed",
        ),
        "supply_chain.backend_update_evaluation": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=backend_update_evaluation,
            label="backend update evaluation",
            required_keys=("schema_version", "passed", "backends", "checks", "failures"),
            success_field="passed",
        ),
        "supply_chain.backend_contract": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=backend_contract_result,
            label="backend contract result",
            required_keys=("schema_version", "passed", "contract", "native_backend_shas", "checks"),
            success_field="passed",
        ),
        "supply_chain.liboqs_non_native_scope": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=liboqs_inventory,
            label="external-provider non-native inventory",
            required_keys=("schema_version", "passed", "provider_family", "schemes"),
            success_field="passed",
        ),
        "benchmark.campaign_reproducibility": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=benchmark_campaign_result,
            label="benchmark campaign result",
            required_keys=("schema_version", "passed", "statistics", "comparison_context"),
            success_field="passed",
        ),
        "benchmark.paper_comparison_export": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=paper_comparison_result,
            label="paper-comparison campaign result",
            required_keys=("schema_version", "passed", "summary", "comparison_context"),
            success_field="passed",
        ),
        "benchmark.external_reference_context": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=benchmark_campaign_result,
            label="benchmark campaign result",
            required_keys=("schema_version", "passed", "external_reference", "comparison_context"),
            success_field="passed",
        ),
        "security.ct_campaign_analysis": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=ct_campaign_result,
            label="CT campaign result",
            required_keys=("schema_version", "passed", "algorithms", "checks"),
            success_field="passed",
        ),
        "acvp.json_schema_coverage": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=acvp_json_schema_result,
            label="ACVP JSON schema coverage result",
            required_keys=("schema_version", "passed", "summary", "checks"),
            success_field="passed",
        ),
        "firmware.device_evidence_token": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=device_evidence_result,
            label="device evidence token result",
            required_keys=("schema_version", "passed", "checks"),
            success_field="passed",
        ),
        "release.strict_partner_policy": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=appraisal_result,
            label="PQC appraisal verification result",
            required_keys=("schema_version", "passed", "mode", "checks"),
            success_field="passed",
        ),
        "release.reference_provider_scope": lambda spec: evaluate_json_artifact_claim(
            spec,
            path=release_reference_values_result or provider_scope_result,
            label="release reference/provider-scope replay result",
            required_keys=("schema_version", "passed", "checks"),
            success_field="passed",
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
    ledger_schema_version = ledger_schema_for_claims(claims_path)
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
        "schema_version": ledger_schema_version,
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
