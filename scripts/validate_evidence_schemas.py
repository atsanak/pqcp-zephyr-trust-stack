#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate release evidence packs against the repository schema contract.

The existing replay verifier checks many semantic relationships after a full
release pack is generated. This script adds the product-facing contract layer:
which artifacts exist, which schema file applies to each artifact, which pack
profiles require it, and which cross-artifact invariants must hold before a
partner dashboard or external review tool can trust the pack shape.

The implementation intentionally uses only Python's standard library. It
supports the JSON-Schema subset used by this repository's checked-in schemas
and layers repository-specific cross checks on top.
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_CATALOG = REPO_ROOT / "schemas/evidence/evidence_schema_catalog.json"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TAG_RE = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z._-]+)?$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z._-]+)?$")
CLAIM_ID_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")
ARTIFACT_ID_RE = re.compile(r"^[a-z][a-z0-9_]*(?:[.-][a-z0-9_]+)*$")


@dataclass(frozen=True)
class ValidationIssue:
    severity: str
    location: str
    message: str


class SchemaContractError(RuntimeError):
    """Raised for unrecoverable catalog/configuration errors."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate PQCP release evidence artifacts against checked-in schemas."
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("benchmark_results/release_check"),
        help="Release evidence output root to validate.",
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        default=DEFAULT_CATALOG,
        help="Evidence schema catalog JSON.",
    )
    parser.add_argument(
        "--module-path",
        type=Path,
        default=REPO_ROOT,
        help="Repository root used for schema and relative path resolution.",
    )
    parser.add_argument(
        "--tag",
        default=None,
        help="Expected release tag. Used for resolving release-manifest paths and tag checks.",
    )
    parser.add_argument(
        "--profile",
        default="partner_review",
        help=(
            "Evidence contract profile to enforce. Contracts whose required_for "
            "contains this profile are required."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=("strict", "available", "catalog-only"),
        default="strict",
        help=(
            "strict requires the selected profile artifacts; available validates "
            "only files present under output-root; catalog-only validates catalog "
            "and schema files without reading an output root."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON result path.",
    )
    parser.add_argument(
        "--list-contracts",
        action="store_true",
        help="Print contract IDs and paths without validating an output root.",
    )
    return parser.parse_args()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SchemaContractError(f"missing JSON file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SchemaContractError(f"invalid JSON in {path}: {exc}") from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_tag(tag: str | None, output_root: Path) -> str:
    if tag:
        return tag
    bundle_root = output_root / "local_release_bundle"
    candidates = sorted(bundle_root.glob("*/release-manifest-*.json"))
    if len(candidates) == 1:
        return candidates[0].parent.name
    return "v0.0.0"


def render_artifact_path(template: str, *, tag: str) -> Path:
    return Path(template.replace("{tag}", tag))


def issue(severity: str, location: str, message: str) -> ValidationIssue:
    return ValidationIssue(severity=severity, location=location, message=message)


def type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return (isinstance(value, int) or isinstance(value, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return False


def validate_format(value: Any, fmt: str, location: str) -> list[ValidationIssue]:
    if not isinstance(value, str):
        return [issue("error", location, f"format {fmt!r} requires a string")]
    if fmt == "sha256" and not SHA256_RE.match(value):
        return [issue("error", location, "expected lowercase SHA-256 hex digest")]
    if fmt == "tag" and not TAG_RE.match(value):
        return [issue("error", location, "expected semantic release tag")]
    if fmt == "version" and not VERSION_RE.match(value):
        return [issue("error", location, "expected semantic version string")]
    if fmt == "claim-id" and not CLAIM_ID_RE.match(value):
        return [issue("error", location, "expected dotted assurance claim id")]
    if fmt == "artifact-id" and not ARTIFACT_ID_RE.match(value):
        return [issue("error", location, "expected artifact identifier")]
    if fmt == "relative-path":
        if value.startswith("/") or ".." in Path(value).parts:
            return [issue("error", location, "expected safe relative path")]
    if fmt == "date-time":
        try:
            _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return [issue("error", location, "expected ISO-8601 date-time")]
    if fmt == "uri":
        if "://" not in value:
            return [issue("error", location, "expected URI-like string")]
    return []


def validate_schema(value: Any, schema: dict[str, Any], location: str = "$") -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []

    if "const" in schema and value != schema["const"]:
        issues.append(issue("error", location, f"expected constant {schema['const']!r}"))
        return issues

    if "enum" in schema and value not in schema["enum"]:
        issues.append(issue("error", location, f"expected one of {schema['enum']!r}"))

    expected_type = schema.get("type")
    if isinstance(expected_type, list):
        if not any(type_matches(value, item) for item in expected_type):
            issues.append(issue("error", location, f"expected type one of {expected_type!r}"))
            return issues
    elif isinstance(expected_type, str):
        if not type_matches(value, expected_type):
            issues.append(issue("error", location, f"expected type {expected_type!r}"))
            return issues

    if "format" in schema:
        issues.extend(validate_format(value, schema["format"], location))

    if isinstance(value, str):
        min_length = schema.get("minLength")
        max_length = schema.get("maxLength")
        if isinstance(min_length, int) and len(value) < min_length:
            issues.append(issue("error", location, f"string length {len(value)} < {min_length}"))
        if isinstance(max_length, int) and len(value) > max_length:
            issues.append(issue("error", location, f"string length {len(value)} > {max_length}"))
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and not re.search(pattern, value):
            issues.append(issue("error", location, f"string does not match pattern {pattern!r}"))

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, float)) and value < minimum:
            issues.append(issue("error", location, f"value {value!r} < minimum {minimum!r}"))
        if isinstance(maximum, (int, float)) and value > maximum:
            issues.append(issue("error", location, f"value {value!r} > maximum {maximum!r}"))

    if isinstance(value, list):
        min_items = schema.get("minItems")
        max_items = schema.get("maxItems")
        if isinstance(min_items, int) and len(value) < min_items:
            issues.append(issue("error", location, f"array length {len(value)} < {min_items}"))
        if isinstance(max_items, int) and len(value) > max_items:
            issues.append(issue("error", location, f"array length {len(value)} > {max_items}"))
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                issues.extend(validate_schema(item, item_schema, f"{location}[{index}]"))
        unique_items = schema.get("uniqueItems")
        if unique_items is True:
            encoded = [json.dumps(item, sort_keys=True) for item in value]
            if len(encoded) != len(set(encoded)):
                issues.append(issue("error", location, "array items must be unique"))

    if isinstance(value, dict):
        required = schema.get("required", [])
        if isinstance(required, list):
            for key in required:
                if key not in value:
                    issues.append(issue("error", f"{location}.{key}", "missing required property"))

        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for key, child_schema in properties.items():
                if key in value and isinstance(child_schema, dict):
                    issues.extend(validate_schema(value[key], child_schema, f"{location}.{key}"))

        pattern_properties = schema.get("patternProperties", {})
        matched_keys: set[str] = set()
        if isinstance(pattern_properties, dict):
            for pattern, child_schema in pattern_properties.items():
                try:
                    regex = re.compile(pattern)
                except re.error as exc:
                    issues.append(issue("error", location, f"invalid patternProperties regex {pattern!r}: {exc}"))
                    continue
                for key, child_value in value.items():
                    if regex.search(key):
                        matched_keys.add(key)
                        if isinstance(child_schema, dict):
                            issues.extend(validate_schema(child_value, child_schema, f"{location}.{key}"))

        additional = schema.get("additionalProperties", True)
        if additional is False and isinstance(properties, dict):
            allowed = set(properties) | matched_keys
            extra = sorted(set(value) - allowed)
            for key in extra:
                issues.append(issue("error", f"{location}.{key}", "unexpected additional property"))
        elif isinstance(additional, dict):
            known = set(properties) | matched_keys if isinstance(properties, dict) else matched_keys
            for key, child_value in value.items():
                if key not in known:
                    issues.extend(validate_schema(child_value, additional, f"{location}.{key}"))

    return issues


def validate_catalog(catalog: dict[str, Any], catalog_path: Path, module_path: Path) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if catalog.get("schema_version") != 1:
        issues.append(issue("error", "catalog.schema_version", "expected schema_version 1"))
    contracts = catalog.get("contracts")
    if not isinstance(contracts, list) or not contracts:
        issues.append(issue("error", "catalog.contracts", "catalog must contain non-empty contracts"))
        return issues

    ids: set[str] = set()
    catalog_dir = catalog_path.parent
    for index, contract in enumerate(contracts):
        loc = f"catalog.contracts[{index}]"
        if not isinstance(contract, dict):
            issues.append(issue("error", loc, "contract must be an object"))
            continue
        contract_id = contract.get("id")
        if not isinstance(contract_id, str) or not ARTIFACT_ID_RE.match(contract_id):
            issues.append(issue("error", f"{loc}.id", "invalid contract id"))
        elif contract_id in ids:
            issues.append(issue("error", f"{loc}.id", f"duplicate contract id {contract_id!r}"))
        else:
            ids.add(contract_id)
        for key in ("path", "schema", "artifact_type", "description"):
            if not isinstance(contract.get(key), str) or not contract[key]:
                issues.append(issue("error", f"{loc}.{key}", "required non-empty string"))
        required_for = contract.get("required_for")
        if not isinstance(required_for, list) or not all(isinstance(item, str) for item in required_for):
            issues.append(issue("error", f"{loc}.required_for", "required_for must be a string list"))
        schema_ref = contract.get("schema")
        if isinstance(schema_ref, str):
            schema_path = (catalog_dir / schema_ref).resolve()
            try:
                loaded = load_json(schema_path)
            except SchemaContractError as exc:
                issues.append(issue("error", f"{loc}.schema", str(exc)))
                continue
            if not isinstance(loaded, dict):
                issues.append(issue("error", f"{loc}.schema", "schema root must be an object"))
            if loaded.get("$schema") is None:
                issues.append(issue("warning", f"{loc}.schema", "schema has no $schema field"))
            if loaded.get("title") is None:
                issues.append(issue("warning", f"{loc}.schema", "schema has no title field"))

    profiles = catalog.get("profiles", {})
    if profiles and not isinstance(profiles, dict):
        issues.append(issue("error", "catalog.profiles", "profiles must be an object"))
    if isinstance(profiles, dict):
        for profile, meta in profiles.items():
            if not isinstance(meta, dict):
                issues.append(issue("error", f"catalog.profiles.{profile}", "profile metadata must be an object"))
            elif not isinstance(meta.get("description"), str):
                issues.append(issue("warning", f"catalog.profiles.{profile}.description", "missing profile description"))

    if not module_path.exists():
        issues.append(issue("error", "module_path", f"module path does not exist: {module_path}"))
    return issues


def validate_csv_artifact(path: Path, contract: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    required_columns = contract.get("required_columns", [])
    min_rows = contract.get("min_rows", 1)
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
    except OSError as exc:
        return [issue("error", str(path), f"unable to read CSV: {exc}")]
    if not rows:
        issues.append(issue("error", str(path), "CSV has no data rows"))
        return issues
    if isinstance(min_rows, int) and len(rows) < min_rows:
        issues.append(issue("error", str(path), f"CSV row count {len(rows)} < {min_rows}"))
    columns = set(rows[0].keys())
    for column in required_columns:
        if column not in columns:
            issues.append(issue("error", f"{path}:{column}", "missing required CSV column"))
    return issues


def load_contract_schema(contract: dict[str, Any], catalog_path: Path) -> dict[str, Any]:
    schema_ref = contract["schema"]
    schema_path = (catalog_path.parent / schema_ref).resolve()
    schema = load_json(schema_path)
    if not isinstance(schema, dict):
        raise SchemaContractError(f"schema root must be object: {schema_path}")
    return schema


def validate_artifact(
    *,
    output_root: Path,
    tag: str,
    contract: dict[str, Any],
    catalog_path: Path,
) -> tuple[dict[str, Any] | None, list[ValidationIssue]]:
    rel_path = render_artifact_path(contract["path"], tag=tag)
    path = output_root / rel_path
    issues: list[ValidationIssue] = []
    if not path.exists():
        return None, [issue("error", str(rel_path), "required artifact is missing")]
    if not path.is_file():
        return None, [issue("error", str(rel_path), "artifact path is not a file")]
    if path.stat().st_size == 0:
        return None, [issue("error", str(rel_path), "artifact is empty")]

    artifact_type = contract.get("artifact_type")
    if artifact_type == "json":
        raw = load_json(path)
        schema = load_contract_schema(contract, catalog_path)
        issues.extend(validate_schema(raw, schema, "$"))
        return raw if isinstance(raw, dict) else {"_root": raw}, issues
    if artifact_type == "csv":
        issues.extend(validate_csv_artifact(path, contract))
        return {"path": str(rel_path), "sha256": sha256_file(path)}, issues
    if artifact_type in {"markdown", "html", "log", "header"}:
        return {"path": str(rel_path), "sha256": sha256_file(path), "size_bytes": path.stat().st_size}, issues
    issues.append(issue("error", str(rel_path), f"unsupported artifact_type {artifact_type!r}"))
    return None, issues


def select_contracts(catalog: dict[str, Any], *, profile: str, mode: str, output_root: Path, tag: str) -> list[dict[str, Any]]:
    contracts = catalog.get("contracts", [])
    selected: list[dict[str, Any]] = []
    for contract in contracts:
        if not isinstance(contract, dict):
            continue
        if mode == "available":
            rel_path = render_artifact_path(str(contract.get("path", "")), tag=tag)
            if (output_root / rel_path).exists():
                selected.append(contract)
        elif mode == "strict":
            if profile in contract.get("required_for", []):
                selected.append(contract)
        elif mode == "catalog-only":
            continue
    return selected


def get_path(root: dict[str, Any], dotted: str) -> Any:
    current: Any = root
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def check_transcript_hashes(
    *,
    output_root: Path,
    manifest: dict[str, Any],
    contract_id: str,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    base = output_root / "transcripts"
    entries = []
    for key in ("entries", "transcripts", "qemu_stdout_transcripts"):
        value = manifest.get(key)
        if isinstance(value, list):
            entries.extend(item for item in value if isinstance(item, dict))
    for index, entry in enumerate(entries):
        rel = entry.get("transcript_path") or entry.get("path")
        expected = entry.get("sha256")
        if not isinstance(rel, str) or not isinstance(expected, str):
            continue
        path = base / rel
        if not path.exists():
            alt = output_root / rel
            path = alt if alt.exists() else path
        if not path.exists():
            issues.append(issue("error", f"{contract_id}.entries[{index}]", f"transcript not found: {rel}"))
            continue
        actual = sha256_file(path)
        if actual != expected:
            issues.append(issue("error", f"{contract_id}.entries[{index}]", f"transcript hash drift for {rel}"))
    return issues


def cross_check_artifacts(
    *,
    output_root: Path,
    tag: str,
    artifacts: dict[str, dict[str, Any]],
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []

    ledger = artifacts.get("assurance_ledger")
    manifest = artifacts.get("release_manifest")
    policy = artifacts.get("pqc_policy_result")
    cbom = artifacts.get("pqc_cbom")
    attestation = artifacts.get("pqc_attestation")
    reference = artifacts.get("pqc_reference_values")
    transcript_manifest = artifacts.get("evidence_transcript_manifest")

    if ledger and tag and ledger.get("tag") not in (None, tag):
        issues.append(issue("error", "assurance_ledger.tag", f"ledger tag {ledger.get('tag')!r} != expected {tag!r}"))

    if ledger and manifest:
        comparisons = (
            ("version", ledger.get("version"), manifest.get("version")),
            ("tag", ledger.get("tag"), manifest.get("tag")),
            ("head/source", ledger.get("head_sha"), manifest.get("source_commit")),
            ("dirty", ledger.get("dirty"), manifest.get("working_tree_dirty")),
        )
        for label, left, right in comparisons:
            if left is not None and right is not None and left != right:
                issues.append(issue("error", f"ledger_vs_manifest.{label}", f"{left!r} != {right!r}"))

    if policy and ledger:
        if policy.get("passed") is not True and policy.get("status") not in ("pass", "passed"):
            issues.append(issue("error", "pqc_policy_result", "policy result is not passing"))
        required_claims = policy.get("required_claims") or policy.get("checked_claims") or []
        if isinstance(required_claims, list):
            ledger_claims = ledger.get("claims", [])
            claim_ids = {item.get("id") for item in ledger_claims if isinstance(item, dict)}
            missing = sorted(str(item) for item in required_claims if isinstance(item, str) and item not in claim_ids)
            for claim_id in missing:
                issues.append(issue("error", f"pqc_policy_result.required_claims.{claim_id}", "claim missing from ledger"))

    if cbom and ledger:
        components = cbom.get("components", [])
        if isinstance(components, list):
            component_ids = {
                item.get("bom-ref") or item.get("name")
                for item in components
                if isinstance(item, dict)
            }
            if not component_ids:
                issues.append(issue("error", "pqc_cbom.components", "CBOM has no component identifiers"))

    if attestation:
        subjects = attestation.get("subject", [])
        if not isinstance(subjects, list) or not subjects:
            issues.append(issue("error", "pqc_attestation.subject", "attestation has no subjects"))
        else:
            for index, subject in enumerate(subjects):
                if not isinstance(subject, dict):
                    issues.append(issue("error", f"pqc_attestation.subject[{index}]", "subject must be object"))
                    continue
                digest = subject.get("digest")
                if isinstance(digest, dict):
                    sha = digest.get("sha256")
                    if isinstance(sha, str) and not SHA256_RE.match(sha):
                        issues.append(issue("error", f"pqc_attestation.subject[{index}].digest.sha256", "bad digest"))

    if reference and ledger:
        ref_version = reference.get("version")
        if ref_version is not None and ledger.get("version") is not None and ref_version != ledger.get("version"):
            issues.append(issue("error", "pqc_reference_values.version", "reference version disagrees with ledger"))
        ref_tag = reference.get("tag")
        if ref_tag is not None and ledger.get("tag") is not None and ref_tag != ledger.get("tag"):
            issues.append(issue("error", "pqc_reference_values.tag", "reference tag disagrees with ledger"))

    if transcript_manifest:
        issues.extend(
            check_transcript_hashes(
                output_root=output_root,
                manifest=transcript_manifest,
                contract_id="evidence_transcript_manifest",
            )
        )

    return issues


def result_document(
    *,
    args: argparse.Namespace,
    catalog: dict[str, Any],
    selected: list[dict[str, Any]],
    artifacts: dict[str, dict[str, Any]],
    issues: list[ValidationIssue],
) -> dict[str, Any]:
    errors = [item for item in issues if item.severity == "error"]
    warnings = [item for item in issues if item.severity == "warning"]
    return {
        "schema_version": 1,
        "status": "pass" if not errors else "fail",
        "passed": not errors,
        "profile": args.profile,
        "mode": args.mode,
        "output_root": str(args.output_root.resolve()),
        "catalog": str(args.catalog.resolve()),
        "contract_count": len(catalog.get("contracts", [])) if isinstance(catalog.get("contracts"), list) else 0,
        "selected_contract_count": len(selected),
        "validated_artifacts": sorted(artifacts),
        "error_count": len(errors),
        "warning_count": len(warnings),
        "issues": [
            {"severity": item.severity, "location": item.location, "message": item.message}
            for item in issues
        ],
    }


def main() -> int:
    args = parse_args()
    module_path = args.module_path.resolve()
    catalog_path = args.catalog if args.catalog.is_absolute() else module_path / args.catalog
    output_root = args.output_root.resolve()

    catalog_raw = load_json(catalog_path)
    if not isinstance(catalog_raw, dict):
        raise SchemaContractError("catalog root must be a JSON object")

    issues = validate_catalog(catalog_raw, catalog_path, module_path)
    tag = normalize_tag(args.tag, output_root)

    contracts = [item for item in catalog_raw.get("contracts", []) if isinstance(item, dict)]
    if args.list_contracts:
        for contract in contracts:
            print(f"{contract.get('id')}\t{contract.get('path')}\t{','.join(contract.get('required_for', []))}")
        return 0 if not any(item.severity == "error" for item in issues) else 1

    selected = select_contracts(catalog_raw, profile=args.profile, mode=args.mode, output_root=output_root, tag=tag)
    artifacts: dict[str, dict[str, Any]] = {}

    if args.mode != "catalog-only":
        for contract in selected:
            contract_id = str(contract.get("id"))
            artifact, artifact_issues = validate_artifact(
                output_root=output_root,
                tag=tag,
                contract=contract,
                catalog_path=catalog_path,
            )
            issues.extend(artifact_issues)
            if artifact is not None:
                artifacts[contract_id] = artifact
        issues.extend(cross_check_artifacts(output_root=output_root, tag=tag, artifacts=artifacts))

    result = result_document(
        args=args,
        catalog=catalog_raw,
        selected=selected,
        artifacts=artifacts,
        issues=issues,
    )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for item in issues:
        prefix = "ERROR" if item.severity == "error" else "WARN"
        print(f"{prefix}: {item.location}: {item.message}")
    if result["passed"]:
        print(
            "PASS: evidence schema contract validation passed "
            f"({result['selected_contract_count']} artifact contract(s), profile={args.profile}, mode={args.mode})"
        )
        return 0
    print(
        "FAIL: evidence schema contract validation failed "
        f"({result['error_count']} error(s), {result['warning_count']} warning(s))"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
