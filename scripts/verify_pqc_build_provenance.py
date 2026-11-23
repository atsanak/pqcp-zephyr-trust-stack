#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify the SLSA-shaped PQC build provenance artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
ALLOWED_EXTERNAL_PARAMETERS = {"tag", "version", "source_commit"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--subject", type=Path, action="append", default=[])
    parser.add_argument("--byproduct", type=Path, action="append", default=[])
    parser.add_argument("--release-manifest", type=Path, required=True)
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
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        failures.append(f"{label} is not valid JSON: {exc}")
        return {}
    if not isinstance(payload, dict):
        failures.append(f"{label} root must be a JSON object")
        return {}
    return payload


def subject_map(statement: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for subject in statement.get("subject") or []:
        if not isinstance(subject, dict):
            continue
        digest = subject.get("digest")
        name = subject.get("name")
        if isinstance(name, str) and isinstance(digest, dict) and isinstance(digest.get("sha256"), str):
            result[Path(name).name] = digest["sha256"]
    return result


def digest_map(entries: object) -> dict[str, str]:
    result: dict[str, str] = {}
    if not isinstance(entries, list):
        return result
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        digest = entry.get("digest")
        name = entry.get("name")
        if isinstance(name, str) and isinstance(digest, dict) and isinstance(digest.get("sha256"), str):
            result[Path(name).name] = digest["sha256"]
    return result


def verify(args: argparse.Namespace) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    statement = load_json(args.provenance, "PQC build provenance", failures)
    manifest = load_json(args.release_manifest, "release manifest", failures)
    if not statement or not manifest:
        return {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "passed": False,
            "checks": checks,
            "failures": failures,
        }
    if statement.get("_type") != STATEMENT_TYPE:
        failures.append(f"wrong statement _type: {statement.get('_type')!r}")
    if statement.get("predicateType") != PREDICATE_TYPE:
        failures.append(f"wrong predicateType: {statement.get('predicateType')!r}")
    predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
    build_definition = predicate.get("buildDefinition") if isinstance(predicate.get("buildDefinition"), dict) else {}
    run_details = predicate.get("runDetails") if isinstance(predicate.get("runDetails"), dict) else {}
    external = build_definition.get("externalParameters") if isinstance(build_definition.get("externalParameters"), dict) else {}
    unexpected = sorted(set(external) - ALLOWED_EXTERNAL_PARAMETERS)
    checks.append({"check": "external_parameters", "unexpected": unexpected, "passed": not unexpected})
    if unexpected:
        failures.append("unexpected external parameter(s): " + ", ".join(unexpected))
    for key, expected in (
        ("tag", manifest.get("tag")),
        ("version", manifest.get("version")),
        ("source_commit", manifest.get("source_commit")),
    ):
        ok = external.get(key) == expected
        checks.append({"check": "external_parameter_value", "key": key, "passed": ok})
        if not ok:
            failures.append(f"external parameter {key} mismatch")
    dependencies = build_definition.get("resolvedDependencies")
    if not isinstance(dependencies, list) or not dependencies:
        failures.append("resolvedDependencies is missing or empty")
    else:
        names = {str(item.get("name") or item.get("uri")) for item in dependencies if isinstance(item, dict)}
        required_dependencies = [
            "west.yml",
            "CMakeLists.txt",
            "assurance_claims.json",
            "pqc_assurance_policy.json",
        ]
        if isinstance(manifest.get("dependencies"), dict):
            required_dependencies.extend(str(name) for name in manifest["dependencies"])
        for required in required_dependencies:
            ok = any(required in name for name in names)
            checks.append({"check": "resolved_dependency", "name": required, "passed": ok})
            if not ok:
                failures.append(f"resolved dependency missing: {required}")
    byproducts = run_details.get("byproducts")
    if not isinstance(byproducts, list):
        failures.append("runDetails.byproducts must be a list")
        byproduct_hashes: dict[str, str] = {}
    else:
        byproduct_hashes = digest_map(byproducts)
    subjects = subject_map(statement)
    for path in args.subject:
        expected = sha256_file(path)
        observed = subjects.get(path.name)
        ok = observed == expected
        checks.append({"check": "subject_hash", "name": path.name, "passed": ok})
        if not ok:
            failures.append(f"subject hash mismatch or missing: {path.name}")
    for path in args.byproduct:
        expected = sha256_file(path)
        observed = byproduct_hashes.get(path.name)
        ok = observed == expected
        checks.append({"check": "byproduct_hash", "name": path.name, "passed": ok})
        if not ok:
            failures.append(f"byproduct hash mismatch or missing: {path.name}")
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": not failures,
        "checks": checks,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    result = verify(args)
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: PQC build provenance verified")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("FAIL: PQC build provenance verification failed", file=sys.stderr)
    for failure in result["failures"]:
        print(f"  - {failure}", file=sys.stderr)
    print(f"  output: {args.output.resolve()}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
