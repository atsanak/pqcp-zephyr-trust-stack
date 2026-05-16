#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Validate ACVP JSON interop evidence shape and operation coverage."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_OPERATIONS = ("keyGen", "encap", "decap", "sigGen", "sigVer")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--transcript-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"{path} root must be a JSON object")
    return raw


def expected_hash(command: str, response: str) -> str:
    return hashlib.sha256(f"{command}\n{response}\n".encode("utf-8")).hexdigest()


def validate(args: argparse.Namespace) -> dict[str, Any]:
    result = load_json(args.result)
    manifest = load_json(args.transcript_manifest)
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    if result.get("schema_version") != 1:
        failures.append(f"unsupported ACVP JSON result schema_version={result.get('schema_version')!r}")
    if manifest.get("schema_version") != 1:
        failures.append(f"unsupported ACVP JSON transcript schema_version={manifest.get('schema_version')!r}")
    rows = result.get("results") if isinstance(result.get("results"), list) else []
    transcripts = manifest.get("transcripts") if isinstance(manifest.get("transcripts"), list) else []
    transcript_index = {
        (row.get("source"), row.get("tgId"), row.get("tcId"), row.get("operation_class")): row
        for row in transcripts
        if isinstance(row, dict)
    }
    operations = {row.get("operation_class") for row in rows if isinstance(row, dict)}
    for operation in REQUIRED_OPERATIONS:
        ok = operation in operations
        checks.append({"check": "operation_coverage", "operation": operation, "passed": ok})
        if not ok:
            failures.append(f"ACVP JSON interop missing operation class {operation}")
    saw_negative_then_valid = False
    previous_negative = False
    for row in rows:
        if not isinstance(row, dict):
            failures.append("ACVP JSON result row must be an object")
            continue
        for key in ("source", "mode", "operation_class", "tgId", "tcId", "command", "response", "expected_result_class", "transcript_sha256"):
            if key not in row:
                failures.append(f"ACVP JSON result row missing {key}")
        digest = expected_hash(str(row.get("command", "")), str(row.get("response", "")))
        if row.get("transcript_sha256") != digest:
            failures.append(f"ACVP JSON row tcId={row.get('tcId')} transcript hash mismatch")
        key = (row.get("source"), row.get("tgId"), row.get("tcId"), row.get("operation_class"))
        transcript = transcript_index.get(key)
        if not transcript:
            failures.append(f"ACVP JSON transcript missing for tcId={row.get('tcId')} operation={row.get('operation_class')}")
        elif transcript.get("sha256") != row.get("transcript_sha256"):
            failures.append(f"ACVP JSON transcript manifest hash mismatch for tcId={row.get('tcId')}")
        if row.get("expected_result_class") != "success":
            previous_negative = True
        elif previous_negative:
            saw_negative_then_valid = True
    checks.append({"check": "malformed_then_valid_recovery", "passed": saw_negative_then_valid})
    if not saw_negative_then_valid:
        failures.append("ACVP JSON interop lacks malformed-then-valid recovery coverage")
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": not failures,
        "summary": {
            "test_cases": len(rows),
            "operation_classes": sorted(str(item) for item in operations if item),
            "failures": len(failures),
        },
        "checks": checks,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    result = validate(args)
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: ACVP JSON schema coverage verified")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("FAIL: ACVP JSON schema coverage failed")
    for failure in result["failures"]:
        print(f"  - {failure}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
