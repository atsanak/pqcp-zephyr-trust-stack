#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Replay-check ACVP JSON interop response and transcript-manifest artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from run_acvp_json_vectors import transcript_hash

VALID_CLASSES = {"success", "negative", "unsupported_parameter_set"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--transcript-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


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


def stable_case_key(row: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    return (
        str(row.get("source")),
        str(row.get("mode")),
        str(row.get("tgId")),
        str(row.get("tcId")),
        str(row.get("command")),
        str(row.get("response")),
    )


def verify(args: argparse.Namespace) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    result = load_json(args.result, "ACVP JSON interop result", failures)
    manifest = load_json(args.transcript_manifest, "ACVP JSON transcript manifest", failures)
    if not result or not manifest:
        return {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "passed": False,
            "checks": checks,
            "failures": failures,
        }

    if result.get("schema_version") != 1:
        failures.append(f"unsupported ACVP JSON result schema_version={result.get('schema_version')!r}")
    if manifest.get("schema_version") != 1:
        failures.append(f"unsupported ACVP JSON transcript schema_version={manifest.get('schema_version')!r}")
    if result.get("passed") is not True:
        failures.append("ACVP JSON interop result did not pass")

    rows = result.get("results")
    transcripts = manifest.get("transcripts")
    if not isinstance(rows, list) or not rows:
        failures.append("ACVP JSON interop result must contain non-empty results")
        rows = []
    if not isinstance(transcripts, list) or not transcripts:
        failures.append("ACVP JSON transcript manifest must contain non-empty transcripts")
        transcripts = []

    result_keys: set[tuple[str, str, str, str, str, str]] = set()
    manifest_by_key: dict[tuple[str, str, str, str, str, str], dict[str, Any]] = {}
    for index, row in enumerate(transcripts, start=1):
        if not isinstance(row, dict):
            failures.append(f"ACVP JSON transcript row {index} must be an object")
            continue
        key = stable_case_key(row)
        if key in manifest_by_key:
            failures.append(f"ACVP JSON transcript row {index} duplicates an earlier test case")
        manifest_by_key[key] = row
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            failures.append(f"ACVP JSON result row {index} must be an object")
            continue
        key = stable_case_key(row)
        if key in result_keys:
            failures.append(f"ACVP JSON result row {index} duplicates an earlier test case")
        result_keys.add(key)
        command = row.get("command")
        response = row.get("response")
        if not isinstance(command, str) or not command:
            failures.append(f"ACVP JSON result row {index} missing command")
            continue
        if not isinstance(response, str) or not response:
            failures.append(f"ACVP JSON result row {index} missing response")
            continue
        expected_hash = transcript_hash(command, response)
        observed_hash = row.get("transcript_sha256")
        ok = observed_hash == expected_hash
        checks.append({"check": "result_transcript_hash", "index": index, "passed": ok})
        if not ok:
            failures.append(f"ACVP JSON result row {index} transcript hash mismatch")

        result_class = row.get("expected_result_class")
        if result_class not in VALID_CLASSES:
            failures.append(f"ACVP JSON result row {index} has invalid result class {result_class!r}")
        elif result_class == "success" and response != "RESULT:OK":
            failures.append(f"ACVP JSON result row {index} success class did not return RESULT:OK")
        elif result_class != "success" and not (
            response.startswith("ERROR:") or response.startswith("RESULT:INVALID")
        ):
            failures.append(f"ACVP JSON result row {index} negative class has non-error response")

        manifest_row = manifest_by_key.get(key)
        ok = isinstance(manifest_row, dict)
        checks.append({"check": "manifest_row_present", "index": index, "passed": ok})
        if not ok:
            failures.append(f"ACVP JSON result row {index} missing from transcript manifest")
        elif manifest_row.get("sha256") != expected_hash:
            failures.append(f"ACVP JSON transcript row {index} hash mismatch")

    extra_manifest = sorted(
        f"{key[0]}:{key[1]}:{key[2]}:{key[3]}"
        for key in set(manifest_by_key) - result_keys
    )
    checks.append({"check": "no_extra_manifest_rows", "extras": extra_manifest, "passed": not extra_manifest})
    if extra_manifest:
        failures.append("ACVP JSON transcript manifest has unreferenced row(s): " + ", ".join(extra_manifest))

    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
    expected_negative = sum(
        1 for row in rows
        if isinstance(row, dict) and row.get("expected_result_class") != "success"
    )
    for key, expected in (("test_cases", len(rows)), ("negative_cases", expected_negative)):
        ok = summary.get(key) == expected
        checks.append({"check": "summary", "field": key, "expected": expected, "observed": summary.get(key), "passed": ok})
        if not ok:
            failures.append(f"ACVP JSON summary {key} mismatch")

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
        print("PASS: ACVP JSON interop artifacts verified")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("FAIL: ACVP JSON interop verification failed", file=sys.stderr)
    for failure in result["failures"]:
        print(f"  - {failure}", file=sys.stderr)
    print(f"  output: {args.output.resolve()}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
