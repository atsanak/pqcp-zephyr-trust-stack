#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Verify firmware-reported assurance status lines against reference values."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HEX64 = r"[0-9a-f]{64}"
STATUS_RE = re.compile(
    rf"^PQCP_ASSURANCE_STATUS\s+version=(?P<version>\S+)\s+"
    rf"digest=(?P<digest>{HEX64})\s+artifact_count=(?P<count>\d+)\s+schema=(?P<schema>\d+)$"
)
ARTIFACT_RE = re.compile(
    rf"^PQCP_ASSURANCE_ARTIFACT\s+name=(?P<name>\S+)\s+sha256=(?P<sha>{HEX64})$"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-values", type=Path, required=True)
    parser.add_argument("--transcript", type=Path)
    parser.add_argument(
        "--transcript-dir",
        type=Path,
        help="Directory of release_check.py transcript logs to scan for the firmware status marker.",
    )
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


def read_transcript(args: argparse.Namespace, failures: list[str]) -> tuple[str, str]:
    candidates: list[Path] = []
    if args.transcript:
        candidates.append(args.transcript)
    if args.transcript_dir:
        candidates.extend(sorted(args.transcript_dir.glob("*.log")))
    for candidate in candidates:
        if not candidate.exists() or not candidate.is_file():
            continue
        body = candidate.read_text(encoding="utf-8", errors="replace")
        if "PQCP_ASSURANCE_STATUS" in body:
            return body, str(candidate)
    failures.append("firmware assurance status transcript marker not found")
    return "", ""


def parse_status(body: str, failures: list[str]) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    status: dict[str, Any] | None = None
    artifacts: list[dict[str, str]] = []
    for raw_line in body.splitlines():
        line = raw_line.strip()
        match = STATUS_RE.match(line)
        if match:
            if status is not None:
                failures.append("multiple PQCP_ASSURANCE_STATUS lines found")
                continue
            status = {
                "version": match.group("version"),
                "digest": match.group("digest"),
                "artifact_count": int(match.group("count")),
                "schema": int(match.group("schema")),
            }
            continue
        match = ARTIFACT_RE.match(line)
        if match:
            artifacts.append({"name": match.group("name"), "sha256": match.group("sha")})
    if status is None:
        failures.append("missing PQCP_ASSURANCE_STATUS marker")
    return status, artifacts


def verify_status(args: argparse.Namespace) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    reference = load_json(args.reference_values, "PQC reference values", failures)
    body, source = read_transcript(args, failures)
    status, artifacts = parse_status(body, failures)
    if not reference or status is None:
        return {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "passed": False,
            "source": source,
            "checks": checks,
            "failures": failures,
        }

    expected_digest = reference.get("expected_firmware_digest_root")
    ok = status["digest"] == expected_digest
    checks.append({"check": "digest", "expected": expected_digest, "observed": status["digest"], "passed": ok})
    if not ok:
        failures.append("firmware assurance digest mismatch")

    expected_count = int(reference.get("firmware_digest_artifact_count") or 0)
    ok = status["artifact_count"] == expected_count
    checks.append({"check": "artifact_count", "expected": expected_count, "observed": status["artifact_count"], "passed": ok})
    if not ok:
        failures.append("firmware assurance artifact count mismatch")

    ok = status["schema"] == 1
    checks.append({"check": "schema", "observed": status["schema"], "passed": ok})
    if not ok:
        failures.append(f"unsupported firmware status schema={status['schema']!r}")

    expected_version = reference.get("version")
    ok = status["version"] == expected_version
    checks.append({"check": "version", "expected": expected_version, "observed": status["version"], "passed": ok})
    if not ok:
        failures.append("firmware assurance version mismatch")

    ok = len(artifacts) == expected_count
    checks.append({"check": "artifact_marker_count", "expected": expected_count, "observed": len(artifacts), "passed": ok})
    if not ok:
        failures.append("firmware assurance artifact marker count mismatch")

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": not failures,
        "source": source,
        "status": status,
        "artifacts": artifacts,
        "checks": checks,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    result = verify_status(args)
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: firmware assurance status verified")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("FAIL: firmware assurance status verification failed", file=sys.stderr)
    for failure in result["failures"]:
        print(f"  - {failure}", file=sys.stderr)
    print(f"  output: {args.output.resolve()}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
