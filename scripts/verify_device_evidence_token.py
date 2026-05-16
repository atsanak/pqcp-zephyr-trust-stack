#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Verify additive PQCP_DEVICE_EVIDENCE markers from assurance-status firmware."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HEX = r"[0-9a-f]{64}"
TOKEN_RE = re.compile(
    rf"^PQCP_DEVICE_EVIDENCE\s+nonce=(?P<nonce>[0-9a-f]+)\s+"
    rf"digest=(?P<digest>{HEX})\s+artifact_count=(?P<count>\d+)\s+"
    rf"schema=(?P<schema>\d+)\s+transcript_sha256=(?P<trace>{HEX})$"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-values", type=Path, required=True)
    parser.add_argument("--transcript-dir", type=Path, required=True)
    parser.add_argument("--token-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"{path} root must be a JSON object")
    return raw


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def find_marker(transcript_dir: Path) -> tuple[dict[str, Any] | None, str, str]:
    for path in sorted(transcript_dir.glob("*.log")):
        body = path.read_text(encoding="utf-8", errors="replace")
        for line in body.splitlines():
            match = TOKEN_RE.match(line.strip())
            if match:
                token = {
                    "nonce": match.group("nonce"),
                    "digest": match.group("digest"),
                    "artifact_count": int(match.group("count")),
                    "schema": int(match.group("schema")),
                    "transcript_sha256": match.group("trace"),
                }
                return token, str(path), sha256_text(body)
    return None, "", ""


def verify(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    reference = load_json(args.reference_values)
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    token, source, actual_transcript_sha = find_marker(args.transcript_dir)
    if token is None:
        failures.append("PQCP_DEVICE_EVIDENCE marker not found")
        token = {}
    expected_digest = reference.get("expected_firmware_digest_root")
    expected_count = int(reference.get("firmware_digest_artifact_count") or 0)
    expected_nonce = str(expected_digest or "")[:32]
    for check, expected, observed in (
        ("digest", expected_digest, token.get("digest")),
        ("artifact_count", expected_count, token.get("artifact_count")),
        ("schema", 1, token.get("schema")),
        ("nonce", expected_nonce, token.get("nonce")),
    ):
        ok = observed == expected
        checks.append({"check": check, "expected": expected, "observed": observed, "passed": ok})
        if not ok:
            failures.append(f"device evidence {check} mismatch")
    token_payload = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "transcript_sha256_actual": actual_transcript_sha,
        "token": token,
    }
    result = {
        "schema_version": 1,
        "generated_at": token_payload["generated_at"],
        "passed": not failures,
        "token_path": str(args.token_output),
        "checks": checks,
        "failures": failures,
    }
    return token_payload, result


def main() -> int:
    args = parse_args()
    token, result = verify(args)
    args.token_output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.token_output.resolve().write_text(json.dumps(token, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: device evidence token verified")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("FAIL: device evidence token verification failed")
    for failure in result["failures"]:
        print(f"  - {failure}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
