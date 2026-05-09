#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Verify claim evidence quality metadata against a generated ledger."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_QUALITY = SCRIPT_DIR / "pqc_evidence_quality.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quality", type=Path, default=DEFAULT_QUALITY)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--graph", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


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


def ledger_claims(ledger: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(claim.get("id")): claim
        for claim in ledger.get("claims") or []
        if isinstance(claim, dict) and isinstance(claim.get("id"), str)
    }


def graph_claim_ids(graph: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for node in graph.get("nodes") or []:
        if not isinstance(node, dict):
            continue
        if node.get("type") == "claim" and isinstance(node.get("label"), str):
            result.add(node["label"])
    return result


def verify_quality(
    *,
    quality_path: Path = DEFAULT_QUALITY,
    ledger_path: Path,
    graph_path: Path | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    quality = load_json(quality_path, "evidence quality index", failures)
    ledger = load_json(ledger_path, "assurance ledger", failures)
    graph = (
        load_json(graph_path, "PQC evidence graph", failures)
        if graph_path is not None and graph_path.exists()
        else {}
    )
    if not quality or not ledger:
        return {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "passed": False,
            "failures": failures,
            "checks": checks,
        }

    if quality.get("schema_version") != 1:
        failures.append(f"unsupported evidence quality schema_version={quality.get('schema_version')!r}")
    accepted = set(quality.get("accepted_evidence_classes") or [])
    if not accepted:
        failures.append("accepted_evidence_classes must be non-empty")

    claims = ledger_claims(ledger)
    required_claims = {
        claim_id
        for claim_id, claim in claims.items()
        if claim.get("required", True)
    }
    quality_entries = quality.get("claims")
    if not isinstance(quality_entries, list) or not quality_entries:
        failures.append("quality claims must be a non-empty list")
        quality_entries = []
    quality_by_id: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(quality_entries):
        if not isinstance(entry, dict):
            failures.append(f"quality claims[{index}] must be an object")
            continue
        claim_id = entry.get("id")
        if not isinstance(claim_id, str) or not claim_id:
            failures.append(f"quality claims[{index}] missing id")
            continue
        if claim_id in quality_by_id:
            failures.append(f"duplicate evidence quality claim id: {claim_id}")
        quality_by_id[claim_id] = entry

    missing_quality = sorted(required_claims - set(quality_by_id))
    if missing_quality:
        failures.append("required ledger claim(s) missing evidence quality entry: " + ", ".join(missing_quality))

    graph_claims = graph_claim_ids(graph) if graph else set()
    for claim_id, entry in sorted(quality_by_id.items()):
        claim = claims.get(claim_id)
        if claim is None:
            failures.append(f"evidence quality references unknown ledger claim: {claim_id}")
            checks.append({"check": "quality_claim_exists", "claim_id": claim_id, "passed": False})
            continue
        evidence_class = entry.get("evidence_class")
        if evidence_class not in accepted:
            failures.append(f"{claim_id} evidence_class {evidence_class!r} is not accepted")
        environment = entry.get("environment")
        if not isinstance(environment, str) or not environment:
            failures.append(f"{claim_id} must declare an environment")

        status = claim.get("status")
        allow_na = bool(entry.get("allow_not_applicable")) or evidence_class == "not_applicable_allowed"
        status_ok = status == "pass" or (status == "not_applicable" and allow_na)
        checks.append(
            {
                "check": "claim_status",
                "claim_id": claim_id,
                "status": status,
                "evidence_class": evidence_class,
                "passed": status_ok,
            }
        )
        if not status_ok:
            failures.append(f"{claim_id} has status {status!r}, not accepted by evidence quality index")

        artifacts = claim.get("evidence_artifacts")
        has_artifact = isinstance(artifacts, list) and any(
            isinstance(item, dict) and item.get("exists") is True for item in artifacts
        )
        if entry.get("requires_artifact") and status == "pass" and not has_artifact:
            failures.append(f"{claim_id} requires at least one existing evidence artifact")

        if entry.get("graph_required"):
            in_graph = claim_id in graph_claims
            checks.append({"check": "claim_in_evidence_graph", "claim_id": claim_id, "passed": in_graph})
            if not in_graph:
                failures.append(f"{claim_id} is not present in the evidence graph")

        if claim_id == "security.ct_smoke" and status == "pass":
            details = claim.get("details") if isinstance(claim.get("details"), dict) else {}
            smoke_ok = bool(details.get("is_smoke_test_only")) and bool(entry.get("smoke_only"))
            checks.append({"check": "ct_smoke_labeled_as_smoke", "claim_id": claim_id, "passed": smoke_ok})
            if not smoke_ok:
                failures.append("security.ct_smoke must be explicitly labelled as smoke-only")

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "quality": str(quality_path),
        "passed": not failures,
        "summary": {
            "ledger_claims": len(claims),
            "quality_entries": len(quality_by_id),
            "checks": len(checks),
            "failures": len(failures),
        },
        "failures": failures,
        "checks": checks,
    }


def main() -> int:
    args = parse_args()
    result = verify_quality(
        quality_path=args.quality.resolve(),
        ledger_path=args.ledger.resolve(),
        graph_path=args.graph.resolve() if args.graph else None,
    )
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PQC evidence quality passed")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("PQC evidence quality failed:", file=sys.stderr)
    for failure in result["failures"]:
        print(f"  - {failure}", file=sys.stderr)
    print(f"  output: {args.output.resolve()}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
