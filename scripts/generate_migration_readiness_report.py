#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Generate JSON and Markdown migration-readiness summaries from Passport checks."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile-result", type=Path, required=True)
    parser.add_argument("--quality-result", type=Path, required=True)
    parser.add_argument("--cbom", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-md", type=Path, required=True)
    return parser.parse_args()


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"{label} not found: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"{label} root must be a JSON object")
    return raw


def properties_map(component: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and isinstance(prop.get("name"), str):
            result[prop["name"]] = str(prop.get("value", ""))
    return result


def cbom_assets(cbom: dict[str, Any]) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    for component in cbom.get("components") or []:
        if not isinstance(component, dict):
            continue
        props = properties_map(component)
        if not props.get("pqcp:trace_asset_id"):
            continue
        assets.append(
            {
                "name": component.get("name"),
                "trace_asset_id": props.get("pqcp:trace_asset_id"),
                "lifecycle_status": props.get("pqcp:lifecycle_status", "unknown"),
                "production_allowed": props.get("pqcp:production_allowed", "unknown"),
                "profile_support": sorted(
                    item.strip()
                    for item in props.get("pqcp:profile_support", "").split(",")
                    if item.strip()
                ),
                "validation_scope": sorted(
                    item.strip()
                    for item in props.get("pqcp:validation_scope", "").split(",")
                    if item.strip()
                ),
            }
        )
    return sorted(assets, key=lambda item: str(item.get("trace_asset_id")))


def build_report(profile_result: dict[str, Any], quality_result: dict[str, Any], cbom: dict[str, Any]) -> dict[str, Any]:
    blocked = []
    for failure in profile_result.get("failures") or []:
        blocked.append({"source": "profile", "reason": str(failure)})
    for failure in quality_result.get("failures") or []:
        blocked.append({"source": "evidence_quality", "reason": str(failure)})
    assets = cbom_assets(cbom)
    production_assets = [
        asset for asset in assets if asset.get("production_allowed") == "true"
    ]
    test_only_assets = [
        asset for asset in assets if asset.get("lifecycle_status") == "test_only"
    ]
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": profile_result.get("passed") is True and quality_result.get("passed") is True and not blocked,
        "summary": {
            "asset_count": len(assets),
            "production_asset_count": len(production_assets),
            "test_only_asset_count": len(test_only_assets),
            "blocked_condition_count": len(blocked),
        },
        "blocked_conditions": blocked,
        "assets": assets,
        "profile_summary": profile_result.get("summary", {}),
        "evidence_quality_summary": quality_result.get("summary", {}),
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# PQC Migration Readiness",
        "",
        f"- Generated: `{report['generated_at']}`",
        f"- Status: `{'pass' if report['passed'] else 'fail'}`",
        f"- Assets: `{report['summary']['asset_count']}`",
        f"- Production-allowed assets: `{report['summary']['production_asset_count']}`",
        f"- Test-only assets: `{report['summary']['test_only_asset_count']}`",
        "",
    ]
    if report["blocked_conditions"]:
        lines.extend(["## Blocking Conditions", ""])
        for item in report["blocked_conditions"]:
            lines.append(f"- `{item['source']}`: {item['reason']}")
        lines.append("")
    lines.extend(
        [
            "## Asset Profile Summary",
            "",
            "| Asset | Lifecycle | Production | Profiles | Validation Scope |",
            "|---|---|---:|---|---|",
        ]
    )
    for asset in report["assets"]:
        lines.append(
            "| {name} | {lifecycle} | {prod} | {profiles} | {scope} |".format(
                name=asset.get("name"),
                lifecycle=asset.get("lifecycle_status"),
                prod=asset.get("production_allowed"),
                profiles=", ".join(asset.get("profile_support") or []),
                scope=", ".join(asset.get("validation_scope") or []),
            )
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    try:
        profile_result = load_json(args.profile_result, "profile result")
        quality_result = load_json(args.quality_result, "evidence quality result")
        cbom = load_json(args.cbom, "PQC CBOM")
        report = build_report(profile_result, quality_result, cbom)
    except (OSError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    args.output_json.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output_md.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output_json.resolve().write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output_md.resolve().write_text(render_markdown(report), encoding="utf-8")
    if report["passed"]:
        print("PQC migration readiness passed")
        print(f"  json: {args.output_json.resolve()}")
        print(f"  md  : {args.output_md.resolve()}")
        return 0
    print("PQC migration readiness failed:", file=sys.stderr)
    for item in report["blocked_conditions"]:
        print(f"  - {item['source']}: {item['reason']}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
