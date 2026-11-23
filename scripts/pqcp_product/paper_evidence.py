#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compact paper-evidence report aggregation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .fs import utc_now, write_json_atomic, write_text_atomic

SECTION_NAMES = (
    "reproducibility",
    "coverage",
    "baseline",
    "regression",
    "quality",
    "statistics",
)


def generate_paper_evidence_report(
    *,
    output_root: Path,
    reports: dict[str, Path | None],
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    sections = []
    for name in SECTION_NAMES:
        path = reports.get(name)
        sections.append(_section(name, path))
    status = _status(sections)
    result = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": status,
        "passed": status != "FAIL",
        "sections": sections,
    }
    write_json_atomic(output_root / "paper-evidence-report.json", result)
    write_text_atomic(output_root / "paper-evidence-report.md", render_paper_evidence_report(result))
    return result


def _section(name: str, path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"name": name, "status": "WARN", "reason": "not_available", "path": None}
    if not path.exists():
        return {"name": name, "status": "WARN", "reason": "not_available", "path": str(path)}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {"name": name, "status": "FAIL", "reason": f"invalid_json: {exc}", "path": str(path)}
    status = _payload_status(payload)
    return {
        "name": name,
        "status": status,
        "reason": payload.get("status") or ("passed" if payload.get("passed") else "failed"),
        "path": str(path),
        "schema_version": payload.get("schema_version"),
        "summary": _summary(payload),
    }


def _payload_status(payload: dict[str, Any]) -> str:
    raw_status = str(payload.get("status", "")).upper()
    if raw_status in {"PASS", "WARN", "FAIL"}:
        return raw_status
    if payload.get("passed") is True:
        return "PASS"
    if payload.get("passed") is False:
        return "FAIL"
    return "WARN"


def _summary(payload: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "artifact_count",
        "row_count",
        "group_count",
        "result_count",
        "manifest_count",
        "diagnostic_counts",
        "diagnostics",
    )
    out: dict[str, Any] = {}
    for key in keys:
        if key in payload:
            value = payload[key]
            out[key] = len(value) if key == "diagnostics" and isinstance(value, list) else value
    return out


def _status(sections: list[dict[str, Any]]) -> str:
    if any(section["status"] == "FAIL" for section in sections):
        return "FAIL"
    if any(section["status"] == "WARN" for section in sections):
        return "WARN"
    return "PASS"


def render_paper_evidence_report(result: dict[str, Any]) -> str:
    lines = [
        "# Paper Evidence Report",
        "",
        f"Status: **{result['status']}**",
        "",
        "| Section | Status | Reason |",
        "|---|---|---|",
    ]
    for section in result["sections"]:
        lines.append(f"| `{section['name']}` | {section['status']} | {section.get('reason', '')} |")
    return "\n".join(lines).rstrip() + "\n"
