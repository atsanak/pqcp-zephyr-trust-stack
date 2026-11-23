#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Render a dependency-free HTML assurance report from an assurance ledger."""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path
from typing import Any

REPORT_GENERATOR = "scripts/render_assurance_report.py"
STATUS_COLOURS = {
    "pass": "#1b7a3a",
    "fail": "#a3091a",
    "not_applicable": "#5a5a5a",
}
STATUS_BG = {
    "pass": "#e6f4ea",
    "fail": "#fdecea",
    "not_applicable": "#eeeeee",
}
STATUS_LABELS = {
    "pass": "PASS",
    "fail": "FAIL",
    "not_applicable": "N/A",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Render a dependency-free HTML assurance report from a generated "
            "assurance_ledger.json. Output is self-contained: inline CSS only, "
            "no external assets, no JS."
        )
    )
    parser.add_argument("ledger_json", type=Path, help="Path to assurance_ledger.json")
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path to write the HTML assurance report.",
    )
    return parser.parse_args()


def load_ledger(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"assurance ledger not found: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path} root must be a JSON object")
    return raw


def _h(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _render_artifact_list(artifacts: list[dict[str, object]]) -> str:
    if not artifacts:
        return "<em>none</em>"
    items: list[str] = []
    for item in artifacts:
        if not isinstance(item, dict):
            continue
        label = _h(item.get("label", ""))
        path = _h(item.get("path", ""))
        exists = item.get("exists")
        sha = item.get("sha256")
        bits = [f"<code>{path}</code>"]
        if label:
            bits.insert(0, f"<strong>{label}</strong>")
        if exists is False:
            bits.append('<span class="missing">missing</span>')
        if isinstance(sha, str) and sha:
            bits.append(f'<span class="sha">sha256:{_h(sha)}</span>')
        items.append("<li>" + " &middot; ".join(bits) + "</li>")
    return "<ul class=\"artifacts\">" + "".join(items) + "</ul>"


def _render_validators(validators: list[str]) -> str:
    if not validators:
        return "<em>none</em>"
    return "<ul class=\"validators\">" + "".join(
        f"<li><code>{_h(v)}</code></li>" for v in validators
    ) + "</ul>"


def render_report(ledger: dict[str, Any]) -> str:
    project = _h(ledger.get("project", "pqcp-zephyr-trust-stack"))
    version = _h(ledger.get("version", "unknown"))
    tag = _h(ledger.get("tag") or "(none)")
    head_sha = _h(ledger.get("head_sha") or "unknown")
    dirty = _h(ledger.get("dirty"))
    generated_at = _h(ledger.get("generated_at", "unknown"))
    schema_version = _h(ledger.get("schema_version", "?"))

    summary = ledger.get("summary") or {}
    n_pass = int(summary.get("pass", 0) or 0)
    n_fail = int(summary.get("fail", 0) or 0)
    n_na = int(summary.get("not_applicable", 0) or 0)

    claims_raw = ledger.get("claims") or []
    claim_rows: list[str] = []
    for claim in claims_raw:
        if not isinstance(claim, dict):
            continue
        status = str(claim.get("status", "fail"))
        colour = STATUS_COLOURS.get(status, STATUS_COLOURS["fail"])
        bg = STATUS_BG.get(status, STATUS_BG["fail"])
        label = STATUS_LABELS.get(status, status.upper())
        claim_id = _h(claim.get("id"))
        category = _h(claim.get("category"))
        text = _h(claim.get("claim"))
        required = "yes" if claim.get("required", True) else "no"
        reason = _h(claim.get("failure_reason") or "")
        artifacts_html = _render_artifact_list(
            claim.get("evidence_artifacts") or []
        )
        validators_html = _render_validators(
            claim.get("validators") or []
        )

        reason_block = (
            f'<div class="reason"><strong>failure_reason:</strong> {reason}</div>'
            if reason
            else ""
        )
        claim_rows.append(
            f"""
            <tr class="status-row">
              <td><code>{claim_id}</code><div class="cat">{category}</div></td>
              <td><span class="badge" style="color:{colour};background:{bg};">{label}</span></td>
              <td>{required}</td>
              <td>
                <div class="claim-text">{text}</div>
                {reason_block}
                <details><summary>validators &amp; artifacts</summary>
                  <div class="details-block">
                    <strong>validators:</strong>
                    {validators_html}
                    <strong>evidence_artifacts:</strong>
                    {artifacts_html}
                  </div>
                </details>
              </td>
            </tr>
            """
        )

    summary_pass_colour = STATUS_COLOURS["pass"] if n_fail == 0 else STATUS_COLOURS["fail"]
    summary_pass_bg = STATUS_BG["pass"] if n_fail == 0 else STATUS_BG["fail"]
    summary_label = "ALL CLAIMS PASS" if n_fail == 0 else f"{n_fail} CLAIM(S) FAIL"

    style = """
      body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; margin: 0; padding: 2rem; background: #fafafa; color: #222; }
      h1 { margin-top: 0; }
      header.meta { background: #ffffff; border: 1px solid #e0e0e0; border-radius: 6px; padding: 1rem 1.25rem; margin-bottom: 1rem; }
      header.meta dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.25rem 1rem; margin: 0; }
      header.meta dt { font-weight: 600; color: #555; }
      header.meta dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
      .summary { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
      .summary .card { padding: 0.75rem 1.25rem; border-radius: 6px; border: 1px solid #d0d0d0; background: #fff; min-width: 6rem; text-align: center; }
      .summary .card.headline { font-weight: 700; }
      .summary .card .count { font-size: 1.5rem; font-weight: 700; }
      table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e0e0e0; border-radius: 6px; overflow: hidden; }
      th, td { padding: 0.75rem 1rem; text-align: left; vertical-align: top; border-bottom: 1px solid #eee; }
      th { background: #f4f4f4; font-weight: 600; }
      tr:last-child td { border-bottom: none; }
      td .cat { color: #777; font-size: 0.8rem; margin-top: 0.25rem; }
      td .claim-text { max-width: 60ch; }
      .badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px; font-weight: 700; font-size: 0.85rem; letter-spacing: 0.04em; }
      details { margin-top: 0.5rem; }
      summary { cursor: pointer; color: #444; }
      .details-block { margin: 0.5rem 0 0 1rem; font-size: 0.9rem; }
      .reason { margin-top: 0.4rem; color: #a3091a; font-size: 0.9rem; }
      ul.artifacts, ul.validators { margin: 0.25rem 0 0.75rem 1.25rem; padding: 0; }
      ul.artifacts li, ul.validators li { margin: 0.15rem 0; font-size: 0.85rem; }
      .missing { color: #a3091a; font-weight: 600; }
      .sha { color: #555; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
      footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #e0e0e0; color: #777; font-size: 0.85rem; }
      code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    """

    table_rows = "".join(claim_rows) if claim_rows else (
        '<tr><td colspan="4"><em>No claims recorded in this ledger.</em></td></tr>'
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Assurance Report &mdash; {project} {version}</title>
  <style>{style}</style>
</head>
<body>
  <h1>Assurance Report</h1>
  <header class="meta">
    <dl>
      <dt>Project</dt><dd>{project}</dd>
      <dt>Version</dt><dd>{version}</dd>
      <dt>Tag</dt><dd>{tag}</dd>
      <dt>Source commit</dt><dd>{head_sha}</dd>
      <dt>Working tree dirty</dt><dd>{dirty}</dd>
      <dt>Generated at</dt><dd>{generated_at}</dd>
      <dt>Ledger schema</dt><dd>schema_version={schema_version}</dd>
    </dl>
  </header>
  <section class="summary">
    <div class="card headline" style="color:{summary_pass_colour};background:{summary_pass_bg};">{summary_label}</div>
    <div class="card"><div class="count" style="color:{STATUS_COLOURS['pass']}">{n_pass}</div>pass</div>
    <div class="card"><div class="count" style="color:{STATUS_COLOURS['fail']}">{n_fail}</div>fail</div>
    <div class="card"><div class="count" style="color:{STATUS_COLOURS['not_applicable']}">{n_na}</div>not applicable</div>
  </section>
  <table>
    <thead>
      <tr>
        <th>Claim ID / category</th>
        <th>Status</th>
        <th>Required</th>
        <th>Claim text &amp; evidence</th>
      </tr>
    </thead>
    <tbody>
      {table_rows}
    </tbody>
  </table>
  <footer>
    This report was generated by pqcp-zephyr-trust-stack <code>release_check.py</code>
    via <code>{REPORT_GENERATOR}</code>. The HTML is dependency-free and replay-checkable
    by <code>scripts/verify_release_evidence_pack.py</code>.
  </footer>
</body>
</html>
"""


def main() -> int:
    args = parse_args()
    try:
        ledger = load_ledger(args.ledger_json)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"render_assurance_report: {exc}", file=sys.stderr)
        return 1
    report = render_report(ledger)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(f"[INFO] wrote assurance report to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
