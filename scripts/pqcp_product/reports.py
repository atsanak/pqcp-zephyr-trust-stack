#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Human-readable report rendering for product evidence outputs."""

from __future__ import annotations

from .models import BaselineComparisonReport, CatalogValidationResult, EvidencePackManifest, RunManifest


def render_catalog_report(result: CatalogValidationResult) -> str:
    summary = result.catalog_summary
    lines = [
        "# Experiment Catalog Validation",
        "",
        f"Status: {'PASS' if result.passed else 'FAIL'}",
        f"Catalog: `{summary.catalog_id}`",
        f"Experiments: {summary.experiment_count}",
        f"Digest: `{summary.digest}`",
        "",
        "## Categories",
    ]
    for category, count in sorted(summary.category_counts.items()):
        lines.append(f"- `{category}`: {count}")
    lines.extend(["", "## Diagnostics"])
    if not result.diagnostics:
        lines.append("- No diagnostics.")
    for diag in result.diagnostics:
        lines.append(f"- **{diag.severity}** `{diag.code}` `{diag.location}`: {diag.message}")
    return "\n".join(lines) + "\n"


def render_run_report(manifest: RunManifest) -> str:
    lines = [
        "# Experiment Run Manifest",
        "",
        f"Run ID: `{manifest.run_id}`",
        f"Status: {'PASS' if manifest.passed() else 'FAIL'}",
        f"Dry run: {manifest.dry_run}",
        f"Selected experiments: {len(manifest.selection.experiments)}",
        f"Command plans: {len(manifest.plans)}",
        "",
        "## Results",
    ]
    for result in manifest.results:
        lines.append(
            f"- `{result.plan.experiment_id}` command {result.plan.command_index}: "
            f"{result.status} rc={result.returncode} transcript=`{result.transcript_sha256}`"
        )
    return "\n".join(lines) + "\n"


def render_pack_report(manifest: EvidencePackManifest) -> str:
    lines = [
        "# Evidence Pack Manifest",
        "",
        f"Pack ID: `{manifest.pack_id}`",
        f"Status: {'PASS' if manifest.passed() else 'FAIL'}",
        f"Artifacts: {len(manifest.artifacts)}",
        "",
        "## Artifacts",
    ]
    for artifact in manifest.artifacts:
        req = "required" if artifact.required else "optional"
        lines.append(f"- `{artifact.relative_path}` ({req}, {artifact.size_bytes} bytes): `{artifact.sha256}`")
    if manifest.diagnostics:
        lines.extend(["", "## Diagnostics"])
        for diag in manifest.diagnostics:
            lines.append(f"- **{diag.severity}** `{diag.code}` `{diag.location}`: {diag.message}")
    return "\n".join(lines) + "\n"


def render_baseline_report(report: BaselineComparisonReport) -> str:
    lines = [
        "# Baseline Comparison",
        "",
        f"Status: {'PASS' if report.passed() else 'FAIL'}",
        f"Threshold: {report.threshold}",
        f"Results: {len(report.results)}",
        "",
        "| Key | Ratio | Status |",
        "|---|---:|---|",
    ]
    for result in report.results:
        key = ":".join(result.key)
        ratio = "n/a" if result.ratio is None else f"{result.ratio:.4f}"
        lines.append(f"| `{key}` | {ratio} | {result.status} |")
    return "\n".join(lines) + "\n"
