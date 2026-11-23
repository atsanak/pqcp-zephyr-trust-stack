#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Experiment coverage validation for research/product evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .catalog import ALLOWED_CATEGORIES, ExperimentCatalog, PROFILE_CATEGORIES
from .errors import Diagnostic, error
from .fs import read_text_lossless, utc_now, write_json_atomic, write_text_atomic
from .models import ExperimentSpec

DEFAULT_ALGORITHMS = {
    "ML-KEM": ("ml-kem", "mlkem"),
    "ML-DSA": ("ml-dsa", "mldsa"),
}
DEFAULT_TARGETS = {
    "qemu_x86_64": ("qemu_x86_64", "qemu"),
    "native_sim": ("native_sim", "native tls", "native simulator"),
    "nucleo_h743zi": ("nucleo_h743zi", "nucleo", "mcu"),
}
DEFAULT_PROFILES = ("fast", "paper", "product", "hardware")


def validate_coverage(*, catalog: ExperimentCatalog, output_root: Path) -> dict[str, Any]:
    """Validate experiment coverage against built-in product/research defaults."""

    output_root.mkdir(parents=True, exist_ok=True)
    diagnostics: list[Diagnostic] = []
    experiments = list(catalog.experiments)
    category_rows = _category_coverage(experiments, diagnostics)
    algorithm_rows = _keyword_coverage(experiments, catalog.module_path, DEFAULT_ALGORITHMS, "algorithm", diagnostics)
    target_rows = _keyword_coverage(experiments, catalog.module_path, DEFAULT_TARGETS, "target", diagnostics)
    profile_rows = _profile_coverage(catalog, diagnostics)
    baseline_row = _baseline_coverage(experiments, catalog.module_path, diagnostics)
    status = _status(diagnostics)
    result = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": status,
        "passed": status != "FAIL",
        "category_coverage": category_rows,
        "algorithm_coverage": algorithm_rows,
        "target_coverage": target_rows,
        "profile_coverage": profile_rows,
        "baseline_coverage": baseline_row,
        "diagnostics": [item.to_dict() for item in diagnostics],
    }
    write_json_atomic(output_root / "experiment-coverage-report.json", result)
    write_text_atomic(output_root / "experiment-coverage-summary.md", render_coverage_summary(result))
    return result


def _experiment_text(experiment: ExperimentSpec, module_path: Path) -> str:
    parts = [
        experiment.id,
        experiment.category,
        experiment.objective,
        experiment.positive_control,
        experiment.negative_control,
        experiment.research_value,
        experiment.product_value,
        experiment.status,
        *experiment.repository_inputs,
        *experiment.commands,
        *experiment.expected_outputs,
        *experiment.acceptance_criteria,
    ]
    for rel in experiment.repository_inputs:
        path = module_path / rel
        if path.exists() and path.is_file() and path.stat().st_size <= 256_000:
            parts.append(read_text_lossless(path))
    return "\n".join(parts).lower()


def _category_coverage(experiments: list[ExperimentSpec], diagnostics: list[Diagnostic]) -> list[dict[str, Any]]:
    counts = {category: 0 for category in sorted(ALLOWED_CATEGORIES)}
    for experiment in experiments:
        if experiment.category in counts:
            counts[experiment.category] += 1
    rows: list[dict[str, Any]] = []
    for category, count in counts.items():
        covered = count > 0
        if not covered:
            diagnostics.append(error("coverage_missing_category", category, "required experiment category has no entries"))
        rows.append({"category": category, "count": count, "covered": covered})
    return rows


def _keyword_coverage(
    experiments: list[ExperimentSpec],
    module_path: Path,
    required: dict[str, tuple[str, ...]],
    kind: str,
    diagnostics: list[Diagnostic],
) -> list[dict[str, Any]]:
    texts = [(experiment, _experiment_text(experiment, module_path)) for experiment in experiments]
    rows: list[dict[str, Any]] = []
    for name, aliases in required.items():
        hits = [experiment.id for experiment, text in texts if any(alias in text for alias in aliases)]
        covered = bool(hits)
        if not covered:
            diagnostics.append(error(f"coverage_missing_{kind}", name, f"required {kind} is not covered"))
        rows.append({"name": name, "aliases": list(aliases), "covered": covered, "experiment_ids": hits[:25], "count": len(hits)})
    return rows


def _profile_coverage(catalog: ExperimentCatalog, diagnostics: list[Diagnostic]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for profile in DEFAULT_PROFILES:
        selection = catalog.select(profile=profile)
        covered = bool(selection.experiments) and profile in PROFILE_CATEGORIES
        if not covered:
            diagnostics.append(error("coverage_missing_profile", profile, "profile selects no experiments"))
        rows.append({"profile": profile, "covered": covered, "experiment_count": len(selection.experiments)})
    return rows


def _baseline_coverage(experiments: list[ExperimentSpec], module_path: Path, diagnostics: list[Diagnostic]) -> dict[str, Any]:
    hits = []
    for experiment in experiments:
        text = _experiment_text(experiment, module_path)
        if any(word in text for word in ("baseline", "comparison", "regression")):
            hits.append(experiment.id)
    covered = bool(hits)
    if not covered:
        diagnostics.append(error("coverage_missing_baseline", "baseline", "no baseline/comparison/regression evidence experiment found"))
    return {"covered": covered, "experiment_ids": hits[:25], "count": len(hits)}


def _status(diagnostics: list[Diagnostic]) -> str:
    return "FAIL" if any(item.is_error for item in diagnostics) else "PASS"


def render_coverage_summary(result: dict[str, Any]) -> str:
    lines = ["# Experiment Coverage", "", f"Status: **{result['status']}**", ""]
    for section in ("category_coverage", "algorithm_coverage", "target_coverage", "profile_coverage"):
        lines.append(f"## {section.replace('_', ' ').title()}")
        for row in result[section]:
            name = row.get("category") or row.get("name") or row.get("profile")
            lines.append(f"- `{name}`: {'covered' if row['covered'] else 'missing'}")
        lines.append("")
    baseline = result["baseline_coverage"]
    lines.append(f"Baseline/comparison evidence: {'covered' if baseline['covered'] else 'missing'}")
    if result.get("diagnostics"):
        lines.extend(["", "## Diagnostics"])
        for diag in result["diagnostics"]:
            lines.append(f"- {diag['severity'].upper()} `{diag['code']}` `{diag['location']}`: {diag['message']}")
    return "\n".join(lines).rstrip() + "\n"
