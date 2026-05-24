#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Experiment catalog loading, validation, and summaries."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any, Iterable

from .errors import CatalogError, Diagnostic, error, warning
from .fs import json_digest, load_json, sha256_file
from .models import CatalogSummary, CatalogValidationResult, ExperimentSelection, ExperimentSpec

EXPERIMENT_ID_RE = re.compile(r"^[a-z][a-z0-9_]*(?:[.-][a-z0-9_]+)*$")
ALLOWED_CATEGORIES = {
    "claim_replay",
    "asset_traceability",
    "artifact_schema",
    "benchmark_methodology",
    "acvp_interop",
    "side_channel_smoke",
    "hardware_promotion",
    "product_packaging",
}
PROFILE_CATEGORIES = {
    "fast": {"artifact_schema", "claim_replay", "asset_traceability"},
    "paper": {"claim_replay", "artifact_schema", "benchmark_methodology", "side_channel_smoke", "acvp_interop"},
    "product": {"claim_replay", "asset_traceability", "artifact_schema", "product_packaging", "acvp_interop"},
    "hardware": {"hardware_promotion", "benchmark_methodology", "side_channel_smoke"},
    "all": ALLOWED_CATEGORIES,
}


def default_catalog_path(module_path: Path) -> Path:
    return module_path / "scripts" / "research_experiment_catalog.json"


def is_safe_relative(path: str) -> bool:
    parsed = Path(path)
    return not parsed.is_absolute() and ".." not in parsed.parts and str(path).strip() != ""


class ExperimentCatalog:
    """Loaded experiment catalog plus validation and selection helpers."""

    def __init__(self, module_path: Path, catalog_path: Path | None = None):
        self.module_path = module_path.resolve()
        self.catalog_path = (catalog_path or default_catalog_path(self.module_path)).resolve()
        if not self.catalog_path.exists():
            raise CatalogError(f"missing experiment catalog: {self.catalog_path}")
        self.raw = load_json(self.catalog_path)
        self.experiments = tuple(ExperimentSpec.from_dict(item) for item in self.raw.get("experiments", []))

    def summary(self) -> CatalogSummary:
        category_counts: dict[str, int] = {}
        command_count = 0
        input_count = 0
        output_count = 0
        for experiment in self.experiments:
            category_counts[experiment.category] = category_counts.get(experiment.category, 0) + 1
            command_count += len(experiment.commands)
            input_count += len(experiment.repository_inputs)
            output_count += len(experiment.expected_outputs)
        return CatalogSummary(
            schema_version=int(self.raw.get("schema_version", 0) or 0),
            catalog_id=str(self.raw.get("catalog_id", "")),
            experiment_count=len(self.experiments),
            category_counts=category_counts,
            command_count=command_count,
            repository_input_count=input_count,
            expected_output_count=output_count,
            digest=sha256_file(self.catalog_path),
        )

    def validate(self, *, use_generated_rules: bool = True) -> CatalogValidationResult:
        diagnostics: list[Diagnostic] = []
        if self.raw.get("schema_version") != 1:
            diagnostics.append(error("catalog_schema", "schema_version", "catalog schema_version must be 1"))
        if not isinstance(self.raw.get("experiments"), list) or not self.raw.get("experiments"):
            diagnostics.append(error("catalog_empty", "experiments", "catalog must contain experiments"))
        seen: set[str] = set()
        for index, experiment in enumerate(self.experiments):
            location = f"experiments[{index}]"
            diagnostics.extend(self._validate_experiment(experiment, location, seen))
        missing_categories = sorted(ALLOWED_CATEGORIES - {item.category for item in self.experiments})
        for category in missing_categories:
            diagnostics.append(warning("category_empty", category, "no experiments in this category"))
        if use_generated_rules:
            try:
                from .experiment_rules import validate_catalog_rules
                diagnostics.extend(validate_catalog_rules(self.experiments, self.module_path))
            except Exception as exc:  # pragma: no cover - defensive guard for generated module drift
                diagnostics.append(error("generated_rules_failed", "experiment_rules", str(exc)))
        passed = not any(item.is_error for item in diagnostics)
        return CatalogValidationResult(passed, self.summary(), tuple(diagnostics))

    def _validate_experiment(self, experiment: ExperimentSpec, location: str, seen: set[str]) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []
        if not EXPERIMENT_ID_RE.match(experiment.id):
            diagnostics.append(error("experiment_id", f"{location}.id", "invalid experiment id"))
        elif experiment.id in seen:
            diagnostics.append(error("experiment_duplicate", f"{location}.id", f"duplicate experiment id: {experiment.id}"))
        seen.add(experiment.id)
        if experiment.category not in ALLOWED_CATEGORIES:
            diagnostics.append(error("experiment_category", f"{experiment.id}.category", "unknown experiment category"))
        for field_name in ("objective", "positive_control", "negative_control", "research_value", "product_value", "status"):
            value = getattr(experiment, field_name)
            if len(value.split()) < 4:
                diagnostics.append(error("experiment_sentence", f"{experiment.id}.{field_name}", "field must be a meaningful sentence"))
        if not experiment.repository_inputs:
            diagnostics.append(error("experiment_inputs", f"{experiment.id}.repository_inputs", "at least one input is required"))
        for item in experiment.repository_inputs:
            if not is_safe_relative(item):
                diagnostics.append(error("experiment_input_path", f"{experiment.id}.repository_inputs", f"unsafe path: {item}"))
            elif not (self.module_path / item).exists():
                diagnostics.append(error("experiment_missing_input", item, "repository input does not exist"))
        if not experiment.commands:
            diagnostics.append(error("experiment_commands", f"{experiment.id}.commands", "at least one command is required"))
        if not experiment.expected_outputs:
            diagnostics.append(error("experiment_outputs", f"{experiment.id}.expected_outputs", "at least one output is required"))
        if len(experiment.acceptance_criteria) < 3:
            diagnostics.append(error("experiment_acceptance", f"{experiment.id}.acceptance_criteria", "at least three acceptance criteria are required"))
        if experiment.commands and not any("python3" in command or "west " in command for command in experiment.commands):
            diagnostics.append(warning("experiment_command_kind", experiment.id, "commands should include python3 or west"))
        return diagnostics

    def select(
        self,
        *,
        ids: Iterable[str] | None = None,
        categories: Iterable[str] | None = None,
        profile: str | None = None,
        glob: str | None = None,
        contains: str | None = None,
        limit: int | None = None,
    ) -> ExperimentSelection:
        selected = list(self.experiments)
        filters: dict[str, Any] = {}
        if ids:
            wanted = list(ids)
            wanted_set = set(wanted)
            selected = [item for item in selected if item.id in wanted_set]
            filters["ids"] = wanted
        if profile:
            if profile not in PROFILE_CATEGORIES:
                raise CatalogError(f"unknown experiment profile: {profile}")
            allowed = PROFILE_CATEGORIES[profile]
            selected = [item for item in selected if item.category in allowed]
            filters["profile"] = profile
        if categories:
            wanted_categories = set(categories)
            unknown = wanted_categories - ALLOWED_CATEGORIES
            if unknown:
                raise CatalogError(f"unknown experiment categories: {', '.join(sorted(unknown))}")
            selected = [item for item in selected if item.category in wanted_categories]
            filters["categories"] = sorted(wanted_categories)
        if glob:
            selected = [item for item in selected if fnmatch.fnmatch(item.id, glob)]
            filters["glob"] = glob
        if contains:
            selected = [item for item in selected if item.contains(contains)]
            filters["contains"] = contains
        if limit is not None:
            if limit < 0:
                raise CatalogError("--limit must be non-negative")
            selected = selected[:limit]
            filters["limit"] = limit
        return ExperimentSelection(tuple(selected), filters)

    def by_id(self) -> dict[str, ExperimentSpec]:
        return {item.id: item for item in self.experiments}

    def categories(self) -> dict[str, list[ExperimentSpec]]:
        grouped: dict[str, list[ExperimentSpec]] = {}
        for experiment in self.experiments:
            grouped.setdefault(experiment.category, []).append(experiment)
        return grouped

    def digest(self) -> str:
        return self.summary().digest

    def stable_fingerprint(self) -> str:
        return json_digest([experiment.to_dict() for experiment in self.experiments])
