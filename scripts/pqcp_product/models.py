#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Typed models used by the PQCP product evidence toolkit."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .errors import Diagnostic, summarize_diagnostics

JsonObject = dict[str, Any]


@dataclass(frozen=True)
class ExperimentSpec:
    """One replayable experiment derived from the research/product catalog."""

    id: str
    category: str
    objective: str
    repository_inputs: tuple[str, ...]
    commands: tuple[str, ...]
    expected_outputs: tuple[str, ...]
    positive_control: str
    negative_control: str
    acceptance_criteria: tuple[str, ...]
    research_value: str
    product_value: str
    status: str

    @classmethod
    def from_dict(cls, raw: JsonObject) -> "ExperimentSpec":
        return cls(
            id=str(raw.get("id", "")),
            category=str(raw.get("category", "")),
            objective=str(raw.get("objective", "")),
            repository_inputs=tuple(str(item) for item in raw.get("repository_inputs", [])),
            commands=tuple(str(item) for item in raw.get("commands", [])),
            expected_outputs=tuple(str(item) for item in raw.get("expected_outputs", [])),
            positive_control=str(raw.get("positive_control", "")),
            negative_control=str(raw.get("negative_control", "")),
            acceptance_criteria=tuple(str(item) for item in raw.get("acceptance_criteria", [])),
            research_value=str(raw.get("research_value", "")),
            product_value=str(raw.get("product_value", "")),
            status=str(raw.get("status", "")),
        )

    def to_dict(self) -> JsonObject:
        return {
            "id": self.id,
            "category": self.category,
            "objective": self.objective,
            "repository_inputs": list(self.repository_inputs),
            "commands": list(self.commands),
            "expected_outputs": list(self.expected_outputs),
            "positive_control": self.positive_control,
            "negative_control": self.negative_control,
            "acceptance_criteria": list(self.acceptance_criteria),
            "research_value": self.research_value,
            "product_value": self.product_value,
            "status": self.status,
        }

    def missing_inputs(self, module_path: Path) -> list[str]:
        return [item for item in self.repository_inputs if not (module_path / item).exists()]

    def command_count(self) -> int:
        return len(self.commands)

    def expected_output_count(self) -> int:
        return len(self.expected_outputs)

    def acceptance_count(self) -> int:
        return len(self.acceptance_criteria)

    def contains(self, needle: str) -> bool:
        if not needle:
            return True
        haystack = "\n".join(
            [
                self.id,
                self.category,
                self.objective,
                self.positive_control,
                self.negative_control,
                self.research_value,
                self.product_value,
                self.status,
                *self.repository_inputs,
                *self.commands,
                *self.expected_outputs,
                *self.acceptance_criteria,
            ]
        ).lower()
        return needle.lower() in haystack

    def safe_id(self) -> str:
        return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in self.id)

    def profile_score(self) -> int:
        score = 0
        if any("--help" in command for command in self.commands):
            score += 1
        if any("release_check" in command or "verify_release" in command for command in self.commands):
            score += 2
        if any("west " in command for command in self.commands):
            score += 3
        if "hardware" in self.category:
            score += 5
        return score


@dataclass(frozen=True)
class CatalogSummary:
    schema_version: int
    catalog_id: str
    experiment_count: int
    category_counts: dict[str, int]
    command_count: int
    repository_input_count: int
    expected_output_count: int
    digest: str

    def to_dict(self) -> JsonObject:
        return {
            "schema_version": self.schema_version,
            "catalog_id": self.catalog_id,
            "experiment_count": self.experiment_count,
            "category_counts": dict(sorted(self.category_counts.items())),
            "command_count": self.command_count,
            "repository_input_count": self.repository_input_count,
            "expected_output_count": self.expected_output_count,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class CatalogValidationResult:
    passed: bool
    catalog_summary: CatalogSummary
    diagnostics: tuple[Diagnostic, ...]

    def to_dict(self) -> JsonObject:
        return {
            "schema_version": 1,
            "passed": self.passed,
            "summary": self.catalog_summary.to_dict(),
            "diagnostic_counts": summarize_diagnostics(self.diagnostics),
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }


@dataclass(frozen=True)
class ExperimentSelection:
    experiments: tuple[ExperimentSpec, ...]
    filters: JsonObject = field(default_factory=dict)

    def ids(self) -> list[str]:
        return [item.id for item in self.experiments]

    def categories(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.experiments:
            counts[item.category] = counts.get(item.category, 0) + 1
        return counts

    def to_dict(self) -> JsonObject:
        return {
            "count": len(self.experiments),
            "filters": self.filters,
            "categories": dict(sorted(self.categories().items())),
            "experiment_ids": self.ids(),
            "experiments": [item.to_dict() for item in self.experiments],
        }


@dataclass(frozen=True)
class CommandPlan:
    experiment_id: str
    command_index: int
    command: str
    cwd: str
    timeout_seconds: int
    transcript_path: str
    dry_run: bool

    def to_dict(self) -> JsonObject:
        return {
            "experiment_id": self.experiment_id,
            "command_index": self.command_index,
            "command": self.command,
            "cwd": self.cwd,
            "timeout_seconds": self.timeout_seconds,
            "transcript_path": self.transcript_path,
            "dry_run": self.dry_run,
        }


@dataclass(frozen=True)
class CommandResult:
    plan: CommandPlan
    returncode: int
    stdout_sha256: str
    stderr_sha256: str
    transcript_sha256: str
    duration_seconds: float
    status: str
    started_at: str
    finished_at: str

    def to_dict(self) -> JsonObject:
        return {
            "plan": self.plan.to_dict(),
            "returncode": self.returncode,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "transcript_sha256": self.transcript_sha256,
            "duration_seconds": round(self.duration_seconds, 6),
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


@dataclass(frozen=True)
class RunManifest:
    schema_version: int
    run_id: str
    output_root: str
    module_path: str
    dry_run: bool
    started_at: str
    finished_at: str
    selection: ExperimentSelection
    plans: tuple[CommandPlan, ...]
    results: tuple[CommandResult, ...]
    diagnostics: tuple[Diagnostic, ...]
    metadata: JsonObject = field(default_factory=dict)

    def passed(self) -> bool:
        return not any(item.is_error for item in self.diagnostics) and all(
            result.status in {"pass", "planned"} for result in self.results
        )

    def to_dict(self) -> JsonObject:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "output_root": self.output_root,
            "module_path": self.module_path,
            "dry_run": self.dry_run,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "passed": self.passed(),
            "selection": self.selection.to_dict(),
            "plans": [item.to_dict() for item in self.plans],
            "results": [item.to_dict() for item in self.results],
            "diagnostic_counts": summarize_diagnostics(self.diagnostics),
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class EvidenceArtifact:
    artifact_id: str
    relative_path: str
    absolute_path: str
    sha256: str
    size_bytes: int
    media_type: str
    required: bool
    status: str

    def to_dict(self) -> JsonObject:
        return {
            "artifact_id": self.artifact_id,
            "relative_path": self.relative_path,
            "absolute_path": self.absolute_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
            "required": self.required,
            "status": self.status,
        }


@dataclass(frozen=True)
class EvidencePackManifest:
    schema_version: int
    pack_id: str
    output_root: str
    generated_at: str
    profile: str
    tag: str | None
    artifacts: tuple[EvidenceArtifact, ...]
    diagnostics: tuple[Diagnostic, ...]
    metadata: JsonObject = field(default_factory=dict)

    def passed(self) -> bool:
        return not any(item.is_error for item in self.diagnostics)

    def artifact_ids(self) -> set[str]:
        return {item.artifact_id for item in self.artifacts}

    def to_dict(self) -> JsonObject:
        return {
            "schema_version": self.schema_version,
            "pack_id": self.pack_id,
            "output_root": self.output_root,
            "generated_at": self.generated_at,
            "profile": self.profile,
            "tag": self.tag,
            "passed": self.passed(),
            "artifact_count": len(self.artifacts),
            "artifacts": [item.to_dict() for item in self.artifacts],
            "diagnostic_counts": summarize_diagnostics(self.diagnostics),
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class BaselineRow:
    algorithm: str
    operation: str
    parameter_set: str
    implementation: str
    board: str
    profile: str
    metric: str
    statistic: str
    value: float
    unit: str
    source: str
    row_number: int
    extra: JsonObject = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: JsonObject, row_number: int) -> "BaselineRow":
        def get(*names: str, default: str = "") -> str:
            for name in names:
                value = raw.get(name)
                if value not in (None, ""):
                    return str(value)
            return default

        value_text = get("value", "median", "candidate_value", "baseline_value", default="nan")
        try:
            numeric = float(value_text)
        except ValueError:
            numeric = float("nan")
        known = {
            "algorithm", "alg", "operation", "op", "parameter_set", "parameter", "level",
            "implementation", "impl", "board", "target", "profile", "metric", "statistic",
            "stat", "value", "median", "unit", "source", "source_url",
        }
        extra = {key: value for key, value in raw.items() if key not in known and value not in (None, "")}
        return cls(
            algorithm=get("algorithm", "alg"),
            operation=get("operation", "op"),
            parameter_set=get("parameter_set", "parameter", "level"),
            implementation=get("implementation", "impl"),
            board=get("board", "target"),
            profile=get("profile"),
            metric=get("metric"),
            statistic=get("statistic", "stat", default="median"),
            value=numeric,
            unit=get("unit"),
            source=get("source", "source_url"),
            row_number=row_number,
            extra=extra,
        )

    def key(self) -> tuple[str, str, str, str, str, str, str, str]:
        return (
            self.algorithm,
            self.operation,
            self.parameter_set,
            self.implementation,
            self.board,
            self.profile,
            self.metric,
            self.statistic,
        )

    def comparison_key(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.algorithm,
            self.operation,
            self.parameter_set,
            self.board,
            self.profile,
            self.metric,
        )

    def to_dict(self) -> JsonObject:
        return {
            "algorithm": self.algorithm,
            "operation": self.operation,
            "parameter_set": self.parameter_set,
            "implementation": self.implementation,
            "board": self.board,
            "profile": self.profile,
            "metric": self.metric,
            "statistic": self.statistic,
            "value": self.value,
            "unit": self.unit,
            "source": self.source,
            "row_number": self.row_number,
            "extra": self.extra,
        }


@dataclass(frozen=True)
class ComparisonResult:
    key: tuple[str, ...]
    candidate: BaselineRow | None
    baseline: BaselineRow | None
    ratio: float | None
    status: str
    threshold: float
    diagnostics: tuple[Diagnostic, ...] = ()

    def to_dict(self) -> JsonObject:
        return {
            "key": list(self.key),
            "candidate": self.candidate.to_dict() if self.candidate else None,
            "baseline": self.baseline.to_dict() if self.baseline else None,
            "ratio": self.ratio,
            "status": self.status,
            "threshold": self.threshold,
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }


@dataclass(frozen=True)
class BaselineComparisonReport:
    schema_version: int
    generated_at: str
    candidate_csv: str
    baseline_csv: str
    threshold: float
    results: tuple[ComparisonResult, ...]
    diagnostics: tuple[Diagnostic, ...]

    def passed(self) -> bool:
        return not any(item.is_error for item in self.diagnostics) and all(
            item.status in {"pass", "candidate_missing_allowed"} for item in self.results
        )

    def to_dict(self) -> JsonObject:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "candidate_csv": self.candidate_csv,
            "baseline_csv": self.baseline_csv,
            "threshold": self.threshold,
            "passed": self.passed(),
            "result_count": len(self.results),
            "results": [item.to_dict() for item in self.results],
            "diagnostic_counts": summarize_diagnostics(self.diagnostics),
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }


@dataclass(frozen=True)
class ReproducibilitySnapshot:
    schema_version: int
    generated_at: str
    module_path: str
    python_executable: str
    python_version: str
    platform: str
    git_head: str | None
    git_dirty: bool | None
    required_scripts: tuple[str, ...]
    missing_scripts: tuple[str, ...]
    environment: JsonObject

    def passed(self) -> bool:
        return not self.missing_scripts

    def to_dict(self) -> JsonObject:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "module_path": self.module_path,
            "python_executable": self.python_executable,
            "python_version": self.python_version,
            "platform": self.platform,
            "git_head": self.git_head,
            "git_dirty": self.git_dirty,
            "required_scripts": list(self.required_scripts),
            "missing_scripts": list(self.missing_scripts),
            "environment": self.environment,
            "passed": self.passed(),
        }


def rows_to_dicts(rows: Iterable[BaselineRow]) -> list[JsonObject]:
    return [row.to_dict() for row in rows]
