#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Error types and diagnostics for the PQCP product evidence toolkit."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Diagnostic:
    """A structured problem found while validating or executing evidence work."""

    severity: str
    code: str
    location: str
    message: str
    hint: str | None = None

    def to_dict(self) -> dict[str, str]:
        payload = {
            "severity": self.severity,
            "code": self.code,
            "location": self.location,
            "message": self.message,
        }
        if self.hint:
            payload["hint"] = self.hint
        return payload

    @property
    def is_error(self) -> bool:
        return self.severity == "error"

    @property
    def is_warning(self) -> bool:
        return self.severity == "warning"


def error(code: str, location: str, message: str, hint: str | None = None) -> Diagnostic:
    return Diagnostic("error", code, location, message, hint)


def warning(code: str, location: str, message: str, hint: str | None = None) -> Diagnostic:
    return Diagnostic("warning", code, location, message, hint)


def info(code: str, location: str, message: str, hint: str | None = None) -> Diagnostic:
    return Diagnostic("info", code, location, message, hint)


def has_errors(diagnostics: Iterable[Diagnostic]) -> bool:
    return any(item.is_error for item in diagnostics)


def summarize_diagnostics(diagnostics: Iterable[Diagnostic]) -> dict[str, int]:
    summary = {"error": 0, "warning": 0, "info": 0}
    for item in diagnostics:
        summary[item.severity] = summary.get(item.severity, 0) + 1
    return summary


class ProductEvidenceError(RuntimeError):
    """Base error for CLI-friendly product evidence failures."""

    exit_code = 1

    def __init__(self, message: str, diagnostics: Iterable[Diagnostic] | None = None):
        super().__init__(message)
        self.message = message
        self.diagnostics = tuple(diagnostics or ())

    def to_dict(self) -> dict[str, object]:
        return {
            "error": self.message,
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "summary": summarize_diagnostics(self.diagnostics),
        }

    def format_for_console(self) -> str:
        lines = [self.message]
        for item in self.diagnostics:
            lines.append(f"{item.severity.upper()} {item.code} {item.location}: {item.message}")
            if item.hint:
                lines.append(f"  hint: {item.hint}")
        return "\n".join(lines)


class CatalogError(ProductEvidenceError):
    """Raised when the experiment catalog cannot be loaded or validated."""


class EvidencePackError(ProductEvidenceError):
    """Raised when evidence pack construction or replay fails."""


class BaselineComparisonError(ProductEvidenceError):
    """Raised when benchmark CSV comparison inputs are malformed."""


class CommandExecutionError(ProductEvidenceError):
    """Raised when an experiment command cannot be planned or executed."""


class ConfigurationError(ProductEvidenceError):
    """Raised when a user-provided configuration is inconsistent."""


ERROR_HELP = {
    "catalog_missing": "Pass --catalog or run from a checkout containing scripts/research_experiment_catalog.json.",
    "catalog_invalid_json": "Fix the JSON syntax before attempting experiment selection.",
    "experiment_missing_input": "Every experiment must reference repository files that exist in this checkout.",
    "command_timeout": "Increase --timeout or split the experiment into a smaller profile.",
    "artifact_missing": "Generate the artifact or mark it explicitly not applicable in the source validator.",
    "hash_mismatch": "Regenerate the evidence pack after changing artifacts.",
    "baseline_missing_pair": "Provide matching algorithm/operation/parameter rows in both CSV files.",
    "regression_detected": "Inspect the candidate output and keep the previous baseline until a measured win is reproduced.",
}


def hint_for(code: str) -> str | None:
    return ERROR_HELP.get(code)


def require_no_errors(message: str, diagnostics: Iterable[Diagnostic]) -> None:
    collected = tuple(diagnostics)
    if has_errors(collected):
        raise ProductEvidenceError(message, collected)
