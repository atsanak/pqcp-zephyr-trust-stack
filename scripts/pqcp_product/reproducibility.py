#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Reproducibility snapshots and manifest sanity checks."""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

from .fs import utc_now
from .models import ReproducibilitySnapshot

REQUIRED_SCRIPTS = (
    "scripts/release_check.py",
    "scripts/run_extended_checks.py",
    "scripts/generate_assurance_ledger.py",
    "scripts/verify_release_evidence_pack.py",
    "scripts/research_experiment_catalog.json",
    "scripts/pqcp_tool.py",
)


def git_text(module_path: Path, args: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=str(module_path),
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def git_head(module_path: Path) -> str | None:
    return git_text(module_path, ["rev-parse", "HEAD"])


def git_dirty(module_path: Path) -> bool | None:
    status = git_text(module_path, ["status", "--short"])
    if status is None:
        return None
    return bool(status.strip())


def capture_reproducibility_snapshot(module_path: Path, required_scripts: tuple[str, ...] = REQUIRED_SCRIPTS) -> ReproducibilitySnapshot:
    module_path = module_path.resolve()
    missing = tuple(script for script in required_scripts if not (module_path / script).exists())
    environment: dict[str, Any] = {
        "cwd": str(Path.cwd()),
        "path_entries": os.environ.get("PATH", "").split(os.pathsep),
        "west_available": bool(_which("west")),
        "doxygen_available": bool(_which("doxygen")),
        "cmake_available": bool(_which("cmake")),
    }
    return ReproducibilitySnapshot(
        schema_version=1,
        generated_at=utc_now(),
        module_path=str(module_path),
        python_executable=sys.executable,
        python_version=sys.version.replace("\n", " "),
        platform=platform.platform(),
        git_head=git_head(module_path),
        git_dirty=git_dirty(module_path),
        required_scripts=required_scripts,
        missing_scripts=missing,
        environment=environment,
    )


def _which(name: str) -> str | None:
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        path = Path(entry) / name
        if path.exists() and os.access(path, os.X_OK):
            return str(path)
    return None


def validate_manifest_replay(payload: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for key in ("schema_version", "run_id", "output_root", "selection", "plans", "results"):
        if key not in payload:
            failures.append(f"run manifest missing {key}")
    if payload.get("schema_version") != 1:
        failures.append("run manifest schema_version must be 1")
    if not isinstance(payload.get("plans", []), list):
        failures.append("run manifest plans must be a list")
    if not isinstance(payload.get("results", []), list):
        failures.append("run manifest results must be a list")
    for index, result in enumerate(payload.get("results", [])):
        if "transcript_sha256" not in result:
            failures.append(f"result {index} missing transcript_sha256")
        if result.get("status") not in {"pass", "fail", "timeout", "error", "planned"}:
            failures.append(f"result {index} has invalid status {result.get('status')!r}")
    return failures
