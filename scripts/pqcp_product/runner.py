#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Experiment planning and execution with transcript capture."""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from pathlib import Path

from .errors import CommandExecutionError, Diagnostic, error, warning
from .fs import deterministic_slug, sha256_text, utc_now, write_command_transcript, write_json_atomic
from .models import CommandPlan, CommandResult, ExperimentSelection, RunManifest
from .reproducibility import capture_reproducibility_snapshot


class ExperimentRunner:
    """Plan and run catalog experiments with deterministic output layout."""

    def __init__(self, module_path: Path):
        self.module_path = module_path.resolve()

    def build_plans(
        self,
        selection: ExperimentSelection,
        output_root: Path,
        *,
        dry_run: bool,
        timeout_seconds: int,
    ) -> tuple[CommandPlan, ...]:
        plans: list[CommandPlan] = []
        for experiment in selection.experiments:
            experiment_dir = output_root / "experiments" / deterministic_slug(experiment.id)
            transcript_dir = experiment_dir / "transcripts"
            for index, command in enumerate(experiment.commands):
                transcript_path = transcript_dir / f"command-{index:03d}.log"
                plans.append(
                    CommandPlan(
                        experiment_id=experiment.id,
                        command_index=index,
                        command=command,
                        cwd=str(self.module_path),
                        timeout_seconds=timeout_seconds,
                        transcript_path=str(transcript_path),
                        dry_run=dry_run,
                    )
                )
        return tuple(plans)

    def run(
        self,
        selection: ExperimentSelection,
        output_root: Path,
        *,
        dry_run: bool = True,
        timeout_seconds: int = 300,
        run_id: str | None = None,
    ) -> RunManifest:
        output_root = output_root.resolve()
        output_root.mkdir(parents=True, exist_ok=True)
        started_at = utc_now()
        run_id = run_id or f"pqcp-{int(time.time())}-{sha256_text('|'.join(selection.ids()))[:10]}"
        plans = self.build_plans(selection, output_root, dry_run=dry_run, timeout_seconds=timeout_seconds)
        diagnostics: list[Diagnostic] = []
        for experiment in selection.experiments:
            missing = experiment.missing_inputs(self.module_path)
            for item in missing:
                diagnostics.append(error("experiment_missing_input", f"{experiment.id}:{item}", "input does not exist"))
        results: list[CommandResult] = []
        for plan in plans:
            if dry_run:
                results.append(self._planned_result(plan))
            else:
                results.append(self._execute_plan(plan, diagnostics))
        snapshot = capture_reproducibility_snapshot(self.module_path)
        manifest = RunManifest(
            schema_version=1,
            run_id=run_id,
            output_root=str(output_root),
            module_path=str(self.module_path),
            dry_run=dry_run,
            started_at=started_at,
            finished_at=utc_now(),
            selection=selection,
            plans=plans,
            results=tuple(results),
            diagnostics=tuple(diagnostics),
            metadata={"reproducibility": snapshot.to_dict()},
        )
        write_json_atomic(output_root / "run-manifest.json", manifest.to_dict())
        return manifest

    def _planned_result(self, plan: CommandPlan) -> CommandResult:
        now = utc_now()
        transcript_path = Path(plan.transcript_path)
        transcript_hash = write_command_transcript(transcript_path, plan.command, "DRY RUN: command not executed\n", "", 0)
        return CommandResult(
            plan=plan,
            returncode=0,
            stdout_sha256=sha256_text("DRY RUN: command not executed\n"),
            stderr_sha256=sha256_text(""),
            transcript_sha256=transcript_hash,
            duration_seconds=0.0,
            status="planned",
            started_at=now,
            finished_at=now,
        )

    def _execute_plan(self, plan: CommandPlan, diagnostics: list[Diagnostic]) -> CommandResult:
        started = utc_now()
        begin = time.monotonic()
        stdout = ""
        stderr = ""
        returncode = 1
        status = "fail"
        try:
            completed = subprocess.run(
                plan.command,
                cwd=plan.cwd,
                shell=True,
                text=True,
                capture_output=True,
                timeout=plan.timeout_seconds,
                check=False,
                env=self._command_env(),
            )
            stdout = completed.stdout
            stderr = completed.stderr
            returncode = completed.returncode
            status = "pass" if completed.returncode == 0 else "fail"
            if completed.returncode != 0:
                diagnostics.append(error("command_failed", plan.experiment_id, f"command exited {completed.returncode}"))
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = (exc.stderr or "") + f"\nTIMEOUT after {plan.timeout_seconds} seconds\n"
            returncode = 124
            status = "timeout"
            diagnostics.append(error("command_timeout", plan.experiment_id, f"command exceeded {plan.timeout_seconds} seconds"))
        except OSError as exc:
            stderr = str(exc)
            returncode = 127
            status = "error"
            diagnostics.append(error("command_os_error", plan.experiment_id, str(exc)))
        duration = time.monotonic() - begin
        transcript_hash = write_command_transcript(Path(plan.transcript_path), plan.command, stdout, stderr, returncode)
        return CommandResult(
            plan=plan,
            returncode=returncode,
            stdout_sha256=sha256_text(stdout),
            stderr_sha256=sha256_text(stderr),
            transcript_sha256=transcript_hash,
            duration_seconds=duration,
            status=status,
            started_at=started,
            finished_at=utc_now(),
        )

    def _command_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env.setdefault("PYTHONUNBUFFERED", "1")
        env.setdefault("PQCP_PRODUCT_TOOL", "1")
        return env


def shell_words(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError as exc:
        raise CommandExecutionError(f"cannot parse command: {command}") from exc
