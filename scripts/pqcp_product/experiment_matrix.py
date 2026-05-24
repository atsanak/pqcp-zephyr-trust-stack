#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Executable experiment readiness matrix for product/research evidence planning."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import Diagnostic, error, warning
from .fs import json_digest
from .models import ExperimentSpec


@dataclass(frozen=True)
class ExperimentReadiness:
    experiment_id: str
    category: str
    required_inputs: tuple[str, ...]
    required_outputs: tuple[str, ...]
    commands: tuple[str, ...]
    replay_ready: bool
    falsification_ready: bool
    schema_ready: bool
    hardware_sensitive: bool
    ci_safe: bool
    evidence_score: int
    risk_tags: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "category": self.category,
            "required_inputs": list(self.required_inputs),
            "required_outputs": list(self.required_outputs),
            "commands": list(self.commands),
            "replay_ready": self.replay_ready,
            "falsification_ready": self.falsification_ready,
            "schema_ready": self.schema_ready,
            "hardware_sensitive": self.hardware_sensitive,
            "ci_safe": self.ci_safe,
            "evidence_score": self.evidence_score,
            "risk_tags": list(self.risk_tags),
        }


def _has_replay_command(commands: tuple[str, ...]) -> bool:
    return any("verify" in command or "validate" in command or "--help" in command for command in commands)

def _has_schema_output(outputs: tuple[str, ...]) -> bool:
    return any(output.endswith(".json") or "schema" in output or "manifest" in output for output in outputs)

def _has_negative_action(text: str) -> bool:
    lower = text.lower()
    return any(word in lower for word in ("remove", "corrupt", "tamper", "invalid", "malformed", "stale", "missing", "duplicate"))

def _risk_tags(experiment: ExperimentSpec) -> tuple[str, ...]:
    tags: list[str] = []
    body = " ".join([experiment.id, experiment.category, experiment.objective, *experiment.commands, *experiment.expected_outputs]).lower()
    if "hardware" in body or "board" in body:
        tags.append("hardware")
    if "benchmark" in body or "metric" in body:
        tags.append("benchmark")
    if "acvp" in body:
        tags.append("interop")
    if "side" in body or "ct" in body:
        tags.append("side_channel_smoke")
    if "release" in body or "tag" in body:
        tags.append("release")
    if "policy" in body:
        tags.append("policy")
    if "transcript" in body or "hash" in body:
        tags.append("transcript_bound")
    return tuple(sorted(set(tags)))

def _score(experiment: ExperimentSpec, replay_ready: bool, falsification_ready: bool, schema_ready: bool) -> int:
    score = 0
    score += 20 if replay_ready else 0
    score += 20 if falsification_ready else 0
    score += 15 if schema_ready else 0
    score += min(len(experiment.repository_inputs), 5) * 3
    score += min(len(experiment.commands), 4) * 4
    score += min(len(experiment.expected_outputs), 5) * 3
    score += min(len(experiment.acceptance_criteria), 6) * 2
    return score

def _ci_safe(experiment: ExperimentSpec) -> bool:
    text = " ".join([experiment.category, *experiment.commands, *experiment.expected_outputs]).lower()
    if "hardware" in text or "nucleo" in text:
        return False
    if "west build" in text and "--help" not in text:
        return False
    return True

def readiness_claim_release_version_consistency(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.release_version_consistency."""
    expected_id = 'claim.release_version_consistency'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_release_tag_integrity(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.release_tag_integrity."""
    expected_id = 'claim.release_tag_integrity'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_kat_offline_provenance(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.kat_offline_provenance."""
    expected_id = 'claim.kat_offline_provenance'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_kat_mlkem_512(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.kat_mlkem_512."""
    expected_id = 'claim.kat_mlkem_512'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_kat_mlkem_768(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.kat_mlkem_768."""
    expected_id = 'claim.kat_mlkem_768'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_kat_mlkem_1024(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.kat_mlkem_1024."""
    expected_id = 'claim.kat_mlkem_1024'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_kat_mldsa_44(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.kat_mldsa_44."""
    expected_id = 'claim.kat_mldsa_44'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_kat_mldsa_65(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.kat_mldsa_65."""
    expected_id = 'claim.kat_mldsa_65'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_kat_mldsa_87(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.kat_mldsa_87."""
    expected_id = 'claim.kat_mldsa_87'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_benchmark_csv_validity(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.benchmark_csv_validity."""
    expected_id = 'claim.benchmark_csv_validity'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_benchmark_provenance_binding(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.benchmark_provenance_binding."""
    expected_id = 'claim.benchmark_provenance_binding'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_benchmark_mlkem_throughput(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.benchmark_mlkem_throughput."""
    expected_id = 'claim.benchmark_mlkem_throughput'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_benchmark_mldsa_throughput(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.benchmark_mldsa_throughput."""
    expected_id = 'claim.benchmark_mldsa_throughput'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_benchmark_distribution_quality(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.benchmark_distribution_quality."""
    expected_id = 'claim.benchmark_distribution_quality'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_cost_of_assurance_guardrails(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.cost_of_assurance_guardrails."""
    expected_id = 'claim.cost_of_assurance_guardrails'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_release_local_bundle(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.release_local_bundle."""
    expected_id = 'claim.release_local_bundle'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_release_transcript_binding(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.release_transcript_binding."""
    expected_id = 'claim.release_transcript_binding'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_acvp_negative_path_rejection(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.acvp_negative_path_rejection."""
    expected_id = 'claim.acvp_negative_path_rejection'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_acvp_timeout_recovery(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.acvp_timeout_recovery."""
    expected_id = 'claim.acvp_timeout_recovery'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_acvp_negative_scenarios_replay(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.acvp_negative_scenarios_replay."""
    expected_id = 'claim.acvp_negative_scenarios_replay'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_acvp_mlkem_negative_paths(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.acvp_mlkem_negative_paths."""
    expected_id = 'claim.acvp_mlkem_negative_paths'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_acvp_mldsa_negative_paths(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.acvp_mldsa_negative_paths."""
    expected_id = 'claim.acvp_mldsa_negative_paths'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_acvp_negative_scenario_floor(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.acvp_negative_scenario_floor."""
    expected_id = 'claim.acvp_negative_scenario_floor'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_security_asan_clean(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.security_asan_clean."""
    expected_id = 'claim.security_asan_clean'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_security_ubsan_clean(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.security_ubsan_clean."""
    expected_id = 'claim.security_ubsan_clean'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_boot_kat_self_verify(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.boot_kat_self_verify."""
    expected_id = 'claim.boot_kat_self_verify'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_security_ct_smoke(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.security_ct_smoke."""
    expected_id = 'claim.security_ct_smoke'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_security_mlkem_decap_instruction_policy(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.security_mlkem_decap_instruction_policy."""
    expected_id = 'claim.security_mlkem_decap_instruction_policy'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_supply_chain_cbom_crypto_inventory(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.supply_chain_cbom_crypto_inventory."""
    expected_id = 'claim.supply_chain_cbom_crypto_inventory'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_supply_chain_pqc_assurance_attestation(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.supply_chain_pqc_assurance_attestation."""
    expected_id = 'claim.supply_chain_pqc_assurance_attestation'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_supply_chain_crypto_asset_traceability(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.supply_chain_crypto_asset_traceability."""
    expected_id = 'claim.supply_chain_crypto_asset_traceability'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_supply_chain_evidence_graph_integrity(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.supply_chain_evidence_graph_integrity."""
    expected_id = 'claim.supply_chain_evidence_graph_integrity'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_release_policy_pass(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.release_policy_pass."""
    expected_id = 'claim.release_policy_pass'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_firmware_assurance_digest_manifest(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.firmware_assurance_digest_manifest."""
    expected_id = 'claim.firmware_assurance_digest_manifest'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_firmware_assurance_digest_embeddable(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.firmware_assurance_digest_embeddable."""
    expected_id = 'claim.firmware_assurance_digest_embeddable'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_supply_chain_assurance_profile_policy(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.supply_chain_assurance_profile_policy."""
    expected_id = 'claim.supply_chain_assurance_profile_policy'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_supply_chain_evidence_quality_index(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.supply_chain_evidence_quality_index."""
    expected_id = 'claim.supply_chain_evidence_quality_index'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_crypto_agility_profile_separation(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.crypto_agility_profile_separation."""
    expected_id = 'claim.crypto_agility_profile_separation'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_release_migration_readiness(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.release_migration_readiness."""
    expected_id = 'claim.release_migration_readiness'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_security_production_rng_policy(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.security_production_rng_policy."""
    expected_id = 'claim.security_production_rng_policy'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_release_reference_values(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.release_reference_values."""
    expected_id = 'claim.release_reference_values'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_firmware_assurance_status_report(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.firmware_assurance_status_report."""
    expected_id = 'claim.firmware_assurance_status_report'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_acvp_json_interop(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.acvp_json_interop."""
    expected_id = 'claim.acvp_json_interop'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_supply_chain_slsa_build_provenance(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.supply_chain_slsa_build_provenance."""
    expected_id = 'claim.supply_chain_slsa_build_provenance'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_security_ct_sample_analysis(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.security_ct_sample_analysis."""
    expected_id = 'claim.security_ct_sample_analysis'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_release_evidence_appraisal_profile(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.release_evidence_appraisal_profile."""
    expected_id = 'claim.release_evidence_appraisal_profile'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_supply_chain_backend_update_evaluation(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.supply_chain_backend_update_evaluation."""
    expected_id = 'claim.supply_chain_backend_update_evaluation'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_benchmark_campaign_reproducibility(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.benchmark_campaign_reproducibility."""
    expected_id = 'claim.benchmark_campaign_reproducibility'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_benchmark_external_reference_context(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.benchmark_external_reference_context."""
    expected_id = 'claim.benchmark_external_reference_context'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_security_ct_campaign_analysis(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.security_ct_campaign_analysis."""
    expected_id = 'claim.security_ct_campaign_analysis'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_acvp_json_schema_coverage(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.acvp_json_schema_coverage."""
    expected_id = 'claim.acvp_json_schema_coverage'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_firmware_device_evidence_token(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.firmware_device_evidence_token."""
    expected_id = 'claim.firmware_device_evidence_token'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_release_strict_partner_policy(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.release_strict_partner_policy."""
    expected_id = 'claim.release_strict_partner_policy'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_supply_chain_backend_contract(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.supply_chain_backend_contract."""
    expected_id = 'claim.supply_chain_backend_contract'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_supply_chain_liboqs_non_native_scope(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.supply_chain_liboqs_non_native_scope."""
    expected_id = 'claim.supply_chain_liboqs_non_native_scope'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_benchmark_paper_comparison_export(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.benchmark_paper_comparison_export."""
    expected_id = 'claim.benchmark_paper_comparison_export'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_claim_release_reference_provider_scope(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for claim.release_reference_provider_scope."""
    expected_id = 'claim.release_reference_provider_scope'
    expected_category = 'claim_replay'
    required_inputs = ('scripts/assurance_claims.json', 'scripts/generate_assurance_ledger.py', 'scripts/verify_assurance_policy.py', 'scripts/verify_release_evidence_pack.py')
    required_outputs = ('assurance_ledger.json', 'pqc_policy_result.json', 'release replay failure naming the affected claim')
    required_commands = ('python3 scripts/generate_assurance_ledger.py --help', 'python3 scripts/verify_release_evidence_pack.py --help')
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_asset_crypto_mlkem_512(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for asset.crypto_mlkem_512."""
    expected_id = 'asset.crypto_mlkem_512'
    expected_category = 'asset_traceability'
    required_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mlkem.h', 'src/mlkem_zephyr.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_acvp_kat/src/main.c', 'tests/ztest_ct_smoke/src/main.c', 'scripts/verify_ct_instruction_policy.py')
    required_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    required_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_asset_crypto_mlkem_768(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for asset.crypto_mlkem_768."""
    expected_id = 'asset.crypto_mlkem_768'
    expected_category = 'asset_traceability'
    required_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mlkem.h', 'src/mlkem_zephyr.c', 'src/psa_mlkem_driver.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_ct_smoke/src/main.c', 'tests/ztest_primitive/src/main.c', 'scripts/verify_ct_instruction_policy.py')
    required_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    required_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_asset_crypto_mlkem_1024(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for asset.crypto_mlkem_1024."""
    expected_id = 'asset.crypto_mlkem_1024'
    expected_category = 'asset_traceability'
    required_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mlkem.h', 'src/mlkem_zephyr.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_acvp_kat/src/main.c', 'tests/ztest_ct_smoke/src/main.c', 'scripts/verify_ct_instruction_policy.py')
    required_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    required_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_asset_crypto_mldsa_44(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for asset.crypto_mldsa_44."""
    expected_id = 'asset.crypto_mldsa_44'
    expected_category = 'asset_traceability'
    required_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mldsa.h', 'src/mldsa_zephyr.c', 'src/mldsa_streaming.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_acvp_kat/src/main.c')
    required_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    required_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_asset_crypto_mldsa_65(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for asset.crypto_mldsa_65."""
    expected_id = 'asset.crypto_mldsa_65'
    expected_category = 'asset_traceability'
    required_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mldsa.h', 'src/mldsa_zephyr.c', 'src/mldsa_streaming.c', 'src/psa_mldsa_driver.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_primitive/src/main.c')
    required_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    required_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_asset_crypto_mldsa_87(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for asset.crypto_mldsa_87."""
    expected_id = 'asset.crypto_mldsa_87'
    expected_category = 'asset_traceability'
    required_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/mldsa.h', 'src/mldsa_zephyr.c', 'src/mldsa_streaming.c', 'tests/ztest_acvp_kat/src/kat_vectors.h', 'tests/ztest_acvp_kat/src/main.c')
    required_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    required_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_asset_validation_acvp_serial(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for asset.validation_acvp_serial."""
    expected_id = 'asset.validation_acvp_serial'
    expected_category = 'asset_traceability'
    required_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/acvp_cmd.h', 'src/acvp_cmd.c', 'samples/pqcp_serial_acvp/src/main.c', 'scripts/acvp_negative_scenarios.json', 'scripts/acvp_negative_scenario_floor.json', 'tests/ztest_acvp_serial/src/main.c', 'tests/ztest_acvp_serial_negative/src/main.c')
    required_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    required_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_asset_validation_tls_selftest(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for asset.validation_tls_selftest."""
    expected_id = 'asset.validation_tls_selftest'
    expected_category = 'asset_traceability'
    required_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/tls_selftest.h', 'src/tls_selftest.c', 'samples/pqcp_tls_mbedtls_psa/src/main.c', 'tests/ztest_tls_selftest/src/main.c')
    required_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    required_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_asset_rng_zephyr_entropy(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for asset.rng_zephyr_entropy."""
    expected_id = 'asset.rng_zephyr_entropy'
    expected_category = 'asset_traceability'
    required_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/rng.h', 'src/rng_common.c', 'src/rng_zephyr_entropy.c', 'tests/ztest_rng/src/main.c')
    required_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    required_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_asset_rng_psa(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for asset.rng_psa."""
    expected_id = 'asset.rng_psa'
    expected_category = 'asset_traceability'
    required_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/rng.h', 'src/rng_common.c', 'src/rng_psa.c', 'tests/ztest_rng/src/main.c')
    required_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    required_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_asset_rng_deterministic_test(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for asset.rng_deterministic_test."""
    expected_id = 'asset.rng_deterministic_test'
    expected_category = 'asset_traceability'
    required_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'include/pqcp_zephyr/rng.h', 'src/rng_common.c', 'src/rng_deterministic.c', 'samples/pqcp_kat_deterministic/src/main.c', 'tests/ztest_primitive/src/main.c')
    required_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    required_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_asset_boot_kat_self_verify(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for asset.boot_kat_self_verify."""
    expected_id = 'asset.boot_kat_self_verify'
    expected_category = 'asset_traceability'
    required_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'src/kat_boot_verify.c', 'tests/ztest_kat_boot_verify/src/main.c')
    required_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    required_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_asset_security_ct_smoke(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for asset.security_ct_smoke."""
    expected_id = 'asset.security_ct_smoke'
    expected_category = 'asset_traceability'
    required_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'tests/ztest_ct_smoke/src/main.c', 'scripts/verify_ct_instruction_policy.py')
    required_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    required_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_asset_crypto_slhdsa_external(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for asset.crypto_slhdsa_external."""
    expected_id = 'asset.crypto_slhdsa_external'
    expected_category = 'asset_traceability'
    required_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'scripts/export_liboqs_inventory.py', 'scripts/verify_provider_scope.py')
    required_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    required_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_asset_crypto_hqc_external(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for asset.crypto_hqc_external."""
    expected_id = 'asset.crypto_hqc_external'
    expected_category = 'asset_traceability'
    required_inputs = ('scripts/pqc_asset_trace_map.json', 'scripts/verify_pqc_asset_trace_map.py', 'scripts/export_liboqs_inventory.py', 'scripts/verify_provider_scope.py')
    required_outputs = ('pqc_asset_trace_result.json', 'pqc_evidence_graph.json', 'pqc_cbom.cdx.json')
    required_commands = ('python3 scripts/verify_pqc_asset_trace_map.py --trace-map scripts/pqc_asset_trace_map.json --module-path . --output /tmp/pqcp-asset-trace.json',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_acvp_json_interop_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.acvp_json_interop_result."""
    expected_id = 'artifact.acvp_json_interop_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_acvp_json_schema_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.acvp_json_schema_result."""
    expected_id = 'artifact.acvp_json_schema_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_acvp_json_transcript_manifest(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.acvp_json_transcript_manifest."""
    expected_id = 'artifact.acvp_json_transcript_manifest'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_acvp_negative_scenario_floor_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.acvp_negative_scenario_floor_result."""
    expected_id = 'artifact.acvp_negative_scenario_floor_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_assurance_ledger(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.assurance_ledger."""
    expected_id = 'artifact.assurance_ledger'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_assurance_ledger_markdown(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.assurance_ledger_markdown."""
    expected_id = 'artifact.assurance_ledger_markdown'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_assurance_report_html(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.assurance_report_html."""
    expected_id = 'artifact.assurance_report_html'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_backend_contract_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.backend_contract_result."""
    expected_id = 'artifact.backend_contract_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_backend_update_evaluation(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.backend_update_evaluation."""
    expected_id = 'artifact.backend_update_evaluation'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_benchmark_campaign_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.benchmark_campaign_result."""
    expected_id = 'artifact.benchmark_campaign_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_benchmark_campaign_verify_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.benchmark_campaign_verify_result."""
    expected_id = 'artifact.benchmark_campaign_verify_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_benchmark_confidence_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.benchmark_confidence_result."""
    expected_id = 'artifact.benchmark_confidence_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_benchmark_provenance(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.benchmark_provenance."""
    expected_id = 'artifact.benchmark_provenance'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_benchmark_results_csv(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.benchmark_results_csv."""
    expected_id = 'artifact.benchmark_results_csv'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_benchmark_summary_markdown(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.benchmark_summary_markdown."""
    expected_id = 'artifact.benchmark_summary_markdown'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_cost_of_assurance_evidence(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.cost_of_assurance_evidence."""
    expected_id = 'artifact.cost_of_assurance_evidence'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_ct_campaign_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.ct_campaign_result."""
    expected_id = 'artifact.ct_campaign_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_ct_instruction_policy_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.ct_instruction_policy_result."""
    expected_id = 'artifact.ct_instruction_policy_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_ct_sample_analysis_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.ct_sample_analysis_result."""
    expected_id = 'artifact.ct_sample_analysis_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_device_evidence_token(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.device_evidence_token."""
    expected_id = 'artifact.device_evidence_token'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_device_evidence_token_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.device_evidence_token_result."""
    expected_id = 'artifact.device_evidence_token_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_evidence_tamper_drill_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.evidence_tamper_drill_result."""
    expected_id = 'artifact.evidence_tamper_drill_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_evidence_transcript_manifest(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.evidence_transcript_manifest."""
    expected_id = 'artifact.evidence_transcript_manifest'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_external_non_native_inventory(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.external_non_native_inventory."""
    expected_id = 'artifact.external_non_native_inventory'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_firmware_assurance_status_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.firmware_assurance_status_result."""
    expected_id = 'artifact.firmware_assurance_status_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_firmware_digest_header(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.firmware_digest_header."""
    expected_id = 'artifact.firmware_digest_header'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_mcu_protocol_footprint_csv(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.mcu_protocol_footprint_csv."""
    expected_id = 'artifact.mcu_protocol_footprint_csv'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_paper_comparison_campaign_csv(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.paper_comparison_campaign_csv."""
    expected_id = 'artifact.paper_comparison_campaign_csv'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_paper_comparison_campaign_json(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.paper_comparison_campaign_json."""
    expected_id = 'artifact.paper_comparison_campaign_json'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_partner_review_scorecard(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.partner_review_scorecard."""
    expected_id = 'artifact.partner_review_scorecard'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_partner_review_scorecard_markdown(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.partner_review_scorecard_markdown."""
    expected_id = 'artifact.partner_review_scorecard_markdown'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_partner_review_scorecard_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.partner_review_scorecard_result."""
    expected_id = 'artifact.partner_review_scorecard_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_appraisal_evidence(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_appraisal_evidence."""
    expected_id = 'artifact.pqc_appraisal_evidence'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_appraisal_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_appraisal_result."""
    expected_id = 'artifact.pqc_appraisal_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_asset_trace_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_asset_trace_result."""
    expected_id = 'artifact.pqc_asset_trace_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_assurance_digest(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_assurance_digest."""
    expected_id = 'artifact.pqc_assurance_digest'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_assurance_profile_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_assurance_profile_result."""
    expected_id = 'artifact.pqc_assurance_profile_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_attestation(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_attestation."""
    expected_id = 'artifact.pqc_attestation'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_build_provenance(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_build_provenance."""
    expected_id = 'artifact.pqc_build_provenance'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_build_provenance_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_build_provenance_result."""
    expected_id = 'artifact.pqc_build_provenance_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_cbom(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_cbom."""
    expected_id = 'artifact.pqc_cbom'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_claim_closure_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_claim_closure_result."""
    expected_id = 'artifact.pqc_claim_closure_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_environment_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_environment_result."""
    expected_id = 'artifact.pqc_environment_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_evidence_graph_json(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_evidence_graph_json."""
    expected_id = 'artifact.pqc_evidence_graph_json'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_evidence_graph_markdown(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_evidence_graph_markdown."""
    expected_id = 'artifact.pqc_evidence_graph_markdown'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_evidence_quality_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_evidence_quality_result."""
    expected_id = 'artifact.pqc_evidence_quality_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_migration_readiness_json(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_migration_readiness_json."""
    expected_id = 'artifact.pqc_migration_readiness_json'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_migration_readiness_markdown(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_migration_readiness_markdown."""
    expected_id = 'artifact.pqc_migration_readiness_markdown'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_policy_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_policy_result."""
    expected_id = 'artifact.pqc_policy_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_reference_values(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_reference_values."""
    expected_id = 'artifact.pqc_reference_values'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_pqc_reference_values_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.pqc_reference_values_result."""
    expected_id = 'artifact.pqc_reference_values_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_provider_scope_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.provider_scope_result."""
    expected_id = 'artifact.provider_scope_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_release_manifest(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.release_manifest."""
    expected_id = 'artifact.release_manifest'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_release_notes_markdown(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.release_notes_markdown."""
    expected_id = 'artifact.release_notes_markdown'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_artifact_release_reference_values_result(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for artifact.release_reference_values_result."""
    expected_id = 'artifact.release_reference_values_result'
    expected_category = 'artifact_schema'
    required_inputs = ('schemas/evidence/evidence_schema_catalog.json', 'scripts/validate_evidence_schemas.py', 'scripts/testdata/evidence_schema_pack/product_mvp')
    required_outputs = ('evidence schema validation result', 'schema-specific failure on malformed fixture')
    required_commands = ('python3 scripts/validate_evidence_schemas.py --output-root scripts/testdata/evidence_schema_pack/product_mvp --tag v1.0.0 --profile product_mvp',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_benchmark_paper_comparable_campaign(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for benchmark.paper_comparable_campaign."""
    expected_id = 'benchmark.paper_comparable_campaign'
    expected_category = 'benchmark_methodology'
    required_inputs = ('scripts/run_benchmark_campaign.py',)
    required_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    required_commands = ('python3 scripts/run_benchmark_campaign.py --help',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_benchmark_external_reference_import(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for benchmark.external_reference_import."""
    expected_id = 'benchmark.external_reference_import'
    expected_category = 'benchmark_methodology'
    required_inputs = ('scripts/run_paper_comparison_campaign.py',)
    required_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    required_commands = ('python3 scripts/run_paper_comparison_campaign.py --help',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_acvp_malformed_then_valid_recovery(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for acvp.malformed_then_valid_recovery."""
    expected_id = 'acvp.malformed_then_valid_recovery'
    expected_category = 'acvp_interop'
    required_inputs = ('scripts/run_acvp_json_vectors.py',)
    required_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    required_commands = ('python3 scripts/run_acvp_json_vectors.py --help',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_acvp_operation_schema_coverage(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for acvp.operation_schema_coverage."""
    expected_id = 'acvp.operation_schema_coverage'
    expected_category = 'acvp_interop'
    required_inputs = ('scripts/validate_acvp_json_schema.py',)
    required_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    required_commands = ('python3 scripts/validate_acvp_json_schema.py --help',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_ct_sample_balance(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for ct.sample_balance."""
    expected_id = 'ct.sample_balance'
    expected_category = 'side_channel_smoke'
    required_inputs = ('scripts/analyze_ct_samples.py',)
    required_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    required_commands = ('python3 scripts/analyze_ct_samples.py --help',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_ct_instruction_policy_coverage(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for ct.instruction_policy_coverage."""
    expected_id = 'ct.instruction_policy_coverage'
    expected_category = 'side_channel_smoke'
    required_inputs = ('scripts/verify_ct_instruction_policy.py',)
    required_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    required_commands = ('python3 scripts/verify_ct_instruction_policy.py --help',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_hardware_uart_transcript_capture(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for hardware.uart_transcript_capture."""
    expected_id = 'hardware.uart_transcript_capture'
    expected_category = 'hardware_promotion'
    required_inputs = ('scripts/run_hardware_benchmarks.py',)
    required_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    required_commands = ('python3 scripts/run_hardware_benchmarks.py --help',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_hardware_entropy_source_review(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for hardware.entropy_source_review."""
    expected_id = 'hardware.entropy_source_review'
    expected_category = 'hardware_promotion'
    required_inputs = ('include/pqcp_zephyr/rng.h',)
    required_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    required_commands = ('python3 scripts/run_local_tool_tests.py --list',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_product_cli_release_pack(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for product.cli_release_pack."""
    expected_id = 'product.cli_release_pack'
    expected_category = 'product_packaging'
    required_inputs = ('scripts/verify_product_readiness.py',)
    required_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    required_commands = ('python3 scripts/verify_product_readiness.py --help',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_product_dashboard_ingest_contract(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for product.dashboard_ingest_contract."""
    expected_id = 'product.dashboard_ingest_contract'
    expected_category = 'product_packaging'
    required_inputs = ('docs/evidence-schema-contract.md',)
    required_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    required_commands = ('python3 scripts/run_local_tool_tests.py --list',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_product_customer_policy_overlay(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for product.customer_policy_overlay."""
    expected_id = 'product.customer_policy_overlay'
    expected_category = 'product_packaging'
    required_inputs = ('scripts/pqc_assurance_policy.json',)
    required_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    required_commands = ('python3 scripts/run_local_tool_tests.py --list',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

def readiness_product_signed_pack_readiness(experiment: ExperimentSpec) -> ExperimentReadiness:
    """Build readiness matrix row for product.signed_pack_readiness."""
    expected_id = 'product.signed_pack_readiness'
    expected_category = 'product_packaging'
    required_inputs = ('docs/release.md',)
    required_outputs = ('validated JSON result', 'human-readable remediation note', 'non-zero failure for negative control')
    required_commands = ('python3 scripts/run_local_tool_tests.py --list',)
    commands = tuple(experiment.commands)
    replay_ready = _has_replay_command(commands)
    falsification_ready = _has_negative_action(experiment.negative_control)
    schema_ready = _has_schema_output(tuple(experiment.expected_outputs))
    hardware_sensitive = "hardware" in experiment.category or any("nucleo" in command.lower() for command in commands)
    ci_safe = _ci_safe(experiment)
    score = _score(experiment, replay_ready, falsification_ready, schema_ready)
    tags = _risk_tags(experiment)
    if experiment.id != expected_id:
        score = max(0, score - 40)
    if experiment.category != expected_category:
        score = max(0, score - 20)
    if not set(required_inputs).issubset(set(experiment.repository_inputs)):
        score = max(0, score - 25)
    if not set(required_outputs).issubset(set(experiment.expected_outputs)):
        score = max(0, score - 25)
    if not set(required_commands).issubset(set(commands)):
        score = max(0, score - 25)
    return ExperimentReadiness(
        experiment_id=experiment.id,
        category=experiment.category,
        required_inputs=required_inputs,
        required_outputs=required_outputs,
        commands=required_commands,
        replay_ready=replay_ready,
        falsification_ready=falsification_ready,
        schema_ready=schema_ready,
        hardware_sensitive=hardware_sensitive,
        ci_safe=ci_safe,
        evidence_score=score,
        risk_tags=tags,
    )

READINESS_BUILDERS = {
    'claim.release_version_consistency': readiness_claim_release_version_consistency,
    'claim.release_tag_integrity': readiness_claim_release_tag_integrity,
    'claim.kat_offline_provenance': readiness_claim_kat_offline_provenance,
    'claim.kat_mlkem_512': readiness_claim_kat_mlkem_512,
    'claim.kat_mlkem_768': readiness_claim_kat_mlkem_768,
    'claim.kat_mlkem_1024': readiness_claim_kat_mlkem_1024,
    'claim.kat_mldsa_44': readiness_claim_kat_mldsa_44,
    'claim.kat_mldsa_65': readiness_claim_kat_mldsa_65,
    'claim.kat_mldsa_87': readiness_claim_kat_mldsa_87,
    'claim.benchmark_csv_validity': readiness_claim_benchmark_csv_validity,
    'claim.benchmark_provenance_binding': readiness_claim_benchmark_provenance_binding,
    'claim.benchmark_mlkem_throughput': readiness_claim_benchmark_mlkem_throughput,
    'claim.benchmark_mldsa_throughput': readiness_claim_benchmark_mldsa_throughput,
    'claim.benchmark_distribution_quality': readiness_claim_benchmark_distribution_quality,
    'claim.cost_of_assurance_guardrails': readiness_claim_cost_of_assurance_guardrails,
    'claim.release_local_bundle': readiness_claim_release_local_bundle,
    'claim.release_transcript_binding': readiness_claim_release_transcript_binding,
    'claim.acvp_negative_path_rejection': readiness_claim_acvp_negative_path_rejection,
    'claim.acvp_timeout_recovery': readiness_claim_acvp_timeout_recovery,
    'claim.acvp_negative_scenarios_replay': readiness_claim_acvp_negative_scenarios_replay,
    'claim.acvp_mlkem_negative_paths': readiness_claim_acvp_mlkem_negative_paths,
    'claim.acvp_mldsa_negative_paths': readiness_claim_acvp_mldsa_negative_paths,
    'claim.acvp_negative_scenario_floor': readiness_claim_acvp_negative_scenario_floor,
    'claim.security_asan_clean': readiness_claim_security_asan_clean,
    'claim.security_ubsan_clean': readiness_claim_security_ubsan_clean,
    'claim.boot_kat_self_verify': readiness_claim_boot_kat_self_verify,
    'claim.security_ct_smoke': readiness_claim_security_ct_smoke,
    'claim.security_mlkem_decap_instruction_policy': readiness_claim_security_mlkem_decap_instruction_policy,
    'claim.supply_chain_cbom_crypto_inventory': readiness_claim_supply_chain_cbom_crypto_inventory,
    'claim.supply_chain_pqc_assurance_attestation': readiness_claim_supply_chain_pqc_assurance_attestation,
    'claim.supply_chain_crypto_asset_traceability': readiness_claim_supply_chain_crypto_asset_traceability,
    'claim.supply_chain_evidence_graph_integrity': readiness_claim_supply_chain_evidence_graph_integrity,
    'claim.release_policy_pass': readiness_claim_release_policy_pass,
    'claim.firmware_assurance_digest_manifest': readiness_claim_firmware_assurance_digest_manifest,
    'claim.firmware_assurance_digest_embeddable': readiness_claim_firmware_assurance_digest_embeddable,
    'claim.supply_chain_assurance_profile_policy': readiness_claim_supply_chain_assurance_profile_policy,
    'claim.supply_chain_evidence_quality_index': readiness_claim_supply_chain_evidence_quality_index,
    'claim.crypto_agility_profile_separation': readiness_claim_crypto_agility_profile_separation,
    'claim.release_migration_readiness': readiness_claim_release_migration_readiness,
    'claim.security_production_rng_policy': readiness_claim_security_production_rng_policy,
    'claim.release_reference_values': readiness_claim_release_reference_values,
    'claim.firmware_assurance_status_report': readiness_claim_firmware_assurance_status_report,
    'claim.acvp_json_interop': readiness_claim_acvp_json_interop,
    'claim.supply_chain_slsa_build_provenance': readiness_claim_supply_chain_slsa_build_provenance,
    'claim.security_ct_sample_analysis': readiness_claim_security_ct_sample_analysis,
    'claim.release_evidence_appraisal_profile': readiness_claim_release_evidence_appraisal_profile,
    'claim.supply_chain_backend_update_evaluation': readiness_claim_supply_chain_backend_update_evaluation,
    'claim.benchmark_campaign_reproducibility': readiness_claim_benchmark_campaign_reproducibility,
    'claim.benchmark_external_reference_context': readiness_claim_benchmark_external_reference_context,
    'claim.security_ct_campaign_analysis': readiness_claim_security_ct_campaign_analysis,
    'claim.acvp_json_schema_coverage': readiness_claim_acvp_json_schema_coverage,
    'claim.firmware_device_evidence_token': readiness_claim_firmware_device_evidence_token,
    'claim.release_strict_partner_policy': readiness_claim_release_strict_partner_policy,
    'claim.supply_chain_backend_contract': readiness_claim_supply_chain_backend_contract,
    'claim.supply_chain_liboqs_non_native_scope': readiness_claim_supply_chain_liboqs_non_native_scope,
    'claim.benchmark_paper_comparison_export': readiness_claim_benchmark_paper_comparison_export,
    'claim.release_reference_provider_scope': readiness_claim_release_reference_provider_scope,
    'asset.crypto_mlkem_512': readiness_asset_crypto_mlkem_512,
    'asset.crypto_mlkem_768': readiness_asset_crypto_mlkem_768,
    'asset.crypto_mlkem_1024': readiness_asset_crypto_mlkem_1024,
    'asset.crypto_mldsa_44': readiness_asset_crypto_mldsa_44,
    'asset.crypto_mldsa_65': readiness_asset_crypto_mldsa_65,
    'asset.crypto_mldsa_87': readiness_asset_crypto_mldsa_87,
    'asset.validation_acvp_serial': readiness_asset_validation_acvp_serial,
    'asset.validation_tls_selftest': readiness_asset_validation_tls_selftest,
    'asset.rng_zephyr_entropy': readiness_asset_rng_zephyr_entropy,
    'asset.rng_psa': readiness_asset_rng_psa,
    'asset.rng_deterministic_test': readiness_asset_rng_deterministic_test,
    'asset.boot_kat_self_verify': readiness_asset_boot_kat_self_verify,
    'asset.security_ct_smoke': readiness_asset_security_ct_smoke,
    'asset.crypto_slhdsa_external': readiness_asset_crypto_slhdsa_external,
    'asset.crypto_hqc_external': readiness_asset_crypto_hqc_external,
    'artifact.acvp_json_interop_result': readiness_artifact_acvp_json_interop_result,
    'artifact.acvp_json_schema_result': readiness_artifact_acvp_json_schema_result,
    'artifact.acvp_json_transcript_manifest': readiness_artifact_acvp_json_transcript_manifest,
    'artifact.acvp_negative_scenario_floor_result': readiness_artifact_acvp_negative_scenario_floor_result,
    'artifact.assurance_ledger': readiness_artifact_assurance_ledger,
    'artifact.assurance_ledger_markdown': readiness_artifact_assurance_ledger_markdown,
    'artifact.assurance_report_html': readiness_artifact_assurance_report_html,
    'artifact.backend_contract_result': readiness_artifact_backend_contract_result,
    'artifact.backend_update_evaluation': readiness_artifact_backend_update_evaluation,
    'artifact.benchmark_campaign_result': readiness_artifact_benchmark_campaign_result,
    'artifact.benchmark_campaign_verify_result': readiness_artifact_benchmark_campaign_verify_result,
    'artifact.benchmark_confidence_result': readiness_artifact_benchmark_confidence_result,
    'artifact.benchmark_provenance': readiness_artifact_benchmark_provenance,
    'artifact.benchmark_results_csv': readiness_artifact_benchmark_results_csv,
    'artifact.benchmark_summary_markdown': readiness_artifact_benchmark_summary_markdown,
    'artifact.cost_of_assurance_evidence': readiness_artifact_cost_of_assurance_evidence,
    'artifact.ct_campaign_result': readiness_artifact_ct_campaign_result,
    'artifact.ct_instruction_policy_result': readiness_artifact_ct_instruction_policy_result,
    'artifact.ct_sample_analysis_result': readiness_artifact_ct_sample_analysis_result,
    'artifact.device_evidence_token': readiness_artifact_device_evidence_token,
    'artifact.device_evidence_token_result': readiness_artifact_device_evidence_token_result,
    'artifact.evidence_tamper_drill_result': readiness_artifact_evidence_tamper_drill_result,
    'artifact.evidence_transcript_manifest': readiness_artifact_evidence_transcript_manifest,
    'artifact.external_non_native_inventory': readiness_artifact_external_non_native_inventory,
    'artifact.firmware_assurance_status_result': readiness_artifact_firmware_assurance_status_result,
    'artifact.firmware_digest_header': readiness_artifact_firmware_digest_header,
    'artifact.mcu_protocol_footprint_csv': readiness_artifact_mcu_protocol_footprint_csv,
    'artifact.paper_comparison_campaign_csv': readiness_artifact_paper_comparison_campaign_csv,
    'artifact.paper_comparison_campaign_json': readiness_artifact_paper_comparison_campaign_json,
    'artifact.partner_review_scorecard': readiness_artifact_partner_review_scorecard,
    'artifact.partner_review_scorecard_markdown': readiness_artifact_partner_review_scorecard_markdown,
    'artifact.partner_review_scorecard_result': readiness_artifact_partner_review_scorecard_result,
    'artifact.pqc_appraisal_evidence': readiness_artifact_pqc_appraisal_evidence,
    'artifact.pqc_appraisal_result': readiness_artifact_pqc_appraisal_result,
    'artifact.pqc_asset_trace_result': readiness_artifact_pqc_asset_trace_result,
    'artifact.pqc_assurance_digest': readiness_artifact_pqc_assurance_digest,
    'artifact.pqc_assurance_profile_result': readiness_artifact_pqc_assurance_profile_result,
    'artifact.pqc_attestation': readiness_artifact_pqc_attestation,
    'artifact.pqc_build_provenance': readiness_artifact_pqc_build_provenance,
    'artifact.pqc_build_provenance_result': readiness_artifact_pqc_build_provenance_result,
    'artifact.pqc_cbom': readiness_artifact_pqc_cbom,
    'artifact.pqc_claim_closure_result': readiness_artifact_pqc_claim_closure_result,
    'artifact.pqc_environment_result': readiness_artifact_pqc_environment_result,
    'artifact.pqc_evidence_graph_json': readiness_artifact_pqc_evidence_graph_json,
    'artifact.pqc_evidence_graph_markdown': readiness_artifact_pqc_evidence_graph_markdown,
    'artifact.pqc_evidence_quality_result': readiness_artifact_pqc_evidence_quality_result,
    'artifact.pqc_migration_readiness_json': readiness_artifact_pqc_migration_readiness_json,
    'artifact.pqc_migration_readiness_markdown': readiness_artifact_pqc_migration_readiness_markdown,
    'artifact.pqc_policy_result': readiness_artifact_pqc_policy_result,
    'artifact.pqc_reference_values': readiness_artifact_pqc_reference_values,
    'artifact.pqc_reference_values_result': readiness_artifact_pqc_reference_values_result,
    'artifact.provider_scope_result': readiness_artifact_provider_scope_result,
    'artifact.release_manifest': readiness_artifact_release_manifest,
    'artifact.release_notes_markdown': readiness_artifact_release_notes_markdown,
    'artifact.release_reference_values_result': readiness_artifact_release_reference_values_result,
    'benchmark.paper_comparable_campaign': readiness_benchmark_paper_comparable_campaign,
    'benchmark.external_reference_import': readiness_benchmark_external_reference_import,
    'acvp.malformed_then_valid_recovery': readiness_acvp_malformed_then_valid_recovery,
    'acvp.operation_schema_coverage': readiness_acvp_operation_schema_coverage,
    'ct.sample_balance': readiness_ct_sample_balance,
    'ct.instruction_policy_coverage': readiness_ct_instruction_policy_coverage,
    'hardware.uart_transcript_capture': readiness_hardware_uart_transcript_capture,
    'hardware.entropy_source_review': readiness_hardware_entropy_source_review,
    'product.cli_release_pack': readiness_product_cli_release_pack,
    'product.dashboard_ingest_contract': readiness_product_dashboard_ingest_contract,
    'product.customer_policy_overlay': readiness_product_customer_policy_overlay,
    'product.signed_pack_readiness': readiness_product_signed_pack_readiness,
}

def build_readiness_matrix(experiments: tuple[ExperimentSpec, ...] | list[ExperimentSpec]) -> list[ExperimentReadiness]:
    rows: list[ExperimentReadiness] = []
    for experiment in experiments:
        builder = READINESS_BUILDERS.get(experiment.id)
        if builder is None:
            replay_ready = _has_replay_command(experiment.commands)
            falsification_ready = _has_negative_action(experiment.negative_control)
            schema_ready = _has_schema_output(experiment.expected_outputs)
            rows.append(ExperimentReadiness(
                experiment_id=experiment.id, category=experiment.category,
                required_inputs=experiment.repository_inputs, required_outputs=experiment.expected_outputs,
                commands=experiment.commands, replay_ready=replay_ready, falsification_ready=falsification_ready,
                schema_ready=schema_ready, hardware_sensitive="hardware" in experiment.category,
                ci_safe=_ci_safe(experiment), evidence_score=_score(experiment, replay_ready, falsification_ready, schema_ready),
                risk_tags=_risk_tags(experiment),
            ))
            continue
        rows.append(builder(experiment))
    return rows

def readiness_summary(rows: list[ExperimentReadiness]) -> dict[str, Any]:
    category_counts: dict[str, int] = {}
    risk_counts: dict[str, int] = {}
    replay_ready = 0
    falsification_ready = 0
    schema_ready = 0
    ci_safe = 0
    for row in rows:
        category_counts[row.category] = category_counts.get(row.category, 0) + 1
        replay_ready += 1 if row.replay_ready else 0
        falsification_ready += 1 if row.falsification_ready else 0
        schema_ready += 1 if row.schema_ready else 0
        ci_safe += 1 if row.ci_safe else 0
        for tag in row.risk_tags:
            risk_counts[tag] = risk_counts.get(tag, 0) + 1
    average_score = round(sum(row.evidence_score for row in rows) / len(rows), 3) if rows else 0
    return {
        "schema_version": 1,
        "experiment_count": len(rows),
        "category_counts": dict(sorted(category_counts.items())),
        "risk_counts": dict(sorted(risk_counts.items())),
        "replay_ready_count": replay_ready,
        "falsification_ready_count": falsification_ready,
        "schema_ready_count": schema_ready,
        "ci_safe_count": ci_safe,
        "average_evidence_score": average_score,
        "matrix_digest": json_digest([row.to_dict() for row in rows]),
    }

def validate_readiness_matrix(rows: list[ExperimentReadiness], module_path: Path) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    seen: set[str] = set()
    for row in rows:
        if row.experiment_id in seen:
            diagnostics.append(error("matrix_duplicate", row.experiment_id, "duplicate readiness row"))
        seen.add(row.experiment_id)
        if row.experiment_id not in READINESS_BUILDERS:
            diagnostics.append(warning("matrix_untracked", row.experiment_id, "experiment has no generated readiness builder"))
        for rel in row.required_inputs:
            if not (module_path / rel).exists():
                diagnostics.append(error("matrix_missing_input", f"{row.experiment_id}:{rel}", "required input missing"))
        if row.evidence_score < 40:
            diagnostics.append(warning("matrix_low_score", row.experiment_id, "evidence score is below product readiness target"))
        if not row.falsification_ready:
            diagnostics.append(error("matrix_no_negative_control", row.experiment_id, "negative control does not describe a falsification action"))
    missing = sorted(set(READINESS_BUILDERS) - seen)
    for experiment_id in missing:
        diagnostics.append(error("matrix_missing_row", experiment_id, "readiness row missing"))
    return diagnostics

def matrix_payload(experiments: tuple[ExperimentSpec, ...] | list[ExperimentSpec], module_path: Path) -> dict[str, Any]:
    rows = build_readiness_matrix(experiments)
    diagnostics = validate_readiness_matrix(rows, module_path)
    return {
        "schema_version": 1,
        "summary": readiness_summary(rows),
        "rows": [row.to_dict() for row in rows],
        "passed": not any(diag.is_error for diag in diagnostics),
        "diagnostics": [diag.to_dict() for diag in diagnostics],
    }
