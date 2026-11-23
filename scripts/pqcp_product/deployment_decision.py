#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Deployment recommendations from PQC benchmark and evidence artifacts."""

from __future__ import annotations

import csv
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .catalog import ExperimentCatalog
from .errors import Diagnostic, error, warning
from .fs import load_json, utc_now, write_json_atomic, write_text_atomic

OPERATION_TYPES = {
    "KEM",
    "signature",
    "hybrid_tls",
    "onboarding",
    "reconnect",
    "firmware_update",
    "telemetry_session",
}
PREFERENCES = {"conservative_security", "balanced_performance", "compact_artifacts"}
EVIDENCE_LEVELS = {"prototype", "paper", "product", "partner-demo"}

KEM_CANDIDATES = (
    ("ML-KEM", "512", 1),
    ("ML-KEM", "768", 3),
    ("ML-KEM", "1024", 5),
)
DSA_CANDIDATES = (
    ("ML-DSA", "44", 2),
    ("ML-DSA", "65", 3),
    ("ML-DSA", "87", 5),
)
CORE_CLAIMS = (
    "ML-KEM is feasible on constrained embedded targets",
    "ML-DSA signing is the bottleneck",
    "HQC is a fallback but has resource cost",
    "Kyber768/ML-KEM-768 is a balanced operating point",
    "The system supports reproducible cross-target benchmarking",
    "The tool can produce partner-ready evidence packs",
)


@dataclass(frozen=True)
class DeploymentScenario:
    scenario_id: str
    device_class: str
    target_board: str
    target_architecture: str
    security_level: int
    operation_type: str
    latency_budget_us: float | None
    latency_budget_cycles: float | None
    memory_budget_bytes: float | None
    energy_budget_uj: float | None
    stack_limit_bytes: float | None
    heap_limit_bytes: float | None
    preference: str
    required_evidence_level: str
    preferred_algorithms: tuple[str, ...]

    @classmethod
    def from_path(cls, path: Path) -> "DeploymentScenario":
        raw = _load_structured_file(path)
        if not isinstance(raw, dict):
            raise ValueError(f"scenario must be an object: {path}")
        return cls.from_dict(raw, source=str(path))

    @classmethod
    def from_dict(cls, raw: dict[str, Any], *, source: str = "scenario") -> "DeploymentScenario":
        def required_text(key: str) -> str:
            value = raw.get(key)
            if value in (None, ""):
                raise ValueError(f"{source}: missing required field {key}")
            return str(value)

        operation_type = required_text("operation_type")
        if operation_type not in OPERATION_TYPES:
            raise ValueError(f"{source}: unsupported operation_type {operation_type}")
        preference = str(raw.get("preference", "balanced_performance"))
        if preference not in PREFERENCES:
            raise ValueError(f"{source}: unsupported preference {preference}")
        evidence_level = str(raw.get("required_evidence_level", "prototype"))
        if evidence_level not in EVIDENCE_LEVELS:
            raise ValueError(f"{source}: unsupported required_evidence_level {evidence_level}")

        scenario = cls(
            scenario_id=required_text("scenario_id"),
            device_class=required_text("device_class"),
            target_board=required_text("target_board"),
            target_architecture=str(raw.get("target_architecture", "")),
            security_level=_parse_security_level(raw.get("security_level")),
            operation_type=operation_type,
            latency_budget_us=_optional_nonnegative(raw, "latency_budget_us", source),
            latency_budget_cycles=_optional_nonnegative(raw, "latency_budget_cycles", source),
            memory_budget_bytes=_optional_nonnegative(raw, "memory_budget_bytes", source),
            energy_budget_uj=_optional_nonnegative(raw, "energy_budget_uj", source),
            stack_limit_bytes=_optional_nonnegative(raw, "stack_limit_bytes", source),
            heap_limit_bytes=_optional_nonnegative(raw, "heap_limit_bytes", source),
            preference=preference,
            required_evidence_level=evidence_level,
            preferred_algorithms=tuple(str(item) for item in _as_list(raw.get("preferred_algorithms", []))),
        )
        if scenario.security_level < 1 or scenario.security_level > 5:
            raise ValueError(f"{source}: security_level must be in range 1..5")
        return scenario

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "device_class": self.device_class,
            "target_board": self.target_board,
            "target_architecture": self.target_architecture,
            "security_level": self.security_level,
            "operation_type": self.operation_type,
            "latency_budget_us": self.latency_budget_us,
            "latency_budget_cycles": self.latency_budget_cycles,
            "memory_budget_bytes": self.memory_budget_bytes,
            "energy_budget_uj": self.energy_budget_uj,
            "stack_limit_bytes": self.stack_limit_bytes,
            "heap_limit_bytes": self.heap_limit_bytes,
            "preference": self.preference,
            "required_evidence_level": self.required_evidence_level,
            "preferred_algorithms": list(self.preferred_algorithms),
        }


@dataclass(frozen=True)
class MetricObservation:
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
    source_file: str
    row_number: int

    def to_dict(self) -> dict[str, Any]:
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
            "source_file": self.source_file,
            "row_number": self.row_number,
        }


@dataclass(frozen=True)
class Candidate:
    candidate_id: str
    algorithm: str
    parameter_set: str
    profile: str
    target_board: str
    operation_family: str
    security_level: int
    operations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "algorithm": self.algorithm,
            "parameter_set": self.parameter_set,
            "profile": self.profile,
            "target_board": self.target_board,
            "operation_family": self.operation_family,
            "security_level": self.security_level,
            "operations": list(self.operations),
        }


class EvidenceIndex:
    """Normalized view of benchmark rows, pack manifests, and validation reports."""

    def __init__(
        self,
        *,
        module_path: Path,
        packs: list[Path] | None = None,
        csv_paths: list[Path] | None = None,
        validation_reports: list[Path] | None = None,
    ):
        self.module_path = module_path.resolve()
        self.packs = [path.resolve() for path in (packs or [])]
        self.csv_paths = [path.resolve() for path in (csv_paths or [])]
        self.validation_reports = [path.resolve() for path in (validation_reports or [])]
        self.diagnostics: list[Diagnostic] = []
        self.metrics = self._load_metrics()
        self.pack_manifests = self._load_pack_manifests()
        self.reports = self._load_reports()
        self.artifacts = self._collect_artifacts()

    @classmethod
    def from_inputs(
        cls,
        *,
        module_path: Path,
        packs: list[Path] | None = None,
        csv_paths: list[Path] | None = None,
        validation_reports: list[Path] | None = None,
    ) -> "EvidenceIndex":
        return cls(module_path=module_path, packs=packs, csv_paths=csv_paths, validation_reports=validation_reports)

    def to_summary(self) -> dict[str, Any]:
        return {
            "metric_count": len(self.metrics),
            "pack_count": len(self.pack_manifests),
            "report_count": len(self.reports),
            "artifact_count": len(self.artifacts),
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }

    def matching_metrics(self, candidate: Candidate) -> list[MetricObservation]:
        return [
            row for row in self.metrics
            if row.algorithm == candidate.algorithm
            and row.parameter_set == candidate.parameter_set
            and row.board == candidate.target_board
            and row.operation in candidate.operations
        ]

    def metric_value(self, candidate: Candidate, names: tuple[str, ...]) -> float | None:
        rows = self.matching_metrics(candidate)
        values = [
            row.value for row in rows
            if any(name in row.metric.lower() for name in names)
            and row.statistic in {"median", "value", "sample0", "mean"}
            and not math.isnan(row.value)
        ]
        return min(values) if values else None

    def has_algorithm(self, algorithm: str, parameter_set: str | None = None) -> bool:
        return any(
            row.algorithm == algorithm and (parameter_set is None or row.parameter_set == parameter_set)
            for row in self.metrics
        )

    def has_board(self, board: str) -> bool:
        return any(row.board == board for row in self.metrics)

    def has_multiple_targets(self) -> bool:
        return len({row.board for row in self.metrics if row.board}) >= 2

    def has_baseline(self) -> bool:
        return any(_report_kind(report) == "baseline" and _report_passed(report) for report in self.reports) or any(
            "baseline" in artifact.get("relative_path", "").lower() or "comparison" in artifact.get("relative_path", "").lower()
            for artifact in self.artifacts
        )

    def has_reproducibility(self) -> bool:
        return any(_report_kind(report) == "reproducibility" and _report_passed(report) for report in self.reports)

    def has_quality(self) -> bool:
        return any(_report_kind(report) in {"quality", "statistics"} and _report_passed(report) for report in self.reports)

    def has_validation(self) -> bool:
        return any(_report_passed(report) for report in self.reports) or any(
            artifact.get("relative_path", "").endswith(("assurance_ledger.json", "pqc_policy_result.json", "evidence-pack-validation.json"))
            for artifact in self.artifacts
        )

    def has_partner_pack(self) -> bool:
        names = {artifact.get("relative_path", "") for artifact in self.artifacts}
        return bool(names & {"assurance_ledger.json", "pqc_policy_result.json"}) or any(
            "evidence-pack-manifest.json" in name for name in names
        )

    def artifacts_for(self, *needles: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for artifact in self.artifacts:
            haystack = " ".join(str(artifact.get(key, "")) for key in ("artifact_id", "relative_path", "media_type")).lower()
            if all(needle.lower() in haystack for needle in needles):
                out.append(artifact)
        return out

    def _load_metrics(self) -> list[MetricObservation]:
        rows: list[MetricObservation] = []
        for path in self.csv_paths:
            if not path.exists():
                self.diagnostics.append(error("decision_csv_missing", str(path), "result CSV is missing"))
                continue
            with path.open("r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                if not reader.fieldnames:
                    self.diagnostics.append(error("decision_csv_header", str(path), "result CSV has no header"))
                    continue
                for row_number, raw in enumerate(reader, start=2):
                    observation = _metric_from_row(raw, path, row_number)
                    if observation is None:
                        self.diagnostics.append(warning("decision_metric_skip", f"{path}:{row_number}", "row has no numeric value"))
                    else:
                        rows.append(observation)
        return rows

    def _load_pack_manifests(self) -> list[dict[str, Any]]:
        manifests: list[dict[str, Any]] = []
        for root in self.packs:
            manifest_path = root / "evidence-pack-manifest.json"
            if not manifest_path.exists():
                self.diagnostics.append(error("decision_manifest_missing", str(manifest_path), "evidence pack manifest is missing"))
                continue
            payload = load_json(manifest_path)
            payload["_path"] = str(manifest_path)
            manifests.append(payload)
        return manifests

    def _load_reports(self) -> list[dict[str, Any]]:
        reports: list[dict[str, Any]] = []
        for path in self.validation_reports:
            if not path.exists():
                self.diagnostics.append(error("decision_report_missing", str(path), "validation report is missing"))
                continue
            payload = load_json(path)
            payload["_path"] = str(path)
            reports.append(payload)
        for root in self.packs:
            for name in (
                "evidence-pack-validation.json",
                "baseline-comparison.json",
                "cross-run-reproducibility-report.json",
                "result-quality-report.json",
                "statistical-sanity-report.json",
                "paper-evidence-report.json",
            ):
                path = root / name
                if path.exists():
                    payload = load_json(path)
                    payload["_path"] = str(path)
                    reports.append(payload)
        return reports

    def _collect_artifacts(self) -> list[dict[str, Any]]:
        artifacts: list[dict[str, Any]] = []
        for manifest in self.pack_manifests:
            for artifact in manifest.get("artifacts", []):
                item = dict(artifact)
                item["_manifest"] = manifest.get("_path")
                artifacts.append(item)
        return artifacts


def recommend_deployment(
    *,
    scenario_path: Path,
    module_path: Path,
    output_root: Path,
    packs: list[Path] | None = None,
    csv_paths: list[Path] | None = None,
    validation_reports: list[Path] | None = None,
) -> dict[str, Any]:
    scenario = DeploymentScenario.from_path(scenario_path)
    evidence = EvidenceIndex.from_inputs(
        module_path=module_path,
        packs=packs,
        csv_paths=csv_paths,
        validation_reports=validation_reports,
    )
    candidates = _candidate_set(scenario, evidence)
    recommendations = [_score_candidate(scenario, evidence, candidate) for candidate in candidates]
    recommendations.sort(key=lambda item: (item["rejected"], -item["score"], -item["confidence"]))
    supportable = [item for item in recommendations if not item["rejected"]]
    status = "FAIL" if not supportable else ("WARN" if any(item["evidence_gaps"] for item in supportable[:1]) else "PASS")
    result = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": status,
        "passed": status != "FAIL",
        "scenario": scenario.to_dict(),
        "evidence_summary": evidence.to_summary(),
        "recommendations": recommendations,
        "top_recommendation": supportable[0] if supportable else None,
    }
    _write_report_pair(output_root, "deployment-recommendations", result, _render_recommendations(result))
    return result


def plan_evidence(
    *,
    scenario_path: Path,
    module_path: Path,
    output_root: Path,
    catalog_path: Path | None = None,
    packs: list[Path] | None = None,
    csv_paths: list[Path] | None = None,
    validation_reports: list[Path] | None = None,
) -> dict[str, Any]:
    scenario = DeploymentScenario.from_path(scenario_path)
    evidence = EvidenceIndex.from_inputs(
        module_path=module_path,
        packs=packs,
        csv_paths=csv_paths,
        validation_reports=validation_reports,
    )
    catalog = ExperimentCatalog(module_path, catalog_path)
    recs = [_score_candidate(scenario, evidence, candidate) for candidate in _candidate_set(scenario, evidence)]
    recs.sort(key=lambda item: (item["rejected"], -item["score"], -item["confidence"]))
    gaps = _dedupe_experiments(
        experiment for recommendation in recs[:3] for experiment in _experiments_for_gaps(
            scenario,
            recommendation["candidate"],
            recommendation["evidence_gaps"],
            catalog,
        )
    )
    status = "PASS" if not gaps else "WARN"
    result = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": status,
        "passed": True,
        "scenario": scenario.to_dict(),
        "experiment_count": len(gaps),
        "experiments": gaps,
    }
    _write_report_pair(output_root, "evidence-gap-plan", result, _render_gap_plan(result))
    return result


def claim_matrix(
    *,
    module_path: Path,
    output_root: Path,
    packs: list[Path] | None = None,
    csv_paths: list[Path] | None = None,
    validation_reports: list[Path] | None = None,
) -> dict[str, Any]:
    evidence = EvidenceIndex.from_inputs(
        module_path=module_path,
        packs=packs,
        csv_paths=csv_paths,
        validation_reports=validation_reports,
    )
    claims = [_assess_claim(claim, evidence) for claim in CORE_CLAIMS]
    status = "PASS" if all(item["support"] == "supported" for item in claims) else "WARN"
    result = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": status,
        "passed": True,
        "evidence_summary": evidence.to_summary(),
        "claims": claims,
    }
    _write_report_pair(output_root, "claim-support-matrix", result, _render_claim_matrix(result))
    return result


def compare_scenarios(
    *,
    scenario_paths: list[Path],
    module_path: Path,
    output_root: Path,
    packs: list[Path] | None = None,
    csv_paths: list[Path] | None = None,
    validation_reports: list[Path] | None = None,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    diagnostics: list[Diagnostic] = []
    for path in scenario_paths:
        try:
            report = recommend_deployment(
                scenario_path=path,
                module_path=module_path,
                output_root=output_root / f"_scenario_{path.stem}",
                packs=packs,
                csv_paths=csv_paths,
                validation_reports=validation_reports,
            )
            top = report.get("top_recommendation") or {}
            candidate = top.get("candidate") or {}
            rows.append(
                {
                    "scenario_id": report["scenario"]["scenario_id"],
                    "status": report["status"],
                    "supportable": bool(top),
                    "top_candidate": candidate.get("candidate_id"),
                    "confidence": top.get("confidence", 0),
                    "gap_count": len(top.get("evidence_gaps", [])) if top else 0,
                    "blocking_reasons": top.get("blocking_reasons", []) if top else ["no supportable candidate"],
                }
            )
        except Exception as exc:
            diagnostics.append(error("scenario_compare_failed", str(path), str(exc)))
            rows.append({"scenario_id": path.stem, "status": "FAIL", "supportable": False, "top_candidate": None, "confidence": 0, "gap_count": 0, "blocking_reasons": [str(exc)]})
    status = "FAIL" if any(row["status"] == "FAIL" for row in rows) else ("WARN" if any(row["status"] == "WARN" for row in rows) else "PASS")
    result = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": status,
        "passed": status != "FAIL",
        "scenario_count": len(rows),
        "scenarios": rows,
        "diagnostics": [item.to_dict() for item in diagnostics],
    }
    _write_report_pair(output_root, "scenario-comparison", result, _render_scenario_comparison(result))
    return result


def _candidate_set(scenario: DeploymentScenario, evidence: EvidenceIndex) -> list[Candidate]:
    board = scenario.target_board
    profile = _profile_for_evidence_level(scenario.required_evidence_level)
    families: list[tuple[str, str, int]]
    if scenario.operation_type in {"KEM", "onboarding", "reconnect", "telemetry_session"}:
        families = list(KEM_CANDIDATES)
        operations = ("keygen", "encaps", "decaps")
        family_name = "KEM"
    elif scenario.operation_type in {"signature", "firmware_update"}:
        families = list(DSA_CANDIDATES)
        operations = ("keygen", "sign", "verify")
        family_name = "signature"
    else:
        families = [("ML-KEM", "768", 3), ("ML-KEM+ML-DSA", "768+65", 3), ("ML-KEM+ML-DSA", "1024+87", 5)]
        operations = ("keygen", "encaps", "decaps", "sign", "verify", "handshake")
        family_name = "hybrid_tls"

    preferred = {_normalize_algorithm_name(item) for item in scenario.preferred_algorithms}
    candidates: list[Candidate] = []
    for algorithm, parameter_set, level in families:
        if preferred and _normalize_algorithm_name(algorithm) not in preferred:
            continue
        cid = f"{algorithm}-{parameter_set}-{board}-{profile}".replace("+", "_").replace(" ", "_")
        candidates.append(
            Candidate(
                candidate_id=cid,
                algorithm=algorithm,
                parameter_set=parameter_set,
                profile=profile,
                target_board=board,
                operation_family=family_name,
                security_level=level,
                operations=operations,
            )
        )
    if not candidates and preferred:
        evidence.diagnostics.append(warning("decision_no_preferred_candidate", scenario.scenario_id, "preferred_algorithms excluded all built-in candidates"))
    return candidates


def _score_candidate(scenario: DeploymentScenario, evidence: EvidenceIndex, candidate: Candidate) -> dict[str, Any]:
    score = 100.0
    confidence = 0.25
    blocking: list[str] = []
    gaps: list[str] = []
    explanation: list[str] = []

    if candidate.security_level < scenario.security_level:
        blocking.append(f"security level {candidate.security_level} is below required level {scenario.security_level}")
    if not _operation_matches(scenario, candidate):
        blocking.append(f"{candidate.algorithm} does not support operation_type {scenario.operation_type}")

    rows = evidence.matching_metrics(candidate)
    if rows:
        confidence += 0.20
        explanation.append(f"found {len(rows)} benchmark/result rows for {candidate.algorithm}-{candidate.parameter_set} on {candidate.target_board}")
    else:
        score -= 22
        gaps.append("benchmark_result_missing")
        explanation.append("no matching benchmark/result row is available for this target and parameter set")

    latency_value, latency_unit = _best_latency(rows)
    if latency_value is not None:
        confidence += 0.10
        if scenario.latency_budget_us is not None and latency_unit == "us" and latency_value > scenario.latency_budget_us:
            blocking.append(f"latency {latency_value:g} us exceeds budget {scenario.latency_budget_us:g} us")
        if scenario.latency_budget_cycles is not None and latency_unit == "cycles" and latency_value > scenario.latency_budget_cycles:
            blocking.append(f"latency {latency_value:g} cycles exceeds budget {scenario.latency_budget_cycles:g} cycles")
        score += _budget_score(latency_value, scenario.latency_budget_us if latency_unit == "us" else scenario.latency_budget_cycles)
    elif scenario.latency_budget_us is not None or scenario.latency_budget_cycles is not None:
        gaps.append("latency_evidence_missing")
        score -= 10

    memory_value = _best_metric(rows, ("ram", "rom", "memory", "working_set"))
    stack_value = _best_metric(rows, ("stack",))
    heap_value = _best_metric(rows, ("heap",))
    if scenario.memory_budget_bytes is not None:
        if memory_value is None:
            gaps.append("memory_evidence_missing")
            score -= 10
        elif memory_value > scenario.memory_budget_bytes:
            blocking.append(f"memory {memory_value:g} B exceeds budget {scenario.memory_budget_bytes:g} B")
        else:
            score += _budget_score(memory_value, scenario.memory_budget_bytes)
    if scenario.stack_limit_bytes is not None:
        if stack_value is None:
            gaps.append("stack_evidence_missing")
            score -= 8
        elif stack_value > scenario.stack_limit_bytes:
            blocking.append(f"stack {stack_value:g} B exceeds limit {scenario.stack_limit_bytes:g} B")
    if scenario.heap_limit_bytes is not None:
        if heap_value is None:
            gaps.append("heap_evidence_missing")
            score -= 6
        elif heap_value > scenario.heap_limit_bytes:
            blocking.append(f"heap {heap_value:g} B exceeds limit {scenario.heap_limit_bytes:g} B")

    evidence_bits = _evidence_bits(evidence)
    confidence += 0.08 * sum(1 for value in evidence_bits.values() if value)
    for name, present in evidence_bits.items():
        if not present:
            gaps.append(f"{name}_missing")
            score -= _gap_penalty(name, scenario.required_evidence_level)

    if scenario.required_evidence_level in {"product", "partner-demo"} and scenario.target_board not in {"qemu_x86_64", "native_sim"}:
        if not evidence.has_board(scenario.target_board):
            gaps.append("hardware_target_evidence_missing")
            score -= 16
    if scenario.preference == "conservative_security":
        score += candidate.security_level * 2
    elif scenario.preference == "compact_artifacts":
        score += 8 if candidate.parameter_set in {"512", "44"} else -4
    else:
        score += 8 if candidate.parameter_set in {"768", "65", "768+65"} else 0

    if blocking:
        score = min(score, 20)
    confidence = max(0.0, min(1.0, confidence - 0.05 * len(gaps) - 0.15 * len(blocking)))
    return {
        "candidate": candidate.to_dict(),
        "score": round(max(0.0, min(100.0, score)), 2),
        "confidence": round(confidence, 3),
        "rejected": bool(blocking),
        "blocking_reasons": blocking,
        "explanation": explanation or ["candidate is available as a canonical option but has no direct local evidence yet"],
        "observed_metrics": [row.to_dict() for row in rows[:12]],
        "evidence_gaps": sorted(set(gaps)),
        "next_experiments": _experiments_for_gaps(scenario, candidate.to_dict(), sorted(set(gaps)), None),
    }


def _experiments_for_gaps(
    scenario: DeploymentScenario,
    candidate: dict[str, Any],
    gaps: list[str],
    catalog: ExperimentCatalog | None,
) -> list[dict[str, Any]]:
    experiments: list[dict[str, Any]] = []
    for index, gap in enumerate(gaps):
        experiments.append(_experiment_for_gap(scenario, candidate, gap, index, catalog))
    if not experiments and scenario.required_evidence_level in {"paper", "product", "partner-demo"}:
        experiments.append(_experiment_for_gap(scenario, candidate, "reviewer_confirmation", 0, catalog))
    return experiments


def _experiment_for_gap(
    scenario: DeploymentScenario,
    candidate: dict[str, Any],
    gap: str,
    index: int,
    catalog: ExperimentCatalog | None,
) -> dict[str, Any]:
    algorithm = str(candidate.get("algorithm", "candidate"))
    parameter_set = str(candidate.get("parameter_set", "unknown"))
    target = str(candidate.get("target_board", scenario.target_board))
    purpose_map = {
        "benchmark_result_missing": "Run the primitive or protocol benchmark for the candidate on the scenario target.",
        "latency_evidence_missing": "Capture latency/cycle rows that can be checked against the deployment budget.",
        "memory_evidence_missing": "Capture ROM/RAM/working-set rows for the target profile.",
        "stack_evidence_missing": "Capture stack high-water or stack metric rows for the target profile.",
        "heap_evidence_missing": "Capture heap or allocation footprint evidence for the target profile.",
        "baseline_missing": "Generate a baseline/comparison report so reviewers can interpret the candidate result.",
        "reproducibility_missing": "Compare at least two evidence packs from independent runs.",
        "quality_missing": "Run result-quality and statistical sanity checks over the benchmark CSV.",
        "validation_missing": "Run local release validation or replay checks that bind the candidate to pass/fail evidence.",
        "partner_pack_missing": "Build a hash-bound evidence pack with ledger/policy artifacts.",
        "hardware_target_evidence_missing": "Promote the QEMU result to the requested board or record a hardware-not-available boundary.",
    }
    maturity = _maturity_for_gap(gap, scenario.required_evidence_level)
    matched = _matching_catalog_ids(catalog, gap, algorithm, target) if catalog else []
    return {
        "priority": index + 1,
        "gap": gap,
        "purpose": purpose_map.get(gap, "Add reviewer-facing evidence for the recommendation."),
        "algorithm": algorithm,
        "parameter_set": parameter_set,
        "target": target,
        "profile": candidate.get("profile", _profile_for_evidence_level(scenario.required_evidence_level)),
        "expected_artifact": _artifact_for_gap(gap),
        "claim_supported": _claim_for_gap(gap, algorithm),
        "why_it_matters": _why_gap_matters(gap),
        "acceptance_criteria": _acceptance_for_gap(gap),
        "required_for": maturity,
        "catalog_experiment_ids": matched,
    }


def _assess_claim(claim: str, evidence: EvidenceIndex) -> dict[str, Any]:
    if claim == "ML-KEM is feasible on constrained embedded targets":
        supported = evidence.has_algorithm("ML-KEM")
        support = "supported" if supported and evidence.has_quality() else ("partially_supported" if supported else "unsupported")
        missing = [] if support == "supported" else ["ML-KEM benchmark rows", "result-quality/statistical evidence"]
        artifacts = [row.to_dict() for row in evidence.metrics if row.algorithm == "ML-KEM"][:8]
    elif claim == "ML-DSA signing is the bottleneck":
        sign_rows = [row for row in evidence.metrics if row.algorithm == "ML-DSA" and row.operation == "sign"]
        other_rows = [row for row in evidence.metrics if row.algorithm == "ML-DSA" and row.operation in {"keygen", "verify"}]
        sign_median = _median([row.value for row in sign_rows])
        other_median = _median([row.value for row in other_rows])
        supported = sign_median is not None and other_median is not None and sign_median > other_median
        support = "supported" if supported else ("partially_supported" if sign_rows else "unsupported")
        missing = [] if supported else ["ML-DSA sign/verify/keygen comparable rows"]
        artifacts = [row.to_dict() for row in sign_rows[:8]]
    elif claim == "HQC is a fallback but has resource cost":
        supported = evidence.has_algorithm("HQC")
        support = "partially_supported" if supported else "unsupported"
        missing = [] if supported else ["HQC inventory and benchmark evidence"]
        artifacts = [row.to_dict() for row in evidence.metrics if row.algorithm == "HQC"][:8]
    elif claim == "Kyber768/ML-KEM-768 is a balanced operating point":
        supported = evidence.has_algorithm("ML-KEM", "768")
        support = "supported" if supported and evidence.has_baseline() else ("partially_supported" if supported else "unsupported")
        missing = [] if support == "supported" else ["ML-KEM-768 rows with baseline/comparison context"]
        artifacts = [row.to_dict() for row in evidence.metrics if row.algorithm == "ML-KEM" and row.parameter_set == "768"][:8]
    elif claim == "The system supports reproducible cross-target benchmarking":
        supported = evidence.has_reproducibility() and evidence.has_multiple_targets()
        support = "supported" if supported else ("partially_supported" if evidence.has_reproducibility() or evidence.has_multiple_targets() else "unsupported")
        missing = [] if supported else ["cross-run reproducibility report", "benchmark rows from at least two targets"]
        artifacts = evidence.artifacts_for("benchmark")[:8]
    else:
        supported = evidence.has_partner_pack() and evidence.has_validation()
        support = "supported" if supported else ("partially_supported" if evidence.has_partner_pack() else "unsupported")
        missing = [] if supported else ["evidence pack manifest", "assurance ledger/policy validation"]
        artifacts = evidence.artifacts[:8]
    return {
        "claim": claim,
        "support": support,
        "risk_level": "low" if support == "supported" else ("medium" if support == "partially_supported" else "high"),
        "supporting_artifacts": artifacts,
        "missing_artifacts": missing,
        "next_experiment": _next_for_claim(claim, missing),
    }


def _load_structured_file(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json" or text.lstrip().startswith("{"):
        return json.loads(text)
    return _parse_simple_yaml(text, str(path))


def _parse_simple_yaml(text: str, source: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    current_key: str | None = None
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.startswith("  - ") and current_key:
            result.setdefault(current_key, []).append(_parse_scalar(line[4:].strip()))
            continue
        if line.startswith((" ", "\t")):
            raise ValueError(f"{source}:{line_number}: unsupported nested YAML syntax")
        if ":" not in line:
            raise ValueError(f"{source}:{line_number}: expected key: value")
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise ValueError(f"{source}:{line_number}: empty key")
        if value == "":
            result[key] = []
            current_key = key
        else:
            result[key] = _parse_scalar(value)
            current_key = None
    return result


def _parse_scalar(value: str) -> Any:
    if value.startswith("[") and value.endswith("]"):
        body = value[1:-1].strip()
        if not body:
            return []
        return [_parse_scalar(part.strip()) for part in body.split(",")]
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _parse_security_level(value: Any) -> int:
    if value in (None, ""):
        raise ValueError("scenario: missing required field security_level")
    text = str(value).lower().replace("level", "").replace("nist", "").strip()
    return int(text)


def _optional_nonnegative(raw: dict[str, Any], key: str, source: str) -> float | None:
    value = raw.get(key)
    if value in (None, ""):
        return None
    numeric = float(value)
    if numeric < 0:
        raise ValueError(f"{source}: {key} must be non-negative")
    return numeric


def _as_list(value: Any) -> list[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return value
    return [value]


def _metric_from_row(raw: dict[str, str], path: Path, row_number: int) -> MetricObservation | None:
    value_text = _first(raw, ("value", "median", "median_cycles", "cycles", "candidate_value"))
    try:
        value = float(value_text)
    except (TypeError, ValueError):
        return None
    if math.isnan(value) or math.isinf(value):
        return None
    return MetricObservation(
        algorithm=_normalize_algorithm_name(_first(raw, ("algorithm", "alg", "scheme"))),
        operation=_normalize_operation(_first(raw, ("operation", "op"))),
        parameter_set=_first(raw, ("parameter_set", "parameter", "level", "param")),
        implementation=_first(raw, ("implementation", "impl")) or "unknown",
        board=_first(raw, ("board", "target")) or "unknown",
        profile=_first(raw, ("profile",)) or "unknown",
        metric=_first(raw, ("metric", "statistic_type")) or "value",
        statistic=_normalize_statistic(_first(raw, ("statistic", "stat")), _first(raw, ("metric", "statistic_type"))),
        value=value,
        unit=_first(raw, ("unit",)) or _infer_unit(_first(raw, ("metric", "statistic_type"))),
        source=_first(raw, ("source", "source_url", "source_dataset")) or path.name,
        source_file=str(path),
        row_number=row_number,
    )


def _first(raw: dict[str, str], aliases: tuple[str, ...]) -> str:
    for alias in aliases:
        value = raw.get(alias)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _normalize_algorithm_name(value: str) -> str:
    compact = value.replace("-", "").replace("_", "").replace(" ", "").replace("+", "").upper()
    if compact in {"MLKEM", "KYBER"}:
        return "ML-KEM"
    if compact in {"MLDSA", "DILITHIUM"}:
        return "ML-DSA"
    if "MLKEM" in compact and "MLDSA" in compact:
        return "ML-KEM+ML-DSA"
    return value


def _normalize_operation(value: str) -> str:
    compact = value.lower().replace("_", "").replace("-", "")
    return {
        "keygen": "keygen",
        "keygeneration": "keygen",
        "encaps": "encaps",
        "encapsulation": "encaps",
        "decaps": "decaps",
        "decapsulation": "decaps",
        "sign": "sign",
        "signature": "sign",
        "siggen": "sign",
        "verify": "verify",
        "verification": "verify",
        "sigver": "verify",
        "handshake": "handshake",
    }.get(compact, value.lower())


def _normalize_statistic(statistic: str, metric: str) -> str:
    stat = statistic.lower()
    metric_lower = metric.lower()
    for candidate in ("min", "median", "mean", "p90", "p99", "max", "sample0"):
        if stat == candidate or metric_lower.endswith("_" + candidate):
            return candidate
    return stat or "value"


def _infer_unit(metric: str) -> str:
    lower = metric.lower()
    if "cycle" in lower:
        return "cycles"
    if "time" in lower or "latency" in lower:
        return "us"
    if any(name in lower for name in ("ram", "rom", "stack", "heap", "bytes", "working_set")):
        return "B"
    if "energy" in lower:
        return "uJ"
    return ""


def _operation_matches(scenario: DeploymentScenario, candidate: Candidate) -> bool:
    if scenario.operation_type in {"KEM", "onboarding", "reconnect", "telemetry_session"}:
        return candidate.operation_family == "KEM"
    if scenario.operation_type in {"signature", "firmware_update"}:
        return candidate.operation_family == "signature"
    return candidate.operation_family == "hybrid_tls"


def _best_latency(rows: list[MetricObservation]) -> tuple[float | None, str | None]:
    for unit in ("us", "cycles"):
        values = [
            row.value for row in rows
            if row.unit == unit and any(name in row.metric.lower() for name in ("time", "latency", "cycle"))
        ]
        if values:
            return min(values), unit
    return None, None


def _best_metric(rows: list[MetricObservation], names: tuple[str, ...]) -> float | None:
    values = [row.value for row in rows if any(name in row.metric.lower() for name in names)]
    return min(values) if values else None


def _budget_score(value: float, budget: float | None) -> float:
    if budget is None or budget <= 0:
        return 0.0
    ratio = value / budget
    if ratio <= 0.5:
        return 8.0
    if ratio <= 0.8:
        return 4.0
    if ratio <= 1.0:
        return 1.0
    return -12.0


def _evidence_bits(evidence: EvidenceIndex) -> dict[str, bool]:
    return {
        "baseline": evidence.has_baseline(),
        "reproducibility": evidence.has_reproducibility(),
        "quality": evidence.has_quality(),
        "validation": evidence.has_validation(),
        "partner_pack": evidence.has_partner_pack(),
    }


def _gap_penalty(name: str, evidence_level: str) -> int:
    if evidence_level == "prototype":
        return {"baseline": 3, "reproducibility": 3, "quality": 4, "validation": 4, "partner_pack": 2}.get(name, 4)
    if evidence_level == "paper":
        return {"baseline": 8, "reproducibility": 10, "quality": 10, "validation": 6, "partner_pack": 4}.get(name, 8)
    return {"baseline": 10, "reproducibility": 12, "quality": 12, "validation": 12, "partner_pack": 12}.get(name, 10)


def _profile_for_evidence_level(level: str) -> str:
    return {"prototype": "fast", "paper": "paper", "product": "product", "partner-demo": "product"}.get(level, "fast")


def _maturity_for_gap(gap: str, scenario_level: str) -> str:
    if gap in {"benchmark_result_missing", "latency_evidence_missing"}:
        return "prototype"
    if gap in {"baseline_missing", "reproducibility_missing", "quality_missing"}:
        return "paper"
    if gap in {"validation_missing", "partner_pack_missing", "hardware_target_evidence_missing"}:
        return "product" if scenario_level != "partner-demo" else "partner-demo"
    return scenario_level


def _artifact_for_gap(gap: str) -> str:
    return {
        "benchmark_result_missing": "benchmark_results.csv",
        "latency_evidence_missing": "benchmark_results.csv",
        "memory_evidence_missing": "resource or benchmark CSV with ROM/RAM/stack rows",
        "stack_evidence_missing": "stack metric CSV or QEMU transcript",
        "heap_evidence_missing": "heap metric CSV or allocation report",
        "baseline_missing": "baseline-comparison.json",
        "reproducibility_missing": "cross-run-reproducibility-report.json",
        "quality_missing": "result-quality-report.json and statistical-sanity-report.json",
        "validation_missing": "evidence-pack-validation.json or pqc_policy_result.json",
        "partner_pack_missing": "evidence-pack-manifest.json",
        "hardware_target_evidence_missing": "hardware benchmark transcript and benchmark CSV rows",
    }.get(gap, "reviewer evidence artifact")


def _claim_for_gap(gap: str, algorithm: str) -> str:
    if "benchmark" in gap or "latency" in gap or "memory" in gap or "stack" in gap:
        return f"{algorithm} deployment feasibility under constrained-system budgets"
    if gap == "baseline_missing":
        return "The system supports paper-comparable benchmark interpretation"
    if gap == "reproducibility_missing":
        return "The system supports reproducible cross-target benchmarking"
    if gap == "partner_pack_missing":
        return "The tool can produce partner-ready evidence packs"
    return "Deployment recommendation is supported by replayable evidence"


def _why_gap_matters(gap: str) -> str:
    if gap in {"benchmark_result_missing", "latency_evidence_missing", "memory_evidence_missing", "stack_evidence_missing"}:
        return "The recommendation cannot be defended against deployment constraints without measured local evidence."
    if gap == "baseline_missing":
        return "Reviewers need a baseline or comparison point to understand whether the result is competitive."
    if gap == "reproducibility_missing":
        return "A single run is weaker than a replayed cross-run result for paper and partner review."
    if gap == "quality_missing":
        return "CSV rows need sanity checks before they can be used as decision evidence."
    if gap == "partner_pack_missing":
        return "Partner review needs a hash-bound package rather than loose files."
    return "The scenario remains supportable only as a lower-confidence recommendation."


def _acceptance_for_gap(gap: str) -> list[str]:
    common = ["Output artifact exists under the selected output root.", "Tool exits non-zero on a deliberately tampered negative control."]
    if gap in {"benchmark_result_missing", "latency_evidence_missing", "memory_evidence_missing", "stack_evidence_missing"}:
        return ["CSV contains algorithm, operation, parameter_set, board, metric, statistic, value, unit, and source.", "Rows cover the scenario target and candidate parameter set.", *common]
    if gap == "reproducibility_missing":
        return ["At least two evidence packs compare with PASS or reviewer-visible WARN.", *common]
    if gap == "baseline_missing":
        return ["Candidate and baseline rows share comparable keys.", "Regression status is PASS or explicitly justified.", *common]
    return common


def _matching_catalog_ids(catalog: ExperimentCatalog | None, gap: str, algorithm: str, target: str) -> list[str]:
    if not catalog:
        return []
    needles = [algorithm.lower().replace("-", ""), target.lower()]
    if "baseline" in gap:
        needles.append("baseline")
    elif "reproducibility" in gap:
        needles.append("reproduc")
    elif "quality" in gap:
        needles.append("quality")
    else:
        needles.append("benchmark")
    matched: list[str] = []
    for experiment in catalog.experiments:
        body = " ".join([experiment.id, experiment.objective, experiment.product_value, experiment.research_value, *experiment.commands, *experiment.expected_outputs]).lower().replace("-", "")
        if any(needle in body for needle in needles):
            matched.append(experiment.id)
    return matched[:8]


def _dedupe_experiments(experiments: Any) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for experiment in experiments:
        key = (experiment["gap"], experiment["algorithm"], experiment["target"])
        if key in seen:
            continue
        seen.add(key)
        item = dict(experiment)
        item["priority"] = len(out) + 1
        out.append(item)
    return out


def _report_kind(report: dict[str, Any]) -> str:
    path = str(report.get("_path", "")).lower()
    if "baseline" in path:
        return "baseline"
    if "reproducibility" in path or "compare" in path:
        return "reproducibility"
    if "quality" in path:
        return "quality"
    if "statistical" in path or "stats" in path:
        return "statistics"
    return "validation"


def _report_passed(report: dict[str, Any]) -> bool:
    if report.get("passed") is True:
        return True
    status = str(report.get("status", "")).upper()
    return status in {"PASS", "WARN"}


def _median(values: list[float]) -> float | None:
    clean = sorted(value for value in values if not math.isnan(value))
    if not clean:
        return None
    mid = len(clean) // 2
    if len(clean) % 2:
        return clean[mid]
    return (clean[mid - 1] + clean[mid]) / 2


def _next_for_claim(claim: str, missing: list[str]) -> dict[str, Any]:
    if not missing:
        return {"required": False, "purpose": "No immediate experiment required for this claim."}
    return {
        "required": True,
        "purpose": f"Generate missing evidence for: {', '.join(missing)}",
        "expected_artifact": "benchmark CSV, validation report, or evidence pack depending on the missing artifact.",
    }


def _write_report_pair(output_root: Path, stem: str, payload: dict[str, Any], markdown: str) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    write_json_atomic(output_root / f"{stem}.json", payload)
    write_text_atomic(output_root / f"{stem}.md", markdown)


def _render_recommendations(result: dict[str, Any]) -> str:
    lines = ["# Deployment Recommendations", "", f"Status: {result['status']}", ""]
    scenario = result["scenario"]
    lines.append(f"Scenario: {scenario['scenario_id']} ({scenario['operation_type']} on {scenario['target_board']})")
    lines.append("")
    lines.append("| Rank | Candidate | Score | Confidence | Decision | Gaps |")
    lines.append("|---:|---|---:|---:|---|---|")
    for rank, item in enumerate(result["recommendations"], start=1):
        candidate = item["candidate"]
        decision = "rejected" if item["rejected"] else "recommended"
        gaps = ", ".join(item["evidence_gaps"]) or "none"
        lines.append(f"| {rank} | {candidate['candidate_id']} | {item['score']} | {item['confidence']} | {decision} | {gaps} |")
    return "\n".join(lines) + "\n"


def _render_gap_plan(result: dict[str, Any]) -> str:
    lines = ["# Evidence Gap Plan", "", f"Status: {result['status']}", ""]
    for item in result["experiments"]:
        lines.append(f"{item['priority']}. {item['purpose']}")
        lines.append(f"   Artifact: {item['expected_artifact']}")
        lines.append(f"   Claim: {item['claim_supported']}")
    return "\n".join(lines) + "\n"


def _render_claim_matrix(result: dict[str, Any]) -> str:
    lines = ["# Claim Support Matrix", "", f"Status: {result['status']}", "", "| Claim | Support | Risk | Missing |", "|---|---|---|---|"]
    for item in result["claims"]:
        lines.append(f"| {item['claim']} | {item['support']} | {item['risk_level']} | {', '.join(item['missing_artifacts']) or 'none'} |")
    return "\n".join(lines) + "\n"


def _render_scenario_comparison(result: dict[str, Any]) -> str:
    lines = ["# Scenario Comparison", "", f"Status: {result['status']}", "", "| Scenario | Status | Supportable | Top candidate | Confidence | Gaps |", "|---|---|---:|---|---:|---:|"]
    for row in result["scenarios"]:
        lines.append(f"| {row['scenario_id']} | {row['status']} | {row['supportable']} | {row['top_candidate'] or ''} | {row['confidence']} | {row['gap_count']} |")
    return "\n".join(lines) + "\n"
