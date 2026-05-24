#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Programmatic API for product/research evidence workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .baseline import compare_csvs
from .catalog import ExperimentCatalog
from .coverage import validate_coverage
from .cross_framework_bridge import (
    audit_cross_framework_evidence,
    compare_frameworks,
    ecosystem_gap_report,
    import_external_evidence,
    plan_cross_framework_experiments,
    score_evidence,
    verify_cross_framework_evidence_manifest,
)
from .deployment_decision import claim_matrix, compare_scenarios, plan_evidence, recommend_deployment
from .evidence_pack import EvidencePackBuilder
from .experiment_matrix import matrix_payload
from .paper_evidence import generate_paper_evidence_report
from .reproducibility_compare import compare_evidence_packs
from .result_quality import validate_result_csvs
from .statistical_sanity import analyze_statistics
from .models import BaselineComparisonReport, CatalogValidationResult, EvidencePackManifest, ExperimentSelection, RunManifest, ReproducibilitySnapshot
from .reproducibility import capture_reproducibility_snapshot
from .runner import ExperimentRunner


class ProductEvidenceApi:
    """Small stable API used by CLI, tests, and future dashboards."""

    def __init__(self, module_path: Path):
        self.module_path = module_path.resolve()

    def catalog(self, catalog_path: Path | None = None) -> ExperimentCatalog:
        return ExperimentCatalog(self.module_path, catalog_path)

    def validate_catalog(self, catalog_path: Path | None = None) -> CatalogValidationResult:
        return self.catalog(catalog_path).validate()

    def select_experiments(
        self,
        *,
        catalog_path: Path | None = None,
        ids: Iterable[str] | None = None,
        categories: Iterable[str] | None = None,
        profile: str | None = None,
        glob: str | None = None,
        contains: str | None = None,
        limit: int | None = None,
    ) -> ExperimentSelection:
        return self.catalog(catalog_path).select(
            ids=ids,
            categories=categories,
            profile=profile,
            glob=glob,
            contains=contains,
            limit=limit,
        )

    def run_experiments(
        self,
        *,
        selection: ExperimentSelection,
        output_root: Path,
        dry_run: bool,
        timeout_seconds: int = 300,
    ) -> RunManifest:
        return ExperimentRunner(self.module_path).run(
            selection,
            output_root,
            dry_run=dry_run,
            timeout_seconds=timeout_seconds,
        )

    def build_evidence_pack(
        self,
        *,
        output_root: Path,
        pack_id: str,
        profile: str,
        tag: str | None = None,
        required: Iterable[str] = (),
    ) -> EvidencePackManifest:
        return EvidencePackBuilder(self.module_path).build(
            output_root=output_root,
            pack_id=pack_id,
            profile=profile,
            tag=tag,
            required=required,
        )

    def validate_evidence_pack(self, *, output_root: Path) -> dict[str, object]:
        return EvidencePackBuilder(self.module_path).validate(output_root=output_root)

    def compare_baselines(
        self,
        *,
        candidate_csv: Path,
        baseline_csv: Path,
        output_root: Path,
        threshold: float = 1.05,
    ) -> BaselineComparisonReport:
        return compare_csvs(
            candidate_csv=candidate_csv,
            baseline_csv=baseline_csv,
            threshold=threshold,
            output_root=output_root,
        )

    def reproducibility(self) -> ReproducibilitySnapshot:
        return capture_reproducibility_snapshot(self.module_path)

    def readiness_matrix(self, *, catalog_path: Path | None = None) -> dict[str, object]:
        catalog = self.catalog(catalog_path)
        return matrix_payload(catalog.experiments, self.module_path)

    def compare_runs(self, *, packs: list[Path], output_root: Path) -> dict[str, object]:
        return compare_evidence_packs(packs=packs, output_root=output_root)

    def validate_coverage(self, *, output_root: Path, catalog_path: Path | None = None) -> dict[str, object]:
        return validate_coverage(catalog=self.catalog(catalog_path), output_root=output_root)

    def validate_results(
        self,
        *,
        csv_paths: list[Path],
        output_root: Path,
        zero_is_fail: bool = False,
        require_core_combos: bool = True,
    ) -> dict[str, object]:
        return validate_result_csvs(
            csv_paths=csv_paths,
            output_root=output_root,
            zero_is_fail=zero_is_fail,
            require_core_combos=require_core_combos,
        )

    def statistical_sanity(
        self,
        *,
        csv_paths: list[Path],
        output_root: Path,
        min_samples: int = 3,
        cv_warn_threshold: float = 0.10,
    ) -> dict[str, object]:
        return analyze_statistics(
            csv_paths=csv_paths,
            output_root=output_root,
            min_samples=min_samples,
            cv_warn_threshold=cv_warn_threshold,
        )

    def paper_evidence_report(
        self,
        *,
        output_root: Path,
        reports: dict[str, Path | None],
    ) -> dict[str, object]:
        return generate_paper_evidence_report(output_root=output_root, reports=reports)

    def recommend_deployment(
        self,
        *,
        scenario_path: Path,
        output_root: Path,
        packs: list[Path] | None = None,
        csv_paths: list[Path] | None = None,
        validation_reports: list[Path] | None = None,
    ) -> dict[str, object]:
        return recommend_deployment(
            scenario_path=scenario_path,
            module_path=self.module_path,
            output_root=output_root,
            packs=packs,
            csv_paths=csv_paths,
            validation_reports=validation_reports,
        )

    def plan_evidence(
        self,
        *,
        scenario_path: Path,
        output_root: Path,
        catalog_path: Path | None = None,
        packs: list[Path] | None = None,
        csv_paths: list[Path] | None = None,
        validation_reports: list[Path] | None = None,
    ) -> dict[str, object]:
        return plan_evidence(
            scenario_path=scenario_path,
            module_path=self.module_path,
            output_root=output_root,
            catalog_path=catalog_path,
            packs=packs,
            csv_paths=csv_paths,
            validation_reports=validation_reports,
        )

    def claim_matrix(
        self,
        *,
        output_root: Path,
        packs: list[Path] | None = None,
        csv_paths: list[Path] | None = None,
        validation_reports: list[Path] | None = None,
    ) -> dict[str, object]:
        return claim_matrix(
            module_path=self.module_path,
            output_root=output_root,
            packs=packs,
            csv_paths=csv_paths,
            validation_reports=validation_reports,
        )

    def compare_scenarios(
        self,
        *,
        scenario_paths: list[Path],
        output_root: Path,
        packs: list[Path] | None = None,
        csv_paths: list[Path] | None = None,
        validation_reports: list[Path] | None = None,
    ) -> dict[str, object]:
        return compare_scenarios(
            scenario_paths=scenario_paths,
            module_path=self.module_path,
            output_root=output_root,
            packs=packs,
            csv_paths=csv_paths,
            validation_reports=validation_reports,
        )

    def import_external_evidence(
        self,
        *,
        source_type: str,
        input_paths: list[Path],
        output_root: Path,
        aliases: dict[str, str] | None = None,
    ) -> dict[str, object]:
        return import_external_evidence(
            source_type=source_type,
            input_paths=input_paths,
            output_root=output_root,
            aliases=aliases,
        )

    def compare_frameworks(self, *, evidence_paths: list[Path], output_root: Path) -> dict[str, object]:
        return compare_frameworks(evidence_paths=evidence_paths, output_root=output_root)

    def verify_cross_framework_evidence_manifest(self, *, manifest_path: Path, output_root: Path) -> dict[str, object]:
        return verify_cross_framework_evidence_manifest(manifest_path=manifest_path, output_root=output_root)

    def audit_cross_framework_evidence(self, *, evidence_paths: list[Path], output_root: Path) -> dict[str, object]:
        return audit_cross_framework_evidence(evidence_paths=evidence_paths, output_root=output_root)

    def score_evidence(
        self,
        *,
        evidence_paths: list[Path],
        output_root: Path,
        scenario_path: Path | None = None,
    ) -> dict[str, object]:
        return score_evidence(evidence_paths=evidence_paths, output_root=output_root, scenario_path=scenario_path)

    def plan_cross_framework_experiments(
        self,
        *,
        evidence_paths: list[Path],
        output_root: Path,
        catalog_path: Path | None = None,
    ) -> dict[str, object]:
        return plan_cross_framework_experiments(
            evidence_paths=evidence_paths,
            module_path=self.module_path,
            output_root=output_root,
            catalog_path=catalog_path,
        )

    def ecosystem_gap_report(
        self,
        *,
        evidence_paths: list[Path],
        output_root: Path,
        pack: Path | None = None,
    ) -> dict[str, object]:
        return ecosystem_gap_report(evidence_paths=evidence_paths, output_root=output_root, pack=pack)
