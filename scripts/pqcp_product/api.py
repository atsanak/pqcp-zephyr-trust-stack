#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Programmatic API for product/research evidence workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .baseline import compare_csvs
from .catalog import ExperimentCatalog
from .evidence_pack import EvidencePackBuilder
from .experiment_matrix import matrix_payload
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
