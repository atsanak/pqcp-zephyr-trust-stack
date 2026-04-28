#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Focused tests for the local assurance ledger generator."""

from __future__ import annotations

import csv
import hashlib
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import generate_assurance_ledger as ledger
from export_results import CSV_FIELDNAMES, EXPECTED_PRIMITIVE_ROWS


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AssuranceLedgerTests(unittest.TestCase):
    def make_module(self, root: Path) -> None:
        (root / "include/pqcp_zephyr").mkdir(parents=True)
        (root / "include/pqcp_zephyr/version.h").write_text(
            '#define PQCP_VERSION_STRING "1.2.3"\n',
            encoding="utf-8",
        )
        (root / "CMakeLists.txt").write_text(
            'set(PQCP_PROJECT_VERSION "1.2.3")\n',
            encoding="utf-8",
        )
        (root / "CHANGELOG.md").write_text(
            "## [Unreleased]\n\n## [1.2.3] - 2026-04-28\n\n- shipped\n",
            encoding="utf-8",
        )

    def make_claims(self, root: Path, claim_ids: list[str]) -> Path:
        all_claims = json.loads((ledger.DEFAULT_CLAIMS).read_text(encoding="utf-8"))["claims"]
        selected = [claim for claim in all_claims if claim["id"] in claim_ids]
        path = root / "claims.json"
        path.write_text(
            json.dumps({"schema_version": 1, "claims": selected}, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def make_benchmark_csv(self, root: Path) -> Path:
        path = root / "benchmark_results.csv"
        rows: list[dict[str, object]] = []
        for parameter_set, operations in EXPECTED_PRIMITIVE_ROWS.items():
            suite = parameter_set.split("-")[1]
            for operation in operations:
                for implementation in ("pqcp", "baseline"):
                    rows.append(
                        {
                            "suite": suite,
                            "parameter_set": parameter_set,
                            "implementation": implementation,
                            "backend": "auto" if implementation == "pqcp" else "clean",
                            "operation": operation,
                            "cycles": 1000,
                            "time_us": 100,
                            "rom_bytes": 2000,
                            "ram_bytes": 3000,
                            "platform": "qemu_x86_64",
                            "timestamp": "2026-04-28T00:00:00+00:00",
                        }
                    )
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_FIELDNAMES)
            writer.writeheader()
            writer.writerows(rows)
        return path

    def make_provenance(self, csv_path: Path) -> Path:
        path = csv_path.with_name("benchmark_provenance.json")
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "csv": {
                        "path": csv_path.name,
                        "sha256": sha256(csv_path),
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def make_cost_evidence(self, root: Path, *, metric: bool = True) -> Path:
        path = root / "cost_of_assurance_evidence.json"
        metrics = [
            {
                "metric": "handshake_time",
                "candidate_value": 10.0,
                "baseline_value": 8.0,
                "ratio": 1.25,
                "threshold": {"max_ratio": 6.0},
                "passed": True,
                "failure_reason": None,
            }
        ] if metric else []
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "comparisons": [
                        {
                            "name": "comparison-a",
                            "passed": True,
                            "failure_reason": None,
                            "metrics": metrics,
                        }
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def make_release_bundle(self, root: Path) -> Path:
        bundle = root / "bundle" / "v1.2.3"
        bundle.mkdir(parents=True)
        notes = bundle / "release-notes-v1.2.3.md"
        notes.write_text("- shipped\n", encoding="utf-8")
        (bundle / "release-manifest-v1.2.3.json").write_text(
            json.dumps(
                {
                    "version": "1.2.3",
                    "tag": "v1.2.3",
                    "release_notes": {
                        "path": notes.name,
                        "sha256": sha256(notes),
                    },
                    "tag_points_to_head": False,
                    "working_tree_dirty": False,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return root / "bundle"

    def make_args(
        self,
        root: Path,
        claims: Path,
        csv_path: Path,
        provenance: Path,
        cost_evidence: Path,
        bundle: Path,
        *,
        tag: str | None = None,
    ) -> Namespace:
        return Namespace(
            module_path=root,
            claims=claims,
            version=None,
            tag=tag,
            benchmark_csv=csv_path,
            benchmark_provenance=provenance,
            cost_of_assurance_evidence=cost_evidence,
            release_bundle_root=bundle,
            kat_header=root / "missing_kat_vectors.h",
            kat_vectors_dir=root / "missing_nist_vectors",
            output_json=root / "assurance_ledger.json",
            output_md=root / "assurance_ledger.md",
        )

    def test_passing_ledger_from_synthetic_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            provenance = self.make_provenance(csv_path)
            cost = self.make_cost_evidence(root)
            bundle = self.make_release_bundle(root)
            claims = self.make_claims(
                root,
                [
                    "release.version_consistency",
                    "benchmark.csv_validity",
                    "benchmark.provenance_binding",
                    "cost_of_assurance.guardrails",
                    "release.local_bundle",
                ],
            )
            result = ledger.build_ledger(
                self.make_args(root, claims, csv_path, provenance, cost, bundle, tag="v1.2.3")
            )
            self.assertEqual(result["summary"]["fail"], 0)

    def test_missing_benchmark_provenance_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            claims = self.make_claims(root, ["benchmark.provenance_binding"])
            result = ledger.build_ledger(
                self.make_args(
                    root,
                    claims,
                    csv_path,
                    root / "missing-provenance.json",
                    self.make_cost_evidence(root),
                    self.make_release_bundle(root),
                )
            )
            self.assertEqual(result["claims"][0]["status"], "fail")

    def test_corrupted_csv_hash_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            provenance = self.make_provenance(csv_path)
            with csv_path.open("a", encoding="utf-8") as handle:
                handle.write("# corrupt\n")
            claims = self.make_claims(root, ["benchmark.provenance_binding"])
            result = ledger.build_ledger(
                self.make_args(
                    root,
                    claims,
                    csv_path,
                    provenance,
                    self.make_cost_evidence(root),
                    self.make_release_bundle(root),
                )
            )
            self.assertEqual(result["claims"][0]["status"], "fail")

    def test_missing_cost_metric_evidence_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            claims = self.make_claims(root, ["cost_of_assurance.guardrails"])
            result = ledger.build_ledger(
                self.make_args(
                    root,
                    claims,
                    csv_path,
                    self.make_provenance(csv_path),
                    self.make_cost_evidence(root, metric=False),
                    self.make_release_bundle(root),
                )
            )
            self.assertEqual(result["claims"][0]["status"], "fail")

    def test_tag_claim_is_not_applicable_without_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            claims = self.make_claims(root, ["release.tag_integrity"])
            result = ledger.build_ledger(
                self.make_args(
                    root,
                    claims,
                    csv_path,
                    self.make_provenance(csv_path),
                    self.make_cost_evidence(root),
                    self.make_release_bundle(root),
                )
            )
            self.assertEqual(result["claims"][0]["status"], "not_applicable")

    def test_markdown_and_json_include_same_claim_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_module(root)
            csv_path = self.make_benchmark_csv(root)
            claims = self.make_claims(
                root,
                ["release.version_consistency", "benchmark.csv_validity"],
            )
            result = ledger.build_ledger(
                self.make_args(
                    root,
                    claims,
                    csv_path,
                    self.make_provenance(csv_path),
                    self.make_cost_evidence(root),
                    self.make_release_bundle(root),
                )
            )
            markdown = ledger.render_markdown(result)
            for claim in result["claims"]:
                self.assertIn(claim["id"], markdown)


if __name__ == "__main__":
    unittest.main()
