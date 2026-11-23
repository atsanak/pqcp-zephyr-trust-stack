#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression tests for SLSA-shaped PQC build provenance."""

from __future__ import annotations

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import generate_pqc_build_provenance
import verify_pqc_build_provenance


class BuildProvenanceTests(unittest.TestCase):
    def fixtures(self, root: Path) -> Namespace:
        (root / "west.yml").write_text("manifest:\n  projects:\n  - name: zephyr\n    revision: abc\n", encoding="utf-8")
        (root / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.20)\n", encoding="utf-8")
        claims = root / "assurance_claims.json"
        policy = root / "pqc_assurance_policy.json"
        profile = root / "pqc_assurance_profile.json"
        for path in (claims, policy, profile):
            path.write_text("{}\n", encoding="utf-8")
        manifest = root / "release-manifest-v1.0.0.json"
        manifest.write_text(
            json.dumps({"version": "1.0.0", "tag": "v1.0.0", "source_commit": "abc123", "dependencies": {"zephyr": "abc"}}),
            encoding="utf-8",
        )
        subject = root / "pqc_reference_values.json"
        subject.write_text('{"schema_version":1}\n', encoding="utf-8")
        byproduct = root / "ct_sample_analysis_result.json"
        byproduct.write_text('{"schema_version":1,"passed":true}\n', encoding="utf-8")
        return Namespace(
            module_path=root,
            release_manifest=manifest,
            claims=claims,
            policy=policy,
            profile=profile,
            subject=[subject],
            byproduct=[byproduct],
            output=root / "pqc_build_provenance.slsa.json",
        )

    def test_generate_and_verify_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixtures(Path(tmp))
            statement = generate_pqc_build_provenance.build_statement(args)
            args.output.write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")
            result = verify_pqc_build_provenance.verify(
                Namespace(
                    provenance=args.output,
                    subject=args.subject,
                    byproduct=args.byproduct,
                    release_manifest=args.release_manifest,
                    output=Path(tmp) / "result.json",
                )
            )
            self.assertTrue(result["passed"], result["failures"])

    def test_unexpected_external_parameter_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixtures(Path(tmp))
            statement = generate_pqc_build_provenance.build_statement(args)
            statement["predicate"]["buildDefinition"]["externalParameters"]["surprise"] = "nope"
            args.output.write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")
            result = verify_pqc_build_provenance.verify(
                Namespace(provenance=args.output, subject=args.subject, byproduct=args.byproduct, release_manifest=args.release_manifest, output=Path(tmp) / "result.json")
            )
            self.assertFalse(result["passed"])

    def test_wrong_predicate_type_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixtures(Path(tmp))
            statement = generate_pqc_build_provenance.build_statement(args)
            statement["predicateType"] = "wrong"
            args.output.write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")
            result = verify_pqc_build_provenance.verify(
                Namespace(provenance=args.output, subject=args.subject, byproduct=args.byproduct, release_manifest=args.release_manifest, output=Path(tmp) / "result.json")
            )
            self.assertFalse(result["passed"])

    def test_missing_subject_hash_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixtures(Path(tmp))
            statement = generate_pqc_build_provenance.build_statement(args)
            statement["subject"] = []
            args.output.write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")
            result = verify_pqc_build_provenance.verify(
                Namespace(provenance=args.output, subject=args.subject, byproduct=args.byproduct, release_manifest=args.release_manifest, output=Path(tmp) / "result.json")
            )
            self.assertFalse(result["passed"])

    def test_missing_resolved_dependency_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixtures(Path(tmp))
            statement = generate_pqc_build_provenance.build_statement(args)
            statement["predicate"]["buildDefinition"]["resolvedDependencies"] = []
            args.output.write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")
            result = verify_pqc_build_provenance.verify(
                Namespace(provenance=args.output, subject=args.subject, byproduct=args.byproduct, release_manifest=args.release_manifest, output=Path(tmp) / "result.json")
            )
            self.assertFalse(result["passed"])

    def test_stale_byproduct_digest_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixtures(Path(tmp))
            statement = generate_pqc_build_provenance.build_statement(args)
            args.output.write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")
            args.byproduct[0].write_text("tampered\n", encoding="utf-8")
            result = verify_pqc_build_provenance.verify(
                Namespace(provenance=args.output, subject=args.subject, byproduct=args.byproduct, release_manifest=args.release_manifest, output=Path(tmp) / "result.json")
            )
            self.assertFalse(result["passed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
