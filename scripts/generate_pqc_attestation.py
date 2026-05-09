#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Generate an unsigned hash-bound PQC assurance attestation."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
PREDICATE_TYPE = (
    "https://github.com/atsana01/pqcp-zephyr-trust-stack/"
    "attestations/pqc-assurance/v1"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate pqc_attestation.intoto.json and optional assurance digest."
    )
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--ledger-md", type=Path)
    parser.add_argument("--assurance-report", type=Path)
    parser.add_argument("--cbom", type=Path, required=True)
    parser.add_argument("--release-manifest", type=Path, required=True)
    parser.add_argument("--transcript-manifest", type=Path, required=True)
    parser.add_argument("--benchmark-csv", type=Path)
    parser.add_argument("--benchmark-provenance", type=Path)
    parser.add_argument("--cost-of-assurance-evidence", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--digest-output", type=Path)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"{label} not found: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"{label} root must be a JSON object: {path}")
    return raw


def git_optional(module_path: Path, *args: str) -> str | None:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(module_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def subject(path: Path, *, name: str | None = None, required: bool = True) -> dict[str, Any] | None:
    path = path.resolve()
    if not path.exists():
        if required:
            raise FileNotFoundError(f"attestation subject not found: {path}")
        return None
    if not path.is_file():
        if required:
            raise RuntimeError(f"attestation subject is not a file: {path}")
        return None
    return {
        "name": name or path.name,
        "digest": {"sha256": sha256_file(path)},
    }


def parse_west_projects(module_path: Path) -> dict[str, str]:
    projects: dict[str, str] = {}
    west_path = module_path / "west.yml"
    if not west_path.exists():
        return projects
    current: str | None = None
    for raw_line in west_path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("- name:"):
            current = stripped.split(":", 1)[1].strip().strip("'\"")
            continue
        if current and stripped.startswith("revision:"):
            projects[current] = stripped.split(":", 1)[1].strip().strip("'\"")
    return projects


def claim_summary(ledger: dict[str, Any]) -> dict[str, Any]:
    claims = [claim for claim in ledger.get("claims") or [] if isinstance(claim, dict)]
    required = [claim for claim in claims if claim.get("required", True)]
    return {
        "total": len(claims),
        "required": len(required),
        "pass": sum(1 for claim in claims if claim.get("status") == "pass"),
        "fail": sum(1 for claim in claims if claim.get("status") == "fail"),
        "not_applicable": sum(1 for claim in claims if claim.get("status") == "not_applicable"),
        "failed_required_claims": [
            claim.get("id")
            for claim in required
            if claim.get("status") == "fail"
        ],
    }


def build_subjects(args: argparse.Namespace) -> list[dict[str, Any]]:
    candidates: list[tuple[Path, str, bool]] = [
        (args.ledger, "assurance_ledger.json", True),
        (args.ledger_md or args.ledger.with_suffix(".md"), "assurance_ledger.md", True),
        (args.assurance_report or args.ledger.with_name("assurance_report.html"), "assurance_report.html", True),
        (args.cbom, "pqc_cbom.cdx.json", True),
        (args.benchmark_csv or args.ledger.with_name("benchmark_results.csv"), "benchmark_results.csv", True),
        (args.benchmark_provenance or args.ledger.with_name("benchmark_provenance.json"), "benchmark_provenance.json", True),
        (args.cost_of_assurance_evidence or args.ledger.with_name("cost_of_assurance_evidence.json"), "cost_of_assurance_evidence.json", True),
        (args.transcript_manifest, "transcripts/evidence_transcript_manifest.json", True),
        (args.release_manifest, "release-manifest.json", True),
        (args.module_path / "west.yml", "west.yml", True),
        (args.module_path / "CMakeLists.txt", "CMakeLists.txt", True),
    ]
    subjects = []
    for path, name, required in candidates:
        item = subject(path, name=name, required=required)
        if item is not None:
            subjects.append(item)
    return subjects


def build_attestation(args: argparse.Namespace) -> dict[str, Any]:
    module_path = args.module_path.resolve()
    ledger = load_json(args.ledger.resolve(), "assurance ledger")
    cbom = load_json(args.cbom.resolve(), "PQC CBOM")
    manifest = load_json(args.release_manifest.resolve(), "release manifest")
    west_dependencies = parse_west_projects(module_path)

    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": PREDICATE_TYPE,
        "subject": build_subjects(args),
        "predicate": {
            "schemaVersion": 1,
            "buildType": "local-pqcp-assurance-passport",
            "builder": {
                "id": "scripts/release_check.py",
                "version": str(ledger.get("version") or manifest.get("version") or "unknown"),
            },
            "invocation": {
                "configSource": {
                    "uri": git_optional(module_path, "config", "--get", "remote.origin.url") or str(module_path),
                    "digest": {"sha1": str(ledger.get("head_sha") or manifest.get("source_commit") or "")},
                    "entryPoint": "scripts/release_check.py",
                },
                "parameters": {
                    "tag": ledger.get("tag") or manifest.get("tag"),
                    "outputRoot": str(args.ledger.resolve().parent),
                },
            },
            "metadata": {
                "buildStartedOn": ledger.get("generated_at"),
                "buildFinishedOn": datetime.now(timezone.utc).isoformat(),
                "reproducible": False,
                "completeness": {
                    "parameters": True,
                    "environment": False,
                    "materials": True,
                },
            },
            "materials": [
                {"uri": f"git+https://github.com/zephyrproject-rtos/zephyr@{west_dependencies.get('zephyr', 'unknown')}"},
                {"uri": f"git+https://github.com/pq-code-package/mlkem-native@{west_dependencies.get('mlkem-native', 'unknown')}"},
                {"uri": f"git+https://github.com/pq-code-package/mldsa-native@{west_dependencies.get('mldsa-native', 'unknown')}"},
            ],
            "pqcAssurance": {
                "project": ledger.get("project", "pqcp-zephyr-trust-stack"),
                "version": ledger.get("version") or manifest.get("version"),
                "tag": ledger.get("tag") or manifest.get("tag"),
                "headSha": ledger.get("head_sha") or manifest.get("source_commit"),
                "dirty": ledger.get("dirty"),
                "ledgerSchemaVersion": ledger.get("schema_version"),
                "cbomSpecVersion": cbom.get("specVersion"),
                "claimSummary": claim_summary(ledger),
                "westDependencies": west_dependencies,
            },
        },
    }


def write_digest(output: Path, artifacts: list[Path], *, attestation_path: Path) -> None:
    entries = []
    for path in [*artifacts, attestation_path]:
        path = path.resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"cannot digest missing artifact: {path}")
        entries.append(
            {
                "path": path.name if path.parent == output.resolve().parent else str(path),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/generate_pqc_attestation.py",
        "digest_algorithm": "sha256",
        "artifacts": entries,
    }
    output.resolve().parent.mkdir(parents=True, exist_ok=True)
    output.resolve().write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    args.module_path = args.module_path.resolve()
    attestation = build_attestation(args)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(attestation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("PQC assurance attestation generated")
    print(f"  output: {output}")
    print(f"  subjects: {len(attestation['subject'])}")
    if args.digest_output:
        digest_artifacts = [
            args.ledger,
            args.cbom,
            args.transcript_manifest,
            args.benchmark_provenance or args.ledger.with_name("benchmark_provenance.json"),
            args.release_manifest,
        ]
        write_digest(args.digest_output, digest_artifacts, attestation_path=output)
        print(f"  digest: {args.digest_output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
