#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Generate replayable PQC release reference values.

The reference-values artifact is the compact bridge between a release evidence
pack and a future device/appraisal workflow: it records the expected release
metadata, artifact hashes, required claim IDs, CBOM component identities, and
the firmware assurance digest root that a device sample can report.
"""

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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--cbom", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--assurance-digest", type=Path, required=True)
    parser.add_argument("--release-manifest", type=Path, required=True)
    parser.add_argument("--policy-result", type=Path, required=True)
    parser.add_argument("--profile-result", type=Path, required=True)
    parser.add_argument("--transcript-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
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
        raise RuntimeError(f"{label} root must be a JSON object")
    return raw


def canonical_digest_root(digest: dict[str, Any]) -> str:
    canonical = json.dumps(digest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


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


def cbom_component_ids(cbom: dict[str, Any]) -> list[str]:
    ids: set[str] = set()
    for component in cbom.get("components") or []:
        if not isinstance(component, dict):
            continue
        for key in ("bom-ref", "name"):
            value = component.get(key)
            if isinstance(value, str) and value:
                ids.add(value)
    return sorted(ids)


def required_claim_ids(ledger: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for claim in ledger.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        if claim.get("required", True) and isinstance(claim.get("id"), str):
            ids.append(claim["id"])
    return sorted(set(ids))


def allowed_profile_ids(profile: dict[str, Any]) -> list[str]:
    profile_ids: set[str] = set()
    for key in ("profiles", "profile_results", "accepted_profiles"):
        value = profile.get(key)
        if isinstance(value, dict):
            profile_ids.update(str(name) for name in value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    profile_ids.add(item)
                elif isinstance(item, dict) and isinstance(item.get("id"), str):
                    profile_ids.add(item["id"])
    summary = profile.get("summary")
    if isinstance(summary, dict):
        accepted = summary.get("accepted_profiles")
        if isinstance(accepted, list):
            profile_ids.update(str(item) for item in accepted)
    return sorted(profile_ids)


def artifact_hashes(paths: dict[str, Path]) -> dict[str, dict[str, Any]]:
    hashes: dict[str, dict[str, Any]] = {}
    for name, path in paths.items():
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"reference artifact not found: {path}")
        hashes[name] = {"sha256": sha256_file(path), "size_bytes": path.stat().st_size}
    return hashes


def build_reference(args: argparse.Namespace) -> dict[str, Any]:
    module_path = args.module_path.resolve()
    ledger = load_json(args.ledger.resolve(), "assurance ledger")
    cbom = load_json(args.cbom.resolve(), "PQC CBOM")
    attestation = load_json(args.attestation.resolve(), "PQC attestation")
    digest = load_json(args.assurance_digest.resolve(), "PQC assurance digest")
    manifest = load_json(args.release_manifest.resolve(), "release manifest")
    policy = load_json(args.policy_result.resolve(), "PQC policy result")
    profile = load_json(args.profile_result.resolve(), "PQC assurance profile result")
    transcript_manifest = load_json(args.transcript_manifest.resolve(), "transcript manifest")

    version = str(ledger.get("version") or manifest.get("version") or "")
    tag = str(ledger.get("tag") or manifest.get("tag") or "")
    head_sha = str(ledger.get("head_sha") or manifest.get("source_commit") or "")
    dirty = bool(ledger.get("dirty"))
    deps = manifest.get("dependencies") if isinstance(manifest.get("dependencies"), dict) else {}

    artifacts = artifact_hashes(
        {
            "assurance_ledger.json": args.ledger.resolve(),
            "pqc_cbom.cdx.json": args.cbom.resolve(),
            "pqc_attestation.intoto.json": args.attestation.resolve(),
            "pqc_assurance_digest.json": args.assurance_digest.resolve(),
            "release_manifest.json": args.release_manifest.resolve(),
            "pqc_policy_result.json": args.policy_result.resolve(),
            "pqc_assurance_profile_result.json": args.profile_result.resolve(),
            "transcripts/evidence_transcript_manifest.json": args.transcript_manifest.resolve(),
        }
    )

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/generate_pqc_reference_values.py",
        "project": str(ledger.get("project") or manifest.get("project") or "pqcp-zephyr-trust-stack"),
        "version": version,
        "tag": tag,
        "head_sha": head_sha,
        "dirty": dirty,
        "tag_commit": manifest.get("tag_commit"),
        "tag_points_to_head": manifest.get("tag_points_to_head"),
        "zephyr_revision": manifest.get("zephyr_revision") or deps.get("zephyr"),
        "sdk_version": manifest.get("sdk_version") or "unknown",
        "west_dependencies": deps,
        "artifact_hashes": artifacts,
        "expected_firmware_digest_root": canonical_digest_root(digest),
        "firmware_digest_artifact_count": len(digest.get("artifacts") or []),
        "required_claim_ids": required_claim_ids(ledger),
        "cbom_component_ids": cbom_component_ids(cbom),
        "allowed_profile_ids": allowed_profile_ids(profile),
        "policy_passed": policy.get("passed") is True,
        "profile_passed": profile.get("passed") is True,
        "attestation_subject_count": len(attestation.get("subject") or []),
        "transcript_count": len(transcript_manifest.get("transcripts") or transcript_manifest.get("entries") or []),
        "source_remote": git_optional(module_path, "config", "--get", "remote.origin.url"),
    }


def main() -> int:
    args = parse_args()
    try:
        reference = build_reference(args)
    except (OSError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(reference, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("PQC reference values generated")
    print(f"  output: {output}")
    print(f"  artifacts: {len(reference['artifact_hashes'])}")
    print(f"  firmware_digest: {reference['expected_firmware_digest_root']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
