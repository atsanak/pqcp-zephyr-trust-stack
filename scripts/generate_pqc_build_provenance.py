#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Generate an unsigned SLSA-shaped build provenance statement."""

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
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT)
    parser.add_argument("--release-manifest", type=Path, required=True)
    parser.add_argument("--claims", type=Path, default=SCRIPT_DIR / "assurance_claims.json")
    parser.add_argument("--policy", type=Path, default=SCRIPT_DIR / "pqc_assurance_policy.json")
    parser.add_argument("--profile", type=Path, default=SCRIPT_DIR / "pqc_assurance_profile.json")
    parser.add_argument("--subject", type=Path, action="append", default=[])
    parser.add_argument("--byproduct", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path, label: str) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"{label} root must be a JSON object")
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


def named_digest(path: Path, *, base: Path | None = None) -> dict[str, Any]:
    path = path.resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"provenance input not found: {path}")
    name = str(path)
    if base is not None:
        try:
            name = str(path.relative_to(base.resolve()))
        except ValueError:
            name = path.name
    return {"name": name, "digest": {"sha256": sha256_file(path)}}


def parse_west_revisions(module_path: Path) -> dict[str, str]:
    revisions: dict[str, str] = {}
    west = module_path / "west.yml"
    current: str | None = None
    if not west.exists():
        return revisions
    for raw in west.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped.startswith("- name:"):
            current = stripped.split(":", 1)[1].strip().strip("'\"")
        elif current and stripped.startswith("revision:"):
            revisions[current] = stripped.split(":", 1)[1].strip().strip("'\"")
            current = None
    return revisions


def build_statement(args: argparse.Namespace) -> dict[str, Any]:
    module_path = args.module_path.resolve()
    manifest = load_json(args.release_manifest.resolve(), "release manifest")
    revisions = parse_west_revisions(module_path)
    source_commit = manifest.get("source_commit") or git_optional(module_path, "rev-parse", "HEAD")
    subjects = [named_digest(path, base=args.release_manifest.resolve().parent.parent.parent) for path in args.subject]
    if not subjects:
        raise RuntimeError("at least one --subject is required")
    resolved = [
        named_digest(module_path / "west.yml", base=module_path),
        named_digest(module_path / "CMakeLists.txt", base=module_path),
        named_digest(args.release_manifest.resolve()),
        named_digest(args.claims.resolve()),
        named_digest(args.policy.resolve()),
        named_digest(args.profile.resolve()),
    ]
    for name, revision in sorted((manifest.get("dependencies") or revisions).items()):
        resolved.append({"uri": name, "digest": {"gitCommit": revision}})
    byproducts = [named_digest(path, base=args.release_manifest.resolve().parent.parent.parent) for path in args.byproduct if path.exists()]
    return {
        "_type": STATEMENT_TYPE,
        "predicateType": PREDICATE_TYPE,
        "subject": subjects,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/atsana01/pqcp-zephyr-trust-stack/build-types/local-release/v1",
                "externalParameters": {
                    "tag": manifest.get("tag"),
                    "version": manifest.get("version"),
                    "source_commit": source_commit,
                },
                "internalParameters": {
                    "release_check": "scripts/release_check.py",
                    "github_actions_required": False,
                },
                "resolvedDependencies": resolved,
            },
            "runDetails": {
                "builder": {"id": "pqcp-local-release-check"},
                "metadata": {
                    "invocationId": f"local:{source_commit}:{manifest.get('tag')}",
                    "startedOn": manifest.get("generated_at"),
                    "finishedOn": datetime.now(timezone.utc).isoformat(),
                },
                "byproducts": byproducts,
            },
        },
    }


def main() -> int:
    args = parse_args()
    try:
        statement = build_statement(args)
    except (OSError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(statement, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("PQC build provenance generated")
    print(f"  output: {args.output.resolve()}")
    print(f"  subjects: {len(statement['subject'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
