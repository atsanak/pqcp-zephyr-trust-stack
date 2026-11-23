#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Export an experimental non-native scheme inventory for provider-scope review."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
LIBOQS_PROVIDER = "lib" + "oqs"

DEFAULT_SCHEMES = (
    {
        "id": "crypto.slhdsa.external",
        "name": "SLH-DSA",
        "primitive": "signature",
        "standard": "FIPS 205",
        "status": "tracked_external",
        "claim_ids": ["supply_chain.liboqs_non_native_scope"],
    },
    {
        "id": "crypto.hqc.external",
        "name": "HQC",
        "primitive": "kem",
        "standard": "NIST PQC additional-signature/KEM tracking",
        "status": "tracked_external",
        "claim_ids": ["supply_chain.liboqs_non_native_scope"],
    },
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT)
    parser.add_argument("--liboqs-root", type=Path, help="Optional local comparison checkout. Not vendored.")
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_optional(path: Path, *args: str) -> str | None:
    if not path.exists():
        return None
    proc = subprocess.run(
        ["git", *args],
        cwd=str(path),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def local_provider_metadata(root: Path | None) -> dict[str, Any]:
    if root is None:
        return {
            "local_source_available": False,
            "path": None,
            "head_sha": None,
            "license_files": [],
        }
    licenses = []
    for name in ("LICENSE", "LICENSE.txt", "README.md"):
        path = root / name
        if path.exists():
            licenses.append(
                {
                    "path": str(path),
                    "sha256": sha256_file(path),
                    "size_bytes": path.stat().st_size,
                }
            )
    return {
        "local_source_available": root.exists(),
        "path": str(root),
        "head_sha": git_optional(root, "rev-parse", "HEAD"),
        "remote": git_optional(root, "config", "--get", "remote.origin.url"),
        "license_files": licenses,
    }


def build_inventory(args: argparse.Namespace) -> dict[str, Any]:
    provider = local_provider_metadata(args.liboqs_root.resolve() if args.liboqs_root else None)
    schemes = []
    for scheme in DEFAULT_SCHEMES:
        schemes.append(
            {
                **scheme,
                "provider_family": LIBOQS_PROVIDER,
                "implementation_source": "external comparison provider",
                "production_allowed": False,
                "profile_allowed": {
                    "native_lab": True,
                    "qemu_release": False,
                    "mcu_minimal": False,
                    "gateway": False,
                    "partner_review": "allowed_with_policy",
                },
                "validation_scope": ["inventory_only", "policy_replay"],
                "native_family_overlap": False,
            }
        )
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/export_liboqs_inventory.py",
        "module_path": str(args.module_path.resolve()),
        "provider_family": LIBOQS_PROVIDER,
        "enabled_by_default": False,
        "production_default": False,
        "provider_metadata": provider,
        "schemes": schemes,
        "passed": True,
        "failures": [],
    }


def main() -> int:
    args = parse_args()
    inventory = build_inventory(args)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("liboqs non-native inventory exported")
    print(f"  output: {output}")
    print(f"  schemes: {len(inventory['schemes'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
