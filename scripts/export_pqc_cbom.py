#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Export a CycloneDX-style cryptography BOM for the PQCP assurance pack."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from check_version_consistency import parse_header_version  # noqa: E402

LICENSE_EXPRESSION = "LicenseRef-Proprietary-Collaborative-Evaluation"
DEFAULT_PROFILE = SCRIPT_DIR / "pqc_assurance_profile.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate pqc_cbom.cdx.json from release assurance artifacts."
    )
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--release-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


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


def parse_west_projects(module_path: Path) -> dict[str, dict[str, str]]:
    """Parse the simple project records used by the repository west.yml."""
    west_path = module_path / "west.yml"
    projects: dict[str, dict[str, str]] = {}
    if not west_path.exists():
        return projects

    current: dict[str, str] | None = None
    for raw_line in west_path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("- name:"):
            name = stripped.split(":", 1)[1].strip().strip("'\"")
            current = {"name": name}
            projects[name] = current
            continue
        if current is None or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if key in {"remote", "revision", "path"}:
            current[key] = value
    return projects


def parse_sdk_version(module_path: Path) -> str | None:
    """Return the workflow SDK version when it is pinned in GitHub Actions."""
    workflow_dir = module_path / ".github/workflows"
    if not workflow_dir.exists():
        return None
    pattern = re.compile(r"ZEPHYR_SDK_VERSION:\s*[\"']?([^\"'\n]+)")
    for path in sorted(workflow_dir.glob("*.yml")):
        match = pattern.search(path.read_text(encoding="utf-8"))
        if match:
            return match.group(1).strip()
    return None


def property_item(name: str, value: object) -> dict[str, str]:
    return {"name": name, "value": str(value)}


def licenses() -> list[dict[str, dict[str, str]]]:
    return [{"license": {"id": LICENSE_EXPRESSION}}]


def claim_statuses(ledger: dict[str, Any]) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for claim in ledger.get("claims") or []:
        if isinstance(claim, dict) and isinstance(claim.get("id"), str):
            statuses[claim["id"]] = str(claim.get("status", "unknown"))
    return statuses


def load_profile_metadata(module_path: Path) -> dict[str, dict[str, Any]]:
    """Return CBOM component profile metadata from pqc_assurance_profile.json."""
    profile_path = module_path / "scripts/pqc_assurance_profile.json"
    if not profile_path.exists():
        profile_path = DEFAULT_PROFILE
    if not profile_path.exists():
        return {}
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    metadata: dict[str, dict[str, Any]] = {}
    for item in profile.get("asset_lifecycle") or []:
        if not isinstance(item, dict):
            continue
        component = item.get("cbom_component")
        asset_id = item.get("asset_id")
        if not isinstance(component, str) or not component:
            continue
        if not isinstance(asset_id, str) or not asset_id:
            continue
        metadata[component] = {
            "trace_asset_id": asset_id,
            "lifecycle_status": item.get("lifecycle_status", "unknown"),
            "production_allowed": bool(item.get("production_allowed", False)),
            "profile_support": item.get("profile_support") or [],
            "validation_scope": item.get("validation_scope") or [],
        }
    return metadata


def crypto_asset(
    *,
    name: str,
    bom_ref: str,
    primitive: str,
    parameter_set: str,
    standard: str,
    production_status: str,
    claim_ids: list[str],
    usage: str,
) -> dict[str, Any]:
    return {
        "type": "cryptographic-asset",
        "bom-ref": bom_ref,
        "name": name,
        "version": standard,
        "licenses": licenses(),
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": primitive,
                "parameterSetIdentifier": parameter_set,
            },
        },
        "properties": [
            property_item("pqcp:standard", standard),
            property_item("pqcp:production_status", production_status),
            property_item("pqcp:usage", usage),
            property_item("pqcp:claim_ids", ",".join(claim_ids)),
        ],
    }


def library_component(
    *,
    name: str,
    version: str | None,
    bom_ref: str,
    purpose: str,
) -> dict[str, Any]:
    return {
        "type": "library",
        "bom-ref": bom_ref,
        "name": name,
        "version": version or "unknown",
        "licenses": licenses(),
        "properties": [
            property_item("pqcp:purpose", purpose),
        ],
    }


def build_cbom(module_path: Path, ledger: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    version = str(manifest.get("version") or ledger.get("version") or parse_header_version(module_path))
    tag = str(manifest.get("tag") or ledger.get("tag") or "")
    head_sha = str(manifest.get("source_commit") or ledger.get("head_sha") or "")
    dirty = bool(manifest.get("working_tree_dirty", ledger.get("dirty", False)))
    west_projects = parse_west_projects(module_path)
    dependencies = manifest.get("dependencies")
    if not isinstance(dependencies, dict):
        dependencies = {}
    sdk_version = parse_sdk_version(module_path) or "unknown"
    statuses = claim_statuses(ledger)
    profile_metadata = load_profile_metadata(module_path)

    components: list[dict[str, Any]] = [
        crypto_asset(
            name="ML-KEM-512",
            bom_ref="pqcp:crypto:ml-kem-512",
            primitive="kem",
            parameter_set="ML-KEM-512",
            standard="FIPS 203",
            production_status="supported",
            claim_ids=["kat.mlkem_512", "benchmark.mlkem_throughput"],
            usage="key establishment",
        ),
        crypto_asset(
            name="ML-KEM-768",
            bom_ref="pqcp:crypto:ml-kem-768",
            primitive="kem",
            parameter_set="ML-KEM-768",
            standard="FIPS 203",
            production_status="supported",
            claim_ids=["kat.mlkem_768", "benchmark.mlkem_throughput", "security.ct_smoke"],
            usage="key establishment and TLS self-test",
        ),
        crypto_asset(
            name="ML-KEM-1024",
            bom_ref="pqcp:crypto:ml-kem-1024",
            primitive="kem",
            parameter_set="ML-KEM-1024",
            standard="FIPS 203",
            production_status="supported",
            claim_ids=["kat.mlkem_1024", "benchmark.mlkem_throughput"],
            usage="key establishment",
        ),
        crypto_asset(
            name="ML-DSA-44",
            bom_ref="pqcp:crypto:ml-dsa-44",
            primitive="signature",
            parameter_set="ML-DSA-44",
            standard="FIPS 204",
            production_status="supported",
            claim_ids=["kat.mldsa_44", "benchmark.mldsa_throughput"],
            usage="digital signature",
        ),
        crypto_asset(
            name="ML-DSA-65",
            bom_ref="pqcp:crypto:ml-dsa-65",
            primitive="signature",
            parameter_set="ML-DSA-65",
            standard="FIPS 204",
            production_status="supported",
            claim_ids=["kat.mldsa_65", "benchmark.mldsa_throughput"],
            usage="digital signature and TLS self-test",
        ),
        crypto_asset(
            name="ML-DSA-87",
            bom_ref="pqcp:crypto:ml-dsa-87",
            primitive="signature",
            parameter_set="ML-DSA-87",
            standard="FIPS 204",
            production_status="supported",
            claim_ids=["kat.mldsa_87", "benchmark.mldsa_throughput"],
            usage="digital signature",
        ),
        crypto_asset(
            name="ACVP serial validation harness",
            bom_ref="pqcp:validation:acvp-serial",
            primitive="validation-protocol",
            parameter_set="ACVP serial",
            standard="NIST ACVP-compatible",
            production_status="lab_only",
            claim_ids=[
                "acvp.negative_path_rejection",
                "acvp.timeout_recovery",
                "acvp.negative_scenarios_replay",
            ],
            usage="lab validation and negative-path replay",
        ),
        crypto_asset(
            name="TLS/PSA PQC self-test path",
            bom_ref="pqcp:validation:tls-selftest",
            primitive="protocol-self-test",
            parameter_set="TLS13-ML-KEM-768-ML-DSA-65",
            standard="PQCP offline validation",
            production_status="validation_only",
            claim_ids=["security.asan_clean", "security.ubsan_clean"],
            usage="offline integration self-test and protocol metrics",
        ),
        crypto_asset(
            name="Zephyr entropy RNG",
            bom_ref="pqcp:rng:zephyr-entropy",
            primitive="rng",
            parameter_set="CONFIG_PQCP_RNG_ZEPHYR_ENTROPY",
            standard="Zephyr entropy API",
            production_status="supported",
            claim_ids=[],
            usage="production entropy backend",
        ),
        crypto_asset(
            name="PSA RNG",
            bom_ref="pqcp:rng:psa",
            primitive="rng",
            parameter_set="CONFIG_PQCP_RNG_PSA",
            standard="PSA Crypto RNG",
            production_status="supported",
            claim_ids=[],
            usage="production PSA RNG backend",
        ),
        crypto_asset(
            name="Deterministic test RNG",
            bom_ref="pqcp:rng:deterministic-test",
            primitive="rng",
            parameter_set="CONFIG_PQCP_RNG_DETERMINISTIC_TEST",
            standard="PQCP deterministic KAT RNG",
            production_status="test_only",
            claim_ids=["kat.offline_provenance"],
            usage="KAT and deterministic test vectors only",
        ),
        library_component(
            name="Zephyr RTOS",
            version=str(dependencies.get("zephyr") or west_projects.get("zephyr", {}).get("revision") or "unknown"),
            bom_ref="pqcp:dependency:zephyr",
            purpose="RTOS baseline imported by west.yml",
        ),
        library_component(
            name="Zephyr SDK",
            version=sdk_version,
            bom_ref="pqcp:dependency:zephyr-sdk",
            purpose="CI and local build toolchain",
        ),
        library_component(
            name="mlkem-native",
            version=str(dependencies.get("mlkem-native") or west_projects.get("mlkem-native", {}).get("revision") or "unknown"),
            bom_ref="pqcp:dependency:mlkem-native",
            purpose="ML-KEM implementation backend",
        ),
        library_component(
            name="mldsa-native",
            version=str(dependencies.get("mldsa-native") or west_projects.get("mldsa-native", {}).get("revision") or "unknown"),
            bom_ref="pqcp:dependency:mldsa-native",
            purpose="ML-DSA implementation backend",
        ),
    ]

    for component in components:
        metadata = profile_metadata.get(str(component.get("name")))
        if metadata:
            component.setdefault("properties", []).extend(
                [
                    property_item("pqcp:trace_asset_id", metadata["trace_asset_id"]),
                    property_item("pqcp:lifecycle_status", metadata["lifecycle_status"]),
                    property_item(
                        "pqcp:production_allowed",
                        str(metadata["production_allowed"]).lower(),
                    ),
                    property_item(
                        "pqcp:profile_support",
                        ",".join(str(item) for item in metadata["profile_support"]),
                    ),
                    property_item(
                        "pqcp:validation_scope",
                        ",".join(str(item) for item in metadata["validation_scope"]),
                    ),
                ]
            )
        linked_claims = ""
        for prop in component.get("properties", []):
            if prop.get("name") == "pqcp:claim_ids":
                linked_claims = prop.get("value", "")
                break
        if linked_claims:
            for claim_id in linked_claims.split(","):
                if claim_id:
                    component.setdefault("properties", []).append(
                        property_item(f"pqcp:claim_status:{claim_id}", statuses.get(claim_id, "missing"))
                    )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "bom-ref": "pqcp:project:pqcp-zephyr-trust-stack",
                "name": "pqcp-zephyr-trust-stack",
                "version": version,
                "licenses": licenses(),
                "properties": [
                    property_item("pqcp:tag", tag),
                    property_item("pqcp:head_sha", head_sha),
                    property_item("pqcp:dirty", str(dirty).lower()),
                    property_item("pqcp:ledger_schema_version", ledger.get("schema_version", "unknown")),
                    property_item("pqcp:claim_pass_count", ledger.get("summary", {}).get("pass", "unknown")),
                    property_item("pqcp:source", git_optional(module_path, "config", "--get", "remote.origin.url") or "local"),
                ],
            },
        },
        "components": components,
        "dependencies": [
            {
                "ref": "pqcp:project:pqcp-zephyr-trust-stack",
                "dependsOn": [component["bom-ref"] for component in components],
            }
        ],
    }


def main() -> int:
    args = parse_args()
    module_path = args.module_path.resolve()
    ledger = load_json(args.ledger.resolve(), "assurance ledger")
    manifest = load_json(args.release_manifest.resolve(), "release manifest")
    cbom = build_cbom(module_path, ledger, manifest)
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(cbom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("PQC CBOM generated")
    print(f"  output: {args.output.resolve()}")
    print(f"  components: {len(cbom['components'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
