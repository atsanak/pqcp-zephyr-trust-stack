#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Generate repo-grounded research and product hardening dossiers.

The dossier is a derived release artifact. It does not invent claims and it does
not replace the Assurance Passport. It reads the live claim catalog, trace map,
policy, profile, benchmark campaign configuration, and optional release-pack
outputs, then emits long-form analysis that names the exact evidence objects a
reviewer can inspect.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1

REFERENCE_ANCHORS = [
    {
        "id": "nist-fips-203",
        "name": "NIST FIPS 203: ML-KEM",
        "url": "https://csrc.nist.gov/pubs/fips/203/final",
        "relevance": "Defines the ML-KEM primitive family and parameter sets that this module inventories and validates.",
    },
    {
        "id": "nist-fips-204",
        "name": "NIST FIPS 204: ML-DSA",
        "url": "https://csrc.nist.gov/pubs/fips/204/final",
        "relevance": "Defines the ML-DSA signature family and parameter sets that this module inventories and validates.",
    },
    {
        "id": "nist-nccoe-pqc-migration",
        "name": "NIST NCCoE Migration to Post-Quantum Cryptography",
        "url": "https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc",
        "relevance": "Motivates crypto inventory, migration readiness, and evidence that downstream teams can review.",
    },
    {
        "id": "cisa-quantum-readiness",
        "name": "CISA Quantum Readiness",
        "url": "https://www.cisa.gov/quantum",
        "relevance": "Frames operational readiness around inventory, prioritization, and migration planning.",
    },
    {
        "id": "cyclonedx-cbom",
        "name": "CycloneDX Cryptography Bill of Materials",
        "url": "https://cyclonedx.org/capabilities/cbom/",
        "relevance": "Provides the external shape for cryptographic asset inventory and evidence links.",
    },
    {
        "id": "in-toto-attestation",
        "name": "in-toto Attestation Framework",
        "url": "https://github.com/in-toto/attestation/tree/main/spec",
        "relevance": "Provides the statement shape used by hash-bound assurance attestations.",
    },
    {
        "id": "slsa-provenance",
        "name": "SLSA Provenance v1.0",
        "url": "https://slsa.dev/spec/v1.0/provenance",
        "relevance": "Provides vocabulary for build definitions, byproducts, dependencies, and reproducible release evidence.",
    },
    {
        "id": "rats-rfc-9334",
        "name": "RFC 9334: Remote ATtestation procedureS Architecture",
        "url": "https://www.rfc-editor.org/rfc/rfc9334.html",
        "relevance": "Frames the device-evidence and reference-value direction without claiming a hardware root of trust.",
    },
    {
        "id": "pqm4",
        "name": "pqm4: Post-quantum crypto benchmarking on Cortex-M4",
        "url": "https://github.com/mupq/pqm4",
        "relevance": "Reference methodology for hardware-comparable embedded PQC measurements.",
    },
    {
        "id": "supercop",
        "name": "SUPERCOP/eBACS",
        "url": "https://bench.cr.yp.to/supercop.html",
        "relevance": "Reference methodology for normalized performance reporting and cross-implementation comparisons.",
    },
    {
        "id": "kyberslash",
        "name": "KyberSlash implementation-risk notes",
        "url": "https://kyberslash.cr.yp.to/faq.html",
        "relevance": "Motivates instruction-policy and timing-smoke checks for ML-KEM decapsulation regressions.",
    },
]

REQUIRED_REPO_JSON = {
    "claims": "scripts/assurance_claims.json",
    "trace_map": "scripts/pqc_asset_trace_map.json",
    "policy": "scripts/pqc_assurance_policy.json",
    "profile": "scripts/pqc_assurance_profile.json",
    "quality": "scripts/pqc_evidence_quality.json",
    "benchmark_campaign": "scripts/pqc_benchmark_campaign.json",
}

OPTIONAL_RELEASE_ARTIFACTS = {
    "ledger": "assurance_ledger.json",
    "cbom": "pqc_cbom.cdx.json",
    "policy_result": "pqc_policy_result.json",
    "profile_result": "pqc_assurance_profile_result.json",
    "evidence_quality_result": "pqc_evidence_quality_result.json",
    "migration_readiness": "pqc_migration_readiness.json",
    "benchmark_campaign_result": "benchmark_campaign_result.json",
    "benchmark_confidence_result": "benchmark_confidence_result.json",
    "backend_contract_result": "backend_contract_result.json",
    "provider_scope_result": "provider_scope_result.json",
    "ct_campaign_result": "ct_campaign_result.json",
    "ct_instruction_policy_result": "ct_instruction_policy_result.json",
    "partner_review_scorecard": "partner_review_scorecard.json",
    "transcript_manifest": "transcripts/evidence_transcript_manifest.json",
}

EVIDENCE_DIMENSIONS = {
    "correctness": ("kat.", "acvp.", "boot."),
    "performance": ("benchmark.", "cost_of_assurance."),
    "side_channel_smoke": ("security.ct", "security.mlkem_decap_instruction_policy"),
    "supply_chain": ("supply_chain.", "release.", "firmware."),
    "migration": ("crypto_agility.", "release.migration_readiness", "security.production_rng_policy"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module-path", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--release-output",
        type=Path,
        help="Optional release_check.py output root to bind into the dossier.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        required=True,
        help="Directory for generated dossier artifacts.",
    )
    parser.add_argument("--version", default=None)
    parser.add_argument("--tag", default=None)
    parser.add_argument(
        "--depth",
        choices=("concise", "full"),
        default="full",
        help="full includes claim-by-claim and asset-by-asset appendices.",
    )
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"{path} root must be a JSON object")
    return payload


def read_required_json(module_path: Path) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    payloads: dict[str, dict[str, Any]] = {}
    inputs: list[dict[str, Any]] = []
    for label, rel in REQUIRED_REPO_JSON.items():
        path = module_path / rel
        if not path.exists():
            raise RuntimeError(f"required repository input not found: {path}")
        payloads[label] = read_json(path)
        inputs.append(input_record(label, path, module_path))
    return payloads, inputs


def input_record(label: str, path: Path, base: Path) -> dict[str, Any]:
    record: dict[str, Any] = {
        "label": label,
        "path": relative_or_absolute(path, base),
        "exists": path.exists() and path.is_file(),
    }
    if record["exists"]:
        record["sha256"] = sha256_file(path)
        record["size_bytes"] = path.stat().st_size
    return record


def relative_or_absolute(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except ValueError:
        return str(path)


def git_value(module_path: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=module_path,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def repo_state(module_path: Path) -> dict[str, Any]:
    status = git_value(module_path, "status", "--short")
    return {
        "head_sha": git_value(module_path, "rev-parse", "HEAD"),
        "branch": git_value(module_path, "rev-parse", "--abbrev-ref", "HEAD"),
        "dirty": bool(status),
    }


def collect_release_artifacts(release_output: Path | None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not release_output:
        return {"available": False, "root": None, "artifacts": {}}, []
    artifacts: dict[str, Any] = {}
    inputs: list[dict[str, Any]] = []
    for label, rel in OPTIONAL_RELEASE_ARTIFACTS.items():
        path = release_output / rel
        record = input_record(label, path, release_output)
        artifacts[label] = record
        if record["exists"]:
            inputs.append(record)
            if path.suffix == ".json":
                try:
                    payload = read_json(path)
                    record["schema_version"] = payload.get("schema_version")
                    if "passed" in payload:
                        record["passed"] = payload.get("passed") is True
                    if "summary" in payload:
                        record["summary"] = payload.get("summary")
                except (json.JSONDecodeError, RuntimeError) as exc:
                    record["parse_error"] = str(exc)
    return {
        "available": True,
        "root": str(release_output),
        "artifacts": artifacts,
    }, inputs


def claim_category(claim_id: str) -> str:
    return claim_id.split(".", 1)[0] if "." in claim_id else "uncategorized"


def dimension_for_claim(claim_id: str) -> str:
    for dimension, prefixes in EVIDENCE_DIMENSIONS.items():
        if any(claim_id.startswith(prefix) for prefix in prefixes):
            return dimension
    return "assurance"


def summarize_claims(claim_catalog: dict[str, Any], ledger: dict[str, Any] | None) -> dict[str, Any]:
    claims = [item for item in claim_catalog.get("claims") or [] if isinstance(item, dict)]
    category_counts = Counter(claim_category(str(item.get("id", ""))) for item in claims)
    dimension_counts = Counter(dimension_for_claim(str(item.get("id", ""))) for item in claims)
    ledger_status: dict[str, str] = {}
    ledger_failures: list[dict[str, Any]] = []
    if ledger:
        for claim in ledger.get("claims") or []:
            if not isinstance(claim, dict):
                continue
            claim_id = str(claim.get("id", ""))
            status = str(claim.get("status", "unknown"))
            ledger_status[claim_id] = status
            if status == "fail":
                ledger_failures.append(
                    {
                        "id": claim_id,
                        "reason": claim.get("failure_reason") or claim.get("claim") or "",
                    }
                )
    return {
        "schema_version": claim_catalog.get("schema_version"),
        "count": len(claims),
        "categories": dict(sorted(category_counts.items())),
        "dimensions": dict(sorted(dimension_counts.items())),
        "ledger_status_counts": dict(sorted(Counter(ledger_status.values()).items())),
        "ledger_failures": ledger_failures,
        "required_claim_ids": [str(item.get("id")) for item in claims if item.get("required", True)],
        "all_claim_ids": [str(item.get("id")) for item in claims],
        "records": [
            {
                "id": str(item.get("id")),
                "category": claim_category(str(item.get("id", ""))),
                "dimension": dimension_for_claim(str(item.get("id", ""))),
                "claim": str(item.get("claim", "")),
                "required": item.get("required", True),
            }
            for item in claims
        ],
    }


def component_properties(component: dict[str, Any]) -> dict[str, str]:
    props: dict[str, str] = {}
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and isinstance(prop.get("name"), str):
            props[prop["name"]] = str(prop.get("value", ""))
    return props


def summarize_assets(trace_map: dict[str, Any], cbom: dict[str, Any] | None) -> dict[str, Any]:
    trace_assets = [item for item in trace_map.get("assets") or [] if isinstance(item, dict)]
    trace_asset_ids = [str(item.get("id") or item.get("asset_id") or item.get("name")) for item in trace_assets]
    source_counts = {
        asset_id: len(item.get("source_files") or [])
        for asset_id, item in zip(trace_asset_ids, trace_assets, strict=False)
    }
    claim_link_counts = {
        asset_id: len(item.get("claim_ids") or item.get("claims") or [])
        for asset_id, item in zip(trace_asset_ids, trace_assets, strict=False)
    }
    cbom_components: list[dict[str, Any]] = []
    provider_counts: Counter[str] = Counter()
    production_allowed = 0
    if cbom:
        for component in cbom.get("components") or []:
            if not isinstance(component, dict):
                continue
            props = component_properties(component)
            trace_id = props.get("pqcp:trace_asset_id")
            provider = props.get("pqcp:provider_family") or props.get("pqcp:implementation_source") or "unspecified"
            if trace_id or component.get("type") == "cryptographic-asset":
                cbom_components.append(
                    {
                        "name": component.get("name"),
                        "type": component.get("type"),
                        "trace_asset_id": trace_id,
                        "provider_family": provider,
                        "production_allowed": props.get("pqcp:production_allowed"),
                        "lifecycle_status": props.get("pqcp:lifecycle_status"),
                    }
                )
                provider_counts[provider] += 1
                if props.get("pqcp:production_allowed") == "true":
                    production_allowed += 1
    return {
        "trace_asset_count": len(trace_assets),
        "trace_asset_ids": trace_asset_ids,
        "trace_source_counts": source_counts,
        "trace_claim_link_counts": claim_link_counts,
        "trace_assets": [
            {
                "id": asset_id,
                "source_files": item.get("source_files") or [],
                "kconfig_symbols": item.get("kconfig_symbols") or item.get("kconfig") or [],
                "claim_ids": item.get("claim_ids") or item.get("claims") or [],
                "ztests": item.get("ztests") or [],
                "transcript_markers": item.get("transcript_markers") or [],
            }
            for asset_id, item in zip(trace_asset_ids, trace_assets, strict=False)
        ],
        "cbom_component_count": len(cbom_components),
        "cbom_components": cbom_components,
        "provider_counts": dict(sorted(provider_counts.items())),
        "production_allowed_components": production_allowed,
    }


def summarize_policy(policy: dict[str, Any], profile: dict[str, Any], quality: dict[str, Any]) -> dict[str, Any]:
    profiles = profile.get("profiles")
    profile_ids = sorted(profiles.keys()) if isinstance(profiles, dict) else []
    required_claims = policy.get("required_claim_ids") or []
    allow_na = policy.get("allow_not_applicable_claim_ids") or []
    quality_claims = quality.get("claims") or quality.get("claim_evidence") or []
    quality_count = len(quality_claims) if isinstance(quality_claims, list) else len(quality_claims or {})
    return {
        "policy_schema_version": policy.get("schema_version"),
        "required_claim_count": len(required_claims),
        "not_applicable_allowlist_count": len(allow_na),
        "required_cbom_components": policy.get("required_cbom_components") or [],
        "profile_ids": profile_ids,
        "evidence_quality_entry_count": quality_count,
    }


def summarize_benchmark_config(config: dict[str, Any], benchmark_confidence: dict[str, Any] | None) -> dict[str, Any]:
    summary = {
        "schema_version": config.get("schema_version"),
        "warmup_runs": config.get("warmup_runs"),
        "repetitions": config.get("repetitions"),
        "required_statistics": config.get("required_statistics") or [],
        "required_context_fields": config.get("required_context_fields") or [],
        "default_environment_type": config.get("default_environment_type"),
    }
    if benchmark_confidence:
        summary["confidence_passed"] = benchmark_confidence.get("passed") is True
        summary["confidence_summary"] = benchmark_confidence.get("summary") or {}
        summary["confidence_warnings"] = benchmark_confidence.get("warnings") or []
    return summary


def load_optional_release_json(release_output: Path | None, relative_path: str) -> dict[str, Any] | None:
    if not release_output:
        return None
    path = release_output / relative_path
    if not path.exists():
        return None
    try:
        return read_json(path)
    except (json.JSONDecodeError, RuntimeError):
        return None


def hardening_items(summary: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    claim_summary = summary["claims"]
    benchmark = summary["benchmark"]
    release = summary["release"]
    assets = summary["assets"]
    ledger_status = claim_summary.get("ledger_status_counts") or {}
    not_applicable = int(ledger_status.get("not_applicable", 0))
    if not_applicable:
        items.append(
            {
                "id": "reduce_not_applicable_evidence",
                "priority": "high",
                "area": "evidence",
                "rationale": f"{not_applicable} ledger claims are currently not applicable in the inspected pack.",
                "implementation": "Promote the most important not-applicable claims into replayable artifacts or make the policy allowlist explicit per profile.",
            }
        )
    confidence = benchmark.get("confidence_summary") or {}
    if confidence.get("paper_comparable_rows", 0) == 0:
        items.append(
            {
                "id": "increase_benchmark_sample_depth",
                "priority": "high",
                "area": "measurement",
                "rationale": "Benchmark confidence replay reports no paper-comparable rows in the inspected QEMU pack.",
                "implementation": "Run repeated benchmark campaigns with at least the configured paper-comparable sample count and keep QEMU/hardware labels separate.",
            }
        )
    provider_counts = assets.get("provider_counts") or {}
    if provider_counts.get("liboqs", 0):
        items.append(
            {
                "id": "tighten_external_provider_scope",
                "priority": "medium",
                "area": "supply-chain",
                "rationale": "The CBOM includes experimental non-native provider inventory entries.",
                "implementation": "Keep liboqs scoped to non-ML-KEM/non-ML-DSA schemes and require provider-scope replay before partner review.",
            }
        )
    if release.get("available") and not (release.get("artifacts", {}).get("transcript_manifest", {}).get("exists")):
        items.append(
            {
                "id": "restore_transcript_manifest_binding",
                "priority": "blocker",
                "area": "release",
                "rationale": "The release output root was provided but the transcript manifest was missing.",
                "implementation": "Regenerate the full local release pack and require transcript-manifest hash replay.",
            }
        )
    items.extend(
        [
            {
                "id": "hardware_promotion_lane",
                "priority": "high",
                "area": "hardware",
                "rationale": "QEMU evidence is useful for regression and replay, but physical embedded results are needed for performance credibility.",
                "implementation": "Promote stable QEMU campaigns to nucleo_h743zi and Cortex-M-class hardware lanes with UART transcript hashes and clock metadata.",
            },
            {
                "id": "signed_partner_attestation",
                "priority": "medium",
                "area": "release",
                "rationale": "Current artifacts are hash-bound and replayable, but not identity-signed.",
                "implementation": "Define key custody and add detached signatures only after release-signing responsibility is decided.",
            },
            {
                "id": "device_reference_value_binding",
                "priority": "medium",
                "area": "firmware",
                "rationale": "Firmware digest reporting exists as local evidence; future device review benefits from nonce-bound appraisal.",
                "implementation": "Bind reference values to a hardware root-of-trust path when a target board policy is selected.",
            },
        ]
    )
    return items


def build_dossier(
    *,
    module_path: Path,
    release_output: Path | None,
    version: str | None,
    tag: str | None,
) -> dict[str, Any]:
    module_path = module_path.resolve()
    repo_inputs, input_records = read_required_json(module_path)
    release_summary, release_inputs = collect_release_artifacts(release_output.resolve() if release_output else None)
    ledger = load_optional_release_json(release_output, "assurance_ledger.json")
    cbom = load_optional_release_json(release_output, "pqc_cbom.cdx.json")
    benchmark_confidence = load_optional_release_json(release_output, "benchmark_confidence_result.json")
    claims = summarize_claims(repo_inputs["claims"], ledger)
    assets = summarize_assets(repo_inputs["trace_map"], cbom)
    policy = summarize_policy(repo_inputs["policy"], repo_inputs["profile"], repo_inputs["quality"])
    benchmark = summarize_benchmark_config(repo_inputs["benchmark_campaign"], benchmark_confidence)
    state = repo_state(module_path)
    detected_version = version or str((ledger or {}).get("version") or "")
    detected_tag = tag or str((ledger or {}).get("tag") or "")
    summary = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "project": "pqcp-zephyr-trust-stack",
        "version": detected_version,
        "tag": detected_tag,
        "repo_state": state,
        "inputs": input_records + release_inputs,
        "references": REFERENCE_ANCHORS,
        "claims": claims,
        "assets": assets,
        "policy": policy,
        "benchmark": benchmark,
        "release": release_summary,
    }
    summary["hardening_backlog"] = hardening_items(summary)
    summary["market_strategy"] = market_strategy(summary)
    return summary


def market_strategy(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "positioning": "A Zephyr-focused PQC assurance module for partners who need to inspect what was built, tested, measured, and released.",
        "primary_users": [
            "embedded firmware teams evaluating PQC migration paths",
            "security reviewers who need replayable evidence instead of slide-only claims",
            "platform owners preparing Zephyr-based products for post-quantum transition",
        ],
        "buyer_triggers": [
            "need to inventory ML-KEM/ML-DSA use in embedded firmware",
            "need to hand partners a local release pack without granting CI access",
            "need to separate QEMU regression evidence from hardware-validated performance claims",
            "need to enforce backend policy: mlkem-native for ML-KEM, mldsa-native for ML-DSA, no PQClean",
        ],
        "packaging": [
            "repository access under the proprietary collaborative evaluation terms",
            "local release evidence pack generated by release_check.py",
            "partner dashboard or static report pointed at generated JSON artifacts",
            "optional hardware-validation add-on once physical boards are available",
        ],
        "proof_points": [
            f"{summary['claims']['count']} cataloged assurance claims",
            f"{summary['assets']['trace_asset_count']} traced PQC/security assets",
            f"{summary['policy']['required_claim_count']} policy-required claims",
            f"{summary['benchmark'].get('repetitions')} configured benchmark campaign repetitions",
        ],
    }


def md_heading(level: int, title: str) -> str:
    return f"{'#' * level} {title}\n\n"


def md_table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_No rows._\n\n"
    out = ["| " + " | ".join(headers) + " |"]
    out.append("|" + "|".join(["---"] * len(headers)) + "|")
    for row in rows:
        out.append("| " + " | ".join(escape_md(str(value)) for value in row) + " |")
    return "\n".join(out) + "\n\n"


def escape_md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render_research_markdown(summary: dict[str, Any], *, depth: str) -> str:
    claims = summary["claims"]
    assets = summary["assets"]
    policy = summary["policy"]
    benchmark = summary["benchmark"]
    release = summary["release"]
    lines: list[str] = []
    lines.append(md_heading(1, "PQCP Research And Engineering Hardening Dossier"))
    lines.append(
        f"Generated at `{summary['generated_at']}` for `{summary['project']}` "
        f"version `{summary.get('version') or 'unknown'}` tag `{summary.get('tag') or 'unbound'}`.\n\n"
    )
    lines.append(
        "This dossier is generated from repository and release-pack artifacts. "
        "It is meant to guide implementation and review; it is not a certification statement.\n\n"
    )
    lines.append(md_heading(2, "Executive Technical Thesis"))
    lines.append(
        "The project is strongest when it behaves like a replayable evidence system for embedded PQC firmware. "
        "The important engineering move is not merely running ML-KEM and ML-DSA; it is binding the firmware build, "
        "correctness checks, ACVP-style command behavior, benchmark methodology, crypto inventory, transcript hashes, "
        "provider policy, and release metadata into artifacts that another reviewer can inspect locally.\n\n"
    )
    lines.append(md_heading(2, "Current Evidence Surface"))
    lines.append(
        md_table(
            ["Area", "Current count / setting", "Meaning"],
            [
                ["Assurance claims", claims["count"], "Versioned claim catalog driving ledger and policy replay"],
                ["Trace-map assets", assets["trace_asset_count"], "Crypto/security assets linked to source, Kconfig, tests, and claims"],
                ["CBOM components", assets["cbom_component_count"], "Cryptographic inventory components found in the inspected release pack"],
                ["Required policy claims", policy["required_claim_count"], "Claims required by the default partner policy"],
                ["Benchmark repetitions", benchmark.get("repetitions"), "Configured repeated-measurement campaign repetitions"],
                ["Release output available", release["available"], "Whether this dossier is bound to generated release artifacts"],
            ],
        )
    )
    lines.append(md_heading(2, "Standards And Methodology Anchors"))
    lines.append(
        md_table(
            ["Anchor", "Use in this project"],
            [[item["name"], item["relevance"]] for item in summary["references"]],
        )
    )
    lines.append(md_heading(2, "Evidence Dimensions"))
    dimension_rows = []
    for dimension, count in sorted(claims.get("dimensions", {}).items()):
        dimension_rows.append([dimension, count, dimension_recommendation(dimension)])
    lines.append(md_table(["Dimension", "Claim count", "Hardening direction"], dimension_rows))
    lines.append(md_heading(2, "Provider And Asset Posture"))
    provider_rows = [[provider, count] for provider, count in sorted((assets.get("provider_counts") or {}).items())]
    lines.append(md_table(["Provider family", "CBOM component count"], provider_rows))
    lines.append(
        "Backend policy remains explicit: ML-KEM evidence must stay on `mlkem-native`, ML-DSA evidence must stay on "
        "`mldsa-native`, PQClean remains denied, and liboqs is limited to schemes outside those native families.\n\n"
    )
    lines.append(md_heading(2, "Benchmark And Measurement Credibility"))
    confidence = benchmark.get("confidence_summary") or {}
    lines.append(
        md_table(
            ["Metric", "Value"],
            [
                ["required statistics", ", ".join(map(str, benchmark.get("required_statistics") or []))],
                ["required context fields", ", ".join(map(str, benchmark.get("required_context_fields") or []))],
                ["benchmark-confidence passed", benchmark.get("confidence_passed")],
                ["paper-comparable rows", confidence.get("paper_comparable_rows", "not bound")],
                ["single-observation rows", confidence.get("single_observation_rows", "not bound")],
                ["max tail spread ratio", confidence.get("max_tail_spread_ratio", "not bound")],
            ],
        )
    )
    lines.append(
        "The next measurement bar is hardware-promoted, repeated campaigns with explicit clock, compiler, backend, "
        "sample-count, and transcript-hash context. QEMU results should remain labelled as regression evidence.\n\n"
    )
    lines.append(md_heading(2, "Highest-Value Implementation Backlog"))
    lines.append(
        md_table(
            ["Priority", "Area", "Task", "Implementation"],
            [
                [item["priority"], item["area"], item["id"], item["implementation"]]
                for item in summary["hardening_backlog"]
            ],
        )
    )
    lines.append(md_heading(2, "Implementation Work Packages"))
    lines.append(render_work_packages(summary))
    lines.append(md_heading(2, "Release-Pack Binding"))
    artifact_rows = []
    for label, record in sorted((release.get("artifacts") or {}).items()):
        artifact_rows.append(
            [
                label,
                record.get("exists"),
                record.get("passed", ""),
                shorten_hash(record.get("sha256", "")),
                record.get("path", ""),
            ]
        )
    lines.append(md_table(["Artifact", "Exists", "Passed", "SHA-256", "Path"], artifact_rows))
    if depth == "full":
        lines.append(md_heading(2, "Claim Implementation Cards"))
        lines.append(render_claim_cards(summary))
        lines.append(md_heading(2, "Asset Integration Cards"))
        lines.append(render_asset_cards(summary))
        lines.append(md_heading(2, "Claim Appendix"))
        claim_rows = []
        for claim_id in claims.get("all_claim_ids") or []:
            claim_rows.append([claim_id, claim_category(claim_id), dimension_for_claim(claim_id)])
        lines.append(md_table(["Claim ID", "Category", "Evidence dimension"], claim_rows))
        lines.append(md_heading(2, "Asset Appendix"))
        asset_rows = []
        for asset_id in assets.get("trace_asset_ids") or []:
            asset_rows.append(
                [
                    asset_id,
                    assets.get("trace_source_counts", {}).get(asset_id, 0),
                    assets.get("trace_claim_link_counts", {}).get(asset_id, 0),
                ]
            )
        lines.append(md_table(["Trace asset ID", "Source links", "Claim links"], asset_rows))
    return "".join(lines)


def render_work_packages(summary: dict[str, Any]) -> str:
    rows = [
        [
            "Correctness replay",
            "KAT and ACVP claims with positive, negative, and recovery paths",
            "Keep fixture floors immutable; add more malformed-then-valid sequences without deleting existing scenarios.",
            "Every command class maps to a transcript hash and a claim ID.",
        ],
        [
            "Measurement credibility",
            "Benchmark campaign config plus benchmark-confidence replay",
            "Increase repetitions, separate QEMU/native/hardware evidence, and require context for imported reference rows.",
            "Rows become paper-comparable only when sample depth and variance thresholds pass.",
        ],
        [
            "Provider governance",
            "Backend contract, provider scope, CBOM provider-family properties",
            "Keep ML-KEM on mlkem-native and ML-DSA on mldsa-native; keep liboqs outside those native families.",
            "Release pack fails if provider family and CBOM/policy/reference values disagree.",
        ],
        [
            "Side-channel smoke",
            "CT sample analysis, CT campaign, ML-KEM decapsulation instruction policy",
            "Promote from smoke checks to board-specific campaign captures; keep claims explicitly non-formal.",
            "Duplicate indexes, unbalanced classes, and harness-only instruction scans fail replay.",
        ],
        [
            "Device evidence path",
            "Firmware assurance digest, status sample, reference values, device evidence token",
            "Bind future hardware tokens to nonce, digest root, artifact count, and transcript hash.",
            "A partner can compare device output against the release reference values.",
        ],
        [
            "Partner review workflow",
            "Scorecard, appraisal policy, tamper drill, release-pack verifier",
            "Make all failures actionable and reproducible without CI or private infrastructure.",
            "Reviewer sees blocker/warning status plus exact artifact paths and hashes.",
        ],
    ]
    return md_table(["Work package", "Current base", "Next implementation move", "Acceptance test"], rows)


def render_claim_cards(summary: dict[str, Any]) -> str:
    status_counts = summary.get("claims", {}).get("ledger_status_counts") or {}
    ledger_available = bool(status_counts)
    lines: list[str] = []
    for record in summary.get("claims", {}).get("records") or []:
        claim_id = record["id"]
        dimension = record["dimension"]
        lines.append(f"### `{claim_id}`\n\n")
        lines.append(f"- **Claim text:** {record.get('claim') or 'No claim text provided.'}\n")
        lines.append(f"- **Evidence dimension:** {dimension}\n")
        lines.append(f"- **Required by catalog:** {str(record.get('required')).lower()}\n")
        if ledger_available:
            lines.append("- **Release-pack status source:** `assurance_ledger.json`\n")
        lines.append(f"- **Why it matters:** {claim_value_statement(claim_id, dimension)}\n")
        lines.append(f"- **Hardening move:** {claim_hardening_move(claim_id, dimension)}\n\n")
    return "".join(lines)


def claim_value_statement(claim_id: str, dimension: str) -> str:
    if claim_id.startswith("kat."):
        return "It proves the implementation still agrees with trusted vector material for the named primitive or path."
    if claim_id.startswith("acvp."):
        return "It proves the serial validation surface handles supported and malformed command flows predictably."
    if claim_id.startswith("benchmark."):
        return "It turns a performance statement into measured rows with reproducible context instead of an anecdotal number."
    if claim_id.startswith("security."):
        return "It catches regression-class security risks and keeps the evidence label honest about what is and is not proven."
    if claim_id.startswith("supply_chain."):
        return "It binds provider choice, inventory, and provenance so reviewers can see which implementation family is actually in use."
    if claim_id.startswith("release."):
        return "It ties release metadata to generated artifacts so version, tag, and hashes do not drift silently."
    if claim_id.startswith("firmware."):
        return "It prepares the bridge from local release evidence to firmware-observable digest reporting."
    if claim_id.startswith("crypto_agility."):
        return "It separates production-allowed assets from experimental or profile-specific migration inventory."
    return f"It contributes to the {dimension} evidence surface and should remain tied to a concrete validator."


def claim_hardening_move(claim_id: str, dimension: str) -> str:
    if claim_id.startswith("benchmark."):
        return "Increase sample count, require context metadata, and compare p50/p90/p99 without mixing QEMU and hardware claims."
    if claim_id.startswith("security.ct") or "instruction_policy" in claim_id:
        return "Preserve smoke wording while adding board-specific traces and instruction coverage assertions."
    if claim_id.startswith("acvp."):
        return "Add malformed-then-valid recovery fixtures and keep all old negative scenarios locked by the scenario floor."
    if claim_id.startswith("kat."):
        return "Keep vector provenance hashed and split failures by primitive and parameter set."
    if claim_id.startswith("supply_chain."):
        return "Cross-check CBOM, backend contract, provider scope, attestation subjects, and reference values for the same provider family."
    if claim_id.startswith("release."):
        return "Keep the verifier replay-only and require exact tag/head/version agreement before partner review."
    if claim_id.startswith("firmware."):
        return "Add nonce-bound device evidence only after target-board policy and key custody are defined."
    return f"Add a replay verifier specific to the {dimension} evidence class if one does not already exist."


def render_asset_cards(summary: dict[str, Any]) -> str:
    lines: list[str] = []
    cbom_by_trace = {
        item.get("trace_asset_id"): item
        for item in summary.get("assets", {}).get("cbom_components") or []
        if item.get("trace_asset_id")
    }
    for asset in summary.get("assets", {}).get("trace_assets") or []:
        asset_id = asset["id"]
        cbom = cbom_by_trace.get(asset_id, {})
        lines.append(f"### `{asset_id}`\n\n")
        lines.append(f"- **Source files:** {comma_or_none(asset.get('source_files') or [])}\n")
        lines.append(f"- **Kconfig symbols:** {comma_or_none(asset.get('kconfig_symbols') or [])}\n")
        lines.append(f"- **Claim links:** {comma_or_none(asset.get('claim_ids') or [])}\n")
        lines.append(f"- **Ztests:** {comma_or_none(asset.get('ztests') or [])}\n")
        lines.append(f"- **Transcript markers:** {comma_or_none(asset.get('transcript_markers') or [])}\n")
        if cbom:
            lines.append(
                f"- **CBOM provider:** {cbom.get('provider_family') or 'unspecified'}; "
                f"production_allowed={cbom.get('production_allowed') or 'unspecified'}; "
                f"lifecycle={cbom.get('lifecycle_status') or 'unspecified'}\n"
            )
        lines.append("- **Integration review:** confirm the source, Kconfig, tests, transcript markers, and CBOM entry all describe the same asset.\n\n")
    return "".join(lines)


def comma_or_none(values: list[Any]) -> str:
    if not values:
        return "none recorded"
    return ", ".join(f"`{value}`" for value in values)


def dimension_recommendation(dimension: str) -> str:
    return {
        "correctness": "Keep positive, negative, and recovery tests tied to transcript hashes.",
        "performance": "Promote from QEMU regression numbers to repeated hardware campaigns.",
        "side_channel_smoke": "Keep smoke labels honest and expand instruction-policy coverage.",
        "supply_chain": "Keep CBOM, attestation, backend contract, and release metadata in replay agreement.",
        "migration": "Separate production-allowed assets from test-only or experimental inventory.",
        "assurance": "Keep each claim tied to a concrete validator and evidence artifact.",
    }.get(dimension, "Keep validator ownership explicit.")


def shorten_hash(value: str) -> str:
    return value[:12] if value else ""


def render_product_markdown(summary: dict[str, Any]) -> str:
    strategy = summary["market_strategy"]
    lines: list[str] = []
    lines.append(md_heading(1, "PQCP Product Strategy Brief"))
    lines.append(
        f"Generated at `{summary['generated_at']}` from repository evidence. "
        "This brief is intended for product planning and partner-review positioning.\n\n"
    )
    lines.append(md_heading(2, "Positioning"))
    lines.append(strategy["positioning"] + "\n\n")
    lines.append(md_heading(2, "Who It Is For"))
    lines.append(bullet_list(strategy["primary_users"]))
    lines.append(md_heading(2, "Why They Care"))
    lines.append(bullet_list(strategy["buyer_triggers"]))
    lines.append(md_heading(2, "What The Product Package Contains"))
    lines.append(bullet_list(strategy["packaging"]))
    lines.append(md_heading(2, "Proof Points"))
    lines.append(bullet_list(strategy["proof_points"]))
    lines.append(md_heading(2, "Product Boundaries"))
    lines.append(
        bullet_list(
            [
                "QEMU results are regression evidence, not physical performance claims.",
                "CT smoke and instruction-policy checks are regression signals, not a formal side-channel proof.",
                "Hash-bound attestations are replayable evidence, not identity-signed certification artifacts.",
                "liboqs inventory remains experimental and outside ML-KEM / ML-DSA implementation paths.",
            ]
        )
    )
    lines.append(md_heading(2, "Partner Pilot Offer"))
    lines.append(
        "A strong first pilot is a two-stage review: first a local replay of the release evidence pack, then a "
        "hardware-promotion run on the partner's selected board. The deliverable is a signed-off evidence archive "
        "containing the ledger, CBOM, transcripts, benchmark campaign result, policy result, and any board-specific "
        "UART captures.\n\n"
    )
    lines.append(md_heading(2, "Roadmap For Commercial Readiness"))
    lines.append(
        md_table(
            ["Phase", "Outcome", "Success metric"],
            [
                ["1. Local replay", "Partner can verify the pack without CI access", "Release verifier exits zero and names exact hashes"],
                ["2. Hardware promotion", "QEMU evidence is repeated on selected hardware", "Board transcript and clock metadata are hash-bound"],
                ["3. Signed evidence", "Pack is identity-bound", "Detached signatures and key custody policy are documented"],
                ["4. Integration service", "Dashboard/API consumes release packs", "Partner can compare versions and see drift"],
            ],
        )
    )
    lines.append(md_heading(2, "Partner Review Workflow"))
    lines.append(
        md_table(
            ["Step", "What partner receives", "Why it reduces review friction"],
            [
                ["Evidence replay", "release output root + verifier command", "They can replay the pack locally without CI access."],
                ["Inventory review", "CBOM + trace map + provider contract", "They can see which crypto assets and backends are in scope."],
                ["Measurement review", "benchmark campaign + confidence replay", "They can separate regression evidence from hardware claims."],
                ["Policy review", "policy result + appraisal result + scorecard", "They can see blockers and warnings in one place."],
                ["Device follow-up", "firmware digest status output", "They can compare firmware-reported digest data to reference values."],
            ],
        )
    )
    lines.append(md_heading(2, "High-Level Questions To Prepare For"))
    lines.append(
        md_table(
            ["Question", "Short answer"],
            [
                [
                    "Is this a crypto library or an assurance system?",
                    "Both, but the stronger product value is the evidence system around Zephyr PQC integration.",
                ],
                [
                    "What does a partner verify?",
                    "They verify the ledger, CBOM, transcripts, benchmark provenance, policy result, reference values, and hashes.",
                ],
                [
                    "What is not proven yet?",
                    "Formal side-channel security, physical-board performance, and signed release identity are explicit future steps.",
                ],
                [
                    "Why not use generic ML-KEM/ML-DSA from liboqs?",
                    "The backend contract keeps ML-KEM on mlkem-native and ML-DSA on mldsa-native; liboqs is scoped to other schemes only.",
                ],
                [
                    "What makes this partner-ready?",
                    "The reviewer gets replay commands and exact artifacts rather than a verbal checklist.",
                ],
            ],
        )
    )
    return "".join(lines)


def bullet_list(items: list[str]) -> str:
    return "".join(f"- {item}\n" for item in items) + "\n"


def write_outputs(summary: dict[str, Any], output_root: Path, *, depth: str) -> dict[str, Path]:
    output_root.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": output_root / "research_product_dossier.json",
        "research_md": output_root / "research_hardening_dossier.md",
        "product_md": output_root / "product_strategy_brief.md",
    }
    paths["json"].write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["research_md"].write_text(render_research_markdown(summary, depth=depth), encoding="utf-8")
    paths["product_md"].write_text(render_product_markdown(summary), encoding="utf-8")
    return paths


def validate_grounding(summary: dict[str, Any], research_md: str, product_md: str) -> list[str]:
    failures: list[str] = []
    claim_ids = summary.get("claims", {}).get("all_claim_ids") or []
    asset_ids = summary.get("assets", {}).get("trace_asset_ids") or []
    required_claim_mentions = min(5, len(claim_ids))
    mentioned_claims = sum(1 for claim_id in claim_ids if claim_id in research_md)
    if mentioned_claims < required_claim_mentions:
        failures.append(
            f"research dossier mentions {mentioned_claims} claim ids; expected at least {required_claim_mentions}"
        )
    required_asset_mentions = min(3, len(asset_ids))
    mentioned_assets = sum(1 for asset_id in asset_ids if asset_id in research_md)
    if mentioned_assets < required_asset_mentions:
        failures.append(
            f"research dossier mentions {mentioned_assets} asset ids; expected at least {required_asset_mentions}"
        )
    if "QEMU results are regression evidence" not in product_md:
        failures.append("product brief must preserve the QEMU evidence boundary")
    denied_terms = [r"\bcertified\b", r"\bguaranteed constant-time\b"]
    combined = research_md + "\n" + product_md
    for pattern in denied_terms:
        if re.search(pattern, combined, flags=re.IGNORECASE):
            failures.append(f"dossier contains overclaiming language matching {pattern!r}")
    return failures


def main() -> int:
    args = parse_args()
    summary = build_dossier(
        module_path=args.module_path,
        release_output=args.release_output,
        version=args.version,
        tag=args.tag,
    )
    paths = write_outputs(summary, args.output_root, depth=args.depth)
    research = paths["research_md"].read_text(encoding="utf-8")
    product = paths["product_md"].read_text(encoding="utf-8")
    failures = validate_grounding(summary, research, product)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print("Generated research/product dossier:")
    for label, path in paths.items():
        print(f"  {label}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
