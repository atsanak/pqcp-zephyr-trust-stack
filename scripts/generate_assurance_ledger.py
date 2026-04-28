#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate a local release assurance ledger from validated artifacts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from check_version_consistency import (  # noqa: E402
    normalize_tag,
    parse_cmake_version,
    parse_header_version,
    validate_changelog,
)
from export_results import validate_benchmark_csv, verify_provenance  # noqa: E402
from verify_kat_provenance import (  # noqa: E402
    DEFAULT_HEADER as DEFAULT_KAT_HEADER,
    DEFAULT_VECTORS_DIR,
    load_all_fixture_constants,
    load_header_constants,
    verify_vectors,
)

LEDGER_SCHEMA_VERSION = 1
DEFAULT_CLAIMS = SCRIPT_DIR / "assurance_claims.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a machine-readable PQCP release assurance ledger."
    )
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT)
    parser.add_argument("--claims", type=Path, default=DEFAULT_CLAIMS)
    parser.add_argument("--version", help="Expected release version. Defaults to version.h")
    parser.add_argument("--tag", help="Optional release tag to verify, e.g. v1.0.0")
    parser.add_argument("--benchmark-csv", type=Path, required=True)
    parser.add_argument("--benchmark-provenance", type=Path, required=True)
    parser.add_argument("--cost-of-assurance-evidence", type=Path, required=True)
    parser.add_argument("--release-bundle-root", type=Path, required=True)
    parser.add_argument("--kat-header", type=Path, default=DEFAULT_KAT_HEADER)
    parser.add_argument("--kat-vectors-dir", type=Path, default=DEFAULT_VECTORS_DIR)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-md", type=Path, required=True)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def git_optional(module_path: Path, *args: str) -> str | None:
    result = subprocess.run(
        ["git", *args],
        cwd=str(module_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def artifact(path: Path, *, label: str) -> dict[str, object]:
    exists = path.exists()
    data: dict[str, object] = {
        "label": label,
        "path": str(path),
        "exists": exists,
    }
    if exists and path.is_file():
        data["sha256"] = sha256_file(path)
    return data


def pass_claim(
    spec: dict[str, Any],
    *,
    validators: list[str],
    evidence_artifacts: list[dict[str, object]],
    commands: list[str],
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        **base_claim(spec),
        "status": "pass",
        "validators": validators,
        "evidence_artifacts": evidence_artifacts,
        "commands": commands,
        "failure_reason": None,
        "details": details or {},
    }


def fail_claim(
    spec: dict[str, Any],
    *,
    reason: str,
    validators: list[str],
    evidence_artifacts: list[dict[str, object]],
    commands: list[str],
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        **base_claim(spec),
        "status": "fail",
        "validators": validators,
        "evidence_artifacts": evidence_artifacts,
        "commands": commands,
        "failure_reason": reason,
        "details": details or {},
    }


def not_applicable_claim(
    spec: dict[str, Any],
    *,
    reason: str,
    validators: list[str],
    evidence_artifacts: list[dict[str, object]],
    commands: list[str],
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        **base_claim(spec),
        "status": "not_applicable",
        "validators": validators,
        "evidence_artifacts": evidence_artifacts,
        "commands": commands,
        "failure_reason": reason,
        "details": details or {},
    }


def base_claim(spec: dict[str, Any]) -> dict[str, object]:
    return {
        "id": spec["id"],
        "category": spec["category"],
        "claim": spec["claim"],
        "required": bool(spec.get("required", True)),
    }


def resolve_path(path: Path, module_path: Path) -> Path:
    return path if path.is_absolute() else (module_path / path).resolve()


def load_claim_specs(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema_version") != 1:
        raise RuntimeError(f"unsupported assurance claims schema in {path}")
    claims = raw.get("claims")
    if not isinstance(claims, list) or not claims:
        raise RuntimeError(f"{path} does not define any claims")
    seen: set[str] = set()
    for claim in claims:
        claim_id = claim.get("id")
        if not isinstance(claim_id, str) or not claim_id:
            raise RuntimeError(f"{path} contains a claim without an id")
        if claim_id in seen:
            raise RuntimeError(f"{path} contains duplicate claim id {claim_id}")
        seen.add(claim_id)
        for key in ("category", "claim"):
            if not isinstance(claim.get(key), str) or not claim[key]:
                raise RuntimeError(f"{path} claim {claim_id} is missing {key}")
    return claims


def find_release_manifest(bundle_root: Path, tag: str | None) -> Path | None:
    candidates = sorted(bundle_root.glob("*/release-manifest-*.json"))
    if tag:
        tagged = [
            path
            for path in candidates
            if path.parent.name == tag and path.name == f"release-manifest-{tag}.json"
        ]
        return tagged[0] if tagged else None
    if len(candidates) == 1:
        return candidates[0]
    return None


def evaluate_version_consistency(
    spec: dict[str, Any],
    *,
    module_path: Path,
    version: str,
    tag: str | None,
) -> dict[str, object]:
    changelog = module_path / "CHANGELOG.md"
    artifacts = [
        artifact(module_path / "include/pqcp_zephyr/version.h", label="version header"),
        artifact(module_path / "CMakeLists.txt", label="CMake version"),
        artifact(changelog, label="changelog"),
    ]
    validators = ["scripts/check_version_consistency.py"]
    commands = [
        "python3 scripts/check_version_consistency.py --changelog CHANGELOG.md"
        + (f" --tag {tag}" if tag else "")
    ]
    failures: list[str] = []
    header_version = parse_header_version(module_path)
    cmake_version = parse_cmake_version(module_path)
    if version != header_version:
        failures.append(f"requested version={version} does not match version.h={header_version}")
    if header_version != cmake_version:
        failures.append(f"version.h={header_version} does not match CMakeLists.txt={cmake_version}")
    if tag and normalize_tag(tag) != header_version:
        failures.append(f"tag={normalize_tag(tag)} does not match version.h={header_version}")
    failures.extend(validate_changelog(changelog, header_version))
    details = {
        "version": version,
        "version_h": header_version,
        "cmake": cmake_version,
        "tag": tag,
    }
    if failures:
        return fail_claim(
            spec,
            reason="; ".join(failures),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details=details,
    )


def evaluate_tag_integrity(
    spec: dict[str, Any],
    *,
    module_path: Path,
    tag: str | None,
) -> dict[str, object]:
    validators = ["git rev-parse", "git cat-file -t"]
    commands = [
        f"git rev-parse refs/tags/{tag}" if tag else "git rev-parse refs/tags/<tag>",
        f"git rev-parse refs/tags/{tag}^{{}}" if tag else "git rev-parse refs/tags/<tag>^{}",
    ]
    if not tag:
        return not_applicable_claim(
            spec,
            reason="no --tag supplied; release tag integrity is not applicable",
            validators=validators,
            evidence_artifacts=[],
            commands=commands,
        )
    tag_ref = f"refs/tags/{tag}"
    tag_object = git_optional(module_path, "rev-parse", tag_ref)
    tag_commit = git_optional(module_path, "rev-parse", f"{tag_ref}^{{}}")
    tag_type = git_optional(module_path, "cat-file", "-t", tag_ref)
    details = {
        "tag": tag,
        "tag_object": tag_object,
        "tag_commit": tag_commit,
        "tag_type": tag_type,
    }
    if not tag_object or not tag_commit:
        return fail_claim(
            spec,
            reason=f"local tag {tag} was not found",
            validators=validators,
            evidence_artifacts=[],
            commands=commands,
            details=details,
        )
    if tag_type != "tag":
        return fail_claim(
            spec,
            reason=f"local tag {tag} is not annotated (git object type: {tag_type})",
            validators=validators,
            evidence_artifacts=[],
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=[],
        commands=commands,
        details=details,
    )


def evaluate_kat_provenance(
    spec: dict[str, Any],
    *,
    header: Path,
    vectors_dir: Path,
) -> dict[str, object]:
    artifacts = [
        artifact(header, label="KAT header"),
        artifact(vectors_dir, label="vendored NIST ACVP fixtures"),
    ]
    validators = ["scripts/verify_kat_provenance.py"]
    commands = [f"python3 scripts/verify_kat_provenance.py --header {header}"]
    try:
        fixture_strings, fixture_numeric, _metadata = load_all_fixture_constants(vectors_dir)
        header_strings, header_numeric = load_header_constants(header)
        mismatches = verify_vectors(
            header_strings,
            header_numeric,
            fixture_strings,
            fixture_numeric,
        )
    except Exception as exc:  # noqa: BLE001 - render exact validation defect.
        return fail_claim(
            spec,
            reason=str(exc),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    if mismatches:
        return fail_claim(
            spec,
            reason="; ".join(mismatches),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details={"fixture_count": len(list(vectors_dir.glob("*.json")))},
    )


def evaluate_benchmark_csv(
    spec: dict[str, Any],
    *,
    csv_path: Path,
) -> dict[str, object]:
    artifacts = [artifact(csv_path, label="benchmark CSV")]
    validators = ["scripts/export_results.py --validate-only"]
    commands = [f"python3 scripts/export_results.py --validate-only {csv_path}"]
    if not csv_path.exists():
        return fail_claim(
            spec,
            reason=f"benchmark CSV not found: {csv_path}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    failures = validate_benchmark_csv(csv_path)
    details: dict[str, object] = {}
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    details["row_count"] = len(rows)
    if failures:
        return fail_claim(
            spec,
            reason="; ".join(f"[{item['check']}] {item['message']}" for item in failures),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details=details,
    )


def evaluate_benchmark_provenance(
    spec: dict[str, Any],
    *,
    csv_path: Path,
    provenance_path: Path,
) -> dict[str, object]:
    artifacts = [
        artifact(csv_path, label="benchmark CSV"),
        artifact(provenance_path, label="benchmark provenance"),
    ]
    validators = ["scripts/export_results.py --validate-only --verify-provenance"]
    commands = [
        f"python3 scripts/export_results.py --validate-only {csv_path} --verify-provenance"
    ]
    if not csv_path.exists():
        return fail_claim(
            spec,
            reason=f"benchmark CSV not found: {csv_path}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    if not provenance_path.exists():
        return fail_claim(
            spec,
            reason=f"benchmark provenance sidecar not found: {provenance_path}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    failures = verify_provenance(csv_path, provenance_path)
    if failures:
        return fail_claim(
            spec,
            reason="; ".join(f"[{item['check']}] {item['message']}" for item in failures),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
    )


def evaluate_cost_guardrails(
    spec: dict[str, Any],
    *,
    evidence_path: Path,
) -> dict[str, object]:
    artifacts = [artifact(evidence_path, label="cost-of-assurance regression evidence")]
    validators = ["scripts/run_extended_checks.py --run-cost-of-assurance-smoke"]
    commands = [
        "python3 scripts/run_extended_checks.py --strict "
        "--run-cost-of-assurance-smoke --cost-of-assurance-evidence "
        f"{evidence_path}"
    ]
    if not evidence_path.exists():
        return fail_claim(
            spec,
            reason=f"cost-of-assurance evidence not found: {evidence_path}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return fail_claim(
            spec,
            reason=f"invalid cost-of-assurance evidence JSON: {exc}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    comparisons = evidence.get("comparisons")
    if evidence.get("schema_version") != 1 or not isinstance(comparisons, list) or not comparisons:
        return fail_claim(
            spec,
            reason="cost-of-assurance evidence has no schema_version=1 comparisons",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    failures: list[str] = []
    metric_count = 0
    for comparison in comparisons:
        name = comparison.get("name", "<unnamed>")
        metrics = comparison.get("metrics")
        if not isinstance(metrics, list) or not metrics:
            failures.append(f"{name} evaluated no metrics")
            continue
        if not comparison.get("passed", False):
            failures.append(f"{name} failed: {comparison.get('failure_reason')}")
        for metric in metrics:
            metric_count += 1
            if not metric.get("passed", False):
                failures.append(
                    f"{name}/{metric.get('metric')}: {metric.get('failure_reason')}"
                )
            if metric.get("candidate_value") is None:
                failures.append(f"{name}/{metric.get('metric')}: candidate value missing")
    details = {
        "comparison_count": len(comparisons),
        "metric_count": metric_count,
    }
    if failures:
        return fail_claim(
            spec,
            reason="; ".join(failures),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details=details,
    )


def evaluate_local_bundle(
    spec: dict[str, Any],
    *,
    bundle_root: Path,
    version: str,
    tag: str | None,
) -> dict[str, object]:
    manifest_path = find_release_manifest(bundle_root, tag)
    artifacts = [
        artifact(bundle_root, label="release bundle root"),
    ]
    if manifest_path is not None:
        artifacts.append(artifact(manifest_path, label="release bundle manifest"))
    validators = ["scripts/prepare_release_bundle.py"]
    commands = [
        "python3 scripts/prepare_release_bundle.py"
        + (f" --tag {tag}" if tag else "")
        + f" --output-dir {bundle_root}"
    ]
    if manifest_path is None:
        return fail_claim(
            spec,
            reason=f"release manifest not found under {bundle_root}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return fail_claim(
            spec,
            reason=f"invalid release manifest JSON: {exc}",
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
        )
    failures: list[str] = []
    if manifest.get("version") != version:
        failures.append(f"manifest version {manifest.get('version')!r} != {version!r}")
    if tag and manifest.get("tag") != tag:
        failures.append(f"manifest tag {manifest.get('tag')!r} != {tag!r}")
    notes_meta = manifest.get("release_notes") or {}
    notes_path = manifest_path.parent / str(notes_meta.get("path", ""))
    artifacts.append(artifact(notes_path, label="release notes"))
    if not notes_path.exists():
        failures.append(f"release notes path missing: {notes_path}")
    elif notes_meta.get("sha256") != sha256_file(notes_path):
        failures.append("release notes sha256 does not match manifest")
    details = {
        "manifest": manifest_path.name,
        "tag_points_to_head": manifest.get("tag_points_to_head"),
        "working_tree_dirty": manifest.get("working_tree_dirty"),
    }
    if failures:
        return fail_claim(
            spec,
            reason="; ".join(failures),
            validators=validators,
            evidence_artifacts=artifacts,
            commands=commands,
            details=details,
        )
    return pass_claim(
        spec,
        validators=validators,
        evidence_artifacts=artifacts,
        commands=commands,
        details=details,
    )


def build_claim_evaluators(args: argparse.Namespace, version: str) -> dict[str, Callable[[dict[str, Any]], dict[str, object]]]:
    module_path = args.module_path.resolve()
    benchmark_csv = resolve_path(args.benchmark_csv, module_path)
    benchmark_provenance = resolve_path(args.benchmark_provenance, module_path)
    cost_evidence = resolve_path(args.cost_of_assurance_evidence, module_path)
    release_bundle_root = resolve_path(args.release_bundle_root, module_path)
    kat_header = resolve_path(args.kat_header, module_path)
    kat_vectors_dir = resolve_path(args.kat_vectors_dir, module_path)
    tag = args.tag

    return {
        "release.version_consistency": lambda spec: evaluate_version_consistency(
            spec,
            module_path=module_path,
            version=version,
            tag=tag,
        ),
        "release.tag_integrity": lambda spec: evaluate_tag_integrity(
            spec,
            module_path=module_path,
            tag=tag,
        ),
        "kat.offline_provenance": lambda spec: evaluate_kat_provenance(
            spec,
            header=kat_header,
            vectors_dir=kat_vectors_dir,
        ),
        "benchmark.csv_validity": lambda spec: evaluate_benchmark_csv(
            spec,
            csv_path=benchmark_csv,
        ),
        "benchmark.provenance_binding": lambda spec: evaluate_benchmark_provenance(
            spec,
            csv_path=benchmark_csv,
            provenance_path=benchmark_provenance,
        ),
        "cost_of_assurance.guardrails": lambda spec: evaluate_cost_guardrails(
            spec,
            evidence_path=cost_evidence,
        ),
        "release.local_bundle": lambda spec: evaluate_local_bundle(
            spec,
            bundle_root=release_bundle_root,
            version=version,
            tag=tag,
        ),
    }


def render_markdown(ledger: dict[str, object]) -> str:
    claims = ledger["claims"]
    lines = [
        f"# Assurance Ledger: {ledger['project']} {ledger['version']}",
        "",
        f"- Generated: `{ledger['generated_at']}`",
        f"- Tag: `{ledger.get('tag') or 'not supplied'}`",
        f"- HEAD: `{ledger.get('head_sha') or 'unknown'}`",
        f"- Dirty tree: `{ledger['dirty']}`",
        "",
        "## Summary",
        "",
    ]
    summary = ledger["summary"]
    for key in ("pass", "fail", "not_applicable"):
        lines.append(f"- {key}: {summary[key]}")
    lines.extend(
        [
            "",
            "## Claims",
            "",
            "| Claim ID | Category | Status | Evidence |",
            "|----------|----------|--------|----------|",
        ]
    )
    for claim in claims:
        artifacts = [
            Path(str(item["path"])).name
            for item in claim.get("evidence_artifacts", [])
            if item.get("exists")
        ]
        evidence = ", ".join(artifacts) if artifacts else "n/a"
        lines.append(
            "| {id} | {category} | {status} | {evidence} |".format(
                id=claim["id"],
                category=claim["category"],
                status=claim["status"],
                evidence=evidence,
            )
        )
    lines.append("")
    failures = [
        claim for claim in claims
        if claim["status"] == "fail" and claim.get("failure_reason")
    ]
    if failures:
        lines.extend(["## Failures", ""])
        for claim in failures:
            lines.append(f"- `{claim['id']}`: {claim['failure_reason']}")
        lines.append("")
    return "\n".join(lines)


def build_ledger(args: argparse.Namespace) -> dict[str, object]:
    module_path = args.module_path.resolve()
    version = args.version or parse_header_version(module_path)
    claims_path = resolve_path(args.claims, module_path)
    claim_specs = load_claim_specs(claims_path)
    evaluators = build_claim_evaluators(args, version)
    claims: list[dict[str, object]] = []
    for spec in claim_specs:
        evaluator = evaluators.get(spec["id"])
        if evaluator is None:
            claims.append(
                fail_claim(
                    spec,
                    reason=f"unsupported assurance claim id {spec['id']}",
                    validators=[],
                    evidence_artifacts=[],
                    commands=[],
                )
            )
            continue
        claims.append(evaluator(spec))

    summary = {
        "pass": sum(1 for claim in claims if claim["status"] == "pass"),
        "fail": sum(1 for claim in claims if claim["status"] == "fail"),
        "not_applicable": sum(1 for claim in claims if claim["status"] == "not_applicable"),
    }
    return {
        "schema_version": LEDGER_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": "pqcp-zephyr-trust-stack",
        "version": version,
        "tag": args.tag,
        "head_sha": git_optional(module_path, "rev-parse", "HEAD"),
        "dirty": bool(git_optional(module_path, "status", "--porcelain")),
        "summary": summary,
        "claims": claims,
    }


def main() -> int:
    args = parse_args()
    ledger = build_ledger(args)
    output_json = args.output_json.resolve()
    output_md = args.output_md.resolve()
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output_md.write_text(render_markdown(ledger), encoding="utf-8")

    print("Assurance ledger generated")
    print(f"  json : {output_json}")
    print(f"  md   : {output_md}")
    print(
        "  summary: "
        f"pass={ledger['summary']['pass']} "
        f"fail={ledger['summary']['fail']} "
        f"not_applicable={ledger['summary']['not_applicable']}"
    )
    failures = [
        claim for claim in ledger["claims"]
        if claim["status"] == "fail" and claim.get("required", True)
    ]
    if failures:
        print("Assurance ledger failures:", file=sys.stderr)
        for claim in failures:
            print(f"  - {claim['id']}: {claim['failure_reason']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
