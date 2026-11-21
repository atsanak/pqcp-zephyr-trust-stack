#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""
Run the project release validation sequence with clear per-step PASS/FAIL output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from local_workflow import (  # noqa: E402
    HOST_ENV_BLACKLIST,
    clean_env,
    command_to_text,
    detect_west_root as _shared_detect_west_root,
    discover_west as _shared_discover_west,
)

XML_INVALID_CHARS_RE = re.compile(
    "[^\u0009\u000A\u000D\u0020-\uD7FF\uE000-\uFFFD]"
)

REQUIRED_EVIDENCE_TRANSCRIPT_STEPS = (
    "Extended Checks (strict cost-of-assurance smoke)",
    "sanitizers",
    "ACVP serial ztest run",
    "ACVP serial negative ztest run",
    "ACVP KAT ztest run",
    "boot KAT self-verify ztest run",
    "evidence coverage audit",
    "evidence chain host replay",
    "transparent appraisal receipt",
    "evidence parser fuzz",
    "edge model conformance",
    "ct instruction-count",
    "ct trace relational",
    "ct leak rediscovery",
    "fault campaign",
    "ct smoke ztest run",
    "ct instruction policy",
    "benchmark_csv",
    "benchmark_csv_validate",
    "resource_budgets",
)

CI_EVIDENCE_TRANSCRIPT_STEPS = (
    "version_consistency",
    "cppcheck",
    "Extended Checks (strict)",
    "ACVP serial negative scenario header check",
    "ACVP negative scenario floor validation",
    "ACVP serial negative ztest build",
    "ACVP serial negative ztest run",
    "kat_provenance",
    "evidence coverage audit",
    "transparent appraisal receipt",
)

CI_FAST_GATE_STEPS = (
    "version_consistency",
    "cppcheck",
    "Extended Checks (strict)",
    "ACVP serial negative scenario header check",
    "ACVP negative scenario floor validation",
    "ACVP serial negative ztest build",
    "ACVP serial negative ztest run",
    "kat_provenance",
    "evidence coverage audit",
    "transparent appraisal receipt",
)


@dataclass
class Step:
    name: str
    cmd: List[str]
    cwd: Path
    timeout: Optional[int] = None
    success_markers: tuple[str, ...] = ()


@dataclass
class StepResult:
    name: str
    returncode: int
    output: str
    duration_seconds: float


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the PQCP release validation sequence"
    )
    parser.add_argument("--west-root", type=Path, help="Zephyr workspace root")
    parser.add_argument("--module-path", type=Path, help="PQCP module path")
    parser.add_argument("--west", help="Explicit west binary or command")
    parser.add_argument("--tag", help="Optional git tag/version string to validate")
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("benchmark_results/release_check"),
        help="Root directory for release-check build artifacts",
    )
    parser.add_argument(
        "--ci",
        "--fast-gate",
        "--ci-fast",
        action="store_true",
        dest="ci",
        help=(
            "Run the fast CI release gate. This keeps version, static, strict "
            "extended, ACVP negative ztest, KAT provenance, and transcript-bound "
            "CI ledger checks blocking while leaving sanitizer, benchmark, MCU "
            "budget, and full release-bundle evidence generation to the default "
            "local release path."
        ),
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Echo commands before running them")
    return parser.parse_args()


def detect_west_root(start: Path) -> Path:
    return _shared_detect_west_root(start, strict=False)


def discover_west(explicit: Optional[str], west_root: Path, module_path: Path) -> List[str]:
    return _shared_discover_west(explicit, west_root, module_path)


def build_env() -> dict[str, str]:
    return clean_env()


def discover_tool(name: str) -> str:
    tool = shutil.which(name)
    if tool is None:
        raise RuntimeError(f"Unable to find required tool: {name}")
    return tool


def sanitize_junit_text(text: str) -> str:
    return XML_INVALID_CHARS_RE.sub("", text)


def slugify_step_name(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", name.strip().lower()).strip("-")
    return slug or "step"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_version_string(module_path: Path) -> str:
    header = module_path / "include/pqcp_zephyr/version.h"
    for line in header.read_text(encoding="utf-8").splitlines():
        match = re.search(r'#define\s+PQCP_VERSION_STRING\s+"([^"]+)"', line)
        if match:
            return match.group(1)
    raise RuntimeError(f"unable to read PQCP_VERSION_STRING from {header}")


def git_output(module_path: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(module_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout.strip()


def git_head_sha(module_path: Path) -> str:
    return git_output(module_path, "rev-parse", "HEAD")


def git_tree_dirty(module_path: Path) -> bool:
    return bool(git_output(module_path, "status", "--porcelain"))


def write_step_transcript(
    *,
    index: int,
    step: Step,
    result: StepResult,
    transcript_dir: Path,
) -> dict[str, object]:
    transcript_dir.mkdir(parents=True, exist_ok=True)
    path = transcript_dir / f"{index:02d}-{slugify_step_name(step.name)}.log"
    body = [
        f"step: {step.name}",
        f"returncode: {result.returncode}",
        f"duration_seconds: {result.duration_seconds:.3f}",
        f"cwd: {step.cwd}",
        f"command: {command_to_text(step.cmd)}",
        "",
        result.output,
    ]
    path.write_text("\n".join(body), encoding="utf-8")
    return {
        "step": step.name,
        "command": step.cmd,
        "command_text": command_to_text(step.cmd),
        "cwd": str(step.cwd),
        "returncode": result.returncode,
        "duration_seconds": round(result.duration_seconds, 3),
        "transcript_path": path.name,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def write_evidence_transcript_manifest(
    *,
    entries: list[dict[str, object]],
    transcript_dir: Path,
    qemu_stdout_roots: list[Path],
    output_path: Path,
    required_steps: tuple[str, ...] = REQUIRED_EVIDENCE_TRANSCRIPT_STEPS,
) -> None:
    transcript_dir.mkdir(parents=True, exist_ok=True)
    required = set(required_steps)
    selected = [entry for entry in entries if entry.get("step") in required]
    qemu_stdout_transcripts = []
    for root in qemu_stdout_roots:
        if not root.exists():
            continue
        for log_path in sorted(root.glob("runs/*/run.log")):
            if not log_path.is_file():
                continue
            qemu_stdout_transcripts.append(
                {
                    "label": f"qemu stdout: {log_path.parent.name}",
                    "transcript_path": os.path.relpath(log_path, transcript_dir),
                    "sha256": sha256_file(log_path),
                    "size_bytes": log_path.stat().st_size,
                }
            )
    manifest = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/release_check.py",
        "required_steps": list(required_steps),
        "transcripts": selected,
        "qemu_stdout_transcripts": qemu_stdout_transcripts,
    }
    output_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_ci_assurance_ledger(
    *,
    module_path: Path,
    output_root: Path,
    version: str,
    tag: str | None,
    head_sha: str,
    dirty: bool,
    transcript_manifest_path: Path,
    ledger_json_path: Path,
    ledger_md_path: Path,
) -> None:
    transcript_sha = sha256_file(transcript_manifest_path)
    transcript_size = transcript_manifest_path.stat().st_size
    claims = [
        {
            "id": "release.ci_fast_gate",
            "category": "release",
            "claim": "The CI fast release gate completed the essential local validation set.",
            "status": "pass",
            "validators": ["scripts/release_check.py --ci"],
            "evidence_artifacts": [
                {
                    "path": os.path.relpath(transcript_manifest_path, output_root),
                    "sha256": transcript_sha,
                    "size_bytes": transcript_size,
                }
            ],
            "commands": [
                "python scripts/release_check.py --ci --output-root <output-root>"
            ],
            "failure_reason": "",
        },
        {
            "id": "release.transcript_binding",
            "category": "release",
            "claim": "CI release claims are bound to hashed command transcripts.",
            "status": "pass",
            "validators": ["scripts/release_check.py transcript manifest"],
            "evidence_artifacts": [
                {
                    "path": os.path.relpath(transcript_manifest_path, output_root),
                    "sha256": transcript_sha,
                    "size_bytes": transcript_size,
                }
            ],
            "commands": ["write_evidence_transcript_manifest"],
            "failure_reason": "",
        },
    ]
    ledger = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": "pqcp-zephyr-trust-stack",
        "module_path": str(module_path),
        "version": version,
        "tag": tag or "",
        "head_sha": head_sha,
        "dirty": dirty,
        "summary": {
            "status": "pass",
            "claims_total": len(claims),
            "claims_passed": len(claims),
            "claims_failed": 0,
            "mode": "ci-fast-gate",
        },
        "claims": claims,
    }
    ledger_json_path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# PQCP CI Assurance Ledger",
        "",
        f"- Project: `pqcp-zephyr-trust-stack`",
        f"- Version: `{version}`",
        f"- Tag: `{tag or 'not supplied'}`",
        f"- HEAD: `{head_sha}`",
        f"- Dirty tree: `{str(dirty).lower()}`",
        f"- Transcript manifest: `{os.path.relpath(transcript_manifest_path, output_root)}`",
        f"- Transcript manifest SHA-256: `{transcript_sha}`",
        "",
        "| Claim ID | Status | Evidence |",
        "|---|---|---|",
    ]
    for claim in claims:
        evidence = claim["evidence_artifacts"][0]
        lines.append(
            f"| `{claim['id']}` | `{claim['status']}` | "
            f"`{evidence['path']}` (`{evidence['sha256']}`) |"
        )
    ledger_md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_junit_report(results: List[StepResult], output_path: Path) -> None:
    testsuite = ET.Element(
        "testsuite",
        name="release_check",
        tests=str(len(results)),
        failures=str(sum(1 for result in results if result.returncode != 0)),
        errors="0",
        skipped="0",
        time=f"{sum(result.duration_seconds for result in results):.3f}",
    )
    for result in results:
        testcase = ET.SubElement(
            testsuite,
            "testcase",
            classname="release_check",
            name=result.name,
            time=f"{result.duration_seconds:.3f}",
        )
        if result.returncode != 0:
            failure = ET.SubElement(
                testcase,
                "failure",
                message=f"Step exited with code {result.returncode}",
                type="failure",
            )
            failure.text = sanitize_junit_text(result.output)
        system_out = ET.SubElement(testcase, "system-out")
        system_out.text = sanitize_junit_text(result.output)

    root = ET.Element("testsuites")
    root.append(testsuite)
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tree.write(output_path, encoding="utf-8", xml_declaration=True)


def terminate_process_group(proc: subprocess.Popen[str], sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        pass
    except PermissionError:
        pass


def communicate_until_markers(
    proc: subprocess.Popen[str],
    *,
    timeout: Optional[int],
    success_markers: tuple[str, ...],
) -> tuple[int, str, bool]:
    chunks: list[bytes] = []
    deadline = time.monotonic() + timeout if timeout else None
    marker_bytes = tuple(marker.encode("utf-8") for marker in success_markers)
    selector = selectors.DefaultSelector()

    if proc.stdout is not None:
        selector.register(proc.stdout, selectors.EVENT_READ)

    try:
        while True:
            for key, _event in selector.select(timeout=0.1):
                try:
                    chunk = os.read(key.fileobj.fileno(), 4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    try:
                        selector.unregister(key.fileobj)
                    except (KeyError, ValueError):
                        pass
                    continue

                chunks.append(chunk)
                stdout_bytes = b"".join(chunks)
                if all(marker in stdout_bytes for marker in marker_bytes):
                    terminate_process_group(proc, signal.SIGTERM)
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        terminate_process_group(proc, signal.SIGKILL)
                        proc.wait()
                    return (
                        0,
                        stdout_bytes.decode("utf-8", errors="replace"),
                        True,
                    )

            if proc.poll() is not None:
                stdout = b"".join(chunks).decode("utf-8", errors="replace")
                return proc.returncode, stdout, False

            if deadline is not None and time.monotonic() >= deadline:
                terminate_process_group(proc, signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    terminate_process_group(proc, signal.SIGKILL)
                    proc.wait()
                stdout = b"".join(chunks).decode("utf-8", errors="replace")
                return 124, stdout, False
    finally:
        selector.close()
        if proc.stdout is not None:
            proc.stdout.close()


def run_step(step: Step, env: dict[str, str], verbose: bool) -> StepResult:
    print(f"[RUN ] {step.name}")
    if verbose:
        print("       " + " ".join(shlex.quote(part) for part in step.cmd))

    started = time.perf_counter()
    proc: subprocess.Popen[str] | None = None
    try:
        proc = subprocess.Popen(
            step.cmd,
            cwd=str(step.cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        if step.success_markers:
            returncode, stdout, marker_terminated = communicate_until_markers(
                proc,
                timeout=step.timeout,
                success_markers=step.success_markers,
            )
        else:
            stdout, _ = proc.communicate(timeout=step.timeout)
            stdout = stdout or ""
            returncode = proc.returncode
            marker_terminated = False
    except subprocess.TimeoutExpired:
        stdout = ""
        if proc is not None:
            terminate_process_group(proc, signal.SIGTERM)
            try:
                stdout, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                terminate_process_group(proc, signal.SIGKILL)
                stdout, _ = proc.communicate()
        returncode = 124
        marker_terminated = False

    duration_seconds = time.perf_counter() - started

    if stdout:
        print(stdout, end="" if stdout.endswith("\n") else "\n")

    if marker_terminated:
        print(f"[PASS] {step.name} (success marker reached; stopped runner)")
        return StepResult(
            name=step.name,
            returncode=0,
            output=stdout,
            duration_seconds=duration_seconds,
        )

    if returncode == 124 and step.success_markers:
        if all(marker in stdout for marker in step.success_markers):
            print(f"[PASS] {step.name} (completed with timed-out QEMU teardown)")
            return StepResult(
                name=step.name,
                returncode=0,
                output=stdout,
                duration_seconds=duration_seconds,
            )

    if returncode == 0:
        print(f"[PASS] {step.name}")
    else:
        print(f"[FAIL] {step.name} (exit {returncode})")
    return StepResult(
        name=step.name,
        returncode=returncode,
        output=stdout,
        duration_seconds=duration_seconds,
    )


def select_steps_for_mode(steps: list[Step], *, ci: bool) -> list[Step]:
    if not ci:
        return steps

    selected = [step for step in steps if step.name in CI_FAST_GATE_STEPS]
    selected_names = {step.name for step in selected}
    missing = [name for name in CI_FAST_GATE_STEPS if name not in selected_names]
    if missing:
        raise RuntimeError(f"CI fast gate step list is stale; missing: {', '.join(missing)}")
    return selected


def remove_stale_release_artifacts(output_root: Path, paths: list[Path]) -> None:
    """Remove known generated artifacts so reruns cannot bind stale evidence."""
    root = output_root.resolve()
    for path in paths:
        candidate = path.resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            raise RuntimeError(f"refusing to clean path outside output root: {candidate}") from None
        if not candidate.exists():
            continue
        if candidate.is_dir():
            shutil.rmtree(candidate)
        else:
            candidate.unlink()


def main() -> int:
    args = parse_args()
    module_path = args.module_path.resolve() if args.module_path else Path(__file__).resolve().parent.parent
    west_root = args.west_root.resolve() if args.west_root else detect_west_root(module_path)
    output_root = args.output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    west_cmd = discover_west(args.west, west_root, module_path)
    cppcheck_cmd = discover_tool("cppcheck")
    env = build_env()
    ztest_build_dir = output_root / "ztest_acvp_serial_qemu"
    ztest_negative_build_dir = output_root / "ztest_acvp_serial_negative_qemu"
    kat_build_dir = output_root / "ztest_acvp_kat_qemu"
    boot_verify_build_dir = output_root / "ztest_kat_boot_verify_qemu"
    evidence_chain_output_dir = output_root / "evidence_chain_replay"
    evidence_fuzz_build_dir = output_root / "evidence_fuzz"
    evidence_coverage_report = output_root / "evidence_coverage.json"
    transparent_appraisal_output_dir = output_root / "transparent_appraisal"
    edge_model_output_dir = output_root / "edge_model"
    ct_instruction_output_dir = output_root / "ct_instruction"
    ct_trace_output_dir = output_root / "ct_trace"
    fault_output_dir = output_root / "fault_campaign"
    ct_smoke_build_dir = output_root / "ztest_ct_smoke_qemu"
    profile_output_dir = output_root / "profile_validation"
    benchmark_csv_path = output_root / "benchmark_results.csv"
    benchmark_provenance_path = benchmark_csv_path.with_name("benchmark_provenance.json")
    cost_evidence_path = output_root / "cost_of_assurance_evidence.json"
    cost_smoke_output_root = output_root / "cost_of_assurance_smoke"
    release_bundle_root = output_root / "local_release_bundle"
    assurance_ledger_json = output_root / "assurance_ledger.json"
    assurance_ledger_md = output_root / "assurance_ledger.md"
    assurance_report_html = output_root / "assurance_report.html"
    pqc_cbom_path = output_root / "pqc_cbom.cdx.json"
    pqc_environment_result_path = output_root / "pqc_environment_result.json"
    pqc_attestation_path = output_root / "pqc_attestation.intoto.json"
    pqc_policy_result_path = output_root / "pqc_policy_result.json"
    pqc_assurance_digest_path = output_root / "pqc_assurance_digest.json"
    negative_floor_result_path = output_root / "acvp_negative_scenario_floor_result.json"
    pqc_asset_trace_result_path = output_root / "pqc_asset_trace_result.json"
    pqc_evidence_graph_json = output_root / "pqc_evidence_graph.json"
    pqc_evidence_graph_md = output_root / "pqc_evidence_graph.md"
    pqc_assurance_profile_result_path = output_root / "pqc_assurance_profile_result.json"
    pqc_evidence_quality_result_path = output_root / "pqc_evidence_quality_result.json"
    pqc_migration_readiness_json_path = output_root / "pqc_migration_readiness.json"
    pqc_migration_readiness_md_path = output_root / "pqc_migration_readiness.md"
    ct_instruction_policy_result_path = output_root / "ct_instruction_policy_result.json"
    pqc_claim_closure_result_path = output_root / "pqc_claim_closure_result.json"
    ct_sample_analysis_result_path = output_root / "ct_sample_analysis_result.json"
    ct_sample_manifest_path = output_root / "ct_sample_manifest.json"
    acvp_json_interop_result_path = output_root / "acvp_json_interop_result.json"
    acvp_json_transcript_manifest_path = output_root / "acvp_json_transcript_manifest.json"
    backend_currency_result_path = output_root / "backend_currency_result.json"
    backend_contract_result_path = output_root / "backend_contract_result.json"
    liboqs_inventory_path = output_root / "liboqs_non_native_inventory.json"
    provider_scope_result_path = output_root / "provider_scope_result.json"
    external_reference_output_dir = output_root / "external_reference_import"
    external_reference_result_path = external_reference_output_dir / "hardware_benchmark_report.json"
    paper_comparison_csv_path = output_root / "paper_comparison_campaign.csv"
    paper_comparison_result_path = output_root / "paper_comparison_campaign.json"
    pqc_reference_values_path = output_root / "pqc_reference_values.json"
    pqc_reference_values_result_path = output_root / "pqc_reference_values_result.json"
    release_reference_values_result_path = output_root / "release_reference_values_result.json"
    firmware_assurance_status_result_path = output_root / "firmware_assurance_status_result.json"
    pqc_build_provenance_path = output_root / "pqc_build_provenance.slsa.json"
    pqc_build_provenance_result_path = output_root / "pqc_build_provenance_result.json"
    backend_update_evaluation_path = output_root / "backend_update_evaluation.json"
    benchmark_campaign_result_path = output_root / "benchmark_campaign_result.json"
    benchmark_campaign_verify_result_path = output_root / "benchmark_campaign_verify_result.json"
    benchmark_confidence_result_path = output_root / "benchmark_confidence_result.json"
    metric_optimization_result_path = output_root / "metric_optimization_campaign.json"
    metric_optimization_overlay_dir = output_root / "metric_optimization_overlays"
    ct_campaign_result_path = output_root / "ct_campaign_result.json"
    acvp_json_schema_result_path = output_root / "acvp_json_schema_result.json"
    device_evidence_token_path = output_root / "device_evidence_token.json"
    device_evidence_token_result_path = output_root / "device_evidence_token_result.json"
    pqc_appraisal_evidence_path = output_root / "pqc_appraisal_evidence.json"
    pqc_appraisal_result_path = output_root / "pqc_appraisal_result.json"
    partner_scorecard_json_path = output_root / "partner_review_scorecard.json"
    partner_scorecard_md_path = output_root / "partner_review_scorecard.md"
    partner_scorecard_result_path = output_root / "partner_review_scorecard_result.json"
    research_product_dossier_json_path = output_root / "research_product_dossier.json"
    research_hardening_dossier_md_path = output_root / "research_hardening_dossier.md"
    product_strategy_brief_md_path = output_root / "product_strategy_brief.md"
    evidence_tamper_drill_result_path = output_root / "evidence_tamper_drill_result.json"
    generated_include_dir = output_root / "generated"
    firmware_digest_header_path = generated_include_dir / "pqcp_assurance_digest_generated.h"
    assurance_status_build_dir = output_root / "pqcp_assurance_status_qemu"
    transcript_dir = output_root / "transcripts"
    evidence_transcript_manifest = transcript_dir / "evidence_transcript_manifest.json"
    junit_output = output_root / "release_check_results.xml"
    release_tag = args.tag or f"v{read_version_string(module_path)}"
    release_manifest_path = release_bundle_root / release_tag / f"release-manifest-{release_tag}.json"
    remove_stale_release_artifacts(
        output_root,
        [
            transcript_dir,
            generated_include_dir,
            external_reference_output_dir,
            benchmark_csv_path,
            benchmark_provenance_path,
            cost_evidence_path,
            assurance_ledger_json,
            assurance_ledger_md,
            assurance_report_html,
            pqc_cbom_path,
            pqc_environment_result_path,
            pqc_attestation_path,
            pqc_policy_result_path,
            pqc_assurance_digest_path,
            negative_floor_result_path,
            pqc_asset_trace_result_path,
            pqc_evidence_graph_json,
            pqc_evidence_graph_md,
            pqc_assurance_profile_result_path,
            pqc_evidence_quality_result_path,
            pqc_migration_readiness_json_path,
            pqc_migration_readiness_md_path,
            ct_instruction_policy_result_path,
            pqc_claim_closure_result_path,
            ct_sample_analysis_result_path,
            ct_sample_manifest_path,
            acvp_json_interop_result_path,
            acvp_json_transcript_manifest_path,
            backend_currency_result_path,
            backend_contract_result_path,
            liboqs_inventory_path,
            provider_scope_result_path,
            paper_comparison_csv_path,
            paper_comparison_result_path,
            pqc_reference_values_path,
            pqc_reference_values_result_path,
            release_reference_values_result_path,
            firmware_assurance_status_result_path,
            pqc_build_provenance_path,
            pqc_build_provenance_result_path,
            backend_update_evaluation_path,
            benchmark_campaign_result_path,
            benchmark_campaign_verify_result_path,
            benchmark_confidence_result_path,
            metric_optimization_result_path,
            metric_optimization_overlay_dir,
            ct_campaign_result_path,
            acvp_json_schema_result_path,
            device_evidence_token_path,
            device_evidence_token_result_path,
            pqc_appraisal_evidence_path,
            pqc_appraisal_result_path,
            partner_scorecard_json_path,
            partner_scorecard_md_path,
            partner_scorecard_result_path,
            research_product_dossier_json_path,
            research_hardening_dossier_md_path,
            product_strategy_brief_md_path,
            evidence_tamper_drill_result_path,
            junit_output,
        ],
    )
    version_check_cmd = [
        sys.executable,
        str(module_path / "scripts/check_version_consistency.py"),
        "--module-path",
        str(module_path),
        "--changelog",
        str(module_path / "CHANGELOG.md"),
    ]
    if args.tag:
        version_check_cmd.extend(["--tag", args.tag])
    release_bundle_cmd = [
        sys.executable,
        str(module_path / "scripts/prepare_release_bundle.py"),
        "--module-path",
        str(module_path),
        "--output-dir",
        str(release_bundle_root),
        "--skip-api-docs",
    ]
    if args.tag:
        release_bundle_cmd.extend(["--tag", args.tag])
    assurance_ledger_cmd = [
        sys.executable,
        str(module_path / "scripts/generate_assurance_ledger.py"),
        "--module-path",
        str(module_path),
        "--claims",
        str(module_path / "scripts/assurance_claims.json"),
        "--benchmark-csv",
        str(benchmark_csv_path),
        "--benchmark-provenance",
        str(benchmark_provenance_path),
        "--cost-of-assurance-evidence",
        str(cost_evidence_path),
        "--release-bundle-root",
        str(release_bundle_root),
        "--transcript-manifest",
        str(evidence_transcript_manifest),
        "--negative-scenario-floor-result",
        str(negative_floor_result_path),
        "--ct-instruction-policy-result",
        str(ct_instruction_policy_result_path),
        "--acvp-json-interop-result",
        str(acvp_json_interop_result_path),
        "--ct-sample-analysis-result",
        str(ct_sample_analysis_result_path),
        "--reference-values",
        str(pqc_reference_values_path),
        "--firmware-status-result",
        str(firmware_assurance_status_result_path),
        "--build-provenance-result",
        str(pqc_build_provenance_result_path),
        "--backend-update-evaluation",
        str(backend_update_evaluation_path),
        "--backend-contract-result",
        str(backend_contract_result_path),
        "--liboqs-inventory",
        str(liboqs_inventory_path),
        "--benchmark-campaign-result",
        str(benchmark_campaign_result_path),
        "--paper-comparison-result",
        str(paper_comparison_result_path),
        "--ct-campaign-result",
        str(ct_campaign_result_path),
        "--acvp-json-schema-result",
        str(acvp_json_schema_result_path),
        "--device-evidence-result",
        str(device_evidence_token_result_path),
        "--appraisal-result",
        str(pqc_appraisal_result_path),
        "--provider-scope-result",
        str(provider_scope_result_path),
        "--release-reference-values-result",
        str(release_reference_values_result_path),
        "--output-json",
        str(assurance_ledger_json),
        "--output-md",
        str(assurance_ledger_md),
    ]
    if args.tag:
        assurance_ledger_cmd.extend(["--tag", args.tag])
    assurance_ledger_verify_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_assurance_ledger.py"),
        str(assurance_ledger_json),
        "--markdown",
        str(assurance_ledger_md),
        "--claims",
        str(module_path / "scripts/assurance_claims.json"),
        "--module-path",
        str(module_path),
    ]
    assurance_report_cmd = [
        sys.executable,
        str(module_path / "scripts/render_assurance_report.py"),
        str(assurance_ledger_json),
        "--output",
        str(assurance_report_html),
    ]
    pqc_cbom_cmd = [
        sys.executable,
        str(module_path / "scripts/export_pqc_cbom.py"),
        "--module-path",
        str(module_path),
        "--ledger",
        str(assurance_ledger_json),
        "--release-manifest",
        str(release_manifest_path),
        "--liboqs-inventory",
        str(liboqs_inventory_path),
        "--output",
        str(pqc_cbom_path),
    ]
    pqc_attestation_cmd = [
        sys.executable,
        str(module_path / "scripts/generate_pqc_attestation.py"),
        "--module-path",
        str(module_path),
        "--ledger",
        str(assurance_ledger_json),
        "--ledger-md",
        str(assurance_ledger_md),
        "--assurance-report",
        str(assurance_report_html),
        "--cbom",
        str(pqc_cbom_path),
        "--release-manifest",
        str(release_manifest_path),
        "--transcript-manifest",
        str(evidence_transcript_manifest),
        "--benchmark-csv",
        str(benchmark_csv_path),
        "--benchmark-provenance",
        str(benchmark_provenance_path),
        "--cost-of-assurance-evidence",
        str(cost_evidence_path),
        "--ct-instruction-policy-result",
        str(ct_instruction_policy_result_path),
        "--evidence-graph",
        str(pqc_evidence_graph_json),
        "--asset-trace-result",
        str(pqc_asset_trace_result_path),
        "--assurance-profile-result",
        str(pqc_assurance_profile_result_path),
        "--evidence-quality-result",
        str(pqc_evidence_quality_result_path),
        "--migration-readiness-json",
        str(pqc_migration_readiness_json_path),
        "--migration-readiness-md",
        str(pqc_migration_readiness_md_path),
        "--environment-result",
        str(pqc_environment_result_path),
        "--acvp-json-interop-result",
        str(acvp_json_interop_result_path),
        "--acvp-json-transcript-manifest",
        str(acvp_json_transcript_manifest_path),
        "--ct-sample-analysis-result",
        str(ct_sample_analysis_result_path),
        "--ct-sample-manifest",
        str(ct_sample_manifest_path),
        "--backend-currency-result",
        str(backend_currency_result_path),
        "--backend-contract-result",
        str(backend_contract_result_path),
        "--liboqs-inventory",
        str(liboqs_inventory_path),
        "--provider-scope-result",
        str(provider_scope_result_path),
        "--benchmark-confidence-result",
        str(benchmark_confidence_result_path),
        "--external-reference-result",
        str(external_reference_result_path),
        "--paper-comparison-json",
        str(paper_comparison_result_path),
        "--paper-comparison-csv",
        str(paper_comparison_csv_path),
        "--output",
        str(pqc_attestation_path),
        "--digest-output",
        str(pqc_assurance_digest_path),
    ]
    provider_scope_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_provider_scope.py"),
        "--cbom",
        str(pqc_cbom_path),
        "--backend-contract",
        str(backend_contract_result_path),
        "--liboqs-inventory",
        str(liboqs_inventory_path),
        "--output",
        str(provider_scope_result_path),
    ]
    pqc_policy_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_assurance_policy.py"),
        "--policy",
        str(module_path / "scripts/pqc_assurance_policy.json"),
        "--ledger",
        str(assurance_ledger_json),
        "--cbom",
        str(pqc_cbom_path),
        "--attestation",
        str(pqc_attestation_path),
        "--release-manifest",
        str(release_manifest_path),
        "--asset-trace-result",
        str(pqc_asset_trace_result_path),
        "--evidence-graph",
        str(pqc_evidence_graph_json),
        "--assurance-digest",
        str(pqc_assurance_digest_path),
        "--ct-instruction-policy-result",
        str(ct_instruction_policy_result_path),
        "--firmware-digest-header",
        str(firmware_digest_header_path),
        "--assurance-profile-result",
        str(pqc_assurance_profile_result_path),
        "--evidence-quality-result",
        str(pqc_evidence_quality_result_path),
        "--migration-readiness-json",
        str(pqc_migration_readiness_json_path),
        "--migration-readiness-md",
        str(pqc_migration_readiness_md_path),
        "--reference-values",
        str(pqc_reference_values_path),
        "--reference-values-result",
        str(pqc_reference_values_result_path),
        "--firmware-status-result",
        str(firmware_assurance_status_result_path),
        "--acvp-json-interop-result",
        str(acvp_json_interop_result_path),
        "--acvp-json-transcript-manifest",
        str(acvp_json_transcript_manifest_path),
        "--build-provenance",
        str(pqc_build_provenance_path),
        "--build-provenance-result",
        str(pqc_build_provenance_result_path),
        "--ct-sample-analysis-result",
        str(ct_sample_analysis_result_path),
        "--ct-sample-manifest",
        str(ct_sample_manifest_path),
        "--backend-currency-result",
        str(backend_currency_result_path),
        "--external-reference-result",
        str(external_reference_result_path),
        "--output",
        str(pqc_policy_result_path),
    ]
    pqc_claim_closure_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_pqc_claim_closure.py"),
        "--ledger",
        str(assurance_ledger_json),
        "--attestation",
        str(pqc_attestation_path),
        "--assurance-digest",
        str(pqc_assurance_digest_path),
        "--ct-instruction-policy-result",
        str(ct_instruction_policy_result_path),
        "--policy-result",
        str(pqc_policy_result_path),
        "--assurance-profile-result",
        str(pqc_assurance_profile_result_path),
        "--evidence-quality-result",
        str(pqc_evidence_quality_result_path),
        "--migration-readiness-json",
        str(pqc_migration_readiness_json_path),
        "--migration-readiness-md",
        str(pqc_migration_readiness_md_path),
        "--firmware-digest-header",
        str(firmware_digest_header_path),
        "--reference-values",
        str(pqc_reference_values_path),
        "--firmware-status-result",
        str(firmware_assurance_status_result_path),
        "--acvp-json-interop-result",
        str(acvp_json_interop_result_path),
        "--build-provenance-result",
        str(pqc_build_provenance_result_path),
        "--ct-sample-analysis-result",
        str(ct_sample_analysis_result_path),
        "--backend-currency-result",
        str(backend_currency_result_path),
        "--output",
        str(pqc_claim_closure_result_path),
    ]
    negative_floor_cmd = [
        sys.executable,
        str(module_path / "scripts/validate_acvp_negative_scenarios.py"),
        "--scenarios",
        str(module_path / "scripts/acvp_negative_scenarios.json"),
        "--floor",
        str(module_path / "scripts/acvp_negative_scenario_floor.json"),
        "--output",
        str(negative_floor_result_path),
    ]
    pqc_asset_trace_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_pqc_asset_trace_map.py"),
        "--trace-map",
        str(module_path / "scripts/pqc_asset_trace_map.json"),
        "--module-path",
        str(module_path),
        "--ledger",
        str(assurance_ledger_json),
        "--cbom",
        str(pqc_cbom_path),
        "--output",
        str(pqc_asset_trace_result_path),
    ]
    pqc_environment_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_release_environment.py"),
        "--module-path",
        str(module_path),
        "--release-manifest",
        str(release_manifest_path),
        "--cbom",
        str(pqc_cbom_path),
        "--output",
        str(pqc_environment_result_path),
    ]
    pqc_evidence_graph_cmd = [
        sys.executable,
        str(module_path / "scripts/generate_pqc_evidence_graph.py"),
        "--trace-map",
        str(module_path / "scripts/pqc_asset_trace_map.json"),
        "--module-path",
        str(module_path),
        "--ledger",
        str(assurance_ledger_json),
        "--cbom",
        str(pqc_cbom_path),
        "--transcript-manifest",
        str(evidence_transcript_manifest),
        "--release-manifest",
        str(release_manifest_path),
        "--ct-instruction-policy-result",
        str(ct_instruction_policy_result_path),
        "--output-json",
        str(pqc_evidence_graph_json),
        "--output-md",
        str(pqc_evidence_graph_md),
    ]
    pqc_assurance_profile_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_pqc_assurance_profile.py"),
        "--profile",
        str(module_path / "scripts/pqc_assurance_profile.json"),
        "--ledger",
        str(assurance_ledger_json),
        "--cbom",
        str(pqc_cbom_path),
        "--trace-map",
        str(module_path / "scripts/pqc_asset_trace_map.json"),
        "--output",
        str(pqc_assurance_profile_result_path),
    ]
    pqc_evidence_quality_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_pqc_evidence_quality.py"),
        "--quality",
        str(module_path / "scripts/pqc_evidence_quality.json"),
        "--ledger",
        str(assurance_ledger_json),
        "--graph",
        str(pqc_evidence_graph_json),
        "--output",
        str(pqc_evidence_quality_result_path),
    ]
    ct_instruction_policy_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_ct_instruction_policy.py"),
        "--elf",
        str(ct_smoke_build_dir / "zephyr/zephyr.elf"),
        "--output",
        str(ct_instruction_policy_result_path),
    ]
    ct_sample_analysis_cmd = [
        sys.executable,
        str(module_path / "scripts/analyze_ct_samples.py"),
        "--transcript-dir",
        str(transcript_dir),
        "--output",
        str(ct_sample_analysis_result_path),
        "--manifest-output",
        str(ct_sample_manifest_path),
    ]
    backend_currency_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_backend_currency.py"),
        "--module-path",
        str(module_path),
        "--output",
        str(backend_currency_result_path),
    ]
    backend_contract_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_backend_contract.py"),
        "--module-path",
        str(module_path),
        "--backend-currency-result",
        str(backend_currency_result_path),
        "--output",
        str(backend_contract_result_path),
    ]
    liboqs_inventory_cmd = [
        sys.executable,
        str(module_path / "scripts/export_liboqs_inventory.py"),
        "--module-path",
        str(module_path),
        "--output",
        str(liboqs_inventory_path),
    ]
    backend_update_cmd = [
        sys.executable,
        str(module_path / "scripts/evaluate_backend_update.py"),
        "--module-path",
        str(module_path),
        "--output",
        str(backend_update_evaluation_path),
    ]
    external_reference_import_cmd = [
        sys.executable,
        str(module_path / "scripts/run_hardware_benchmarks.py"),
        "--mode",
        "import-reference",
        "--reference-csv",
        str(module_path / "scripts/testdata/reference/pqm4_methodology_smoke.csv"),
        "--reference-name",
        "pqm4-methodology-smoke",
        "--source-ecosystem",
        "pqm4",
        "--board-class",
        "cortex-m4",
        "--clock-mhz",
        "168",
        "--compiler",
        "arm-none-eabi-gcc",
        "--toolchain",
        "pqm4",
        "--optimization-flags=-O3",
        "--statistic-type",
        "median_cycles",
        "--environment-type",
        "external_reference",
        "--output-root",
        str(external_reference_output_dir),
    ]
    acvp_json_interop_cmd = [
        sys.executable,
        str(module_path / "scripts/run_acvp_json_vectors.py"),
        str(module_path / "scripts/testdata/acvp_json/mlkem_valid.json"),
        str(module_path / "scripts/testdata/acvp_json/mldsa_valid.json"),
        str(module_path / "scripts/testdata/acvp_json/negative_cases.json"),
        "--mode",
        "auto",
        "--output",
        str(acvp_json_interop_result_path),
        "--transcript-manifest",
        str(acvp_json_transcript_manifest_path),
    ]
    acvp_json_schema_cmd = [
        sys.executable,
        str(module_path / "scripts/validate_acvp_json_schema.py"),
        "--result",
        str(acvp_json_interop_result_path),
        "--transcript-manifest",
        str(acvp_json_transcript_manifest_path),
        "--output",
        str(acvp_json_schema_result_path),
    ]
    pqc_migration_readiness_cmd = [
        sys.executable,
        str(module_path / "scripts/generate_migration_readiness_report.py"),
        "--profile-result",
        str(pqc_assurance_profile_result_path),
        "--quality-result",
        str(pqc_evidence_quality_result_path),
        "--cbom",
        str(pqc_cbom_path),
        "--output-json",
        str(pqc_migration_readiness_json_path),
        "--output-md",
        str(pqc_migration_readiness_md_path),
    ]
    firmware_digest_header_cmd = [
        sys.executable,
        str(module_path / "scripts/export_firmware_assurance_digest.py"),
        "--digest",
        str(pqc_assurance_digest_path),
        "--output",
        str(firmware_digest_header_path),
        "--version",
        read_version_string(module_path),
    ]
    assurance_status_build_cmd = [
        *west_cmd,
        "build",
        "-p",
        "always",
        "-b",
        "qemu_x86_64",
        str(module_path / "samples/pqcp_assurance_status"),
        "-d",
        str(assurance_status_build_dir),
        "--",
        f"-DZEPHYR_EXTRA_MODULES={module_path}",
        f"-DPQCP_ASSURANCE_DIGEST_INCLUDE_DIR={generated_include_dir}",
    ]
    assurance_status_run_cmd = [
        *west_cmd,
        "build",
        "-d",
        str(assurance_status_build_dir),
        "-t",
        "run",
    ]
    pqc_reference_values_cmd = [
        sys.executable,
        str(module_path / "scripts/generate_pqc_reference_values.py"),
        "--module-path",
        str(module_path),
        "--ledger",
        str(assurance_ledger_json),
        "--cbom",
        str(pqc_cbom_path),
        "--attestation",
        str(pqc_attestation_path),
        "--assurance-digest",
        str(pqc_assurance_digest_path),
        "--release-manifest",
        str(release_manifest_path),
        "--policy-result",
        str(pqc_policy_result_path),
        "--profile-result",
        str(pqc_assurance_profile_result_path),
        "--transcript-manifest",
        str(evidence_transcript_manifest),
        "--backend-contract",
        str(backend_contract_result_path),
        "--provider-scope-result",
        str(provider_scope_result_path),
        "--output",
        str(pqc_reference_values_path),
    ]
    pqc_reference_values_verify_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_pqc_reference_values.py"),
        "--reference-values",
        str(pqc_reference_values_path),
        "--ledger",
        str(assurance_ledger_json),
        "--cbom",
        str(pqc_cbom_path),
        "--attestation",
        str(pqc_attestation_path),
        "--assurance-digest",
        str(pqc_assurance_digest_path),
        "--release-manifest",
        str(release_manifest_path),
        "--policy-result",
        str(pqc_policy_result_path),
        "--profile-result",
        str(pqc_assurance_profile_result_path),
        "--transcript-manifest",
        str(evidence_transcript_manifest),
        "--backend-contract",
        str(backend_contract_result_path),
        "--provider-scope-result",
        str(provider_scope_result_path),
        "--output",
        str(pqc_reference_values_result_path),
    ]
    release_reference_values_verify_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_release_reference_values.py"),
        "--reference-values",
        str(pqc_reference_values_path),
        "--release-manifest",
        str(release_manifest_path),
        "--backend-contract",
        str(backend_contract_result_path),
        "--provider-scope-result",
        str(provider_scope_result_path),
        "--cbom",
        str(pqc_cbom_path),
        "--output",
        str(release_reference_values_result_path),
    ]
    firmware_assurance_status_verify_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_firmware_assurance_status.py"),
        "--reference-values",
        str(pqc_reference_values_path),
        "--transcript-dir",
        str(transcript_dir),
        "--output",
        str(firmware_assurance_status_result_path),
    ]
    pqc_build_provenance_cmd = [
        sys.executable,
        str(module_path / "scripts/generate_pqc_build_provenance.py"),
        "--module-path",
        str(module_path),
        "--release-manifest",
        str(release_manifest_path),
        "--subject",
        str(assurance_ledger_json),
        "--subject",
        str(pqc_reference_values_path),
        "--subject",
        str(pqc_cbom_path),
        "--subject",
        str(pqc_attestation_path),
        "--byproduct",
        str(benchmark_csv_path),
        "--byproduct",
        str(cost_evidence_path),
        "--byproduct",
        str(acvp_json_interop_result_path),
        "--byproduct",
        str(acvp_json_schema_result_path),
        "--byproduct",
        str(ct_sample_analysis_result_path),
        "--byproduct",
        str(ct_sample_manifest_path),
        "--byproduct",
        str(ct_campaign_result_path),
        "--byproduct",
        str(backend_currency_result_path),
        "--byproduct",
        str(backend_contract_result_path),
        "--byproduct",
        str(provider_scope_result_path),
        "--byproduct",
        str(liboqs_inventory_path),
        "--byproduct",
        str(backend_update_evaluation_path),
        "--byproduct",
        str(external_reference_result_path),
        "--byproduct",
        str(benchmark_campaign_result_path),
        "--byproduct",
        str(benchmark_confidence_result_path),
        "--byproduct",
        str(paper_comparison_result_path),
        "--byproduct",
        str(paper_comparison_csv_path),
        "--byproduct",
        str(device_evidence_token_path),
        "--byproduct",
        str(device_evidence_token_result_path),
        "--byproduct",
        str(release_reference_values_result_path),
        "--output",
        str(pqc_build_provenance_path),
    ]
    pqc_build_provenance_verify_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_pqc_build_provenance.py"),
        "--provenance",
        str(pqc_build_provenance_path),
        "--subject",
        str(assurance_ledger_json),
        "--subject",
        str(pqc_reference_values_path),
        "--subject",
        str(pqc_cbom_path),
        "--subject",
        str(pqc_attestation_path),
        "--byproduct",
        str(benchmark_csv_path),
        "--byproduct",
        str(cost_evidence_path),
        "--byproduct",
        str(acvp_json_interop_result_path),
        "--byproduct",
        str(acvp_json_schema_result_path),
        "--byproduct",
        str(ct_sample_analysis_result_path),
        "--byproduct",
        str(ct_sample_manifest_path),
        "--byproduct",
        str(ct_campaign_result_path),
        "--byproduct",
        str(backend_currency_result_path),
        "--byproduct",
        str(backend_contract_result_path),
        "--byproduct",
        str(provider_scope_result_path),
        "--byproduct",
        str(liboqs_inventory_path),
        "--byproduct",
        str(backend_update_evaluation_path),
        "--byproduct",
        str(external_reference_result_path),
        "--byproduct",
        str(benchmark_campaign_result_path),
        "--byproduct",
        str(benchmark_confidence_result_path),
        "--byproduct",
        str(paper_comparison_result_path),
        "--byproduct",
        str(paper_comparison_csv_path),
        "--byproduct",
        str(device_evidence_token_path),
        "--byproduct",
        str(device_evidence_token_result_path),
        "--byproduct",
        str(release_reference_values_result_path),
        "--release-manifest",
        str(release_manifest_path),
        "--output",
        str(pqc_build_provenance_result_path),
    ]
    benchmark_campaign_cmd = [
        sys.executable,
        str(module_path / "scripts/run_benchmark_campaign.py"),
        "--benchmark-csv",
        str(benchmark_csv_path),
        "--benchmark-provenance",
        str(benchmark_provenance_path),
        "--external-reference-result",
        str(external_reference_result_path),
        "--output",
        str(benchmark_campaign_result_path),
    ]
    benchmark_campaign_verify_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_benchmark_campaign.py"),
        "--campaign",
        str(benchmark_campaign_result_path),
        "--output",
        str(benchmark_campaign_verify_result_path),
    ]
    benchmark_confidence_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_benchmark_confidence.py"),
        "--campaign",
        str(benchmark_campaign_result_path),
        "--output",
        str(benchmark_confidence_result_path),
    ]
    paper_comparison_cmd = [
        sys.executable,
        str(module_path / "scripts/run_paper_comparison_campaign.py"),
        "--benchmark-campaign",
        str(benchmark_campaign_result_path),
        "--output-csv",
        str(paper_comparison_csv_path),
        "--output-json",
        str(paper_comparison_result_path),
    ]
    metric_optimization_cmd = [
        sys.executable,
        str(module_path / "scripts/optimize_metric_campaign.py"),
        "--baseline-campaign",
        str(benchmark_campaign_result_path),
        "--cost-evidence",
        str(cost_evidence_path),
        "--emit-overlays",
        str(metric_optimization_overlay_dir),
        "--output",
        str(metric_optimization_result_path),
    ]
    ct_campaign_cmd = [
        sys.executable,
        str(module_path / "scripts/run_ct_campaign.py"),
        "--analysis",
        str(ct_sample_analysis_result_path),
        "--manifest",
        str(ct_sample_manifest_path),
        "--output",
        str(ct_campaign_result_path),
    ]
    device_evidence_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_device_evidence_token.py"),
        "--reference-values",
        str(pqc_reference_values_path),
        "--transcript-dir",
        str(transcript_dir),
        "--token-output",
        str(device_evidence_token_path),
        "--output",
        str(device_evidence_token_result_path),
    ]
    appraisal_evidence_cmd = [
        sys.executable,
        str(module_path / "scripts/generate_pqc_appraisal_evidence.py"),
        "--output-root",
        str(output_root),
        "--policy",
        str(module_path / "scripts/pqc_appraisal_policy.json"),
        "--ledger",
        str(assurance_ledger_json),
        "--policy-result",
        str(pqc_policy_result_path),
        "--backend-update",
        str(backend_update_evaluation_path),
        "--benchmark-campaign",
        str(benchmark_campaign_result_path),
        "--ct-campaign",
        str(ct_campaign_result_path),
        "--acvp-schema-result",
        str(acvp_json_schema_result_path),
        "--device-evidence-result",
        str(device_evidence_token_result_path),
        "--output",
        str(pqc_appraisal_evidence_path),
    ]
    appraisal_verify_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_pqc_appraisal_evidence.py"),
        "--policy",
        str(module_path / "scripts/pqc_appraisal_policy.json"),
        "--appraisal-evidence",
        str(pqc_appraisal_evidence_path),
        "--ledger",
        str(assurance_ledger_json),
        "--mode",
        "partner_review",
        "--output",
        str(pqc_appraisal_result_path),
    ]
    partner_scorecard_cmd = [
        sys.executable,
        str(module_path / "scripts/generate_partner_review_scorecard.py"),
        "--ledger",
        str(assurance_ledger_json),
        "--cbom",
        str(pqc_cbom_path),
        "--policy-result",
        str(pqc_policy_result_path),
        "--profile-result",
        str(pqc_assurance_profile_result_path),
        "--quality-result",
        str(pqc_evidence_quality_result_path),
        "--migration-readiness",
        str(pqc_migration_readiness_json_path),
        "--backend-contract",
        str(backend_contract_result_path),
        "--provider-scope-result",
        str(provider_scope_result_path),
        "--benchmark-campaign",
        str(benchmark_campaign_result_path),
        "--ct-campaign",
        str(ct_campaign_result_path),
        "--acvp-schema-result",
        str(acvp_json_schema_result_path),
        "--device-evidence-result",
        str(device_evidence_token_result_path),
        "--reference-values",
        str(pqc_reference_values_path),
        "--appraisal-result",
        str(pqc_appraisal_result_path),
        "--output-json",
        str(partner_scorecard_json_path),
        "--output-md",
        str(partner_scorecard_md_path),
    ]
    partner_scorecard_verify_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_partner_review_scorecard.py"),
        "--scorecard",
        str(partner_scorecard_json_path),
        "--markdown",
        str(partner_scorecard_md_path),
        "--ledger",
        str(assurance_ledger_json),
        "--cbom",
        str(pqc_cbom_path),
        "--policy-result",
        str(pqc_policy_result_path),
        "--profile-result",
        str(pqc_assurance_profile_result_path),
        "--quality-result",
        str(pqc_evidence_quality_result_path),
        "--migration-readiness",
        str(pqc_migration_readiness_json_path),
        "--backend-contract",
        str(backend_contract_result_path),
        "--provider-scope-result",
        str(provider_scope_result_path),
        "--benchmark-campaign",
        str(benchmark_campaign_result_path),
        "--ct-campaign",
        str(ct_campaign_result_path),
        "--acvp-schema-result",
        str(acvp_json_schema_result_path),
        "--device-evidence-result",
        str(device_evidence_token_result_path),
        "--reference-values",
        str(pqc_reference_values_path),
        "--appraisal-result",
        str(pqc_appraisal_result_path),
        "--output",
        str(partner_scorecard_result_path),
    ]
    research_product_dossier_cmd = [
        sys.executable,
        str(module_path / "scripts/generate_research_product_dossier.py"),
        "--module-path",
        str(module_path),
        "--release-output",
        str(output_root),
        "--output-root",
        str(output_root),
        "--tag",
        release_tag,
        "--depth",
        "full",
    ]
    evidence_pack_verify_cmd = [
        sys.executable,
        str(module_path / "scripts/verify_release_evidence_pack.py"),
        str(output_root),
        "--module-path",
        str(module_path),
        "--claims",
        str(module_path / "scripts/assurance_claims.json"),
    ]
    if args.tag:
        evidence_pack_verify_cmd.extend(["--tag", args.tag])
    evidence_tamper_drill_cmd = [
        sys.executable,
        str(module_path / "scripts/run_evidence_tamper_drill.py"),
        str(output_root),
        "--module-path",
        str(module_path),
        "--policy",
        str(module_path / "scripts/evidence_tamper_drill_policy.json"),
        "--output",
        str(evidence_tamper_drill_result_path),
    ]
    if args.tag:
        evidence_tamper_drill_cmd.extend(["--tag", args.tag])

    steps = [
        Step(
            name="version_consistency",
            cmd=version_check_cmd,
            cwd=module_path,
        ),
        Step(
            name="cppcheck",
            cmd=[
                cppcheck_cmd,
                "--quiet",
                "--enable=warning,style,performance,portability",
                "--error-exitcode=2",
                "--inline-suppr",
                "--suppress=missingIncludeSystem",
                "--suppress=unusedStructMember",
                # cppcheck 2.7 emits this informational diagnostic and applies
                # --error-exitcode to it when the tree has more preprocessor
                # combinations than its default exploration limit. Newer
                # cppcheck versions do not report it for this invocation. It
                # is configuration-coverage metadata, not a source finding;
                # strict per-file/config analysis remains in extended checks.
                "--suppress=toomanyconfigs",
                # Keep the release gate focused on control-flow, bounds,
                # initialization, portability, and performance defects. These
                # five IDs are readability/const-propagation heuristics and
                # are already non-blocking in the focused extended checker.
                "--suppress=variableScope",
                "--suppress=constParameter",
                "--suppress=constParameterPointer",
                "--suppress=constVariablePointer",
                "--suppress=constVariable",
                "--template={severity}:{id}:{file}:{line}:{message}",
                f"-I{module_path / 'include'}",
                str(module_path / "src"),
            ],
            cwd=module_path,
        ),
        Step(
            name="Extended Checks (strict)",
            cmd=[
                sys.executable,
                str(module_path / "scripts/run_extended_checks.py"),
                "--west-root",
                str(west_root),
                "--module-path",
                str(module_path),
                "--strict",
            ],
            cwd=module_path,
        ),
        Step(
            name="sanitizers",
            cmd=[
                sys.executable,
                str(module_path / "scripts/run_sanitizer_checks.py"),
                "--west-root",
                str(west_root),
                "--module-path",
                str(module_path),
            ],
            cwd=module_path,
            timeout=1200,
        ),
        Step(
            name="Extended Checks (strict cost-of-assurance smoke)",
            cmd=[
                sys.executable,
                str(module_path / "scripts/run_extended_checks.py"),
                "--west-root",
                str(west_root),
                "--module-path",
                str(module_path),
                "--strict",
                "--run-cost-of-assurance-smoke",
                "--cost-of-assurance-output-root",
                str(cost_smoke_output_root),
                "--cost-of-assurance-evidence",
                str(cost_evidence_path),
            ],
            cwd=module_path,
        ),
        Step(
            name="ACVP serial ztest build",
            cmd=[
                *west_cmd,
                "build",
                "-p",
                "always",
                "-b",
                "qemu_x86_64",
                str(module_path / "tests/ztest_acvp_serial"),
                "-d",
                str(ztest_build_dir),
                "--",
                f"-DZEPHYR_EXTRA_MODULES={module_path}",
            ],
            cwd=west_root,
        ),
        Step(
            name="ACVP serial ztest run",
            cmd=[
                *west_cmd,
                "build",
                "-d",
                str(ztest_build_dir),
                "-t",
                "run",
            ],
            cwd=west_root,
            timeout=120,
            success_markers=(
                "TESTSUITE pqcp_acvp_serial succeeded",
                "PROJECT EXECUTION SUCCESSFUL",
            ),
        ),
        Step(
            name="ACVP serial negative scenario header check",
            cmd=[
                sys.executable,
                str(module_path / "scripts/generate_acvp_negative_header.py"),
                "--check",
            ],
            cwd=module_path,
        ),
        Step(
            name="ACVP negative scenario floor validation",
            cmd=negative_floor_cmd,
            cwd=module_path,
        ),
        Step(
            name="ACVP serial negative ztest build",
            cmd=[
                *west_cmd,
                "build",
                "-p",
                "always",
                "-b",
                "qemu_x86_64",
                str(module_path / "tests/ztest_acvp_serial_negative"),
                "-d",
                str(ztest_negative_build_dir),
                "--",
                f"-DZEPHYR_EXTRA_MODULES={module_path}",
            ],
            cwd=west_root,
        ),
        Step(
            name="ACVP serial negative ztest run",
            cmd=[
                *west_cmd,
                "build",
                "-d",
                str(ztest_negative_build_dir),
                "-t",
                "run",
            ],
            cwd=west_root,
            timeout=120,
            success_markers=(
                "TESTSUITE pqcp_acvp_serial_negative succeeded",
                "PROJECT EXECUTION SUCCESSFUL",
            ),
        ),
        Step(
            name="ACVP JSON interop",
            cmd=acvp_json_interop_cmd,
            cwd=module_path,
        ),
        Step(
            name="ACVP JSON schema coverage",
            cmd=acvp_json_schema_cmd,
            cwd=module_path,
        ),
        Step(
            name="kat_provenance",
            cmd=[
                sys.executable,
                str(module_path / "scripts/verify_kat_provenance.py"),
                "--header",
                str(module_path / "tests/ztest_acvp_kat/src/kat_vectors.h"),
            ],
            cwd=module_path,
        ),
        Step(
            name="ACVP KAT ztest build",
            cmd=[
                *west_cmd,
                "build",
                "-p",
                "always",
                "-b",
                "qemu_x86_64",
                str(module_path / "tests/ztest_acvp_kat"),
                "-d",
                str(kat_build_dir),
                "--",
                f"-DZEPHYR_EXTRA_MODULES={module_path}",
            ],
            cwd=west_root,
        ),
        Step(
            name="ACVP KAT ztest run",
            cmd=[
                *west_cmd,
                "build",
                "-d",
                str(kat_build_dir),
                "-t",
                "run",
            ],
            cwd=west_root,
            timeout=180,
            success_markers=(
                "TESTSUITE pqcp_acvp_kat succeeded",
                "PROJECT EXECUTION SUCCESSFUL",
            ),
        ),
        Step(
            name="boot KAT self-verify ztest build",
            cmd=[
                *west_cmd,
                "build",
                "-p",
                "always",
                "-b",
                "qemu_x86_64",
                str(module_path / "tests/ztest_kat_boot_verify"),
                "-d",
                str(boot_verify_build_dir),
                "--",
                f"-DZEPHYR_EXTRA_MODULES={module_path}",
            ],
            cwd=west_root,
        ),
        Step(
            name="boot KAT self-verify ztest run",
            cmd=[
                *west_cmd,
                "build",
                "-d",
                str(boot_verify_build_dir),
                "-t",
                "run",
            ],
            cwd=west_root,
            timeout=120,
            success_markers=(
                "TESTSUITE pqcp_kat_boot_verify succeeded",
                "PROJECT EXECUTION SUCCESSFUL",
            ),
        ),
        Step(
            name="evidence chain host replay",
            cmd=[
                sys.executable,
                str(module_path / "scripts/run_evidence_chain_replay.py"),
                "--west-root",
                str(west_root),
                "--output-dir",
                str(evidence_chain_output_dir),
            ],
            cwd=module_path,
            timeout=900,
            success_markers=(
                "pqcp-evidence-verify: CHAIN OK",
                "[evidence-chain] PASS: device evidence chain replayed on host",
            ),
        ),
        Step(
            name="transparent appraisal receipt",
            cmd=[
                sys.executable,
                str(module_path / "scripts/run_transparent_appraisal.py"),
                "--output-dir",
                str(transparent_appraisal_output_dir),
            ],
            cwd=module_path,
            timeout=900,
            success_markers=("PQCP_APPRAISAL_RECEIPT PASS",),
        ),
        Step(
            name="evidence coverage audit",
            cmd=[
                sys.executable,
                str(module_path / "scripts/audit_evidence_coverage.py"),
                "--check",
                "--json",
                str(evidence_coverage_report),
            ],
            cwd=module_path,
            timeout=120,
            success_markers=(
                "PQCP_EVIDENCE_COVERAGE PASS",
                "[coverage] PASS:",
            ),
        ),
        Step(
            name="evidence parser fuzz",
            cmd=[
                sys.executable,
                str(module_path / "scripts/run_fuzz_checks.py"),
                "--build-dir",
                str(evidence_fuzz_build_dir),
            ],
            cwd=module_path,
            timeout=900,
            success_markers=(
                "PQCP_FUZZ PASS",
                "[fuzz] PASS:",
            ),
        ),
        # Full gate only (not CI_FAST_GATE_STEPS): the rediscovery half
        # rebuilds the model app once per historical defect.
        Step(
            name="edge model conformance",
            cmd=[
                sys.executable,
                str(module_path / "scripts/run_model_checks.py"),
                "--rediscover",
                "--west-root",
                str(west_root),
                "--output-dir",
                str(edge_model_output_dir),
            ],
            cwd=module_path,
            timeout=3600,
            success_markers=(
                "PQCP_MODEL_SUMMARY",
                "PQCP_MODEL_REDISCOVERY PASS",
            ),
        ),
        Step(
            name="ct instruction-count",
            cmd=[
                sys.executable,
                str(module_path / "scripts/run_ct_instruction_checks.py"),
                "--west-root",
                str(west_root),
                "--output-dir",
                str(ct_instruction_output_dir),
            ],
            cwd=module_path,
            timeout=900,
            success_markers=(
                "PQCP_CT_INSTRUCTION_COUNT PASS",
                "[ct-insn] PASS:",
            ),
        ),
        Step(
            name="ct trace relational",
            cmd=[
                sys.executable,
                str(module_path / "scripts/run_ct_trace_checks.py"),
                "--west-root",
                str(west_root),
                "--output-dir",
                str(ct_trace_output_dir / "clean"),
                "--opt",
                "default",
                "--opt",
                "speed",
                "--opt",
                "debug",
            ],
            cwd=module_path,
            timeout=900,
            success_markers=(
                "PQCP_CT_TRACE PASS",
                "[ct-trace] PASS:",
            ),
        ),
        Step(
            name="ct leak rediscovery",
            cmd=[
                sys.executable,
                str(module_path / "scripts/run_ct_trace_checks.py"),
                "--west-root",
                str(west_root),
                "--output-dir",
                str(ct_trace_output_dir / "rediscovery"),
                "--rediscover",
                "--opt",
                "default",
            ],
            cwd=module_path,
            timeout=3600,
            success_markers=("PQCP_CT_TRACE_REDISCOVERY PASS",),
        ),
        Step(
            name="fault campaign",
            cmd=[
                sys.executable,
                str(module_path / "scripts/run_fault_gate.py"),
                "--west-root",
                str(west_root),
                "--output-dir",
                str(fault_output_dir),
            ],
            cwd=module_path,
            timeout=5400,
            success_markers=("PQCP_FAULT_GATE PASS",),
        ),
        Step(
            name="ct smoke ztest build",
            cmd=[
                *west_cmd,
                "build",
                "-p",
                "always",
                "-b",
                "qemu_x86_64",
                str(module_path / "tests/ztest_ct_smoke"),
                "-d",
                str(ct_smoke_build_dir),
                "--",
                f"-DZEPHYR_EXTRA_MODULES={module_path}",
                "-DCONFIG_PQCP_CT_SAMPLE_TRANSCRIPT=y",
            ],
            cwd=west_root,
        ),
        Step(
            name="ct smoke ztest run",
            cmd=[
                *west_cmd,
                "build",
                "-d",
                str(ct_smoke_build_dir),
                "-t",
                "run",
            ],
            cwd=west_root,
            timeout=180,
            success_markers=(
                "TESTSUITE pqcp_ct_smoke succeeded",
                "PROJECT EXECUTION SUCCESSFUL",
            ),
        ),
        Step(
            name="ct sample analysis",
            cmd=ct_sample_analysis_cmd,
            cwd=module_path,
        ),
        Step(
            name="ct campaign analysis",
            cmd=ct_campaign_cmd,
            cwd=module_path,
        ),
        Step(
            name="ct instruction policy",
            cmd=ct_instruction_policy_cmd,
            cwd=module_path,
        ),
        Step(
            name="benchmark_csv",
            cmd=[
                sys.executable,
                str(module_path / "scripts/export_results.py"),
                "--west-root",
                str(west_root),
                "--module-path",
                str(module_path),
                "--output",
                str(benchmark_csv_path),
                "--platform",
                "qemu_x86_64",
                "--smoke",
            ],
            cwd=module_path,
            timeout=900,
            success_markers=(
                "[export] Wrote",
                "benchmark_results.csv",
            ),
        ),
        Step(
            name="benchmark_csv_validate",
            cmd=[
                sys.executable,
                str(module_path / "scripts/export_results.py"),
                "--validate-only",
                str(benchmark_csv_path),
                "--verify-provenance",
            ],
            cwd=module_path,
        ),
        Step(
            name="external reference import",
            cmd=external_reference_import_cmd,
            cwd=module_path,
        ),
        Step(
            name="benchmark campaign",
            cmd=benchmark_campaign_cmd,
            cwd=module_path,
        ),
        Step(
            name="benchmark campaign verification",
            cmd=benchmark_campaign_verify_cmd,
            cwd=module_path,
        ),
        Step(
            name="benchmark confidence replay",
            cmd=benchmark_confidence_cmd,
            cwd=module_path,
        ),
        Step(
            name="paper comparison campaign",
            cmd=paper_comparison_cmd,
            cwd=module_path,
        ),
        Step(
            name="metric optimization campaign",
            cmd=metric_optimization_cmd,
            cwd=module_path,
        ),
        Step(
            name="backend currency",
            cmd=backend_currency_cmd,
            cwd=module_path,
        ),
        Step(
            name="backend contract",
            cmd=backend_contract_cmd,
            cwd=module_path,
        ),
        Step(
            name="external provider inventory",
            cmd=liboqs_inventory_cmd,
            cwd=module_path,
        ),
        Step(
            name="backend update evaluation",
            cmd=backend_update_cmd,
            cwd=module_path,
        ),
        Step(
            name="resource_budgets",
            cmd=[
                sys.executable,
                str(module_path / "scripts/check_resource_budgets.py"),
                "--west-root",
                str(west_root),
                "--module-path",
                str(module_path),
                "--output-root",
                str(output_root / "mcu_protocol_footprint"),
            ],
            cwd=module_path,
            timeout=1200,
        ),
        Step(
            name="Profile validation with resource budgets",
            cmd=[
                sys.executable,
                str(module_path / "scripts/run_benchmarks.py"),
                "--west-root",
                str(west_root),
                "--module-path",
                str(module_path),
                "--profile-validation",
                "--build-only",
                "--resource-budgets",
                str(module_path / "scripts/resource_budgets.json"),
                "--output",
                str(profile_output_dir),
            ],
            cwd=module_path,
        ),
        Step(
            name="local release bundle",
            cmd=release_bundle_cmd,
            cwd=module_path,
        ),
        Step(
            name="assurance ledger",
            cmd=assurance_ledger_cmd,
            cwd=module_path,
        ),
        Step(
            name="assurance ledger verification",
            cmd=assurance_ledger_verify_cmd,
            cwd=module_path,
        ),
        Step(
            name="assurance report",
            cmd=assurance_report_cmd,
            cwd=module_path,
        ),
        Step(
            name="PQC CBOM",
            cmd=pqc_cbom_cmd,
            cwd=module_path,
        ),
        Step(
            name="provider scope",
            cmd=provider_scope_cmd,
            cwd=module_path,
        ),
        Step(
            name="PQC release environment",
            cmd=pqc_environment_cmd,
            cwd=module_path,
        ),
        Step(
            name="PQC asset trace map",
            cmd=pqc_asset_trace_cmd,
            cwd=module_path,
        ),
        Step(
            name="PQC evidence graph",
            cmd=pqc_evidence_graph_cmd,
            cwd=module_path,
        ),
        Step(
            name="PQC assurance profile",
            cmd=pqc_assurance_profile_cmd,
            cwd=module_path,
        ),
        Step(
            name="PQC evidence quality",
            cmd=pqc_evidence_quality_cmd,
            cwd=module_path,
        ),
        Step(
            name="PQC migration readiness",
            cmd=pqc_migration_readiness_cmd,
            cwd=module_path,
        ),
        Step(
            name="PQC assurance attestation",
            cmd=pqc_attestation_cmd,
            cwd=module_path,
        ),
        Step(
            name="firmware assurance digest header",
            cmd=firmware_digest_header_cmd,
            cwd=module_path,
        ),
        Step(
            name="firmware assurance status build",
            cmd=assurance_status_build_cmd,
            cwd=west_root,
            timeout=240,
        ),
        Step(
            name="firmware assurance status run",
            cmd=assurance_status_run_cmd,
            cwd=west_root,
            timeout=120,
            success_markers=(
                "PQCP_ASSURANCE_STATUS",
                "PROJECT EXECUTION SUCCESSFUL",
            ),
        ),
        Step(
            name="PQC assurance policy",
            cmd=pqc_policy_cmd,
            cwd=module_path,
        ),
        Step(
            name="PQC reference values",
            cmd=pqc_reference_values_cmd,
            cwd=module_path,
        ),
        Step(
            name="PQC reference values verification",
            cmd=pqc_reference_values_verify_cmd,
            cwd=module_path,
        ),
        Step(
            name="release reference values provider replay",
            cmd=release_reference_values_verify_cmd,
            cwd=module_path,
        ),
        Step(
            name="firmware assurance status verification",
            cmd=firmware_assurance_status_verify_cmd,
            cwd=module_path,
        ),
        Step(
            name="device evidence token verification",
            cmd=device_evidence_cmd,
            cwd=module_path,
        ),
        Step(
            name="PQC build provenance",
            cmd=pqc_build_provenance_cmd,
            cwd=module_path,
        ),
        Step(
            name="PQC build provenance verification",
            cmd=pqc_build_provenance_verify_cmd,
            cwd=module_path,
        ),
        Step(
            name="PQC appraisal evidence",
            cmd=appraisal_evidence_cmd,
            cwd=module_path,
        ),
        Step(
            name="PQC appraisal verification",
            cmd=appraisal_verify_cmd,
            cwd=module_path,
        ),
        Step(
            name="partner review scorecard",
            cmd=partner_scorecard_cmd,
            cwd=module_path,
        ),
        Step(
            name="partner review scorecard verification",
            cmd=partner_scorecard_verify_cmd,
            cwd=module_path,
        ),
        Step(
            name="research product dossier",
            cmd=research_product_dossier_cmd,
            cwd=module_path,
        ),
        Step(
            name="PQC claim closure",
            cmd=pqc_claim_closure_cmd,
            cwd=module_path,
        ),
        Step(
            name="release evidence pack verification",
            cmd=evidence_pack_verify_cmd,
            cwd=module_path,
        ),
        Step(
            name="release evidence tamper drill",
            cmd=evidence_tamper_drill_cmd,
            cwd=module_path,
        ),
    ]
    steps = select_steps_for_mode(steps, ci=args.ci)

    print("PQCP Release Check")
    print(f"  west root : {west_root}")
    print(f"  module    : {module_path}")
    print(f"  west cmd  : {' '.join(west_cmd)}")
    print(f"  output    : {output_root}")
    print(f"  mode      : {'CI fast gate' if args.ci else 'full local release gate'}")

    results: List[StepResult] = []
    transcript_entries: list[dict[str, object]] = []
    for index, step in enumerate(steps, start=1):
        if step.name == "assurance ledger":
            write_evidence_transcript_manifest(
                entries=transcript_entries,
                transcript_dir=transcript_dir,
                qemu_stdout_roots=[cost_smoke_output_root],
                output_path=evidence_transcript_manifest,
            )
        result = run_step(step, env, args.verbose)
        results.append(result)
        transcript_entries.append(
            write_step_transcript(
                index=index,
                step=step,
                result=result,
                transcript_dir=transcript_dir,
            )
        )
        write_junit_report(results, junit_output)
        if result.returncode != 0:
            print(f"[INFO] Wrote JUnit report to {junit_output}")
            return result.returncode

    write_junit_report(results, junit_output)
    print(f"[INFO] Wrote JUnit report to {junit_output}")

    if args.ci:
        write_evidence_transcript_manifest(
            entries=transcript_entries,
            transcript_dir=transcript_dir,
            qemu_stdout_roots=[],
            output_path=evidence_transcript_manifest,
            required_steps=CI_EVIDENCE_TRANSCRIPT_STEPS,
        )
        write_ci_assurance_ledger(
            module_path=module_path,
            output_root=output_root,
            version=read_version_string(module_path),
            tag=args.tag,
            head_sha=git_head_sha(module_path),
            dirty=git_tree_dirty(module_path),
            transcript_manifest_path=evidence_transcript_manifest,
            ledger_json_path=assurance_ledger_json,
            ledger_md_path=assurance_ledger_md,
        )
        print(f"[PASS] CI assurance ledger written to {assurance_ledger_json}")
        print("[PASS] CI fast release gate completed successfully.")
        return 0

    print("[PASS] Release validation sequence completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
