#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Run the project release validation sequence with clear per-step PASS/FAIL output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
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
    "ACVP serial ztest run",
    "ACVP KAT ztest run",
    "benchmark_csv",
    "benchmark_csv_validate",
    "resource_budgets",
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
) -> None:
    transcript_dir.mkdir(parents=True, exist_ok=True)
    required = set(REQUIRED_EVIDENCE_TRANSCRIPT_STEPS)
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
        "required_steps": list(REQUIRED_EVIDENCE_TRANSCRIPT_STEPS),
        "transcripts": selected,
        "qemu_stdout_transcripts": qemu_stdout_transcripts,
    }
    output_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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
        stdout, _ = proc.communicate(timeout=step.timeout)
        stdout = stdout or ""
        returncode = proc.returncode
    except subprocess.TimeoutExpired:
        stdout = ""
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except PermissionError:
                pass
            try:
                stdout, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    pass
                stdout, _ = proc.communicate()
        returncode = 124

    duration_seconds = time.perf_counter() - started

    if stdout:
        print(stdout, end="" if stdout.endswith("\n") else "\n")

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
    kat_build_dir = output_root / "ztest_acvp_kat_qemu"
    profile_output_dir = output_root / "profile_validation"
    benchmark_csv_path = output_root / "benchmark_results.csv"
    benchmark_provenance_path = benchmark_csv_path.with_name("benchmark_provenance.json")
    cost_evidence_path = output_root / "cost_of_assurance_evidence.json"
    cost_smoke_output_root = output_root / "cost_of_assurance_smoke"
    release_bundle_root = output_root / "local_release_bundle"
    assurance_ledger_json = output_root / "assurance_ledger.json"
    assurance_ledger_md = output_root / "assurance_ledger.md"
    transcript_dir = output_root / "transcripts"
    evidence_transcript_manifest = transcript_dir / "evidence_transcript_manifest.json"
    junit_output = output_root / "release_check_results.xml"
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
            name="release evidence pack verification",
            cmd=evidence_pack_verify_cmd,
            cwd=module_path,
        ),
    ]

    print("PQCP Release Check")
    print(f"  west root : {west_root}")
    print(f"  module    : {module_path}")
    print(f"  west cmd  : {' '.join(west_cmd)}")
    print(f"  output    : {output_root}")

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
    print("[PASS] Release validation sequence completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
