#!/usr/bin/env python3
"""
Run the project release validation sequence with clear per-step PASS/FAIL output.
"""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from xml.etree import ElementTree as ET

HOST_ENV_BLACKLIST = (
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "CPATH",
    "SDKROOT",
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
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("benchmark_results/release_check"),
        help="Root directory for release-check build artifacts",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Echo commands before running them")
    return parser.parse_args()


def detect_west_root(start: Path) -> Path:
    current = start.resolve()
    while current != current.parent:
        if (current / ".west").exists():
            return current
        current = current.parent
    return start.resolve()


def discover_west(explicit: Optional[str], west_root: Path, module_path: Path) -> List[str]:
    candidates: List[List[str]] = []

    if explicit:
        candidates.append(shlex.split(explicit))

    path_west = shutil.which("west")
    if path_west:
        candidates.append([path_west])

    for candidate in (
        west_root / ".venv/bin/west",
        module_path / ".venv/bin/west",
    ):
        if candidate.exists():
            candidates.append([str(candidate)])

    candidates.append([sys.executable, "-m", "west"])

    seen = set()
    for command in candidates:
        key = tuple(command)
        if key in seen:
            continue
        seen.add(key)
        try:
            result = subprocess.run(
                command + ["--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
                check=False,
            )
        except OSError:
            continue

        if result.returncode == 0:
            return command

    raise RuntimeError("Unable to find a working west command")


def build_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in HOST_ENV_BLACKLIST:
        env.pop(key, None)
    return env


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
            failure.text = result.output
        system_out = ET.SubElement(testcase, "system-out")
        system_out.text = result.output

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
    try:
        result = subprocess.run(
            step.cmd,
            cwd=str(step.cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=step.timeout,
            check=False,
        )
        stdout = result.stdout or ""
        returncode = result.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
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
    env = build_env()
    ztest_build_dir = output_root / "ztest_acvp_serial_qemu"
    nucleo_protocol_default_dir = output_root / "nucleo_protocol_default"
    nucleo_protocol_single_level_dir = output_root / "nucleo_protocol_single_level"
    profile_output_dir = output_root / "profile_validation"
    junit_output = output_root / "release_check_results.xml"

    steps = [
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
            name="MCU protocol CMake-only (nucleo_h743zi ML-KEM-768 + ML-DSA-65)",
            cmd=[
                *west_cmd,
                "build",
                "-p",
                "always",
                "-b",
                "nucleo_h743zi",
                str(module_path / "samples/pqcp_bench_protocol"),
                "-d",
                str(nucleo_protocol_default_dir),
                "--cmake-only",
                "--",
                "-DOVERLAY_CONFIG=overlay-rtos-metrics.conf",
            ],
            cwd=west_root,
        ),
        Step(
            name="MCU protocol CMake-only (nucleo_h743zi ML-KEM-512 + ML-DSA-87)",
            cmd=[
                *west_cmd,
                "build",
                "-p",
                "always",
                "-b",
                "nucleo_h743zi",
                str(module_path / "samples/pqcp_bench_protocol"),
                "-d",
                str(nucleo_protocol_single_level_dir),
                "--cmake-only",
                "--",
                "-DOVERLAY_CONFIG=overlay-rtos-metrics.conf",
                "-DCONFIG_PQCP_MLKEM_LEVEL_512=y",
                "-DCONFIG_PQCP_MLKEM_LEVEL_768=n",
                "-DCONFIG_PQCP_MLKEM_LEVEL_1024=n",
                "-DCONFIG_PQCP_MLDSA_LEVEL_44=n",
                "-DCONFIG_PQCP_MLDSA_LEVEL_65=n",
                "-DCONFIG_PQCP_MLDSA_LEVEL_87=y",
                "-DCONFIG_MAIN_STACK_SIZE=196608",
            ],
            cwd=west_root,
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
    ]

    print("PQCP Release Check")
    print(f"  west root : {west_root}")
    print(f"  module    : {module_path}")
    print(f"  west cmd  : {' '.join(west_cmd)}")
    print(f"  output    : {output_root}")

    results: List[StepResult] = []
    for step in steps:
        result = run_step(step, env, args.verbose)
        results.append(result)
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
