#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Run focused sanitizer builds for the highest-risk PQCP harnesses.

This helper is intentionally separate from the fast CI and static-analysis
paths so maintainers can run ASan/UBSan checks on demand without changing the
default qemu_x86_64 smoke workflow.
"""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from local_workflow import (  # noqa: E402
    HOST_ENV_BLACKLIST,
    clean_env,
    detect_west_root as _shared_detect_west_root,
    discover_west as _shared_discover_west,
)


@dataclass(frozen=True)
class SanitizerCase:
    name: str
    app_path: str
    overlay: str
    run: bool
    run_timeout_s: int = 300


# Cases exercised under ASan/UBSan on native_sim/native/64.
#
# The default sanitizer set exercises command parsing, primitive driver glue,
# the TLS self-test harness, and the protocol benchmark at runtime. The TLS
# ztest uses deterministic Zephyr test entropy in its sanitizer overlay and
# avoids sanitizer-host-specific printk hook assertions, so ASan/UBSan still
# execute the full handshake path without relying on fragile stdout capture.
DEFAULT_CASES = [
    SanitizerCase(
        name="ztest_acvp_serial",
        app_path="tests/ztest_acvp_serial",
        overlay="overlay-sanitize.conf",
        run=True,
    ),
    SanitizerCase(
        name="ztest_primitive",
        app_path="tests/ztest_primitive",
        overlay="overlay-sanitize.conf",
        run=True,
    ),
    SanitizerCase(
        name="ztest_tls_selftest",
        app_path="tests/ztest_tls_selftest",
        overlay="overlay-sanitize.conf",
        run=True,
    ),
    SanitizerCase(
        name="pqcp_bench_protocol",
        app_path="samples/pqcp_bench_protocol",
        overlay="overlay-sanitize.conf",
        # Build-only by default. The native_sim ASan + mbedTLS TLS-handshake
        # path hangs past the per-case 120s wall-clock budget on the GitHub
        # hosted runner; root-causing the hang is tracked separately in
        # PROJECT_NOTES.md. Build-only keeps the sanitizer build path covered, and
        # the runtime ASan/UBSan TLS path is now exercised by
        # tests/ztest_tls_selftest after the timer-source fix landed in
        # src/tls_selftest.c (commit 011c937).
        run=False,
    ),
]

# Opt-in via --case to exercise the protocol benchmark at runtime once the
# native_sim ASan hang is root-caused.
OPT_IN_CASES: list[SanitizerCase] = [
    SanitizerCase(
        name="pqcp_bench_protocol_run",
        app_path="samples/pqcp_bench_protocol",
        overlay="overlay-sanitize.conf",
        run=True,
        run_timeout_s=300,
    ),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run focused PQCP ASan/UBSan builds on native_sim/native/64"
    )
    parser.add_argument("--west-root", type=Path, help="Zephyr workspace root")
    parser.add_argument("--module-path", type=Path, help="PQCP module path")
    parser.add_argument("--west", help="Explicit west binary or command")
    parser.add_argument(
        "--board",
        default="native_sim/native/64",
        help="Board used for sanitizer builds",
    )
    parser.add_argument(
        "--build-dir-root",
        type=Path,
        default=Path("benchmark_results/sanitizers/build"),
        help="Directory that stores per-target sanitizer builds",
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=Path("benchmark_results/sanitizers/logs"),
        help="Directory that stores build/run logs",
    )
    parser.add_argument(
        "--build-only",
        action="store_true",
        help="Configure and compile the sanitizer targets without running them",
    )
    parser.add_argument(
        "--case",
        action="append",
        dest="cases",
        help="Optional target name filter (for example: ztest_acvp_serial)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose command logging")
    return parser.parse_args()


def detect_west_root(start: Path) -> Path:
    return _shared_detect_west_root(start, strict=False)


def discover_west(explicit: Optional[str], west_root: Path, module_path: Path) -> List[str]:
    return _shared_discover_west(explicit, west_root, module_path)


def build_env() -> dict[str, str]:
    return clean_env()


def required_success_markers(case: SanitizerCase) -> List[str]:
    markers = ["PROJECT EXECUTION SUCCESSFUL"]
    if case.name == "pqcp_bench_protocol":
        markers.append("PQCP_METRIC,protocol,handshake")
    return markers


def run_command(
    cmd: List[str],
    *,
    cwd: Path,
    env: dict[str, str],
    verbose: bool,
    timeout: Optional[int] = None,
) -> subprocess.CompletedProcess[str]:
    # Runs a subprocess, collects stdout + stderr, and optionally enforces
    # a wall-clock timeout. On timeout we kill the process tree and return
    # a CompletedProcess with a non-zero returncode plus a clear marker in
    # the captured output. This is deliberately preferred over
    # subprocess.run(..., timeout=...) raising TimeoutExpired: the caller
    # treats the result uniformly and we avoid losing whatever stdout had
    # been produced before the hang — critical for diagnosing which
    # sanitizer case is wedged on CI.
    if verbose:
        print(" ".join(cmd))

    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        stdout, _ = proc.communicate(timeout=timeout)
        returncode = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            stdout_tail, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout_tail = ""
        stdout = (
            (stdout_tail or "")
            + f"\n[run_sanitizer_checks] Killed after {timeout}s wall-clock timeout.\n"
        )
        returncode = 124

    return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=None)


def select_cases(names: Optional[List[str]]) -> List[SanitizerCase]:
    if not names:
        return list(DEFAULT_CASES)

    available = {case.name: case for case in DEFAULT_CASES + OPT_IN_CASES}
    wanted = list(dict.fromkeys(names))
    selected = [available[name] for name in wanted if name in available]
    missing = [name for name in wanted if name not in available]
    if missing:
        raise ValueError(f"Unknown sanitizer case(s): {', '.join(missing)}")
    return selected


def main() -> int:
    args = parse_args()
    module_path = args.module_path.resolve() if args.module_path else Path(__file__).resolve().parent.parent
    west_root = args.west_root.resolve() if args.west_root else detect_west_root(Path.cwd())
    build_dir_root = args.build_dir_root.resolve()
    log_dir = args.log_dir.resolve()

    if args.board.startswith("native_") and sys.platform != "linux":
        print(
            "Sanitizer checks for "
            f"{args.board} require a Linux host because Zephyr's POSIX/native "
            "architecture does not run on macOS or Windows."
        )
        print(
            "Run this helper on Linux (or in GitHub Actions), or pass a different "
            "board only if that target is known to support ASan/UBSan."
        )
        ci_env = any(
            os.environ.get(var) for var in ("CI", "GITHUB_ACTIONS", "PQCP_STRICT_SANITIZERS")
        )
        if ci_env:
            print(
                "CI environment detected: refusing to silently skip sanitizer checks. "
                "Exiting with failure so the gate surfaces the unsupported host."
            )
            return 2
        print(
            "Non-CI host: skipping sanitizer execution. Set PQCP_STRICT_SANITIZERS=1 "
            "to force strict behavior locally."
        )
        return 0

    env = build_env()
    west_cmd = discover_west(args.west, west_root, module_path)
    cases = select_cases(args.cases)

    build_dir_root.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    print("PQCP Sanitizer Checks")
    print(f"  west root : {west_root}")
    print(f"  module    : {module_path}")
    print(f"  west cmd  : {' '.join(west_cmd)}")
    print(f"  board     : {args.board}")
    print(f"  build dir : {build_dir_root}")
    print(f"  log dir   : {log_dir}")
    print("  cases     :")
    for case in cases:
        mode = "build+run" if case.run and not args.build_only else "build-only"
        print(f"    - {case.name} ({mode})")

    for case in cases:
        build_dir = build_dir_root / case.name
        build_log = log_dir / f"{case.name}.build.log"
        run_log = log_dir / f"{case.name}.run.log"
        overlay_path = module_path / case.app_path / case.overlay

        build_cmd = [
            *west_cmd,
            "build",
            "-p",
            "always",
            "-d",
            str(build_dir),
            "-b",
            args.board,
            str(module_path / case.app_path),
            "--",
            f"-DZEPHYR_EXTRA_MODULES={module_path}",
            f"-DOVERLAY_CONFIG={overlay_path.name}",
        ]

        # Per-phase wall-clock budgets. These are intentionally generous
        # vs. local runtimes (a Linux GHA runner is ~1.5x slower than a
        # modern workstation) but tight enough that the outer
        # release_check.py 1200s budget for the whole sanitizer step is
        # still honoured for 3 default cases (3 * (build + run) well
        # under 1200s). If any single phase blows its budget, we surface
        # the case name rather than letting the outer timeout kill us
        # silently with no attribution.
        build_timeout = 300
        run_timeout = case.run_timeout_s

        print(f"\n[{case.name}] Building with ASan/UBSan", flush=True)
        build_result = run_command(
            build_cmd,
            cwd=west_root,
            env=env,
            verbose=args.verbose,
            timeout=build_timeout,
        )
        build_log.write_text(build_result.stdout)
        if build_result.returncode != 0:
            print(build_result.stdout)
            print(
                f"[{case.name}] Build failed (exit {build_result.returncode}); "
                f"full log: {build_log}",
                flush=True,
            )
            return build_result.returncode or 1
        print(f"[{case.name}] Build OK ({build_log})", flush=True)

        if args.build_only or not case.run:
            continue

        run_cmd = [*west_cmd, "build", "-d", str(build_dir), "-t", "run"]
        print(f"[{case.name}] Running sanitizer image", flush=True)
        run_result = run_command(
            run_cmd,
            cwd=west_root,
            env=env,
            verbose=args.verbose,
            timeout=run_timeout,
        )
        run_log.write_text(run_result.stdout)
        if run_result.returncode != 0:
            print(run_result.stdout)
            print(
                f"[{case.name}] Run failed (exit {run_result.returncode}); "
                f"full log: {run_log}",
                flush=True,
            )
            return run_result.returncode or 1

        missing_markers = [
            marker for marker in required_success_markers(case)
            if marker not in run_result.stdout
        ]
        if missing_markers:
            print(run_result.stdout)
            print(
                f"[{case.name}] Missing success marker(s): "
                f"{', '.join(missing_markers)}; full log: {run_log}",
                flush=True,
            )
            return 1

        print(f"[{case.name}] Run OK ({run_log})", flush=True)

    print("\nSanitizer checks completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
