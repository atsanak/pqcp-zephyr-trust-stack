#!/usr/bin/env python3
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

HOST_ENV_BLACKLIST = (
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "CPATH",
    "SDKROOT",
)


@dataclass(frozen=True)
class SanitizerCase:
    name: str
    app_path: str
    overlay: str
    run: bool


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
        run=True,
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

    raise RuntimeError("Unable to find a working west command.")


def build_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in HOST_ENV_BLACKLIST:
        env.pop(key, None)
    return env


def run_command(
    cmd: List[str],
    *,
    cwd: Path,
    env: dict[str, str],
    verbose: bool,
) -> subprocess.CompletedProcess[str]:
    if verbose:
        print(" ".join(cmd))

    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )


def select_cases(names: Optional[List[str]]) -> List[SanitizerCase]:
    if not names:
        return list(DEFAULT_CASES)

    wanted = set(names)
    selected = [case for case in DEFAULT_CASES if case.name in wanted]
    missing = sorted(wanted - {case.name for case in selected})
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

        print(f"\n[{case.name}] Building with ASan/UBSan")
        build_result = run_command(
            build_cmd,
            cwd=west_root,
            env=env,
            verbose=args.verbose,
        )
        build_log.write_text(build_result.stdout)
        if build_result.returncode != 0:
            print(build_result.stdout)
            print(f"[{case.name}] Build failed; full log: {build_log}")
            return build_result.returncode
        print(f"[{case.name}] Build OK ({build_log})")

        if args.build_only or not case.run:
            continue

        run_cmd = [*west_cmd, "build", "-d", str(build_dir), "-t", "run"]
        print(f"[{case.name}] Running sanitizer image")
        run_result = run_command(
            run_cmd,
            cwd=west_root,
            env=env,
            verbose=args.verbose,
        )
        run_log.write_text(run_result.stdout)
        if run_result.returncode != 0:
            print(run_result.stdout)
            print(f"[{case.name}] Run failed; full log: {run_log}")
            return run_result.returncode

        if "PROJECT EXECUTION SUCCESSFUL" not in run_result.stdout:
            print(run_result.stdout)
            print(f"[{case.name}] Missing success marker; full log: {run_log}")
            return 1

        print(f"[{case.name}] Run OK ({run_log})")

    print("\nSanitizer checks completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
