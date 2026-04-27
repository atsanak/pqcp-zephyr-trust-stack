#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the smallest west-based consumer smoke check for this module."""

from __future__ import annotations

import argparse
import os
import signal
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

HOST_ENV_BLACKLIST = (
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "CPATH",
    "SDKROOT",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build and optionally run a minimal PQCP target from a west "
            "workspace, using this checkout as a Zephyr module."
        )
    )
    parser.add_argument(
        "--module-path",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Path to the pqcp-zephyr-trust-stack checkout.",
    )
    parser.add_argument(
        "--west-root",
        type=Path,
        help="Zephyr west workspace root. Auto-detected by walking upward.",
    )
    parser.add_argument(
        "--west",
        help="Explicit west command, for example '/path/to/.venv/bin/west'.",
    )
    parser.add_argument(
        "--board",
        default="qemu_x86_64",
        help="Board to build for.",
    )
    parser.add_argument(
        "--target",
        default="tests/ztest_rng",
        help="Module-relative target to build.",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=Path("build-consumer-smoke"),
        help="Build directory, relative to the module path unless absolute.",
    )
    parser.add_argument(
        "--build-only",
        action="store_true",
        help="Only build the target; do not run west build -t run.",
    )
    parser.add_argument(
        "--run-timeout",
        type=int,
        default=120,
        help="Seconds to wait for west build -t run before accepting success markers.",
    )
    return parser.parse_args()


def clean_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in HOST_ENV_BLACKLIST:
        env.pop(key, None)
    return env


def detect_west_root(start: Path) -> Path:
    current = start.resolve()
    while current != current.parent:
        if (current / ".west").exists():
            return current
        current = current.parent
    raise RuntimeError(
        "unable to find a west workspace root; pass --west-root explicitly"
    )


def discover_west(explicit: str | None, west_root: Path, module_path: Path) -> list[str]:
    candidates: list[list[str]] = []
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

    seen: set[tuple[str, ...]] = set()
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
    raise RuntimeError("unable to find a working west command")


def run_command(
    cmd: list[str],
    cwd: Path,
    env: dict[str, str],
    *,
    timeout: int | None = None,
    success_markers: tuple[str, ...] = (),
) -> str:
    print("+ " + " ".join(shlex.quote(part) for part in cmd))
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, _ = proc.communicate(timeout=timeout)
        returncode = proc.returncode
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, _ = proc.communicate()
        returncode = 124

    stdout = stdout or ""
    if stdout:
        print(stdout, end="" if stdout.endswith("\n") else "\n")
    if returncode == 124 and success_markers and all(marker in stdout for marker in success_markers):
        print("[PASS] command reached timeout after printing expected success markers")
        return stdout
    if returncode != 0:
        raise RuntimeError(f"command failed with exit {returncode}")
    return stdout


def main() -> int:
    args = parse_args()
    module_path = args.module_path.resolve()
    west_root = args.west_root.resolve() if args.west_root else detect_west_root(module_path)
    target = (module_path / args.target).resolve()
    build_dir = args.build_dir if args.build_dir.is_absolute() else module_path / args.build_dir
    west_cmd = discover_west(args.west, west_root, module_path)
    env = clean_env()

    if not target.exists():
        raise RuntimeError(f"target path does not exist: {target}")

    print("PQCP consumer smoke")
    print(f"  west root : {west_root}")
    print(f"  module    : {module_path}")
    print(f"  target    : {target}")
    print(f"  board     : {args.board}")
    print(f"  build dir : {build_dir}")

    run_command(
        [
            *west_cmd,
            "build",
            "-p",
            "always",
            "-b",
            args.board,
            str(target),
            "-d",
            str(build_dir),
            "--",
            f"-DZEPHYR_EXTRA_MODULES={module_path}",
        ],
        cwd=west_root,
        env=env,
    )

    if not args.build_only:
        output = run_command(
            [*west_cmd, "build", "-d", str(build_dir), "-t", "run"],
            cwd=west_root,
            env=env,
            timeout=args.run_timeout,
            success_markers=("PROJECT EXECUTION SUCCESSFUL",),
        )
        if "PROJECT EXECUTION SUCCESSFUL" not in output:
            raise RuntimeError("target ran but did not print PROJECT EXECUTION SUCCESSFUL")

    print("[PASS] consumer smoke completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
