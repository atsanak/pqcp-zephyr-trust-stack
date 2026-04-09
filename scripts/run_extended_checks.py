#!/usr/bin/env python3
"""
Developer-oriented extended checks for the PQCP Zephyr module.

This helper keeps heavier static-analysis style checks out of the fast smoke CI
while making them easy to run locally or from a scheduled/manual workflow.
"""

from __future__ import annotations

import argparse
from collections import Counter
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Optional

HOST_ENV_BLACKLIST = (
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "CPATH",
    "SDKROOT",
)

DEFAULT_ANALYSIS_PATHS = [
    "include/pqcp_zephyr/acvp_cmd.h",
    "include/pqcp_zephyr/bench.h",
    "include/pqcp_zephyr/tls_selftest.h",
    "src/acvp_cmd.c",
    "src/bench_primitive.c",
    "src/bench_protocol.c",
    "src/mlkem_zephyr.c",
    "src/mldsa_zephyr.c",
    "src/rng_common.c",
    "src/rng_psa.c",
    "src/rng_zephyr_entropy.c",
    "src/tls_selftest.c",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run extended PQCP developer checks")
    parser.add_argument("--west-root", type=Path, help="Zephyr workspace root")
    parser.add_argument("--module-path", type=Path, help="PQCP module path")
    parser.add_argument("--west", help="Explicit west binary or command")
    parser.add_argument("--board", default="qemu_x86_64", help="Board for graph/config checks")
    parser.add_argument(
        "--target",
        default="tests/ztest_primitive",
        help="Target application used to configure a graphviz-ready build",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=Path("build-extended-checks"),
        help="Build directory for the graphviz/configure stage",
    )
    parser.add_argument(
        "--graphviz-out",
        type=Path,
        default=Path("benchmark_results/extended/pqcp-cmake-graph.dot"),
        help="Path for the generated CMake graphviz output",
    )
    parser.add_argument("--cppcheck", help="Explicit cppcheck binary")
    parser.add_argument("--skip-graphviz", action="store_true", help="Skip graphviz generation")
    parser.add_argument("--skip-cppcheck", action="store_true", help="Skip cppcheck analysis")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if an optional tool is unavailable instead of skipping it",
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


def find_tool(explicit: Optional[str], name: str) -> Optional[List[str]]:
    if explicit:
        return shlex.split(explicit)

    path = shutil.which(name)
    if path:
        return [path]

    return None


def configure_graphviz_build(
    *,
    west_cmd: List[str],
    west_root: Path,
    module_path: Path,
    board: str,
    target: str,
    build_dir: Path,
    env: dict[str, str],
    verbose: bool,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        *west_cmd,
        "build",
        "-p",
        "always",
        "-d",
        str(build_dir),
        "-b",
        board,
        str(module_path / target),
        "--",
        f"-DZEPHYR_EXTRA_MODULES={module_path}",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
    ]
    return run_command(cmd, cwd=west_root, env=env, verbose=verbose)


def run_graphviz(
    *,
    build_dir: Path,
    output_path: Path,
    env: dict[str, str],
    verbose: bool,
) -> subprocess.CompletedProcess[str]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["cmake", f"--graphviz={output_path}", str(build_dir)]
    return run_command(cmd, cwd=build_dir.parent, env=env, verbose=verbose)


def run_cppcheck(
    *,
    cppcheck_cmd: List[str],
    module_path: Path,
    env: dict[str, str],
    verbose: bool,
    targets: Iterable[str],
) -> subprocess.CompletedProcess[str]:
    cmd = [
        *cppcheck_cmd,
        "--quiet",
        "--enable=warning,style,performance,portability",
        "--error-exitcode=2",
        "--inline-suppr",
        "--suppress=missingIncludeSystem",
        "--template={severity}:{id}:{file}:{line}:{message}",
        f"-I{module_path / 'include'}",
        *[str(module_path / target) for target in targets],
    ]
    return run_command(cmd, cwd=module_path, env=env, verbose=verbose)


def summarize_cppcheck(output: str) -> Counter[str]:
    counts: Counter[str] = Counter()

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        parts = line.split(":", 4)
        if len(parts) != 5:
            continue

        severity = parts[0].strip()
        if severity:
            counts[severity] += 1

    return counts


def format_counter_summary(counts: Counter[str]) -> str:
    if not counts:
        return "no findings"

    order = ("error", "warning", "style", "performance", "portability", "information")
    items = [f"{severity}={counts[severity]}" for severity in order if counts[severity]]
    for severity in sorted(counts):
        if severity not in order:
            items.append(f"{severity}={counts[severity]}")
    return ", ".join(items)


def main() -> int:
    args = parse_args()
    module_path = args.module_path.resolve() if args.module_path else Path(__file__).resolve().parent.parent
    west_root = args.west_root.resolve() if args.west_root else detect_west_root(Path.cwd())
    build_dir = args.build_dir.resolve()
    graphviz_out = args.graphviz_out.resolve()
    env = build_env()

    west_cmd = discover_west(args.west, west_root, module_path)

    print("PQCP Extended Checks")
    print(f"  west root : {west_root}")
    print(f"  module    : {module_path}")
    print(f"  west cmd  : {' '.join(west_cmd)}")

    if not args.skip_graphviz:
        print(f"\n[graphviz] Configuring {args.target} for {args.board}")
        print(f"[graphviz] Build directory: {build_dir}")
        print(f"[graphviz] Output path:     {graphviz_out}")
        build_result = configure_graphviz_build(
            west_cmd=west_cmd,
            west_root=west_root,
            module_path=module_path,
            board=args.board,
            target=args.target,
            build_dir=build_dir,
            env=env,
            verbose=args.verbose,
        )
        if build_result.returncode != 0:
            print(build_result.stdout)
            return build_result.returncode

        graph_result = run_graphviz(
            build_dir=build_dir,
            output_path=graphviz_out,
            env=env,
            verbose=args.verbose,
        )
        if graph_result.returncode != 0:
            print(graph_result.stdout)
            return graph_result.returncode

        print(f"[graphviz] Wrote {graphviz_out}")

    if not args.skip_cppcheck:
        cppcheck_cmd = find_tool(args.cppcheck, "cppcheck")
        if cppcheck_cmd is None:
            message = "cppcheck not found"
            if args.strict:
                print(message)
                return 1
            print(f"[cppcheck] {message}; skipping")
        else:
            analysis_paths = [module_path / target for target in DEFAULT_ANALYSIS_PATHS]
            print("\n[cppcheck] Checking focused PQCP sources")
            print("[cppcheck] Analysed paths:")
            for path in analysis_paths:
                print(f"  - {path.relative_to(module_path)}")
            cppcheck_result = run_cppcheck(
                cppcheck_cmd=cppcheck_cmd,
                module_path=module_path,
                env=env,
                verbose=args.verbose,
                targets=DEFAULT_ANALYSIS_PATHS,
            )
            cppcheck_summary = format_counter_summary(
                summarize_cppcheck(cppcheck_result.stdout)
            )
            if cppcheck_result.returncode != 0:
                print(f"[cppcheck] Findings summary: {cppcheck_summary}")
                print(cppcheck_result.stdout)
                return cppcheck_result.returncode
            if cppcheck_result.stdout.strip():
                print(f"[cppcheck] Findings summary: {cppcheck_summary}")
                print(cppcheck_result.stdout)
            else:
                print("[cppcheck] Findings summary: no findings")
            print("[cppcheck] Completed without findings")

    print("\nExtended checks completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
