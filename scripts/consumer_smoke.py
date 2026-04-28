#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the smallest west-based consumer smoke check for this module."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from local_workflow import (  # noqa: E402
    clean_env,
    detect_west_root,
    discover_west,
    is_west_manifest_project,
    run_command,
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
        "--module-mode",
        choices=("auto", "manifest", "extra-module"),
        default="auto",
        help=(
            "How to make the module visible to Zephyr. 'manifest' requires "
            "west/module.yml discovery through the active west manifest; "
            "'extra-module' injects -DZEPHYR_EXTRA_MODULES for in-tree "
            "development; 'auto' prefers manifest discovery and falls back to "
            "extra-module with an explicit note."
        ),
    )
    parser.add_argument(
        "--run-timeout",
        type=int,
        default=120,
        help="Seconds to wait for west build -t run before accepting success markers.",
    )
    return parser.parse_args()


def resolve_module_mode(
    requested: str,
    west_cmd: list[str],
    west_root: Path,
    module_path: Path,
    env: dict[str, str],
) -> str:
    """Resolve auto/manifest/extra-module into the mode used for this build."""
    declared = is_west_manifest_project(west_cmd, west_root, module_path, env)
    if requested == "manifest":
        if not declared:
            raise RuntimeError(
                f"{module_path} is not declared by the active west manifest at "
                f"{west_root}; rerun from a clean west init workspace or use "
                "--module-mode extra-module for local development checkouts"
            )
        return "manifest"
    if requested == "extra-module":
        return "extra-module"
    if declared:
        return "manifest"
    print(
        "[INFO] module is not declared in the active west manifest; "
        "falling back to -DZEPHYR_EXTRA_MODULES for this development checkout"
    )
    return "extra-module"


def west_build_command(
    west_cmd: list[str],
    *,
    board: str,
    target: Path,
    build_dir: Path,
    module_path: Path,
    module_mode: str,
) -> list[str]:
    """Build the west command for the selected module visibility mode."""
    cmd = [
        *west_cmd,
        "build",
        "-p",
        "always",
        "-b",
        board,
        str(target),
        "-d",
        str(build_dir),
    ]
    if module_mode == "extra-module":
        cmd.extend(["--", f"-DZEPHYR_EXTRA_MODULES={module_path}"])
    return cmd


def main() -> int:
    args = parse_args()
    module_path = args.module_path.resolve()
    west_root = args.west_root.resolve() if args.west_root else detect_west_root(module_path)
    target = (module_path / args.target).resolve()
    build_dir = args.build_dir if args.build_dir.is_absolute() else module_path / args.build_dir
    west_cmd = discover_west(args.west, west_root, module_path)
    env = clean_env()
    module_mode = resolve_module_mode(args.module_mode, west_cmd, west_root, module_path, env)

    if not target.exists():
        raise RuntimeError(f"target path does not exist: {target}")

    print("PQCP consumer smoke")
    print(f"  west root : {west_root}")
    print(f"  module    : {module_path}")
    print(f"  target    : {target}")
    print(f"  board     : {args.board}")
    print(f"  build dir : {build_dir}")
    print(f"  mode      : {module_mode}")

    run_command(
        west_build_command(
            west_cmd,
            board=args.board,
            target=target,
            build_dir=build_dir,
            module_path=module_path,
            module_mode=module_mode,
        ),
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
