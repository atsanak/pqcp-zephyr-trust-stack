#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the local product-readiness verification sequence."""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

HOST_ENV_BLACKLIST = (
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "CPATH",
    "SDKROOT",
)

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent


@dataclass
class Step:
    name: str
    cmd: list[str]
    cwd: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Sequence existing PQCP verification tools for local "
            "product-readiness checks. This wrapper orchestrates; it does not "
            "replace release_check.py or reimplement its checks."
        )
    )
    parser.add_argument(
        "--module-path",
        type=Path,
        default=REPO_ROOT,
        help="PQCP module repository root.",
    )
    parser.add_argument(
        "--west-root",
        type=Path,
        help="Zephyr west workspace root passed through to underlying helpers.",
    )
    parser.add_argument(
        "--tag",
        default="v1.0.0",
        help="Release tag/version to validate where helpers accept a tag.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("benchmark_results/product_readiness"),
        help="Output root for generated validation artifacts.",
    )
    parser.add_argument(
        "--skip-cost-smoke",
        action="store_true",
        help="Skip the explicit cost-of-assurance smoke step.",
    )
    parser.add_argument(
        "--skip-consumer-smoke",
        action="store_true",
        help="Skip the west consumer smoke helper.",
    )
    parser.add_argument(
        "--skip-release-bundle",
        action="store_true",
        help="Skip local release bundle generation.",
    )
    parser.add_argument(
        "--skip-release-check",
        action="store_true",
        help="Skip the full release_check.py gate.",
    )
    return parser.parse_args()


def build_env() -> dict[str, str]:
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
    return start.resolve()


def run_step(step: Step, env: dict[str, str]) -> None:
    print(f"\n[RUN ] {step.name}")
    print("       " + " ".join(shlex.quote(part) for part in step.cmd))
    result = subprocess.run(step.cmd, cwd=str(step.cwd), env=env, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{step.name} failed with exit {result.returncode}")
    print(f"[PASS] {step.name}")


def build_steps(args: argparse.Namespace) -> list[Step]:
    module_path = args.module_path.resolve()
    west_root = args.west_root.resolve() if args.west_root else detect_west_root(module_path)
    output_root = args.output_root
    if not output_root.is_absolute():
        output_root = module_path / output_root

    script_paths = sorted(str(path) for path in (module_path / "scripts").glob("*.py"))
    steps = [
        Step(
            "python scripts compile",
            [sys.executable, "-m", "py_compile", *script_paths],
            module_path,
        ),
        Step(
            "version and changelog consistency",
            [
                sys.executable,
                str(module_path / "scripts/check_version_consistency.py"),
                "--module-path",
                str(module_path),
                "--changelog",
                str(module_path / "CHANGELOG.md"),
                "--tag",
                args.tag,
            ],
            module_path,
        ),
        Step(
            "strict extended checks",
            [
                sys.executable,
                str(module_path / "scripts/run_extended_checks.py"),
                "--west-root",
                str(west_root),
                "--module-path",
                str(module_path),
                "--strict",
            ],
            module_path,
        ),
    ]

    if not args.skip_cost_smoke:
        steps.append(
            Step(
                "strict cost-of-assurance smoke",
                [
                    sys.executable,
                    str(module_path / "scripts/run_extended_checks.py"),
                    "--west-root",
                    str(west_root),
                    "--module-path",
                    str(module_path),
                    "--strict",
                    "--run-cost-of-assurance-smoke",
                ],
                module_path,
            )
        )

    if not args.skip_consumer_smoke:
        steps.append(
            Step(
                "consumer smoke",
                [
                    sys.executable,
                    str(module_path / "scripts/consumer_smoke.py"),
                    "--module-path",
                    str(module_path),
                    "--west-root",
                    str(west_root),
                    "--build-dir",
                    str(output_root / "consumer_smoke"),
                ],
                module_path,
            )
        )

    if not args.skip_release_bundle:
        steps.append(
            Step(
                "local release bundle",
                [
                    sys.executable,
                    str(module_path / "scripts/prepare_release_bundle.py"),
                    "--module-path",
                    str(module_path),
                    "--tag",
                    args.tag,
                    "--output-dir",
                    str(output_root / "release_bundle"),
                ],
                module_path,
            )
        )

    if not args.skip_release_check:
        steps.append(
            Step(
                "full release gate",
                [
                    sys.executable,
                    str(module_path / "scripts/release_check.py"),
                    "--west-root",
                    str(west_root),
                    "--module-path",
                    str(module_path),
                    "--tag",
                    args.tag,
                    "--output-root",
                    str(output_root / "release_check"),
                ],
                module_path,
            )
        )

    return steps


def main() -> int:
    args = parse_args()
    env = build_env()
    steps = build_steps(args)

    print("PQCP product-readiness verification")
    print(f"  module: {args.module_path.resolve()}")
    print(f"  tag   : {args.tag}")

    for step in steps:
        run_step(step, env)

    print("\n[PASS] product-readiness verification completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
