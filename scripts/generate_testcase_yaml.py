#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Keep every ztest suite registered with twister.

Twister silently skips any directory that has no testcase.yaml, so a suite
without one compiles and runs nowhere in CI. This tool generates the
missing files from one deterministic template and, with --check, fails if
any tests/ztest_* suite is unregistered, so a new suite cannot be added
without joining the CI sweep.

Existing testcase.yaml files are never overwritten.
"""

import argparse
import sys
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = MODULE_ROOT / "tests"

HEADER = "# SPDX-License-Identifier: MIT\n"

# Suites that enable ML-KEM/ML-DSA run keygen/sign paths and need headroom
# on the emulated target.
CRYPTO_CONFIGS = ("CONFIG_PQCP_MLDSA=y", "CONFIG_PQCP_MLKEM=y")
DEFAULT_TIMEOUT = 120
CRYPTO_TIMEOUT = 300


def suites() -> list[Path]:
    return sorted(
        d for d in TESTS_DIR.iterdir()
        if d.is_dir() and d.name.startswith("ztest_")
        and (d / "CMakeLists.txt").exists())


def render(suite: Path) -> str:
    name = suite.name.removeprefix("ztest_")
    family = name.split("_")[0]
    prj = (suite / "prj.conf")
    conf = prj.read_text(encoding="utf-8") if prj.exists() else ""
    crypto = any(item in conf for item in CRYPTO_CONFIGS)
    tags = ["pqcp", family]
    if family == "deployment" or family == "evidence":
        tags.append("evidence")
    if crypto:
        tags.append("crypto")
    lines = [
        HEADER,
        "tests:\n",
        f"  pqcp.{name}:\n",
        "    tags:\n",
    ]
    lines.extend(f"      - {tag}\n" for tag in tags)
    lines.extend([
        "    harness: ztest\n",
        "    platform_allow:\n",
        "      - qemu_x86_64\n",
        "    integration_platforms:\n",
        "      - qemu_x86_64\n",
        f"    timeout: {CRYPTO_TIMEOUT if crypto else DEFAULT_TIMEOUT}\n",
    ])
    return "".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true",
                        help="fail if any suite lacks a testcase.yaml")
    args = parser.parse_args()

    missing = [s for s in suites() if not (s / "testcase.yaml").exists()]

    if args.check:
        for suite in missing:
            print(f"[testcase] MISSING tests/{suite.name}/testcase.yaml "
                  "(twister would skip this suite)")
        if missing:
            print(f"[testcase] FAIL: {len(missing)} suite(s) unregistered; "
                  "run scripts/generate_testcase_yaml.py")
            return 1
        print(f"PQCP_TESTCASE_REGISTRY PASS suites={len(suites())} missing=0")
        print("[testcase] PASS: every ztest suite is registered with twister")
        return 0

    for suite in missing:
        (suite / "testcase.yaml").write_text(render(suite), encoding="utf-8")
    print(f"[testcase] generated {len(missing)} testcase.yaml file(s); "
          f"{len(suites()) - len(missing)} already existed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
