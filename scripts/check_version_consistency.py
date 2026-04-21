#!/usr/bin/env python3
"""
Validate version consistency across version.h, CMakeLists.txt, and an optional git tag.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

HEADER_VERSION_RE = re.compile(
    r'^#define\s+PQCP_VERSION_STRING\s+"([^"]+)"$',
    re.MULTILINE,
)
CMAKE_VERSION_RE = re.compile(
    r'^\s*set\s*\(\s*PQCP_PROJECT_VERSION\s+"([^"]+)"\s*\)\s*$',
    re.MULTILINE,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check version consistency for the PQCP Zephyr module."
    )
    parser.add_argument(
        "--module-path",
        type=Path,
        default=REPO_ROOT,
        help="PQCP module repository root",
    )
    parser.add_argument(
        "--tag",
        help="Optional git tag/version string to validate (for example: v1.0.0)",
    )
    return parser.parse_args()


def parse_header_version(module_path: Path) -> str:
    text = (module_path / "include/pqcp_zephyr/version.h").read_text(encoding="utf-8")
    match = HEADER_VERSION_RE.search(text)
    if match is None:
        raise RuntimeError("Unable to parse PQCP_VERSION_STRING from version.h")
    return match.group(1)


def parse_cmake_version(module_path: Path) -> str:
    text = (module_path / "CMakeLists.txt").read_text(encoding="utf-8")
    match = CMAKE_VERSION_RE.search(text)
    if match is None:
        raise RuntimeError("Unable to parse PQCP_PROJECT_VERSION from CMakeLists.txt")
    return match.group(1)


def normalize_tag(tag: str) -> str:
    normalized = tag.strip()
    if normalized.startswith("refs/tags/"):
        normalized = normalized.split("/", 2)[-1]
    if normalized.startswith("v"):
        normalized = normalized[1:]
    return normalized


def main() -> int:
    args = parse_args()
    module_path = args.module_path.resolve()

    header_version = parse_header_version(module_path)
    cmake_version = parse_cmake_version(module_path)
    tag_version = normalize_tag(args.tag) if args.tag else None

    failures = []
    if header_version != cmake_version:
        failures.append(
            f"version.h={header_version} does not match CMakeLists.txt={cmake_version}"
        )
    if tag_version and tag_version != header_version:
        failures.append(f"tag={tag_version} does not match version.h={header_version}")

    print("PQCP Version Consistency")
    print(f"  version.h : {header_version}")
    print(f"  CMake     : {cmake_version}")
    if tag_version:
        print(f"  tag       : {tag_version}")

    if failures:
        print("FAIL:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("PASS: version metadata is consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
