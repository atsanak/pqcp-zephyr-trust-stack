#!/usr/bin/env python3
"""
Validate version consistency across version.h, CMakeLists.txt, CHANGELOG.md
(optional), and an optional git tag.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from extract_changelog_section import _iter_sections  # noqa: E402

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
    parser.add_argument(
        "--changelog",
        type=Path,
        help=(
            "Optional path to CHANGELOG.md. When provided, the helper "
            "requires a non-Unreleased section matching the declared "
            "version and at least one non-empty line inside it."
        ),
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


def validate_changelog(changelog_path: Path, expected_version: str) -> list[str]:
    """Return a list of validation failure strings (empty list = PASS)."""
    failures: list[str] = []
    try:
        text = changelog_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [f"changelog not found at {changelog_path}"]

    sections = _iter_sections(text)
    section_names = [name for name, _ in sections]

    if expected_version not in section_names:
        failures.append(
            f"CHANGELOG.md is missing a [{expected_version}] section "
            f"(found: {section_names or '<none>'})"
        )
        return failures

    if section_names[0] == expected_version:
        failures.append(
            f"CHANGELOG.md [{expected_version}] is the first section but no "
            "[Unreleased] placeholder is present above it; the next "
            "change would have no home."
        )

    body = next(body for name, body in sections if name == expected_version).strip()
    if not body:
        failures.append(
            f"CHANGELOG.md [{expected_version}] section is empty; "
            "add at least one entry before releasing."
        )
        return failures

    bullet_lines = [
        line
        for line in body.splitlines()
        if line.lstrip().startswith(("-", "*", "+"))
    ]
    if not bullet_lines:
        failures.append(
            f"CHANGELOG.md [{expected_version}] section has no bullet "
            "entries; record what shipped before releasing."
        )

    header_line = next(
        line
        for line in text.splitlines()
        if line.startswith(f"## [{expected_version}]")
    )
    if " - " not in header_line:
        failures.append(
            f"CHANGELOG.md [{expected_version}] header is missing an "
            "ISO date (expected '## [x.y.z] - YYYY-MM-DD')."
        )

    return failures


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

    if args.changelog is not None:
        changelog_path = args.changelog
        if not changelog_path.is_absolute():
            changelog_path = (module_path / changelog_path).resolve()
        print(f"  changelog : {changelog_path}")
        changelog_failures = validate_changelog(changelog_path, header_version)
        failures.extend(changelog_failures)

    if failures:
        print("FAIL:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("PASS: version metadata is consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
