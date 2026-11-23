#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Extract Keep a Changelog sections for release automation."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


SECTION_RE = re.compile(r"^## \[([^\]]+)\](?:[ \t]+-[ \t]+[^\r\n]*)?$", re.MULTILINE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract a named section from CHANGELOG.md"
    )
    parser.add_argument(
        "file_arg",
        nargs="?",
        type=Path,
        help="Optional positional path to the changelog file",
    )
    parser.add_argument(
        "--file",
        type=Path,
        default=Path("CHANGELOG.md"),
        help="Path to the changelog file",
    )
    parser.add_argument(
        "--section",
        default="Unreleased",
        help="Section name to extract (without brackets)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional output file; defaults to stdout",
    )
    args = parser.parse_args()
    if args.file_arg is not None:
        args.file = args.file_arg
    return args


def _iter_sections(text: str) -> list[tuple[str, str]]:
    matches = list(SECTION_RE.finditer(text))
    sections: list[tuple[str, str]] = []
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        sections.append((match.group(1), body))
    return sections


def extract_section(text: str, section_name: str) -> str:
    sections = _iter_sections(text)
    for index, (name, body) in enumerate(sections):
        if name != section_name:
            continue
        if body:
            return body + "\n"
        if name == "Unreleased":
            for _, fallback_body in sections[index + 1 :]:
                if fallback_body:
                    return fallback_body + "\n"
        return "No release notes were recorded in this section.\n"
    raise SystemExit(f"Section [{section_name}] not found in changelog")


def main() -> int:
    args = parse_args()
    text = args.file.read_text(encoding="utf-8")
    section = extract_section(text, args.section)

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(section, encoding="utf-8")
    else:
        print(section, end="")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
