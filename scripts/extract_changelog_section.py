#!/usr/bin/env python3
"""
Extract a named Keep a Changelog section from CHANGELOG.md.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path


SECTION_RE = re.compile(r"^## \[([^\]]+)\](?:\s+-\s+.*)?$", re.MULTILINE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract a named section from CHANGELOG.md"
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
    return parser.parse_args()


def extract_section(text: str, section_name: str) -> str:
    matches = list(SECTION_RE.finditer(text))
    for index, match in enumerate(matches):
        if match.group(1) != section_name:
            continue

        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        if not body:
            return "No release notes were recorded in this section.\n"
        return body + "\n"

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
