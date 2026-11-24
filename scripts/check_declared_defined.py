#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Find public functions that are declared but never defined.

A function advertised in include/pqcp_zephyr/*.h with no definition in
src/ looks like supported API but fails at link time for any caller. The
sovereign audit exporter and its bridge adapters were found this way:
declared in sovereign_audit.h, defined nowhere.

This is a ratchet: scripts/declared_undefined_baseline.json lists the
currently known gaps, and --check fails if a NEW declared-but-undefined
function appears. Fixing one (implement it, or delete the stale
declaration) and rewriting the baseline lets the number only go down.

Stdlib only; static text analysis, nothing is executed.
"""

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

from pqcp_generated_sources import render_generated_sources

MODULE_ROOT = Path(__file__).resolve().parent.parent
HEADERS = MODULE_ROOT / "include" / "pqcp_zephyr"
SOURCES = MODULE_ROOT / "src"
BASELINE = MODULE_ROOT / "scripts" / "declared_undefined_baseline.json"

COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
PREPROC_RE = re.compile(r"^[ \t]*#.*(?:\\\n.*)*$", re.M)
# Statement-level declaration: <type tokens> name(<args>);
DECL_RE = re.compile(
    r"(?:^|(?<=[;{}]))\s*"
    r"((?:[A-Za-z_][\w]*[\s\*]+)+?)"
    r"([A-Za-z_]\w*)\s*\(([^;{}()]*(?:\([^;{}()]*\)[^;{}()]*)*)\)\s*;")
DEF_RE = re.compile(
    r"^(?!static\b|typedef\b|extern\b|#)[A-Za-z_][\w \t\*]*?[ \t\*]"
    r"([A-Za-z_]\w*)\s*\(", re.M)
# Return type on the previous line, function name alone at column 0.
DEF_NAME_FIRST_RE = re.compile(r"^([a-z_][a-z0-9_]*)\s*\(", re.M)
INLINE_DEF_RE = re.compile(
    r"\bstatic\s+inline\b[^;{]*?\b([A-Za-z_]\w*)\s*\(")
DEFINE_RE = re.compile(r"^[ \t]*#\s*define\s+([A-Za-z_]\w*)\s*\(", re.M)
SKIP_TYPES = {"typedef", "return", "else", "if", "while", "for", "switch",
              "sizeof", "define"}


def strip(text: str) -> str:
    return PREPROC_RE.sub("", COMMENT_RE.sub(" ", text))


def declared_functions(header: Path) -> set[str]:
    text = strip(header.read_text(encoding="utf-8", errors="replace"))
    # Drop struct/enum/union bodies so function-pointer members and
    # initializers are not mistaken for declarations.
    previous = None
    while previous != text:
        previous = text
        text = re.sub(
            r"\b(?:struct|union|enum)\b[^;{}]*\{[^{}]*\}", " AGG ", text)
    names = set()
    for types, name, _ in DECL_RE.findall(text):
        tokens = set(types.split())
        if tokens & SKIP_TYPES or "typedef" in tokens:
            continue
        if re.search(r"\(\s*\*\s*$", types):
            continue
        names.add(name)
    return names


def defined_functions() -> set[str]:
    defined = set()
    with tempfile.TemporaryDirectory(prefix="pqcp-generated-") as tmp:
        generated = {p.name: p.read_text(encoding="utf-8")
                     for p in render_generated_sources(Path(tmp))}
    for text in generated.values():
        text = strip(text)
        defined.update(DEF_RE.findall(text))
        defined.update(DEF_NAME_FIRST_RE.findall(text))
    for path in SOURCES.rglob("*.c"):
        text = strip(path.read_text(encoding="utf-8", errors="replace"))
        defined.update(DEF_RE.findall(text))
        defined.update(DEF_NAME_FIRST_RE.findall(text))
    for path in HEADERS.glob("*.h"):
        raw = path.read_text(encoding="utf-8", errors="replace")
        defined.update(INLINE_DEF_RE.findall(strip(raw)))
        defined.update(DEFINE_RE.findall(raw))
    return defined


def build_report() -> dict[str, list[str]]:
    defined = defined_functions()
    report = {}
    for header in sorted(HEADERS.glob("*.h")):
        missing = sorted(n for n in declared_functions(header)
                         if n not in defined)
        if missing:
            report[header.name] = missing
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--update-baseline", action="store_true")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()

    report = build_report()
    total = sum(len(v) for v in report.values())
    print(f"[declared] {total} declared-but-undefined function(s) in "
          f"{len(report)} header(s)")
    for header, names in report.items():
        print(f"  {header}: {len(names)}")

    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n",
                             encoding="utf-8")
    if args.update_baseline:
        BASELINE.write_text(json.dumps(
            {"schema_version": 1,
             "note": ("Known declared-but-undefined functions. Fix by "
                      "implementing or deleting the declaration, then "
                      "rewrite with --update-baseline."),
             "functions": report}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        print(f"[declared] baseline rewritten: {BASELINE}")
        return 0
    if not args.check:
        return 0

    known = {}
    if BASELINE.exists():
        known = json.loads(BASELINE.read_text(encoding="utf-8")).get(
            "functions", {})
    known_names = {n for names in known.values() for n in names}
    new = [(h, n) for h, names in report.items() for n in names
           if n not in known_names]
    fixed = sum(len(v) for v in known.values()) - (
        total - len(new))
    for header, name in new:
        print(f"[declared] NEW undefined function {name} in {header}: "
              "implement it or remove the declaration")
    if new:
        print("[declared] FAIL: new declared-but-undefined function(s)")
        return 1
    if fixed > 0:
        print(f"[declared] {fixed} baseline entr(ies) fixed; lower the "
              "baseline with --update-baseline")
    print(f"PQCP_DECLARED_DEFINED PASS undefined={total} new=0")
    print("[declared] PASS: no new declared-but-undefined functions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
