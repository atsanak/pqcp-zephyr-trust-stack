#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Measure and ratchet how much of src/ is actually backed by evidence.

Every module (src/<name>.c) is assigned an evidence level:

  L0 untested  no ztest suite references any function the module defines
  L1 tested    at least one ztest suite calls a function the module defines
  L2 gated     an exercising suite is wired into an automated gate:
               extended-check compatibility targets, release_check.py,
               a GitHub workflow that names it, or registration with
               twister (testcase.yaml) while a workflow runs twister
               over tests/ in run mode (not --build-only)
  L3 claimed   gated, and the module (or its Kconfig symbol, header, or
               exercising suite) is bound by the assurance claim catalog
               or the crypto asset trace map

The audit is a ratchet, not a vanity metric: scripts/
evidence_coverage_baseline.json records each module's level, and --check
fails if any module regresses or if a NEW module appears untested. Levels
can only go up unless the baseline is deliberately rewritten.

Stdlib only; reads source text, never executes anything from the tree.
"""

import argparse
import json
import re
import sys
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = MODULE_ROOT / "scripts" / "evidence_coverage_baseline.json"

LEVEL_NAMES = {0: "untested", 1: "tested", 2: "gated", 3: "claimed"}

INCLUDE_RE = re.compile(r"#\s*include\s*<pqcp_zephyr/([A-Za-z0-9_]+)\.h>")
CMAKE_SRC_RE = re.compile(r"\$\{PQCP_SRC\}/([A-Za-z0-9_]+)\.c")
CMAKE_IF_RE = re.compile(r"^\s*if\s*\((.*)\)\s*$")
CONFIG_RE = re.compile(r"\bCONFIG_[A-Z0-9_]+\b")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# A non-static function definition: starts at column 0 with a return type
# and an identifier followed by '(' (return type on the same line).
DEF_RE = re.compile(
    r"^(?!static\b|typedef\b|extern\b|#|//|/\*|\*)"
    r"[A-Za-z_][\w \t\*]*?[ \t\*]([A-Za-z_]\w*)\s*\(",
    re.MULTILINE)
KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "else"}


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def parse_cmake_configs(cmake_text: str) -> dict[str, list[str]]:
    """Map each module to the CONFIG_ symbols of its enclosing if() frames."""
    configs: dict[str, list[str]] = {}
    stack: list[list[str]] = []
    for line in cmake_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        match = CMAKE_IF_RE.match(line)
        if match:
            stack.append(CONFIG_RE.findall(match.group(1)))
            continue
        if re.match(r"^\s*endif\s*\(", line):
            if stack:
                stack.pop()
            continue
        for module in CMAKE_SRC_RE.findall(line):
            flat: list[str] = []
            for frame in stack:
                for symbol in frame:
                    if symbol not in flat:
                        flat.append(symbol)
            configs.setdefault(module, flat)
    return configs


def defined_symbols(source_text: str) -> set[str]:
    """Names of the non-static functions this translation unit defines."""
    return {name for name in DEF_RE.findall(source_text)
            if name not in KEYWORDS}


def implemented_header(module: str, source_text: str,
                       headers: set[str]) -> str | None:
    """Pick the public header this translation unit implements."""
    best = None
    for stem in INCLUDE_RE.findall(source_text):
        if stem not in headers:
            continue
        if module == stem or module.startswith(stem + "_"):
            if best is None or len(stem) > len(best):
                best = stem
    if best is None and module in headers:
        best = module
    return best


def collect_tests(root: Path) -> dict[str, dict]:
    tests: dict[str, dict] = {}
    for test_dir in sorted((root / "tests").glob("*")):
        if not test_dir.is_dir():
            continue
        idents: set[str] = set()
        for source in test_dir.rglob("*.c"):
            idents.update(IDENT_RE.findall(read_text(source)))
        tests[test_dir.name] = {
            "idents": idents,
            "prj_conf": read_text(test_dir / "prj.conf"),
            "twister": (test_dir / "testcase.yaml").exists(),
        }
    return tests


def gate_surfaces(root: Path) -> dict[str, str]:
    """Text of every automated gate that can name a test suite."""
    surfaces = {
        "extended_checks": read_text(root / "scripts/run_extended_checks.py"),
        "release_check": read_text(root / "scripts/release_check.py"),
    }
    for workflow in sorted((root / ".github" / "workflows").glob("*.yml")):
        surfaces[f"workflow:{workflow.name}"] = read_text(workflow)
    return surfaces


TWISTER_RE = re.compile(r"west\s+twister\b(.*?)(?:\n\s*\n|\Z)", re.S)


def twister_runs_all_tests(surfaces: dict[str, str]) -> bool:
    """True if a workflow runs twister over tests/ in run mode."""
    for name, text in surfaces.items():
        if not name.startswith("workflow:"):
            continue
        for command in TWISTER_RE.findall(text):
            if "--build-only" in command:
                continue
            if re.search(r"-T\s+\S*tests\b", command):
                return True
    return False


def build_report(root: Path) -> dict:
    src_dir = root / "src"
    headers = {p.stem for p in (root / "include/pqcp_zephyr").glob("*.h")}
    cmake_configs = parse_cmake_configs(read_text(root / "CMakeLists.txt"))
    tests = collect_tests(root)
    surfaces = gate_surfaces(root)
    sweep = twister_runs_all_tests(surfaces)
    claim_text = (read_text(root / "scripts/assurance_claims.json") +
                  read_text(root / "scripts/pqc_asset_trace_map.json")).lower()

    raw: dict[str, dict] = {}
    owner: dict[str, str] = {}
    for source in sorted(src_dir.glob("*.c")):
        text = read_text(source)
        symbols = defined_symbols(text)
        raw[source.stem] = {"text": text, "symbols": symbols,
                            "idents": set(IDENT_RE.findall(text))}
        for symbol in symbols:
            owner.setdefault(symbol, source.stem)

    # Call graph: A -> B when A references a symbol that B defines.
    edges: dict[str, set[str]] = {}
    for name, info in raw.items():
        edges[name] = {owner[i] for i in info["idents"]
                       if i in owner and owner[i] != name}

    direct = {name for name, info in raw.items()
              if any(info["symbols"] & t["idents"] for t in tests.values())}
    reached = set(direct)
    frontier = list(direct)
    while frontier:
        for callee in edges[frontier.pop()]:
            if callee not in reached:
                reached.add(callee)
                frontier.append(callee)

    modules = []
    for source in sorted(src_dir.glob("*.c")):
        name = source.stem
        text = raw[name]["text"]
        header = implemented_header(name, text, headers)
        configs = cmake_configs.get(name, [])
        symbols = raw[name]["symbols"]

        exercisers = sorted(
            test for test, info in tests.items()
            if symbols & info["idents"])

        gated = {surface for test in exercisers
                 for surface, text in surfaces.items() if test in text}
        if sweep and any(tests[t]["twister"] for t in exercisers):
            gated.add("twister-run")
        gated_by = sorted(gated)

        probes = {name.lower()}
        if header:
            probes.add(header.lower())
        probes.update(t.lower() for t in exercisers)
        probes.update(c.lower().removeprefix("config_") for c in configs[-1:])
        claimed = any(probe in claim_text for probe in probes)

        if not exercisers:
            level = 0
        elif not gated_by:
            level = 1
        elif not claimed:
            level = 2
        else:
            level = 3

        modules.append({
            "module": name,
            "family": name.split("_")[0],
            "header": header,
            "defined_symbols": len(symbols),
            "reach": ("direct" if name in direct else
                      "transitive" if name in reached else "none"),
            "lines": text.count("\n") + 1,
            "configs": configs,
            "exercised_by": exercisers,
            "gated_by": gated_by,
            "claimed": claimed,
            "level": level,
        })

    summary = {"modules": len(modules)}
    for level, label in LEVEL_NAMES.items():
        summary[f"L{level}_{label}"] = sum(
            1 for m in modules if m["level"] == level)

    l0 = [m for m in modules if m["level"] == 0]
    summary["L0_reached_transitively"] = sum(
        1 for m in l0 if m["reach"] == "transitive")
    summary["L0_unreachable_from_tests"] = sum(
        1 for m in l0 if m["reach"] == "none")
    summary["lines_total"] = sum(m["lines"] for m in modules)
    summary["lines_unreachable_from_tests"] = sum(
        m["lines"] for m in l0 if m["reach"] == "none")
    summary["lines_direct_gated_or_claimed"] = sum(
        m["lines"] for m in modules if m["level"] >= 2)

    families: dict[str, dict[str, int]] = {}
    for module in modules:
        fam = families.setdefault(
            module["family"], {"modules": 0, "L0": 0, "L1": 0, "L2": 0,
                               "L3": 0})
        fam["modules"] += 1
        fam[f"L{module['level']}"] += 1

    return {"schema_version": 1, "summary": summary, "families": families,
            "modules": modules}


def load_baseline() -> dict[str, int]:
    if not BASELINE_PATH.exists():
        return {}
    data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    return {k: int(v) for k, v in data.get("modules", {}).items()}


def write_baseline(report: dict) -> None:
    payload = {
        "schema_version": 1,
        "note": ("Evidence-coverage ratchet. Levels may only rise; new "
                 "modules must start at L1 or higher. Rewrite with "
                 "scripts/audit_evidence_coverage.py --update-baseline."),
        "modules": {m["module"]: m["level"] for m in report["modules"]},
    }
    BASELINE_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True)
                             + "\n", encoding="utf-8")


def check_ratchet(report: dict, baseline: dict[str, int]):
    regressions = []
    new_orphans = []
    improved = []
    for module in report["modules"]:
        name, level = module["module"], module["level"]
        if name not in baseline:
            if level == 0:
                new_orphans.append(name)
            continue
        if level < baseline[name]:
            regressions.append((name, baseline[name], level))
        elif level > baseline[name]:
            improved.append((name, baseline[name], level))
    return regressions, new_orphans, improved


def print_family_table(report: dict) -> None:
    print(f"  {'family':<14}{'mods':>5}{'L0':>5}{'L1':>5}{'L2':>5}{'L3':>5}")
    rows = sorted(report["families"].items(),
                  key=lambda kv: kv[1]["modules"], reverse=True)
    for family, counts in rows[:12]:
        print(f"  {family:<14}{counts['modules']:>5}{counts['L0']:>5}"
              f"{counts['L1']:>5}{counts['L2']:>5}{counts['L3']:>5}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--root", type=Path, default=MODULE_ROOT)
    parser.add_argument("--json", type=Path, help="write the full report")
    parser.add_argument("--check", action="store_true",
                        help="fail on regressions or new untested modules")
    parser.add_argument("--update-baseline", action="store_true",
                        help="rewrite the ratchet baseline from the tree")
    args = parser.parse_args()

    report = build_report(args.root)
    summary = report["summary"]

    print(f"[coverage] {summary['modules']} modules: "
          f"L0 untested={summary['L0_untested']} "
          f"L1 tested={summary['L1_tested']} "
          f"L2 gated={summary['L2_gated']} "
          f"L3 claimed={summary['L3_claimed']}")
    print(f"[coverage] of the {summary['L0_untested']} untested modules, "
          f"{summary['L0_reached_transitively']} are only reached through "
          f"another tested module; {summary['L0_unreachable_from_tests']} "
          f"are unreachable from any test "
          f"({summary['lines_unreachable_from_tests']} of "
          f"{summary['lines_total']} lines)")
    print_family_table(report)

    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n",
                             encoding="utf-8")
        print(f"[coverage] report written to {args.json}")

    if args.update_baseline:
        write_baseline(report)
        print(f"[coverage] baseline rewritten: {BASELINE_PATH}")
        return 0

    if not args.check:
        return 0

    baseline = load_baseline()
    if not baseline:
        print("[coverage] FAIL: no baseline; run --update-baseline first")
        return 1

    regressions, new_orphans, improved = check_ratchet(report, baseline)
    for name, was, now in regressions:
        print(f"[coverage] REGRESSION {name}: L{was} -> L{now}")
    for name in new_orphans:
        print(f"[coverage] NEW UNTESTED MODULE {name}: add a ztest suite")
    if improved:
        print(f"[coverage] {len(improved)} module(s) improved; raise the "
              "baseline with --update-baseline")

    if regressions or new_orphans:
        print("[coverage] FAIL: evidence coverage ratchet violated")
        return 1

    print(f"PQCP_EVIDENCE_COVERAGE PASS modules={summary['modules']} "
          f"L0={summary['L0_untested']} L1={summary['L1_tested']} "
          f"L2={summary['L2_gated']} L3={summary['L3_claimed']} "
          f"new_untested=0 regressions=0")
    print("[coverage] PASS: no module lost evidence and no new module is "
          "untested")
    return 0


if __name__ == "__main__":
    sys.exit(main())
