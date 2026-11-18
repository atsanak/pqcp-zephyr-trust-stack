#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Run the edge state-machine model checks and measure their power.

tests/ztest_edge_model drives four edge firmware modules (principal
directory, session registry, credential cache, policy distributor) with
seeded random operation traces against small abstract security models,
using each module's own audit function as a second oracle. On a violation it
shrinks the trace on the device and prints a replayable counterexample. The
device marker grammar this script parses is fixed:

  PQCP_MODEL_CHECK module=<m> seeds=<n> ops=<n> violations=<n> status=PASS|FAIL
  PQCP_MODEL_COUNTEREXAMPLE module=<m> seed=<hex16> violation=<code> ops=<n> trace=<hex>
  PQCP_MODEL_SUMMARY modules=4 traces=<n> ops=<n> violations=0 status=PASS

Default mode builds and runs the suite on qemu_x86_64 and requires one PASS
CHECK per module and a clean SUMMARY.

--rediscover answers a different question: would the suite notice a real
bug? HISTORICAL_DEFECTS re-injects, one at a time, the defects that were
hand-found and fixed in the edge firmware (commit b7d4cc1 and its edge
suite) into a private copy of the sources, rebuilds, and requires the model
run to print a COUNTEREXAMPLE for the module the defect lives in:

  rediscovered  a COUNTEREXAMPLE for the expected module appeared
  missed        the run passed, failed without a marker, or only another
                module reported a counterexample (this never counts)
  allowed       missed, but with a written reason; stays visible in the marker
  STALE         the pattern no longer matches exactly once: the list rotted
  ERROR         the mutated tree did not build, or the run produced nothing
                interpretable

The rediscovered count is a ratchet against
scripts/model_rediscovery_baseline.json. Any STALE or ERROR result, any miss
without an allowance, or a count below the baseline fails the run. Defects
are exercised sequentially in one private tree and build directory (QEMU and
the Zephyr build directory do not tolerate parallel use); the working tree is
never modified.

--check-patterns applies every defect's edits to a scratch copy of the
affected sources without building, so a rotted pattern is found in seconds.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from local_workflow import (  # noqa: E402
    clean_env,
    command_to_text,
    detect_west_root,
    discover_west,
    run_command,
)
from run_mutation_checks import Mutant, apply_edit  # noqa: E402

TEST_APP_RELATIVE = "tests/ztest_edge_model"
MODULES = ("principal", "session", "credential", "policy")
BASELINE_PATH = SCRIPT_DIR / "model_rediscovery_baseline.json"

# Sources a private tree needs to build the model app. ext/ is linked, not
# copied (it holds the vendored PQ libraries and is large).
COPY_PATHS = (
    "src",
    "include",
    "cmake",
    "CMakeLists.txt",
    "Kconfig",
    "zephyr",
    TEST_APP_RELATIVE,
    # The model app reuses this suite's test_common.h.
    "tests/ztest_edge_security",
)
LINK_PATHS = ("ext",)

CHECK_RE = re.compile(
    r"PQCP_MODEL_CHECK module=(\w+) seeds=(\d+) ops=(\d+) "
    r"violations=(\d+) status=(PASS|FAIL)")
COUNTEREXAMPLE_RE = re.compile(
    r"PQCP_MODEL_COUNTEREXAMPLE module=(\w+) seed=([0-9a-f]{16}) "
    r"violation=([\w.-]+) ops=(\d+) trace=([0-9a-f]+)")
SUMMARY_RE = re.compile(
    r"PQCP_MODEL_SUMMARY modules=(\d+) traces=(\d+) ops=(\d+) "
    r"violations=(\d+) status=(PASS|FAIL)")
# Emitted by this script (not the device): one line per historical defect.
DEFECT_LINE_RE = re.compile(
    r"PQCP_MODEL_DEFECT id=(\S+) module=(\w+) "
    r"status=(rediscovered|allowed|missed|STALE|ERROR)")
REDISCOVERY_RE = re.compile(
    r"PQCP_MODEL_REDISCOVERY PASS rediscovered=(\d+)/(\d+) allowed=(\d+)")

EXECUTION_OK = "PROJECT EXECUTION SUCCESSFUL"
EXECUTION_FAILED = "PROJECT EXECUTION FAILED"


# ---------------------------------------------------------------------------
# Marker parsing (pure functions, unit-tested by test_model_checks.py)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Check:
    module: str
    seeds: int
    ops: int
    violations: int
    status: str


@dataclass(frozen=True)
class Counterexample:
    module: str
    seed: str
    violation: str
    ops: int
    trace: str


@dataclass(frozen=True)
class Summary:
    modules: int
    traces: int
    ops: int
    violations: int
    status: str


@dataclass
class Parsed:
    checks: list[Check] = field(default_factory=list)
    counterexamples: list[Counterexample] = field(default_factory=list)
    summaries: list[Summary] = field(default_factory=list)
    execution_ok: bool = False


def parse_transcript(text: str) -> Parsed:
    parsed = Parsed()
    for m in CHECK_RE.finditer(text):
        parsed.checks.append(Check(m[1], int(m[2]), int(m[3]), int(m[4]), m[5]))
    for m in COUNTEREXAMPLE_RE.finditer(text):
        parsed.counterexamples.append(
            Counterexample(m[1], m[2], m[3], int(m[4]), m[5]))
    for m in SUMMARY_RE.finditer(text):
        parsed.summaries.append(
            Summary(int(m[1]), int(m[2]), int(m[3]), int(m[4]), m[5]))
    parsed.execution_ok = (EXECUTION_OK in text and
                           EXECUTION_FAILED not in text)
    return parsed


def assess_conformance(parsed: Parsed, *, require_execution: bool = True
                       ) -> list[str]:
    """Return the reasons a plain (unmutated) model run is not a clean PASS."""
    problems: list[str] = []
    if require_execution and not parsed.execution_ok:
        problems.append(f"transcript lacks '{EXECUTION_OK}' (or reports "
                        f"'{EXECUTION_FAILED}')")
    seen: dict[str, Check] = {}
    for check in parsed.checks:
        if check.module not in MODULES:
            problems.append(f"CHECK for unknown module {check.module!r}")
        elif check.module in seen:
            problems.append(f"duplicate CHECK for module {check.module}")
        else:
            seen[check.module] = check
    for module in MODULES:
        check = seen.get(module)
        if check is None:
            problems.append(f"missing CHECK marker for module {module}")
            continue
        if check.status != "PASS" or check.violations != 0:
            problems.append(f"module {module} reports status={check.status} "
                            f"violations={check.violations}")
        if check.seeds <= 0 or check.ops <= 0:
            problems.append(f"module {module} ran no traces "
                            f"(seeds={check.seeds} ops={check.ops})")
    for cex in parsed.counterexamples:
        problems.append(f"counterexample for module {cex.module} "
                        f"violation={cex.violation} seed={cex.seed}")
    if len(parsed.summaries) != 1:
        problems.append(f"expected exactly one PQCP_MODEL_SUMMARY, found "
                        f"{len(parsed.summaries)}")
    else:
        summary = parsed.summaries[0]
        if summary.modules != len(MODULES):
            problems.append(f"summary covers {summary.modules} modules, "
                            f"expected {len(MODULES)}")
        if summary.violations != 0 or summary.status != "PASS":
            problems.append(f"summary reports status={summary.status} "
                            f"violations={summary.violations}")
        if summary.traces != sum(c.seeds for c in parsed.checks):
            problems.append("summary trace count does not equal the sum of "
                            "the per-module seeds")
        if summary.ops != sum(c.ops for c in parsed.checks):
            problems.append("summary op count does not equal the sum of the "
                            "per-module ops")
    return problems


def classify_defect(expected_module: str, parsed: Parsed) -> tuple[str, str]:
    """Judge one mutated run. Returns (status, note).

    Only a COUNTEREXAMPLE naming the defect's own module is a rediscovery.
    """
    own = [c for c in parsed.counterexamples if c.module == expected_module]
    others = sorted({c.module for c in parsed.counterexamples
                     if c.module != expected_module})
    if own:
        if any(s.status == "PASS" for s in parsed.summaries):
            return "ERROR", ("counterexample marker alongside a PASS "
                             "summary: inconsistent transcript")
        first = own[0]
        return "rediscovered", (
            f"cex_module={first.module} cex_seed={first.seed} "
            f"cex_violation={first.violation} cex_ops={first.ops}")
    if others:
        return "missed", ("counterexample only for module(s) "
                          f"{', '.join(others)}, not {expected_module}")
    if any(s.status == "PASS" for s in parsed.summaries):
        return "missed", "model run passed with the defect present"
    if not parsed.execution_ok:
        return "missed", ("run failed without a counterexample marker "
                          "(not counted as a rediscovery)")
    return "missed", "no counterexample and no passing summary"


# ---------------------------------------------------------------------------
# Historical defects
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HistoricalDefect:
    ident: str
    module: str  # model module that must report the counterexample
    mutant: Mutant


def _defect(ident: str, module: str, name: str, path: str, pattern: str,
            replacement: str, allowance: str = "") -> HistoricalDefect:
    return HistoricalDefect(
        ident, module,
        Mutant(name=name, path=path, pattern=pattern,
               replacement=replacement, allowance=allowance))


# Each entry re-creates a defect that was found by hand and fixed (commit
# b7d4cc1, "20 defects found by the edge security suite") by undoing exactly
# its fix in the current source. Patterns must match the current source
# exactly once; replacements restore the pre-fix behaviour.
HISTORICAL_DEFECTS = (
    _defect(
        "H1", "credential",
        "credential cache: revoked records recycled as free slots",
        "src/edge_credential_cache.c",
        r"/\* Revoked records are tombstones and are never recycled\. \*/\s*"
        r"if \(!cache->records\[index\]\.occupied\) \{",
        "if (!cache->records[index].occupied ||\n"
        "\t\t    cache->records[index].state ==\n"
        "\t\t\t    PQCP_EDGE_CREDENTIAL_REVOKED) {"),
    _defect(
        "H2", "credential",
        "credential cache: put over a revoked id no longer rejected",
        "src/edge_credential_cache.c",
        r"/\* A revoked id stays revoked until an explicit policy.*?\*/\s*"
        r"if \(cache->records\[index\]\.state ==\s*"
        r"PQCP_EDGE_CREDENTIAL_REVOKED\) \{\s*"
        r"ret = -EKEYREVOKED;\s*goto reject;\s*\}",
        ""),
    _defect(
        "H3", "principal",
        "principal directory: re-register lifts a quarantine",
        "src/edge_identity_directory.c",
        r"if \(current->state ==\s*"
        r"PQCP_EDGE_PRINCIPAL_QUARANTINED\) \{",
        "if (0) {"),
    _defect(
        "H4", "principal",
        "principal directory: observe no longer honours a sticky quarantine",
        "src/edge_identity_directory.c",
        r"if \(principal->state ==\s*"
        r"PQCP_EDGE_PRINCIPAL_QUARANTINED &&\s*"
        r"\(principal->quarantine_until_ms == 0U \|\|\s*"
        r"now_ms < principal->quarantine_until_ms\)\) \{",
        "if (0) {"),
    _defect(
        "H5", "principal",
        "principal directory: tick demotes a quarantined principal on "
        "credential expiry",
        "src/edge_identity_directory.c",
        r"PQCP_EDGE_PRINCIPAL_DEGRADED &&\s*"
        r"principal->state !=\s*"
        r"PQCP_EDGE_PRINCIPAL_QUARANTINED\) \{",
        "PQCP_EDGE_PRINCIPAL_DEGRADED) {"),
    _defect(
        "H6", "session",
        "session registry: closing a finished session decrements the quota "
        "again",
        "src/edge_session_registry.c",
        r"session->state == PQCP_EDGE_SESSION_CLOSED \|\|\s*"
        r"session->principal_released\) \{",
        "session->state == PQCP_EDGE_SESSION_CLOSED) {"),
    _defect(
        "H7", "session",
        "session registry: closed session slots are never reclaimed",
        "src/edge_session_registry.c",
        r"return reclaim >= 0 \? reclaim : -ENOSPC;",
        "return -ENOSPC;"),
    _defect(
        "H8", "policy",
        "policy distributor: stale bundle may be promoted over a newer "
        "active epoch",
        "src/edge_policy_distributor.c",
        r"if \(bundle->policy_epoch <= distributor->active_policy_epoch\) \{",
        "if (0) {"),
    _defect(
        "H9", "policy",
        "policy distributor: rollback rewrites expires_at_ms and breaks the "
        "bundle digest",
        "src/edge_policy_distributor.c",
        r"/\* expires_at_ms is covered by bundle_digest and must not change;"
        r".*?\*/",
        "bundle->expires_at_ms = now_ms;"),
    _defect(
        "H10", "policy",
        "identifier counter: first issued id is 2, not 1",
        "src/edge_security_common.c",
        r"uint64_t issued = \*identifier;\s*"
        r"if \(issued == 0U \|\| issued == UINT64_MAX\) \{\s*"
        r"issued = 1U;\s*\}\s*"
        r"\*identifier = issued \+ 1U;\s*return issued;",
        "if (*identifier == 0U || *identifier == UINT64_MAX) {\n"
        "\t\t*identifier = 1U;\n"
        "\t} else {\n"
        "\t\t++(*identifier);\n"
        "\t}\n"
        "\treturn *identifier;"),
)


def check_patterns(root: Path, defects=HISTORICAL_DEFECTS) -> list[str]:
    """Apply every defect to scratch copies of the sources; no build."""
    problems: list[str] = []
    with tempfile.TemporaryDirectory(prefix="pqcp-model-patterns-") as tmp:
        scratch = Path(tmp)
        for defect in defects:
            edits = ((defect.mutant.path, defect.mutant.pattern,
                      defect.mutant.replacement), *defect.mutant.extra)
            for path, *_ in edits:
                target = scratch / path
                if not target.exists():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(root / path, target)
            for path, pattern, replacement in edits:
                before = (scratch / path).read_text(encoding="utf-8")
                problem = apply_edit(scratch, path, pattern, replacement)
                if problem:
                    problems.append(f"{defect.ident}: {problem}")
                    continue
                if (scratch / path).read_text(encoding="utf-8") == before:
                    problems.append(f"{defect.ident}: {path}: replacement "
                                    "left the source unchanged")
            # Re-copy so one defect's edit never leaks into the next.
            for path, *_ in edits:
                shutil.copy2(root / path, scratch / path)
    return problems


# ---------------------------------------------------------------------------
# Baseline and verdict
# ---------------------------------------------------------------------------

def load_baseline(path: Path = BASELINE_PATH) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(data.get("rediscovered_min"), int) or
            isinstance(data.get("rediscovered_min"), bool) or
            data["rediscovered_min"] < 0):
        raise ValueError(f"{path}: rediscovered_min must be a "
                         "non-negative integer")
    total = data.get("defects_total")
    if total is not None and (not isinstance(total, int) or total < 1):
        raise ValueError(f"{path}: defects_total must be a positive integer")
    return data


def judge_rediscovery(outcomes: list[tuple[HistoricalDefect, str, str]],
                      baseline: dict) -> tuple[list[str], str]:
    """Return (problems, marker). The marker is PASS only without problems."""
    problems: list[str] = []
    rediscovered = sum(1 for _, s, _ in outcomes if s == "rediscovered")
    allowed = sum(1 for _, s, _ in outcomes if s == "allowed")
    total = len(outcomes)
    for defect, status, note in outcomes:
        if status in ("STALE", "ERROR"):
            problems.append(f"{defect.ident} {status}: {note}")
        elif status == "missed":
            problems.append(f"{defect.ident} missed without an allowance: "
                            f"{note}")
    if rediscovered < baseline["rediscovered_min"]:
        problems.append(f"rediscovered {rediscovered} is below the baseline "
                        f"{baseline['rediscovered_min']}")
    expected_total = baseline.get("defects_total")
    if expected_total is not None and total < expected_total:
        problems.append(f"defect list shrank to {total} (baseline "
                        f"{expected_total})")
    if problems:
        return problems, (f"PQCP_MODEL_REDISCOVERY FAIL "
                          f"rediscovered={rediscovered}/{total} "
                          f"allowed={allowed}")
    return problems, (f"PQCP_MODEL_REDISCOVERY PASS "
                      f"rediscovered={rediscovered}/{total} allowed={allowed}")


def defect_line(defect: HistoricalDefect, status: str) -> str:
    return (f"PQCP_MODEL_DEFECT id={defect.ident} module={defect.module} "
            f"status={status}")


# ---------------------------------------------------------------------------
# Build and run
# ---------------------------------------------------------------------------

def build_tree(destination: Path) -> None:
    for relative in COPY_PATHS:
        source = MODULE_ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(
                source, target,
                ignore=shutil.ignore_patterns("__pycache__", "build*"))
        else:
            shutil.copy2(source, target)
    for relative in LINK_PATHS:
        (destination / relative).symlink_to(MODULE_ROOT / relative)


def west_build(west_cmd: list[str], west_root: Path, env: dict, module: Path,
               build_dir: Path, *, pristine: bool, timeout: int) -> None:
    cmd = [*west_cmd, "build"]
    if pristine:
        cmd += ["-p", "always"]
    cmd += ["-b", "qemu_x86_64", str(module / TEST_APP_RELATIVE),
            "-d", str(build_dir), "--",
            f"-DZEPHYR_EXTRA_MODULES={module}"]
    run_command(cmd, cwd=west_root, env=env, timeout=timeout)


def kill_qemu(build_dir: Path) -> None:
    """QEMU on macOS outlives its parent; reap anything tied to this build."""
    subprocess.run(["pkill", "-f", f"qemu-system-x86_64.*{build_dir}"],
                   check=False, capture_output=True)


def west_run(west_cmd: list[str], west_root: Path, env: dict, build_dir: Path,
             *, timeout: int) -> str:
    """Run the built image under QEMU and return its console output.

    QEMU never exits by itself, so output is read until Zephyr's
    PROJECT EXECUTION line (or the timeout) and the process group is killed.
    """
    cmd = [*west_cmd, "build", "-d", str(build_dir), "-t", "run"]
    print("+ " + command_to_text(cmd), flush=True)
    proc = subprocess.Popen(
        cmd, cwd=str(west_root), env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        errors="replace", start_new_session=True)
    lines: list[str] = []
    done = threading.Event()

    def reader() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            lines.append(line)
            if EXECUTION_OK in line or EXECUTION_FAILED in line:
                done.set()
                break
        done.set()

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    finished = done.wait(timeout)
    if not finished:
        lines.append(f"[model] run timed out after {timeout}s\n")
    for sig in (signal.SIGINT, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            break
        try:
            proc.wait(timeout=5)
            break
        except subprocess.TimeoutExpired:
            continue
    kill_qemu(build_dir)
    thread.join(timeout=5)
    return "".join(lines)


def echo(text: str) -> None:
    print(text, end="" if text.endswith("\n") else "\n", flush=True)


def run_conformance(west_cmd, west_root, env, module: Path, build_dir: Path,
                    args) -> tuple[Parsed, list[str], str]:
    west_build(west_cmd, west_root, env, module, build_dir, pristine=True,
               timeout=args.build_timeout)
    output = west_run(west_cmd, west_root, env, build_dir,
                      timeout=args.run_timeout)
    echo(output)
    parsed = parse_transcript(output)
    return parsed, assess_conformance(parsed), output


def rediscover(west_cmd, west_root, env, build_dir: Path, args) -> int:
    baseline = load_baseline()
    stale = check_patterns(MODULE_ROOT)
    outcomes: list[tuple[HistoricalDefect, str, str]] = []
    stale_ids = {p.split(":", 1)[0] for p in stale}

    with tempfile.TemporaryDirectory(prefix="pqcp-model-rediscover-") as tmp:
        tree = Path(tmp) / "tree"
        build_tree(tree)
        rd_build = Path(tmp) / "build"
        print("[model] rediscovery baseline: unmutated private tree must "
              "pass", flush=True)
        _, problems, _ = run_conformance(west_cmd, west_root, env, tree,
                                         rd_build, args)
        if problems:
            for problem in problems:
                print(f"[model] FAIL: {problem}")
            return 1

        for defect in HISTORICAL_DEFECTS:
            print(f"[model] {defect.ident}: {defect.mutant.name}", flush=True)
            if defect.ident in stale_ids:
                note = "; ".join(p for p in stale
                                 if p.startswith(defect.ident + ":"))
                outcomes.append((defect, "STALE", note))
                continue
            edits = ((defect.mutant.path, defect.mutant.pattern,
                      defect.mutant.replacement), *defect.mutant.extra)
            originals = {p: (tree / p).read_text(encoding="utf-8")
                         for p, *_ in edits}
            try:
                for p, pattern, replacement in edits:
                    problem = apply_edit(tree, p, pattern, replacement)
                    if problem:
                        raise RuntimeError(f"STALE {problem}")
                try:
                    west_build(west_cmd, west_root, env, tree, rd_build,
                               pristine=False, timeout=args.build_timeout)
                except RuntimeError as exc:
                    outcomes.append((defect, "ERROR",
                                     f"mutated tree did not build: {exc}"))
                    continue
                output = west_run(west_cmd, west_root, env, rd_build,
                                  timeout=args.run_timeout)
                echo_defect_output(output)
                status, note = classify_defect(defect.module,
                                               parse_transcript(output))
                if status == "missed" and defect.mutant.allowance:
                    status, note = "allowed", defect.mutant.allowance
                outcomes.append((defect, status, note))
            except RuntimeError as exc:
                if str(exc).startswith("STALE "):
                    outcomes.append((defect, "STALE", str(exc)[6:]))
                else:
                    raise
            finally:
                for p, text in originals.items():
                    (tree / p).write_text(text, encoding="utf-8")

        print("[model] rediscovery epilogue: restored tree must pass again",
              flush=True)
        west_build(west_cmd, west_root, env, tree, rd_build, pristine=False,
                   timeout=args.build_timeout)
        epilogue = west_run(west_cmd, west_root, env, rd_build,
                            timeout=args.run_timeout)
        epilogue_problems = assess_conformance(parse_transcript(epilogue))
        if epilogue_problems:
            echo(epilogue)
            for problem in epilogue_problems:
                print(f"[model] FAIL: restored tree: {problem}")
            return 1

    print("[model] historical-defect rediscovery:")
    for defect, status, note in outcomes:
        suffix = f" ({note})" if note else ""
        print(f"[model] {status:12s} {defect.ident:4s} "
              f"{defect.mutant.name}{suffix}")
    for defect, status, _ in outcomes:
        print(defect_line(defect, status))
    problems, marker = judge_rediscovery(outcomes, baseline)
    print(marker)
    if problems:
        for problem in problems:
            print(f"[model] FAIL: {problem}")
        return 1
    rediscovered = sum(1 for _, s, _ in outcomes if s == "rediscovered")
    if rediscovered > baseline["rediscovered_min"]:
        print(f"[model] NOTE: rediscovered {rediscovered} exceeds the "
              f"baseline {baseline['rediscovered_min']}; raise "
              "scripts/model_rediscovery_baseline.json")
    print("[model] PASS: historical defects rediscovered at or above the "
          "baseline; every miss carries a written allowance")
    return 0


def echo_defect_output(output: str) -> None:
    """Show a mutated run without echoing device markers a gate could trust.

    The device COUNTEREXAMPLE lines are rewritten (prefix 'mutated run:') so
    a transcript scan for plain-run markers never mistakes a deliberate
    counterexample for a clean-run finding.
    """
    for line in output.splitlines():
        if "PQCP_MODEL_" in line:
            print("[model] mutated run: " +
                  line.replace("PQCP_MODEL_", "mutated_model_"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--west-root", type=Path)
    parser.add_argument("--west", help="Explicit west binary or command")
    parser.add_argument("--output-dir", type=Path, default=None,
                        help="directory for the plain-run build")
    parser.add_argument("--rediscover", action="store_true",
                        help="also re-inject the historical defects")
    parser.add_argument("--check-patterns", action="store_true",
                        help="only verify the defect patterns still match")
    parser.add_argument("--build-timeout", type=int, default=900)
    parser.add_argument("--run-timeout", type=int, default=300)
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.check_patterns:
        problems = check_patterns(MODULE_ROOT)
        for problem in problems:
            print(f"[model] STALE: {problem}")
        if problems:
            return 1
        print(f"[model] PASS: all {len(HISTORICAL_DEFECTS)} defect patterns "
              "match the current sources exactly once")
        return 0

    if not (MODULE_ROOT / TEST_APP_RELATIVE).is_dir():
        print(f"[model] FAIL: {TEST_APP_RELATIVE} does not exist")
        return 1

    env = clean_env()
    west_root = detect_west_root(args.west_root or MODULE_ROOT)
    west_cmd = discover_west(args.west, west_root, MODULE_ROOT)
    output_dir = args.output_dir or (MODULE_ROOT / "build-model-checks")
    output_dir.mkdir(parents=True, exist_ok=True)
    build_dir = output_dir / "build-edge-model"

    print("[model] building and running tests/ztest_edge_model "
          "(qemu_x86_64)", flush=True)
    try:
        _, problems, _ = run_conformance(west_cmd, west_root, env,
                                         MODULE_ROOT, build_dir, args)
    except RuntimeError as exc:
        print(f"[model] FAIL: {exc}")
        return 1
    finally:
        kill_qemu(build_dir)
    if problems:
        for problem in problems:
            print(f"[model] FAIL: {problem}")
        return 1
    print("[model] PASS: every module model conforms on every seeded trace")

    if not args.rediscover:
        return 0
    try:
        return rediscover(west_cmd, west_root, env, build_dir, args)
    except RuntimeError as exc:
        print(f"[model] FAIL: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
