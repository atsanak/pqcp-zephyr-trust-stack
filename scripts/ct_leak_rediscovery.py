#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Measure the sensitivity and specificity of the relational CT trace test.

A detector that has never seen a leak proves little. This re-injects known
PQC timing-leak PATTERNS into a private copy of mlkem-native (the real
upstream sources are never modified), rebuilds the deployed image, reruns
the relational test and records whether it noticed:

  leak     a secret-dependent branch (the clangover pattern), a secret-indexed
           table lookup, a KyberSlash-style variable-latency division, an
           early-exit ciphertext comparison, a secret-dependent early
           `continue`: the test must report a divergence
  benign   a dead volatile store, a public-constant branch, a constant-time
           multiplication-based rewrite of the same arithmetic: the test
           must stay clean (specificity)

Each outcome: rediscovered / missed / STALE (pattern no longer matches
exactly once) / ERROR. Leak results also record which channels caught it and
whether a counts-only check (instruction, load and store totals, the
project's earlier CT evidence) would have caught it, so the value of the
extra channels is measured rather than asserted.

clangover (CVE-2024-37880) is a Clang code-generation bug; the Zephyr SDK
uses GCC, so only the source-level pattern is injected, with an empty asm
statement in the branch so the compiler keeps it as a branch.
"""

import json
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

import ct_trace_analysis as cta  # noqa: E402

BASELINE_PATH = SCRIPT_DIR / "ct_leak_rediscovery_baseline.json"
COMPRESS = "ext/mlkem-native/mlkem/src/compress.c"
KEM = "ext/mlkem-native/mlkem/src/kem.c"
TOMSG_LINE = r"msg\[i\] \|= \(uint8_t\)\(t << j\);"
COMPRESS_LINE = (r"uint32_t t = mlk_scalar_compress_d1\("
                 r"a->coeffs\[8 \* i \+ j\]\);")

COPY_PATHS = ("src", "include", "cmake", "CMakeLists.txt", "Kconfig",
              "zephyr", "ext", "tests/ztest_ct_trace")


@dataclass(frozen=True)
class Injection:
    ident: str
    kind: str          # "leak" or "benign"
    description: str
    path: str
    pattern: str
    replacement: str
    allowance: str = ""    # a leak may be missed only with a written reason


INJECTIONS = (
    Injection(
        "L1", "leak",
        "secret-dependent branch on the decrypted message bit "
        "(clangover pattern)",
        COMPRESS, TOMSG_LINE,
        "if (t != 0U) { __asm__ volatile(\"\"); "
        "msg[i] |= (uint8_t)(1u << j); }"),
    Injection(
        "L2", "leak",
        "secret-indexed table lookup on a decrypted coefficient",
        COMPRESS, TOMSG_LINE,
        "msg[i] |= (uint8_t)(t << j); { static const volatile uint8_t "
        "leak_tbl[256] = { 1 }; volatile uint8_t leak_sink = "
        "leak_tbl[(uint32_t)a->coeffs[8 * i + j] & 0xFFu]; "
        "(void)leak_sink; }"),
    Injection(
        "L3", "leak",
        "variable-latency division of a decrypted coefficient "
        "(KyberSlash pattern)",
        COMPRESS, COMPRESS_LINE,
        "static volatile uint32_t leak_q = MLKEM_Q; uint32_t t = "
        "((((uint32_t)a->coeffs[8 * i + j] << 1) + MLKEM_Q / 2) / leak_q)"
        " & 1u;"),
    Injection(
        "L4", "leak",
        "early-exit ciphertext comparison in the Fujisaki-Okamoto check",
        KEM,
        r"fail = mlk_ct_memcmp\(ct, tmp, MLKEM_INDCCA_CIPHERTEXTBYTES\);",
        "fail = (uint8_t)(__builtin_memcmp(ct, tmp, "
        "MLKEM_INDCCA_CIPHERTEXTBYTES) != 0);"),
    Injection(
        "L5", "leak",
        "secret-dependent early continue skips work for zero message bits",
        COMPRESS, TOMSG_LINE,
        "if (t == 0U) { continue; } msg[i] |= (uint8_t)(t << j);"),
    Injection(
        "B1", "benign", "dead volatile store, independent of any secret",
        COMPRESS, TOMSG_LINE,
        "msg[i] |= (uint8_t)(t << j); { volatile uint8_t benign_sink = 0U; "
        "benign_sink = (uint8_t)MLKEM_N; (void)benign_sink; }"),
    Injection(
        "B2", "benign", "branch on a public compile-time constant",
        COMPRESS, TOMSG_LINE,
        "if (MLKEM_N == 256) { __asm__ volatile(\"\"); } "
        "msg[i] |= (uint8_t)(t << j);"),
    Injection(
        "B3", "benign",
        "constant-time multiplication rewrite of the same compression",
        COMPRESS, COMPRESS_LINE,
        "uint32_t t = (((((uint32_t)a->coeffs[8 * i + j] << 1) + 1665u)"
        " * 80635u) >> 28) & 1u;"),
)


def counts_only_clean(regions: list) -> bool:
    """The earlier evidence class: totals of insns/loads/stores per group."""
    groups: dict[int, set] = {}
    for r in regions:
        groups.setdefault(r.label >> cta.GROUP_SHIFT, set()).add(
            (r.insns, r.loads, r.stores))
    return all(len(v) == 1 for v in groups.values())


def apply_injection(tree: Path, inj: Injection) -> str | None:
    target = tree / inj.path
    text = target.read_text(encoding="utf-8")
    matches = re.findall(inj.pattern, text)
    if len(matches) != 1:
        return f"{inj.path}: pattern matched {len(matches)} times"
    target.write_text(re.sub(inj.pattern, lambda _m: inj.replacement, text,
                             count=1), encoding="utf-8")
    return None


def check_patterns(root: Path = MODULE_PATH) -> list[str]:
    """Dry run: every pattern must match the CURRENT sources exactly once."""
    problems = []
    for inj in INJECTIONS:
        text = (root / inj.path).read_text(encoding="utf-8")
        n = len(re.findall(inj.pattern, text))
        if n != 1:
            problems.append(f"{inj.ident} STALE: {inj.path} matched {n}x")
    return problems


def build_base(destination: Path) -> None:
    for relative in COPY_PATHS:
        source = MODULE_PATH / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(
                source, target,
                ignore=lambda d, names: [
                    n for n in names
                    if n in ("__pycache__", ".git") or
                    (n.startswith("build") and (Path(d) / n).is_dir())])
        else:
            shutil.copy2(source, target)


def classify(inj: Injection, analysis, regions: list) -> tuple[str, str]:
    counts_clean = counts_only_clean(regions)
    channels = ",".join(ch for ch in cta.CHANNELS
                        if analysis.distinct[ch] > 1) or "none"
    detail = (f"channels={channels} counts_only="
              f"{'clean' if counts_clean else 'diverged'} "
              f"ndiv={sorted(analysis.ndiv)}")
    if inj.kind == "leak":
        if not analysis.clean:
            return "rediscovered", detail
        return ("allowed", inj.allowance) if inj.allowance else \
            ("missed", detail)
    if analysis.clean:
        return "ok", detail
    return "false_positive", detail


def judge(outcomes: list, baseline: dict) -> tuple[list[str], str]:
    problems = []
    leaks = [o for o in outcomes if o[0].kind == "leak"]
    benign = [o for o in outcomes if o[0].kind == "benign"]
    found = sum(1 for _, s, _, _ in leaks if s == "rediscovered")
    flagged = sum(1 for _, s, _, _ in benign if s == "false_positive")
    counts_miss = sum(
        1 for _, s, d, _ in leaks
        if s == "rediscovered" and "counts_only=clean" in d)
    for inj, status, note, _ in outcomes:
        if status in ("STALE", "ERROR", "missed", "false_positive"):
            problems.append(f"{inj.ident} {status}: {note}")
    if found < baseline.get("leaks_rediscovered_min", len(leaks)):
        problems.append(f"rediscovered {found} below baseline "
                        f"{baseline.get('leaks_rediscovered_min')}")
    if flagged > baseline.get("benign_false_positives_max", 0):
        problems.append(f"{flagged} benign change(s) flagged")
    marker = (f"PQCP_CT_TRACE_REDISCOVERY "
              f"{'FAIL' if problems else 'PASS'} leaks={found}/{len(leaks)} "
              f"benign_flagged={flagged}/{len(benign)} "
              f"missed_by_counts_only={counts_miss}/{found}")
    return problems, marker


def load_baseline() -> dict:
    if BASELINE_PATH.exists():
        return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    return {}


def rediscover(run_trace, opt: str, only: set | None = None) -> int:
    """`run_trace(tree, build_dir, outfile, opt) -> trace text`."""
    problems = check_patterns()
    if problems:
        print("\n".join(f"[ct-leak] {p}" for p in problems))
        return 1
    outcomes = []
    with tempfile.TemporaryDirectory(prefix="pqcp-ct-leak-") as tmp:
        scratch = Path(tmp)
        base = scratch / "base"
        build_base(base)
        for inj in INJECTIONS:
            if only and inj.ident not in only:
                continue
            tree = scratch / inj.ident
            shutil.copytree(base, tree, symlinks=True)
            problem = apply_injection(tree, inj)
            if problem:
                outcomes.append((inj, "STALE", problem, None))
                continue
            try:
                text = run_trace(tree, scratch / f"b-{inj.ident}",
                                 scratch / f"t-{inj.ident}.txt", opt)
                regions = cta.parse_trace(text)
                analysis = cta.analyze(regions)
                status, note = classify(inj, analysis, regions)
            except Exception as exc:  # noqa: BLE001 - reported, not hidden
                status, note = "ERROR", str(exc)[-300:]
            print(f"[ct-leak] {status:14s} {inj.ident} {inj.description} "
                  f"({note})", flush=True)
            outcomes.append((inj, status, note, None))
            shutil.rmtree(tree, ignore_errors=True)
            shutil.rmtree(scratch / f"b-{inj.ident}", ignore_errors=True)
    problems, marker = judge(outcomes, load_baseline())
    print(marker)
    for problem in problems:
        print(f"[ct-leak] FAIL: {problem}")
    return 1 if problems else 0
