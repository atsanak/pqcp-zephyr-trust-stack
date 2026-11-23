#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Sensitivity and specificity of the declassification-aware ML-DSA test.

Same method as ct_leak_rediscovery.py (re-inject known leak PATTERNS into a
private copy of mldsa-native, rebuild, rerun, classify), applied to the
segment relation of scripts/ct_trace_analysis.py instead of the whole-region
relation. Leaks sit on the secret-handling path of signing (the product
c*s1 and the sum z = y + c*s1); benign changes are independent of any secret.
The counts-only column asks whether a totals-only check (instructions, loads,
stores per comparable segment) would have caught the same leak.
"""

import json
import shutil
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import ct_leak_rediscovery as base  # noqa: E402
import ct_trace_analysis as cta  # noqa: E402

BASELINE_PATH = SCRIPT_DIR / "ct_leak_rediscovery_mldsa_baseline.json"
POLY = "ext/mldsa-native/mldsa/src/poly.c"
COPY_PATHS = tuple(p if p != "tests/ztest_ct_trace" else
                   "tests/ztest_ct_trace_mldsa" for p in base.COPY_PATHS)

PW_LINE = (r"c->coeffs\[i\] = mld_montgomery_reduce\("
           r"\(int64_t\)a->coeffs\[i\] \* b->coeffs\[i\]\);")
ADD_LINE = r"r->coeffs\[i\] = r->coeffs\[i\] \+ b->coeffs\[i\];"
RED_LINE = r"a->coeffs\[i\] = mld_reduce32\(a->coeffs\[i\]\);"

INJECTIONS = (
    base.Injection(
        "D1", "leak",
        "secret-dependent branch on a coefficient of c*s1 "
        "(clangover pattern)",
        POLY, PW_LINE,
        "c->coeffs[i] = mld_montgomery_reduce("
        "(int64_t)a->coeffs[i] * b->coeffs[i]); "
        "if ((c->coeffs[i] & 1) != 0) { static volatile uint32_t leak_br; "
        "leak_br = 1U; }"),
    base.Injection(
        "D2", "leak",
        "secret-indexed table lookup on a coefficient of z = y + c*s1",
        POLY, ADD_LINE,
        "r->coeffs[i] = r->coeffs[i] + b->coeffs[i]; "
        "{ static const volatile uint8_t leak_tbl[256] = { 1 }; "
        "volatile uint8_t leak_sink = "
        "leak_tbl[(uint32_t)r->coeffs[i] & 0xFFu]; (void)leak_sink; }"),
    base.Injection(
        "D3", "leak",
        "variable-latency division of a z coefficient "
        "(KyberSlash pattern)",
        POLY, ADD_LINE,
        "{ static volatile int32_t leak_d = 7; "
        "r->coeffs[i] = r->coeffs[i] + b->coeffs[i]; "
        "r->coeffs[i] = (r->coeffs[i] / leak_d) * leak_d + "
        "(r->coeffs[i] % leak_d); }"),
    base.Injection(
        "D4", "leak",
        "secret-dependent early continue skips work for zero coefficients",
        POLY, RED_LINE,
        "if (a->coeffs[i] == 0) { continue; } "
        "a->coeffs[i] = mld_reduce32(a->coeffs[i]);"),
    base.Injection(
        "E1", "benign", "dead volatile store, independent of any secret",
        POLY, PW_LINE,
        "c->coeffs[i] = mld_montgomery_reduce("
        "(int64_t)a->coeffs[i] * b->coeffs[i]); "
        "{ volatile uint8_t benign_sink = 0U; "
        "benign_sink = (uint8_t)MLDSA_N; (void)benign_sink; }"),
    base.Injection(
        "E2", "benign", "branch on a public compile-time constant",
        POLY, ADD_LINE,
        "if (MLDSA_N == 256) { __asm__ volatile(\"\"); } "
        "r->coeffs[i] = r->coeffs[i] + b->coeffs[i];"),
    base.Injection(
        "E3", "benign", "branch on the public loop index",
        POLY, RED_LINE,
        "if (i == 7U) { __asm__ volatile(\"\"); } "
        "a->coeffs[i] = mld_reduce32(a->coeffs[i]);"),
)


def counts_only_clean(analysis_inputs: tuple) -> bool:
    """Totals of (insns, loads, stores) agree inside every comparable class.

    Uses the segment lines, which carry insns/loads/stores.
    """
    text = analysis_inputs[0]
    regions = analysis_inputs[1]
    groups: dict = {}
    for r in regions:
        groups.setdefault(r.label >> cta.GROUP_SHIFT, []).append(r)
    segs = {}
    for line in text.splitlines():
        m = cta.SEG_RE.match(line.strip())
        if m:
            g = m.groups()
            segs.setdefault(int(g[0]), []).append(
                (int(g[2]), int(g[3]), int(g[4]), (int(g[5]), int(g[6]),
                                                    int(g[7]))))
    for members in groups.values():
        buckets: dict = {}
        for r in members:
            prefix: tuple = ()
            for site, length, cls, totals in segs[r.index]:
                buckets.setdefault(prefix, []).append((site, totals))
                prefix = prefix + ((site, length, cls),)
        for entries in buckets.values():
            if len({e for e in entries}) > 1 and len(entries) > 1:
                return False
    return True


def classify(inj: base.Injection, text: str) -> tuple[str, str]:
    regions = cta.parse_trace(text)
    analysis = cta.analyze_declassified(regions, cta.parse_segments(text))
    counts_clean = counts_only_clean((text, regions))
    kinds = sorted({v[0] for v in analysis.violations})
    detail = (f"violations={len(analysis.violations)} "
              f"channels={','.join(kinds) or 'none'} "
              f"counts_only={'clean' if counts_clean else 'diverged'} "
              f"coverage_pct={100.0 * analysis.coverage:.1f}")
    if inj.kind == "leak":
        return ("rediscovered", detail) if analysis.violations else \
            ("missed", detail)
    return ("ok", detail) if analysis.clean else ("false_positive", detail)


def check_patterns() -> list[str]:
    problems = []
    for inj in INJECTIONS:
        text = (base.MODULE_PATH / inj.path).read_text(encoding="utf-8")
        n = len(base.re.findall(inj.pattern, text))
        if n != 1:
            problems.append(f"{inj.ident} STALE: {inj.path} matched {n}x")
    return problems


def judge(outcomes: list) -> tuple[list[str], str]:
    baseline = (json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
                if BASELINE_PATH.exists() else {})
    problems = []
    leaks = [o for o in outcomes if o[0].kind == "leak"]
    benign = [o for o in outcomes if o[0].kind == "benign"]
    found = sum(1 for _, s, _ in leaks if s == "rediscovered")
    flagged = sum(1 for _, s, _ in benign if s == "false_positive")
    counts_miss = sum(1 for _, s, d in leaks
                      if s == "rediscovered" and "counts_only=clean" in d)
    for inj, status, note in outcomes:
        if status in ("STALE", "ERROR", "missed", "false_positive"):
            problems.append(f"{inj.ident} {status}: {note}")
    if found < baseline.get("leaks_rediscovered_min", len(leaks)):
        problems.append(f"rediscovered {found} below baseline "
                        f"{baseline.get('leaks_rediscovered_min')}")
    if flagged > baseline.get("benign_false_positives_max", 0):
        problems.append(f"{flagged} benign change(s) flagged")
    marker = (f"PQCP_CT_TRACE_DECLASS_REDISCOVERY "
              f"{'FAIL' if problems else 'PASS'} leaks={found}/{len(leaks)} "
              f"benign_flagged={flagged}/{len(benign)} "
              f"missed_by_counts_only={counts_miss}/{found}")
    return problems, marker


def rediscover(run_trace, opt: str, only: set | None = None) -> int:
    problems = check_patterns()
    if problems:
        print("\n".join(f"[ct-leak] {p}" for p in problems))
        return 1
    outcomes = []
    with tempfile.TemporaryDirectory(prefix="pqcp-ct-dsa-leak-") as tmp:
        scratch = Path(tmp)
        root = scratch / "base"
        base.build_base(root, COPY_PATHS)
        for inj in INJECTIONS:
            if only and inj.ident not in only:
                continue
            tree = scratch / inj.ident
            shutil.copytree(root, tree, symlinks=True)
            problem = base.apply_injection(tree, inj)
            if problem:
                outcomes.append((inj, "STALE", problem))
                continue
            try:
                text = run_trace(tree, scratch / f"b-{inj.ident}",
                                 scratch / f"t-{inj.ident}.txt", opt)
                status, note = classify(inj, text)
            except Exception as exc:  # noqa: BLE001 - reported, not hidden
                status, note = "ERROR", str(exc)[-300:]
            print(f"[ct-leak] {status:14s} {inj.ident} {inj.description} "
                  f"({note})", flush=True)
            outcomes.append((inj, status, note))
            shutil.rmtree(tree, ignore_errors=True)
            shutil.rmtree(scratch / f"b-{inj.ident}", ignore_errors=True)
    problems, marker = judge(outcomes)
    print(marker)
    for problem in problems:
        print(f"[ct-leak] FAIL: {problem}")
    return 1 if problems else 0
