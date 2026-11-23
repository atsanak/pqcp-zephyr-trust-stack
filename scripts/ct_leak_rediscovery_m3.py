#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Sensitivity/specificity of the Cortex-M3 operand-latency channel.

Re-injects constant-time-source-looking changes that nevertheless feed secret
data into a variable-latency Thumb-2 instruction, into a private copy of
mlkem-native (the real sources are never modified), rebuilds the mps2/an385
image, reruns the relational test and records whether the new channel
noticed:

  leak    a runtime-divisor UDIV and SDIV of a decrypted coefficient (the
          KyberSlash pattern on a core whose divider is variable-latency) and
          a UMULL whose operand magnitude follows a decrypted message bit.
          None of them changes a branch, an address or an instruction count,
          so the address-level channels cannot see them: the result records
          how many leaks those channels would have missed.
  benign  a UDIV on public loop-index operands, a UMULL of a secret
          coefficient by a small constant (both operands stay below 65536,
          so the documented M3 predicate is constant), and a dead store. The
          verdict must stay clean; the second is also expected to raise the
          candidate-site inventory (exact operands vary).
"""

import shutil
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import ct_leak_rediscovery as base  # noqa: E402
import ct_trace_analysis as cta  # noqa: E402

BASELINE_PATH = SCRIPT_DIR / "ct_leak_rediscovery_m3_baseline.json"
Injection = base.Injection
COMPRESS = base.COMPRESS
TOMSG_LINE = base.TOMSG_LINE
COMPRESS_LINE = base.COMPRESS_LINE

INJECTIONS = (
    Injection(
        "V1", "leak",
        "UDIV of a decrypted coefficient by a runtime divisor "
        "(variable-latency divider, KyberSlash pattern)",
        COMPRESS, COMPRESS_LINE,
        "static volatile uint32_t leak_q = MLKEM_Q; uint32_t t = "
        "((((uint32_t)a->coeffs[8 * i + j] << 1) + MLKEM_Q / 2) / leak_q)"
        " & 1u;"),
    Injection(
        "V2", "leak",
        "SDIV of a decrypted coefficient by a runtime divisor",
        COMPRESS, COMPRESS_LINE,
        "static volatile int32_t leak_q = MLKEM_Q; uint32_t t = "
        "(uint32_t)((((int32_t)a->coeffs[8 * i + j] << 1) + MLKEM_Q / 2) "
        "/ leak_q) & 1u;"),
    Injection(
        "V3", "leak",
        "UMULL whose operand magnitude follows a decrypted message bit",
        COMPRESS, COMPRESS_LINE,
        "uint32_t t = mlk_scalar_compress_d1(a->coeffs[8 * i + j]); "
        "{ static volatile uint32_t leak_m = 3U; "
        "static volatile uint32_t leak_sink; "
        "uint64_t leak_p = (uint64_t)(1u + (0x12345677u & (0u - t))) * "
        "leak_m; leak_sink = (uint32_t)(leak_p >> 32); }"),
    Injection(
        "N1", "benign",
        "UDIV on public loop-index operands only",
        COMPRESS, TOMSG_LINE,
        "msg[i] |= (uint8_t)(t << j); { static volatile uint32_t d = 7U; "
        "static volatile uint32_t sink; "
        "sink = ((uint32_t)i * 8U + (uint32_t)j + 100U) / d; }"),
    Injection(
        "N2", "benign",
        "UMULL of a secret coefficient by a small constant (both operands "
        "below 65536: documented M3 predicate constant)",
        COMPRESS, TOMSG_LINE,
        "msg[i] |= (uint8_t)(t << j); { static volatile uint32_t m = 3U; "
        "static volatile uint32_t sink; "
        "uint64_t p = (uint64_t)(uint32_t)(uint16_t)a->coeffs[8 * i + j] "
        "* m; sink = (uint32_t)(p >> 32); }"),
    Injection(
        "N3", "benign", "dead volatile store, independent of any secret",
        COMPRESS, TOMSG_LINE,
        "msg[i] |= (uint8_t)(t << j); { volatile uint8_t benign_sink = 0U; "
        "benign_sink = (uint8_t)MLKEM_N; (void)benign_sink; }"),
)


def check_patterns(root: Path = base.MODULE_PATH) -> list[str]:
    problems = []
    for inj in INJECTIONS:
        text = (root / inj.path).read_text(encoding="utf-8")
        n = len(base.re.findall(inj.pattern, text))
        if n != 1:
            problems.append(f"{inj.ident} STALE: {inj.path} matched {n}x")
    return problems


def classify(inj: Injection, text: str) -> tuple[str, str]:
    regions = cta.parse_trace(text)
    analysis = cta.analyze_vlat(regions, cta.parse_vlat(text))
    detail = (f"fail_sites={len(analysis.fail_sites)} "
              f"candidates={len(analysis.candidate_sites)} "
              f"address_channels={'clean' if analysis.base_clean else 'diverged'}")
    if inj.kind == "leak":
        return ("rediscovered" if not analysis.clean else "missed"), detail
    return ("ok" if analysis.clean else "false_positive"), detail


def judge(outcomes: list, baseline: dict) -> tuple[list[str], str]:
    problems = []
    leaks = [o for o in outcomes if o[0].kind == "leak"]
    benign = [o for o in outcomes if o[0].kind == "benign"]
    found = sum(1 for _, s, _ in leaks if s == "rediscovered")
    flagged = sum(1 for _, s, _ in benign if s == "false_positive")
    addr_miss = sum(1 for _, s, d in leaks
                    if s == "rediscovered" and "address_channels=clean" in d)
    for inj, status, note in outcomes:
        if status in ("STALE", "ERROR", "missed", "false_positive"):
            problems.append(f"{inj.ident} {status}: {note}")
    if found < baseline.get("leaks_rediscovered_min", len(leaks)):
        problems.append(f"rediscovered {found} below baseline "
                        f"{baseline.get('leaks_rediscovered_min')}")
    if flagged > baseline.get("benign_false_positives_max", 0):
        problems.append(f"{flagged} benign change(s) flagged")
    marker = (f"PQCP_CT_TRACE_VLAT_REDISCOVERY "
              f"{'FAIL' if problems else 'PASS'} leaks={found}/{len(leaks)} "
              f"benign_flagged={flagged}/{len(benign)} "
              f"missed_by_address_channels={addr_miss}/{found}")
    return problems, marker


def load_baseline() -> dict:
    import json  # noqa: PLC0415
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
    with tempfile.TemporaryDirectory(prefix="pqcp-ct-leak-m3-") as tmp:
        scratch = Path(tmp)
        tree_base = scratch / "base"
        base.build_base(tree_base)
        for inj in INJECTIONS:
            if only and inj.ident not in only:
                continue
            tree = scratch / inj.ident
            shutil.copytree(tree_base, tree, symlinks=True)
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
    problems, marker = judge(outcomes, load_baseline())
    print(marker)
    for problem in problems:
        print(f"[ct-leak] FAIL: {problem}")
    return 1 if problems else 0
