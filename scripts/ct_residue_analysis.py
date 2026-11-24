#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Memory residue below the caller's stack pointer, compared across secrets.

Input is a trace written by the pqcp_ct_trace plugin with `residue=1`. Regions
of one group share every public input and differ only in the secret, so a
stack word whose value differs inside a group depends on the secret. Words are
attributed to the function of their last writer. Output buffers are global and
are not part of the window.
"""

import re
import sys
from dataclasses import dataclass, field

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import ct_trace_analysis as cta  # noqa: E402

WORD_RE = re.compile(
    r"^PQCP_CT_RESIDUE region=(\d+) addr=([0-9a-f]+) val=([0-9a-f]{8}) "
    r"pc=([0-9a-f]+)$")
REGION_RE = re.compile(
    r"^PQCP_CT_RESIDUE_REGION region=(\d+) sp=([0-9a-f]+) words=(\d+) "
    r"nonzero=(\d+) overflow=(\d)$")


@dataclass
class Residue:
    groups: int
    regions: int
    nonzero_mean: float
    differing_max: int
    differing_mean: float
    overflow: bool
    by_pc: dict = field(default_factory=dict)   # last-writer pc -> words


def parse(text: str):
    words: dict[int, dict[int, tuple]] = {}
    overflow = False
    seen = 0
    for raw in text.splitlines():
        line = raw.strip()
        m = WORD_RE.match(line)
        if m:
            words.setdefault(int(m[1]), {})[int(m[2], 16)] = (
                int(m[3], 16), int(m[4], 16))
            continue
        m = REGION_RE.match(line)
        if m:
            seen += 1
            overflow = overflow or m[5] == "1"
    if seen == 0:
        raise cta.TraceError("trace has no PQCP_CT_RESIDUE_REGION lines")
    return words, overflow


def analyze(text: str, exclude=()) -> Residue:
    """`exclude` is a list of (low, high) address ranges to ignore, for
    example the output buffers of the traced call."""
    regions = cta.parse_trace(text)
    words, overflow = parse(text)
    if exclude:
        words = {r: {a: v for a, v in w.items()
                     if not any(lo <= a < hi for lo, hi in exclude)}
                 for r, w in words.items()}
    groups: dict[int, list[int]] = {}
    for r in regions:
        groups.setdefault(r.label >> cta.GROUP_SHIFT, []).append(r.index)
    differing, nonzero, by_pc = [], [], {}
    for members in groups.values():
        addrs = set()
        for idx in members:
            addrs |= set(words.get(idx, {}))
        diff = 0
        for a in addrs:
            vals = {words.get(idx, {}).get(a, (0, 0))[0] for idx in members}
            if len(vals) > 1:
                diff += 1
                writers = {words.get(idx, {}).get(a, (0, 0))[1]
                           for idx in members} - {0}
                for pc in writers:
                    by_pc[pc] = by_pc.get(pc, 0) + 1
        differing.append(diff)
        nonzero.extend(len(words.get(idx, {})) for idx in members)
    return Residue(
        groups=len(groups), regions=len(regions),
        nonzero_mean=sum(nonzero) / max(len(nonzero), 1),
        differing_max=max(differing, default=0),
        differing_mean=sum(differing) / max(len(differing), 1),
        overflow=overflow, by_pc=by_pc)


SK_RE = re.compile(r"PQCP_CT_SK key=(\d+) ([0-9a-f]+)")


def key_words(device_log: str) -> dict:
    """key index -> set of usable 32-bit words of the secret key bytes."""
    result = {}
    for m in SK_RE.finditer(device_log):
        raw = bytes.fromhex(m[2])
        ws = {int.from_bytes(raw[i:i + 4], "little")
              for i in range(0, len(raw) - 3, 4)}
        # drop words that match by chance or are common constants
        result[int(m[1])] = {w for w in ws if w >= 0x10000 and w != 0xffffffff}
    return result


def key_matches(text: str, device_log: str, exclude=()) -> dict:
    """Per region, the residue words that equal a word of that key, with the
    last writing pc. Regions are labelled (key << 8) | ciphertext."""
    regions = cta.parse_trace(text)
    words, _ = parse(text)
    keys = key_words(device_log)
    found = {}
    for r in regions:
        dictionary = keys.get(r.label >> cta.GROUP_SHIFT, set())
        hits = [(a, v, pc) for a, (v, pc) in words.get(r.index, {}).items()
                if v in dictionary and
                not any(lo <= a < hi for lo, hi in exclude)]
        found[r.index] = (r.label, hits)
    return found


def format_key_marker(found: dict, alg: str, opt: str, target: str,
                      functions: dict | None = None) -> str:
    fns = functions or {}
    total = sum(len(h) for _, h in found.values())
    regions_with = sum(1 for _, h in found.values() if h)
    writers: dict[str, int] = {}
    for _, hits in found.values():
        for _, _, pc in hits:
            writers[fns.get(pc, "?")] = writers.get(fns.get(pc, "?"), 0) + 1
    top = ",".join(f"{k}:{v}" for k, v in
                   sorted(writers.items(), key=lambda kv: -kv[1])[:4]) or "none"
    return (f"PQCP_CT_TRACE_RESIDUE_KEY alg={alg} target={target} opt={opt} "
            f"regions={len(found)} regions_with_key_words={regions_with} "
            f"key_word_hits={total} writers={top}")


SS_RE = re.compile(r"PQCP_CT_SS label=(\d+) ([0-9a-f]+)")


def ss_matches(text: str, device_log: str, exclude=()) -> dict:
    """Per region, the residue words equal to a word of that region's own
    shared secret (the output of the call)."""
    regions = cta.parse_trace(text)
    words, _ = parse(text)
    ss = {}
    for m in SS_RE.finditer(device_log):
        raw = bytes.fromhex(m[2])
        ss[int(m[1])] = {int.from_bytes(raw[i:i + 4], "little")
                         for i in range(0, len(raw) - 3, 4)}
    return {r.index: (r.label,
                      [(a, v, pc) for a, (v, pc) in
                       words.get(r.index, {}).items()
                       if v in ss.get(r.label, set()) and v >= 0x10000 and
                       not any(lo <= a < hi for lo, hi in exclude)])
            for r in regions}


def format_marker(r: Residue, alg: str, opt: str, target: str,
                  functions: dict | None = None) -> str:
    fns = functions or {}
    top: dict[str, int] = {}
    for pc, n in r.by_pc.items():
        top[fns.get(pc, "?")] = top.get(fns.get(pc, "?"), 0) + n
    best = ",".join(f"{k}:{v}" for k, v in
                    sorted(top.items(), key=lambda kv: -kv[1])[:4]) or "none"
    return (f"PQCP_CT_TRACE_RESIDUE alg={alg} target={target} opt={opt} "
            f"groups={r.groups} regions={r.regions} "
            f"nonzero_words_mean={r.nonzero_mean:.0f} "
            f"differing_words_max={r.differing_max} "
            f"differing_words_mean={r.differing_mean:.1f} "
            f"overflow={int(r.overflow)} top_writers={best}")
