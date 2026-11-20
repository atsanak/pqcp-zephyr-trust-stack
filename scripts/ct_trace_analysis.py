#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Relational analysis of pqcp_ct_trace plugin output.

A run executes the same cryptographic operation under different secrets
(and ciphertext classes). The firmware promises that nothing observable on
the modelled channels depends on the secret, so every region must produce an
identical fingerprint on every channel. This module parses the plugin's
region lines, groups them, and reports per channel how many distinct
fingerprints were seen.

  group      label >> 8: regions of one group share the public inputs (one
             key); the relation is checked WITHIN each group. Variation
             across groups (e.g. rejection sampling of the public matrix)
             is reported as `cross_group_distinct`, not as a failure.
  distinct   number of different fingerprints within a group on the channel
             (the maximum over groups)
  bits       log2(distinct): a lower bound, in bits, on what the observation
             model distinguishes; 0 means nothing was distinguished
  miss_bound with zero divergence over N regions, the 95% upper confidence
             bound that a further random secret would diverge (rule of
             three: 3/N)

Pure stdlib; no I/O besides reading the text it is given.
"""

import math
import re
from dataclasses import dataclass, field

CHANNELS = ("pc", "addr", "line", "div")
GROUP_SHIFT = 8
LINE_RE = re.compile(
    r"PQCP_CT_TRACE region=(\d+) label=(\d+) insns=(\d+) loads=(\d+) "
    r"stores=(\d+) ndiv=(\d+) h_pc=([0-9a-f]{16}) h_addr=([0-9a-f]{16}) "
    r"h_line=([0-9a-f]{16}) h_div=([0-9a-f]{16})$")
DONE_RE = re.compile(r"PQCP_CT_TRACE done regions=(\d+)$")


class TraceError(ValueError):
    """The plugin output is malformed or internally inconsistent."""


@dataclass(frozen=True)
class Region:
    index: int
    label: int
    insns: int
    loads: int
    stores: int
    ndiv: int
    fingerprints: dict = field(default_factory=dict)


def parse_trace(text: str) -> list[Region]:
    regions: list[Region] = []
    done = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("PQCP_CT_TRACE"):
            continue
        m = DONE_RE.match(line)
        if m:
            done = int(m.group(1))
            continue
        m = LINE_RE.match(line)
        if not m:
            raise TraceError(f"malformed trace line: {line!r}")
        g = m.groups()
        regions.append(Region(
            index=int(g[0]), label=int(g[1]), insns=int(g[2]),
            loads=int(g[3]), stores=int(g[4]), ndiv=int(g[5]),
            fingerprints={"pc": g[6], "addr": g[7], "line": g[8],
                          "div": g[9]}))
    if done is None:
        raise TraceError("missing 'done' line: plugin did not exit cleanly")
    if done != len(regions):
        raise TraceError(
            f"done line says {done} regions, parsed {len(regions)}")
    if [r.index for r in regions] != list(range(len(regions))):
        raise TraceError("region indices are not 0..n-1 in order")
    return regions


@dataclass
class Analysis:
    regions: int
    labels: dict
    groups: int
    distinct: dict          # channel -> max distinct fingerprints in a group
    cross_group_distinct: dict  # channel -> distinct over all regions
    bits: dict              # channel -> log2(distinct)
    miss_bound_95: float | None
    divergent: list         # [(channel, region index, fingerprint)] outliers
    instructions: set       # distinct insns counts
    ndiv: set               # distinct div counts

    @property
    def clean(self) -> bool:
        return all(count == 1 for count in self.distinct.values())

    @property
    def worst_bits(self) -> float:
        return max(self.bits.values()) if self.bits else 0.0


def analyze(regions: list[Region]) -> Analysis:
    if not regions:
        raise TraceError("no regions captured")
    labels: dict[int, int] = {}
    for r in regions:
        labels[r.label] = labels.get(r.label, 0) + 1
    distinct = {}
    cross = {}
    bits = {}
    divergent = []
    by_group: dict[int, list] = {}
    for r in regions:
        by_group.setdefault(r.label >> GROUP_SHIFT, []).append(r)
    for ch in CHANNELS:
        cross[ch] = len({r.fingerprints[ch] for r in regions})
        worst = 1
        for members in by_group.values():
            counts: dict[str, int] = {}
            for r in members:
                v = r.fingerprints[ch]
                counts[v] = counts.get(v, 0) + 1
            worst = max(worst, len(counts))
            if len(counts) > 1:
                majority = max(counts, key=counts.get)
                for r in members:
                    if r.fingerprints[ch] != majority:
                        divergent.append((ch, r.index, r.fingerprints[ch]))
        distinct[ch] = worst
        bits[ch] = math.log2(worst)
    clean = all(c == 1 for c in distinct.values())
    return Analysis(
        regions=len(regions), labels=labels, groups=len(by_group),
        distinct=distinct, cross_group_distinct=cross, bits=bits,
        miss_bound_95=(3.0 / len(regions)) if clean else None,
        divergent=divergent,
        instructions={r.insns for r in regions},
        ndiv={r.ndiv for r in regions})


def format_marker(analysis: Analysis, alg: str, opt: str) -> str:
    status = "PASS" if analysis.clean else "FAIL"
    distinct = max(analysis.distinct.values())
    bound = (f"{analysis.miss_bound_95:.3f}"
             if analysis.miss_bound_95 is not None else "na")
    return (f"PQCP_CT_TRACE {status} alg={alg} opt={opt} "
            f"regions={analysis.regions} groups={analysis.groups} "
            f"channels={','.join(CHANNELS)} "
            f"distinct={distinct} bits={analysis.worst_bits:.2f} "
            f"miss_bound_95={bound}")
