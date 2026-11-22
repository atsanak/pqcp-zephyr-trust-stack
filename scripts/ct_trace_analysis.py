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


# ---------------------------------------------------------------------------
# Declassification-aware analysis
#
# Signing algorithms with rejection loops legitimately leak (through timing)
# the outcome of their accept/reject decisions, and every other secret ->
# public flow is annotated upstream. The plugin cuts each region into
# segments at those events. The relation checked is relational noninterference
# modulo declassification: two executions that agree on EVERY declassified
# value so far (same sites, lengths and value classes) must run the next
# segment identically on every channel AND reach the same next event site.
# Anything else is secret-dependent behaviour the annotations do not explain.
# ---------------------------------------------------------------------------

SEG_RE = re.compile(
    r"PQCP_CT_SEG region=(\d+) seq=(\d+) site=(\d+) len=(\d+) cls=(\d+) "
    r"insns=(\d+) loads=(\d+) stores=(\d+) ndiv=(\d+) h_pc=([0-9a-f]{16}) "
    r"h_addr=([0-9a-f]{16}) h_line=([0-9a-f]{16}) h_div=([0-9a-f]{16})$")


@dataclass(frozen=True)
class Segment:
    region: int
    seq: int
    site: int       # call site of the closing event (0 = region tail)
    length: int
    cls: int        # value class of what was declassified
    insns: int
    fingerprints: dict = field(default_factory=dict)


def parse_segments(text: str) -> dict:
    """Return {region index: [Segment in seq order]}."""
    by_region: dict[int, list] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("PQCP_CT_SEG"):
            continue
        m = SEG_RE.match(line)
        if not m:
            raise TraceError(f"malformed segment line: {line!r}")
        g = m.groups()
        by_region.setdefault(int(g[0]), []).append(Segment(
            region=int(g[0]), seq=int(g[1]), site=int(g[2]),
            length=int(g[3]), cls=int(g[4]), insns=int(g[5]),
            fingerprints={"pc": g[9], "addr": g[10], "line": g[11],
                          "div": g[12]}))
    for region, segs in by_region.items():
        if [s.seq for s in segs] != list(range(len(segs))):
            raise TraceError(f"region {region}: segment seq out of order")
        if segs[-1].site != 0:
            raise TraceError(f"region {region}: missing tail segment")
    return by_region


@dataclass
class DeclassAnalysis:
    regions: int
    groups: int
    segments: int            # total segments observed
    testable: int            # segments whose prefix class has >= 2 members
    classes: int             # distinct (group, prefix) classes that are testable
    singleton: int           # segments with no peer (public-data processing)
    violations: list         # [(kind, group, region, seq, detail)]
    sites: int               # distinct declassification call sites seen
    max_events: int          # most events in one region
    iterations_seen: set     # distinct event counts per region

    @property
    def clean(self) -> bool:
        return not self.violations and self.testable > 0

    @property
    def coverage(self) -> float:
        return self.testable / self.segments if self.segments else 0.0


def analyze_declassified(regions: list[Region],
                         segments: dict) -> DeclassAnalysis:
    if not regions:
        raise TraceError("no regions captured")
    missing = [r.index for r in regions if r.index not in segments]
    if missing:
        raise TraceError(f"regions without segments: {missing[:5]}")
    by_group: dict[int, list] = {}
    for r in regions:
        by_group.setdefault(r.label >> GROUP_SHIFT, []).append(r)

    violations: list = []
    total = testable = classes = 0
    sites: set = set()
    max_events = 0
    event_counts: set = set()
    for group, members in sorted(by_group.items()):
        buckets: dict[tuple, list] = {}
        for r in members:
            segs = segments[r.index]
            event_counts.add(len(segs) - 1)
            max_events = max(max_events, len(segs) - 1)
            prefix: tuple = ()
            for seg in segs:
                sites.add(seg.site)
                buckets.setdefault(prefix, []).append((r, seg))
                prefix = prefix + ((seg.site, seg.length, seg.cls),)
        for prefix, entries in buckets.items():
            total += len(entries)
            if len(entries) < 2:
                continue
            testable += len(entries)
            classes += 1
            ref_r, ref = entries[0]
            for r, seg in entries[1:]:
                if (seg.site, seg.length) != (ref.site, ref.length):
                    violations.append(
                        ("control", group, r.index, seg.seq,
                         f"next event site {seg.site}/{seg.length} != "
                         f"{ref.site}/{ref.length} (region {ref_r.index})"))
                    continue
                for ch in CHANNELS:
                    if seg.fingerprints[ch] != ref.fingerprints[ch]:
                        violations.append(
                            (ch, group, r.index, seg.seq,
                             f"{seg.fingerprints[ch]} != "
                             f"{ref.fingerprints[ch]} (region {ref_r.index})"))
    return DeclassAnalysis(
        regions=len(regions), groups=len(by_group), segments=total,
        testable=testable, classes=classes, singleton=total - testable,
        violations=violations, sites=len(sites - {0}),
        max_events=max_events, iterations_seen=event_counts)


def format_declass_marker(a: DeclassAnalysis, alg: str, opt: str) -> str:
    status = "PASS" if a.clean else "FAIL"
    return (f"PQCP_CT_TRACE_DECLASS {status} alg={alg} opt={opt} "
            f"regions={a.regions} groups={a.groups} segments={a.segments} "
            f"testable={a.testable} classes={a.classes} sites={a.sites} "
            f"violations={len(a.violations)} "
            f"coverage_pct={100.0 * a.coverage:.1f}")
