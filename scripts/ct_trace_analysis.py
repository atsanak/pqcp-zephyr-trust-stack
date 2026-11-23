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
    r"h_addr=([0-9a-f]{16}) h_line=([0-9a-f]{16}) h_div=([0-9a-f]{16})"
    r"(?: nvl=(\d+) h_vdiv=([0-9a-f]{16}) h_vmul=([0-9a-f]{16}) "
    r"h_vop=([0-9a-f]{16})(?: h_vcm=([0-9a-f]{16}))?)?$")
# Cortex-M cores differ in which instruction classes have operand-dependent
# latency: an M3's long multiplies terminate early (ARM DDI 0337); an M4's
# are single-cycle (DDI 0439). Both share the variable-latency divider.
CORE_CHANNELS = {
    "cortex-m3": ("pc", "addr", "line", "vdiv", "vmul"),
    "cortex-m4": ("pc", "addr", "line", "vdiv"),
    # Same core, second latency model (CMEmu, see ct_latency_models.py): one
    # stream carries the modelled latency class of every variable-latency
    # instruction, divides and long multiplies alike.
    "cortex-m3-cmemu": ("pc", "addr", "line", "vcm"),
}


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
        if g[13] is not None:
            by_region[int(g[0])][-1].fingerprints.update(
                {"vdiv": g[14], "vmul": g[15], "vop": g[16]})
            if g[17] is not None:
                by_region[int(g[0])][-1].fingerprints["vcm"] = g[17]
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
    candidate_segments: int = 0  # exact operands vary, FAIL model constant

    @property
    def clean(self) -> bool:
        return not self.violations and self.testable > 0

    @property
    def coverage(self) -> float:
        return self.testable / self.segments if self.segments else 0.0


def analyze_declassified(regions: list[Region], segments: dict,
                         channels: tuple = CHANNELS) -> DeclassAnalysis:
    if not regions:
        raise TraceError("no regions captured")
    missing = [r.index for r in regions if r.index not in segments]
    if missing:
        raise TraceError(f"regions without segments: {missing[:5]}")
    by_group: dict[int, list] = {}
    for r in regions:
        by_group.setdefault(r.label >> GROUP_SHIFT, []).append(r)

    violations: list = []
    candidates = 0
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
                before = len(violations)
                for ch in channels:
                    if seg.fingerprints[ch] != ref.fingerprints[ch]:
                        violations.append(
                            (ch, group, r.index, seg.seq,
                             f"{seg.fingerprints[ch]} != "
                             f"{ref.fingerprints[ch]} (region {ref_r.index})"))
                if (len(violations) == before and "vop" in seg.fingerprints
                        and seg.fingerprints["vop"] !=
                        ref.fingerprints["vop"]):
                    candidates += 1
    return DeclassAnalysis(
        regions=len(regions), groups=len(by_group), segments=total,
        testable=testable, classes=classes, singleton=total - testable,
        violations=violations, sites=len(sites - {0}),
        max_events=max_events, iterations_seen=event_counts,
        candidate_segments=candidates)


def format_declass_marker(a: DeclassAnalysis, alg: str, opt: str) -> str:
    status = "PASS" if a.clean else "FAIL"
    return (f"PQCP_CT_TRACE_DECLASS {status} alg={alg} opt={opt} "
            f"regions={a.regions} groups={a.groups} segments={a.segments} "
            f"testable={a.testable} classes={a.classes} sites={a.sites} "
            f"violations={len(a.violations)} "
            f"coverage_pct={100.0 * a.coverage:.1f}")


# ---------------------------------------------------------------------------
# Operand-dependent-latency channel (Cortex-M, plugin target "arm").
#
# The plugin emits one PQCP_CT_VLAT line per (region, instruction address) for
# every Thumb-2 UDIV/SDIV/UMULL/SMULL/UMLAL/SMLAL executed in the region, with
# three hashes of the operand stream: identity (h_op), bit-length class
# (h_cls) and, for long multiplies, the documented Cortex-M3 predicate
# "both operands below 65536" (h_doc). Within a group (same public inputs) a
# site is secret-dependent on a model when its hash differs between regions.
#
#   FAIL model   a division whose bit-length class varies, or a long multiply
#                whose documented predicate varies (ARM DDI 0337 timing), or a
#                site that runs a different number of times between regions.
#   candidate    any site whose exact operands vary but passes the FAIL
#                model. The conservative reading: BearSSL measured M3 devices
#                deviating from the documented rule, so these are an
#                inventory that a ratchet can only shrink, not a pass/fail.
# ---------------------------------------------------------------------------

VLAT_RE = re.compile(
    r"PQCP_CT_VLAT region=(\d+) pc=([0-9a-f]+) kind=(\d) n=(\d+) "
    r"h_op=([0-9a-f]{16}) h_cls=([0-9a-f]{16}) h_doc=([0-9a-f]{16})"
    r"(?: h_cm=([0-9a-f]{16}))?$")
VLAT_KINDS = {1: "udiv", 2: "sdiv", 3: "umull", 4: "smull", 5: "umlal",
              6: "smlal"}


@dataclass(frozen=True)
class VlatRecord:
    region: int
    pc: int
    kind: int
    n: int
    h_op: str
    h_cls: str
    h_doc: str
    h_cm: str = ""


def parse_vlat(text: str) -> list[VlatRecord]:
    records = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("PQCP_CT_VLAT"):
            continue
        m = VLAT_RE.match(line)
        if not m:
            raise TraceError(f"malformed vlat line: {line!r}")
        g = m.groups()
        records.append(VlatRecord(int(g[0]), int(g[1], 16), int(g[2]),
                                  int(g[3]), g[4], g[5], g[6], g[7] or ""))
    return records


@dataclass
class VlatAnalysis:
    regions: int
    sites: dict            # pc -> kind
    fail_sites: list       # [(pc, kind, reason)]
    candidate_sites: list  # [(pc, kind)] operands vary, FAIL model clean
    base_clean: bool       # pc/addr/line/div relational result
    kinds_seen: dict       # kind name -> sites

    @property
    def clean(self) -> bool:
        return self.base_clean and not self.fail_sites


def analyze_vlat(regions: list[Region], records: list[VlatRecord], *,
                 long_mul_variable: bool = True,
                 compare_counts: bool = True,
                 model: str = "documented") -> VlatAnalysis:
    """Per-site verdict. `long_mul_variable` is the core policy (M3 true, M4
    false); `compare_counts=False` skips sites whose execution count differs
    between regions (rejection loops), which the segment analysis covers."""
    base = analyze(regions)
    by_region: dict[int, dict[int, VlatRecord]] = {}
    sites: dict[int, int] = {}
    for rec in records:
        by_region.setdefault(rec.region, {})[rec.pc] = rec
        sites[rec.pc] = rec.kind
    groups: dict[int, list[Region]] = {}
    for r in regions:
        groups.setdefault(r.label >> GROUP_SHIFT, []).append(r)
    fail: dict[int, str] = {}
    candidate: set[int] = set()
    for members in groups.values():
        for pc, kind in sites.items():
            seen = [by_region.get(r.index, {}).get(pc) for r in members]
            counts = {None if s is None else s.n for s in seen}
            if len(counts) > 1:
                if compare_counts:
                    fail.setdefault(pc,
                                    "execution count differs between runs")
                continue
            if None in counts:
                continue
            if model == "cmemu":
                if any(not s.h_cm for s in seen):
                    raise TraceError("trace has no h_cm (rebuild the plugin)")
                if len({s.h_cm for s in seen}) > 1:
                    fail.setdefault(pc, "cmemu latency class varies")
                elif len({s.h_op for s in seen}) > 1:
                    candidate.add(pc)
                continue
            if kind > 2 and not long_mul_variable:
                if (len({s.h_doc for s in seen}) > 1 or
                        len({s.h_op for s in seen}) > 1):
                    candidate.add(pc)
                continue
            model = "h_cls" if kind <= 2 else "h_doc"
            if len({getattr(s, model) for s in seen}) > 1:
                fail.setdefault(
                    pc, "operand bit-length varies" if kind <= 2
                    else "operand-size predicate varies")
            elif len({s.h_op for s in seen}) > 1:
                candidate.add(pc)
    candidate -= set(fail)
    kinds: dict[str, int] = {}
    for kind in sites.values():
        kinds[VLAT_KINDS[kind]] = kinds.get(VLAT_KINDS[kind], 0) + 1
    return VlatAnalysis(
        regions=len(regions), sites=sites,
        fail_sites=sorted((pc, sites[pc], why) for pc, why in fail.items()),
        candidate_sites=sorted((pc, sites[pc]) for pc in candidate),
        base_clean=base.clean, kinds_seen=kinds)


def format_vlat_marker(a: VlatAnalysis, alg: str, opt: str,
                       target: str) -> str:
    divs = sum(1 for k in a.sites.values() if k <= 2)
    return (f"PQCP_CT_TRACE_VLAT {'PASS' if a.clean else 'FAIL'} alg={alg} "
            f"target={target} opt={opt} regions={a.regions} "
            f"sites={len(a.sites)} div_sites={divs} "
            f"mul_sites={len(a.sites) - divs} fail_sites="
            f"{len(a.fail_sites)} candidate_sites={len(a.candidate_sites)} "
            f"base={'clean' if a.base_clean else 'diverged'}")


def format_vlat_declass_marker(a: DeclassAnalysis, v: VlatAnalysis, alg: str,
                               opt: str, target: str) -> str:
    """Verdict of a declassification-aware Cortex-M run: segment relation on
    the core's channels, plus the per-site attribution of operand-class
    variation (sites that ran equally often in every region of a group)."""
    by_channel: dict[str, int] = {}
    for kind, *_ in a.violations:
        by_channel[kind] = by_channel.get(kind, 0) + 1
    clean = a.clean
    return (f"PQCP_CT_TRACE_VLAT_DECLASS {'PASS' if clean else 'FAIL'} "
            f"alg={alg} target={target} opt={opt} regions={a.regions} "
            f"segments={a.segments} testable={a.testable} "
            f"violations={len(a.violations)} "
            f"vdiv_violations={by_channel.get('vdiv', 0)} "
            f"vmul_violations={by_channel.get('vmul', 0)} "
            f"other_violations="
            f"{len(a.violations) - by_channel.get('vdiv', 0) - by_channel.get('vmul', 0)} "
            f"candidate_segments={a.candidate_segments} "
            f"attributed_sites={len(v.fail_sites)}")


@dataclass
class ModelComparison:
    """Per-site disagreement of two latency models over the SAME trace."""
    documented: set      # pcs failing under the documented model
    cmemu: set           # pcs failing under the CMEmu model
    kinds: dict          # pc -> kind

    @property
    def both(self) -> set:
        return self.documented & self.cmemu

    @property
    def documented_only(self) -> set:
        return self.documented - self.cmemu

    @property
    def cmemu_only(self) -> set:
        return self.cmemu - self.documented


def compare_latency_models(regions: list[Region], records: list[VlatRecord],
                           *, long_mul_variable: bool = True,
                           compare_counts: bool = True) -> ModelComparison:
    doc = analyze_vlat(regions, records, long_mul_variable=long_mul_variable,
                       compare_counts=compare_counts, model="documented")
    cm = analyze_vlat(regions, records, long_mul_variable=long_mul_variable,
                      compare_counts=compare_counts, model="cmemu")
    return ModelComparison(
        documented={pc for pc, _, _ in doc.fail_sites},
        cmemu={pc for pc, _, _ in cm.fail_sites},
        kinds=dict(doc.sites))


def format_models_marker(c: ModelComparison, alg: str, opt: str,
                         target: str, functions: dict | None = None,
                         doc_segment_violations: int | None = None,
                         cmemu_segment_violations: int | None = None) -> str:
    fns = functions or {}
    only = sorted({fns.get(pc, "?") for pc in c.cmemu_only})
    seg = ""
    if doc_segment_violations is not None:
        seg = (f" doc_violations={doc_segment_violations} "
               f"cmemu_violations={cmemu_segment_violations}")
    return (f"PQCP_CT_TRACE_LATENCY_MODELS alg={alg} target={target} "
            f"opt={opt} documented_sites={len(c.documented)} "
            f"cmemu_sites={len(c.cmemu)} both={len(c.both)} "
            f"documented_only={len(c.documented_only)} "
            f"cmemu_only={len(c.cmemu_only)}{seg} "
            f"cmemu_only_functions={','.join(only) if only else 'none'}")
