// views-provenance.jsx, Evidence graph (real nodes+edges from
// pqc_evidence_graph.json), transcript manifest, asset trace map.

const { Card: PrCard, KV: PrKV, Tag: PrTag, Badge: PrBadge, Hr: PrHr, Sev: PrSev,
        Kpi: PrKpi, Tabs: PrTabs, Pagination: PrPgn, usePaged: prUsePaged,
        EvBind: PrEv, Callout: PrCallout, Code: PrCode, EmptyState: PrEmpty } = window.UI;
const { HashChip: PrHash, OriginChip: PrOrigin, EvBind2: PrEvBind2,
        DetailRow: PrDetail, StatGrid: PrSGrid, Stat: PrStat } = window.UIX;
const PrP = window.PQCP;
const PrS = window.STORE;
const { useState: prS, useMemo: prM } = React;

function ProvenanceView({ session, pack }) {
  const [tab, setTab] = prS("graph");
  const eg = PrS.evidenceGraph(pack);
  const tm = PrS.transcriptManifest(pack);
  const refv = PrS.referenceValues(pack);

  return (
    <>
      <div className="grid-kpi" style={{ marginBottom: 12 }}>
        <PrKpi label="Evidence graph" status={eg ? "ok" : "warn"}
               value={eg ? `${eg.nodes.length} / ${eg.edges.length}` : "n/a"}
               sub={eg ? "nodes / edges" : "awaiting pqc_evidence_graph.json"}
               evbind={<PrEvBind2 ev={eg?.evbind} compact />} />
        <PrKpi label="Transcripts" status={tm ? "ok" : "warn"}
               value={tm ? (tm.qemu_stdout_transcripts.length + tm.transcripts.length) : "n/a"}
               sub={tm ? `${tm.qemu_stdout_transcripts.length} qemu stdout · ${tm.transcripts.length} other` : "awaiting"}
               evbind={<PrEvBind2 ev={tm?.evbind} compact />} />
        <PrKpi label="Reference values" status={refv ? "ok" : "warn"}
               value={refv ? `${Object.keys(refv.artifact_hashes).length}` : "n/a"}
               sub="hash-bound artifacts" />
        <PrKpi label="Allowed profiles" status="info"
               value={refv ? (refv.allowed_profile_ids.length || "any") : "n/a"}
               sub="empty = unrestricted in this mode" />
        <PrKpi label="CBOM ids in references" status="info"
               value={refv ? refv.cbom_component_ids.length : "n/a"}
               sub="pqc_reference_values.cbom_component_ids" />
      </div>

      <div className="grid grid-12">
        <PrCard span={12} kicker="Provenance" title={eg ? "Evidence graph · live from pqc_evidence_graph.json" : "Awaiting evidence graph"}
              subtitle="asset → source → kconfig → ztest → claim → marker → artifact. Filter to one asset to declutter."
              padded={false}
              actions={<PrTabs value={tab} onChange={setTab} tabs={[
                { id: "graph",      label: "Graph", count: eg?.nodes.length || 0 },
                { id: "transcripts", label: "Transcripts", count: tm ? (tm.qemu_stdout_transcripts.length + tm.transcripts.length) : 0 },
                { id: "references", label: "Reference values" },
              ]} />}>
          {tab === "graph" && (eg ? <EvidenceGraphView eg={eg} /> : <div style={{ padding: 14 }}><PrEmpty icon="○" title="No pqc_evidence_graph.json" hint="Produced by scripts/generate_pqc_evidence_graph.py." /></div>)}
          {tab === "transcripts" && (tm ? <TranscriptList tm={tm} /> : <div style={{ padding: 14 }}><PrEmpty icon="○" title="No transcript manifest" hint="Awaiting transcripts/evidence_transcript_manifest.json." /></div>)}
          {tab === "references" && (refv ? <ReferenceValuesView refv={refv} /> : <div style={{ padding: 14 }}><PrEmpty icon="○" title="No reference values" hint="Awaiting pqc_reference_values.json." /></div>)}
        </PrCard>
      </div>
    </>
  );
}

function EvidenceGraphView({ eg }) {
  // Pick a focal asset to show; default to the first asset:* node
  const assetNodes = prM(() => eg.nodes.filter(n => n.id && n.id.startsWith("asset:")), [eg]);
  const [focus, setFocus] = prS(assetNodes[0]?.id || null);

  // Filter edges & nodes by a 1-hop neighborhood around the focus
  const visible = prM(() => {
    if (!focus) return { nodes: eg.nodes, edges: eg.edges };
    const keep = new Set([focus]);
    eg.edges.forEach(e => {
      if (e.from === focus) keep.add(e.to);
      if (e.to === focus)   keep.add(e.from);
    });
    return {
      nodes: eg.nodes.filter(n => keep.has(n.id)),
      edges: eg.edges.filter(e => keep.has(e.from) && keep.has(e.to)),
    };
  }, [eg, focus]);

  return (
    <div style={{ display: "grid", gridTemplateColumns: "260px 1fr", gap: 0 }}>
      <div style={{ borderRight: "1px solid var(--line)", padding: 12 }}>
        <div className="kv__k" style={{ marginBottom: 8 }}>Focal asset</div>
        <div className="assetnav">
          {assetNodes.map(n => {
            const label = n.id.replace(/^asset:/, "");
            return (
              <button key={n.id} className={`assetnav__i ${focus === n.id ? "assetnav__i--on" : ""}`} onClick={() => setFocus(n.id)}>
                <span className="assetnav__cat assetnav__cat--ok">A</span>
                <span className="assetnav__id">{label}</span>
              </button>
            );
          })}
        </div>
        <div style={{ marginTop: 12 }} className="kv__k">Legend</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 11, marginTop: 6 }}>
          <span><span className="sdot sdot--pass" /> asset</span>
          <span><span className="sdot sdot--info" /> source / kconfig</span>
          <span><span className="sdot sdot--warn" /> test / marker</span>
          <span><span className="sdot sdot--ok" /> claim / artifact</span>
        </div>
      </div>
      <div style={{ padding: 12, minWidth: 0 }}>
        <GraphSVG nodes={visible.nodes} edges={visible.edges} focus={focus} />
        <PrHr />
        <div className="kv__k" style={{ marginBottom: 6 }}>Edges around focal asset ({visible.edges.length})</div>
        <table className="tbl">
          <thead><tr><th>From</th><th>Relationship</th><th>To</th></tr></thead>
          <tbody>
            {visible.edges.slice(0, 40).map((e, i) => (
              <tr key={i}>
                <td className="mono dim">{e.from}</td>
                <td><PrTag>{e.relationship}</PrTag></td>
                <td className="mono dim">{e.to}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function GraphSVG({ nodes, edges, focus }) {
  // Group nodes by type, lay out in columns.
  const kindOrder = ["asset", "file", "kconfig", "ztest", "claim", "marker", "artifact", "cbom"];
  function kindOf(id) {
    if (!id) return "other";
    const k = id.split(":")[0];
    return kindOrder.includes(k) ? k : "other";
  }
  const byKind = {};
  kindOrder.forEach(k => { byKind[k] = []; });
  byKind.other = [];
  nodes.forEach(n => {
    const k = kindOf(n.id);
    (byKind[k] || byKind.other).push(n);
  });
  const cols = [...kindOrder, "other"].filter(k => byKind[k]?.length);
  const W = 1180, ROW = 30, padT = 28;
  const maxRows = Math.max(1, ...cols.map(c => byKind[c].length));
  const H = padT + maxRows * ROW + 28;
  const colW = W / cols.length;
  const pos = {};
  cols.forEach((c, ci) => {
    byKind[c].forEach((n, ri) => {
      pos[n.id] = { x: ci * colW + colW / 2, y: padT + ri * ROW + ROW / 2, kind: c, id: n.id };
    });
  });

  return (
    <div className="evgwrap">
      <svg viewBox={`0 0 ${W} ${H}`} className="evg" preserveAspectRatio="xMidYMid meet" style={{ minWidth: 900 }}>
        {cols.map((c, ci) => (
          <g key={c}>
            <text x={ci * colW + 12} y={18} className="evg__col">{c}</text>
            <line x1={ci * colW} x2={ci * colW} y1={26} y2={H - 4} className="evg__cl" />
          </g>
        ))}
        {edges.map((e, i) => {
          const pa = pos[e.from], pb = pos[e.to];
          if (!pa || !pb) return null;
          const mx = (pa.x + pb.x) / 2;
          return <path key={i} d={`M${pa.x + 60},${pa.y} C${mx},${pa.y} ${mx},${pb.y} ${pb.x - 60},${pb.y}`} className="evg__e" />;
        })}
        {Object.values(pos).map(p => {
          const label = p.id.replace(/^[^:]+:/, "");
          const trimmed = label.length > 22 ? label.slice(0, 21) + "…" : label;
          const cls = p.id === focus ? "evg__n evg__n--claim" : `evg__n evg__n--${p.kind}`;
          return (
            <g key={p.id} transform={`translate(${p.x - 70}, ${p.y - 12})`}>
              <rect width="140" height="24" rx="3" className={cls} />
              <text x="8" y="16" className="evg__nt">{trimmed}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function TranscriptList({ tm }) {
  return (
    <div style={{ padding: 14 }}>
      <div className="kv__k" style={{ marginBottom: 6 }}>QEMU stdout transcripts ({tm.qemu_stdout_transcripts.length})</div>
      <div className="subjgrid">
        {tm.qemu_stdout_transcripts.map((t, i) => (
          <div key={i} className="subjrow">
            <span className="subjrow__f">{t.label}</span>
            <span className="subjrow__h"><PrHash sha={t.sha256} /></span>
            <PrTag tone="info">{t.size_bytes} B</PrTag>
          </div>
        ))}
      </div>
      <PrHr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Required steps ({(tm.required_steps || []).length})</div>
      <ul className="filelist">
        {(tm.required_steps || []).map((s, i) => <li key={i} className="filelist__f filelist__f--wrap">{typeof s === "string" ? s : JSON.stringify(s)}</li>)}
      </ul>
      <PrHr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Other transcripts ({tm.transcripts.length})</div>
      <div className="subjgrid">
        {tm.transcripts.slice(0, 24).map((t, i) => (
          <div key={i} className="subjrow">
            <span className="subjrow__f">{t.label || t.step_label || `transcript-${i}`}</span>
            <span className="subjrow__h"><PrHash sha={t.sha256} /></span>
            <PrTag>{t.size_bytes != null ? `${t.size_bytes} B` : "n/a"}</PrTag>
          </div>
        ))}
      </div>
    </div>
  );
}

function ReferenceValuesView({ refv }) {
  return (
    <div style={{ padding: 14 }}>
      <div className="splitcols">
        <div>
          <PrDetail k="tag" v={refv.tag ? <span className="mono">{refv.tag}</span> : null} />
          <PrDetail k="version" v={refv.version ? <span className="mono">{refv.version}</span> : null} />
          <PrDetail k="head_sha" v={refv.head_sha ? <PrHash sha={refv.head_sha} /> : null} />
          <PrDetail k="tag_commit" v={refv.tag_commit ? <PrHash sha={refv.tag_commit} /> : null} />
          <PrDetail k="tag → HEAD" v={refv.tag_points_to_head == null ? null : <PrTag tone={refv.tag_points_to_head ? "ok" : "warn"}>{String(refv.tag_points_to_head)}</PrTag>} />
          <PrDetail k="dirty" v={refv.dirty == null ? null : <PrTag tone={refv.dirty ? "warn" : "ok"}>{String(refv.dirty)}</PrTag>} />
        </div>
        <div>
          <PrDetail k="zephyr_revision" v={refv.zephyr_revision ? <PrHash sha={refv.zephyr_revision} /> : null} />
          <PrDetail k="sdk_version" v={refv.sdk_version ? <span className="mono">{refv.sdk_version}</span> : null} />
          <PrDetail k="policy_passed" v={refv.policy_passed == null ? null : <PrTag tone={refv.policy_passed ? "ok" : "err"}>{String(refv.policy_passed)}</PrTag>} />
          <PrDetail k="profile_passed" v={refv.profile_passed == null ? null : <PrTag tone={refv.profile_passed ? "ok" : "err"}>{String(refv.profile_passed)}</PrTag>} />
          <PrDetail k="required claims" v={<span className="mono">{refv.required_claim_ids.length}</span>} />
          <PrDetail k="cbom_component_ids" v={<span className="mono">{refv.cbom_component_ids.length}</span>} />
        </div>
      </div>
      <PrHr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Hash-bound artifacts ({Object.keys(refv.artifact_hashes).length})</div>
      <div className="subjgrid">
        {Object.entries(refv.artifact_hashes).map(([name, h]) => (
          <div key={name} className="subjrow">
            <span className="subjrow__f">{name}</span>
            <span className="subjrow__h"><PrHash sha={h.sha256} /></span>
            <PrTag>{h.size_bytes != null ? `${h.size_bytes} B` : "n/a"}</PrTag>
          </div>
        ))}
      </div>
    </div>
  );
}

window.VIEW_PROVENANCE = { ProvenanceView };
