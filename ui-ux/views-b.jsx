// views-b.jsx — Provenance, Bench Lab, Validation (ACVP+CT), Firmware, Integration, Configurator.

const { Card: VCard, KV: VKV, Pill: VPill, Tag: VTag, Badge: VBadge, Hr: VHr, Sev: VSev, EvBind: VEv, Await: VAwait, EmptyState: VEmpty, Kpi: VKpi, ThresholdBar: VTBar, Code: VCode, Tabs: VTabs, Segmented: VSeg, Switch: VSwitch, Toggle: VTgl, Callout: VCallout, FilterChip: VFChip, FilterBar: VFBar, Pagination: VPgn, usePaged: vUsePaged } = window.UI;
const PB = window.PQCP;
const { useState: bS, useMemo: bM, useEffect: bE } = React;

function bArt(file) { return PB.ARTIFACTS.find(a => a.file === file) || { file, validator: "?" }; }
function bTone(c) {
  const m = { release:"info", kat:"ok", benchmark:"info", acvp:"warn", security:"warn", supply_chain:"info", crypto_agility:"info", firmware:"info", boot:"warn", kem:"ok", signature:"info", validation:"warn", rng:"info" };
  return m[c] || "neutral";
}
function bDrawer() { return (window.useDrawer && window.useDrawer()) || { openDrawer: () => {} }; }

// ═══════════════════════════════════════════════════════════════════════════
// PROVENANCE — Evidence Graph + Reference values + Asset trace
// ═══════════════════════════════════════════════════════════════════════════

function ProvenanceView({ session }) {
  const [selectedAsset, setAsset] = bS(PB.ASSETS[1].id);
  const asset = PB.ASSETS.find(a => a.id === selectedAsset);
  return (
    <>
      <div className="grid-kpi" style={{ marginBottom: 12 }}>
        <VKpi label="Trace map assets" status="info" value={PB.ASSETS.length} sub="scripts/pqc_asset_trace_map.json" />
        <VKpi label="Source files (selected)" status="info" value={asset.sources.length} sub={asset.id} />
        <VKpi label="Kconfig symbols" status="info" value={asset.kconfig.length} sub={asset.id} />
        <VKpi label="Linked claims" status="info" value={asset.claims.length} sub={asset.id} />
        <VKpi label="Evidence graph" status="warn" value="awaiting" sub="pqc_evidence_graph.json" />
      </div>

      <div className="grid grid-12">
        <VCard span={4} kicker="Trace map" title="Cryptographic assets"
              subtitle="Click an asset to surface its provenance chain"
              actions={<VEv file="scripts/pqc_asset_trace_map.json" status="present" />}>
          <div className="assetnav">
            {PB.ASSETS.map(a => (
              <button key={a.id} className={`assetnav__i ${selectedAsset === a.id ? "assetnav__i--on" : ""}`} onClick={() => setAsset(a.id)}>
                <span className={`assetnav__cat assetnav__cat--${bTone(a.category)}`}>{a.category[0].toUpperCase()}</span>
                <span className="assetnav__id">{a.id}</span>
                {a.test_only && <VTag tone="warn">test</VTag>}
              </button>
            ))}
          </div>
        </VCard>

        <VCard span={8} kicker={asset.id} title={asset.name}
              subtitle={`category · ${asset.category} · cbom: ${asset.cbom || "—"}${asset.test_only ? " · test-only" : ""}`}
              actions={<VEv file="pqc_evidence_graph.json" validator="scripts/generate_pqc_evidence_graph.py" status="missing" />}>
          <EvidenceGraphSVG asset={asset} />
        </VCard>

        <VCard span={6} kicker="Source files" title={`${asset.sources.length} files`}
              subtitle="Files declared in the asset trace map for this asset">
          <ul className="filelist">{asset.sources.map(f => <li key={f} className="filelist__f">{f}</li>)}</ul>
        </VCard>

        <VCard span={6} kicker="Kconfig + ztests" title={`${asset.kconfig.length} symbols · ${asset.ztests.length} ztests`}
              subtitle="Build-time selection symbols and the tests that exercise them">
          <div className="kv__k" style={{ marginBottom: 6 }}>Kconfig</div>
          <div className="kchips">{asset.kconfig.map(k => <span key={k} className="kchip mono">CONFIG_{k}</span>)}</div>
          <VHr />
          <div className="kv__k" style={{ marginBottom: 6 }}>ztests</div>
          <ul className="filelist">{asset.ztests.map(z => <li key={z} className="filelist__f">{z}</li>)}</ul>
        </VCard>

        <VCard span={12} kicker="Transcript markers + claims" title="What is asserted, and how it is observed"
              subtitle="Markers are grep targets in captured transcripts. The ledger evaluator binds each marker to a claim id.">
          <div className="splitcols">
            <div>
              <div className="kv__k" style={{ marginBottom: 6 }}>Claim ids</div>
              {asset.claims.length === 0 ? <div className="dim mono">no claims directly attached</div> : (
                <div className="ptags">{asset.claims.map(c => <span key={c} className="ptag">{c}</span>)}</div>
              )}
            </div>
            <div>
              <div className="kv__k" style={{ marginBottom: 6 }}>Transcript markers</div>
              <ul className="filelist">{asset.markers.map(m => <li key={m} className="filelist__f filelist__f--wrap">{m}</li>)}</ul>
            </div>
          </div>
        </VCard>

        <VCard span={12} kicker="Reference values" title="pqc_reference_values.json"
              subtitle="Compact reference-value set used by replay verifiers"
              actions={<VEv file="pqc_reference_values.json" validator="scripts/generate_pqc_reference_values.py" status="missing" />}>
          <VAwait file="pqc_reference_values.json" validator="scripts/generate_pqc_reference_values.py"
            what="Replayable reference values that bind release metadata, artifact hashes, required claims, CBOM component IDs, and the expected firmware assurance digest root."
            supports={["release.reference_values"]} />
        </VCard>
      </div>
    </>
  );
}

function EvidenceGraphSVG({ asset }) {
  const cols = [
    { key: "asset",   label: "Asset",   items: [{ id: asset.id, label: asset.id }] },
    { key: "source",  label: "Source",  items: asset.sources.slice(0, 5).map(s => ({ id: s, label: shortPath(s) })) },
    { key: "kconfig", label: "Kconfig", items: asset.kconfig.map(k => ({ id: k, label: "CONFIG_" + k })) },
    { key: "test",    label: "Test",    items: asset.ztests.map(z => ({ id: z, label: z.replace("tests/", "") })) },
    { key: "claim",   label: "Claim",   items: asset.claims.map(c => ({ id: c, label: c })) },
    { key: "marker",  label: "Marker",  items: asset.markers.slice(0, 4).map(m => ({ id: m, label: m.length > 32 ? m.slice(0, 31) + "…" : m })) },
    { key: "cbom",    label: "CBOM",    items: asset.cbom ? [{ id: asset.cbom, label: asset.cbom }] : [] },
    { key: "policy",  label: "Policy",  items: [{ id: "policy", label: "pqc_policy_result.json" }] },
  ];
  const W = 1180, ROW = 40, padT = 28, colW = W / cols.length;
  const maxRows = Math.max(...cols.map(c => c.items.length || 1));
  const H = padT + maxRows * ROW + 28;
  const pos = {};
  cols.forEach((col, ci) => col.items.forEach((it, ri) => {
    pos[`${col.key}:${it.id}`] = { x: ci * colW + colW / 2, y: padT + ri * ROW + ROW / 2, col, item: it };
  }));
  const edges = [];
  for (let i = 0; i < cols.length - 1; i++) {
    const a = cols[i], b = cols[i + 1];
    a.items.forEach(ai => b.items.forEach(bi => edges.push([`${a.key}:${ai.id}`, `${b.key}:${bi.id}`])));
  }
  return (
    <div className="evgwrap">
      <svg viewBox={`0 0 ${W} ${H}`} className="evg" preserveAspectRatio="xMidYMid meet">
        {cols.map((c, ci) => (
          <g key={c.key}>
            <text x={ci * colW + 12} y={18} className="evg__col">{c.label}</text>
            <line x1={ci * colW} x2={ci * colW} y1={26} y2={H - 4} className="evg__cl" />
          </g>
        ))}
        {edges.map(([a, b], i) => {
          const pa = pos[a], pb = pos[b];
          if (!pa || !pb) return null;
          const mx = (pa.x + pb.x) / 2;
          return <path key={i} d={`M${pa.x + 60},${pa.y} C${mx},${pa.y} ${mx},${pb.y} ${pb.x - 60},${pb.y}`} className="evg__e" />;
        })}
        {Object.entries(pos).map(([k, p]) => (
          <g key={k} transform={`translate(${p.x - 70}, ${p.y - 13})`}>
            <rect width="140" height="26" rx="3" className={`evg__n evg__n--${p.col.key}`} />
            <text x="8" y="17" className="evg__nt">{p.item.label.length > 22 ? p.item.label.slice(0, 21) + "…" : p.item.label}</text>
          </g>
        ))}
      </svg>
    </div>
  );
}
function shortPath(p) { const ps = p.split("/"); return ps.length > 3 ? ps[0] + "/…/" + ps[ps.length - 1] : p; }

// ═══════════════════════════════════════════════════════════════════════════
// BENCH LAB
// ═══════════════════════════════════════════════════════════════════════════

function BenchLabView({ tweaks, setTweak, session }) {
  const reps = tweaks.reps;
  const minImpr = tweaks.minMedianImpr;
  const maxRegrP90 = tweaks.maxRegrP90;
  const maxRegrRom = tweaks.maxRegrRom;
  const objective = tweaks.objective;
  const [view, setView] = bS("rows");

  return (
    <>
      <div className="grid-kpi" style={{ marginBottom: 12 }}>
        <VKpi label="Campaign reps" status="info" value={reps} sub="slider · maps to --repetitions" evbind={<VEv file="scripts/pqc_benchmark_campaign.json" path="repetitions" status="present" compact />} />
        <VKpi label="Min median impr" status="info" value={`${minImpr.toFixed(1)}%`} sub="acceptance floor for candidates" />
        <VKpi label="Max p90/p99 regr" status="warn" value={`${maxRegrP90.toFixed(1)}%`} sub="reject if exceeded" />
        <VKpi label="Max ROM/RAM regr" status="warn" value={`${maxRegrRom.toFixed(1)}%`} sub="reject if exceeded" />
        <VKpi label="Objective" status="info" value={objective} sub="optimizer goal" />
      </div>

      <div className="grid grid-12">
        <VCard span={4} kicker="Optimization controls" title="Acceptance thresholds"
              subtitle="Slider values become CLI flags. They do NOT mutate any repo files.">
          <Ctrl label="Repetitions" v={reps} min={1} max={50} step={1} onChange={v => setTweak("reps", v)} hint={`scripts/pqc_benchmark_campaign.json default · ${PB.CAMPAIGN.repetitions}`} />
          <Ctrl label="Min median improvement" v={minImpr} unit="%" min={0} max={50} step={0.5} onChange={v => setTweak("minMedianImpr", v)} />
          <Ctrl label="Max p90/p99 regression" v={maxRegrP90} unit="%" min={0} max={25} step={0.5} onChange={v => setTweak("maxRegrP90", v)} />
          <Ctrl label="Max ROM/RAM regression" v={maxRegrRom} unit="%" min={0} max={20} step={0.5} onChange={v => setTweak("maxRegrRom", v)} />
          <div className="ctrl">
            <div className="ctrl__lbl"><span>Objective</span></div>
            <select className="input mono" value={objective} onChange={e => setTweak("objective", e.target.value)}>
              <option value="cycles_median">cycles_median</option>
              <option value="cycles_p90">cycles_p90</option>
              <option value="cycles_p99">cycles_p99</option>
              <option value="handshake_p99_ms">handshake_p99_ms</option>
            </select>
          </div>
          <VHr />
          <div className="kv__k" style={{ marginBottom: 6 }}>Campaign config</div>
          <div className="kvgrid">
            <VKV k="Warmup runs" v={<span className="mono">{PB.CAMPAIGN.warmup_runs}</span>} />
            <VKV k="Repetitions" v={<span className="mono">{PB.CAMPAIGN.repetitions}</span>} />
            <VKV k="Statistics" v={<div className="kchips">{PB.CAMPAIGN.required_statistics.map(s => <span key={s} className="kchip mono">{s}</span>)}</div>} />
            <VKV k="Default env" v={<span className="mono">{PB.CAMPAIGN.default_environment_type}</span>} />
          </div>
          <VEv file="scripts/pqc_benchmark_campaign.json" status="present" />
        </VCard>

        <VCard span={8} kicker="Command preview" title="Live preview, generated from slider state"
              subtitle="Copy and run locally; the console never executes commands.">
          <VCode label="$ run campaign">{`python3 scripts/run_benchmark_campaign.py \\
  --config       scripts/pqc_benchmark_campaign.json \\
  --warmup       ${PB.CAMPAIGN.warmup_runs} \\
  --repetitions  ${reps} \\
  --statistics   ${PB.CAMPAIGN.required_statistics.join(",")} \\
  --out          ${session.path || "<pack>"}/benchmark_campaign_result.json`}</VCode>
          <VCode label="$ optimize">{`python3 scripts/optimize_metric_campaign.py \\
  --in              ${session.path || "<pack>"}/benchmark_campaign_result.json \\
  --objective       ${objective} \\
  --min-improvement ${(minImpr / 100).toFixed(3)} \\
  --max-p90-regr    ${(maxRegrP90 / 100).toFixed(3)} \\
  --max-rom-regr    ${(maxRegrRom / 100).toFixed(3)} \\
  --out             ${session.path || "<pack>"}/optimize_metric_campaign_result.json`}</VCode>
          <VCallout tone="info">Optimizer candidates are <strong>measurement_only</strong> until they pass policy. A candidate that wins on <span className="mono">{objective}</span> still has to satisfy CBOM, profile, and policy gates before it is treated as production-promotable.</VCallout>
        </VCard>

        <VCard span={12} kicker="Benchmark surface" title="Per-algorithm distribution rows"
              subtitle="Schema: benchmark_results.csv + benchmark_campaign_result.json. Numbers populate when a pack is loaded."
              padded={false}
              actions={<>
                <VSeg size="sm" value={view} onChange={setView} options={[{ id: "rows", label: "rows" }, { id: "hex", label: "heatmap" }]} />
                <VEv file="benchmark_campaign_result.json" path="rows[]" validator="scripts/run_benchmark_campaign.py" status="missing" />
              </>}>
          {view === "rows" ? <BenchTable /> : <BenchHexEmpty />}
        </VCard>

        <VCard span={6} kicker="Awaiting" title="Backend currency"
              subtitle="comparison-only review of pinned native backend metadata"
              actions={<VEv file="backend_update_evaluation.json" validator="scripts/evaluate_backend_update.py" status="missing" />}>
          <VAwait file="backend_update_evaluation.json" validator="scripts/evaluate_backend_update.py"
            what="Records pinned revisions, license metadata, META.yml metadata, and optional upstream drift for mlkem-native and mldsa-native."
            supports={["supply_chain.backend_update_evaluation"]} />
        </VCard>

        <VCard span={6} kicker="Awaiting" title="Cost-of-assurance evidence"
              actions={<VEv file="cost_of_assurance_evidence.json" validator="scripts/release_check.py" status="missing" />}>
          <VAwait file="cost_of_assurance_evidence.json" validator="scripts/release_check.py"
            what="Per-metric guardrail evidence consumed by the ledger; cost_of_assurance.guardrails requires every configured guardrail to pass."
            supports={["cost_of_assurance.guardrails"]} />
        </VCard>
      </div>
    </>
  );
}

function Ctrl({ label, v, unit, min, max, step, onChange, hint }) {
  return (
    <div className="ctrl">
      <div className="ctrl__lbl"><span>{label}</span><span className="mono">{typeof v === "number" ? v.toFixed?.(2) ?? v : v}{unit}</span></div>
      <input type="range" className="range" min={min} max={max} step={step} value={v} onChange={e => onChange(+e.target.value)} />
      {hint && <div className="ctrl__hint dim mono">{hint}</div>}
    </div>
  );
}

function BenchTable() {
  const rows = [
    { algo: "ML-KEM-512", ops: ["keygen", "encaps", "decaps"] },
    { algo: "ML-KEM-768", ops: ["keygen", "encaps", "decaps"] },
    { algo: "ML-KEM-1024", ops: ["keygen", "encaps", "decaps"] },
    { algo: "ML-DSA-44",  ops: ["keygen", "sign", "verify"] },
    { algo: "ML-DSA-65",  ops: ["keygen", "sign", "verify"] },
    { algo: "ML-DSA-87",  ops: ["keygen", "sign", "verify"] },
  ];
  return (
    <table className="tbl">
      <thead><tr>
        <th>Algorithm</th><th>Op</th>
        <th className="num">cycles_min</th><th className="num">cycles_median</th>
        <th className="num">cycles_p90</th><th className="num">cycles_p99</th>
        <th className="num">cycles_mad</th><th className="num">sample_count</th>
        <th>Verdict</th>
      </tr></thead>
      <tbody>
        {rows.flatMap(r => r.ops.map(op => (
          <tr key={r.algo + op}>
            <td className="mono"><strong style={{ color: "var(--fg-0)" }}>{r.algo}</strong></td>
            <td>{op}</td>
            <td className="num mono dim">—</td>
            <td className="num mono dim">—</td>
            <td className="num mono dim">—</td>
            <td className="num mono dim">—</td>
            <td className="num mono dim">—</td>
            <td className="num mono dim">—</td>
            <td><VTag tone="warn">awaiting csv</VTag></td>
          </tr>
        )))}
      </tbody>
    </table>
  );
}

function BenchHexEmpty() {
  return (
    <div style={{ padding: 24 }}>
      <VEmpty icon="▦" title="No benchmark heatmap" hint="Heatmap renders once benchmark_campaign_result.json is loaded. No invented heat values are shown." />
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION (combined ACVP + CT smoke)
// ═══════════════════════════════════════════════════════════════════════════

function ValidationView({ session }) {
  const [tab, setTab] = bS("acvp");
  return (
    <div className="grid grid-12">
      <VCard span={12} kicker="Validation" title="ACVP serial + KAT + side-channel smoke"
            subtitle="Algorithm correctness against NIST vectorsets; constant-time smoke on ML-KEM decapsulation hot path."
            actions={<VTabs value={tab} onChange={setTab} tabs={[
              { id: "acvp",   label: "ACVP + KAT" },
              { id: "ct",     label: "Side-channel smoke" },
              { id: "boot",   label: "Boot KAT self-verify" },
            ]} />}>
        {tab === "acvp" && <ACVPPanel />}
        {tab === "ct"   && <CTPanel />}
        {tab === "boot" && <BootPanel />}
      </VCard>
    </div>
  );
}

function ACVPPanel() {
  const acvpClaims = PB.CLAIMS.filter(c => c.category === "acvp");
  const katClaims  = PB.CLAIMS.filter(c => c.category === "kat");
  return (
    <>
      <div className="grid grid-12" style={{ gridTemplateColumns: "1fr 1fr" }}>
        <div>
          <div className="kv__k" style={{ marginBottom: 6 }}>ACVP error vocabulary</div>
          <div className="errgrid">
            {PB.ACVP_ERRORS.map(e => (
              <div key={e} className="errcell">
                <span className="errcell__t">{e}</span>
                <span className="errcell__d">{
                  e === "ERROR:INVALID_CMD"   ? "unknown keyword or argc mismatch" :
                  e === "ERROR:INVALID_HEX"   ? "payload is not valid hex" :
                  e === "ERROR:INVALID_LEVEL" ? "parameter set not enabled by Kconfig" :
                  e === "ERROR:WRONG_SIZE"    ? "payload length does not match parameter set" :
                  e === "ERROR:MISSING_ARGS"  ? "required argument absent" :
                                                "readline timeout on stalled frame; recovers cleanly"
                }</span>
              </div>
            ))}
          </div>
        </div>
        <div>
          <div className="kv__k" style={{ marginBottom: 6 }}>Vectorset translations</div>
          <VAwait file="acvp_json_interop_result.json" validator="scripts/run_acvp_json_vectors.py"
            what="Operation coverage: keyGen, encap, decap, sigGen, sigVer, transcript hashing, malformed-then-valid recovery."
            supports={["acvp.json_interop","acvp.json_schema_coverage"]} />
          <VHr />
          <div className="kv__k" style={{ marginBottom: 6 }}>Per-test transcript hashes</div>
          <VAwait file="acvp_json_transcript_manifest.json" validator="scripts/run_acvp_json_vectors.py"
            what="Per-test transcript hashes. Replay verifies every serial command-response pair against recorded sha256."
            supports={["acvp.json_interop"]} />
        </div>
      </div>
      <VHr />
      <table className="tbl">
        <thead><tr><th>Claim id</th><th>Category</th><th>Evidence class</th><th>Environment</th><th>v7</th><th>Status</th></tr></thead>
        <tbody>
          {[...acvpClaims, ...katClaims].map(c => {
            const q = PB.QUALITY.byClaim[c.id] || {};
            return (
              <tr key={c.id}>
                <td className="mono"><strong style={{ color: "var(--fg-0)" }}>{c.id}</strong></td>
                <td><VTag tone={bTone(c.category)}>{c.category}</VTag></td>
                <td><VBadge tone="info">{q.class || "—"}</VBadge></td>
                <td className="mono dim">{q.env || "—"}</td>
                <td>{c.schema_version_added === 7 ? <VTag tone="accent">v7</VTag> : <span className="dim mono">≤v6</span>}</td>
                <td><VTag tone="warn">awaiting ledger</VTag></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </>
  );
}

function CTPanel() {
  return (
    <>
      <VCallout tone="warn" title="Scope reminder">
        CT smoke is regression evidence collected on <span className="mono">qemu_x86_64</span> /
        <span className="mono"> native_sim</span>. It catches first-order regressions (e.g. early return on invalid CT)
        but is not a constant-time proof and does not extend to physical hardware.
        Source: <span className="mono">docs/assurance-model.md § security.ct_smoke</span>.
      </VCallout>
      <div className="splitcols" style={{ marginTop: 12 }}>
        <div>
          <div className="kv__k" style={{ marginBottom: 6 }}>Runtime markers</div>
          <div className="markers__h">CT smoke marker</div>
          <div className="markers__m">PQCP_CT_SMOKE alg=&lt;ALG&gt; iters=32 median_valid=&lt;C&gt; median_invalid=&lt;C&gt; delta=&lt;C&gt; relative_pct=&lt;P&gt; bound_pct=&lt;B&gt;</div>
          <div className="markers__h">Welch-style t-statistic</div>
          <div className="markers__m">PQCP_CT_TTEST alg=&lt;ALG&gt; iters=32 mean_valid=&lt;C&gt; mean_invalid=&lt;C&gt; t2_x1000=&lt;T&gt;</div>
          <VHr />
          <div className="kv__k" style={{ marginBottom: 6 }}>Algorithms exercised</div>
          <div className="kchips">
            <span className="kchip">MLKEM-512</span>
            <span className="kchip">MLKEM-768</span>
            <span className="kchip">MLKEM-1024</span>
          </div>
        </div>
        <div>
          <div className="kv__k" style={{ marginBottom: 6 }}>Sample analysis</div>
          <VAwait file="ct_sample_analysis_result.json" validator="scripts/analyze_ct_samples.py"
            what="per_alg[]: alg, sample_count, median_valid, median_invalid, delta, relative_pct, t_stat. Checks balance of valid/invalid classes and contiguous per-class indexes."
            supports={["security.ct_sample_analysis","security.ct_campaign_analysis"]} />
          <VHr />
          <div className="kv__k" style={{ marginBottom: 6 }}>Instruction-policy scan</div>
          <VAwait file="ct_instruction_policy_result.json" validator="scripts/verify_ct_instruction_policy.py"
            what="Disassembles the CT-smoke ELF and scans ML-KEM decapsulation-related symbols for variable-latency division mnemonics."
            supports={["security.mlkem_decap_instruction_policy"]} />
        </div>
      </div>
    </>
  );
}

function BootPanel() {
  return (
    <>
      <div className="markers__h">Boot KAT marker</div>
      <div className="markers__m">PQCP_KAT_BOOT_VERIFY: starting power-on self-test</div>
      <div className="markers__m">PQCP_KAT_BOOT_VERIFY: all enabled primitives passed</div>
      <VHr />
      <table className="tbl">
        <thead><tr><th>Claim id</th><th>Category</th><th>Evidence class</th><th>Environment</th><th>Status</th></tr></thead>
        <tbody>
          {[PB.CLAIMS.find(c => c.id === "boot.kat_self_verify")].filter(Boolean).map(c => {
            const q = PB.QUALITY.byClaim[c.id] || {};
            return (
              <tr key={c.id}>
                <td className="mono"><strong style={{ color: "var(--fg-0)" }}>{c.id}</strong></td>
                <td><VTag tone={bTone(c.category)}>{c.category}</VTag></td>
                <td><VBadge tone="info">{q.class || "—"}</VBadge></td>
                <td className="mono dim">{q.env || "—"}</td>
                <td><VTag tone="warn">awaiting ledger</VTag></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// FIRMWARE
// ═══════════════════════════════════════════════════════════════════════════

function FirmwareView({ session }) {
  return (
    <div className="grid grid-12">
      <VCard span={6} kicker="Assurance digest" title="Hash-bound, not signed"
            subtitle="SHA-256 digest manifest over ledger, CBOM, attestation, transcript manifest, benchmark provenance, release manifest."
            actions={<VEv file="pqc_assurance_digest.json" path="digest_root" validator="scripts/generate_pqc_attestation.py" status="missing" />}>
        <div className="kvgrid">
          <VKV k="digest_root" v={<span className="mono dim">awaiting</span>} />
          <VKV k="artifact_count" v={<span className="mono dim">awaiting</span>} />
          <VKV k="schema_version" v={<span className="mono dim">awaiting</span>} />
        </div>
        <VHr />
        <div className="kv__k" style={{ marginBottom: 6 }}>Bound artifacts</div>
        <div className="subjgrid">
          {["assurance_ledger.json","pqc_cbom.cdx.json","pqc_attestation.intoto.json","transcripts/evidence_transcript_manifest.json","benchmark_provenance.json","release-manifest.json"].map(s => (
            <div key={s} className="subjrow">
              <span className="subjrow__f">{s}</span>
              <span className="subjrow__h">sha256: awaiting</span>
            </div>
          ))}
        </div>
      </VCard>

      <VCard span={6} kicker="Firmware-embeddable header" title="Generated C header"
            actions={<VEv file="generated/pqcp_assurance_digest_generated.h" validator="scripts/export_firmware_assurance_digest.py" status="missing" />}>
        <VCode label="C">{`/* generated/pqcp_assurance_digest_generated.h */
#define PQCP_ASSURANCE_DIGEST_ROOT      "<awaiting>"
#define PQCP_ASSURANCE_ARTIFACT_COUNT   /* awaiting */
#define PQCP_ASSURANCE_SCHEMA_VERSION   /* awaiting */`}</VCode>
        <VHr />
        <div className="dim mono">samples/pqcp_assurance_status — emits PQCP_ASSURANCE_STATUS and PQCP_ASSURANCE_ARTIFACT lines, verified by firmware_assurance_status_result.json</div>
      </VCard>

      <VCard span={12} kicker="Device evidence token" title="schema v7 additive marker"
            actions={<VEv file="device_evidence_token_result.json" validator="scripts/verify_device_evidence_token.py" status="missing" />}>
        <div className="splitcols">
          <VAwait file="device_evidence_token.json" validator="samples/pqcp_assurance_status"
            what="Additive device-evidence marker emitted by firmware. The replay verifier checks the marker against pqc_reference_values.json."
            supports={["firmware.device_evidence_token"]} />
          <VAwait file="firmware_assurance_status_result.json" validator="scripts/verify_firmware_assurance_status.py"
            what="Verifies PQCP_ASSURANCE_STATUS and PQCP_ASSURANCE_ARTIFACT transcript lines against reference values."
            supports={["firmware.assurance_status_report"]} />
        </div>
        <VCallout tone="info">Hardware evidence is <strong>optional</strong>. Absence of a connected board must not fail a normal local release gate unless the maintainer explicitly requests a hardware run (<span className="mono">scripts/run_hardware_benchmarks.py</span>, <span className="mono">hardware_review</span> mode).</VCallout>
      </VCard>

      <VCard span={12} kicker="SLSA-shaped build provenance" title="unsigned in-toto Statement"
            actions={<VEv file="pqc_build_provenance.slsa.json" validator="scripts/generate_pqc_build_provenance.py" status="missing" />}>
        <VAwait file="pqc_build_provenance.slsa.json" validator="scripts/generate_pqc_build_provenance.py"
          what="Subjects, resolved dependencies, external parameters, byproduct hashes. Replay-checked by verify_pqc_build_provenance.py."
          supports={["supply_chain.slsa_build_provenance"]} />
      </VCard>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// INTEGRATION
// ═══════════════════════════════════════════════════════════════════════════

function IntegrationView({ session }) {
  const [board, setBoard] = bS("qemu_x86_64");
  const [target, setTarget] = bS("tests/ztest_rng");
  const [tag, setTag] = bS("v1.0.0");
  const outRoot = session.path || "<release-pack>";

  return (
    <div className="grid grid-12">
      <VCard span={5} kicker="Consumer smoke" title="west-based downstream check"
            subtitle="scripts/consumer_smoke.py — minimum proof that a downstream Zephyr workspace can build this module"
            actions={<VEv file="scripts/consumer_smoke.py" status="present" />}>
        <div className="ctrl">
          <div className="ctrl__lbl"><span>Board</span></div>
          <select className="input mono" value={board} onChange={e => setBoard(e.target.value)}>
            <option>qemu_x86_64</option><option>native_sim</option><option>nucleo_h743zi</option>
          </select>
        </div>
        <div className="ctrl">
          <div className="ctrl__lbl"><span>Module-relative target</span></div>
          <select className="input mono" value={target} onChange={e => setTarget(e.target.value)}>
            <option>tests/ztest_rng</option>
            <option>tests/ztest_acvp_kat</option>
            <option>tests/ztest_ct_smoke</option>
            <option>tests/ztest_primitive</option>
            <option>tests/ztest_tls_selftest</option>
            <option>samples/pqcp_assurance_status</option>
          </select>
        </div>
        <div className="ctrl">
          <div className="ctrl__lbl"><span>Module mode</span></div>
          <select className="input mono" defaultValue="auto"><option>auto</option><option>manifest</option><option>extra-module</option></select>
        </div>
        <VHr />
        <VCode label="$ smoke">{`python3 scripts/consumer_smoke.py \\
  --board       ${board} \\
  --target      ${target} \\
  --build-dir   build-consumer-smoke`}</VCode>
        <div className="dim mono" style={{ fontSize: 11 }}>success marker · PROJECT EXECUTION SUCCESSFUL</div>
      </VCard>

      <VCard span={7} kicker="Release flow" title="Three commands, in order"
            subtitle="docs/release.md TL;DR. The console reads the pack the third command verifies.">
        <div className="flow">
          <FStep n="1" t="Run the full release gate"
            d="Produces JUnit, ledger, HTML report, transcripts, benchmark CSV + provenance, MCU footprint, release bundle, and every Passport artifact."
            code={`python3 scripts/release_check.py --tag ${tag} --output-root ${outRoot}`} />
          <FStep n="2" t="Optionally prepare the exact-tag bundle"
            d="--exact-tag requires a clean checkout that matches the tag. --verify-remote-tag confirms origin agrees."
            code={`git checkout ${tag}\npython3 scripts/prepare_release_bundle.py --exact-tag --verify-remote-tag`} />
          <FStep n="3" t="Replay-verify without rebuilding"
            d="Python 3.12 only. Re-hashes every recorded SHA-256, checks every required claim id, every Passport subject, every SLSA byproduct, every ACVP JSON transcript hash."
            code={`python3 scripts/verify_release_evidence_pack.py ${outRoot} --tag ${tag}`} />
        </div>
        <div className="ctrl" style={{ marginTop: 8 }}>
          <div className="ctrl__lbl"><span>Tag</span></div>
          <input className="input mono" value={tag} onChange={e => setTag(e.target.value)} />
        </div>
      </VCard>

      <VCard span={12} kicker="west.yml manifest" title="Authoritative module pins" actions={<VEv file="west.yml" status="present" />}>
        <VCode label="west.yml">{`manifest:
  self:
    path: pqcp-zephyr-trust-stack

  remotes:
    - name: zephyrproject-rtos
      url-base: https://github.com/zephyrproject-rtos
    - name: pqcp
      url-base: https://github.com/pq-code-package

  projects:
${PB.REPO.west_pins.map(p => `    - name: ${p.name}
      remote: ${p.remote}
      revision: ${p.revision}${p.name === "zephyr" ? "\n      import: true" : `\n      path: modules/crypto/${p.name}`}`).join("\n")}`}</VCode>
      </VCard>
    </div>
  );
}

function FStep({ n, t, d, code }) {
  return (
    <div className="flowstep">
      <div className="flowstep__n">{n}</div>
      <div>
        <div className="flowstep__t">{t}</div>
        <div className="flowstep__d">{d}</div>
        <VCode label={`$ step ${n}`}>{code}</VCode>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATOR
// ═══════════════════════════════════════════════════════════════════════════

function ConfiguratorView({ tweaks, setTweak, session }) {
  const [cfg, setCfg] = bS({
    mlkem_512: true, mlkem_768: true, mlkem_1024: false,
    mldsa_44: false, mldsa_65: true, mldsa_87: false,
    backend: "auto",
    kat_smoke_only: false,
    rtos_metrics: true,
    sanitizer_overlay: false,
    ct_sample_transcript: true,
    acvp_readline_timeout_ms: 5000,
    opt_level: "Os",
    lto: false,
    profile: "qemu_release",
    mode: session.mode || "partner_review",
  });
  function set(k, v) { setCfg(p => ({ ...p, [k]: v })); }

  const kconfigLines = [];
  if (cfg.mlkem_512 || cfg.mlkem_768 || cfg.mlkem_1024) kconfigLines.push("CONFIG_PQCP_MLKEM=y");
  if (cfg.mlkem_512)  kconfigLines.push("CONFIG_PQCP_MLKEM_LEVEL_512=y");
  if (cfg.mlkem_768)  kconfigLines.push("CONFIG_PQCP_MLKEM_LEVEL_768=y");
  if (cfg.mlkem_1024) kconfigLines.push("CONFIG_PQCP_MLKEM_LEVEL_1024=y");
  if (cfg.mldsa_44 || cfg.mldsa_65 || cfg.mldsa_87) kconfigLines.push("CONFIG_PQCP_MLDSA=y");
  if (cfg.mldsa_44) kconfigLines.push("CONFIG_PQCP_MLDSA_LEVEL_44=y");
  if (cfg.mldsa_65) kconfigLines.push("CONFIG_PQCP_MLDSA_LEVEL_65=y");
  if (cfg.mldsa_87) kconfigLines.push("CONFIG_PQCP_MLDSA_LEVEL_87=y");
  kconfigLines.push("");
  kconfigLines.push("# RNG");
  if (cfg.profile === "native_lab") {
    kconfigLines.push("CONFIG_PQCP_RNG_CUSTOM=y");
    kconfigLines.push("CONFIG_PQCP_RNG_DETERMINISTIC_TEST=y  # test-only; forbidden in qemu_release/mcu_minimal/gateway");
  } else {
    kconfigLines.push("CONFIG_PQCP_RNG_ZEPHYR_ENTROPY=y");
  }
  kconfigLines.push("");
  kconfigLines.push("# Validation harness");
  if (cfg.profile !== "mcu_minimal" && cfg.profile !== "gateway") {
    kconfigLines.push("CONFIG_PQCP_ACVP=y");
    kconfigLines.push(`CONFIG_PQCP_ACVP_READLINE_TIMEOUT_MS=${cfg.acvp_readline_timeout_ms}`);
  }
  if (cfg.kat_smoke_only) kconfigLines.push("CONFIG_PQCP_KAT_SMOKE_ONLY=y");
  kconfigLines.push("");
  kconfigLines.push("# Boot self-verify");
  kconfigLines.push("CONFIG_PQCP_KAT_BOOT_VERIFY=y");

  return (
    <div className="grid grid-12">
      <VCard span={5} kicker="Configurator" title="Compose a Kconfig overlay"
            subtitle="Toggles only use Kconfig symbols declared in scripts/pqc_asset_trace_map.json. The console never edits the repo.">
        <div className="cfgsect">
          <div className="cfgsect__h">Profile</div>
          <select className="input mono" value={cfg.profile} onChange={e => set("profile", e.target.value)}>
            {PB.PROFILES.map(p => <option key={p.id} value={p.id}>{p.id}</option>)}
          </select>
          <div className="dim" style={{ fontSize: 11, marginTop: 6 }}>{PB.PROFILES.find(p => p.id === cfg.profile)?.description}</div>
        </div>

        <div className="cfgsect">
          <div className="cfgsect__h">ML-KEM parameter sets</div>
          <CfgRow label="ML-KEM-512" sym="PQCP_MLKEM_LEVEL_512" v={cfg.mlkem_512} on={v => set("mlkem_512", v)} />
          <CfgRow label="ML-KEM-768" sym="PQCP_MLKEM_LEVEL_768" v={cfg.mlkem_768} on={v => set("mlkem_768", v)} note="default in mcu_minimal" />
          <CfgRow label="ML-KEM-1024" sym="PQCP_MLKEM_LEVEL_1024" v={cfg.mlkem_1024} on={v => set("mlkem_1024", v)} />
        </div>

        <div className="cfgsect">
          <div className="cfgsect__h">ML-DSA parameter sets</div>
          <CfgRow label="ML-DSA-44" sym="PQCP_MLDSA_LEVEL_44" v={cfg.mldsa_44} on={v => set("mldsa_44", v)} />
          <CfgRow label="ML-DSA-65" sym="PQCP_MLDSA_LEVEL_65" v={cfg.mldsa_65} on={v => set("mldsa_65", v)} note="default in mcu_minimal" />
          <CfgRow label="ML-DSA-87" sym="PQCP_MLDSA_LEVEL_87" v={cfg.mldsa_87} on={v => set("mldsa_87", v)} />
        </div>

        <div className="cfgsect">
          <div className="cfgsect__h">Validation & evidence</div>
          <CfgRow label="KAT smoke only" sym="PQCP_KAT_SMOKE_ONLY" v={cfg.kat_smoke_only} on={v => set("kat_smoke_only", v)} />
          <CfgRow label="CT sample transcript" sym="(PQCP_CT_SAMPLE markers)" v={cfg.ct_sample_transcript} on={v => set("ct_sample_transcript", v)} />
          <CfgRow label="RTOS metrics" sym="(bench.h emission)" v={cfg.rtos_metrics} on={v => set("rtos_metrics", v)} />
          <CfgRow label="Sanitizer overlay (native_sim)" sym="run_sanitizer_checks.py" v={cfg.sanitizer_overlay} on={v => set("sanitizer_overlay", v)} />
        </div>

        <div className="cfgsect">
          <div className="cfgsect__h">ACVP timing</div>
          <Ctrl label="readline timeout (ms)" v={cfg.acvp_readline_timeout_ms} min={500} max={20000} step={500} onChange={v => set("acvp_readline_timeout_ms", v)} hint="CONFIG_PQCP_ACVP_READLINE_TIMEOUT_MS" />
        </div>

        <div className="cfgsect">
          <div className="cfgsect__h">Backend & optimization</div>
          <div className="ctrl">
            <div className="ctrl__lbl"><span>Backend selector</span></div>
            <select className="input mono" value={cfg.backend} onChange={e => set("backend", e.target.value)}>
              <option value="auto">auto</option>
              <option value="native">native (mlkem-native / mldsa-native)</option>
              <option value="baseline">baseline (C-only)</option>
            </select>
          </div>
          <div className="ctrl">
            <div className="ctrl__lbl"><span>Optimization level</span></div>
            <VSeg value={cfg.opt_level} onChange={v => set("opt_level", v)} options={["Os", "O2", "O3"]} />
          </div>
          <div className="cfgrow">
            <div>
              <div className="cfgrow__l">Link-time optimization</div>
              <div className="cfgrow__s">CONFIG_LTO</div>
            </div>
            <VSwitch value={cfg.lto} onChange={v => set("lto", v)} />
          </div>
        </div>

        <div className="cfgsect">
          <div className="cfgsect__h">Release mode</div>
          <select className="input mono" value={cfg.mode} onChange={e => set("mode", e.target.value)}>
            {PB.MODES.modes.map(m => <option key={m.id} value={m.id}>{m.id}</option>)}
          </select>
          <div className="dim" style={{ fontSize: 11, marginTop: 6 }}>{PB.MODES.modes.find(m => m.id === cfg.mode)?.description}</div>
        </div>
      </VCard>

      <VCard span={7} kicker="Generated overlay" title="prj.conf.overlay"
            subtitle="Pasteable. Symbols match scripts/pqc_asset_trace_map.json. Forbidden combinations are commented inline.">
        <VCode label="prj.conf overlay">{kconfigLines.join("\n")}</VCode>
        <VHr />
        <div className="kv__k" style={{ marginBottom: 6 }}>west build</div>
        <VCode label="$ build">{`west build -p always -b qemu_x86_64 tests/ztest_acvp_kat \\
  -- -DOVERLAY_CONFIG=prj.conf.overlay \\
     -DCONFIG_COMPILER_OPT="-${cfg.opt_level}" \\
     ${cfg.lto ? "-DCONFIG_LTO=y" : "# LTO disabled"}`}</VCode>
        <div className="kv__k" style={{ marginBottom: 6 }}>release_check.py</div>
        <VCode label="$ release_check">{`python3 scripts/release_check.py \\
  --tag v1.0.0 \\
  --output-root ${session.path || "<release-pack>"}`}</VCode>
        <div className="kv__k" style={{ marginBottom: 6 }}>optimize_metric_campaign.py</div>
        <VCode label="$ optimize">{`python3 scripts/optimize_metric_campaign.py \\
  --in        ${session.path || "<pack>"}/benchmark_campaign_result.json \\
  --objective ${tweaks.objective} \\
  --out       ${session.path || "<pack>"}/optimize_metric_campaign_result.json`}</VCode>
        <VCallout tone="info">Selecting <span className="mono">native_lab</span> permits <span className="mono">CONFIG_PQCP_RNG_DETERMINISTIC_TEST=y</span>; selecting <span className="mono">qemu_release</span>, <span className="mono">mcu_minimal</span>, or <span className="mono">gateway</span> forbids it. Enforced by <span className="mono">scripts/verify_pqc_assurance_profile.py</span>, not by this UI.</VCallout>
      </VCard>
    </div>
  );
}

function CfgRow({ label, sym, v, on, note }) {
  return (
    <div className="cfgrow">
      <div>
        <div className="cfgrow__l">{label}</div>
        <div className="cfgrow__s">CONFIG_{sym}{note ? <span className="dim"> · {note}</span> : null}</div>
      </div>
      <VSwitch value={v} onChange={on} />
    </div>
  );
}

window.VIEWS_B = { ProvenanceView, BenchLabView, ValidationView, FirmwareView, IntegrationView, ConfiguratorView };
