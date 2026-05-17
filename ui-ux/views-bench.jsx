// views-bench.jsx — Benchmark Lab driven by benchmark_campaign_result.json,
// benchmark_provenance.json, cost_of_assurance_evidence.json, and
// backend_currency_result.json. Sliders generate CLI commands; nothing is
// "run" in the browser.

const { Card: BnCard, KV: BnKV, Tag: BnTag, Badge: BnBadge, Hr: BnHr, Sev: BnSev,
        Kpi: BnKpi, Tabs: BnTabs, Segmented: BnSeg, Pagination: BnPgn, usePaged: bnUsePaged,
        EvBind: BnEv, Callout: BnCallout, Code: BnCode, EmptyState: BnEmpty, Switch: BnSwitch } = window.UI;
const { HashChip: BnHash, OriginChip: BnOrigin, EvBind2: BnEvBind2,
        DetailRow: BnDetail, StatGrid: BnSGrid, Stat: BnStat,
        ChecksList: BnChecks, BHX: BnBHX, BHXCell: BnBHXCell, RBar: BnRBar } = window.UIX;
const BnP = window.PQCP;
const BnS = window.STORE;
const { useState: bnS, useMemo: bnM } = React;

function BenchLabView({ tweaks, setTweak, session, pack }) {
  const reps = tweaks.reps;
  const minImpr = tweaks.minMedianImpr;
  const maxRegrP90 = tweaks.maxRegrP90;
  const maxRegrRom = tweaks.maxRegrRom;
  const objective = tweaks.objective;
  const [view, setView] = bnS("table");

  const bench = BnS.benchmarkCampaign(pack);
  const cost = BnS.costOfAssurance(pack);
  const backend = BnS.backendCurrency(pack);
  const prov = BnS.benchmarkProvenance(pack);

  const algoSets = bnM(() => {
    if (!bench || !bench.rows) return [];
    const keys = new Set();
    bench.rows.forEach(r => keys.add(r.parameter_set));
    return [...keys].sort();
  }, [bench]);

  // Pair rows: baseline vs pqcp for the same (parameter_set, operation)
  const pairs = bnM(() => {
    if (!bench || !bench.rows) return [];
    const byKey = {};
    bench.rows.forEach(r => {
      const k = `${r.parameter_set}|${r.operation}`;
      if (!byKey[k]) byKey[k] = {};
      const isPqcp = r.implementation === "pqcp" || r.backend === "auto" || r.backend === "native";
      byKey[k][isPqcp ? "pqcp" : "baseline"] = r;
    });
    return Object.entries(byKey).map(([k, v]) => {
      const [ps, op] = k.split("|");
      const baseline = v.baseline, pqcp = v.pqcp;
      const medianRatio = baseline?.median && pqcp?.median ? pqcp.median / baseline.median : null;
      const p99Ratio = baseline?.p99 && pqcp?.p99 ? pqcp.p99 / baseline.p99 : null;
      const romRatio = baseline?.rom_bytes && pqcp?.rom_bytes ? pqcp.rom_bytes / baseline.rom_bytes : null;
      const verdict = (medianRatio != null && medianRatio < (1 - minImpr / 100) && (p99Ratio == null || p99Ratio < (1 + maxRegrP90 / 100)) && (romRatio == null || romRatio < (1 + maxRegrRom / 100)))
        ? "keep"
        : (p99Ratio != null && p99Ratio > (1 + maxRegrP90 / 100)) || (romRatio != null && romRatio > (1 + maxRegrRom / 100))
          ? "reject"
          : "neutral";
      return { ps, op, baseline, pqcp, medianRatio, p99Ratio, romRatio, verdict };
    }).sort((a, b) => (a.ps + a.op).localeCompare(b.ps + b.op));
  }, [bench, minImpr, maxRegrP90, maxRegrRom]);

  const passedCt = pairs.filter(p => p.verdict === "keep").length;
  const rejectCt = pairs.filter(p => p.verdict === "reject").length;

  return (
    <>
      <div className="grid-kpi" style={{ marginBottom: 12 }}>
        <BnKpi label="Campaign" status={bench?.passed === true ? "ok" : bench?.passed === false ? "err" : "warn"}
               value={bench ? (bench.passed ? "pass" : "fail") : "—"}
               sub={bench ? `${bench.rows.length} rows · ${algoSets.length} algos` : "awaiting benchmark_campaign_result.json"}
               evbind={<BnEvBind2 ev={bench?.evbind} compact />} />
        <BnKpi label="Repetitions" status="info" value={bench?.config?.repetitions ?? reps} sub="config.repetitions" />
        <BnKpi label="Keep candidates" status={passedCt > 0 ? "ok" : "warn"} value={pairs.length ? passedCt : "—"} sub={`min impr ${minImpr.toFixed(1)}%`} />
        <BnKpi label="Reject candidates" status={rejectCt > 0 ? "err" : "ok"} value={pairs.length ? rejectCt : "—"} sub={`max p90 regr ${maxRegrP90.toFixed(1)}%`} />
        <BnKpi label="Backend currency" status={backend?.passed === true ? "ok" : backend?.passed === false ? "err" : "warn"}
               value={backend ? (backend.passed ? "pass" : "fail") : "—"}
               sub={backend ? `${backend.backends.length} backends` : "awaiting backend_currency_result.json"}
               evbind={<BnEvBind2 ev={backend?.evbind} compact />} />
      </div>

      <div className="grid grid-12">
        <BnCard span={4} kicker="Optimization thresholds" title="Acceptance gates"
              subtitle="Sliders compose CLI flags for scripts/optimize_metric_campaign.py — they do not run the benchmark inside the browser.">
          <BnCtrl label="Repetitions" v={reps} min={1} max={50} step={1} onChange={v => setTweak("reps", v)} hint={`campaign default · ${BnP.CAMPAIGN.repetitions}`} />
          <BnCtrl label="Min median improvement" v={minImpr} unit="%" min={0} max={50} step={0.5} onChange={v => setTweak("minMedianImpr", v)} />
          <BnCtrl label="Max p90/p99 regression" v={maxRegrP90} unit="%" min={0} max={25} step={0.5} onChange={v => setTweak("maxRegrP90", v)} />
          <BnCtrl label="Max ROM/RAM regression" v={maxRegrRom} unit="%" min={0} max={20} step={0.5} onChange={v => setTweak("maxRegrRom", v)} />
          <div className="ctrl">
            <div className="ctrl__lbl"><span>Objective</span></div>
            <select className="input mono" value={objective} onChange={e => setTweak("objective", e.target.value)}>
              <option value="cycles_median">cycles_median</option>
              <option value="cycles_p90">cycles_p90</option>
              <option value="cycles_p99">cycles_p99</option>
              <option value="handshake_p99_ms">handshake_p99_ms</option>
            </select>
          </div>
          <BnHr />
          <div className="kv__k" style={{ marginBottom: 6 }}>Campaign context</div>
          {bench?.comparison_context ? (
            <>
              <BnDetail k="environment" v={<BnOrigin env={bench.comparison_context.environment_type} />} />
              <BnDetail k="board class" v={<span className="mono">{bench.comparison_context.board_class}</span>} />
              <BnDetail k="dataset" v={<span className="mono">{bench.comparison_context.source_dataset}</span>} />
              <BnDetail k="statistic" v={<span className="mono">{bench.comparison_context.statistic_type}</span>} />
              <BnDetail k="physical?" v={<BnTag tone={bench.comparison_context.is_physical_measurement ? "info" : "warn"}>{String(bench.comparison_context.is_physical_measurement)}</BnTag>} />
            </>
          ) : <span className="dim">awaiting</span>}
        </BnCard>

        <BnCard span={8} kicker="Command preview" title="CommandPreview · slider state → CLI"
              subtitle="Copy and run locally on a Python 3.12 host. The console never executes commands.">
          <BnCode label="$ run campaign">{`python3 scripts/run_benchmark_campaign.py \\
  --config       scripts/pqc_benchmark_campaign.json \\
  --warmup       ${BnP.CAMPAIGN.warmup_runs} \\
  --repetitions  ${reps} \\
  --statistics   ${BnP.CAMPAIGN.required_statistics.join(",")} \\
  --out          ${session.path || "<pack>"}/benchmark_campaign_result.json`}</BnCode>
          <BnCode label="$ optimize metric campaign">{`python3 scripts/optimize_metric_campaign.py \\
  --in              ${session.path || "<pack>"}/benchmark_campaign_result.json \\
  --objective       ${objective} \\
  --min-improvement ${(minImpr / 100).toFixed(3)} \\
  --max-p90-regr    ${(maxRegrP90 / 100).toFixed(3)} \\
  --max-rom-regr    ${(maxRegrRom / 100).toFixed(3)} \\
  --out             ${session.path || "<pack>"}/optimize_metric_campaign_result.json`}</BnCode>
          <BnCallout tone="info">Candidates classified <span className="mono">keep</span> are <strong>measurement_only</strong>. CBOM, profile, and policy gates must still pass before a candidate is promotable.</BnCallout>
        </BnCard>

        {/* Bench surface */}
        <BnCard span={12} kicker="Benchmark surface" title={bench ? `${pairs.length} algo×op pairs` : "Awaiting benchmark_campaign_result.json"}
              subtitle="Per-algorithm distribution rows: min · median · p90 · p99 · MAD · ROM/RAM. Verdicts are computed from the slider thresholds."
              padded={false}
              actions={<>
                <BnSeg size="sm" value={view} onChange={setView}
                  options={[{ id: "table", label: "rows" }, { id: "hex", label: "heatmap" }, { id: "raw", label: "raw" }]} />
                <BnEvBind2 ev={bench?.evbind} />
              </>}>
          {!bench ? (
            <div style={{ padding: 14 }}>
              <BnEmpty icon="○" title="No benchmark results yet"
                hint="Produced by scripts/run_benchmark_campaign.py against the local QEMU benchmark harness." />
            </div>
          ) : view === "table" ? (
            <BenchTable pairs={pairs} />
          ) : view === "hex" ? (
            <BenchHex pairs={pairs} />
          ) : (
            <pre className="code__pre" style={{ fontSize: 11, padding: 14, maxHeight: 520, overflow: "auto" }}>{JSON.stringify(bench.rows.slice(0,12), null, 2)}{bench.rows.length > 12 ? `\n… +${bench.rows.length - 12} more rows …` : ""}</pre>
          )}
        </BnCard>

        {/* Backend currency */}
        <BnCard span={6} kicker="Backend currency" title={backend ? (backend.passed ? "Pinned · current" : "Pinned · drift detected") : "Awaiting backend_currency_result.json"}
              subtitle="Comparison-only review of pinned mlkem-native / mldsa-native metadata."
              actions={<BnEvBind2 ev={backend?.evbind} compact />}>
          {!backend ? (
            <BnEmpty icon="○" title="No backend evaluation" hint="Produced by scripts/evaluate_backend_update.py." />
          ) : (
            <>
              {(backend.backends || []).map(b => {
                const m = b.backend_metadata || {};
                return (
                  <div key={b.name || m.meta_path} style={{ padding: "10px 0", borderBottom: "1px solid var(--line)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
                      <span className="mono"><strong>{b.name || (m.meta_path || "").split("/").slice(-2)[0]}</strong></span>
                      <BnTag tone={m.available ? "ok" : "warn"}>{m.available ? "available" : "missing"}</BnTag>
                    </div>
                    <BnDetail k="license sha256" v={m.license_sha256 ? <BnHash sha={m.license_sha256} /> : null} />
                    <BnDetail k="META.yml sha256" v={m.meta_sha256 ? <BnHash sha={m.meta_sha256} /> : null} />
                    <BnDetail k="implementations" v={m.metadata?.implementations ? <span className="mono">{m.metadata.implementations.length}</span> : null} />
                  </div>
                );
              })}
              {(backend.warnings || []).length > 0 && (
                <BnCallout tone="warn" title="Warnings"><ul className="filelist">{backend.warnings.map((w, i) => <li key={i} className="filelist__f filelist__f--wrap">{typeof w === "string" ? w : JSON.stringify(w)}</li>)}</ul></BnCallout>
              )}
            </>
          )}
        </BnCard>

        {/* Cost-of-assurance */}
        <BnCard span={6} kicker="Cost of assurance" title={cost ? `${(cost.comparisons || []).length} comparisons` : "Awaiting cost_of_assurance_evidence.json"}
              subtitle="Each comparison declares a baseline and a candidate selector; per-metric thresholds gate promotion."
              actions={<BnEvBind2 ev={cost?.evbind} compact />}>
          {!cost ? (
            <BnEmpty icon="○" title="No cost-of-assurance evidence" hint="Produced by scripts/release_check.py." />
          ) : (
            <div style={{ maxHeight: 460, overflowY: "auto" }}>
              {(cost.comparisons || []).slice(0, 6).map((cmp, i) => (
                <div key={i} style={{ padding: 10, borderBottom: "1px solid var(--line)" }}>
                  <div style={{ fontSize: 11, fontFamily: "IBM Plex Mono", color: "var(--fg-1)" }}>
                    {cmp.baseline_selectors?.algorithm}-{cmp.baseline_selectors?.level} · {cmp.baseline_selectors?.profile} · {cmp.candidate_selectors?.backend}
                  </div>
                  <table className="tbl" style={{ marginTop: 4, fontSize: 11 }}>
                    <tbody>
                      {(cmp.metrics || []).map((m, j) => (
                        <tr key={j}>
                          <td className="mono dim">{m.metric}</td>
                          <td className="num mono">{m.baseline_value}</td>
                          <td className="num mono">{m.candidate_value}</td>
                          <td className="num"><BnRBar ratio={m.ratio} span={0.6} /></td>
                          <td><BnTag tone={m.passed ? "ok" : "err"}>{m.passed ? "pass" : "fail"}</BnTag></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ))}
              {(cost.comparisons || []).length > 6 && <div className="dim mono" style={{ padding: 10 }}>+{cost.comparisons.length - 6} more comparisons …</div>}
            </div>
          )}
        </BnCard>

        {/* Provenance summary */}
        {prov && (
          <BnCard span={12} kicker="Benchmark provenance" title="Hash-bound run context"
                subtitle="benchmark_provenance.json — host, platform, compiler, profile flags, smoke flags. All bound to the CSV bytes."
                actions={<BnEvBind2 ev={prov.evbind} compact />}>
            <BnSGrid>
              <BnStat k="csv sha256" v={prov.csv?.sha256 ? <BnHash sha={prov.csv.sha256} /> : "—"} s={prov.csv?.path ? prov.csv.path.split("/").pop() : null} />
              <BnStat k="board" v={prov.benchmark_metadata?.by_key?.["board.name"]?.[0] || "—"} />
              <BnStat k="compiler" v={prov.benchmark_metadata?.by_key?.["compiler.id"]?.[0] || "—"} />
              <BnStat k="sample cap" v={prov.benchmark_metadata?.by_key?.["distribution.sample_cap"]?.[0] || "—"} />
              <BnStat k="environment" v={prov.comparison_context?.environment_type || "—"} />
              <BnStat k="physical?" v={String(prov.comparison_context?.is_physical_measurement ?? "—")} />
            </BnSGrid>
          </BnCard>
        )}
      </div>
    </>
  );
}

function BenchTable({ pairs }) {
  const paged = bnUsePaged(pairs, 18);
  return (
    <>
      <table className="tbl">
        <thead><tr>
          <th>Algo</th><th>Op</th>
          <th className="num">median (base)</th>
          <th className="num">median (pqcp)</th>
          <th className="num">p99 (pqcp)</th>
          <th className="num">MAD</th>
          <th className="num">samples</th>
          <th className="num">ROM Δ</th>
          <th>median ratio</th>
          <th>Verdict</th>
        </tr></thead>
        <tbody>
          {paged.rows.map(p => (
            <tr key={p.ps + p.op}>
              <td className="mono"><strong>{p.ps}</strong></td>
              <td className="mono dim">{p.op}</td>
              <td className="num mono">{p.baseline?.median ?? "—"}</td>
              <td className="num mono">{p.pqcp?.median ?? "—"}</td>
              <td className="num mono">{p.pqcp?.p99 ?? "—"}</td>
              <td className="num mono">{p.pqcp?.mad ?? "—"}</td>
              <td className="num mono">{p.pqcp?.sample_count ?? "—"}</td>
              <td className="num mono">{p.romRatio == null ? "—" : (p.romRatio * 100 - 100).toFixed(1) + "%"}</td>
              <td style={{ minWidth: 130 }}>
                {p.medianRatio == null
                  ? <span className="dim">—</span>
                  : <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <BnRBar ratio={p.medianRatio} span={0.6} />
                      <span className="mono" style={{ fontSize: 10.5 }}>{p.medianRatio.toFixed(2)}×</span>
                    </div>}
              </td>
              <td>
                {p.verdict === "keep"   && <BnTag tone="ok">keep</BnTag>}
                {p.verdict === "reject" && <BnTag tone="err">reject</BnTag>}
                {p.verdict === "neutral" && <BnTag>neutral</BnTag>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <BnPgn {...paged} onChange={paged.setPage} />
    </>
  );
}

function BenchHex({ pairs }) {
  return (
    <BnBHX>
      {pairs.map(p => (
        <BnBHXCell key={p.ps + p.op}
          label={`${p.ps} · ${p.op}`}
          value={p.pqcp?.median ?? "—"}
          ratio={p.medianRatio}
          sub={p.medianRatio == null ? "no pair" : `${p.medianRatio.toFixed(2)}× vs baseline · p99 ${p.p99Ratio?.toFixed(2)}×`}
        />
      ))}
    </BnBHX>
  );
}

function BnCtrl({ label, v, unit, min, max, step, onChange, hint }) {
  return (
    <div className="ctrl">
      <div className="ctrl__lbl"><span>{label}</span><span className="mono">{typeof v === "number" ? v.toFixed?.(2) ?? v : v}{unit}</span></div>
      <input type="range" className="range" min={min} max={max} step={step} value={v} onChange={e => onChange(+e.target.value)} />
      {hint && <div className="ctrl__hint dim mono">{hint}</div>}
    </div>
  );
}

window.VIEW_BENCH = { BenchLabView };
