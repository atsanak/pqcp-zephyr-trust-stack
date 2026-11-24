// views-inventory.jsx, CBOM inventory + Migration readiness + Asset drawer.

const { Card: InCard, KV: InKV, Tag: InTag, Badge: InBadge, Hr: InHr, Sev: InSev,
        Kpi: InKpi, Tabs: InTabs, Pagination: InPgn, usePaged: inUsePaged,
        EvBind: InEv, Callout: InCallout, Code: InCode, EmptyState: InEmpty } = window.UI;
const { HashChip: InHash, OriginChip: InOrigin, EvBind2: InEvBind2,
        DetailRow: InDetail, StatGrid: InSGrid, Stat: InStat,
        ChecksList: InChecks, DTabs: InDT } = window.UIX;
const InP = window.PQCP;
const InS = window.STORE;
const { useState: inS_, useMemo: inM } = React;

function inFiltersSafe() { return (window.useFilters && window.useFilters()) || {}; }
function inDrawerSafe()  { return (window.useDrawer  && window.useDrawer())  || { openDrawer: () => {} }; }

function InventoryView({ session, pack }) {
  const f = inFiltersSafe();
  const drawer = inDrawerSafe();
  const comps = InS.cbomComponents(pack);
  const meta = InS.cbomMeta(pack);
  const mig = InS.migrationReadiness(pack);

  const rows = inM(() => {
    const list = comps.length ? comps.map(c => ({ ...c, _source: "cbom" })) : InP.ASSETS.map(a => ({
      name: a.cbom || a.name, _source: "catalog",
      productionAllowed: !a.test_only,
      productionStatus: a.test_only ? "test_only" : null,
      lifecycleStatus: null,
      profileSupport: [], validationScope: [],
      traceAssetId: a.id, claimIds: a.claims, claimStatuses: {},
      primitive: a.category, parameterSet: a.cbom,
      licenses: [],
      raw: null,
    }));
    if (!f.q) return list;
    const q = f.q.toLowerCase();
    return list.filter(c => (c.name + " " + (c.traceAssetId || "") + " " + (c.claimIds || []).join(" ")).toLowerCase().includes(q));
  }, [comps, f.q]);

  const paged = inUsePaged(rows, 16);

  const floor = InS.cbomFloorState(pack, InP.POLICY.required_cbom_components);

  return (
    <>
      <div className="grid-kpi" style={{ marginBottom: 12 }}>
        <InKpi label="CBOM components" status={meta ? "info" : "warn"}
               value={meta ? meta.component_count : "n/a"}
               sub={meta ? `spec ${meta.specVersion}` : "awaiting pqc_cbom.cdx.json"}
               evbind={<InEvBind2 ev={meta?.evbind} compact />} />
        <InKpi label="Floor coverage" status={floor.missing.length === 0 && meta ? "ok" : "warn"}
               value={meta ? `${floor.floor_present}/${floor.floor_total}` : "n/a"}
               sub={floor.missing.length ? `missing: ${floor.missing.length}` : "all required components present"} />
        <InKpi label="Production-allowed" status="info"
               value={comps.filter(c => c.productionAllowed).length || "n/a"}
               sub="pqcp:production_allowed=true" />
        <InKpi label="Test-only" status={comps.find(c => c.name === "Deterministic test RNG" && c.productionAllowed) ? "err" : "warn"}
               value={comps.filter(c => c.productionStatus === "test_only" || !c.productionAllowed).length || "n/a"}
               sub="forbidden in production profiles" />
        <InKpi label="Migration readiness" status={mig?.passed === false ? "err" : mig?.passed ? "ok" : "warn"}
               value={mig ? (mig.passed ? "ready" : "blocked") : "n/a"}
               sub={mig?.blocked_conditions?.length ? `${mig.blocked_conditions.length} blocked` : "awaiting"}
               evbind={<InEvBind2 ev={mig?.evbind} compact />} />
      </div>

      <div className="grid grid-12">
        {/* CBOM component table */}
        <InCard span={12} kicker="Crypto inventory" title="CycloneDX components · pqcp:* properties"
              subtitle="Production status, lifecycle, profile support, validation scope and claim outcomes are parsed directly from the CBOM."
              padded={false}
              actions={meta ? <InEvBind2 ev={meta.evbind} /> : null}>
          {!meta ? (
            <div style={{ padding: 14 }}>
              <InEmpty icon="○" title="Awaiting pqc_cbom.cdx.json"
                hint="Showing the catalog-only inventory until the CBOM is parsed. Production gating, lifecycle, and profile fields will populate once the pack is loaded." />
            </div>
          ) : (
            <>
              <table className="tbl">
                <thead><tr>
                  <th style={{ width: 22 }}></th>
                  <th>Component</th>
                  <th>Primitive</th>
                  <th>Lifecycle</th>
                  <th>Profile support</th>
                  <th>Validation scope</th>
                  <th>Claims</th>
                  <th className="num">v</th>
                  <th>Status</th>
                  <th className="act"></th>
                </tr></thead>
                <tbody>
                  {paged.rows.map(c => {
                    const allPass = (Object.values(c.claimStatuses).every(s => s === "pass") && Object.keys(c.claimStatuses).length > 0);
                    const someFail = Object.values(c.claimStatuses).some(s => s === "fail");
                    const isTest = !c.productionAllowed || c.productionStatus === "test_only" || c.lifecycleStatus === "test_only";
                    return (
                      <tr key={c.name} onClick={() => drawer.openDrawer("cbom", { id: c.name, title: c.name, subtitle: c.parameterSet || c.primitive })} style={{ cursor: "pointer" }}>
                        <td><span className={`sdot ${someFail ? "sdot--fail" : allPass ? "sdot--pass" : isTest ? "sdot--warn" : "sdot--neutral"}`} /></td>
                        <td className="mono"><strong style={{ color: "var(--fg-0)" }}>{c.name}</strong>{c.standard && <InBadge tone="info" size="sm" style={{ marginLeft: 6 }}>{c.standard}</InBadge>}</td>
                        <td className="mono dim">{c.primitive || c.cryptoAssetType || "n/a"}</td>
                        <td>{c.lifecycleStatus ? <InTag tone={c.lifecycleStatus === "test_only" ? "warn" : c.lifecycleStatus === "default" ? "ok" : "info"}>{c.lifecycleStatus}</InTag> : <span className="dim">n/a</span>}</td>
                        <td>
                          <div className="proflist">
                            {c.profileSupport.length === 0 ? <span className="dim">n/a</span> : c.profileSupport.map(p => <span key={p} className={`prof ${p === "native_lab" ? "prof--test" : ""}`}>{p}</span>)}
                          </div>
                        </td>
                        <td>
                          <div className="kchips">
                            {c.validationScope.slice(0,3).map(v => <span key={v} className="kchip">{v}</span>)}
                            {c.validationScope.length > 3 && <span className="kchip dim">+{c.validationScope.length - 3}</span>}
                          </div>
                        </td>
                        <td className="num mono">{c.claimIds.length || "n/a"}</td>
                        <td className="mono dim">{c.version || "n/a"}</td>
                        <td>{c.productionAllowed
                          ? <InTag tone="ok">production</InTag>
                          : <InTag tone="warn">test-only</InTag>}
                        </td>
                        <td className="act"><button className="actbtn">Inspect →</button></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <InPgn {...paged} onChange={paged.setPage} />
            </>
          )}
        </InCard>

        {/* CBOM floor */}
        <InCard span={6} kicker="Required CBOM components" title={`${floor.floor_present}/${floor.floor_total} present`}
              subtitle="Policy verifier rejects the pack if any of these are absent."
              actions={<InEvBind2 ev={InS.evbind(pack, "pqc_cbom.cdx.json", "components[].name")} compact />}>
          <div className="reqcomp">
            {InP.POLICY.required_cbom_components.map(c => {
              const has = comps.some(x => x.name === c);
              return (
                <div key={c} className="reqcomp__row">
                  <span className="mono">{c}</span>
                  <InTag tone={has ? "ok" : meta ? "err" : "warn"}>{has ? "present" : meta ? "missing" : "awaiting"}</InTag>
                </div>
              );
            })}
          </div>
          <InHr />
          <div className="dim" style={{ fontSize: 11.5 }}>
            <span className="mono">forbidden_production_rng_components:</span>{" "}
            {InP.POLICY.forbidden_production_rng_components.map(c => {
              const det = comps.find(x => x.name === c);
              const tone = !det ? "neutral" : det.productionAllowed ? "err" : "ok";
              const label = !det ? "not in cbom" : det.productionAllowed ? "violation: production-allowed" : "test-only · OK";
              return <InTag key={c} tone={tone}>{c}: {label}</InTag>;
            })}
          </div>
        </InCard>

        {/* Migration readiness asset table */}
        <InCard span={6} kicker="Migration readiness" title={mig ? (mig.passed ? "Ready" : "Blocked") : "Awaiting pqc_migration_readiness.json"}
              subtitle="Per-asset profile support and validation-scope rollup."
              actions={<InEvBind2 ev={mig?.evbind} compact />}>
          {!mig ? (
            <InEmpty icon="○" title="No migration readiness report" hint="Produced by scripts/generate_migration_readiness_report.py." />
          ) : (
            <>
              <InSGrid>
                {Object.entries(mig.profile_summary || {}).map(([p, n]) => <InStat key={p} k={p} v={typeof n === "number" ? n : (n?.count ?? "n/a")} />)}
              </InSGrid>
              <InHr />
              <div className="kv__k" style={{ marginBottom: 6 }}>Per-asset migration status</div>
              <table className="tbl" style={{ background: "var(--bg-1)" }}>
                <thead><tr><th>Asset</th><th>Lifecycle</th><th>Production</th><th>Profiles</th></tr></thead>
                <tbody>
                  {(mig.assets || []).slice(0, 12).map(a => (
                    <tr key={a.name || a.trace_asset_id}>
                      <td className="mono"><strong>{a.name}</strong></td>
                      <td><InTag tone={a.lifecycle_status === "test_only" ? "warn" : a.lifecycle_status === "default" ? "ok" : "info"}>{a.lifecycle_status}</InTag></td>
                      <td><InTag tone={a.production_allowed === "true" || a.production_allowed === true ? "ok" : "warn"}>{String(a.production_allowed)}</InTag></td>
                      <td><div className="proflist">{(a.profile_support || []).map(p => <span key={p} className="prof">{p}</span>)}</div></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {(mig.blocked_conditions || []).length > 0 && (
                <>
                  <InHr />
                  <InCallout tone="warn" title="Blocked conditions">
                    <ul className="filelist">{mig.blocked_conditions.map((b, i) => <li key={i} className="filelist__f filelist__f--wrap">{typeof b === "string" ? b : (b.reason || JSON.stringify(b))}</li>)}</ul>
                  </InCallout>
                </>
              )}
            </>
          )}
        </InCard>
      </div>
    </>
  );
}

// ── CBOM Component drawer ─────────────────────────────────────────────

function CbomComponentDetail({ id, pack }) {
  const [tab, setTab] = inS_("overview");
  const c = InS.cbomComponents(pack).find(x => x.name === id);
  const trace = InP.ASSETS.find(a => a.cbom === id || a.id === id);
  if (!c) return <div className="dim">No matching CBOM component.</div>;
  return (
    <>
      <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 10, flexWrap: "wrap" }}>
        <InTag tone={c.productionAllowed ? "ok" : "warn"}>{c.productionAllowed ? "production-allowed" : "test-only"}</InTag>
        {c.lifecycleStatus && <InTag tone={c.lifecycleStatus === "default" ? "ok" : c.lifecycleStatus === "test_only" ? "warn" : "info"}>{c.lifecycleStatus}</InTag>}
        {c.primitive && <InTag>{c.primitive}</InTag>}
        {c.standard && <InTag tone="info">{c.standard}</InTag>}
      </div>

      <InDT value={tab} onChange={setTab} tabs={[
        { id: "overview",  label: "Overview" },
        { id: "claims",    label: "Claims" },
        { id: "profiles",  label: "Profiles" },
        { id: "raw",       label: "Raw entry" },
      ]} />

      {tab === "overview" && (
        <>
          <InDetail k="bom-ref" v={c.bomRef ? <span className="mono">{c.bomRef}</span> : null} />
          <InDetail k="trace asset" v={c.traceAssetId ? <span className="mono">{c.traceAssetId}</span> : null} />
          <InDetail k="parameter set" v={c.parameterSet ? <span className="mono">{c.parameterSet}</span> : null} />
          <InDetail k="usage" v={c.usage} />
          <InDetail k="version" v={c.version ? <span className="mono">{c.version}</span> : null} />
          <InDetail k="license" v={c.licenses.length ? <span className="mono">{c.licenses.join(", ")}</span> : null} />
          <InHr />
          <div className="kv__k" style={{ marginBottom: 6 }}>Validation scope</div>
          <div className="kchips">{c.validationScope.length === 0 ? <span className="dim mono">n/a</span> : c.validationScope.map(v => <span key={v} className="kchip">{v}</span>)}</div>
        </>
      )}

      {tab === "claims" && (
        <>
          {c.claimIds.length === 0 ? (
            <InEmpty icon="○" title="No claim ids referenced by this component" />
          ) : (
            <table className="tbl">
              <thead><tr><th>Claim id</th><th>Status</th></tr></thead>
              <tbody>
                {c.claimIds.map(cid => {
                  const st = c.claimStatuses[cid];
                  const tone = st === "pass" ? "ok" : st === "fail" ? "err" : st === "not_applicable" ? "na" : "warn";
                  return (
                    <tr key={cid}>
                      <td className="mono">{cid}</td>
                      <td><InTag tone={tone}>{st || "n/a"}</InTag></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </>
      )}

      {tab === "profiles" && (
        <>
          <div className="kv__k" style={{ marginBottom: 6 }}>Profile support (pqcp:profile_support)</div>
          <div className="proflist">{c.profileSupport.length === 0 ? <span className="dim mono">n/a</span> : c.profileSupport.map(p => <span key={p} className="prof">{p}</span>)}</div>

          {trace && (
            <>
              <InHr />
              <div className="kv__k" style={{ marginBottom: 6 }}>Linked asset trace map</div>
              <InDetail k="asset id" v={<span className="mono">{trace.id}</span>} />
              <InDetail k="kconfig" v={<div className="kchips">{trace.kconfig.map(k => <span key={k} className="kchip">CONFIG_{k}</span>)}</div>} />
              <InDetail k="sources" v={<ul className="filelist">{trace.sources.slice(0, 6).map(s => <li key={s} className="filelist__f">{s}</li>)}</ul>} />
              <InDetail k="ztests" v={<ul className="filelist">{trace.ztests.map(z => <li key={z} className="filelist__f">{z}</li>)}</ul>} />
            </>
          )}
        </>
      )}

      {tab === "raw" && (
        <pre className="code__pre" style={{ fontSize: 11, padding: 12, background: "var(--code-bg)", borderRadius: 4, maxHeight: 520, overflow: "auto" }}>
{JSON.stringify(c.raw || c, null, 2)}
        </pre>
      )}
    </>
  );
}

window.VIEW_INVENTORY = { InventoryView, CbomComponentDetail };
