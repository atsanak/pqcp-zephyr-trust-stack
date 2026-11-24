// views-ingest.jsx, ArtifactLoader UI. Two ingest modes (seed-pack or
// release directory), live parsing state, completeness check, parse warnings.

const { Card: IgCard, KV: IgKV, Tag: IgTag, Hr: IgHr, Sev: IgSev,
        Kpi: IgKpi, Callout: IgCallout, EvBind: IgEv,
        Code: IgCode, EmptyState: IgEmpty, Badge: IgBadge } = window.UI;
const { DropZone: IgDrop, PackStateChip: IgState,
        HashChip: IgHash, OriginChip: IgOrigin,
        DetailRow: IgDetail, StatGrid: IgSGrid, Stat: IgStat,
        EvBind2: IgEvBind2 } = window.UIX;
const IgP = window.PQCP;
const IgS = window.STORE;
const IgPK = window.PACK;
const { useState: igS, useMemo: igM } = React;

// All artifacts the dashboard knows how to consume; used for the completeness
// view and the directory-mode picker.
const KNOWN_ARTIFACTS = [
  "assurance_ledger.json",
  "pqc_cbom.cdx.json",
  "pqc_policy_result.json",
  "pqc_environment_result.json",
  "pqc_reference_values.json",
  "pqc_migration_readiness.json",
  "pqc_evidence_graph.json",
  "pqc_assurance_profile_result.json",
  "pqc_evidence_quality_result.json",
  "pqc_appraisal_result.json",
  "pqc_claim_closure_result.json",
  "benchmark_campaign_result.json",
  "benchmark_provenance.json",
  "cost_of_assurance_evidence.json",
  "ct_sample_analysis_result.json",
  "backend_currency_result.json",
  "device_evidence_token_result.json",
  "firmware_assurance_status_result.json",
  "transcripts/evidence_transcript_manifest.json",
  "release_check_results.xml",
];

function IngestView({ session, setSession, pack, onLoadPack, onClearPack }) {
  const [busy, setBusy] = igS(false);
  const [lastErr, setLastErr] = igS(null);

  async function handleFile(file) {
    setBusy(true); setLastErr(null);
    try {
      const p = await IgPK.loadFromFile(file);
      if (!p.loaded) setLastErr(p.errors[0] || "Unknown parse failure");
      onLoadPack(p);
      setSession(s => ({ ...s, ingested: !!p.loaded, path: p.loaded ? (file.name) : "" }));
    } catch (e) {
      setLastErr(e.message || String(e));
    } finally { setBusy(false); }
  }

  async function handleDirectory() {
    if (!window.showDirectoryPicker) {
      setLastErr("Directory picker (showDirectoryPicker) is not available in this browser.");
      return;
    }
    try {
      setBusy(true); setLastErr(null);
      const dir = await window.showDirectoryPicker();
      const p = await IgPK.loadFromDirectory(dir, KNOWN_ARTIFACTS);
      onLoadPack(p);
      setSession(s => ({ ...s, ingested: true, path: dir.name }));
    } catch (e) {
      if (e?.name !== "AbortError") setLastErr(e.message || String(e));
    } finally { setBusy(false); }
  }


  const presence = igM(() => {
    if (!pack || !pack.loaded) return null;
    const known = new Set(KNOWN_ARTIFACTS);
    const present = Object.keys(pack.artifacts).filter(k => known.has(k));
    const missing = KNOWN_ARTIFACTS.filter(k => !pack.artifacts[k]);
    const extra   = Object.keys(pack.artifacts).filter(k => !known.has(k));
    return { present, missing, extra };
  }, [pack]);

  return (
    <div className="grid grid-12">
      {/* Step 1: load */}
      <IgCard span={7} kicker="Step 1 · ArtifactLoader" title="Ingest a release evidence pack"
            subtitle="The console parses release evidence in two ways. Both run entirely in-browser; no upload happens.">
        {busy && <IgCallout tone="info">Parsing…</IgCallout>}
        {lastErr && <IgCallout tone="err" title="Ingest failed">{lastErr}</IgCallout>}

        <IgDrop onFile={handleFile}
                label="Drop a pack JSON here"
                hint="Or pick the output directory of a local release check." />

        <div className="dropzone__or">, or, </div>

        <button className="btn" onClick={handleDirectory}>Pick release output directory…</button>

        <IgHr />
        <div className="kv__k" style={{ marginBottom: 6 }}>Produce a release output directory locally</div>
        <IgCode label="$ release_check">{`python3 scripts/release_check.py \\
  --tag v1.0.0 \\
  --output-root /tmp/pqcp-release-pack`}</IgCode>
        <IgCode label="$ replay-verify">{`python3 scripts/verify_release_evidence_pack.py \\
  /tmp/pqcp-release-pack \\
  --tag v1.0.0`}</IgCode>
      </IgCard>

      {/* Step 2: pack inspection */}
      <IgCard span={5} kicker="Step 2 · Detection" title="Current pack state"
            actions={<IgState pack={pack} />}>
        {!pack || !pack.loaded ? (
          <IgEmpty icon="○" title="No pack loaded"
            hint="Drop a seed-pack JSON on the left, or pick a release directory, to populate the dashboard." />
        ) : (
          <>
            <IgDetail k="State" v={packStateLabel(pack)} />
            <IgDetail k="Source" v={pack.source ? <span className="mono">{pack.source.mode} · {pack.source.name}</span> : null} />
            <IgDetail k="Kind" v={pack.kind ? <span className="mono">{pack.kind}</span> : null} />
            <IgDetail k="Schema version" v={pack.schema_version ? <span className="mono">v{pack.schema_version}</span> : null} />
            <IgDetail k="Generated from" v={pack.generated_from ? <span className="mono">{typeof pack.generated_from === "string" ? pack.generated_from : JSON.stringify(pack.generated_from)}</span> : null} />
            <IgDetail k="Artifacts in pack" v={<span className="mono">{Object.keys(pack.artifacts).length}</span>} />
            <IgDetail k="Recognized" v={presence ? <span className="mono">{presence.present.length}/{KNOWN_ARTIFACTS.length}</span> : null} />

            {pack.warnings.length > 0 && (
              <>
                <IgHr />
                <div className="kv__k" style={{ marginBottom: 6 }}>Parse warnings</div>
                <ul className="filelist">
                  {pack.warnings.map((w, i) => <li key={i} className="filelist__f filelist__f--wrap" style={{ color: "var(--warn)" }}>{w}</li>)}
                </ul>
              </>
            )}
            <IgHr />
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn" onClick={onClearPack}>Clear pack</button>
              {pack.summary?.source_root && <span className="dim mono" style={{ fontSize: 10.5, alignSelf: "center" }}>{pack.summary.source_root}</span>}
            </div>
          </>
        )}
      </IgCard>

      {/* Step 3: completeness */}
      {pack && pack.loaded && presence && (
        <IgCard span={12} kicker="Step 3 · Completeness" title="Recognized artifacts"
              subtitle={`${presence.present.length} present · ${presence.missing.length} awaiting · ${presence.extra.length} extra (parsed but not used)`}
              padded={false}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 0 }}>
            <div style={{ borderRight: "1px solid var(--line)", padding: 12 }}>
              <div className="kv__k" style={{ marginBottom: 8 }}>Present</div>
              <div className="artlist">
                {presence.present.map(f => {
                  const a = pack.artifacts[f];
                  return (
                    <div key={f} className="artlist__row" style={{ borderLeft: "2px solid var(--ok)" }}>
                      <span className="artlist__icn" style={{ color: "var(--ok)" }}>●</span>
                      <div style={{ minWidth: 0 }}>
                        <div className="artlist__f">{f}</div>
                        <div className="artlist__v">
                          {a.sha256 ? <IgHash sha={a.sha256} /> : null}
                          {a.size != null && <span style={{ marginLeft: 8 }}>{IgPK.humanSize(a.size)}</span>}
                          {IgS.envFor(f) && <span style={{ marginLeft: 8 }}><IgOrigin env={IgS.envFor(f)} /></span>}
                        </div>
                      </div>
                      <IgTag tone="ok">parsed</IgTag>
                    </div>
                  );
                })}
              </div>
            </div>
            <div style={{ padding: 12 }}>
              <div className="kv__k" style={{ marginBottom: 8 }}>Awaiting</div>
              <div className="artlist">
                {presence.missing.length === 0 && <IgEmpty icon="✓" title="No awaiting artifacts" hint="Every artifact the dashboard knows how to parse is present in this pack." />}
                {presence.missing.map(f => (
                  <div key={f} className="artlist__row">
                    <span className="artlist__icn">○</span>
                    <div style={{ minWidth: 0 }}>
                      <div className="artlist__f">{f}</div>
                      <div className="artlist__v">{IgS.validatorFor(f) || ""}</div>
                    </div>
                    <IgTag tone="warn">awaiting</IgTag>
                  </div>
                ))}
              </div>

              {presence.extra.length > 0 && (
                <>
                  <IgHr />
                  <div className="kv__k" style={{ marginBottom: 8 }}>Extra (parsed, not consumed by current views)</div>
                  <div className="artlist">
                    {presence.extra.map(f => (
                      <div key={f} className="artlist__row">
                        <span className="artlist__icn">·</span>
                        <div style={{ minWidth: 0 }}>
                          <div className="artlist__f">{f}</div>
                        </div>
                        <IgTag tone="neutral">extra</IgTag>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>
        </IgCard>
      )}

      {/* Non-claims */}
      <IgCard span={12} kicker="Non-claims" title="What this console explicitly does NOT assert"
            subtitle="Verbatim from docs/pqc-assurance-passport.md. Read before sharing exported reports with partners.">
        <ul className="noclaims">
          {IgP.NON_CLAIMS.map((c, i) => <li key={i}><span className="noclaims__x">✕</span>{c}</li>)}
        </ul>
      </IgCard>

      {/* Service-ready architecture */}
      <IgCard span={12} kicker="Architecture" title="React/TypeScript module layout (for the v1 service)"
            subtitle="The browser console is the v0. The same module boundaries promote cleanly to a local read-only Node/FastAPI service. No backend is required for v1.">
        <div className="archlist">
          <ArchRow k="ArtifactLoader" v="Drag-drop + directory-picker + URL fetch. Normalizes seed-packs and raw release directories into a uniform pack shape." />
          <ArchRow k="EvidenceStore"  v="Typed selectors over a loaded pack: ledger, release, policy, cbom, benchmark, ct, firmware, …" />
          <ArchRow k="SchemaValidator" v="Reads schema_version on each artifact, gates the UI on minimum schema, surfaces parse warnings." />
          <ArchRow k="DashboardShell" v="Topbar + sidebar + drawer host. Drives view routing via hash + global filter strip." />
          <ArchRow k="EvidenceDrawer" v="Renders Claim/Asset/Artifact/Finding details, including raw evidence_artifacts[] from the ledger." />
          <ArchRow k="CommandPreview" v="Lifts slider/configurator state into copyable CLI invocations. Never executes." />
          <ArchRow k="ConfigGenerator" v="Composes Kconfig overlays from per-asset Kconfig metadata in the trace map." />
          <ArchRow k="ReportExport" v="Renders the same evidence as the console into a partner-ready static HTML or PDF (planned)." />
        </div>
      </IgCard>
    </div>
  );
}

function ArchRow({ k, v }) {
  return (
    <div className="archlist__row">
      <span className="archlist__k">{k}</span>
      <span className="archlist__v">{v}</span>
    </div>
  );
}

function packStateLabel(pack) {
  const s = pack.state;
  if (s === "loaded") return <IgTag tone="ok">replay-ready</IgTag>;
  if (s === "loaded_warnings") return <IgTag tone="warn">parsed with warnings</IgTag>;
  if (s === "failed") return <IgTag tone="err">failed</IgTag>;
  if (s === "parsing") return <IgTag tone="info">parsing</IgTag>;
  return <IgTag tone="neutral">empty</IgTag>;
}

window.VIEW_INGEST = { IngestView };
