// views-a.jsx — Overview, Findings, Ledger, Policy, Inventory, Ingest + drawer detail components.

const { Card, KV, Pill, Tag, Badge, Hr, Sev, EvBind, Await, EmptyState, Kpi, ThresholdBar, Bar, SparkPlaceholder, Code, Tabs, Segmented, Switch, Toggle, FilterChip, FilterBar, Callout, Pagination, usePaged } = window.UI;
const P = window.PQCP;
const PKA = window.PACK;
const { useState: aS, useMemo: aM, useEffect: aE } = React;

function art(file) { return P.ARTIFACTS.find(a => a.file === file) || { file, validator: "?" }; }
function tone(c) {
  const m = { release:"info", kat:"ok", benchmark:"info", acvp:"warn", security:"warn", supply_chain:"info", crypto_agility:"info", firmware:"info", cost_of_assurance:"info", boot:"warn", kem:"ok", signature:"info", validation:"warn", rng:"info" };
  return m[c] || "neutral";
}

// Tiny helper to access the drawer from anywhere
function useDrawerSafe() { return (window.useDrawer && window.useDrawer()) || { openDrawer: () => {} }; }
function useFiltersSafe() { return (window.useFilters && window.useFilters()) || {}; }

// ═══════════════════════════════════════════════════════════════════════════
// OVERVIEW — KPIs + status panel + real pack values when available
// ═══════════════════════════════════════════════════════════════════════════

function OverviewView({ session, pack }) {
  const ingested = !!(pack && pack.loaded);
  const mode = P.MODES.modes.find(m => m.id === session.mode) || P.MODES.modes[2];
  const requiredArtifacts = P.MODE_REQUIRED_ARTIFACTS[session.mode] || [];

  const rel = PKA.ledgerRelease(pack);
  const policy = PKA.policyResult(pack);
  const packLedgerClaims = PKA.pick(pack, "assurance_ledger.json", "claims");
  const claimsObserved = Array.isArray(packLedgerClaims) ? packLedgerClaims.length : null;
  const passing = Array.isArray(packLedgerClaims) ? packLedgerClaims.filter(c => (c?.status === "pass" || c?.status === "ok" || c?.status === "passed")).length : null;
  const failing = Array.isArray(packLedgerClaims) ? packLedgerClaims.filter(c => (c?.status === "fail" || c?.status === "failed")).length : null;
  const na      = Array.isArray(packLedgerClaims) ? packLedgerClaims.filter(c => (c?.status === "not_applicable" || c?.status === "na" || c?.status === "not-applicable")).length : null;
  const claimCoverage = (claimsObserved && claimsObserved > 0 && passing != null) ? passing / Math.max(1, P.CLAIMS.length) : null;

  const policyStatus = policy?.status || policy?.result || null; // tolerant
  const policyTone = policyStatus === "pass" || policyStatus === "passed" || policyStatus === "ok" ? "ok"
                    : policyStatus === "fail" || policyStatus === "failed" || policyStatus === "error" ? "err"
                    : ingested ? "warn" : "neutral";

  const v7Count = P.CLAIMS.filter(c => c.schema_version_added === 7).length;

  return (
    <>
      {/* KPI row */}
      <div className="grid-kpi" style={{ marginBottom: 12 }}>
        <Kpi
          label="Release tag"
          status={rel?.tag ? "info" : ingested ? "warn" : "neutral"}
          value={rel?.tag || "awaiting"}
          sub={rel?.commit ? <span className="mono">{String(rel.commit).slice(0, 10)}{rel.dirty ? " · dirty" : ""}</span> : (ingested ? "awaiting assurance_ledger.json" : "no pack loaded")}
          evbind={<EvBind file="assurance_ledger.json" path="release.tag" status={PKA.statusFor(pack, "assurance_ledger.json")} compact />}
        />
        <Kpi
          label="Policy result"
          status={policyTone}
          value={policyStatus || "awaiting"}
          sub={policy?.failures ? `${policy.failures.length || 0} failure(s)` : (policy ? "replay output present" : "awaiting pqc_policy_result.json")}
          evbind={<EvBind file="pqc_policy_result.json" path="status" validator="scripts/verify_assurance_policy.py" status={PKA.statusFor(pack, "pqc_policy_result.json")} compact />}
        />
        <Kpi
          label="Claims in ledger"
          status={claimsObserved != null ? "info" : ingested ? "warn" : "neutral"}
          value={claimsObserved != null ? claimsObserved : "awaiting"}
          unit={claimsObserved != null ? "of " + P.CLAIMS.length : null}
          sub={passing != null ? <><span style={{color:"var(--ok)"}}>{passing} pass</span>{failing > 0 && <> · <span style={{color:"var(--err)"}}>{failing} fail</span></>}{na > 0 && <> · <span className="dim">{na} n/a</span></>}</> : "awaiting assurance_ledger.json"}
          evbind={<EvBind file="assurance_ledger.json" path="claims[]" status={PKA.statusFor(pack, "assurance_ledger.json")} compact />}
        />
        <Kpi
          label="CBOM components"
          status={PKA.cbomComponents(pack).length ? "info" : ingested ? "warn" : "neutral"}
          value={PKA.cbomComponents(pack).length || "awaiting"}
          sub={`floor: ${P.POLICY.required_cbom_components.length} required`}
          evbind={<EvBind file="pqc_cbom.cdx.json" path="components[]" validator="scripts/export_pqc_cbom.py" status={PKA.statusFor(pack, "pqc_cbom.cdx.json")} compact />}
        />
        <Kpi
          label="Mode"
          status={mode.strict ? "warn" : "info"}
          value={mode.id}
          sub={mode.strict ? "strict appraisal" : "non-strict"}
          evbind={<EvBind file="scripts/pqc_appraisal_policy.json" path={`modes.${mode.id}`} status="present" compact />}
        />
      </div>

      <div className="grid grid-12">
        {/* Pack health */}
        <Card span={5} kicker="Pack health" title="Artifact completeness"
              subtitle={`${requiredArtifacts.length || 0} mode-required + base ledger artifacts`}
              actions={<EvBind file="scripts/pqc_appraisal_policy.json" path={`modes.${mode.id}.required_artifacts`} status="present" />}>
          <ThresholdBar
            label="Required claim coverage"
            value={claimCoverage}
            bands={[{ to: 0.7, tone: "err" }, { to: 0.9, tone: "warn" }, { to: 1, tone: "ok" }]}
            sub={claimCoverage != null ? `${passing} / ${P.CLAIMS.length} claims passing` : "awaiting assurance_ledger.json"}
          />
          <div style={{ height: 10 }} />
          <ThresholdBar
            label="Attestation subject coverage"
            value={null}
            bands={[{ to: 0.7, tone: "err" }, { to: 0.95, tone: "warn" }, { to: 1, tone: "ok" }]}
            sub={PKA.present(pack, "pqc_attestation.intoto.json") ? "pqc_attestation.intoto.json present" : "awaiting pqc_attestation.intoto.json"}
          />
          <div style={{ height: 10 }} />
          <ThresholdBar
            label="CBOM component floor"
            value={(() => { const n = PKA.cbomComponents(pack).length; if (!n) return null; const req = P.POLICY.required_cbom_components; const found = req.filter(c => PKA.cbomComponents(pack).some(x => x.name === c)).length; return found / req.length; })()}
            bands={[{ to: 0.5, tone: "err" }, { to: 1, tone: "ok" }]}
            sub={PKA.cbomComponents(pack).length ? `${PKA.cbomComponents(pack).length} components in CBOM` : "awaiting pqc_cbom.cdx.json"}
          />
          <Hr />
          <div className="kv__k" style={{ marginBottom: 6 }}>Replay tooling</div>
          <Code label="$ replay">{`python3 scripts/verify_release_evidence_pack.py \\
  ${ingested ? (session.path || "<release-pack>") : "<release-pack>"} --tag <version>`}</Code>
        </Card>

        {/* Release status — real values from ledger when present */}
        <Card span={4} kicker="Release status" title={rel?.tag ? rel.tag : ingested ? "Awaiting parse" : "No pack loaded"}
              subtitle="Values from assurance_ledger.json release metadata">
          <div className="statpanel">
            <StatLine t="Release tag" s="release.tag" value={rel?.tag} />
            <StatLine t="Head SHA" s="release.commit" value={rel?.commit && <span className="mono">{String(rel.commit).slice(0, 12)}…</span>} />
            <StatLine t="Dirty tree" s="release.dirty" value={rel ? (rel.dirty ? <Tag tone="warn">dirty</Tag> : <Tag tone="ok">clean</Tag>) : null} />
            <StatLine t="Schema version" s="schema_version" value={rel?.schema_version && <span className="mono">v{rel.schema_version}</span>} />
            <StatLine t="Generated" s="release.generated_at" value={rel?.generated_at && <span className="mono">{rel.generated_at}</span>} />
            <StatLine t="Policy status" s="pqc_policy_result.json" value={policyStatus && <Tag tone={policyTone}>{policyStatus}</Tag>} />
          </div>
          <Hr />
          <Callout tone={ingested ? "ok" : "info"}>
            {ingested
              ? <>Pack loaded. {pack.summary?.note || "Values above are parsed from the pack."}</>
              : <>Use <a className="link" href="#ingest">Ingest</a> to drop a seed-pack JSON.</>}
          </Callout>
        </Card>

        {/* Schema lineage + west pins */}
        <Card span={3} kicker="Source pinning" title="west.yml manifest"
              actions={<EvBind file="west.yml" status="present" compact />}>
          {P.REPO.west_pins.map(p => (
            <div key={p.name} style={{ padding: "5px 0", borderBottom: "1px solid var(--line)" }}>
              <div style={{ fontSize: 12, fontWeight: 500 }} className="mono">{p.name}</div>
              <div style={{ fontSize: 10, color: "var(--fg-2)", fontFamily: "IBM Plex Mono", marginTop: 2 }}>{p.revision.slice(0, 12)}…</div>
              <div style={{ fontSize: 10, color: "var(--fg-3)" }}>{p.remote}</div>
            </div>
          ))}
        </Card>

        {/* Mode-required artifacts */}
        <Card span={7} kicker={`Mode · ${mode.id}`} title="Required artifacts for this mode"
              subtitle={mode.description}
              actions={<Segmented size="sm" value={session.mode} onChange={() => {}} options={P.MODES.modes.map(m => ({ id: m.id, label: m.id.replace("_", " ") }))} />}>
          {requiredArtifacts.length === 0 ? (
            <EmptyState icon="—" title="No mode-required artifacts" hint="ci_fast does not require v7 appraisal evidence." />
          ) : (
            <div className="modereq">
              {requiredArtifacts.map(f => (
                <div key={f} className="modereq__row">
                  <Sev level="warn" />
                  <span className="modereq__f">{f}</span>
                  <span className="modereq__v">{art(f).validator}</span>
                  <Tag tone="warn">awaiting</Tag>
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* Schema lineage */}
        <Card span={5} kicker="Schema lineage" title={`Catalog @ v${Math.max(...P.SCHEMA_LINEAGE.map(s => s.v))}`}
              subtitle="What each schema version contributes to the assurance ledger"
              actions={<EvBind file="scripts/assurance_claims.json" path="schema_version" status="present" compact />}>
          <div className="lineage">
            {P.SCHEMA_LINEAGE.map(s => (
              <div key={s.v} className="lineage__row">
                <span className="lineage__v">v{s.v}</span>
                <span className="lineage__t">{s.summary}</span>
              </div>
            ))}
          </div>
        </Card>

        {/* Required CBOM floor */}
        <Card span={12} kicker="Required CBOM components" title="Production-gated crypto inventory floor"
              subtitle="From scripts/pqc_assurance_policy.json. Policy verifier rejects the pack if any component is missing."
              actions={<EvBind file="scripts/pqc_assurance_policy.json" path="required_cbom_components" status="present" />}>
          <div className="reqcomp">
            {P.POLICY.required_cbom_components.map(c => (
              <div key={c} className="reqcomp__row">
                <span className="mono">{c}</span>
                <Tag tone={ingested ? "warn" : "neutral"}>{ingested ? "awaiting cdx" : "no pack"}</Tag>
              </div>
            ))}
          </div>
          <Hr />
          <div className="dim" style={{ fontSize: 11.5 }}>
            <span className="mono">forbidden_production_rng_components:</span>{" "}
            {P.POLICY.forbidden_production_rng_components.map(c => <Tag key={c} tone="err">{c}</Tag>)}
          </div>
        </Card>

        {/* Recent activity (semantic feed — no invented events) */}
        <Card span={12} kicker="Activity feed" title="Console actions and pack ingestion events"
              subtitle="A real deployment binds this to release_check.py logs and verify_release_evidence_pack.py output."
              padded={false}>
          <div className="activity">
            <ActivityRow time="—" msg={<>Console initialized · pointing at <span className="mono">{ingested ? session.path : "no pack"}</span></>} sev="info" />
            <ActivityRow time="—" msg={<>Active mode: <span className="mono">{mode.id}</span>{mode.strict && <> (strict)</>}</>} sev="info" />
            <ActivityRow time="—" msg={<>Catalog loaded: <span className="mono">{P.CLAIMS.length}</span> claim ids, schema <span className="mono">v7</span></>} sev="ok" />
            <ActivityRow time="—" msg={<>{P.POLICY.required_cbom_components.length} CBOM components required for production gating</>} sev="info" />
          </div>
        </Card>
      </div>
    </>
  );
}

function StatLine({ t, s, value }) {
  return (
    <div className="statline">
      <div className="statline__l">
        <div className="statline__t">{t}</div>
        <div className="statline__s mono">{s}</div>
      </div>
      {value != null && value !== false ? <span className="mono" style={{ color: "var(--fg-0)" }}>{value}</span> : <Tag tone="warn">awaiting</Tag>}
    </div>
  );
}

function ActivityRow({ time, msg, sev = "info" }) {
  return (
    <div className="activity__row">
      <Sev level={sev} />
      <span className="activity__time">{time}</span>
      <span className="activity__msg">{msg}</span>
      <Tag tone="neutral">console</Tag>
    </div>
  );
}

function truncate(s, n) { return s.length <= n ? s : "…" + s.slice(-(n - 1)); }

// ═══════════════════════════════════════════════════════════════════════════
// FINDINGS — security backlog derived from current console state
// ═══════════════════════════════════════════════════════════════════════════

function FindingsView({ session }) {
  const f = useFiltersSafe();
  const drawer = useDrawerSafe();
  const mode = P.MODES.modes.find(m => m.id === session.mode) || P.MODES.modes[2];

  // Findings: actual, derivable from console state — NOT invented.
  const findings = aM(() => {
    const list = [];
    if (!session.ingested) {
      list.push({
        id: "F-001", severity: "high", category: "release", env: "host_python",
        title: "No release pack ingested",
        sub: "Every claim status, every CBOM property, every hash is awaiting parse.",
        artifact: "assurance_ledger.json", validator: "scripts/release_check.py",
      });
    }
    // For each required artifact of the active mode → one finding
    (P.MODE_REQUIRED_ARTIFACTS[session.mode] || []).forEach((file, i) => {
      const a = art(file);
      list.push({
        id: `F-mode-${i}`, severity: "warn", category: "release", env: "host_python",
        title: `Mode-required artifact awaiting: ${file}`,
        sub: `Required by appraisal mode ${session.mode}. Validator: ${a.validator}.`,
        artifact: file, validator: a.validator,
      });
    });
    // Base ledger pack
    [
      "assurance_ledger.json","pqc_cbom.cdx.json","pqc_policy_result.json","pqc_attestation.intoto.json",
      "pqc_assurance_digest.json","pqc_evidence_graph.json","pqc_asset_trace_result.json",
      "pqc_assurance_profile_result.json","pqc_evidence_quality_result.json","pqc_migration_readiness.json",
      "ct_instruction_policy_result.json","pqc_reference_values.json",
      "benchmark_results.csv","benchmark_provenance.json","cost_of_assurance_evidence.json",
      "transcripts/evidence_transcript_manifest.json",
    ].forEach((file, i) => {
      const a = art(file);
      const cat = file.startsWith("benchmark") ? "benchmark" :
                  file.startsWith("ct_") || file.includes("ct_") ? "security" :
                  file.startsWith("acvp") ? "acvp" :
                  file.startsWith("pqc_cbom") || file.startsWith("pqc_assurance_profile") || file.startsWith("pqc_evidence_") || file.startsWith("pqc_asset") ? "supply_chain" :
                  file.startsWith("pqc_assurance_digest") || file.startsWith("firmware") ? "firmware" :
                  "release";
      list.push({
        id: `F-base-${i}`, severity: "warn", category: cat, env: "host_python",
        title: `Awaiting ${file}`,
        sub: `Generated by ${a.validator}. Supports ${(a.supportsClaims || []).slice(0, 3).join(", ") || "—"}.`,
        artifact: file, validator: a.validator,
      });
    });
    // Production RNG policy informational finding
    list.push({
      id: "F-rng",
      severity: "info",
      category: "security",
      env: "host_python",
      title: "Deterministic test RNG is forbidden in production profiles",
      sub: "Profiles qemu_release / mcu_minimal / gateway reject CONFIG_PQCP_RNG_DETERMINISTIC_TEST=y. Enforced by scripts/verify_pqc_assurance_profile.py.",
      artifact: "scripts/pqc_assurance_profile.json", validator: "scripts/verify_pqc_assurance_profile.py",
    });
    return list;
  }, [session.ingested, session.mode, session.path]);

  // Apply global filters
  const filtered = findings.filter(x =>
    (f.q == null || f.q === "" || (x.title + x.sub + x.artifact).toLowerCase().includes(f.q.toLowerCase())) &&
    (f.category === "any" || x.category === f.category) &&
    (f.severity === "any" || x.severity === f.severity) &&
    (f.env === "any" || x.env === f.env)
  );

  const sevCounts = aM(() => {
    const c = { critical: 0, high: 0, warn: 0, info: 0 };
    findings.forEach(x => { c[x.severity] = (c[x.severity] || 0) + 1; });
    return c;
  }, [findings]);

  const paged = usePaged(filtered, 14);

  return (
    <>
      <div className="grid-kpi" style={{ marginBottom: 12 }}>
        <Kpi label="Open findings" status="warn" value={findings.length} sub="derived from console state" />
        <Kpi label="Critical" status="crit"   value={sevCounts.critical || 0} sub="blocking partner sign-off" />
        <Kpi label="High"     status="err"    value={sevCounts.high     || 0} sub="must resolve to promote" />
        <Kpi label="Warn"     status="warn"   value={sevCounts.warn     || 0} sub="advisory, mode-dependent" />
        <Kpi label="Info"     status="info"   value={sevCounts.info     || 0} sub="documentation / policy notes" />
      </div>

      <div className="grid grid-12">
        <Card span={12} kicker="Findings" title="Backlog (derived, not invented)"
              subtitle="Each finding ties a missing or advisory state to the artifact + validator that would close it."
              padded={false}
              actions={
                <Segmented size="sm" value={f.severity} onChange={f.setSeverity}
                  options={[{ id: "any", label: "all" }, { id: "critical", label: "crit" }, { id: "high", label: "high" }, { id: "warn", label: "warn" }, { id: "info", label: "info" }]} />
              }>
          <FindingsToolbar />
          {paged.rows.length === 0
            ? <EmptyState icon="✓" title="No findings match these filters" hint="Try clearing the global filter chips." />
            : paged.rows.map(x => (
                <div key={x.id} className="finding" onClick={() => drawer.openDrawer("finding", { title: x.title, subtitle: x.id, ...x })}>
                  <Sev level={x.severity} />
                  <div>
                    <div className="finding__t">{x.title}</div>
                    <div className="finding__s">{x.sub}</div>
                  </div>
                  <div className="kchips">
                    <span className="kchip">{x.category}</span>
                    <span className="kchip">{x.env}</span>
                  </div>
                  <Tag tone={x.severity === "critical" ? "crit" : x.severity === "high" ? "err" : x.severity === "warn" ? "warn" : "info"}>{x.severity}</Tag>
                </div>
              ))}
          <Pagination {...paged} onChange={paged.setPage} />
        </Card>
      </div>
    </>
  );
}

function FindingsToolbar() {
  const f = useFiltersSafe();
  return (
    <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--line)", display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
      <span className="kv__k" style={{ marginRight: 6 }}>category</span>
      <Segmented size="sm" value={f.category} onChange={f.setCategory}
        options={[
          { id: "any", label: "all" },
          { id: "release", label: "release" },
          { id: "benchmark", label: "bench" },
          { id: "acvp", label: "acvp" },
          { id: "security", label: "security" },
          { id: "supply_chain", label: "supply" },
          { id: "firmware", label: "firmware" },
        ]} />
      <span style={{ flex: 1 }} />
      <span className="kv__k" style={{ marginRight: 6 }}>environment</span>
      <Segmented size="sm" value={f.env} onChange={f.setEnv}
        options={[
          { id: "any", label: "any" },
          { id: "qemu_x86_64", label: "qemu" },
          { id: "native_sim", label: "native_sim" },
          { id: "host_python", label: "host" },
          { id: "build_only", label: "build" },
        ]} />
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// LEDGER — claims table with drawer drill-down
// ═══════════════════════════════════════════════════════════════════════════

function LedgerView({ session }) {
  const f = useFiltersSafe();
  const drawer = useDrawerSafe();
  const filtered = P.CLAIMS.filter(c =>
    (f.q == null || f.q === "" || (c.id + " " + c.claim).toLowerCase().includes(f.q.toLowerCase())) &&
    (f.category === "any" || c.category === f.category)
  );
  const paged = usePaged(filtered, 18);

  const catCounts = aM(() => {
    const c = { all: P.CLAIMS.length };
    P.CLAIMS.forEach(x => { c[x.category] = (c[x.category] || 0) + 1; });
    return c;
  }, []);

  return (
    <>
      <div className="grid-kpi" style={{ marginBottom: 12 }}>
        <Kpi label="Total claims" status="info" value={P.CLAIMS.length} sub="required by schema v7 catalog" />
        <Kpi label="Required" status="ok" value={P.CLAIMS.filter(c => c.required).length} sub="all are required in v7" />
        <Kpi label="v7-additive" status="info" value={P.CLAIMS.filter(c => c.schema_version_added === 7).length} sub="schema_version_added: 7" />
        <Kpi label="With NA-allowed" status="info" value={Object.values(P.QUALITY.byClaim).filter(q => q.allow_na).length} sub="from pqc_evidence_quality.json" />
        <Kpi label="Categories" status="info" value={Object.keys(catCounts).length - 1} sub="release / kat / bench / …" />
      </div>

      <div className="grid grid-12">
        <Card span={12} kicker="Assurance ledger" title="Claim catalog (scripts/assurance_claims.json)"
              subtitle="Status populates from assurance_ledger.json once a pack is ingested. Click a row to inspect."
              padded={false}
              actions={<>
                <Tabs value={f.category === "any" ? "all" : f.category} onChange={v => f.setCategory(v === "all" ? "any" : v)} tabs={[
                  { id: "all", label: "all", count: catCounts.all },
                  { id: "release", label: "release", count: catCounts.release },
                  { id: "kat", label: "kat", count: catCounts.kat },
                  { id: "benchmark", label: "bench", count: catCounts.benchmark },
                  { id: "acvp", label: "acvp", count: catCounts.acvp },
                  { id: "security", label: "security", count: catCounts.security },
                  { id: "supply_chain", label: "supply", count: catCounts.supply_chain },
                  { id: "firmware", label: "firmware", count: catCounts.firmware },
                ]} />
              </>}>
          <table className="tbl">
            <thead><tr>
              <th style={{ width: 24 }}></th>
              <th>Claim id</th>
              <th>Category</th>
              <th>Evidence class</th>
              <th>Environment</th>
              <th>v7</th>
              <th>NA?</th>
              <th>Status</th>
              <th className="act"></th>
            </tr></thead>
            <tbody>
              {paged.rows.map(c => {
                const q = P.QUALITY.byClaim[c.id] || {};
                return (
                  <tr key={c.id} onClick={() => drawer.openDrawer("claim", { id: c.id, title: c.id, subtitle: c.category })} style={{ cursor: "pointer" }}>
                    <td><Sev level="warn" /></td>
                    <td className="mono"><strong style={{ color: "var(--fg-0)" }}>{c.id}</strong></td>
                    <td><Tag tone={tone(c.category)}>{c.category}</Tag></td>
                    <td><Badge tone="info">{q.class || "—"}</Badge></td>
                    <td className="mono dim">{q.env || "—"}</td>
                    <td>{c.schema_version_added === 7 ? <Tag tone="accent">v7</Tag> : <span className="dim mono">≤v6</span>}</td>
                    <td>{q.allow_na ? <Tag tone="info">yes</Tag> : <span className="dim">no</span>}</td>
                    <td><Tag tone="warn">awaiting</Tag></td>
                    <td className="act"><button className="actbtn">Inspect →</button></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <Pagination {...paged} onChange={paged.setPage} />
        </Card>
      </div>
    </>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// CLAIM DETAIL (drawer body)
// ═══════════════════════════════════════════════════════════════════════════

function ClaimDetail({ id }) {
  const c = P.CLAIMS.find(x => x.id === id);
  if (!c) return <div className="dim">Unknown claim</div>;
  const q = P.QUALITY.byClaim[c.id] || {};
  const linkedAssets = P.ASSETS.filter(a => a.claims.includes(c.id));
  const linkedProfiles = P.PROFILES.filter(p => p.required_claim_ids.includes(c.id));
  return (
    <>
      <Callout tone="info" title={c.id}>{c.claim}</Callout>
      <div className="kvgrid" style={{ marginTop: 14 }}>
        <KV k="Category" v={<Tag tone={tone(c.category)}>{c.category}</Tag>} />
        <KV k="Required" v={c.required ? <Tag tone="ok">true</Tag> : <Tag>false</Tag>} />
        <KV k="Schema added" v={<span className="mono">v{c.schema_version_added || "≤6"}</span>} />
        <KV k="Evidence class" v={<Badge tone="info">{q.class || "?"}</Badge>} />
        <KV k="Environment" v={<span className="mono">{q.env || "—"}</span>} />
        <KV k="Allow NA" v={q.allow_na ? <Tag tone="info">yes</Tag> : <Tag>no</Tag>} />
        <KV k="Smoke-only" v={q.smoke_only ? <Tag tone="warn">yes</Tag> : <Tag>no</Tag>} />
        <KV k="Requires artifact" v={q.artifact ? <Tag tone="ok">yes</Tag> : <Tag>no</Tag>} />
      </div>

      <Hr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Evidence bindings</div>
      <EvBind file="scripts/assurance_claims.json" path={`claims[id="${c.id}"]`} env="repo" status="present" />
      <EvBind file="scripts/pqc_evidence_quality.json" path={`claims[id="${c.id}"]`} env="repo" status="present" />
      <EvBind file="assurance_ledger.json" path={`claims[id="${c.id}"]`} validator="scripts/generate_assurance_ledger.py" env="release_pack" status="missing" />

      <Hr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Linked assets (trace map)</div>
      {linkedAssets.length === 0 ? <div className="dim mono">no assets directly reference this claim</div> : (
        <div className="assetchips">
          {linkedAssets.map(a => (
            <div key={a.id} className="assetchip">
              <span className="assetchip__id">{a.id}</span>
              <span className="mono dim">{a.category}</span>
              <span className="mono dim">cbom: {a.cbom || "—"}</span>
            </div>
          ))}
        </div>
      )}

      <Hr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Profiles requiring this claim</div>
      {linkedProfiles.length === 0 ? <div className="dim mono">none directly required</div> : (
        <div className="ptags">{linkedProfiles.map(p => <span key={p.id} className="ptag ptag--on">{p.id}</span>)}</div>
      )}

      <Hr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Replay command</div>
      <Code label="$ replay">{`python3 scripts/verify_assurance_ledger.py \\
  <pack>/assurance_ledger.json --filter ${c.id}`}</Code>
    </>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// POLICY
// ═══════════════════════════════════════════════════════════════════════════

function PolicyView({ session }) {
  const mode = P.MODES.modes.find(m => m.id === session.mode) || P.MODES.modes[2];
  const reqArt = P.MODE_REQUIRED_ARTIFACTS[session.mode] || [];
  return (
    <div className="grid grid-12">
      <Card span={6} kicker="Policy" title="Partner-review default assurance policy"
            subtitle="scripts/pqc_assurance_policy.json · schema v3"
            actions={<EvBind file="scripts/pqc_assurance_policy.json" status="present" />}>
        <div className="kvgrid">
          <KV k="Required claim ids" v={<span className="mono">{P.CLAIMS.length}</span>} />
          <KV k="Allow not_applicable" v={<span className="mono">{Object.values(P.QUALITY.byClaim).filter(q => q.allow_na).length}</span>} />
          <KV k="Required CBOM components" v={<span className="mono">{P.POLICY.required_cbom_components.length}</span>} />
          <KV k="Required attestation subjects" v={<span className="mono">{P.POLICY.required_attestation_subjects.length}</span>} />
          <KV k="Passport v2 artifacts" v={<span className="mono">{P.POLICY.passport_v2.length}</span>} />
          <KV k="Passport v3 artifacts" v={<span className="mono">{P.POLICY.passport_v3.length}</span>} />
          <KV k="Passport v4 artifacts" v={<span className="mono">{P.POLICY.passport_v4.length}</span>} />
          <KV k="Forbidden production RNG" v={<Tag tone="err">{P.POLICY.forbidden_production_rng_components[0]}</Tag>} />
        </div>
        <Hr />
        <Code label="$ replay policy">{`python3 scripts/verify_assurance_policy.py \\
  --policy scripts/pqc_assurance_policy.json \\
  --ledger ${session.path || "<pack>"}/assurance_ledger.json \\
  --cbom ${session.path || "<pack>"}/pqc_cbom.cdx.json \\
  --attestation ${session.path || "<pack>"}/pqc_attestation.intoto.json \\
  --output ${session.path || "<pack>"}/pqc_policy_result.json`}</Code>
      </Card>

      <Card span={6} kicker="Appraisal mode" title={mode.id}
            subtitle={mode.description}
            actions={mode.strict && <Badge tone="warn">strict</Badge>}>
        <div className="kv__k" style={{ marginBottom: 6 }}>Required claim evidence</div>
        {(mode.id === "partner_review" || mode.id === "hardware_review") ? (
          <ul className="checklist">
            {["release.evidence_appraisal_profile","supply_chain.backend_update_evaluation","benchmark.campaign_reproducibility","benchmark.external_reference_context","security.ct_campaign_analysis","acvp.json_schema_coverage","firmware.device_evidence_token","release.strict_partner_policy"].map(id => (
              <li key={id}><span className="checklist__dot" /><span className="mono">{id}</span></li>
            ))}
          </ul>
        ) : mode.id === "local_release" ? (
          <ul className="checklist">
            {["supply_chain.backend_update_evaluation","benchmark.campaign_reproducibility","benchmark.external_reference_context","security.ct_campaign_analysis","acvp.json_schema_coverage","firmware.device_evidence_token"].map(id => (
              <li key={id}><span className="checklist__dot" /><span className="mono">{id}</span></li>
            ))}
          </ul>
        ) : (
          <div className="dim">CI fast does not require v7 appraisal claim evidence.</div>
        )}
        <Hr />
        <div className="kv__k" style={{ marginBottom: 6 }}>Required artifacts</div>
        {reqArt.length === 0 ? <div className="dim">none beyond the base ledger pack</div> : (
          <div className="modereq">
            {reqArt.map(f => (
              <div key={f} className="modereq__row">
                <Sev level="warn" />
                <span className="modereq__f">{f}</span>
                <Tag tone="warn">awaiting</Tag>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card span={12} kicker="Required attestation subjects" title="Hash-bound by pqc_attestation.intoto.json"
            subtitle="Subjects in the in-toto Statement; verifier rechecks every sha256 against on-disk bytes"
            actions={<EvBind file="pqc_attestation.intoto.json" path="subject[]" validator="scripts/generate_pqc_attestation.py" status="missing" />}>
        <div className="subjgrid">
          {P.POLICY.required_attestation_subjects.map(s => (
            <div key={s} className="subjrow">
              <span className="subjrow__f">{s}</span>
              <span className="subjrow__h">sha256: awaiting</span>
              <Tag tone="warn">awaiting</Tag>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTORY (assets / CBOM)
// ═══════════════════════════════════════════════════════════════════════════

function InventoryView({ session }) {
  const f = useFiltersSafe();
  const drawer = useDrawerSafe();
  const filtered = P.ASSETS.filter(a =>
    (f.q == null || f.q === "" || (a.id + " " + a.name + " " + (a.cbom || "") + " " + a.kconfig.join(" ")).toLowerCase().includes(f.q.toLowerCase()))
  );
  const paged = usePaged(filtered, 14);
  const counts = aM(() => {
    const c = {};
    P.ASSETS.forEach(a => { c[a.category] = (c[a.category] || 0) + 1; });
    return c;
  }, []);

  return (
    <>
      <div className="grid-kpi" style={{ marginBottom: 12 }}>
        <Kpi label="Assets" status="info" value={P.ASSETS.length} sub="scripts/pqc_asset_trace_map.json" />
        <Kpi label="ML-KEM" status="ok" value={counts.kem || 0} sub="parameter sets 512/768/1024" />
        <Kpi label="ML-DSA" status="ok" value={counts.signature || 0} sub="parameter sets 44/65/87" />
        <Kpi label="Test-only" status="warn" value={P.ASSETS.filter(a => a.test_only).length} sub="forbidden in production profiles" />
        <Kpi label="Required CBOM floor" status="info" value={P.POLICY.required_cbom_components.length} sub="production-gated components" />
      </div>

      <div className="grid grid-12">
        <Card span={12} kicker="Crypto inventory" title="Asset trace map (source of truth for the CBOM)"
              subtitle="Each asset binds source files, Kconfig symbols, claim ids, ztests, transcript markers, and a CBOM component name. Click any row for full provenance."
              padded={false}
              actions={<>
                <EvBind file="scripts/pqc_asset_trace_map.json" status="present" />
                <EvBind file="pqc_cbom.cdx.json" validator="scripts/export_pqc_cbom.py" status="missing" />
              </>}>
          <table className="tbl">
            <thead><tr>
              <th>Asset id</th><th>Name</th><th>Category</th><th>CBOM component</th>
              <th>Kconfig</th><th>Claims</th><th>ztests</th><th>Profile use</th><th className="act"></th>
            </tr></thead>
            <tbody>
              {paged.rows.map(a => (
                <tr key={a.id} onClick={() => drawer.openDrawer("asset", { id: a.id, title: a.id, subtitle: a.name })} style={{ cursor: "pointer" }}>
                  <td className="mono"><strong style={{ color: "var(--fg-0)" }}>{a.id}</strong>{a.test_only && <Tag tone="warn">test-only</Tag>}</td>
                  <td>{a.name}</td>
                  <td><Tag tone={tone(a.category)}>{a.category}</Tag></td>
                  <td className="mono">{a.cbom || <span className="dim">—</span>}</td>
                  <td><div className="kchips">{a.kconfig.slice(0,2).map(k => <span key={k} className="kchip mono">{k}</span>)}{a.kconfig.length > 2 && <span className="mono dim">+{a.kconfig.length - 2}</span>}</div></td>
                  <td className="num mono">{a.claims.length}</td>
                  <td className="num mono">{a.ztests.length}</td>
                  <td><ProfileDots asset={a} /></td>
                  <td className="act"><button className="actbtn">Inspect →</button></td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pagination {...paged} onChange={paged.setPage} />
        </Card>

        <Card span={12} kicker="CBOM coverage gates" title="Required production CBOM components"
              subtitle="From scripts/pqc_assurance_policy.json. The policy verifier rejects the pack if any of these are absent from the generated CycloneDX file."
              actions={<EvBind file="scripts/pqc_assurance_policy.json" path="required_cbom_components" status="present" />}>
          <table className="tbl">
            <thead><tr><th>Component</th><th>Asset id</th><th>CBOM presence</th><th>pqcp:production_allowed</th><th>pqcp:lifecycle_status</th><th>pqcp:validation_scope</th></tr></thead>
            <tbody>
              {P.POLICY.required_cbom_components.map(c => {
                const asset = P.ASSETS.find(a => a.cbom === c);
                return (
                  <tr key={c}>
                    <td className="mono">{c}</td>
                    <td className="mono">{asset ? asset.id : <span className="dim">— external</span>}</td>
                    <td><Tag tone="warn">awaiting</Tag></td>
                    <td><Tag tone="warn">awaiting</Tag></td>
                    <td><Tag tone="warn">awaiting</Tag></td>
                    <td><Tag tone="warn">awaiting</Tag></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>
      </div>
    </>
  );
}

function ProfileDots({ asset }) {
  return (
    <div className="ptags">
      {P.PROFILES.map(p => {
        const forbidden = p.forbidden.includes(asset.id);
        const testOnly = (p.test_only || []).includes(asset.id);
        const tone = forbidden ? "err" : testOnly ? "warn" : "ok";
        const status = forbidden ? "forbidden" : testOnly ? "test_only" : "permitted";
        return <span key={p.id} className={`pdot pdot--${tone}`} title={`${p.id}: ${status}`}>{p.id.split("_")[0]}</span>;
      })}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// ASSET DETAIL (drawer body)
// ═══════════════════════════════════════════════════════════════════════════

function AssetDetail({ id }) {
  const a = P.ASSETS.find(x => x.id === id);
  if (!a) return <div className="dim">Unknown asset</div>;
  return (
    <>
      <Callout tone={a.test_only ? "warn" : "info"} title={a.name}>
        category · <span className="mono">{a.category}</span>{a.cbom ? <> · CBOM component: <span className="mono">{a.cbom}</span></> : null}
      </Callout>
      <div className="kvgrid" style={{ marginTop: 14 }}>
        <KV k="Asset id" v={<span className="mono">{a.id}</span>} />
        <KV k="Test-only" v={a.test_only ? <Tag tone="warn">yes</Tag> : <Tag>no</Tag>} />
      </div>

      <Hr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Source files ({a.sources.length})</div>
      <ul className="filelist">{a.sources.map(f => <li key={f} className="filelist__f">{f}</li>)}</ul>

      <Hr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Kconfig symbols</div>
      <div className="kchips">{a.kconfig.map(k => <span key={k} className="kchip mono">CONFIG_{k}</span>)}</div>

      <Hr />
      <div className="kv__k" style={{ marginBottom: 6 }}>ztests ({a.ztests.length})</div>
      <ul className="filelist">{a.ztests.map(z => <li key={z} className="filelist__f">{z}</li>)}</ul>

      <Hr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Claim ids ({a.claims.length})</div>
      {a.claims.length === 0 ? <div className="dim mono">no claims directly attached</div> : (
        <div className="ptags">{a.claims.map(c => <span key={c} className="ptag">{c}</span>)}</div>
      )}

      <Hr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Transcript markers</div>
      <ul className="filelist">{a.markers.map(m => <li key={m} className="filelist__f filelist__f--wrap">{m}</li>)}</ul>

      <Hr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Profile permissions</div>
      <div className="ptags">{P.PROFILES.map(p => {
        const forbidden = p.forbidden.includes(a.id);
        const testOnly = (p.test_only || []).includes(a.id);
        const t = forbidden ? "err" : testOnly ? "warn" : "ok";
        const label = forbidden ? "forbidden" : testOnly ? "test_only" : "permitted";
        return <span key={p.id} className={`pdot pdot--${t}`} title={p.id}>{p.id} · {label}</span>;
      })}</div>
    </>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// ARTIFACT DETAIL (drawer body)
// ═══════════════════════════════════════════════════════════════════════════

function ArtifactDetail({ file }) {
  const a = art(file);
  return (
    <>
      <Callout tone="warn" title={file}>Awaiting on-disk artifact in the loaded release pack.</Callout>
      <div className="kvgrid" style={{ marginTop: 14 }}>
        <KV k="Validator" v={<span className="mono">{a.validator}</span>} />
        <KV k="Status" v={<Tag tone="warn">awaiting</Tag>} />
      </div>
      <Hr />
      <div className="kv__k" style={{ marginBottom: 6 }}>JSON paths consumed</div>
      {a.jsonPaths ? (
        <ul className="filelist">{a.jsonPaths.map(p => <li key={p} className="filelist__f">{p}</li>)}</ul>
      ) : <div className="dim mono">(structure read directly; no canonical path list registered)</div>}

      <Hr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Supports claims</div>
      {a.supportsClaims ? <div className="ptags">{a.supportsClaims.map(c => <span key={c} className="ptag">{c}</span>)}</div> : <div className="dim mono">—</div>}
    </>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDING DETAIL (drawer body)
// ═══════════════════════════════════════════════════════════════════════════

function FindingDetail({ finding }) {
  if (!finding) return null;
  return (
    <>
      <Callout tone={finding.severity === "critical" ? "err" : finding.severity === "high" ? "err" : finding.severity === "warn" ? "warn" : "info"} title={finding.title}>
        {finding.sub}
      </Callout>
      <div className="kvgrid" style={{ marginTop: 14 }}>
        <KV k="Severity" v={<Tag tone={finding.severity === "critical" ? "crit" : finding.severity === "high" ? "err" : finding.severity === "warn" ? "warn" : "info"}>{finding.severity}</Tag>} />
        <KV k="Category" v={<Tag tone={tone(finding.category)}>{finding.category}</Tag>} />
        <KV k="Environment" v={<span className="mono">{finding.env}</span>} />
        <KV k="Finding id" v={<span className="mono">{finding.id}</span>} />
      </div>
      <Hr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Resolution path</div>
      <EvBind file={finding.artifact} validator={finding.validator} status="missing" />
      <Hr />
      <Code label="$ produce">{`python3 ${finding.validator}`}</Code>
    </>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// INGEST
// ═══════════════════════════════════════════════════════════════════════════

function IngestView({ session, setSession }) {
  const [path, setPath] = aS(session.path || "/tmp/pqcp-release-pack");
  const [mode, setMode] = aS(session.mode || P.MODES.default);

  const requiredArtifacts = aM(() => {
    const base = [
      "assurance_ledger.json","assurance_ledger.md","assurance_report.html",
      "pqc_cbom.cdx.json","pqc_policy_result.json","pqc_environment_result.json",
      "pqc_attestation.intoto.json","pqc_assurance_digest.json",
      "pqc_asset_trace_result.json","pqc_evidence_graph.json","pqc_evidence_graph.md",
      "pqc_assurance_profile_result.json","pqc_evidence_quality_result.json",
      "pqc_migration_readiness.json","pqc_migration_readiness.md",
      "ct_instruction_policy_result.json","pqc_claim_closure_result.json",
      "pqc_reference_values.json","pqc_reference_values_result.json",
      "firmware_assurance_status_result.json","acvp_json_interop_result.json",
      "acvp_json_transcript_manifest.json","pqc_build_provenance.slsa.json",
      "pqc_build_provenance_result.json","ct_sample_analysis_result.json",
      "benchmark_results.csv","benchmark_provenance.json","cost_of_assurance_evidence.json",
      "transcripts/evidence_transcript_manifest.json",
      "acvp_negative_scenario_floor_result.json",
      "generated/pqcp_assurance_digest_generated.h",
      "local_release_bundle/release-manifest.json",
    ];
    return [...new Set([...base, ...(P.MODE_REQUIRED_ARTIFACTS[mode] || [])])];
  }, [mode]);

  return (
    <div className="grid grid-12">
      <Card span={8} kicker="Step 1" title="Point the console at a release output directory"
            subtitle="The console is read-only. It inspects artifacts already on disk; it does not run release_check.py for you.">
        <div className="ingest__lbl">Release output root</div>
        <div className="ingest__row">
          <input className="input mono" value={path} onChange={e => setPath(e.target.value)} placeholder="/tmp/pqcp-release-pack" />
          <button className="btn btn--primary" onClick={() => setSession({ ...session, path, mode, ingested: true })}>Load directory</button>
        </div>
        <div className="ingest__hint">
          The browser cannot read filesystem paths directly. In a deployed build, this field opens a folder picker
          (<span className="mono">showDirectoryPicker</span>) or accepts a JSON manifest emitted by
          <span className="mono"> scripts/verify_release_evidence_pack.py</span>.
        </div>

        <Hr />
        <div className="ingest__lbl">Appraisal mode</div>
        <div className="ingest__modes">
          {P.MODES.modes.map(m => (
            <button key={m.id} className={`modecard ${mode === m.id ? "modecard--on" : ""}`} onClick={() => setMode(m.id)}>
              <div className="modecard__h">
                <span className="mono">{m.id}</span>
                {m.strict && <Badge tone="warn">strict</Badge>}
                {m.hardware && <Badge tone="info">hardware</Badge>}
              </div>
              <div className="modecard__d">{m.description}</div>
            </button>
          ))}
        </div>

        <Hr />
        <div className="ingest__lbl">If you do not have a pack yet, produce one locally</div>
        <Code label="$ produce">{`python3 scripts/release_check.py \\
  --tag v1.0.0 \\
  --output-root ${path}`}</Code>
        <div className="ingest__lbl">Then replay-verify it before loading here</div>
        <Code label="$ replay">{`python3 scripts/verify_release_evidence_pack.py ${path} --tag v1.0.0`}</Code>
      </Card>

      <Card span={4} kicker="Step 2" title="Expected artifacts"
            subtitle={`${requiredArtifacts.length} files for mode = ${mode}`}>
        <div className="artlist">
          {requiredArtifacts.map(file => {
            const a = art(file);
            return (
              <div key={file} className="artlist__row">
                <span className="artlist__icn">○</span>
                <div style={{ minWidth: 0 }}>
                  <div className="artlist__f">{file}</div>
                  <div className="artlist__v">{a.validator}</div>
                </div>
                <Tag tone="warn">awaiting</Tag>
              </div>
            );
          })}
        </div>
      </Card>

      <Card span={12} kicker="Non-claims" title="What this console explicitly does NOT assert"
            subtitle="Verbatim from docs/pqc-assurance-passport.md. Surfaced here so partner conversations stay honest.">
        <ul className="noclaims">
          {P.NON_CLAIMS.map((c, i) => <li key={i}><span className="noclaims__x">✕</span>{c}</li>)}
        </ul>
      </Card>
    </div>
  );
}

window.VIEWS_A = { OverviewView, FindingsView, LedgerView, PolicyView, InventoryView, IngestView, ClaimDetail, AssetDetail, ArtifactDetail, FindingDetail };
