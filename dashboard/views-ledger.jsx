// views-ledger.jsx — Assurance Ledger (real claim data + drawer detail).

const { Card: LdCard, KV: LdKV, Tag: LdTag, Badge: LdBadge, Hr: LdHr, Sev: LdSev,
        Kpi: LdKpi, Tabs: LdTabs, Pagination: LdPgn, usePaged: ldUsePaged,
        EvBind: LdEv, Callout: LdCallout, Code: LdCode, EmptyState: LdEmpty } = window.UI;
const { HashChip: LdHash, OriginChip: LdOrigin, EvBind2: LdEvBind2,
        DetailRow: LdDetail, StatGrid: LdSGrid, Stat: LdStat,
        EvidenceList: LdEvList, ChecksList: LdChecks, DTabs: LdDT } = window.UIX;
const LP = window.PQCP;
const LS = window.STORE;
const { useState: lS, useMemo: lM } = React;

function ldFiltersSafe() { return (window.useFilters && window.useFilters()) || {}; }
function ldDrawerSafe()  { return (window.useDrawer  && window.useDrawer())  || { openDrawer: () => {} }; }
function ldTone(c) {
  const m = { release:"info", kat:"ok", benchmark:"info", acvp:"warn", security:"warn",
              supply_chain:"info", crypto_agility:"info", firmware:"info",
              cost_of_assurance:"info", boot:"warn" };
  return m[c] || "neutral";
}
function ldStatusTag(status) {
  if (status === "pass" || status === "passed" || status === "ok") return <LdTag tone="ok">pass</LdTag>;
  if (status === "fail" || status === "failed" || status === "error") return <LdTag tone="err">fail</LdTag>;
  if (status === "not_applicable" || status === "na" || status === "not-applicable") return <LdTag tone="na">n/a</LdTag>;
  return <LdTag tone="warn">awaiting</LdTag>;
}

function LedgerView({ session, pack }) {
  const f = ldFiltersSafe();
  const drawer = ldDrawerSafe();
  const ingested = !!(pack && pack.loaded);
  const lsum = LS.ledgerSummary(pack);
  const claims = LS.ledgerClaims(pack);

  // Build a merged catalog: known claim catalog + actual pack status
  const merged = lM(() => {
    const packById = {};
    claims.forEach(c => { packById[c.id] = c; });
    return LP.CLAIMS.map(c => {
      const pc = packById[c.id];
      const q = LP.QUALITY.byClaim[c.id] || {};
      return {
        id: c.id,
        category: c.category,
        catalog_claim: c.claim,
        required: c.required,
        schema_version_added: c.schema_version_added,
        quality: q,
        // pack-derived:
        status: pc?.status || (ingested ? "missing" : "awaiting"),
        validators: pc?.validators || [],
        commands: pc?.commands || [],
        evidence_artifacts: pc?.evidence_artifacts || [],
        failure_reason: pc?.failure_reason || null,
        details: pc?.details || null,
        pack_present: !!pc,
      };
    });
  }, [claims, ingested]);

  const filtered = merged.filter(c => {
    if (f.q && f.q !== "") {
      const q = f.q.toLowerCase();
      if (!(c.id + " " + c.catalog_claim).toLowerCase().includes(q)) return false;
    }
    if (f.category && f.category !== "any" && c.category !== f.category) return false;
    if (f.status && f.status !== "any" && c.status !== f.status) return false;
    if (f.env && f.env !== "any" && c.quality.env !== f.env) return false;
    return true;
  });
  const paged = ldUsePaged(filtered, 18);

  const catCounts = lM(() => {
    const o = { all: merged.length };
    merged.forEach(c => { o[c.category] = (o[c.category] || 0) + 1; });
    return o;
  }, [merged]);

  return (
    <>
      <div className="grid-kpi" style={{ marginBottom: 12 }}>
        <LdKpi label="Total claims" status="info"
               value={lsum ? lsum.total : LP.CLAIMS.length}
               sub={lsum ? `${lsum.required} required` : `catalog only`}
               evbind={<LdEvBind2 ev={LS.evbind(pack, "assurance_ledger.json", "claims[]")} compact />} />
        <LdKpi label="Passing" status={lsum ? "ok" : "neutral"}
               value={lsum ? lsum.pass : "—"}
               sub={lsum ? `replay verified` : "no pack"} />
        <LdKpi label="Failing" status={lsum && lsum.fail > 0 ? "err" : "ok"}
               value={lsum ? lsum.fail : "—"} sub="block partner sign-off" />
        <LdKpi label="Not applicable" status="na"
               value={lsum ? lsum.not_applicable : "—"}
               sub="environment-skipped, allow_na set" />
        <LdKpi label="v7 additive" status="info"
               value={LP.CLAIMS.filter(c => c.schema_version_added === 7).length}
               sub="schema_version_added=7" />
      </div>

      <div className="grid grid-12">
        <LdCard span={12} kicker="Assurance ledger" title="Claim catalog · pack status"
              subtitle="Each row is a catalog claim from scripts/assurance_claims.json. Pass/fail/na comes from assurance_ledger.json once a pack is loaded."
              padded={false}
              actions={
                <LdTabs value={f.category === "any" ? "all" : f.category} onChange={v => f.setCategory(v === "all" ? "any" : v)} tabs={[
                  { id: "all", label: "all", count: catCounts.all },
                  { id: "release", label: "release", count: catCounts.release },
                  { id: "kat", label: "kat", count: catCounts.kat },
                  { id: "benchmark", label: "bench", count: catCounts.benchmark },
                  { id: "acvp", label: "acvp", count: catCounts.acvp },
                  { id: "security", label: "security", count: catCounts.security },
                  { id: "supply_chain", label: "supply", count: catCounts.supply_chain },
                  { id: "firmware", label: "firmware", count: catCounts.firmware },
                ]} />
              }>
          <table className="tbl">
            <thead><tr>
              <th style={{ width: 22 }}></th>
              <th>Claim id</th>
              <th>Category</th>
              <th>Evidence class</th>
              <th>Env</th>
              <th>v</th>
              <th>Validators</th>
              <th>Evidence</th>
              <th>Status</th>
              <th className="act"></th>
            </tr></thead>
            <tbody>
              {paged.rows.map(c => (
                <tr key={c.id} onClick={() => drawer.openDrawer("claim", { id: c.id, title: c.id, subtitle: c.category })} style={{ cursor: "pointer" }}>
                  <td><span className={`sdot sdot--${c.status === "pass" ? "pass" : c.status === "fail" ? "fail" : c.status === "not_applicable" ? "na" : "neutral"}`} /></td>
                  <td className="mono"><strong style={{ color: "var(--fg-0)" }}>{c.id}</strong></td>
                  <td><LdTag tone={ldTone(c.category)}>{c.category}</LdTag></td>
                  <td><LdBadge tone="info">{c.quality.class || "—"}</LdBadge></td>
                  <td><LdOrigin env={c.quality.env} /></td>
                  <td>{c.schema_version_added === 7 ? <LdTag tone="accent">v7</LdTag> : <span className="dim mono">≤v6</span>}</td>
                  <td className="mono dim" style={{ fontSize: 10.5, maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {c.validators.length > 0 ? c.validators[0] : "—"}
                    {c.validators.length > 1 && <span> +{c.validators.length - 1}</span>}
                  </td>
                  <td className="mono dim" style={{ fontSize: 10.5 }}>{c.evidence_artifacts.length || "—"}</td>
                  <td>{ldStatusTag(c.status)}</td>
                  <td className="act"><button className="actbtn">Inspect →</button></td>
                </tr>
              ))}
            </tbody>
          </table>
          <LdPgn {...paged} onChange={paged.setPage} />
        </LdCard>
      </div>
    </>
  );
}

// ── Claim drawer detail ─────────────────────────────────────────────────

function ClaimDetail({ id, pack }) {
  const [tab, setTab] = lS("evidence");
  const c = LP.CLAIMS.find(x => x.id === id);
  const ledgerClaim = LS.ledgerClaim(pack, id);
  if (!c) return <div className="dim">Unknown claim</div>;
  const q = LP.QUALITY.byClaim[c.id] || {};
  const linkedAssets = LP.ASSETS.filter(a => a.claims.includes(c.id));
  const linkedProfiles = LP.PROFILES.filter(p => p.required_claim_ids.includes(c.id));
  const status = ledgerClaim?.status || (pack?.loaded ? "missing" : "awaiting");

  return (
    <>
      <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 10 }}>
        {ldStatusTag(status)}
        <LdTag tone={ldTone(c.category)}>{c.category}</LdTag>
        {c.required && <LdTag tone="info">required</LdTag>}
        {c.schema_version_added === 7 && <LdTag tone="accent">v7</LdTag>}
        {q.smoke_only && <LdTag tone="warn">smoke-only</LdTag>}
        {q.allow_na && <LdTag tone="na">na-allowed</LdTag>}
      </div>

      <p>{c.claim}</p>

      <LdDT value={tab} onChange={setTab} tabs={[
        { id: "evidence",  label: "Evidence" },
        { id: "details",   label: "Pack details" },
        { id: "trace",     label: "Trace map" },
        { id: "replay",    label: "Replay" },
      ]} />

      {tab === "evidence" && (
        <>
          <div className="kv__k" style={{ marginBottom: 6 }}>Validators</div>
          {(ledgerClaim?.validators || []).length === 0 ? (
            <div className="dim mono">— no validators recorded</div>
          ) : (
            <ul className="filelist">
              {ledgerClaim.validators.map((v, i) => <li key={i} className="filelist__f filelist__f--wrap">{v}</li>)}
            </ul>
          )}
          <LdHr />
          <div className="kv__k" style={{ marginBottom: 6 }}>Evidence artifacts</div>
          <LdEvList items={ledgerClaim?.evidence_artifacts || []} />
          {ledgerClaim?.failure_reason && (
            <>
              <LdHr />
              <LdCallout tone="err" title="Failure reason">{ledgerClaim.failure_reason}</LdCallout>
            </>
          )}
        </>
      )}

      {tab === "details" && (
        <>
          {ledgerClaim?.details ? (
            <pre className="code__pre" style={{ fontSize: 11, padding: 12, background: "var(--code-bg)", borderRadius: 4, maxHeight: 520, overflow: "auto" }}>{JSON.stringify(ledgerClaim.details, null, 2)}</pre>
          ) : <LdEmpty icon="○" title="No structured details" hint="The ledger entry for this claim does not carry a details payload (it's a yes/no claim)." />}
        </>
      )}

      {tab === "trace" && (
        <>
          <LdDetail k="Evidence class" v={<LdBadge tone="info">{q.class || "—"}</LdBadge>} />
          <LdDetail k="Environment" v={<LdOrigin env={q.env} />} />
          <LdDetail k="Allow NA" v={q.allow_na ? <LdTag tone="info">yes</LdTag> : <LdTag>no</LdTag>} />
          <LdDetail k="Smoke-only" v={q.smoke_only ? <LdTag tone="warn">yes</LdTag> : <LdTag>no</LdTag>} />
          <LdDetail k="Requires artifact" v={q.artifact ? <LdTag tone="ok">yes</LdTag> : <LdTag>no</LdTag>} />
          <LdHr />
          <div className="kv__k" style={{ marginBottom: 6 }}>Linked assets ({linkedAssets.length})</div>
          {linkedAssets.length === 0 ? <div className="dim mono">none directly reference this claim</div> : (
            <ul className="filelist">{linkedAssets.map(a => <li key={a.id} className="filelist__f"><span className="mono">{a.id}</span> · <span className="dim">{a.cbom || a.category}</span></li>)}</ul>
          )}
          <LdHr />
          <div className="kv__k" style={{ marginBottom: 6 }}>Profiles requiring this claim ({linkedProfiles.length})</div>
          {linkedProfiles.length === 0 ? <div className="dim mono">none</div> : (
            <div className="ptags">{linkedProfiles.map(p => <span key={p.id} className="ptag ptag--on">{p.id}</span>)}</div>
          )}
        </>
      )}

      {tab === "replay" && (
        <>
          <div className="kv__k" style={{ marginBottom: 6 }}>Commands recorded in the ledger</div>
          {(ledgerClaim?.commands || []).length === 0 ? (
            <div className="dim mono">— no commands captured in this claim</div>
          ) : (
            (ledgerClaim.commands || []).map((cmd, i) => <LdCode key={i} label={`$ ledger.commands[${i}]`}>{cmd}</LdCode>)
          )}
          <LdHr />
          <div className="kv__k" style={{ marginBottom: 6 }}>Replay tooling</div>
          <LdCode label="$ verify">{`python3 scripts/verify_release_evidence_pack.py <pack> --tag <tag>
# Filter to one claim id (script supports per-claim filtering):
python3 scripts/verify_assurance_ledger.py <pack>/assurance_ledger.json --filter ${c.id}`}</LdCode>
        </>
      )}
    </>
  );
}

window.VIEW_LEDGER = { LedgerView, ClaimDetail };
