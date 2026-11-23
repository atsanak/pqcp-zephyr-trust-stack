// views-validation.jsx — ACVP + KAT + CT smoke + Boot.

const { Card: VlCard, KV: VlKV, Tag: VlTag, Badge: VlBadge, Hr: VlHr, Sev: VlSev,
        Kpi: VlKpi, Tabs: VlTabs, Pagination: VlPgn, usePaged: vlUsePaged,
        EvBind: VlEv, Callout: VlCallout, Code: VlCode, EmptyState: VlEmpty } = window.UI;
const { HashChip: VlHash, OriginChip: VlOrigin, EvBind2: VlEvBind2,
        DetailRow: VlDetail, StatGrid: VlSGrid, Stat: VlStat,
        ChecksList: VlChecks } = window.UIX;
const VlP = window.PQCP;
const VlS = window.STORE;
const { useState: vlS, useMemo: vlM } = React;

function ValidationView({ session, pack }) {
  const [tab, setTab] = vlS("acvp");
  return (
    <div className="grid grid-12">
      <VlCard span={12} kicker="Validation" title="ACVP serial + KAT + side-channel smoke + boot KAT"
            subtitle="Algorithm correctness against NIST vectorsets, plus the runtime smoke that catches first-order regressions on the ML-KEM decapsulation hot path."
            actions={<VlTabs value={tab} onChange={setTab} tabs={[
              { id: "acvp",  label: "ACVP" },
              { id: "kat",   label: "KAT" },
              { id: "ct",    label: "CT smoke" },
              { id: "boot",  label: "Boot KAT" },
            ]} />}>
        {tab === "acvp" && <ACVPPanel pack={pack} />}
        {tab === "kat"  && <KATPanel pack={pack} />}
        {tab === "ct"   && <CTPanel pack={pack} />}
        {tab === "boot" && <BootPanel pack={pack} />}
      </VlCard>
    </div>
  );
}

function ACVPPanel({ pack }) {
  const acvpClaims = VlP.CLAIMS.filter(c => c.category === "acvp");
  const ledgerById = {};
  VlS.ledgerClaims(pack).forEach(c => { ledgerById[c.id] = c; });
  return (
    <>
      <div className="splitcols">
        <div>
          <div className="kv__k" style={{ marginBottom: 6 }}>ACVP error vocabulary (docs/api-overview.md)</div>
          <div className="errgrid">
            {VlP.ACVP_ERRORS.map(e => (
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
          <div className="kv__k" style={{ marginBottom: 6 }}>JSON interop + transcript hashes</div>
          <VlDetail k="run_acvp_json_vectors.py" v={<VlEvBind2 ev={VlS.evbind(pack, "acvp_json_interop_result.json")} />} />
          <VlDetail k="acvp_json_transcript_manifest" v={<VlEvBind2 ev={VlS.evbind(pack, "acvp_json_transcript_manifest.json")} />} />
          <VlDetail k="environment" v={<VlOrigin env="qemu_x86_64" />} />
          <VlCallout tone="info">JSON-vector interop currently runs as <strong>QEMU evidence</strong>: keyGen, encap, decap, sigGen, sigVer, transcript hashing, and malformed-then-valid recovery sequences. Not a constant-time proof.</VlCallout>
        </div>
      </div>
      <VlHr />
      <ClaimStatusTable rows={acvpClaims} ledgerById={ledgerById} />
    </>
  );
}

function KATPanel({ pack }) {
  const katClaims = VlP.CLAIMS.filter(c => c.category === "kat");
  const ledgerById = {};
  VlS.ledgerClaims(pack).forEach(c => { ledgerById[c.id] = c; });
  return (
    <>
      <VlCallout tone="info">
        Each ML-KEM and ML-DSA parameter set is verified against the vendored NIST ACVP fixtures.
        Pass/fail and per-claim evidence comes from <span className="mono">assurance_ledger.json</span>;
        the offline provenance check (<span className="mono">kat.offline_provenance</span>) binds the
        vendored vector bytes back to the upstream NIST fileset.
      </VlCallout>
      <ClaimStatusTable rows={katClaims} ledgerById={ledgerById} />
    </>
  );
}

function CTPanel({ pack }) {
  const ct = VlS.ctSampleAnalysis(pack);
  const ctSmokeClaim = VlS.ledgerClaim(pack, "security.ct_smoke");
  const measurements = ctSmokeClaim?.details?.measurements || [];
  const ttest = ctSmokeClaim?.details?.ttest_measurements || [];

  return (
    <>
      <VlCallout tone="warn" title="Smoke / regression evidence — not constant-time proof">
        CT smoke runs each ML-KEM decapsulation 32× against valid and 32× against deliberately corrupted ciphertext on
        <span className="mono"> qemu_x86_64</span>/<span className="mono">native_sim</span>. It catches first-order timing-bifurcation regressions but does not prove constant-time behaviour, and does not extend to physical hardware.
        Source: <span className="mono">docs/assurance-model.md § security.ct_smoke</span>.
      </VlCallout>

      <div style={{ marginTop: 12, display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
        {(ct?.algorithms || []).length > 0 ? (
          ct.algorithms.map(a => <CTCard key={a.algorithm} a={a} />)
        ) : measurements.length > 0 ? (
          measurements.map(m => <CTLedgerCard key={m.algorithm} m={m} ttest={ttest.find(t => t.algorithm === m.algorithm)} />)
        ) : (
          <div style={{ gridColumn: "1 / -1" }}>
            <VlEmpty icon="○" title="No CT smoke data" hint="Awaiting ct_sample_analysis_result.json or assurance_ledger.json security.ct_smoke details." />
          </div>
        )}
      </div>

      <VlHr />
      <div className="splitcols">
        <div>
          <div className="kv__k" style={{ marginBottom: 6 }}>Sample analysis</div>
          <VlEvBind2 ev={ct?.evbind || VlS.evbind(pack, "ct_sample_analysis_result.json")} />
          {ct && (
            <>
              <VlDetail k="passed" v={<VlTag tone={ct.passed ? "ok" : "err"}>{String(ct.passed)}</VlTag>} />
              <VlDetail k="algorithms" v={<span className="mono">{(ct.algorithms || []).map(a => a.algorithm).join(", ")}</span>} />
              <VlDetail k="checks" v={<span className="mono">{ct.checks.length}</span>} />
              <VlDetail k="sources" v={<ul className="filelist">{(ct.sources || []).slice(0, 3).map((s, i) => <li key={i} className="filelist__f filelist__f--wrap">{typeof s === "string" ? s : JSON.stringify(s)}</li>)}</ul>} />
            </>
          )}
        </div>
        <div>
          <div className="kv__k" style={{ marginBottom: 6 }}>Instruction-policy scan</div>
          <VlEvBind2 ev={VlS.evbind(pack, "ct_instruction_policy_result.json")} />
          <VlCallout tone="info">Disassembles the CT-smoke ELF and scans ML-KEM decapsulation-related symbols for variable-latency division mnemonics (KyberSlash regression class). Static regression evidence, not a formal side-channel proof.</VlCallout>
          <div className="markers__h">Runtime markers</div>
          <div className="markers__m">PQCP_CT_SMOKE alg=&lt;ALG&gt; iters=32 median_valid=&lt;C&gt; median_invalid=&lt;C&gt; delta=&lt;C&gt; relative_pct=&lt;P&gt; bound_pct=&lt;B&gt;</div>
          <div className="markers__m">PQCP_CT_TTEST alg=&lt;ALG&gt; iters=32 mean_valid=&lt;C&gt; mean_invalid=&lt;C&gt; t2_x1000=&lt;T&gt;</div>
        </div>
      </div>
    </>
  );
}

function CTCard({ a }) {
  const tone = a.passed ? "ok" : "err";
  return (
    <div className="ctcard">
      <div className="ctcard__h">
        <span className="ctcard__t">{a.algorithm}</span>
        <VlTag tone={tone}>{a.passed ? "within bound" : "out of bound"}</VlTag>
      </div>
      <div className="ctcard__grid">
        <div className="ctcard__row"><span className="ctcard__k">samples</span><span className="ctcard__v">{a.valid_count} · {a.invalid_count}</span></div>
        <div className="ctcard__row"><span className="ctcard__k">median valid</span><span className="ctcard__v">{a.median_valid}</span></div>
        <div className="ctcard__row"><span className="ctcard__k">median invalid</span><span className="ctcard__v">{a.median_invalid}</span></div>
        <div className="ctcard__row"><span className="ctcard__k">median Δ</span><span className="ctcard__v">{a.median_delta}</span></div>
        <div className="ctcard__row"><span className="ctcard__k">p90 valid</span><span className="ctcard__v">{a.p90_valid}</span></div>
        <div className="ctcard__row"><span className="ctcard__k">p99 valid</span><span className="ctcard__v">{a.p99_valid}</span></div>
        <div className="ctcard__row"><span className="ctcard__k">relative Δ%</span><span className="ctcard__v">{(a.relative_delta_percent ?? 0).toFixed(2)}%</span></div>
        <div className="ctcard__row"><span className="ctcard__k">Welch t²</span><span className="ctcard__v">{(a.welch_t2 ?? 0).toFixed(2)}</span></div>
      </div>
    </div>
  );
}

function CTLedgerCard({ m, ttest }) {
  return (
    <div className="ctcard">
      <div className="ctcard__h">
        <span className="ctcard__t">{m.algorithm}</span>
        <VlTag tone={m.relative_variance_pct <= m.smoke_bound_pct ? "ok" : "err"}>within bound</VlTag>
      </div>
      <div className="ctcard__grid">
        <div className="ctcard__row"><span className="ctcard__k">iterations</span><span className="ctcard__v">{m.iterations}</span></div>
        <div className="ctcard__row"><span className="ctcard__k">median valid</span><span className="ctcard__v">{m.median_valid_cycles}</span></div>
        <div className="ctcard__row"><span className="ctcard__k">median invalid</span><span className="ctcard__v">{m.median_invalid_cycles}</span></div>
        <div className="ctcard__row"><span className="ctcard__k">delta cycles</span><span className="ctcard__v">{m.delta_cycles}</span></div>
        <div className="ctcard__row"><span className="ctcard__k">relative %</span><span className="ctcard__v">{m.relative_variance_pct}</span></div>
        <div className="ctcard__row"><span className="ctcard__k">smoke bound</span><span className="ctcard__v">{m.smoke_bound_pct}%</span></div>
        {ttest && <>
          <div className="ctcard__row"><span className="ctcard__k">mean valid</span><span className="ctcard__v">{ttest.mean_valid_cycles}</span></div>
          <div className="ctcard__row"><span className="ctcard__k">Welch t² ×1000</span><span className="ctcard__v">{ttest.welch_t2_x1000}</span></div>
        </>}
      </div>
    </div>
  );
}

function BootPanel({ pack }) {
  const ledgerById = {};
  VlS.ledgerClaims(pack).forEach(c => { ledgerById[c.id] = c; });
  const c = VlP.CLAIMS.find(c => c.id === "boot.kat_self_verify");
  return (
    <>
      <div className="markers__h">Boot KAT marker</div>
      <div className="markers__m">PQCP_KAT_BOOT_VERIFY: starting power-on self-test</div>
      <div className="markers__m">PQCP_KAT_BOOT_VERIFY: all enabled primitives passed</div>
      <VlHr />
      <ClaimStatusTable rows={c ? [c] : []} ledgerById={ledgerById} />
    </>
  );
}

function ClaimStatusTable({ rows, ledgerById }) {
  return (
    <table className="tbl">
      <thead><tr><th>Claim id</th><th>Status</th><th>Evidence class</th><th>Env</th><th>Validators</th><th>Evidence artifacts</th></tr></thead>
      <tbody>
        {rows.map(c => {
          const lc = ledgerById[c.id];
          const status = lc?.status || "missing";
          const q = VlP.QUALITY.byClaim[c.id] || {};
          const tone = status === "pass" ? "ok" : status === "fail" ? "err" : status === "not_applicable" ? "na" : "warn";
          return (
            <tr key={c.id}>
              <td className="mono"><strong style={{ color: "var(--fg-0)" }}>{c.id}</strong></td>
              <td><VlTag tone={tone}>{status}</VlTag></td>
              <td><VlBadge tone="info">{q.class || "—"}</VlBadge></td>
              <td><VlOrigin env={q.env} /></td>
              <td className="mono dim" style={{ fontSize: 10.5, maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{lc?.validators?.[0] || "—"}{lc?.validators?.length > 1 && <span> +{lc.validators.length - 1}</span>}</td>
              <td className="num mono">{lc?.evidence_artifacts?.length ?? "—"}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

window.VIEW_VALIDATION = { ValidationView };
