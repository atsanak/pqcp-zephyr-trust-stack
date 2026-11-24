// views-misc.jsx, Findings, Integration, Configurator. Derived from real
// pack state where possible; everything else exposes the source artifact +
// validator that would close the gap.

const { Card: MsCard, KV: MsKV, Tag: MsTag, Badge: MsBadge, Hr: MsHr, Sev: MsSev,
        Kpi: MsKpi, Tabs: MsTabs, Segmented: MsSeg, Switch: MsSwitch, Pagination: MsPgn, usePaged: msUsePaged,
        EvBind: MsEv, Callout: MsCallout, Code: MsCode, EmptyState: MsEmpty } = window.UI;
const { HashChip: MsHash, OriginChip: MsOrigin, EvBind2: MsEvBind2,
        DetailRow: MsDetail, StatGrid: MsSGrid, Stat: MsStat } = window.UIX;
const MsP = window.PQCP;
const MsS = window.STORE;
const MsPK = window.PACK;
const { useState: msS_, useMemo: msM } = React;

function msFiltersSafe() { return (window.useFilters && window.useFilters()) || {}; }
function msDrawerSafe()  { return (window.useDrawer  && window.useDrawer())  || { openDrawer: () => {} }; }

// ═══════════════════════════════════════════════════════════════════════
// FINDINGS, derived from console state + parsed artifact contents
// ═══════════════════════════════════════════════════════════════════════

function FindingsView({ session, pack }) {
  const f = msFiltersSafe();
  const drawer = msDrawerSafe();

  const findings = msM(() => buildFindings(pack, session), [pack, session]);

  const filtered = findings.filter(x =>
    (!f.q || (x.title + x.sub + x.artifact).toLowerCase().includes(f.q.toLowerCase())) &&
    (f.category === "any" || x.category === f.category || !f.category) &&
    (f.severity === "any" || x.severity === f.severity || !f.severity) &&
    (f.env === "any" || x.env === f.env || !f.env)
  );

  const sev = { critical: 0, high: 0, warn: 0, info: 0 };
  findings.forEach(x => { sev[x.severity] = (sev[x.severity] || 0) + 1; });
  const paged = msUsePaged(filtered, 16);

  return (
    <>
      <div className="grid-kpi" style={{ marginBottom: 12 }}>
        <MsKpi label="Open findings" status="warn" value={findings.length} sub="derived from console state" />
        <MsKpi label="Critical" status="crit" value={sev.critical} sub="blocking partner sign-off" />
        <MsKpi label="High"     status="err"  value={sev.high}     sub="must resolve to promote" />
        <MsKpi label="Warn"     status="warn" value={sev.warn}     sub="advisory, mode-dependent" />
        <MsKpi label="Info"     status="info" value={sev.info}     sub="documentation / policy notes" />
      </div>

      <div className="grid grid-12">
        <MsCard span={12} kicker="Findings" title="Backlog, every entry references a real artifact"
              subtitle="Each finding ties a failed or awaiting state to the artifact + validator that would close it."
              padded={false}
              actions={<MsSeg size="sm" value={f.severity || "any"} onChange={f.setSeverity}
                options={[{ id: "any", label: "all" }, { id: "critical", label: "crit" }, { id: "high", label: "high" }, { id: "warn", label: "warn" }, { id: "info", label: "info" }]} />}>
          {paged.rows.length === 0 ? (
            <MsEmpty icon="✓" title="No findings match these filters" hint="Try clearing the global filter chips." />
          ) : paged.rows.map(x => (
            <div key={x.id} className="finding" onClick={() => drawer.openDrawer("finding", { title: x.title, subtitle: x.id, ...x })}>
              <MsSev level={x.severity} />
              <div>
                <div className="finding__t">{x.title}</div>
                <div className="finding__s">{x.sub}</div>
              </div>
              <span className="evb evb--warn"><span className="evb__sym">○</span><span className="evb__file">{x.artifact}</span></span>
              <MsTag tone={x.severity === "critical" ? "crit" : x.severity === "high" ? "err" : x.severity === "warn" ? "warn" : "info"}>{x.severity}</MsTag>
            </div>
          ))}
          <MsPgn {...paged} onChange={paged.setPage} />
        </MsCard>
      </div>
    </>
  );
}

function buildFindings(pack, session) {
  const list = [];
  const ingested = !!(pack && pack.loaded);
  const mode = session.mode;

  if (!ingested) {
    list.push({ id: "F-no-pack", severity: "high", category: "release", env: "host_python",
      title: "No release pack ingested",
      sub: "Every claim status, every CBOM property, every hash is awaiting parse.",
      artifact: "(none)", validator: "scripts/build_pqcp_dashboard_seed_pack.py" });
    return list;
  }

  // Pack parse warnings
  (pack.warnings || []).forEach((w, i) => list.push({
    id: `F-parse-${i}`, severity: "info", category: "release", env: "host_python",
    title: `Pack parser warning`, sub: w, artifact: "(pack)", validator: "ArtifactLoader",
  }));

  // Failed claims
  MsS.ledgerClaims(pack).filter(c => c.status === "fail").forEach(c => list.push({
    id: `F-claim-${c.id}`, severity: "high", category: c.category, env: "host_python",
    title: `Claim failed: ${c.id}`,
    sub: c.failure_reason || c.claim,
    artifact: "assurance_ledger.json",
    validator: c.validators?.[0] || "scripts/generate_assurance_ledger.py",
  }));

  // Policy failures
  const policy = MsS.policyResult(pack);
  (policy?.failures || []).forEach((f, i) => list.push({
    id: `F-policy-${i}`, severity: "high", category: "release", env: "host_python",
    title: `Policy failure: ${f.check || f.id || "check"}`,
    sub: typeof f === "string" ? f : JSON.stringify(f),
    artifact: "pqc_policy_result.json", validator: "scripts/verify_assurance_policy.py",
  }));

  // Environment failures
  const env = MsS.environmentResult(pack);
  (env?.failures || []).forEach((f, i) => list.push({
    id: `F-env-${i}`, severity: "warn", category: "supply_chain", env: "host_python",
    title: `Environment check failed: ${f.check || ""}`,
    sub: typeof f === "string" ? f : JSON.stringify(f),
    artifact: "pqc_environment_result.json", validator: "scripts/verify_pqc_environment.py",
  }));

  // Migration blocked
  const mig = MsS.migrationReadiness(pack);
  (mig?.blocked_conditions || []).forEach((b, i) => list.push({
    id: `F-mig-${i}`, severity: "warn", category: "release", env: "host_python",
    title: `Migration blocked: ${b.condition || b.id || ""}`,
    sub: b.reason || JSON.stringify(b),
    artifact: "pqc_migration_readiness.json", validator: "scripts/generate_migration_readiness_report.py",
  }));

  // CT smoke: if Welch t² is "high" in the ledger details, surface as info even if it passed
  const ct = MsS.ctSampleAnalysis(pack);
  if (ct) ct.algorithms.forEach(a => {
    if (!a.passed) list.push({
      id: `F-ct-${a.algorithm}`, severity: "high", category: "security", env: "qemu_x86_64",
      title: `CT smoke OOB for ${a.algorithm}`,
      sub: `relative_delta_percent=${a.relative_delta_percent?.toFixed?.(2)}% · welch_t2=${a.welch_t2?.toFixed?.(2)}`,
      artifact: "ct_sample_analysis_result.json", validator: "scripts/analyze_ct_samples.py",
    });
  });

  // Missing-but-mode-required artifacts
  const requiredForMode = MsP.MODE_REQUIRED_ARTIFACTS[mode] || [];
  requiredForMode.forEach(file => {
    if (!MsPK.present(pack, file)) list.push({
      id: `F-mode-${file}`, severity: "warn", category: "release", env: "host_python",
      title: `Mode-required artifact awaiting: ${file}`,
      sub: `Required by mode ${mode}. Validator: ${MsS.validatorFor(file) || "?"}`,
      artifact: file, validator: MsS.validatorFor(file) || "?",
    });
  });

  // RNG policy informational
  const det = MsS.cbomComponents(pack).find(c => c.name === "Deterministic test RNG");
  if (det) list.push({
    id: "F-rng", severity: "info", category: "security", env: "host_python",
    title: "Deterministic test RNG in CBOM",
    sub: det.productionAllowed
      ? "VIOLATION: production_allowed=true. Forbidden in qemu_release / mcu_minimal / gateway."
      : "production_allowed=false. Test-only material, permitted in native_lab only.",
    artifact: "pqc_cbom.cdx.json", validator: "scripts/verify_pqc_assurance_profile.py",
  });

  return list;
}

function FindingDetail({ finding }) {
  if (!finding) return null;
  return (
    <>
      <MsCallout tone={finding.severity === "critical" || finding.severity === "high" ? "err" : finding.severity === "warn" ? "warn" : "info"} title={finding.title}>
        {finding.sub}
      </MsCallout>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 4, marginTop: 14 }}>
        <MsDetail k="Severity" v={<MsTag tone={finding.severity === "critical" ? "crit" : finding.severity === "high" ? "err" : finding.severity === "warn" ? "warn" : "info"}>{finding.severity}</MsTag>} />
        <MsDetail k="Category" v={<MsTag>{finding.category}</MsTag>} />
        <MsDetail k="Environment" v={<MsOrigin env={finding.env} />} />
        <MsDetail k="Finding id" v={<span className="mono">{finding.id}</span>} />
      </div>
      <MsHr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Resolution path</div>
      <MsEvBind2 ev={{ file: finding.artifact, validator: finding.validator, status: "missing" }} />
      <MsHr />
      <MsCode label="$ produce">{`python3 ${finding.validator}`}</MsCode>
    </>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// INTEGRATION
// ═══════════════════════════════════════════════════════════════════════

function IntegrationView({ session, pack }) {
  const [board, setBoard] = msS_("qemu_x86_64");
  const [target, setTarget] = msS_("tests/ztest_rng");
  const [tag, setTag] = msS_(MsS.release(pack)?.tag || "v1.0.0");
  const outRoot = pack.source?.mode === "directory" ? pack.source.name : "<release-pack>";

  return (
    <div className="grid grid-12">
      <MsCard span={5} kicker="Consumer smoke" title="west-based downstream check"
            subtitle="scripts/consumer_smoke.py, minimum proof that a downstream Zephyr workspace can build this module."
            actions={<MsEvBind2 ev={{ file: "scripts/consumer_smoke.py", validator: "scripts/consumer_smoke.py", env: "qemu_x86_64", status: "present" }} compact />}>
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
        <MsHr />
        <MsCode label="$ consumer smoke">{`python3 scripts/consumer_smoke.py \\
  --board       ${board} \\
  --target      ${target} \\
  --build-dir   build-consumer-smoke`}</MsCode>
        <div className="dim mono" style={{ fontSize: 11 }}>success marker · PROJECT EXECUTION SUCCESSFUL</div>
      </MsCard>

      <MsCard span={7} kicker="Release flow" title="Three commands, in order"
            subtitle="docs/release.md TL;DR. The console reads the pack the third command produces.">
        <div className="flow">
          <FStep n="1" t="Run the full release gate"
            d="Produces JUnit, ledger, HTML report, transcripts, benchmark CSV + provenance, MCU footprint, release bundle, and every Passport artifact."
            code={`python3 scripts/release_check.py --tag ${tag} --output-root ${outRoot}`} />
          <FStep n="2" t="Optionally prepare the exact-tag bundle"
            d="--exact-tag requires a clean checkout that matches the tag. --verify-remote-tag confirms origin agrees."
            code={`git checkout ${tag}\npython3 scripts/prepare_release_bundle.py --exact-tag --verify-remote-tag`} />
          <FStep n="3" t="Replay-verify without rebuilding"
            d="Python 3.12 only. Re-hashes every recorded SHA-256, checks every required claim id, every Passport subject, every SLSA byproduct, every ACVP JSON transcript hash."
            code={`python3 scripts/verify_release_evidence_pack.py ${outRoot} --tag ${tag} --mode ${session.mode}`} />
        </div>
        <div className="ctrl" style={{ marginTop: 8 }}>
          <div className="ctrl__lbl"><span>Tag</span></div>
          <input className="input mono" value={tag} onChange={e => setTag(e.target.value)} />
        </div>
      </MsCard>

      <MsCard span={12} kicker="west.yml manifest" title="Authoritative module pins"
            actions={<MsEvBind2 ev={{ file: "west.yml", env: "git", status: "present" }} />}>
        <MsCode label="west.yml">{`manifest:
  self:
    path: pqcp-zephyr-trust-stack

  remotes:
    - name: zephyrproject-rtos
      url-base: https://github.com/zephyrproject-rtos
    - name: pqcp
      url-base: https://github.com/pq-code-package

  projects:
${MsP.REPO.west_pins.map(p => `    - name: ${p.name}
      remote: ${p.remote}
      revision: ${p.revision}${p.name === "zephyr" ? "\n      import: true" : `\n      path: modules/crypto/${p.name}`}`).join("\n")}`}</MsCode>
      </MsCard>
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
        <MsCode label={`$ step ${n}`}>{code}</MsCode>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// CONFIGURATOR
// ═══════════════════════════════════════════════════════════════════════

function ConfiguratorView({ settings, setSetting, session, pack }) {
  const [cfg, setCfg] = msS_({
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

  const lines = [];
  if (cfg.mlkem_512 || cfg.mlkem_768 || cfg.mlkem_1024) lines.push("CONFIG_PQCP_MLKEM=y");
  if (cfg.mlkem_512)  lines.push("CONFIG_PQCP_MLKEM_LEVEL_512=y");
  if (cfg.mlkem_768)  lines.push("CONFIG_PQCP_MLKEM_LEVEL_768=y");
  if (cfg.mlkem_1024) lines.push("CONFIG_PQCP_MLKEM_LEVEL_1024=y");
  if (cfg.mldsa_44 || cfg.mldsa_65 || cfg.mldsa_87) lines.push("CONFIG_PQCP_MLDSA=y");
  if (cfg.mldsa_44) lines.push("CONFIG_PQCP_MLDSA_LEVEL_44=y");
  if (cfg.mldsa_65) lines.push("CONFIG_PQCP_MLDSA_LEVEL_65=y");
  if (cfg.mldsa_87) lines.push("CONFIG_PQCP_MLDSA_LEVEL_87=y");
  lines.push("");
  lines.push("# RNG");
  if (cfg.profile === "native_lab") {
    lines.push("CONFIG_PQCP_RNG_CUSTOM=y");
    lines.push("CONFIG_PQCP_RNG_DETERMINISTIC_TEST=y  # test-only; forbidden in qemu_release/mcu_minimal/gateway");
  } else {
    lines.push("CONFIG_PQCP_RNG_ZEPHYR_ENTROPY=y");
  }
  lines.push("");
  lines.push("# Validation harness");
  if (cfg.profile !== "mcu_minimal" && cfg.profile !== "gateway") {
    lines.push("CONFIG_PQCP_ACVP=y");
    lines.push(`CONFIG_PQCP_ACVP_READLINE_TIMEOUT_MS=${cfg.acvp_readline_timeout_ms}`);
  }
  if (cfg.kat_smoke_only) lines.push("CONFIG_PQCP_KAT_SMOKE_ONLY=y");
  lines.push("");
  lines.push("# Boot self-verify");
  lines.push("CONFIG_PQCP_KAT_BOOT_VERIFY=y");

  return (
    <div className="grid grid-12">
      <MsCard span={5} kicker="Configurator · ConfigGenerator" title="Compose a Kconfig overlay"
            subtitle="Toggles only use symbols declared in scripts/pqc_asset_trace_map.json. The console never edits the repo.">
        <div className="cfgsect">
          <div className="cfgsect__h">Profile</div>
          <select className="input mono" value={cfg.profile} onChange={e => set("profile", e.target.value)}>
            {MsP.PROFILES.map(p => <option key={p.id} value={p.id}>{p.id}</option>)}
          </select>
          <div className="dim" style={{ fontSize: 11, marginTop: 6 }}>{MsP.PROFILES.find(p => p.id === cfg.profile)?.description}</div>
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
            <MsSeg value={cfg.opt_level} onChange={v => set("opt_level", v)} options={["Os", "O2", "O3"]} />
          </div>
          <div className="cfgrow">
            <div>
              <div className="cfgrow__l">Link-time optimization</div>
              <div className="cfgrow__s">CONFIG_LTO</div>
            </div>
            <MsSwitch value={cfg.lto} onChange={v => set("lto", v)} />
          </div>
        </div>

        <div className="cfgsect">
          <div className="cfgsect__h">Release mode</div>
          <select className="input mono" value={cfg.mode} onChange={e => set("mode", e.target.value)}>
            {MsP.MODES.modes.map(m => <option key={m.id} value={m.id}>{m.id}</option>)}
          </select>
          <div className="dim" style={{ fontSize: 11, marginTop: 6 }}>{MsP.MODES.modes.find(m => m.id === cfg.mode)?.description}</div>
        </div>
      </MsCard>

      <MsCard span={7} kicker="Generated overlay" title="prj.conf.overlay"
            subtitle="Pasteable. Symbols match scripts/pqc_asset_trace_map.json. Forbidden combinations are commented inline.">
        <MsCode label="prj.conf overlay">{lines.join("\n")}</MsCode>
        <MsHr />
        <div className="kv__k" style={{ marginBottom: 6 }}>west build</div>
        <MsCode label="$ build">{`west build -p always -b qemu_x86_64 tests/ztest_acvp_kat \\
  -- -DOVERLAY_CONFIG=prj.conf.overlay \\
     -DCONFIG_COMPILER_OPT="-${cfg.opt_level}" \\
     ${cfg.lto ? "-DCONFIG_LTO=y" : "# LTO disabled"}`}</MsCode>
        <div className="kv__k" style={{ marginBottom: 6 }}>release_check.py</div>
        <MsCode label="$ release_check">{`python3 scripts/release_check.py \\
  --tag v1.0.0 \\
  --output-root <release-pack>`}</MsCode>
        <div className="kv__k" style={{ marginBottom: 6 }}>optimize_metric_campaign.py</div>
        <MsCode label="$ optimize">{`python3 scripts/optimize_metric_campaign.py \\
  --in        <pack>/benchmark_campaign_result.json \\
  --objective ${settings.objective} \\
  --out       <pack>/optimize_metric_campaign_result.json`}</MsCode>
        <MsCallout tone="info">Selecting <span className="mono">native_lab</span> permits <span className="mono">CONFIG_PQCP_RNG_DETERMINISTIC_TEST=y</span>; selecting <span className="mono">qemu_release</span>, <span className="mono">mcu_minimal</span>, or <span className="mono">gateway</span> forbids it. Enforced by <span className="mono">scripts/verify_pqc_assurance_profile.py</span>, not by this UI.</MsCallout>
      </MsCard>
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
      <MsSwitch value={v} onChange={on} />
    </div>
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

window.VIEW_MISC = { FindingsView, FindingDetail, IntegrationView, ConfiguratorView };
