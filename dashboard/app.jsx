// app.jsx, DashboardShell: topbar, sidebar, drawer host, view router.

const { useState: pS, useEffect: pE, useMemo: pM, createContext: pCx, useContext: pCt } = React;

const VOver  = window.VIEW_OVERVIEW;
const VLed   = window.VIEW_LEDGER;
const VPol   = window.VIEW_POLICY;
const VInv   = window.VIEW_INVENTORY;
const VBn    = window.VIEW_BENCH;
const VVl    = window.VIEW_VALIDATION;
const VFw    = window.VIEW_FIRMWARE;
const VPr    = window.VIEW_PROVENANCE;
const VIng   = window.VIEW_INGEST;
const VMs    = window.VIEW_MISC;

const { Pill: APill, Tag: ATag, Sev: ASev, EvBind: AEvBind, FilterProvider, useFilters, Drawer } = window.UI;
const { PackStateChip: APackChip } = window.UIX;
const PD = window.PQCP;
const PK = window.PACK;

const SETTINGS_DEFAULTS = {
  "theme": "graphite",
  "accent": "#6FE3B8",
  "density": "regular",
  "reps": 5,
  "minMedianImpr": 3.0,
  "maxRegrP90": 5.0,
  "maxRegrRom": 2.0,
  "objective": "cycles_median",
  "showScopeNotice": true
};

const NAV = [
  { id: "overview",    label: "Control Room",   icn: "◧", group: "Monitor" },
  { id: "findings",    label: "Findings",       icn: "△", group: "Monitor" },
  { id: "ledger",      label: "Assurance Ledger",icn: "≡", group: "Assurance" },
  { id: "policy",      label: "Policy Replay",  icn: "◆", group: "Assurance" },
  { id: "inventory",   label: "CBOM Inventory", icn: "◇", group: "Inventory" },
  { id: "provenance",  label: "Provenance",     icn: "◈", group: "Inventory" },
  { id: "bench",       label: "Benchmark Lab",  icn: "▤", group: "Measurement" },
  { id: "validation",  label: "Validation",     icn: "✓", group: "Measurement" },
  { id: "firmware",    label: "Firmware",       icn: "▣", group: "Measurement" },
  { id: "integration", label: "Integration",    icn: "↻", group: "Settings" },
  { id: "configurator", label: "Configurator",   icn: "⚙", group: "Settings" },
  { id: "ingest",      label: "Ingest",         icn: "↓", group: "Settings" },
];

// Drawer context
const DrawerCtx = pCx(null);
function useDrawer() { return pCt(DrawerCtx); }

function App() {
  const [t, setSetting] = useSettings(SETTINGS_DEFAULTS);
  const [pack, setPack] = pS(() => PK.restorePack() || PK.emptyPack());
  const [session, setSession] = pS(() => ({
    path: pack.loaded ? (pack.source?.name || "(seed pack)") : "",
    ingested: !!pack.loaded,
    mode: PD.MODES.default,
  }));
  const [view, setView] = pS(() => (location.hash || "#overview").slice(1));
  const [drawer, setDrawer] = pS({ open: false, kind: null, payload: null });

  function applyPack(p) {
    setPack(p);
    PK.persistPack(p);
    setSession(s => ({ ...s, ingested: !!p.loaded, path: p.loaded ? (p.source?.name || "(seed pack)") : "" }));
  }
  function clearPack() {
    PK.clearPack();
    const e = PK.emptyPack();
    setPack(e);
    setSession(s => ({ ...s, ingested: false, path: "" }));
  }

  pE(() => {
    const onHash = () => setView((location.hash || "#overview").slice(1));
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  pE(() => {
    document.documentElement.dataset.theme = t.theme;
    document.documentElement.dataset.density = t.density;
    document.documentElement.style.setProperty("--accent", t.accent);
  }, [t.theme, t.density, t.accent]);

  pE(() => {
    function onKey(e) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        document.getElementById("global-search")?.focus();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const groups = ["Monitor", "Assurance", "Inventory", "Measurement", "Settings"];

  function openDrawer(kind, payload) { setDrawer({ open: true, kind, payload }); }
  function closeDrawer() { setDrawer({ open: false, kind: null, payload: null }); }
  function jumpView(id) { location.hash = "#" + id; setView(id); }

  return (
    <FilterProvider>
      <DrawerCtx.Provider value={{ openDrawer, closeDrawer, ...drawer }}>
        <div className="shell">
          <TopBar session={session} setSession={setSession} pack={pack} onClearPack={clearPack} />
          <div className="shell__body">
            <Sidebar view={view} onNav={jumpView} groups={groups} pack={pack} />
            <main className="main">
              {t.showScopeNotice && <ScopeNotice onClose={() => setSetting("showScopeNotice", false)} />}
              <GlobalFilterStrip />

              {view === "overview"     && <VOver.OverviewView session={session} pack={pack} onJumpView={jumpView} />}
              {view === "findings"     && <VMs.FindingsView   session={session} pack={pack} />}
              {view === "ledger"       && <VLed.LedgerView    session={session} pack={pack} />}
              {view === "policy"       && <VPol.PolicyView    session={session} pack={pack} />}
              {view === "inventory"    && <VInv.InventoryView session={session} pack={pack} />}
              {view === "provenance"   && <VPr.ProvenanceView session={session} pack={pack} />}
              {view === "bench"        && <VBn.BenchLabView   session={session} pack={pack} settings={t} setSetting={setSetting} />}
              {view === "validation"   && <VVl.ValidationView session={session} pack={pack} />}
              {view === "firmware"     && <VFw.FirmwareView   session={session} pack={pack} />}
              {view === "integration"  && <VMs.IntegrationView session={session} pack={pack} />}
              {view === "configurator" && <VMs.ConfiguratorView session={session} pack={pack} settings={t} setSetting={setSetting} />}
              {view === "ingest"       && <VIng.IngestView session={session} setSession={setSession} pack={pack} onLoadPack={applyPack} onClearPack={clearPack} />}
            </main>
          </div>

          <DrawerHost pack={pack} />
        </div>

        <SettingsPanel>
          <SettingSection label="Appearance" />
          <SettingRadio label="Theme" value={t.theme} options={["graphite","steel","paper"]} onChange={v => setSetting("theme", v)} />
          <SettingColor label="Accent" value={t.accent} options={["#6FE3B8","#7FB8E8","#E8B870","#E89F8C"]} onChange={v => setSetting("accent", v)} />
          <SettingRadio label="Density" value={t.density} options={["compact","regular","comfy"]} onChange={v => setSetting("density", v)} />

          <SettingSection label="Optimization defaults" />
          <SettingSlider label="Repetitions" value={t.reps} min={1} max={50} step={1} onChange={v => setSetting("reps", v)} />
          <SettingSlider label="Min median impr" value={t.minMedianImpr} min={0} max={50} step={0.5} unit="%" onChange={v => setSetting("minMedianImpr", v)} />
          <SettingSlider label="Max p90/p99 regr" value={t.maxRegrP90} min={0} max={25} step={0.5} unit="%" onChange={v => setSetting("maxRegrP90", v)} />
          <SettingSlider label="Max ROM/RAM regr" value={t.maxRegrRom} min={0} max={20} step={0.5} unit="%" onChange={v => setSetting("maxRegrRom", v)} />
          <SettingSelect label="Objective" value={t.objective} options={["cycles_median","cycles_p90","cycles_p99","handshake_p99_ms"]} onChange={v => setSetting("objective", v)} />

          <SettingSection label="Disclosures" />
          <SettingToggle label="Scope notice" value={t.showScopeNotice} onChange={v => setSetting("showScopeNotice", v)} />
        </SettingsPanel>
      </DrawerCtx.Provider>
    </FilterProvider>
  );
}

function TopBar({ session, setSession, pack, onClearPack }) {
  const f = useFilters();
  const release = window.STORE.release(pack);
  return (
    <header className="topbar">
      <div className="topbar__brand">
        <div className="topbar__mark" aria-hidden>
          <svg viewBox="0 0 24 24" width="18" height="18">
            <rect x="3" y="3" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.6" />
            <path d="M3 8 L21 8 M3 16 L21 16 M8 3 L8 21 M16 3 L16 21" stroke="currentColor" strokeWidth=".6" opacity=".55" />
            <circle cx="12" cy="12" r="2.2" fill="currentColor" />
          </svg>
        </div>
        <div>
          <div className="topbar__t">PQCP Assurance</div>
          <div className="topbar__s mono">
            {release?.tag ? `${release.tag} · ${release.head_sha ? release.head_sha.slice(0, 8) : "n/a"}${release.dirty ? " · dirty" : ""}`
                          : `${PD.REPO.owner}/${PD.REPO.name}`}
          </div>
        </div>
      </div>

      <div className="topbar__center">
        <div className="topbar__search">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.6"/><path d="M21 21l-4.3-4.3" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"/></svg>
          <input id="global-search"
                 placeholder="Search claims, components, artifacts, Kconfig…"
                 value={f.q} onChange={e => f.setQ(e.target.value)} />
          <span className="topbar__kbd">⌘K</span>
        </div>

        {pack && pack.loaded ? (
          <span className="topbar__pack">
            <span className="topbar__pack__t mono" title={pack.source?.name}>{(pack.source?.name || "seed pack").slice(0, 28)}</span>
            <span className="topbar__pack__s">· {Object.keys(pack.artifacts).length} artifacts</span>
            <button className="topbar__pack__x" onClick={onClearPack} aria-label="Clear pack">×</button>
          </span>
        ) : (
          <a href="#ingest" className="topbar__pack" onClick={() => { location.hash = "#ingest"; }}>
            <span className="topbar__pack__t">Load release pack…</span>
          </a>
        )}

        <div className="releasechip">
          <span className="releasechip__l">Mode</span>
          <select className="releasechip__sel" value={session.mode} onChange={e => setSession({ ...session, mode: e.target.value })}>
            {PD.MODES.modes.map(m => <option key={m.id} value={m.id}>{m.id}</option>)}
          </select>
        </div>
      </div>

      <div className="topbar__act">
        <APackChip pack={pack} />
        <ATag tone="warn">read-only</ATag>
      </div>
    </header>
  );
}

function Sidebar({ view, onNav, groups, pack }) {
  return (
    <aside className="sidebar">
      {groups.map(g => (
        <div key={g} className="navgroup">
          <div className="navgroup__h">{g}</div>
          {NAV.filter(n => n.group === g).map(n => (
            <button key={n.id} className={`nav__i ${view === n.id ? "nav__i--on" : ""}`} onClick={() => onNav(n.id)}>
              <span className="nav__icn">{n.icn}</span>
              <span className="nav__lbl">{n.label}</span>
              <span className="nav__badge"></span>
            </button>
          ))}
        </div>
      ))}
      <div className="sidebar__foot">
        <div className="sidebar__legend-h">Status legend</div>
        <div className="leg"><span className="leg__d leg__d--ok" />replay verified</div>
        <div className="leg"><span className="leg__d leg__d--warn" />awaiting / smoke evidence</div>
        <div className="leg"><span className="leg__d leg__d--err" />failed / hash drift</div>
        <div className="sidebar__note">
          Read-only. Every visible number comes from an on-disk artifact in the loaded release pack.
          Missing artifacts show "awaiting" rather than synthesizing replacement values.
        </div>
      </div>
    </aside>
  );
}

function GlobalFilterStrip() {
  const f = useFilters();
  const { FilterChip, FilterBar } = window.UI;
  function truncate(s, n) { return s.length <= n ? s : "…" + s.slice(-(n - 1)); }
  const chips = [];
  if (f.q !== "")        chips.push({ k: "q",       l: "search",    v: '"' + truncate(f.q, 20) + '"', onClear: () => f.setQ("") });
  if (f.category !== "any") chips.push({ k: "cat",  l: "category",  v: f.category, onClear: () => f.setCategory("any") });
  if (f.env !== "any")      chips.push({ k: "env",  l: "env",       v: f.env,     onClear: () => f.setEnv("any") });
  if (f.severity !== "any") chips.push({ k: "sev",  l: "severity",  v: f.severity, onClear: () => f.setSeverity("any") });
  if (f.status !== "any")   chips.push({ k: "stat", l: "status",    v: f.status,  onClear: () => f.setStatus("any") });
  if (!f.hasAny) return null;
  return (
    <FilterBar hasFilters={f.hasAny} onClearAll={f.clear}>
      {chips.map(c => <FilterChip key={c.k} label={c.l} value={c.v} onClear={c.onClear} />)}
    </FilterBar>
  );
}

function ScopeNotice({ onClose }) {
  return (
    <div className="banner">
      <span className="banner__icn"><ASev level="info" /></span>
      <div className="banner__t">
        Reports <strong>local release evidence</strong>, <strong>QEMU regression evidence</strong>, and <strong>hash-bound artifacts</strong>.
        Not a certification, formal verification, or hardware attestation. Provenance markers show the environment
        (<span className="mono">host_python · qemu_x86_64 · native_sim · build_only · git</span>) for every value.
      </div>
      <button className="banner__x" onClick={onClose} aria-label="Dismiss">×</button>
    </div>
  );
}

function DrawerHost({ pack }) {
  const d = useDrawer();
  if (!d) return null;
  const kicker = d.kind === "claim" ? "Claim detail"
              : d.kind === "asset" ? "Asset detail"
              : d.kind === "cbom"  ? "CBOM component"
              : d.kind === "artifact" ? "Artifact detail"
              : d.kind === "finding"  ? "Finding detail" : "";
  return (
    <Drawer open={d.open} onClose={d.closeDrawer}
      kicker={kicker}
      title={d.payload?.title || ""}
      subtitle={d.payload?.subtitle || ""}>
      {d.kind === "claim"    && <VLed.ClaimDetail id={d.payload?.id} pack={pack} />}
      {d.kind === "cbom"     && <VInv.CbomComponentDetail id={d.payload?.id} pack={pack} />}
      {d.kind === "finding"  && <VMs.FindingDetail finding={d.payload} pack={pack} />}
    </Drawer>
  );
}

window.useDrawer = useDrawer;
window.useFilters = useFilters;

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
