// app.jsx — Shell + topbar (search + global filters) + sidebar + drawer state.

const { useState: pS, useEffect: pE, useMemo: pM, createContext: pCx, useContext: pCt } = React;
const VA = window.VIEWS_A;
const VB = window.VIEWS_B;
const { Pill: APill, Tag: ATag, Sev: ASev, EvBind: AEvBind, FilterProvider, useFilters, Drawer } = window.UI;
const PD = window.PQCP;
const PK = window.PACK;

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "theme": "graphite",
  "accent": "#6FE3B8",
  "density": "regular",
  "reps": 5,
  "minMedianImpr": 3.0,
  "maxRegrP90": 5.0,
  "maxRegrRom": 2.0,
  "objective": "cycles_median",
  "showHonestyBanner": true
}/*EDITMODE-END*/;

const NAV = [
  { id: "overview",     label: "Overview",        icn: "◧", group: "Monitor" },
  { id: "findings",     label: "Findings",        icn: "△", group: "Monitor" },
  { id: "ledger",       label: "Ledger",          icn: "≡", group: "Assurance" },
  { id: "policy",       label: "Policy",          icn: "◆", group: "Assurance" },
  { id: "inventory",    label: "Inventory",       icn: "◇", group: "Inventory" },
  { id: "provenance",   label: "Provenance",      icn: "◈", group: "Inventory" },
  { id: "bench",        label: "Bench Lab",       icn: "▤", group: "Measurement" },
  { id: "validation",   label: "Validation",      icn: "✓", group: "Measurement" },
  { id: "firmware",     label: "Firmware",        icn: "▣", group: "Measurement" },
  { id: "integration",  label: "Integration",     icn: "↻", group: "Settings" },
  { id: "configurator", label: "Configurator",    icn: "⚙", group: "Settings" },
  { id: "ingest",       label: "Ingest",          icn: "↓", group: "Settings" },
];

// Drawer context — opens claim/artifact/asset detail anywhere in the app
const DrawerCtx = pCx(null);
function useDrawer() { return pCt(DrawerCtx); }

function App() {
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);
  const [pack, setPack] = pS(() => PK.restorePack() || PK.emptyPack());
  const [session, setSession] = pS(() => ({
    path: pack.loaded ? "(seed pack)" : "",
    ingested: !!pack.loaded,
    mode: PD.MODES.default,
  }));
  const [view, setView] = pS(() => (location.hash || "#overview").slice(1));
  const [drawer, setDrawer] = pS({ open: false, kind: null, payload: null });

  function applyPack(p) {
    setPack(p);
    PK.persistPack(p);
    setSession(s => ({ ...s, ingested: !!p.loaded, path: p.loaded ? (p.generated_from?.path || "(seed pack)") : "" }));
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

  // Keyboard: ⌘/Ctrl+K focuses search; Esc clears
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

  return (
    <FilterProvider>
      <DrawerCtx.Provider value={{ openDrawer, closeDrawer, ...drawer }}>
        <div className="shell">
          <TopBar session={session} setSession={setSession} />
          <div className="shell__body">
            <Sidebar view={view} onNav={(id) => { location.hash = "#" + id; setView(id); }} groups={groups} />
            <main className="main">
              {t.showHonestyBanner && <HonestyBanner onClose={() => setTweak("showHonestyBanner", false)} />}
              <GlobalFilterStrip />

              {view === "overview"     && <VA.OverviewView session={session} pack={pack} />}
              {view === "findings"     && <VA.FindingsView session={session} pack={pack} />}
              {view === "ledger"       && <VA.LedgerView session={session} pack={pack} />}
              {view === "policy"       && <VA.PolicyView session={session} pack={pack} />}
              {view === "inventory"    && <VA.InventoryView session={session} pack={pack} />}
              {view === "provenance"   && <VB.ProvenanceView session={session} pack={pack} />}
              {view === "bench"        && <VB.BenchLabView tweaks={t} setTweak={setTweak} session={session} pack={pack} />}
              {view === "validation"   && <VB.ValidationView session={session} pack={pack} />}
              {view === "firmware"     && <VB.FirmwareView session={session} pack={pack} />}
              {view === "integration"  && <VB.IntegrationView session={session} pack={pack} />}
              {view === "configurator" && <VB.ConfiguratorView tweaks={t} setTweak={setTweak} session={session} pack={pack} />}
              {view === "ingest"       && <VA.IngestView session={session} setSession={setSession} pack={pack} onLoadPack={applyPack} onClearPack={clearPack} />}
            </main>
          </div>

          <DrawerHost pack={pack} />
        </div>

        <TweaksPanel>
          <TweakSection label="Appearance" />
          <TweakRadio label="Theme" value={t.theme} options={["graphite","steel","paper"]} onChange={v => setTweak("theme", v)} />
          <TweakColor label="Accent" value={t.accent} options={["#6FE3B8","#7FB8E8","#E8B870","#E89F8C"]} onChange={v => setTweak("accent", v)} />
          <TweakRadio label="Density" value={t.density} options={["compact","regular","comfy"]} onChange={v => setTweak("density", v)} />

          <TweakSection label="Optimization defaults" />
          <TweakSlider label="Repetitions" value={t.reps} min={1} max={50} step={1} onChange={v => setTweak("reps", v)} />
          <TweakSlider label="Min median impr" value={t.minMedianImpr} min={0} max={50} step={0.5} unit="%" onChange={v => setTweak("minMedianImpr", v)} />
          <TweakSlider label="Max p90/p99 regr" value={t.maxRegrP90} min={0} max={25} step={0.5} unit="%" onChange={v => setTweak("maxRegrP90", v)} />
          <TweakSlider label="Max ROM/RAM regr" value={t.maxRegrRom} min={0} max={20} step={0.5} unit="%" onChange={v => setTweak("maxRegrRom", v)} />
          <TweakSelect label="Objective" value={t.objective} options={["cycles_median","cycles_p90","cycles_p99","handshake_p99_ms"]} onChange={v => setTweak("objective", v)} />

          <TweakSection label="Disclosures" />
          <TweakToggle label="Honesty banner" value={t.showHonestyBanner} onChange={v => setTweak("showHonestyBanner", v)} />
        </TweaksPanel>
      </DrawerCtx.Provider>
    </FilterProvider>
  );
}

function TopBar({ session, setSession }) {
  const f = useFilters();
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
          <div className="topbar__s mono">{PD.REPO.owner}/{PD.REPO.name} · {PD.REPO.head_short}</div>
        </div>
      </div>

      <div className="topbar__center">
        <div className="topbar__search">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.6"/><path d="M21 21l-4.3-4.3" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"/></svg>
          <input
            id="global-search"
            placeholder="Search claims, assets, artifacts, Kconfig…"
            value={f.q}
            onChange={e => f.setQ(e.target.value)}
          />
          <span className="topbar__kbd">⌘K</span>
        </div>

        <div className="releasechip">
          <span className="releasechip__l">Pack</span>
          <span className="releasechip__t mono" title={session.path}>{session.ingested ? truncate(session.path, 22) : "not loaded"}</span>
          <span className="releasechip__dot" />
          <span className="releasechip__l">Mode</span>
          <select className="releasechip__sel" value={session.mode} onChange={e => setSession({ ...session, mode: e.target.value })}>
            {PD.MODES.modes.map(m => <option key={m.id} value={m.id}>{m.id}</option>)}
          </select>
        </div>
      </div>

      <div className="topbar__act">
        <ATag tone="warn">read-only</ATag>
        <button className="btn btn--ghost btn--sm">Export</button>
      </div>
    </header>
  );
}

function truncate(s, n) { return s.length <= n ? s : "…" + s.slice(-(n-1)); }

function Sidebar({ view, onNav, groups }) {
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
        <div className="leg"><span className="leg__d leg__d--ok" />present</div>
        <div className="leg"><span className="leg__d leg__d--warn" />awaiting / stale</div>
        <div className="leg"><span className="leg__d leg__d--err" />error / failed</div>
        <div className="sidebar__note">Read-only. Numbers come from on-disk artifacts; nothing is invented.</div>
      </div>
    </aside>
  );
}

function GlobalFilterStrip() {
  const f = useFilters();
  const { FilterChip, FilterBar } = window.UI;
  const chips = [];
  if (f.q !== "")        chips.push({ k: "q",        l: "search",     v: '"' + truncate(f.q, 20) + '"', onClear: () => f.setQ("") });
  if (f.category !== "any") chips.push({ k: "cat",   l: "category",   v: f.category, onClear: () => f.setCategory("any") });
  if (f.env !== "any")      chips.push({ k: "env",   l: "env",        v: f.env,      onClear: () => f.setEnv("any") });
  if (f.severity !== "any") chips.push({ k: "sev",   l: "severity",   v: f.severity, onClear: () => f.setSeverity("any") });
  if (f.status !== "any")   chips.push({ k: "stat",  l: "status",     v: f.status,   onClear: () => f.setStatus("any") });
  if (!f.hasAny) return null;
  return (
    <FilterBar hasFilters={f.hasAny} onClearAll={f.clear}>
      {chips.map(c => <FilterChip key={c.k} label={c.l} value={c.v} onClear={c.onClear} />)}
    </FilterBar>
  );
}

function HonestyBanner({ onClose }) {
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

// ─── Drawer host: routes by drawer.kind to the right detail panel ───────────

function DrawerHost({ pack }) {
  const d = useDrawer();
  if (!d) return null;
  return (
    <Drawer open={d.open} onClose={d.closeDrawer}
      kicker={d.kind === "claim" ? "Claim detail" : d.kind === "asset" ? "Asset detail" : d.kind === "artifact" ? "Artifact detail" : d.kind === "finding" ? "Finding detail" : ""}
      title={d.payload?.title || ""}
      subtitle={d.payload?.subtitle || ""}>
      {d.kind === "claim"    && <window.VIEWS_A.ClaimDetail id={d.payload?.id} pack={pack} />}
      {d.kind === "asset"    && <window.VIEWS_A.AssetDetail id={d.payload?.id} pack={pack} />}
      {d.kind === "artifact" && <window.VIEWS_A.ArtifactDetail file={d.payload?.file} pack={pack} />}
      {d.kind === "finding"  && <window.VIEWS_A.FindingDetail finding={d.payload} pack={pack} />}
    </Drawer>
  );
}

window.useDrawer = useDrawer;
window.useFilters = useFilters;

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
