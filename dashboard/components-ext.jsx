// components-ext.jsx — additional UI primitives layered on top of UI from
// components.jsx. Adds the source-traceability building blocks the v3 views
// rely on: HashChip, OriginChip, PackStateChip, DropZone, EvidenceList,
// DetailRow, StatGrid, ChecksList, RBar, BHX.

const { useState: eS, useRef: eR, useEffect: eE } = React;
const { Tag: EXTag } = window.UI;

// ── HashChip ──────────────────────────────────────────────────────────
function HashChip({ sha, full = false, label }) {
  if (!sha) return <span className="hash hash--dim">—</span>;
  const txt = full ? sha : sha.slice(0, 12);
  return (
    <span className={`hash ${full ? "hash--full" : ""}`} title={`${label ? label + " · " : ""}sha256:${sha}`}>
      {label && <span style={{ color: "var(--fg-3)", marginRight: 5 }}>{label}</span>}
      {txt}{!full && <span style={{ color: "var(--fg-3)" }}>…</span>}
    </span>
  );
}

// ── OriginChip (environment label) ────────────────────────────────────
function OriginChip({ env }) {
  if (!env) return null;
  return <span className={`origin origin--${env}`}>{env}</span>;
}

// ── PackStateChip (state of currently loaded pack) ────────────────────
function PackStateChip({ pack }) {
  if (!pack || !pack.loaded) return <span className="packstate packstate--empty">no pack</span>;
  const cls = pack.state === "failed" ? "packstate--failed"
            : pack.state === "loaded_warnings" ? "packstate--warnings"
            : "packstate--loaded";
  const label = pack.state === "failed" ? "ingest failed"
              : pack.state === "loaded_warnings" ? "loaded · warnings"
              : "loaded";
  return <span className={`packstate ${cls}`}>{label}</span>;
}

// ── EvBind2: 2-line variant with optional sha trailer ────────────────
function EvBind2({ ev, compact }) {
  if (!ev) return null;
  const tone = ev.status === "present" ? "ok"
             : ev.status === "missing" ? "warn"
             : ev.status === "error" ? "err" : "neutral";
  const sym = ev.status === "present" ? "●" : ev.status === "missing" ? "○" : "✕";
  const title =
    `${ev.file}` +
    (ev.path ? `\nkey: ${ev.path}` : "") +
    (ev.sha256 ? `\nsha256: ${ev.sha256}` : "") +
    (ev.validator ? `\nvalidator: ${ev.validator}` : "") +
    (ev.env ? `\nenv: ${ev.env}` : "");
  return (
    <span className={`evb evb--${tone} ${compact ? "evb--compact" : ""}`} title={title}>
      <span className="evb__sym">{sym}</span>
      <span className="evb__file">{ev.file}</span>
      {ev.path && !compact && <span className="evb__path">{ev.path}</span>}
    </span>
  );
}

// ── DetailRow (label/value) ───────────────────────────────────────────
function DetailRow({ k, v }) {
  return (
    <div className="detailrow">
      <div className="detailrow__k">{k}</div>
      <div className="detailrow__v">{v == null || v === "" ? <span className="dim">—</span> : v}</div>
    </div>
  );
}

// ── StatGrid + Stat ───────────────────────────────────────────────────
function StatGrid({ children }) { return <div className="statgrid">{children}</div>; }
function Stat({ k, v, s, dim }) {
  return (
    <div className="statgrid__cell">
      <div className="statgrid__k">{k}</div>
      <div className="statgrid__v" style={dim ? { color: "var(--fg-3)" } : null}>{v ?? "—"}</div>
      {s && <div className="statgrid__s">{s}</div>}
    </div>
  );
}

// ── EvidenceList: drawer-friendly artifact list with sha256s ─────────
function EvidenceList({ items }) {
  if (!items || !items.length) return <div className="dim mono">— no evidence artifacts attached</div>;
  return (
    <div className="evlist">
      {items.map((it, i) => (
        <div key={i} className={`evlist__row ${it.exists === false ? "evlist__row--missing" : ""}`}>
          <span className="evlist__dot" />
          <div className="evlist__col">
            <div className="evlist__l">{it.label || it.name || it.path}</div>
            {it.path && <div className="evlist__p">{it.path}</div>}
            {it.sha256 && <div className="evlist__h">sha256:{it.sha256}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}

// ── ChecksList: pass/fail rows for policy / closure / appraisal ──────
function ChecksList({ items, max = 200 }) {
  if (!items || !items.length) return <div className="dim mono">— no checks recorded</div>;
  const rows = items.slice(0, max);
  return (
    <div className="checks">
      {rows.map((c, i) => {
        const passed = c.passed !== false;
        return (
          <div key={i} className="checks__row">
            <span className={`sdot ${passed ? "sdot--pass" : "sdot--fail"}`} />
            <span className="checks__t">
              {c.check || c.name || "check"}
              {c.id ? <span className="checks__d">{c.id}</span> : null}
              {c.claim_id ? <span className="checks__d">{c.claim_id}</span> : null}
              {c.component ? <span className="checks__d">{c.component}</span> : null}
              {c.property ? <span className="checks__d">{c.property}</span> : null}
              {c.path ? <span className="checks__d">{c.path}</span> : null}
              {c.dependency ? <span className="checks__d">{c.dependency}</span> : null}
              {c.statistic ? <span className="checks__d">{c.statistic}</span> : null}
              {c.algorithm ? <span className="checks__d">{c.algorithm}</span> : null}
              {c.asset_id ? <span className="checks__d">{c.asset_id}</span> : null}
            </span>
            <EXTag tone={passed ? "ok" : "err"}>{passed ? "pass" : "fail"}</EXTag>
          </div>
        );
      })}
      {items.length > max && <div className="dim mono" style={{ fontSize: 10.5, padding: "4px 8px" }}>+{items.length - max} more</div>}
    </div>
  );
}

// ── RBar: ratio bar centered on 1.0 (regression visual for bench) ────
function RBar({ ratio, span = 0.6 }) {
  // span = max deviation from 1.0 we'll show; default 0.6 → [0.4 … 1.6]
  if (ratio == null || isNaN(ratio)) return <div className="rbar" />;
  const lo = 1 - span, hi = 1 + span;
  const clamped = Math.max(lo, Math.min(hi, ratio));
  const mid = 50;
  let left, width, regress;
  if (clamped <= 1) {
    width = ((1 - clamped) / span) * 50;
    left = 50 - width;
    regress = false;
  } else {
    width = ((clamped - 1) / span) * 50;
    left = 50;
    regress = true;
  }
  return (
    <div className="rbar" title={`ratio: ${ratio.toFixed(3)} (1.00 = no change)`}>
      <span className="rbar__mid" />
      <span className={`rbar__fill ${regress ? "rbar__fill--regress" : ""}`} style={{ left: `${left}%`, width: `${width}%` }} />
    </div>
  );
}

// ── DropZone: drag-drop file picker ───────────────────────────────────
function DropZone({ onFile, label, hint }) {
  const [over, setOver] = eS(false);
  const ref = eR(null);
  function pick(e) {
    const f = e.target.files?.[0];
    if (f) onFile(f);
    e.target.value = "";
  }
  function drop(e) {
    e.preventDefault();
    setOver(false);
    const f = e.dataTransfer.files?.[0];
    if (f) onFile(f);
  }
  return (
    <div className={`dropzone ${over ? "dropzone--over" : ""}`}
         onDragOver={e => { e.preventDefault(); setOver(true); }}
         onDragLeave={() => setOver(false)}
         onDrop={drop}
         onClick={() => ref.current?.click()}>
      <div className="dropzone__icn">↓</div>
      <div className="dropzone__t">{label || "Drop seed-pack JSON here"}</div>
      <div className="dropzone__s">{hint || "Or click to pick a file. The pack is parsed in-browser; no upload happens."}</div>
      <input ref={ref} className="fileinput" type="file" accept="application/json,.json" onChange={pick} />
      <div className="dropzone__hint mono">expected: pqcp_dashboard_seed_pack · schema_version ≥ 1</div>
    </div>
  );
}

// ── BHX: compact heatmap cell grid (bench surface) ───────────────────
function BHX({ children }) { return <div className="bhx">{children}</div>; }
function BHXCell({ label, value, sub, ratio }) {
  const ratioCls = ratio == null ? "bhx__ratio--neutral"
                 : ratio > 1.05 ? "bhx__ratio--regress"
                 : ratio < 0.95 ? "bhx__ratio"
                 : "bhx__ratio--neutral";
  return (
    <div className="bhx__cell">
      <div className="bhx__t">{label}</div>
      <div className="bhx__v">{value ?? "—"}</div>
      {sub && <div className={`bhx__r ${ratioCls}`}>{sub}</div>}
    </div>
  );
}

// ── Tabs inside drawers (smaller variant) ─────────────────────────────
function DTabs({ value, onChange, tabs }) {
  return (
    <div className="dtabs">
      {tabs.map(t => (
        <button key={t.id} className={`dtab ${value === t.id ? "dtab--on" : ""}`} onClick={() => onChange(t.id)}>{t.label}</button>
      ))}
    </div>
  );
}

window.UIX = {
  HashChip, OriginChip, PackStateChip, EvBind2,
  DetailRow, StatGrid, Stat,
  EvidenceList, ChecksList, RBar,
  DropZone, BHX, BHXCell, DTabs,
};
