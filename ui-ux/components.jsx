// components.jsx — UI primitives for the PQCP Assurance Console.
// Service-grade aesthetic — shadcn/Radix/Tremor lineage. Every metric carries
// an EvBind chip (source artifact + JSON path + validator + env).

const { useState, useMemo, useRef, useEffect, useLayoutEffect, createContext, useContext } = React;

// ─── Layout ────────────────────────────────────────────────────────────────

function Card({ children, title, subtitle, kicker, actions, span, footer, padded = true, className = "" }) {
  return (
    <section className={`card ${className}`} style={span ? { gridColumn: `span ${span}` } : null}>
      {(title || kicker || actions) && (
        <header className="card__hd">
          <div className="card__hd-l">
            {kicker && <div className="card__kicker">{kicker}</div>}
            {title && <h3 className="card__title">{title}</h3>}
            {subtitle && <p className="card__sub">{subtitle}</p>}
          </div>
          {actions && <div className="card__act">{actions}</div>}
        </header>
      )}
      <div className={`card__body ${padded ? "" : "card__body--flush"}`}>{children}</div>
      {footer && <footer className="card__ft">{footer}</footer>}
    </section>
  );
}

function KV({ k, v, mono, span = 1 }) {
  return (
    <div className="kv" style={span > 1 ? { gridColumn: `span ${span}` } : null}>
      <div className="kv__k">{k}</div>
      <div className={`kv__v ${mono ? "mono" : ""}`}>{v}</div>
    </div>
  );
}

function Pill({ tone = "neutral", children, dot = true, mono }) {
  return <span className={`pill pill--${tone} ${mono ? "mono" : ""}`}>{dot && <i className="pill__dot" />}{children}</span>;
}

function Tag({ tone = "neutral", children, mono, title }) {
  return <span className={`tag tag--${tone} ${mono ? "mono" : ""}`} title={title || undefined}>{children}</span>;
}

function Badge({ tone = "neutral", children, mono, size = "md" }) {
  return <span className={`badge badge--${tone} badge--${size} ${mono ? "mono" : ""}`}>{children}</span>;
}

function Hr() { return <div className="hr" />; }

function Sev({ level }) {
  return <span className={`sev sev--${level || "neutral"}`} aria-label={level} title={level}>●</span>;
}

// ─── Evidence binding (THE core primitive) ────────────────────────────────

function EvBind({ file, path, validator, env, hash, status, compact }) {
  const tone = status === "present" ? "ok" : status === "missing" ? "warn" : status === "stale" ? "warn" : status === "error" ? "err" : "neutral";
  const sym = status === "present" ? "●" : status === "missing" ? "○" : status === "stale" ? "◐" : status === "error" ? "✕" : "○";
  return (
    <span className={`evb evb--${tone} ${compact ? "evb--compact" : ""}`} title={`${file}${path ? "  →  " + path : ""}${validator ? "\nvalidator: " + validator : ""}${env ? "\nenv: " + env : ""}${hash ? "\nsha256: " + hash : ""}`}>
      <span className="evb__sym">{sym}</span>
      <span className="evb__file mono">{file}</span>
      {path && !compact && <span className="evb__path mono">{path}</span>}
    </span>
  );
}

function Await({ file, validator, what, supports }) {
  return (
    <div className="await">
      <div className="await__hd">
        <span className="await__icn">◌</span>
        <span className="await__t">Awaiting <span className="mono">{file}</span></span>
      </div>
      {what && <div className="await__d">{what}</div>}
      <div className="await__meta">
        {validator && <span className="await__row"><span className="await__k">validator</span><span className="mono">{validator}</span></span>}
        {supports && supports.length > 0 && (
          <span className="await__row">
            <span className="await__k">supports</span>
            <span className="await__claims">{supports.slice(0, 4).map(c => <span key={c} className="mono await__claim">{c}</span>)}{supports.length > 4 && <span className="mono dim">+{supports.length - 4}</span>}</span>
          </span>
        )}
      </div>
    </div>
  );
}

function EmptyState({ icon = "○", title, hint, action }) {
  return (
    <div className="empty">
      <div className="empty__icon">{icon}</div>
      <div className="empty__t">{title}</div>
      {hint && <div className="empty__d">{hint}</div>}
      {action && <div style={{ marginTop: 10 }}>{action}</div>}
    </div>
  );
}

// ─── KPI / Stat (Grafana stat panel) ──────────────────────────────────────

function Kpi({ label, value, unit, status = "neutral", trend, evbind, hint, sub }) {
  return (
    <div className={`kpi kpi--${status}`}>
      <div className="kpi__top">
        <span className="kpi__lbl">{label}</span>
        {hint && <span className="kpi__hint" title={hint}>ⓘ</span>}
      </div>
      <div className="kpi__val">
        <span className={`kpi__num ${value === "—" || value === "awaiting" ? "kpi__num--dim mono" : "mono"}`}>{value}</span>
        {unit && <span className="kpi__unit mono">{unit}</span>}
      </div>
      {sub && <div className="kpi__sub">{sub}</div>}
      {trend && <div className="kpi__trend">{trend}</div>}
      {evbind && <div className="kpi__ev">{evbind}</div>}
    </div>
  );
}

// ─── Threshold bar (Grafana threshold visualization) ──────────────────────
// bands: [{ to: 0.6, tone: 'ok' }, { to: 0.85, tone: 'warn' }, { to: 1, tone: 'err' }]

function ThresholdBar({ value, max = 1, bands, label, sub }) {
  const hasValue = value != null && !isNaN(value);
  const pct = hasValue ? Math.max(0, Math.min(1, value / max)) : 0;
  const segs = bands || [{ to: 0.6, tone: "err" }, { to: 0.85, tone: "warn" }, { to: 1, tone: "ok" }];
  let prev = 0;
  return (
    <div className="tbar">
      {label && <div className="tbar__lbl"><span>{label}</span>{hasValue && <span className="mono num">{(pct * 100).toFixed(0)}%</span>}</div>}
      <div className="tbar__track">
        {segs.map((s, i) => {
          const w = (s.to - prev) * 100;
          const o = prev * 100;
          prev = s.to;
          return <div key={i} className={`tbar__band tbar__band--${s.tone}`} style={{ left: `${o}%`, width: `${w}%` }} />;
        })}
        {hasValue && <div className="tbar__marker" style={{ left: `${pct * 100}%` }} />}
        {!hasValue && <div className="tbar__overlay">awaiting</div>}
      </div>
      {sub && <div className="tbar__sub mono">{sub}</div>}
    </div>
  );
}

// ─── Code block ───────────────────────────────────────────────────────────

function Code({ children, label, lang = "shell" }) {
  const [copied, setCopied] = useState(false);
  const txt = typeof children === "string" ? children : (Array.isArray(children) ? children.join("\n") : "");
  return (
    <div className="code">
      <div className="code__hd">
        <span className="code__lbl mono">{label || lang}</span>
        <button className="code__cp mono" onClick={() => { navigator.clipboard?.writeText(txt); setCopied(true); setTimeout(() => setCopied(false), 900); }}>
          {copied ? "copied" : "copy"}
        </button>
      </div>
      <pre className="code__pre">{children}</pre>
    </div>
  );
}

// ─── Tabs + Segmented Control + Toggle / Switch ───────────────────────────

function Tabs({ tabs, value, onChange }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map(t => (
        <button key={t.id} className={`tab ${value === t.id ? "tab--on" : ""}`} role="tab" aria-selected={value === t.id} onClick={() => onChange(t.id)}>
          {t.label}{t.count != null && <span className="tab__cnt mono">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

function Segmented({ options, value, onChange, size = "md" }) {
  return (
    <div className={`seg seg--${size}`} role="group">
      {options.map(o => {
        const id = typeof o === "string" ? o : o.id;
        const label = typeof o === "string" ? o : o.label;
        return (
          <button key={id} className={`seg__b ${value === id ? "seg__b--on" : ""}`} onClick={() => onChange(id)}>{label}</button>
        );
      })}
    </div>
  );
}

function Switch({ value, onChange, label }) {
  return (
    <label className="switch">
      <button className={`switch__b ${value ? "switch__b--on" : ""}`} onClick={() => onChange(!value)} aria-pressed={value}>
        <span className="switch__k" />
      </button>
      {label && <span className="switch__l">{label}</span>}
    </label>
  );
}

function Toggle({ value, onChange }) {
  return <button className={`tgl ${value ? "tgl--on" : ""}`} onClick={() => onChange(!value)}><span className="tgl__knob" /></button>;
}

// ─── Filter chips + bar (Untitled UI inspired) ────────────────────────────

function FilterChip({ label, value, onClear }) {
  return (
    <span className="fchip">
      <span className="fchip__l">{label}</span>
      <span className="fchip__v mono">{value}</span>
      {onClear && <button className="fchip__x" onClick={onClear} aria-label={`Clear ${label}`}>×</button>}
    </span>
  );
}

function FilterBar({ children, onClearAll, hasFilters }) {
  return (
    <div className="fbar">
      <div className="fbar__chips">{children}</div>
      {hasFilters && <button className="fbar__clear" onClick={onClearAll}>Clear all</button>}
    </div>
  );
}

// ─── Callout ──────────────────────────────────────────────────────────────

function Callout({ tone = "info", title, children }) {
  return (
    <div className={`callout callout--${tone}`}>
      <span className="callout__icn">{tone === "warn" ? "⚠" : tone === "err" ? "✕" : tone === "ok" ? "✓" : "ⓘ"}</span>
      <div className="callout__body">
        {title && <div className="callout__t">{title}</div>}
        <div className="callout__d">{children}</div>
      </div>
    </div>
  );
}

// ─── Drawer (Radix-style slide-in panel) ──────────────────────────────────

function Drawer({ open, onClose, title, subtitle, kicker, children, width = 560, actions }) {
  useEffect(() => {
    function onKey(e) { if (e.key === "Escape") onClose?.(); }
    if (open) { document.addEventListener("keydown", onKey); }
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  return (
    <>
      <div className={`scrim ${open ? "scrim--on" : ""}`} onClick={onClose} />
      <aside className={`drawer ${open ? "drawer--on" : ""}`} style={{ width }} aria-hidden={!open}>
        <header className="drawer__hd">
          <div>
            {kicker && <div className="drawer__kicker">{kicker}</div>}
            <h3 className="drawer__t">{title}</h3>
            {subtitle && <div className="drawer__s">{subtitle}</div>}
          </div>
          <button className="drawer__x" onClick={onClose} aria-label="Close">×</button>
        </header>
        <div className="drawer__body">{children}</div>
        {actions && <footer className="drawer__ft">{actions}</footer>}
      </aside>
    </>
  );
}

// ─── Pagination ───────────────────────────────────────────────────────────

function Pagination({ page, pages, onChange, total, pageSize }) {
  if (pages <= 1) return (
    <div className="pgn">
      <div className="pgn__t mono">{total} rows</div>
    </div>
  );
  const pgs = [];
  for (let i = 1; i <= pages; i++) pgs.push(i);
  const start = (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);
  return (
    <div className="pgn">
      <div className="pgn__t mono">{start}–{end} of {total}</div>
      <div className="pgn__btns">
        <button className="pgn__b" disabled={page === 1} onClick={() => onChange(page - 1)}>‹</button>
        {pgs.map(p => (
          <button key={p} className={`pgn__b ${p === page ? "pgn__b--on" : ""}`} onClick={() => onChange(p)}>{p}</button>
        ))}
        <button className="pgn__b" disabled={page === pages} onClick={() => onChange(page + 1)}>›</button>
      </div>
    </div>
  );
}

// Small helper for paginated data
function usePaged(items, pageSize = 12) {
  const [page, setPage] = useState(1);
  const pages = Math.max(1, Math.ceil(items.length / pageSize));
  useEffect(() => { if (page > pages) setPage(1); }, [pages, page]);
  const start = (page - 1) * pageSize;
  return {
    rows: items.slice(start, start + pageSize),
    page, pages, setPage, total: items.length, pageSize,
  };
}

// ─── Bar (used for *real* values only) ────────────────────────────────────

function Bar({ value, max = 1, tone = "accent" }) {
  const pct = Math.max(0, Math.min(1, value / max));
  return <div className="bar"><div className={`bar__fill bar__fill--${tone}`} style={{ width: `${pct * 100}%` }} /></div>;
}

// ─── Global filter context ────────────────────────────────────────────────

const FilterCtx = createContext(null);
function useFilters() { return useContext(FilterCtx); }

function FilterProvider({ children }) {
  const [q, setQ] = useState("");
  const [env, setEnv] = useState("any");           // qemu_x86_64 | native_sim | host_python | git | qemu_only | hw_validated | any
  const [severity, setSeverity] = useState("any"); // critical | high | warn | info | any
  const [category, setCategory] = useState("any"); // release | kat | benchmark | acvp | security | supply_chain | firmware | any
  const [status, setStatus] = useState("any");     // present | missing | stale | any
  function clear() { setQ(""); setEnv("any"); setSeverity("any"); setCategory("any"); setStatus("any"); }
  const hasAny = q !== "" || env !== "any" || severity !== "any" || category !== "any" || status !== "any";
  return <FilterCtx.Provider value={{ q, setQ, env, setEnv, severity, setSeverity, category, setCategory, status, setStatus, hasAny, clear }}>{children}</FilterCtx.Provider>;
}

// ─── ASCII-style spark for "awaiting" pattern (no fake numbers) ──────────

function SparkPlaceholder() {
  return (
    <svg viewBox="0 0 120 24" className="spark spark--placeholder" preserveAspectRatio="none">
      {[...Array(24)].map((_, i) => (
        <line key={i} x1={i * 5 + 2} y1="12" x2={i * 5 + 2} y2="14" stroke="currentColor" strokeWidth="1" />
      ))}
    </svg>
  );
}

window.UI = {
  Card, KV, Pill, Tag, Badge, Hr, Sev,
  EvBind, Await, EmptyState,
  Kpi, ThresholdBar, Bar, SparkPlaceholder,
  Code,
  Tabs, Segmented, Switch, Toggle,
  FilterChip, FilterBar,
  Callout,
  Drawer,
  Pagination, usePaged,
  FilterProvider, useFilters,
};
