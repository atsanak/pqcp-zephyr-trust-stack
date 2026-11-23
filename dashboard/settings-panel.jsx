// settings-panel.jsx
// Console preferences: a small floating panel plus form controls.
// Values persist per browser in localStorage under SETTINGS_KEY.

const SETTINGS_KEY = "pqcp.console.settings.v1";

const __SETTINGS_STYLE = `
  .set-fab{position:fixed;right:16px;bottom:16px;z-index:900;width:34px;height:34px;
    border-radius:50%;border:var(--hair) solid var(--line-2);background:var(--bg-3);
    color:var(--fg-1);font-size:16px;line-height:1;cursor:pointer;
    box-shadow:0 6px 20px rgba(0,0,0,.35)}
  .set-fab:hover{color:var(--fg-0);background:var(--bg-4)}
  .set-panel{position:fixed;right:16px;bottom:60px;z-index:900;width:280px;
    max-height:calc(100vh - 92px);display:flex;flex-direction:column;
    background:var(--bg-2);color:var(--fg-0);border:var(--hair) solid var(--line-2);
    border-radius:var(--radius-xl);box-shadow:0 12px 40px rgba(0,0,0,.45);
    font-size:11.5px;line-height:1.4;overflow:hidden}
  .set-hd{display:flex;align-items:center;justify-content:space-between;
    padding:10px 8px 10px 14px;border-bottom:var(--hair) solid var(--line)}
  .set-hd b{font-size:12px;font-weight:600}
  .set-x{border:0;background:transparent;color:var(--fg-2);width:22px;height:22px;
    border-radius:var(--radius);cursor:pointer;font-size:14px}
  .set-x:hover{background:var(--bg-4);color:var(--fg-0)}
  .set-body{padding:6px 14px 14px;display:flex;flex-direction:column;gap:10px;overflow-y:auto}
  .set-sect{font-size:10px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;
    color:var(--fg-2);padding-top:8px}
  .set-row{display:flex;flex-direction:column;gap:5px}
  .set-row--inline{flex-direction:row;align-items:center;justify-content:space-between}
  .set-lbl{display:flex;justify-content:space-between;color:var(--fg-1)}
  .set-val{color:var(--fg-2);font-variant-numeric:tabular-nums}
  .set-field{width:100%;height:26px;padding:0 8px;border:var(--hair) solid var(--line-2);
    border-radius:var(--radius);background:var(--bg-1);color:var(--fg-0);font:inherit}
  .set-range{width:100%;accent-color:var(--accent)}
  .set-seg{display:flex;gap:2px;padding:2px;border-radius:var(--radius);background:var(--bg-1)}
  .set-seg button{flex:1;border:0;border-radius:calc(var(--radius) - 2px);padding:4px 6px;
    background:transparent;color:var(--fg-1);font:inherit;cursor:pointer}
  .set-seg button[aria-pressed="true"]{background:var(--bg-4);color:var(--fg-0)}
  .set-switch{position:relative;width:32px;height:18px;border:0;border-radius:999px;
    background:var(--bg-5);cursor:pointer;padding:0}
  .set-switch[aria-checked="true"]{background:var(--accent)}
  .set-switch i{position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;
    background:#fff;transition:transform .15s}
  .set-switch[aria-checked="true"] i{transform:translateX(14px)}
  .set-swatches{display:flex;gap:6px}
  .set-swatch{flex:1;height:22px;border-radius:var(--radius);cursor:pointer;
    border:var(--hair) solid var(--line-2)}
  .set-swatch[aria-pressed="true"]{outline:2px solid var(--fg-0);outline-offset:1px}
`;

function __readSettings() {
  try {
    const raw = window.localStorage.getItem(SETTINGS_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch (_) {
    return {};
  }
}

function __writeSettings(values) {
  try {
    window.localStorage.setItem(SETTINGS_KEY, JSON.stringify(values));
  } catch (_) {
    /* storage unavailable (private mode); keep in-memory values only */
  }
}

// useSettings(defaults) -> [values, set]
// set accepts set("key", value) or set({ key: value, ... }).
function useSettings(defaults) {
  const [values, setValues] = React.useState(() => ({ ...defaults, ...__readSettings() }));
  const set = React.useCallback((keyOrEdits, val) => {
    const edits = typeof keyOrEdits === "object" && keyOrEdits !== null
      ? keyOrEdits : { [keyOrEdits]: val };
    setValues((prev) => {
      const next = { ...prev, ...edits };
      __writeSettings(next);
      return next;
    });
  }, []);
  return [values, set];
}

function SettingsPanel({ title = "Settings", children }) {
  const [open, setOpen] = React.useState(false);
  return (
    <>
      <style>{__SETTINGS_STYLE}</style>
      {open && (
        <div className="set-panel" role="dialog" aria-label={title}>
          <div className="set-hd">
            <b>{title}</b>
            <button className="set-x" aria-label="Close settings" onClick={() => setOpen(false)}>×</button>
          </div>
          <div className="set-body">{children}</div>
        </div>
      )}
      <button className="set-fab" aria-label="Settings" title="Settings" onClick={() => setOpen((o) => !o)}>⚙</button>
    </>
  );
}

function SettingSection({ label }) {
  return <div className="set-sect">{label}</div>;
}

function SettingRow({ label, value, inline = false, children }) {
  return (
    <div className={inline ? "set-row set-row--inline" : "set-row"}>
      <div className="set-lbl">
        <span>{label}</span>
        {value != null && <span className="set-val">{value}</span>}
      </div>
      {children}
    </div>
  );
}

function SettingSlider({ label, value, min = 0, max = 100, step = 1, unit = "", onChange }) {
  return (
    <SettingRow label={label} value={`${value}${unit}`}>
      <input className="set-range" type="range" min={min} max={max} step={step} value={value}
             onChange={(e) => onChange(Number(e.target.value))} />
    </SettingRow>
  );
}

function SettingToggle({ label, value, onChange }) {
  return (
    <SettingRow label={label} inline>
      <button className="set-switch" role="switch" aria-checked={!!value} onClick={() => onChange(!value)}><i /></button>
    </SettingRow>
  );
}

function SettingRadio({ label, value, options, onChange }) {
  return (
    <SettingRow label={label}>
      <div className="set-seg" role="group" aria-label={label}>
        {options.map((o) => (
          <button key={o} aria-pressed={o === value} onClick={() => onChange(o)}>{o}</button>
        ))}
      </div>
    </SettingRow>
  );
}

function SettingSelect({ label, value, options, onChange }) {
  return (
    <SettingRow label={label}>
      <select className="set-field" value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
    </SettingRow>
  );
}

function SettingColor({ label, value, options, onChange }) {
  return (
    <SettingRow label={label}>
      <div className="set-swatches" role="group" aria-label={label}>
        {options.map((c) => (
          <button key={c} className="set-swatch" style={{ background: c }} aria-label={c}
                  aria-pressed={String(c).toLowerCase() === String(value).toLowerCase()}
                  onClick={() => onChange(c)} />
        ))}
      </div>
    </SettingRow>
  );
}

Object.assign(window, {
  useSettings, SettingsPanel, SettingSection, SettingRow,
  SettingSlider, SettingToggle, SettingRadio, SettingSelect, SettingColor,
});
