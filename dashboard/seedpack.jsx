// seedpack.jsx, Seed-pack and release-directory loader.
//
// Two ingest modes:
//   (A) SEED PACK MODE, a single JSON file shaped as a `pqcp_dashboard_seed_pack`:
//       { schema_version, kind, generated_from, summary,
//         artifacts: { "<relpath>": { path, sha256, size, json?, text_preview? } }
//       }
//       NOTE: the on-disk format uses `artifacts` as a MAP keyed by path. We
//       also accept a legacy list form for forward-compatibility.
//
//   (B) RELEASE DIRECTORY MODE, `showDirectoryPicker()` against the release
//       output root. Returns the same internal shape so views stay
//       mode-agnostic.
//
// `EvidenceStore` (store.jsx) consumes whatever this loader returns.

const SEED_LS_KEY = "pqcp_seedpack_v2";

// ─── Pack shape + safe accessors ──────────────────────────────────────────

function emptyPack() {
  return {
    loaded: false,
    state: "empty",        // "empty" | "parsing" | "loaded" | "loaded_warnings" | "failed"
    kind: null,
    schema_version: null,
    generated_from: null,
    summary: null,
    artifacts: {},
    errors: [],
    warnings: [],
    source: null,          // { mode: "seedpack"|"directory", name, size? }
  };
}

const KIND_NAMES = new Set([
  "pqcp-dashboard-seed-pack",
  "pqcp_dashboard_seed_pack",
]);

// Normalize an incoming JSON blob into the internal pack shape.
function normalizePack(raw, source) {
  const errors = [];
  const warnings = [];
  if (!raw || typeof raw !== "object") {
    return { ...emptyPack(), state: "failed", errors: ["Seed pack must be a JSON object."], source: source || null };
  }
  if (raw.kind && !KIND_NAMES.has(raw.kind)) {
    warnings.push(`Unrecognized seed-pack kind "${raw.kind}", proceeding anyway.`);
  }

  // artifacts can be { path: entry } OR [{ path, ... }]
  const byPath = {};
  const rawArts = raw.artifacts;
  if (Array.isArray(rawArts)) {
    for (const a of rawArts) {
      if (!a || !a.path) { warnings.push("Artifact entry without `path`, skipped."); continue; }
      byPath[a.path] = a;
    }
  } else if (rawArts && typeof rawArts === "object") {
    for (const [path, a] of Object.entries(rawArts)) {
      if (!a) continue;
      byPath[path] = { path, ...a };
    }
  } else {
    errors.push("`artifacts` is missing or has an unexpected shape.");
  }

  // Quick consistency probes
  for (const [p, a] of Object.entries(byPath)) {
    if (p.endsWith(".json") && a && a.json === undefined && a.text_preview === undefined) {
      warnings.push(`${p}: no parsed JSON and no text_preview, value lookups will return undefined.`);
    }
  }

  const summary = raw.summary || null;
  if (summary && summary.artifact_count != null) {
    const have = Object.keys(byPath).length;
    if (have !== summary.artifact_count) {
      warnings.push(`Pack summary claims ${summary.artifact_count} artifacts but ${have} were parsed.`);
    }
  }

  return {
    loaded: errors.length === 0,
    state: errors.length ? "failed" : (warnings.length ? "loaded_warnings" : "loaded"),
    kind: raw.kind || null,
    schema_version: raw.schema_version || null,
    generated_from: raw.generated_from || null,
    summary,
    artifacts: byPath,
    errors,
    warnings,
    source: source || null,
  };
}

// pick(pack, "pqc_policy_result.json", "status") returns the value or undefined.
function pick(pack, file, key) {
  if (!pack || !pack.artifacts) return undefined;
  const art = pack.artifacts[file];
  if (!art) return undefined;
  if (!key) return art.json;
  if (art.json == null) return undefined;
  return deepGet(art.json, key);
}

function deepGet(obj, key) {
  if (obj == null) return undefined;
  const tokens = [];
  const re = /([^.\[\]]+)|\[(\d+)\]/g;
  let m;
  while ((m = re.exec(key)) !== null) {
    if (m[1] !== undefined) tokens.push(m[1]);
    else tokens.push(+m[2]);
  }
  let cur = obj;
  for (const t of tokens) {
    if (cur == null) return undefined;
    cur = cur[t];
  }
  return cur;
}

function present(pack, file) {
  return !!(pack && pack.artifacts && pack.artifacts[file]);
}

function statusFor(pack, file) {
  if (!pack || !pack.loaded) return "missing";
  return present(pack, file) ? "present" : "missing";
}

function findByPrefix(pack, prefix) {
  if (!pack || !pack.artifacts) return [];
  return Object.values(pack.artifacts).filter(a => a.path.startsWith(prefix));
}

function findByGlob(pack, glob) {
  if (!pack || !pack.artifacts) return [];
  const re = new RegExp("^" + glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*") + "$");
  return Object.values(pack.artifacts).filter(a => re.test(a.path));
}

function sha256For(pack, file) {
  const a = pack && pack.artifacts && pack.artifacts[file];
  return a?.sha256 || null;
}

function sizeFor(pack, file) {
  const a = pack && pack.artifacts && pack.artifacts[file];
  return a?.size ?? null;
}

// ─── Loading ─────────────────────────────────────────────────────────────

async function loadFromFile(file) {
  const text = await file.text();
  let raw;
  try { raw = JSON.parse(text); }
  catch (e) {
    return { ...emptyPack(), state: "failed", errors: [`Could not parse ${file.name}: ${e.message}`], source: { mode: "seedpack", name: file.name, size: file.size } };
  }
  return normalizePack(raw, { mode: "seedpack", name: file.name, size: file.size });
}

async function loadFromUrl(url, friendlyName) {
  try {
    const r = await fetch(url);
    if (!r.ok) return { ...emptyPack(), state: "failed", errors: [`HTTP ${r.status} fetching ${url}`] };
    const raw = await r.json();
    return normalizePack(raw, { mode: "seedpack", name: friendlyName || url });
  } catch (e) {
    return { ...emptyPack(), state: "failed", errors: [`Fetch failed: ${e.message}`] };
  }
}

// Directory mode, reads a known list of artifact filenames from a DirectoryHandle.
async function loadFromDirectory(dirHandle, expectedFiles) {
  const warnings = [];
  const artifacts = {};
  async function readFileFrom(handle, relPath) {
    try {
      let cur = handle;
      const parts = relPath.split("/");
      for (let i = 0; i < parts.length - 1; i++) cur = await cur.getDirectoryHandle(parts[i]);
      const fh = await cur.getFileHandle(parts[parts.length - 1]);
      const f = await fh.getFile();
      const text = await f.text();
      const size = f.size;
      const sha256 = await sha256Hex(text);
      let json = null;
      if (relPath.endsWith(".json")) {
        try { json = JSON.parse(text); } catch (e) { warnings.push(`${relPath}: invalid JSON`); }
      }
      artifacts[relPath] = {
        path: relPath, sha256, size, json,
        text_preview: relPath.endsWith(".json") ? null : text.slice(0, 4000),
      };
    } catch (e) { /* not present */ }
  }
  for (const f of expectedFiles) await readFileFrom(dirHandle, f);
  return normalizePack({
    schema_version: 1,
    kind: "pqcp_dashboard_seed_pack",
    generated_from: { mode: "directory", picked_at: new Date().toISOString() },
    summary: { artifact_count: Object.keys(artifacts).length, source: "directory" },
    artifacts,
  }, { mode: "directory", name: dirHandle?.name || "(directory)" });
}

async function sha256Hex(s) {
  const buf = new TextEncoder().encode(s);
  const hashBuf = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ─── Persistence ─────────────────────────────────────────────────────────

function persistPack(pack) {
  try {
    if (!pack || !pack.loaded) { localStorage.removeItem(SEED_LS_KEY); return; }
    const json = JSON.stringify({
      schema_version: pack.schema_version,
      kind: pack.kind,
      generated_from: pack.generated_from,
      summary: pack.summary,
      artifacts: Object.values(pack.artifacts),
      __source: pack.source,
    });
    if (json.length < 4_500_000) localStorage.setItem(SEED_LS_KEY, json);
  } catch (e) { /* ignore */ }
}

function restorePack() {
  try {
    const raw = localStorage.getItem(SEED_LS_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return normalizePack(parsed, parsed.__source || { mode: "seedpack", name: "(restored)" });
  } catch { return null; }
}

function clearPack() {
  try { localStorage.removeItem(SEED_LS_KEY); } catch {}
}

// ─── Misc helpers used outside the store ─────────────────────────────────

function shortSha(s, n = 10) {
  if (!s || typeof s !== "string") return null;
  return s.length <= n ? s : s.slice(0, n);
}

function humanSize(n) {
  if (n == null || isNaN(n)) return null;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

window.PACK = {
  emptyPack, normalizePack,
  loadFromFile, loadFromUrl, loadFromDirectory,
  persistPack, restorePack, clearPack,
  pick, present, statusFor, findByPrefix, findByGlob, deepGet,
  sha256For, sizeFor, shortSha, humanSize,
};
