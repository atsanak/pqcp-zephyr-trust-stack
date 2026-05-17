// seedpack.jsx — Seed-pack and release-directory loader.
//
// The console reads release evidence two ways:
//
//   (A) SEED PACK MODE — a single JSON file with this shape:
//       {
//         schema_version: <int>,
//         kind: "pqcp-dashboard-seed-pack",
//         generated_from: <string|object>,
//         summary: { ... },
//         artifacts: [
//           { path, sha256, size, json?, text_preview?, ... },
//           ...
//         ]
//       }
//
//   (B) RELEASE DIRECTORY MODE — a folder (`showDirectoryPicker`) with the raw
//       artifact files on disk. Implemented as a TODO hook below.
//
// Every value the UI shows must flow through `pick(pack, path, key)` so that
// missing data renders as an explicit "Awaiting <path>" state instead of an
// invented number.

const SEED_LS_KEY = "pqcp_seedpack_v1";

// ─── Pack shape + safe accessors ──────────────────────────────────────────

// PackArtifact: { path, sha256, size, json?, text_preview?, ... }

function emptyPack() {
  return { loaded: false, kind: null, schema_version: null, generated_from: null, summary: null, artifacts: {}, errors: [] };
}

// Normalize an incoming JSON blob into the internal pack shape.
function normalizePack(raw) {
  const errors = [];
  if (!raw || typeof raw !== "object") {
    errors.push("Seed pack must be a JSON object.");
    return { ...emptyPack(), errors };
  }
  if (raw.kind && raw.kind !== "pqcp-dashboard-seed-pack") {
    errors.push(`Unrecognized seed pack kind: ${raw.kind}`);
  }
  const list = Array.isArray(raw.artifacts) ? raw.artifacts : [];
  const byPath = {};
  for (const a of list) {
    if (!a || !a.path) { errors.push("Artifact entry without `path` — skipped."); continue; }
    byPath[a.path] = a;
  }
  return {
    loaded: true,
    kind: raw.kind || null,
    schema_version: raw.schema_version || null,
    generated_from: raw.generated_from || null,
    summary: raw.summary || null,
    artifacts: byPath,
    errors,
  };
}

// pick(pack, "pqc_policy_result.json", "status") returns the value or undefined.
// Supports basic JSON-pointer-ish dotted paths and "a[0].b" array access.
function pick(pack, file, key) {
  if (!pack || !pack.artifacts) return undefined;
  const art = pack.artifacts[file];
  if (!art) return undefined;
  if (!key) return art.json;
  if (art.json === undefined || art.json === null) return undefined;
  return deepGet(art.json, key);
}

function deepGet(obj, key) {
  if (obj == null) return undefined;
  // Tokenize a.b[0].c → ['a','b',0,'c']
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

// Is this artifact present in the pack?
function present(pack, file) {
  return !!(pack && pack.artifacts && pack.artifacts[file]);
}

// Friendly status for the EvBind chip
function statusFor(pack, file) {
  if (!pack || !pack.loaded) return "missing";
  return present(pack, file) ? "present" : "missing";
}

// Find every artifact whose path matches a glob-ish prefix (e.g. "local_release_bundle/")
function findByPrefix(pack, prefix) {
  if (!pack || !pack.artifacts) return [];
  return Object.values(pack.artifacts).filter(a => a.path.startsWith(prefix));
}

// Find every artifact whose path matches a glob with a single * wildcard.
function findByGlob(pack, glob) {
  if (!pack || !pack.artifacts) return [];
  const re = new RegExp("^" + glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*") + "$");
  return Object.values(pack.artifacts).filter(a => re.test(a.path));
}

// ─── Loading ─────────────────────────────────────────────────────────────

async function loadFromFile(file) {
  const text = await file.text();
  let raw;
  try { raw = JSON.parse(text); }
  catch (e) {
    return { ...emptyPack(), errors: [`Could not parse JSON: ${e.message}`] };
  }
  return normalizePack(raw);
}

async function loadFromUrl(url) {
  try {
    const r = await fetch(url);
    if (!r.ok) return { ...emptyPack(), errors: [`HTTP ${r.status} fetching ${url}`] };
    const raw = await r.json();
    return normalizePack(raw);
  } catch (e) {
    return { ...emptyPack(), errors: [`Fetch failed: ${e.message}`] };
  }
}

// Hook for (B) — folder picker mode. Reads a known list of artifact filenames.
// Returns the same pack shape so the rest of the app is mode-agnostic.
async function loadFromDirectory(dirHandle, expectedFiles) {
  const errors = [];
  const artifacts = [];
  async function readFileFrom(handle, relPath) {
    try {
      let cur = handle;
      const parts = relPath.split("/");
      for (let i = 0; i < parts.length - 1; i++) {
        cur = await cur.getDirectoryHandle(parts[i]);
      }
      const fileHandle = await cur.getFileHandle(parts[parts.length - 1]);
      const f = await fileHandle.getFile();
      const text = await f.text();
      const size = f.size;
      const sha256 = await sha256Hex(text);
      let json = null;
      if (relPath.endsWith(".json")) {
        try { json = JSON.parse(text); } catch (e) { errors.push(`${relPath}: invalid JSON`); }
      }
      artifacts.push({
        path: relPath, sha256, size,
        json,
        text_preview: relPath.endsWith(".json") ? null : text.slice(0, 4000),
      });
    } catch (e) { /* not present */ }
  }
  for (const f of expectedFiles) await readFileFrom(dirHandle, f);
  return normalizePack({
    schema_version: 1,
    kind: "pqcp-dashboard-seed-pack",
    generated_from: { mode: "directory", picked_at: new Date().toISOString() },
    summary: null,
    artifacts,
  });
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
    // Cap size to avoid blowing the LS quota; the JSON payload is small in
    // practice for a release pack but be defensive.
    const json = JSON.stringify({ schema_version: pack.schema_version, kind: pack.kind, generated_from: pack.generated_from, summary: pack.summary, artifacts: Object.values(pack.artifacts) });
    if (json.length < 4_500_000) localStorage.setItem(SEED_LS_KEY, json);
  } catch (e) { /* ignore */ }
}

function restorePack() {
  try {
    const raw = localStorage.getItem(SEED_LS_KEY);
    if (!raw) return null;
    return normalizePack(JSON.parse(raw));
  } catch { return null; }
}

function clearPack() {
  try { localStorage.removeItem(SEED_LS_KEY); } catch {}
}

// ─── Derived helpers used across views ────────────────────────────────────

function ledgerClaim(pack, claimId) {
  const claims = pick(pack, "assurance_ledger.json", "claims");
  if (!Array.isArray(claims)) return null;
  return claims.find(c => c && c.id === claimId) || null;
}

function policyResult(pack) {
  return pick(pack, "pqc_policy_result.json") || null;
}

function cbomComponents(pack) {
  return pick(pack, "pqc_cbom.cdx.json", "components") || [];
}

function migrationReadiness(pack) {
  return pick(pack, "pqc_migration_readiness.json") || null;
}

function evidenceGraph(pack) {
  return pick(pack, "pqc_evidence_graph.json") || null;
}

function benchmarkCampaign(pack) {
  return pick(pack, "benchmark_campaign_result.json") || null;
}

function ctSampleAnalysis(pack) {
  return pick(pack, "ct_sample_analysis_result.json") || null;
}

function backendCurrency(pack) {
  return pick(pack, "backend_currency_result.json") || pick(pack, "backend_update_evaluation.json") || null;
}

function costOfAssurance(pack) {
  return pick(pack, "cost_of_assurance_evidence.json") || null;
}

function transcriptManifest(pack) {
  return pick(pack, "transcripts/evidence_transcript_manifest.json") || null;
}

function referenceValues(pack) {
  return pick(pack, "pqc_reference_values.json") || null;
}

function releaseManifest(pack) {
  // local_release_bundle/<tag>/release-manifest-<tag>.json — find any.
  const hits = findByGlob(pack, "local_release_bundle/*/release-manifest-*.json");
  return hits[0]?.json || null;
}

function ledgerRelease(pack) {
  // assurance_ledger.json may carry release metadata at the top level (release/release_metadata/tag/etc.)
  const l = pack && pack.artifacts && pack.artifacts["assurance_ledger.json"];
  const j = l && l.json;
  if (!j) return null;
  return {
    tag:        j.tag || j.release?.tag || j.release_metadata?.tag || null,
    commit:     j.commit || j.source_commit || j.release?.commit || j.release_metadata?.source_commit || null,
    dirty:      j.dirty ?? j.release?.dirty ?? j.release_metadata?.dirty ?? null,
    schema_version: j.schema_version ?? null,
    generated_at: j.generated_at || j.release?.generated_at || null,
  };
}

window.PACK = {
  emptyPack, normalizePack,
  loadFromFile, loadFromUrl, loadFromDirectory,
  persistPack, restorePack, clearPack,
  pick, present, statusFor, findByPrefix, findByGlob, deepGet,
  // Derived
  ledgerClaim, policyResult, cbomComponents, migrationReadiness,
  evidenceGraph, benchmarkCampaign, ctSampleAnalysis, backendCurrency,
  costOfAssurance, transcriptManifest, referenceValues, releaseManifest,
  ledgerRelease,
};
