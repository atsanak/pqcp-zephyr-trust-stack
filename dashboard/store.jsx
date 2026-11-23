// store.jsx — EvidenceStore: typed selectors over a loaded seed pack.
//
// Every visible value in the dashboard goes through one of these selectors so
// the rest of the app doesn't poke at raw JSON. Selectors return either a
// concrete object/value or null, never invented data. Each selector also
// returns an `evbind` envelope (file/path/sha256/validator/env) so the UI
// can render the source-of-truth chip next to every metric.

const PK = window.PACK;

// ─── Validator + environment registry ────────────────────────────────────
// Centralizes "this artifact was produced by this script, on this kind of
// environment" — surfaced in EvBind tooltips and detail drawers.

const VALIDATORS = {
  "assurance_ledger.json":                    { v: "scripts/generate_assurance_ledger.py", env: "host_python" },
  "assurance_ledger.md":                      { v: "scripts/generate_assurance_ledger.py", env: "host_python" },
  "assurance_report.html":                    { v: "scripts/render_assurance_report.py",   env: "host_python" },
  "pqc_cbom.cdx.json":                        { v: "scripts/export_pqc_cbom.py",           env: "host_python" },
  "pqc_policy_result.json":                   { v: "scripts/verify_assurance_policy.py",   env: "host_python" },
  "pqc_environment_result.json":              { v: "scripts/verify_pqc_environment.py",    env: "host_python" },
  "pqc_attestation.intoto.json":              { v: "scripts/generate_pqc_attestation.py",  env: "host_python" },
  "pqc_assurance_digest.json":                { v: "scripts/generate_pqc_attestation.py",  env: "host_python" },
  "pqc_asset_trace_result.json":              { v: "scripts/verify_pqc_asset_trace_map.py",env: "host_python" },
  "pqc_evidence_graph.json":                  { v: "scripts/generate_pqc_evidence_graph.py", env: "host_python" },
  "pqc_assurance_profile_result.json":        { v: "scripts/verify_pqc_assurance_profile.py", env: "host_python" },
  "pqc_evidence_quality_result.json":         { v: "scripts/verify_pqc_evidence_quality.py", env: "host_python" },
  "pqc_migration_readiness.json":             { v: "scripts/generate_migration_readiness_report.py", env: "host_python" },
  "ct_instruction_policy_result.json":        { v: "scripts/verify_ct_instruction_policy.py", env: "host_python" },
  "pqc_claim_closure_result.json":            { v: "scripts/verify_pqc_claim_closure.py",  env: "host_python" },
  "pqc_reference_values.json":                { v: "scripts/generate_pqc_reference_values.py", env: "host_python" },
  "firmware_assurance_status_result.json":    { v: "scripts/verify_firmware_assurance_status.py", env: "host_python" },
  "acvp_json_interop_result.json":            { v: "scripts/run_acvp_json_vectors.py",     env: "qemu_x86_64" },
  "pqc_build_provenance.slsa.json":           { v: "scripts/generate_pqc_build_provenance.py", env: "host_python" },
  "ct_sample_analysis_result.json":           { v: "scripts/analyze_ct_samples.py",        env: "host_python" },
  "backend_currency_result.json":             { v: "scripts/evaluate_backend_update.py",   env: "host_python" },
  "backend_update_evaluation.json":           { v: "scripts/evaluate_backend_update.py",   env: "host_python" },
  "benchmark_campaign_result.json":           { v: "scripts/run_benchmark_campaign.py",    env: "qemu_x86_64" },
  "benchmark_results.csv":                    { v: "scripts/release_check.py",             env: "qemu_x86_64" },
  "benchmark_provenance.json":                { v: "scripts/release_check.py",             env: "host_python" },
  "cost_of_assurance_evidence.json":          { v: "scripts/release_check.py",             env: "qemu_x86_64" },
  "device_evidence_token.json":               { v: "samples/pqcp_assurance_status",        env: "qemu_x86_64" },
  "device_evidence_token_result.json":        { v: "scripts/verify_device_evidence_token.py", env: "host_python" },
  "pqc_appraisal_result.json":                { v: "scripts/verify_pqc_appraisal_evidence.py", env: "host_python" },
  "release_check_results.xml":                { v: "scripts/release_check.py",             env: "host_python" },
  "transcripts/evidence_transcript_manifest.json": { v: "scripts/release_check.py",        env: "host_python" },
  "generated/pqcp_assurance_digest_generated.h":   { v: "scripts/export_firmware_assurance_digest.py", env: "host_python" },
};

function validatorFor(file) { return VALIDATORS[file]?.v || null; }
function envFor(file)       { return VALIDATORS[file]?.env || null; }

// Construct an EvBind envelope: { file, path, sha256, validator, env, status }
function evbind(pack, file, path) {
  return {
    file,
    path: path || null,
    sha256: PK.sha256For(pack, file),
    validator: validatorFor(file),
    env: envFor(file),
    status: PK.statusFor(pack, file),
  };
}

// ─── Core selectors ──────────────────────────────────────────────────────

function ledger(pack) {
  return PK.pick(pack, "assurance_ledger.json") || null;
}

function release(pack) {
  // Compose from assurance_ledger.json (canonical) with fallback to release-manifest.
  const lj = ledger(pack);
  const rm = releaseManifest(pack);
  return {
    tag:       lj?.tag       ?? rm?.tag       ?? null,
    version:   lj?.version   ?? rm?.version   ?? null,
    head_sha:  lj?.head_sha  ?? rm?.source_commit ?? null,
    tag_commit:                rm?.tag_commit ?? null,
    tag_points_to_head:        rm?.tag_points_to_head ?? null,
    dirty:     lj?.dirty     ?? rm?.working_tree_dirty ?? null,
    schema_version: lj?.schema_version ?? null,
    generated_at:   lj?.generated_at ?? rm?.release_date ?? null,
    project:        lj?.project ?? rm?.project ?? null,
    dependencies:   rm?.dependencies || null,
    evbind: evbind(pack, "assurance_ledger.json", "tag, head_sha, dirty, generated_at"),
  };
}

function ledgerSummary(pack) {
  const lj = ledger(pack);
  if (!lj) return null;
  const claims = lj.claims || [];
  const summary = lj.summary || {};
  const pass = summary.pass ?? claims.filter(c => c.status === "pass").length;
  const fail = summary.fail ?? claims.filter(c => c.status === "fail").length;
  const na   = summary.not_applicable ?? claims.filter(c => c.status === "not_applicable").length;
  return {
    total: claims.length,
    pass, fail, not_applicable: na,
    required: claims.filter(c => c.required).length,
    by_category: groupBy(claims, c => c.category),
    by_status: groupBy(claims, c => c.status),
    evbind: evbind(pack, "assurance_ledger.json", "claims[].status, summary"),
  };
}

function ledgerClaim(pack, claimId) {
  const lj = ledger(pack);
  if (!lj) return null;
  const claims = lj.claims || [];
  return claims.find(c => c && c.id === claimId) || null;
}

function ledgerClaims(pack) {
  return ledger(pack)?.claims || [];
}

function policyResult(pack) {
  const j = PK.pick(pack, "pqc_policy_result.json");
  if (!j) return null;
  return {
    passed: j.passed ?? null,
    failures: j.failures || [],
    checks: j.checks || [],
    schema_version: j.schema_version,
    generated_at: j.generated_at,
    policy: j.policy || null,
    by_check_type: groupBy(j.checks || [], c => c.check),
    evbind: evbind(pack, "pqc_policy_result.json", "passed, checks[], failures[]"),
  };
}

function cbomComponents(pack) {
  const list = PK.pick(pack, "pqc_cbom.cdx.json", "components") || [];
  return list.map(c => {
    const props = {};
    (c.properties || []).forEach(p => { props[p.name] = p.value; });
    const claimStatuses = {};
    Object.keys(props).forEach(k => {
      if (k.startsWith("pqcp:claim_status:")) claimStatuses[k.slice("pqcp:claim_status:".length)] = props[k];
    });
    return {
      name: c.name,
      bomRef: c["bom-ref"] || null,
      type: c.type || null,
      version: c.version || null,
      cryptoAssetType: c.cryptoProperties?.assetType || null,
      primitive: c.cryptoProperties?.algorithmProperties?.primitive || null,
      parameterSet: c.cryptoProperties?.algorithmProperties?.parameterSetIdentifier || null,
      // Derived from pqcp:* properties:
      productionAllowed:  props["pqcp:production_allowed"] === "true",
      productionStatus:   props["pqcp:production_status"] || null,
      lifecycleStatus:    props["pqcp:lifecycle_status"] || null,
      profileSupport:     (props["pqcp:profile_support"] || "").split(",").filter(Boolean),
      validationScope:    (props["pqcp:validation_scope"] || "").split(",").filter(Boolean),
      traceAssetId:       props["pqcp:trace_asset_id"] || null,
      standard:           props["pqcp:standard"] || null,
      usage:              props["pqcp:usage"] || null,
      claimIds:           (props["pqcp:claim_ids"] || "").split(",").filter(Boolean),
      claimStatuses,
      licenses:           (c.licenses || []).map(l => l.license?.id || l.license?.name).filter(Boolean),
      raw: c,
    };
  });
}

function cbomMeta(pack) {
  const j = PK.pick(pack, "pqc_cbom.cdx.json");
  if (!j) return null;
  return {
    bomFormat: j.bomFormat,
    specVersion: j.specVersion,
    serialNumber: j.serialNumber,
    version: j.version,
    metadata: j.metadata || null,
    component_count: (j.components || []).length,
    dependency_count: (j.dependencies || []).length,
    evbind: evbind(pack, "pqc_cbom.cdx.json", "components[], dependencies[]"),
  };
}

function benchmarkCampaign(pack) {
  const j = PK.pick(pack, "benchmark_campaign_result.json");
  if (!j) return null;
  const stats = Array.isArray(j.statistics) ? j.statistics
              : (j.statistics && typeof j.statistics === "object")
                ? Object.values(j.statistics) : [];
  return {
    passed: j.passed ?? null,
    generated_at: j.generated_at,
    schema_version: j.schema_version,
    rows: stats,
    config: j.config || null,
    comparison_context: j.comparison_context || null,
    external_reference: j.external_reference || null,
    backend_rankings: j.backend_rankings || [],
    pairwise_ratios: j.pairwise_ratios || [],
    checks: j.checks || [],
    failures: j.failures || [],
    summary: j.summary || null,
    evbind: evbind(pack, "benchmark_campaign_result.json", "statistics[]"),
  };
}

function ctSampleAnalysis(pack) {
  const j = PK.pick(pack, "ct_sample_analysis_result.json");
  if (!j) return null;
  return {
    passed: j.passed ?? null,
    algorithms: j.algorithms || [],
    sample_manifest: j.sample_manifest || null,
    checks: j.checks || [],
    failures: j.failures || [],
    sources: j.sources || [],
    summary: j.summary || null,
    generated_at: j.generated_at,
    evbind: evbind(pack, "ct_sample_analysis_result.json", "algorithms[], sample_manifest"),
  };
}

function backendCurrency(pack) {
  const j = PK.pick(pack, "backend_currency_result.json") || PK.pick(pack, "backend_update_evaluation.json");
  if (!j) return null;
  const file = PK.present(pack, "backend_currency_result.json") ? "backend_currency_result.json" : "backend_update_evaluation.json";
  return {
    passed: j.passed ?? null,
    backends: j.backends || [],
    warnings: j.warnings || [],
    failures: j.failures || [],
    summary: j.summary || null,
    west_manifest: j.west_manifest || null,
    check_upstream: j.check_upstream,
    generated_at: j.generated_at,
    evbind: evbind(pack, file, "backends[]"),
  };
}

function costOfAssurance(pack) {
  const j = PK.pick(pack, "cost_of_assurance_evidence.json");
  if (!j) return null;
  return {
    comparisons: j.comparisons || [],
    generated_at: j.generated_at,
    regression_file: j.regression_file,
    evbind: evbind(pack, "cost_of_assurance_evidence.json", "comparisons[]"),
  };
}

function transcriptManifest(pack) {
  const j = PK.pick(pack, "transcripts/evidence_transcript_manifest.json");
  if (!j) return null;
  return {
    transcripts: j.transcripts || [],
    qemu_stdout_transcripts: j.qemu_stdout_transcripts || [],
    required_steps: j.required_steps || [],
    generated_at: j.generated_at,
    evbind: evbind(pack, "transcripts/evidence_transcript_manifest.json", "qemu_stdout_transcripts[], transcripts[]"),
  };
}

function referenceValues(pack) {
  const j = PK.pick(pack, "pqc_reference_values.json");
  if (!j) return null;
  return {
    tag: j.tag, version: j.version, head_sha: j.head_sha,
    project: j.project, source_remote: j.source_remote,
    dirty: j.dirty, tag_commit: j.tag_commit, tag_points_to_head: j.tag_points_to_head,
    sdk_version: j.sdk_version, zephyr_revision: j.zephyr_revision,
    artifact_hashes: j.artifact_hashes || {},
    attestation_subject_count: j.attestation_subject_count,
    cbom_component_ids: j.cbom_component_ids || [],
    required_claim_ids: j.required_claim_ids || [],
    allowed_profile_ids: j.allowed_profile_ids || [],
    transcript_count: j.transcript_count,
    expected_firmware_digest_root: j.expected_firmware_digest_root,
    firmware_digest_artifact_count: j.firmware_digest_artifact_count,
    policy_passed: j.policy_passed,
    profile_passed: j.profile_passed,
    west_dependencies: j.west_dependencies || {},
    generated_at: j.generated_at,
    evbind: evbind(pack, "pqc_reference_values.json", "artifact_hashes, expected_firmware_digest_root"),
  };
}

function firmwareStatus(pack) {
  const j = PK.pick(pack, "firmware_assurance_status_result.json");
  if (!j) return null;
  return {
    passed: j.passed ?? null,
    status: j.status || null,
    artifacts: j.artifacts || [],
    checks: j.checks || [],
    failures: j.failures || [],
    source: j.source || null,
    generated_at: j.generated_at,
    evbind: evbind(pack, "firmware_assurance_status_result.json", "status, artifacts[], checks[]"),
  };
}

function deviceEvidenceToken(pack) {
  const j = PK.pick(pack, "device_evidence_token_result.json");
  if (!j) return null;
  return {
    passed: j.passed ?? null,
    checks: j.checks || [],
    failures: j.failures || [],
    token_path: j.token_path || null,
    generated_at: j.generated_at,
    evbind: evbind(pack, "device_evidence_token_result.json", "checks[]"),
  };
}

function evidenceGraph(pack) {
  const j = PK.pick(pack, "pqc_evidence_graph.json");
  if (!j) return null;
  return {
    tag: j.tag, version: j.version, head_sha: j.head_sha, dirty: j.dirty,
    nodes: j.nodes || [],
    edges: j.edges || [],
    summary: j.summary || null,
    generated_at: j.generated_at,
    evbind: evbind(pack, "pqc_evidence_graph.json", "nodes[], edges[]"),
  };
}

function migrationReadiness(pack) {
  const j = PK.pick(pack, "pqc_migration_readiness.json");
  if (!j) return null;
  return {
    passed: j.passed ?? null,
    assets: j.assets || [],
    profile_summary: j.profile_summary || {},
    evidence_quality_summary: j.evidence_quality_summary || {},
    blocked_conditions: j.blocked_conditions || [],
    summary: j.summary || null,
    generated_at: j.generated_at,
    evbind: evbind(pack, "pqc_migration_readiness.json", "assets[], profile_summary"),
  };
}

function assuranceProfile(pack) {
  const j = PK.pick(pack, "pqc_assurance_profile_result.json");
  if (!j) return null;
  return {
    passed: j.passed ?? null,
    profile: j.profile || null,
    checks: j.checks || [],
    failures: j.failures || [],
    summary: j.summary || null,
    generated_at: j.generated_at,
    evbind: evbind(pack, "pqc_assurance_profile_result.json", "checks[], profile"),
  };
}

function evidenceQuality(pack) {
  const j = PK.pick(pack, "pqc_evidence_quality_result.json");
  if (!j) return null;
  return {
    passed: j.passed ?? null,
    quality: j.quality || null,
    checks: j.checks || [],
    summary: j.summary || null,
    generated_at: j.generated_at,
    evbind: evbind(pack, "pqc_evidence_quality_result.json", "checks[]"),
  };
}

function appraisalResult(pack) {
  const j = PK.pick(pack, "pqc_appraisal_result.json");
  if (!j) return null;
  return {
    passed: j.passed ?? null,
    mode: j.mode || null,
    checks: j.checks || [],
    failures: j.failures || [],
    summary: j.summary || null,
    generated_at: j.generated_at,
    evbind: evbind(pack, "pqc_appraisal_result.json", "checks[], mode"),
  };
}

function claimClosure(pack) {
  const j = PK.pick(pack, "pqc_claim_closure_result.json");
  if (!j) return null;
  return {
    passed: j.passed ?? null,
    closed_claims: j.closed_claims || [],
    checks: j.checks || [],
    failures: j.failures || [],
    summary: j.summary || null,
    generated_at: j.generated_at,
    evbind: evbind(pack, "pqc_claim_closure_result.json", "closed_claims[], checks[]"),
  };
}

function environmentResult(pack) {
  const j = PK.pick(pack, "pqc_environment_result.json");
  if (!j) return null;
  return {
    passed: j.passed ?? null,
    checks: j.checks || [],
    failures: j.failures || [],
    west_dependencies: j.west_dependencies || {},
    workflow_environment: j.workflow_environment || {},
    summary: j.summary || null,
    generated_at: j.generated_at,
    evbind: evbind(pack, "pqc_environment_result.json", "checks[], west_dependencies"),
  };
}

function benchmarkProvenance(pack) {
  const j = PK.pick(pack, "benchmark_provenance.json");
  if (!j) return null;
  return {
    schema_version: j.schema_version,
    benchmark_metadata: j.benchmark_metadata || null,
    comparison_context: j.comparison_context || null,
    csv: j.csv || null,
    git: j.git || null,
    host: j.host || null,
    platform: j.platform || null,
    matrix: j.matrix || null,
    smoke: j.smoke || null,
    tooling: j.tooling || null,
    generator: j.generator || null,
    generated_at: j.generated_at,
    evbind: evbind(pack, "benchmark_provenance.json", "csv, host, platform"),
  };
}

function releaseManifest(pack) {
  // Either a glob hit (local_release_bundle/<tag>/release-manifest-<tag>.json)
  // or a flat release_manifest.json.
  const glob = PK.findByGlob(pack, "local_release_bundle/*/release-manifest-*.json");
  const j = glob[0]?.json || PK.pick(pack, "release_manifest.json") || PK.pick(pack, "release-manifest.json");
  if (!j) return null;
  const path = glob[0]?.path || "release_manifest.json";
  return {
    project: j.project || null,
    tag: j.tag, version: j.version,
    source_commit: j.source_commit, tag_commit: j.tag_commit,
    tag_points_to_head: j.tag_points_to_head,
    working_tree_dirty: j.working_tree_dirty,
    release_date: j.release_date,
    zephyr_revision: j.zephyr_revision,
    dependencies: j.dependencies || {},
    passport_artifacts: j.passport_artifacts || {},
    release_notes: j.release_notes || null,
    schema_version: j.schema_version,
    _path: path,
    evbind: { file: path, sha256: pack.artifacts[path]?.sha256, path: "passport_artifacts, dependencies", validator: "scripts/prepare_release_bundle.py", env: "host_python", status: "present" },
  };
}

// ─── Pack-level health ───────────────────────────────────────────────────

function packCompleteness(pack, requiredFiles) {
  const total = requiredFiles.length;
  const present = requiredFiles.filter(f => PK.present(pack, f)).length;
  return {
    total, present,
    missing: requiredFiles.filter(f => !PK.present(pack, f)),
    ratio: total === 0 ? 1 : present / total,
  };
}

// CBOM floor check (against P.POLICY.required_cbom_components)
function cbomFloorState(pack, floorComponents) {
  const comps = cbomComponents(pack);
  const have = new Set(comps.map(c => c.name));
  const missing = floorComponents.filter(c => !have.has(c));
  const det = comps.find(c => c.name === "Deterministic test RNG");
  return {
    present: comps.length,
    floor_total: floorComponents.length,
    floor_present: floorComponents.length - missing.length,
    missing,
    deterministic_rng_state: det ? (det.productionAllowed ? "production-allowed" : "test-only") : null,
  };
}

// Top blockers/warnings for the Control Room
function topBlockers(pack) {
  const blockers = [];
  const policy = policyResult(pack);
  if (policy && policy.passed === false) {
    (policy.failures || []).slice(0, 5).forEach((f, i) => blockers.push({ id: `policy-${i}`, severity: "high", title: `Policy failure: ${f.check || f.id || JSON.stringify(f).slice(0,40)}`, sub: f.reason || JSON.stringify(f), file: "pqc_policy_result.json" }));
  }
  const lc = ledgerSummary(pack);
  if (lc && lc.fail > 0) {
    ledgerClaims(pack).filter(c => c.status === "fail").slice(0, 5).forEach(c =>
      blockers.push({ id: `claim-${c.id}`, severity: "high", title: `Claim failed: ${c.id}`, sub: c.failure_reason || c.claim, file: "assurance_ledger.json" })
    );
  }
  const env = environmentResult(pack);
  if (env && env.passed === false) {
    (env.failures || []).slice(0, 3).forEach((f, i) => blockers.push({ id: `env-${i}`, severity: "warn", title: `Environment check failed: ${f.check || JSON.stringify(f).slice(0,40)}`, sub: JSON.stringify(f), file: "pqc_environment_result.json" }));
  }
  // Migration blocked conditions
  const mig = migrationReadiness(pack);
  if (mig && (mig.blocked_conditions || []).length) {
    mig.blocked_conditions.slice(0, 3).forEach((b, i) => blockers.push({ id: `mig-${i}`, severity: "warn", title: `Migration blocked: ${b.condition || b.id || ""}`, sub: b.reason || JSON.stringify(b), file: "pqc_migration_readiness.json" }));
  }
  return blockers;
}

// ─── Small util ──────────────────────────────────────────────────────────

function groupBy(arr, fn) {
  const out = {};
  (arr || []).forEach(x => {
    const k = fn(x);
    if (!out[k]) out[k] = 0;
    out[k]++;
  });
  return out;
}

window.STORE = {
  validatorFor, envFor, evbind,
  ledger, release, ledgerSummary, ledgerClaim, ledgerClaims,
  policyResult, cbomComponents, cbomMeta,
  benchmarkCampaign, ctSampleAnalysis,
  backendCurrency, costOfAssurance, transcriptManifest,
  referenceValues, firmwareStatus, deviceEvidenceToken,
  evidenceGraph, migrationReadiness, assuranceProfile, evidenceQuality,
  appraisalResult, claimClosure, environmentResult, benchmarkProvenance,
  releaseManifest,
  packCompleteness, cbomFloorState, topBlockers,
  groupBy,
};
