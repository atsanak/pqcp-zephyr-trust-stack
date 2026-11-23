// data.jsx — Real repo facts (read from atsana01/pqcp-zephyr-trust-stack@main)
// EVERY value here is sourced from a checked-in file in the repository.
// Runtime values (benchmark numbers, ledger statuses, hashes) come from a
// release output pack and are intentionally absent — see ARTIFACTS for the
// awaiting-evidence shape.

// ─── Repository facts ──────────────────────────────────────────────
const REPO = {
  name: "pqcp-zephyr-trust-stack",
  owner: "atsana01",
  head_short: "74ec5053",
  license: "MIT",
  west_pins: [
    { name: "zephyr",        revision: "684c9e8f32e4373a21098559f748f06915f950c9", remote: "zephyrproject-rtos" },
    { name: "mlkem-native",  revision: "e07bff537f38b457601e524038f2395e235b011b", remote: "pqcp" },
    { name: "mldsa-native",  revision: "0f8b8e074b2525eb844b022b03b962bf888d51aa", remote: "pqcp" },
  ],
};

// Authoritative non-claims, copy-faithful from docs/pqc-assurance-passport.md
const NON_CLAIMS = [
  "Not FIPS 140-3 validated.",
  "Not a formal constant-time proof.",
  "Not hardware attestation. CT-smoke runs on QEMU and native_sim; physical-leakage evaluation is out of scope.",
  "The PQC assurance attestation is hash-bound, not identity-signed.",
  "The CBOM is CycloneDX-style and uses repo-specific pqcp:* properties where CycloneDX does not yet model embedded PQC links.",
  "Instruction-policy scan is a narrow regression check, not implementation review or physical leakage testing.",
];

// ─── Claim catalog (scripts/assurance_claims.json, schema v7, 54 claims) ──
const CLAIMS = [
  { id: "release.version_consistency", category: "release", required: true, claim: "version.h, CMakeLists.txt, CHANGELOG.md, and the optional release tag agree on the same semantic version." },
  { id: "release.tag_integrity", category: "release", required: true, claim: "When a release tag is supplied, the local annotated tag exists and peels to a concrete source commit." },
  { id: "kat.offline_provenance", category: "kat", required: true, claim: "Vendored NIST ACVP fixtures match the checked-in KAT header constants (aggregate over every parameter set)." },
  { id: "kat.mlkem_512",  category: "kat", required: true, claim: "ML-KEM-512 keygen and encaps NIST ACVP vectors match the checked-in KAT header constants." },
  { id: "kat.mlkem_768",  category: "kat", required: true, claim: "ML-KEM-768 keygen and encaps NIST ACVP vectors match the checked-in KAT header constants." },
  { id: "kat.mlkem_1024", category: "kat", required: true, claim: "ML-KEM-1024 keygen and encaps NIST ACVP vectors match the checked-in KAT header constants." },
  { id: "kat.mldsa_44",   category: "kat", required: true, claim: "ML-DSA-44 siggen and sigver NIST ACVP vectors match the checked-in KAT header constants." },
  { id: "kat.mldsa_65",   category: "kat", required: true, claim: "ML-DSA-65 siggen and sigver NIST ACVP vectors match the checked-in KAT header constants." },
  { id: "kat.mldsa_87",   category: "kat", required: true, claim: "ML-DSA-87 siggen and sigver NIST ACVP vectors match the checked-in KAT header constants." },
  { id: "benchmark.csv_validity", category: "benchmark", required: true, claim: "The benchmark CSV has the expected schema, required rows, positive numeric fields, and bounded PQCP/baseline timing ratios." },
  { id: "benchmark.provenance_binding", category: "benchmark", required: true, claim: "The benchmark_provenance.json sidecar cryptographically binds to the benchmark CSV bytes." },
  { id: "benchmark.mlkem_throughput", category: "benchmark", required: true, claim: "The benchmark CSV contains valid ML-KEM rows for every configured parameter set with positive cycles and time values." },
  { id: "benchmark.mldsa_throughput", category: "benchmark", required: true, claim: "The benchmark CSV contains valid ML-DSA rows for every configured parameter set with positive cycles and time values." },
  { id: "benchmark.distribution_quality", category: "benchmark", required: true, claim: "The benchmark export includes additive min, median, p90, p99, max, MAD, and sample-count rows for every supported ML-KEM and ML-DSA parameter set without changing the legacy metric contract." },
  { id: "cost_of_assurance.guardrails", category: "cost_of_assurance", required: true, claim: "Every configured cost-of-assurance guardrail metric was evaluated and passed." },
  { id: "release.local_bundle", category: "release", required: true, claim: "A local release bundle manifest exists and hashes the extracted release notes for the selected version." },
  { id: "release.transcript_binding", category: "release", required: true, claim: "Release evidence claims are bound to captured release-check stdout transcripts with recorded SHA-256 hashes." },
  { id: "acvp.negative_path_rejection", category: "acvp", required: true, claim: "The ACVP serial harness rejects malformed inputs with the documented ERROR:* responses, as exercised by ztest_acvp_serial and bound to acvp_negative_scenarios.json." },
  { id: "acvp.timeout_recovery", category: "acvp", required: true, claim: "The ACVP serial readline timeout fires under stalled-frame conditions, emits ERROR:TIMEOUT, and recovers cleanly for the next command." },
  { id: "acvp.negative_scenarios_replay", category: "acvp", required: true, claim: "Every replay-eligible case from acvp_negative_scenarios.json is exercised directly through pqcp_acvp_process_command() by tests/ztest_acvp_serial_negative." },
  { id: "acvp.mlkem_negative_paths", category: "acvp", required: true, claim: "ML-KEM-specific negative paths (INVALID_LEVEL, WRONG_SIZE, INVALID_HEX) are rejected with the documented ERROR:* responses." },
  { id: "acvp.mldsa_negative_paths", category: "acvp", required: true, claim: "ML-DSA-specific negative paths (WRONG_SIZE short SIGN, INVALID_HEX SIGN, WRONG_SIZE truncated VERIFY, INVALID_CMD too-many VERIFY fields) are rejected with the documented ERROR:* responses." },
  { id: "acvp.negative_scenario_floor", category: "acvp", required: true, claim: "acvp_negative_scenario_floor.json locks every compatibility-floor negative scenario so malformed ACVP cases cannot be removed, renamed, duplicated, or weakened." },
  { id: "security.asan_clean", category: "security", required: true, claim: "Every sanitizer-enabled native_sim ztest run captured by run_sanitizer_checks.py finished without an AddressSanitizer error report." },
  { id: "security.ubsan_clean", category: "security", required: true, claim: "Every sanitizer-enabled native_sim ztest run captured by run_sanitizer_checks.py finished without an UndefinedBehaviorSanitizer runtime error report." },
  { id: "boot.kat_self_verify", category: "boot", required: true, claim: "When CONFIG_PQCP_KAT_BOOT_VERIFY=y, the SYS_INIT hook runs deterministic keygen/encaps/decaps for every enabled ML-KEM level and keygen/sign/verify for every enabled ML-DSA level, and ztest main is reached without calling k_panic()." },
  { id: "security.ct_smoke", category: "security", required: true, claim: "ML-KEM-512/768/1024 decapsulation, each run 32 times against valid and 32 times against deliberately corrupted ciphertext, produces median cycle counts whose relative variance stays under a documented bound. Runtime smoke test, not a constant-time proof." },
  { id: "security.mlkem_decap_instruction_policy", category: "security", required: true, claim: "The built ML-KEM decapsulation code path is scanned for variable-latency division instructions associated with KyberSlash-class regressions. Static regression evidence, not a formal side-channel proof." },
  { id: "supply_chain.cbom_crypto_inventory", category: "supply_chain", required: true, claim: "The release pack includes a CycloneDX-style PQC CBOM that inventories supported ML-KEM, ML-DSA, RNG, validation, Zephyr, SDK, mlkem-native, and mldsa-native assets." },
  { id: "supply_chain.pqc_assurance_attestation", category: "supply_chain", required: true, claim: "The release pack includes an unsigned in-toto Statement-style PQC assurance attestation binding release evidence artifact hashes to the ledger metadata." },
  { id: "supply_chain.crypto_asset_traceability", category: "supply_chain", required: true, claim: "The release pack includes a verified PQC asset trace map linking cryptographic assets to source files, Kconfig symbols, assurance claims, ztests, transcript markers, and CBOM components." },
  { id: "supply_chain.evidence_graph_integrity", category: "supply_chain", required: true, claim: "The release pack includes a PQC evidence graph whose asset, claim, source, test, marker, and CBOM links resolve without missing graph edges." },
  { id: "release.policy_pass", category: "release", required: true, claim: "The partner-review PQC assurance policy evaluated the ledger, CBOM, attestation, and release metadata and passed without failures." },
  { id: "firmware.assurance_digest_manifest", category: "firmware", required: true, claim: "The release pack exposes a stable SHA-256 digest manifest over the ledger, CBOM, attestation, transcript manifest, benchmark provenance, and release manifest for future firmware attestation binding." },
  { id: "firmware.assurance_digest_embeddable", category: "firmware", required: true, claim: "The release pack exports the assurance digest into a generated C header and verifies that samples/pqcp_assurance_status can compile it into firmware." },
  { id: "supply_chain.assurance_profile_policy", category: "supply_chain", required: true, claim: "The release pack includes a verified assurance profile result that classifies supported, validation-only, lab-only, smoke-only, and test-only assets across local release profiles." },
  { id: "supply_chain.evidence_quality_index", category: "supply_chain", required: true, claim: "The release pack includes an evidence quality result that assigns each required assurance claim to a concrete validation class and environment." },
  { id: "crypto_agility.profile_separation", category: "crypto_agility", required: true, claim: "The assurance profile separates native-lab, QEMU release, constrained MCU, and gateway profiles so validation-only and test-only assets are not represented as production-enabled." },
  { id: "release.migration_readiness", category: "release", required: true, claim: "The release pack includes a migration-readiness report derived from the assurance profile, evidence quality result, and CBOM profile properties." },
  { id: "security.production_rng_policy", category: "security", required: true, claim: "The assurance profile and CBOM mark deterministic RNG as test-only and forbid it from production-oriented profiles." },
  { id: "release.reference_values", category: "release", required: true, claim: "The release pack includes replayable PQC reference values that bind release metadata, artifact hashes, required claims, CBOM component IDs, and the expected firmware assurance digest root." },
  { id: "firmware.assurance_status_report", category: "firmware", required: true, claim: "The assurance status firmware sample reports the expected digest, artifact count, and artifact hashes, and the transcript is verified against the release reference values." },
  { id: "acvp.json_interop", category: "acvp", required: true, claim: "NIST-style ACVP ML-KEM and ML-DSA JSON vector groups are translated into serial-command evidence with per-test transcript hashes and response classifications." },
  { id: "supply_chain.slsa_build_provenance", category: "supply_chain", required: true, claim: "The release pack includes a SLSA-shaped in-toto build provenance statement whose subjects, dependencies, external parameters, and byproducts replay-check against local artifacts." },
  { id: "security.ct_sample_analysis", category: "security", required: true, claim: "The constant-time smoke path can emit raw valid/invalid ML-KEM decapsulation timing samples, and local analysis checks sample counts, distribution deltas, and Welch-style statistics." },
  { id: "release.evidence_appraisal_profile", category: "release", required: true, schema_version_added: 7, claim: "The release pack includes a mode-specific evidence appraisal result that replay-checks post-Passport artifacts." },
  { id: "supply_chain.backend_update_evaluation", category: "supply_chain", required: true, schema_version_added: 7, claim: "The release pack records a comparison-only backend update evaluation for mlkem-native and mldsa-native, including pinned revisions, license metadata, META.yml metadata, and optional upstream drift information." },
  { id: "benchmark.campaign_reproducibility", category: "benchmark", required: true, schema_version_added: 7, claim: "The release pack includes benchmark-campaign evidence with reproducible statistics and validated comparison context derived from the generated benchmark CSV and provenance sidecar." },
  { id: "benchmark.external_reference_context", category: "benchmark", required: true, schema_version_added: 7, claim: "Imported external reference benchmark rows are normalized with source ecosystem, platform class, clock assumptions, statistic type, and environment metadata before comparison." },
  { id: "security.ct_campaign_analysis", category: "security", required: true, schema_version_added: 7, claim: "The release pack includes CT campaign evidence that replay-checks raw CT sample manifests for balanced valid/invalid counts and contiguous per-class sample indexes." },
  { id: "acvp.json_schema_coverage", category: "acvp", required: true, schema_version_added: 7, claim: "The ACVP JSON interop evidence covers keyGen, encap, decap, sigGen, sigVer, transcript hashing, and malformed-then-valid recovery cases." },
  { id: "firmware.device_evidence_token", category: "firmware", required: true, schema_version_added: 7, claim: "The assurance status firmware sample emits an additive device-evidence marker that binds a nonce, digest, artifact count, schema, and transcript-binding hint to the release reference values." },
  { id: "release.strict_partner_policy", category: "release", required: true, schema_version_added: 7, claim: "The partner-review appraisal policy rejects missing or silently not-applicable v7 evidence unless a less strict mode explicitly permits it." },
];

// ─── Evidence-quality mapping (scripts/pqc_evidence_quality.json) ─────────
const QUALITY = {
  classes: ["unit", "integration", "replay", "transcript_hash", "build_only", "qemu_smoke", "native_sim", "not_applicable_allowed"],
  byClaim: {
    "release.version_consistency": { class: "replay", env: "host_python", artifact: true },
    "release.tag_integrity":       { class: "replay", env: "git", artifact: false },
    "kat.offline_provenance":      { class: "replay", env: "host_python", artifact: true },
    "kat.mlkem_512":  { class: "unit", env: "qemu_x86_64", artifact: true },
    "kat.mlkem_768":  { class: "unit", env: "qemu_x86_64", artifact: true },
    "kat.mlkem_1024": { class: "unit", env: "qemu_x86_64", artifact: true },
    "kat.mldsa_44":   { class: "unit", env: "qemu_x86_64", artifact: true },
    "kat.mldsa_65":   { class: "unit", env: "qemu_x86_64", artifact: true },
    "kat.mldsa_87":   { class: "unit", env: "qemu_x86_64", artifact: true },
    "benchmark.csv_validity":         { class: "replay", env: "host_python", artifact: true },
    "benchmark.provenance_binding":   { class: "replay", env: "host_python", artifact: true },
    "benchmark.mlkem_throughput":     { class: "qemu_smoke", env: "qemu_x86_64", artifact: true },
    "benchmark.mldsa_throughput":     { class: "qemu_smoke", env: "qemu_x86_64", artifact: true },
    "benchmark.distribution_quality": { class: "qemu_smoke", env: "qemu_x86_64", artifact: true },
    "cost_of_assurance.guardrails":   { class: "qemu_smoke", env: "qemu_x86_64", artifact: true },
    "release.local_bundle":           { class: "replay", env: "host_python", artifact: true },
    "release.transcript_binding":     { class: "transcript_hash", env: "host_python", artifact: true },
    "acvp.negative_path_rejection":   { class: "integration", env: "qemu_x86_64", artifact: true },
    "acvp.timeout_recovery":          { class: "integration", env: "qemu_x86_64", artifact: true },
    "acvp.negative_scenarios_replay": { class: "integration", env: "qemu_x86_64", artifact: true },
    "acvp.mlkem_negative_paths":      { class: "integration", env: "qemu_x86_64", artifact: true },
    "acvp.mldsa_negative_paths":      { class: "integration", env: "qemu_x86_64", artifact: true },
    "acvp.negative_scenario_floor":   { class: "replay", env: "host_python", artifact: true },
    "security.asan_clean":  { class: "native_sim", env: "native_sim", artifact: true, allow_na: true },
    "security.ubsan_clean": { class: "native_sim", env: "native_sim", artifact: true, allow_na: true },
    "boot.kat_self_verify": { class: "integration", env: "qemu_x86_64", artifact: true },
    "security.ct_smoke":    { class: "qemu_smoke", env: "qemu_x86_64", artifact: true, smoke_only: true },
    "security.mlkem_decap_instruction_policy": { class: "build_only", env: "qemu_x86_64", artifact: true, smoke_only: true },
  },
};
// Auto-populate the rest as replay/host_python/NA-allowed (matches the JSON)
[
  "supply_chain.cbom_crypto_inventory","supply_chain.pqc_assurance_attestation",
  "supply_chain.crypto_asset_traceability","supply_chain.evidence_graph_integrity",
  "release.policy_pass","firmware.assurance_digest_manifest",
  "supply_chain.assurance_profile_policy","supply_chain.evidence_quality_index",
  "crypto_agility.profile_separation","release.migration_readiness",
  "security.production_rng_policy","release.reference_values","acvp.json_interop",
  "supply_chain.slsa_build_provenance","release.evidence_appraisal_profile",
  "supply_chain.backend_update_evaluation","benchmark.external_reference_context",
  "acvp.json_schema_coverage","release.strict_partner_policy",
].forEach(id => { QUALITY.byClaim[id] = { class: "replay", env: "host_python", artifact: true, allow_na: true }; });
QUALITY.byClaim["firmware.assurance_digest_embeddable"] = { class: "build_only", env: "qemu_x86_64", artifact: true, allow_na: true };
QUALITY.byClaim["firmware.assurance_status_report"]     = { class: "qemu_smoke", env: "qemu_x86_64", artifact: true, allow_na: true };
QUALITY.byClaim["security.ct_sample_analysis"]          = { class: "transcript_hash", env: "qemu_x86_64", artifact: true, allow_na: true };
QUALITY.byClaim["benchmark.campaign_reproducibility"]   = { class: "qemu_smoke", env: "host_python", artifact: true, allow_na: true };
QUALITY.byClaim["security.ct_campaign_analysis"]        = { class: "transcript_hash", env: "qemu_x86_64", artifact: true, allow_na: true };
QUALITY.byClaim["firmware.device_evidence_token"]       = { class: "transcript_hash", env: "qemu_x86_64", artifact: true, allow_na: true };

// ─── Profiles (scripts/pqc_assurance_profile.json) ────────────────────────
const PROFILES = [
  {
    id: "native_lab",
    description: "Local developer and partner-review profile that permits validation-only harnesses and deterministic test material.",
    environments: ["native_sim", "qemu_x86_64", "host_python"],
    required_claim_ids: ["release.version_consistency","kat.offline_provenance","acvp.negative_scenario_floor","supply_chain.crypto_asset_traceability","security.mlkem_decap_instruction_policy"],
    test_only: ["rng.deterministic_test"],
    forbidden: [],
  },
  {
    id: "qemu_release",
    description: "Replay-verifiable release profile backed by QEMU, native_sim, transcripts, Passport artifacts, and local bundle metadata.",
    environments: ["qemu_x86_64", "native_sim", "host_python"],
    required_claim_ids: ["release.version_consistency","release.transcript_binding","benchmark.csv_validity","benchmark.provenance_binding","benchmark.distribution_quality","cost_of_assurance.guardrails","supply_chain.cbom_crypto_inventory","supply_chain.pqc_assurance_attestation","supply_chain.crypto_asset_traceability","supply_chain.evidence_graph_integrity","firmware.assurance_digest_manifest","security.mlkem_decap_instruction_policy"],
    test_only: [],
    forbidden: ["rng.deterministic_test"],
  },
  {
    id: "mcu_minimal",
    description: "Build-only constrained MCU profile centered on the default ML-KEM-768 and ML-DSA-65 protocol suite.",
    environments: ["nucleo_h743zi_build_only", "host_python"],
    required_claim_ids: ["benchmark.csv_validity","benchmark.distribution_quality","cost_of_assurance.guardrails","firmware.assurance_digest_embeddable"],
    test_only: [],
    forbidden: ["rng.deterministic_test","validation.acvp_serial","validation.tls_selftest","security.ct_smoke"],
  },
  {
    id: "gateway",
    description: "Higher-capacity embedded profile that permits all supported ML-KEM and ML-DSA parameter sets with production RNG backends.",
    environments: ["qemu_x86_64", "nucleo_h743zi_build_only", "host_python"],
    required_claim_ids: ["kat.mlkem_512","kat.mlkem_768","kat.mlkem_1024","kat.mldsa_44","kat.mldsa_65","kat.mldsa_87","benchmark.mlkem_throughput","benchmark.mldsa_throughput","benchmark.distribution_quality","supply_chain.cbom_crypto_inventory","supply_chain.crypto_asset_traceability","security.mlkem_decap_instruction_policy"],
    test_only: [],
    forbidden: ["rng.deterministic_test","validation.acvp_serial","validation.tls_selftest","security.ct_smoke"],
  },
];

// ─── Appraisal modes (scripts/pqc_appraisal_policy.json) ──────────────────
const MODES = {
  default: "partner_review",
  modes: [
    { id: "ci_fast",        label: "CI fast",        description: "Fast deterministic CI gate; full Passport appraisal is optional.", strict: false },
    { id: "local_release",  label: "Local release",  description: "Full local release gate with generated Passport evidence.",         strict: false },
    { id: "partner_review", label: "Partner review", description: "Partner-review mode requires every v7 appraisal artifact to pass.", strict: true },
    { id: "hardware_review",label: "Hardware review",description: "Partner-review plus optional physical-hardware benchmark evidence.",strict: true, hardware: true },
  ],
};

// ─── Required artifacts (scripts/pqc_assurance_policy.json) ───────────────
const POLICY = {
  required_cbom_components: ["ML-KEM-768","ML-KEM-1024","ML-DSA-65","ML-DSA-87","Zephyr RTOS","Zephyr SDK","mlkem-native","mldsa-native"],
  forbidden_production_rng_components: ["Deterministic test RNG"],
  required_attestation_subjects: [
    "assurance_ledger.json","assurance_ledger.md","assurance_report.html","pqc_cbom.cdx.json",
    "benchmark_results.csv","benchmark_provenance.json","cost_of_assurance_evidence.json",
    "ct_instruction_policy_result.json","transcripts/evidence_transcript_manifest.json",
    "release-manifest.json","west.yml","CMakeLists.txt","pqc_evidence_graph.json",
    "pqc_assurance_profile_result.json","pqc_evidence_quality_result.json",
    "pqc_migration_readiness.json","pqc_migration_readiness.md",
  ],
  passport_v2: ["acvp_negative_scenario_floor_result.json","ct_instruction_policy_result.json","pqc_asset_trace_result.json","pqc_evidence_graph.json","pqc_evidence_graph.md","pqc_assurance_digest.json","generated/pqcp_assurance_digest_generated.h"],
  passport_v3: ["pqc_assurance_profile_result.json","pqc_evidence_quality_result.json","pqc_migration_readiness.json","pqc_migration_readiness.md"],
  passport_v4: ["pqc_reference_values.json","pqc_reference_values_result.json","firmware_assurance_status_result.json","acvp_json_interop_result.json","acvp_json_transcript_manifest.json","pqc_build_provenance.slsa.json","pqc_build_provenance_result.json","ct_sample_analysis_result.json"],
};

// ─── Asset trace map (scripts/pqc_asset_trace_map.json) — 13 assets ───────
const ASSETS = [
  { id:"crypto.mlkem_512",  name:"ML-KEM-512",  category:"kem",        cbom:"ML-KEM-512",  kconfig:["PQCP_MLKEM","PQCP_MLKEM_LEVEL_512"],  claims:["kat.mlkem_512","benchmark.mlkem_throughput","benchmark.distribution_quality","security.mlkem_decap_instruction_policy"], sources:["include/pqcp_zephyr/mlkem.h","src/mlkem_zephyr.c","src/mlkem_baseline.c","tests/ztest_acvp_kat/src/kat_vectors.h","tests/ztest_ct_smoke/src/main.c"], ztests:["tests/ztest_acvp_kat","tests/ztest_primitive","tests/ztest_ct_smoke"], markers:["PASS - test_mlkem_512_keygen_vectors","PASS - test_mlkem_512_encaps_vectors","PQCP_CT_SMOKE alg=MLKEM-512","PQCP_CT_TTEST alg=MLKEM-512"] },
  { id:"crypto.mlkem_768",  name:"ML-KEM-768",  category:"kem",        cbom:"ML-KEM-768",  kconfig:["PQCP_MLKEM","PQCP_MLKEM_LEVEL_768","PQCP_PSA_DRIVER_MLKEM"], claims:["kat.mlkem_768","benchmark.mlkem_throughput","security.ct_smoke","benchmark.distribution_quality","security.mlkem_decap_instruction_policy"], sources:["include/pqcp_zephyr/mlkem.h","src/mlkem_zephyr.c","src/mlkem_baseline.c","src/psa_mlkem_driver.c","tests/ztest_acvp_kat/src/kat_vectors.h","tests/ztest_ct_smoke/src/main.c","tests/ztest_primitive/src/main.c"], ztests:["tests/ztest_acvp_kat","tests/ztest_ct_smoke","tests/ztest_primitive"], markers:["PASS - test_mlkem_768_keygen_vectors","PASS - test_mlkem_768_encaps_vectors","PQCP_CT_SMOKE alg=MLKEM-768","PQCP_CT_TTEST alg=MLKEM-768"] },
  { id:"crypto.mlkem_1024", name:"ML-KEM-1024", category:"kem",        cbom:"ML-KEM-1024", kconfig:["PQCP_MLKEM","PQCP_MLKEM_LEVEL_1024"], claims:["kat.mlkem_1024","benchmark.mlkem_throughput","benchmark.distribution_quality","security.mlkem_decap_instruction_policy"], sources:["include/pqcp_zephyr/mlkem.h","src/mlkem_zephyr.c","src/mlkem_baseline.c","tests/ztest_acvp_kat/src/kat_vectors.h","tests/ztest_ct_smoke/src/main.c"], ztests:["tests/ztest_acvp_kat","tests/ztest_primitive","tests/ztest_ct_smoke"], markers:["PASS - test_mlkem_1024_keygen_vectors","PASS - test_mlkem_1024_encaps_vectors","PQCP_CT_SMOKE alg=MLKEM-1024","PQCP_CT_TTEST alg=MLKEM-1024"] },
  { id:"crypto.mldsa_44",   name:"ML-DSA-44",   category:"signature",  cbom:"ML-DSA-44",   kconfig:["PQCP_MLDSA","PQCP_MLDSA_LEVEL_44"],  claims:["kat.mldsa_44","benchmark.mldsa_throughput","benchmark.distribution_quality"], sources:["include/pqcp_zephyr/mldsa.h","src/mldsa_zephyr.c","src/mldsa_baseline.c","src/mldsa_streaming.c","tests/ztest_acvp_kat/src/kat_vectors.h"], ztests:["tests/ztest_acvp_kat","tests/ztest_primitive"], markers:["PASS - test_mldsa_44_siggen_vectors","PASS - test_mldsa_44_sigver_vectors"] },
  { id:"crypto.mldsa_65",   name:"ML-DSA-65",   category:"signature",  cbom:"ML-DSA-65",   kconfig:["PQCP_MLDSA","PQCP_MLDSA_LEVEL_65","PQCP_PSA_DRIVER_MLDSA"], claims:["kat.mldsa_65","benchmark.mldsa_throughput","benchmark.distribution_quality"], sources:["include/pqcp_zephyr/mldsa.h","src/mldsa_zephyr.c","src/psa_mldsa_driver.c"], ztests:["tests/ztest_acvp_kat","tests/ztest_primitive"], markers:["PASS - test_mldsa_65_siggen_vectors","PASS - test_mldsa_65_sigver_vectors"] },
  { id:"crypto.mldsa_87",   name:"ML-DSA-87",   category:"signature",  cbom:"ML-DSA-87",   kconfig:["PQCP_MLDSA","PQCP_MLDSA_LEVEL_87"], claims:["kat.mldsa_87","benchmark.mldsa_throughput","benchmark.distribution_quality"], sources:["include/pqcp_zephyr/mldsa.h","src/mldsa_zephyr.c","src/mldsa_baseline.c","tests/ztest_acvp_kat/src/kat_vectors.h"], ztests:["tests/ztest_acvp_kat","tests/ztest_primitive"], markers:["PASS - test_mldsa_87_siggen_vectors","PASS - test_mldsa_87_sigver_vectors"] },
  { id:"validation.acvp_serial",  name:"ACVP serial validation harness", category:"validation", cbom:"ACVP serial validation harness", kconfig:["PQCP_ACVP","PQCP_ACVP_READLINE_TIMEOUT_MS","PQCP_KAT_SMOKE_ONLY"], claims:["acvp.negative_path_rejection","acvp.timeout_recovery","acvp.negative_scenarios_replay","acvp.mlkem_negative_paths","acvp.mldsa_negative_paths"], sources:["include/pqcp_zephyr/acvp_cmd.h","src/acvp_cmd.c","samples/pqcp_serial_acvp/src/main.c","scripts/acvp_negative_scenarios.json","scripts/acvp_negative_scenario_floor.json"], ztests:["tests/ztest_acvp_serial","tests/ztest_acvp_serial_negative"], markers:["PASS - test_readline_timeout","PQCP_ACVP_NEG case=INVALID_MLKEM_ENCAPS_HEX","PQCP_ACVP_NEG case=POST_TIMEOUT_HELP_RECOVERY"] },
  { id:"validation.tls_selftest", name:"TLS/PSA PQC self-test path",     category:"validation", cbom:"TLS/PSA PQC self-test path",     kconfig:["PQCP_TLS_SELFTEST","PQCP_PSA_DRIVER","PQCP_PSA_DRIVER_MLKEM","PQCP_PSA_DRIVER_MLDSA"], claims:["security.asan_clean","security.ubsan_clean"], sources:["include/pqcp_zephyr/tls_selftest.h","src/tls_selftest.c","samples/pqcp_tls_mbedtls_psa/src/main.c"], ztests:["tests/ztest_tls_selftest"], markers:["TESTSUITE pqcp_tls_selftest succeeded","PQCP_METRIC,protocol,handshake,TLS13,0,status,PASS,"] },
  { id:"rng.zephyr_entropy", name:"Zephyr entropy RNG", category:"rng", cbom:"Zephyr entropy RNG", kconfig:["PQCP_RNG_ZEPHYR_ENTROPY"], claims:[], sources:["include/pqcp_zephyr/rng.h","src/rng_common.c","src/rng_zephyr_entropy.c"], ztests:["tests/ztest_rng"], markers:["TESTSUITE pqcp_rng succeeded"] },
  { id:"rng.psa",            name:"PSA RNG",            category:"rng", cbom:"PSA RNG",            kconfig:["PQCP_RNG_PSA"],            claims:[], sources:["include/pqcp_zephyr/rng.h","src/rng_common.c","src/rng_psa.c"], ztests:["tests/ztest_rng"], markers:["TESTSUITE pqcp_rng succeeded"] },
  { id:"rng.deterministic_test", name:"Deterministic test RNG", category:"rng", cbom:"Deterministic test RNG", kconfig:["PQCP_RNG_CUSTOM","PQCP_RNG_DETERMINISTIC_TEST"], claims:["kat.offline_provenance"], sources:["include/pqcp_zephyr/rng.h","src/rng_common.c","src/rng_deterministic.c","samples/pqcp_kat_deterministic/src/main.c"], ztests:["tests/ztest_primitive"], markers:["CONFIG_PQCP_RNG_DETERMINISTIC_TEST","KAT deterministic demo"], test_only: true },
  { id:"boot.kat_self_verify", name:"KAT boot self-verify hook", category:"boot", cbom:null, kconfig:["PQCP_KAT_BOOT_VERIFY","PQCP_RNG_DETERMINISTIC_TEST"], claims:["boot.kat_self_verify"], sources:["src/kat_boot_verify.c","tests/ztest_kat_boot_verify/src/main.c"], ztests:["tests/ztest_kat_boot_verify"], markers:["PQCP_KAT_BOOT_VERIFY: starting power-on self-test","PQCP_KAT_BOOT_VERIFY: all enabled primitives passed"] },
  { id:"security.ct_smoke",  name:"Constant-time smoke test", category:"security", cbom:null, kconfig:["PQCP_MLKEM_LEVEL_512","PQCP_MLKEM_LEVEL_768","PQCP_MLKEM_LEVEL_1024"], claims:["security.ct_smoke","security.mlkem_decap_instruction_policy"], sources:["tests/ztest_ct_smoke/src/main.c","scripts/verify_ct_instruction_policy.py"], ztests:["tests/ztest_ct_smoke"], markers:["PQCP_CT_SMOKE alg=MLKEM-512","PQCP_CT_SMOKE alg=MLKEM-768","PQCP_CT_SMOKE alg=MLKEM-1024","PQCP_CT_TTEST alg=MLKEM-512","PQCP_CT_TTEST alg=MLKEM-768","PQCP_CT_TTEST alg=MLKEM-1024"] },
];

// ACVP error vocabulary (docs/api-overview.md)
const ACVP_ERRORS = ["ERROR:INVALID_CMD","ERROR:INVALID_HEX","ERROR:INVALID_LEVEL","ERROR:WRONG_SIZE","ERROR:MISSING_ARGS","ERROR:TIMEOUT"];

// Benchmark campaign config (scripts/pqc_benchmark_campaign.json)
const CAMPAIGN = {
  name: "qemu-local benchmark campaign",
  warmup_runs: 1,
  repetitions: 5,
  required_statistics: ["min","median","p90","p99","mad"],
  required_context_fields: ["source_dataset","source_ecosystem","board_class","statistic_type","environment_type"],
  default_environment_type: "qemu",
};

// ─── Release artifact registry — populated when a release pack is ingested ──
// Every artifact lists its canonical filename, the validator that produces it,
// the claim ids it supports, JSON path keys we'd read from it, and a typical
// representative metric for the UI.
const ARTIFACTS = [
  { file: "assurance_ledger.json",                  validator: "scripts/generate_assurance_ledger.py", jsonPaths: ["claims[].id", "claims[].status", "claims[].evidence[]", "schema_version", "release.tag", "release.commit", "release.dirty"], supportsClaims: ["release.*","kat.*","benchmark.*","acvp.*","security.*","boot.*"] },
  { file: "assurance_ledger.md",                    validator: "scripts/generate_assurance_ledger.py" },
  { file: "assurance_report.html",                  validator: "scripts/render_assurance_report.py" },
  { file: "pqc_cbom.cdx.json",                      validator: "scripts/export_pqc_cbom.py", jsonPaths: ["components[].name","components[].properties[]","metadata.component","serialNumber"], supportsClaims: ["supply_chain.cbom_crypto_inventory"] },
  { file: "pqc_policy_result.json",                 validator: "scripts/verify_assurance_policy.py", jsonPaths: ["status","failures[]","required_claim_results[]"], supportsClaims: ["release.policy_pass"] },
  { file: "pqc_environment_result.json",            validator: "scripts/verify_pqc_environment.py" },
  { file: "pqc_attestation.intoto.json",            validator: "scripts/generate_pqc_attestation.py", jsonPaths: ["subject[].name","subject[].digest.sha256","predicateType"], supportsClaims: ["supply_chain.pqc_assurance_attestation"] },
  { file: "pqc_assurance_digest.json",              validator: "scripts/generate_pqc_attestation.py", jsonPaths: ["digest_root","artifacts[].name","artifacts[].sha256"], supportsClaims: ["firmware.assurance_digest_manifest"] },
  { file: "pqc_asset_trace_result.json",            validator: "scripts/verify_pqc_asset_trace_map.py", supportsClaims: ["supply_chain.crypto_asset_traceability"] },
  { file: "pqc_evidence_graph.json",                validator: "scripts/generate_pqc_evidence_graph.py", jsonPaths: ["nodes[].id","nodes[].kind","edges[].from","edges[].to"], supportsClaims: ["supply_chain.evidence_graph_integrity"] },
  { file: "pqc_evidence_graph.md",                  validator: "scripts/generate_pqc_evidence_graph.py" },
  { file: "pqc_assurance_profile_result.json",      validator: "scripts/verify_pqc_assurance_profile.py", supportsClaims: ["supply_chain.assurance_profile_policy","crypto_agility.profile_separation"] },
  { file: "pqc_evidence_quality_result.json",       validator: "scripts/verify_pqc_evidence_quality.py", supportsClaims: ["supply_chain.evidence_quality_index"] },
  { file: "pqc_migration_readiness.json",           validator: "scripts/generate_migration_readiness_report.py", supportsClaims: ["release.migration_readiness"] },
  { file: "pqc_migration_readiness.md",             validator: "scripts/generate_migration_readiness_report.py" },
  { file: "ct_instruction_policy_result.json",      validator: "scripts/verify_ct_instruction_policy.py", supportsClaims: ["security.mlkem_decap_instruction_policy"] },
  { file: "pqc_claim_closure_result.json",          validator: "scripts/verify_pqc_claim_closure.py" },
  { file: "pqc_reference_values.json",              validator: "scripts/generate_pqc_reference_values.py", supportsClaims: ["release.reference_values"] },
  { file: "pqc_reference_values_result.json",       validator: "scripts/verify_pqc_reference_values.py" },
  { file: "firmware_assurance_status_result.json",  validator: "scripts/verify_firmware_assurance_status.py", supportsClaims: ["firmware.assurance_status_report"] },
  { file: "acvp_json_interop_result.json",          validator: "scripts/run_acvp_json_vectors.py", supportsClaims: ["acvp.json_interop","acvp.json_schema_coverage"] },
  { file: "acvp_json_transcript_manifest.json",     validator: "scripts/run_acvp_json_vectors.py" },
  { file: "pqc_build_provenance.slsa.json",         validator: "scripts/generate_pqc_build_provenance.py", supportsClaims: ["supply_chain.slsa_build_provenance"] },
  { file: "pqc_build_provenance_result.json",       validator: "scripts/verify_pqc_build_provenance.py" },
  { file: "ct_sample_analysis_result.json",         validator: "scripts/analyze_ct_samples.py", jsonPaths: ["per_alg[].alg","per_alg[].sample_count","per_alg[].median_valid","per_alg[].median_invalid","per_alg[].delta","per_alg[].relative_pct","per_alg[].t_stat"], supportsClaims: ["security.ct_sample_analysis","security.ct_campaign_analysis"] },
  { file: "backend_update_evaluation.json",         validator: "scripts/evaluate_backend_update.py", supportsClaims: ["supply_chain.backend_update_evaluation"] },
  { file: "benchmark_campaign_result.json",         validator: "scripts/run_benchmark_campaign.py", jsonPaths: ["rows[].algo","rows[].op","rows[].cycles_min","rows[].cycles_median","rows[].cycles_p90","rows[].cycles_p99","rows[].cycles_mad","rows[].sample_count","context.board_class","context.environment_type"], supportsClaims: ["benchmark.campaign_reproducibility"] },
  { file: "benchmark_campaign_verify_result.json",  validator: "scripts/verify_benchmark_campaign.py" },
  { file: "benchmark_results.csv",                  validator: "scripts/release_check.py", supportsClaims: ["benchmark.csv_validity","benchmark.mlkem_throughput","benchmark.mldsa_throughput","benchmark.distribution_quality"] },
  { file: "benchmark_provenance.json",              validator: "scripts/release_check.py", supportsClaims: ["benchmark.provenance_binding"] },
  { file: "cost_of_assurance_evidence.json",        validator: "scripts/release_check.py", supportsClaims: ["cost_of_assurance.guardrails"] },
  { file: "ct_campaign_result.json",                validator: "scripts/run_ct_campaign.py", supportsClaims: ["security.ct_campaign_analysis"] },
  { file: "acvp_json_schema_result.json",           validator: "scripts/verify_acvp_json_schema.py", supportsClaims: ["acvp.json_schema_coverage"] },
  { file: "device_evidence_token.json",             validator: "samples/pqcp_assurance_status",     supportsClaims: ["firmware.device_evidence_token"] },
  { file: "device_evidence_token_result.json",      validator: "scripts/verify_device_evidence_token.py" },
  { file: "pqc_appraisal_evidence.json",            validator: "scripts/generate_pqc_appraisal_evidence.py", supportsClaims: ["release.evidence_appraisal_profile"] },
  { file: "pqc_appraisal_result.json",              validator: "scripts/verify_pqc_appraisal_evidence.py", supportsClaims: ["release.strict_partner_policy"] },
  { file: "transcripts/evidence_transcript_manifest.json", validator: "scripts/release_check.py", supportsClaims: ["release.transcript_binding"] },
  { file: "generated/pqcp_assurance_digest_generated.h",   validator: "scripts/export_firmware_assurance_digest.py", supportsClaims: ["firmware.assurance_digest_embeddable"] },
  { file: "acvp_negative_scenario_floor_result.json",      validator: "scripts/validate_acvp_negative_scenarios.py", supportsClaims: ["acvp.negative_scenario_floor"] },
  { file: "local_release_bundle/release-manifest.json",    validator: "scripts/prepare_release_bundle.py", supportsClaims: ["release.local_bundle"] },
];

// Which artifacts are required per appraisal mode (from pqc_appraisal_policy.json)
const MODE_REQUIRED_ARTIFACTS = {
  ci_fast: [],
  local_release: ["backend_update_evaluation.json","benchmark_campaign_result.json","ct_campaign_result.json","acvp_json_schema_result.json","device_evidence_token_result.json"],
  partner_review: ["pqc_appraisal_evidence.json","backend_update_evaluation.json","benchmark_campaign_result.json","ct_campaign_result.json","acvp_json_schema_result.json","device_evidence_token_result.json"],
  hardware_review: ["pqc_appraisal_evidence.json","backend_update_evaluation.json","benchmark_campaign_result.json","ct_campaign_result.json","acvp_json_schema_result.json","device_evidence_token_result.json"],
};

// Schema-version lineage (docs/assurance-model.md)
const SCHEMA_LINEAGE = [
  { v: 1, summary: "Legacy 8-claim set; aggregate KAT and benchmark claims." },
  { v: 2, summary: "Per-primitive KAT claims, per-primitive benchmark claims, two ACVP robustness claims." },
  { v: 3, summary: "Passport: CBOM inventory, assurance attestation, policy result, digest manifest." },
  { v: 4, summary: "ACVP negative-scenario floor, asset traceability, evidence graph integrity, firmware digest embed." },
  { v: 5, summary: "Profile policy, evidence quality, profile separation, migration readiness, production RNG policy." },
  { v: 6, summary: "Reference values, firmware status replay, ACVP JSON interop, SLSA provenance, backend currency, CT sample analysis." },
  { v: 7, summary: "Appraisal modes, backend update evaluation, benchmark campaign replay, CT campaign replay, ACVP JSON schema coverage, device evidence token." },
];

window.PQCP = {
  REPO, NON_CLAIMS, CLAIMS, QUALITY, PROFILES, MODES, POLICY, ASSETS,
  ACVP_ERRORS, CAMPAIGN, ARTIFACTS, MODE_REQUIRED_ARTIFACTS, SCHEMA_LINEAGE,
};
