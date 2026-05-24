# Research And Product Hardening Audit

Status: repo-grounded technical audit for post-v1.0.0 `main`  
Audit date: 2026-05-24  
Audited commit: `dbc2335e5768c762cdbef21ea6c8fc9ef0661131`  
Scope: source tree, public headers, Zephyr build glue, samples, ztests,
release tooling, assurance claims, Passport/appraisal scripts, generated local
benchmark artifacts, and current maintainer documentation.

This document is intentionally severe. The repository is already far beyond a
toy PQC sample: it has a Zephyr module, pinned native backends, ACVP/KAT
fixtures, benchmark instrumentation, a local release gate, transcript hashing,
CBOM-style inventory, in-toto/SLSA-shaped evidence, RATS-inspired reference
values, evidence appraisal, backend-contract policy, and replay verification.
That is real engineering. It is not yet enough, by itself, for a strong
research paper or a convincing partner product. The missing work is no longer
"add more labels." The missing work is comparative evidence, physical
measurements, adversarial validation, tighter schema discipline, product
packaging proof, and a research story that can survive hostile review.

## Source Material Inspected

Repository files and generated artifacts inspected for this audit:

- `README.md`: project positioning, quickstart, performance table, security
  properties, consumer integration, and release status.
- `Kconfig`: provider, parameter-set, RNG, profile, backend, ACVP, benchmark,
  TLS self-test, and assurance-status configuration surface.
- `CMakeLists.txt`: native backend discovery, single-level/multi-level build
  logic, reduced-RAM mode, PSA driver wiring, and sample/test source inclusion.
- `west.yml`: pinned Zephyr and native backend revisions.
- `zephyr/module.yml`: Zephyr module registration.
- `include/pqcp_zephyr/*.h`: stable public API, validation API, benchmark API,
  RNG API, TLS self-test API, and version macros.
- `src/*.c`: ML-KEM wrapper, ML-DSA wrapper, PSA drivers, RNG backends, ACVP
  parser, benchmark emitters, TLS self-test, streaming signing, and boot KAT
  self-verify.
- `samples/*`: consumer examples, serial ACVP sample, protocol benchmark,
  deterministic KAT sample, TLS/PSA sample, and assurance-status sample.
- `tests/*`: ACVP KAT, ACVP serial, ACVP serial negative replay, CT smoke,
  boot KAT self-verify, primitive API, RNG, and TLS self-test ztests.
- `scripts/assurance_claims.json`: schema v7 claim catalog with 57 claims.
- `scripts/pqc_assurance_policy.json`: partner-review policy requiring
  claim IDs, CBOM components, attestation subjects, Passport artifacts, and
  profile properties.
- `scripts/pqc_assurance_profile.json`: `native_lab`, `qemu_release`,
  `mcu_minimal`, and `gateway` profiles.
- `scripts/pqc_evidence_quality.json`: evidence-class mapping for all required
  claims.
- `scripts/pqc_asset_trace_map.json`: 15 traced assets from crypto families,
  validation paths, RNG backends, boot/CT evidence, and external experimental
  inventory placeholders.
- `scripts/release_check.py`: local full release gate and CI fast-gate split.
- `scripts/verify_release_evidence_pack.py`: replay verifier for release packs.
- `scripts/run_benchmarks.py`, `scripts/run_benchmark_campaign.py`,
  `scripts/verify_benchmark_campaign.py`,
  `scripts/verify_benchmark_confidence.py`, and
  `scripts/optimize_metric_campaign.py`: benchmark orchestration, campaign
  replay, confidence replay, and candidate optimization decision logic.
- `scripts/run_acvp_json_vectors.py`,
  `scripts/validate_acvp_json_schema.py`,
  `scripts/verify_acvp_json_interop.py`, and ACVP fixtures under
  `scripts/testdata/acvp_json/`: JSON interop bridge and replay checks.
- `scripts/analyze_ct_samples.py`, `scripts/run_ct_campaign.py`, and
  `scripts/verify_ct_instruction_policy.py`: runtime and static side-channel
  smoke evidence.
- `scripts/export_pqc_cbom.py`, `scripts/generate_pqc_attestation.py`,
  `scripts/generate_pqc_build_provenance.py`,
  `scripts/generate_pqc_reference_values.py`, and
  `scripts/export_firmware_assurance_digest.py`: Passport and reference-value
  artifact generation.
- `scripts/generate_partner_review_scorecard.py`,
  `scripts/verify_partner_review_scorecard.py`, and
  `scripts/run_evidence_tamper_drill.py`: partner-facing evidence rollup and
  tamper detection.
- `benchmark_results/release_check/benchmark_results.csv`: existing local
  benchmark CSV with 36 rows and one observation per primitive/implementation
  group.
- `benchmark_results/release_check/benchmark_provenance.json`: CSV provenance
  sidecar.
- `benchmark_results/release_check/release_check_results.xml`: previous local
  release JUnit output.
- `docs/assurance-model.md`, `docs/pqc-assurance-passport.md`,
  `docs/performance-methodology.md`, `docs/api-overview.md`,
  `docs/release.md`, `docs/maintainer-release-checklist.md`,
  `docs/publications.md`, and `docs/research-product-dossier.md`.

External reference anchors used to calibrate the roadmap:

- NIST FIPS 203, ML-KEM, final publication:
  https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204, ML-DSA, final publication:
  https://csrc.nist.gov/pubs/fips/204/final
- NIST FIPS 205, SLH-DSA, final publication:
  https://csrc.nist.gov/pubs/fips/205/final
- NIST NCCoE migration to post-quantum cryptography:
  https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc
- NIST ACVP ML-KEM JSON specification draft:
  https://pages.nist.gov/ACVP/draft-celi-acvp-ml-kem.html
- NIST ACVP ML-DSA JSON specification draft:
  https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html
- IETF RATS architecture, RFC 9334:
  https://www.rfc-editor.org/info/rfc9334
- SLSA provenance v1.1:
  https://slsa.dev/spec/v1.1/provenance
- in-toto Attestation Framework specification:
  https://github.com/in-toto/attestation/blob/main/spec/README.md
- CycloneDX cryptographic asset / CBOM context:
  https://cyclonedx.org/
- Open Quantum Safe algorithm inventory:
  https://openquantumsafe.org/liboqs/algorithms/
- pqm4 Cortex-M benchmarking framework:
  https://github.com/mupq/pqm4
- SUPERCOP/eBACS benchmarking context:
  https://bench.cr.yp.to/supercop.html
- KyberSlash implementation-risk reference:
  https://kyberslash.cr.yp.to/faq.html
- PQC-LEO evaluation framework:
  https://arxiv.org/abs/2603.06149
- ARM Cortex-M0+ ML-KEM/ML-DSA benchmark paper:
  https://arxiv.org/abs/2603.19340

## Executive Verdict

The current repository is strong as an engineering prototype for embedded PQC
assurance. It is not yet strong enough for a high-confidence product launch or
a novel systems/security paper because the strongest claims are still local,
QEMU-centered, and artifact-structural. The repository can prove that its
release pack is internally coherent. It cannot yet prove that the firmware is
competitive on physical boards, robust under realistic serial/adversarial use,
comparable to established benchmark frameworks, resistant to side-channel
classes beyond smoke tests, or mature enough for external teams to adopt with a
clear support and update contract.

### What is genuinely strong today

- `Kconfig`, `CMakeLists.txt`, and `west.yml` implement a real Zephyr module
  with pinned native backend sources and downstream west consumption.
- Public headers under `include/pqcp_zephyr/` document stable API boundaries
  for ML-KEM, ML-DSA, RNG, ACVP, benchmark, TLS self-test, and versioning.
- `tests/ztest_acvp_kat/` provides vendored NIST-style vector fixtures and a
  checked-in generated header path.
- `scripts/verify_kat_provenance.py` binds ACVP vector JSON files to
  `tests/ztest_acvp_kat/src/kat_vectors.h`.
- `src/acvp_cmd.c` contains bounded ACVP command parsing with negative-path and
  timeout tests in `tests/ztest_acvp_serial/` and
  `tests/ztest_acvp_serial_negative/`.
- `scripts/acvp_negative_scenario_floor.json` and
  `scripts/validate_acvp_negative_scenarios.py` prevent silent deletion or
  weakening of existing malformed-input scenarios.
- `scripts/release_check.py` creates a local release evidence root that does
  not depend on GitHub Actions.
- `scripts/verify_release_evidence_pack.py` can replay-check many artifacts
  without rebuilding Zephyr.
- `scripts/assurance_claims.json` has 57 explicit claims, not vague prose.
- `scripts/pqc_asset_trace_map.json` maps assets to source files, Kconfig
  symbols, claims, tests, markers, and CBOM components.
- `scripts/pqc_assurance_profile.json` separates lab, QEMU release, constrained
  MCU, and gateway profiles.
- `scripts/pqc_evidence_quality.json` forces each claim into an evidence class.
- `scripts/verify_backend_contract.py` and `scripts/verify_backend_currency.py`
  make the native-provider rule executable rather than merely documented.
- `scripts/run_evidence_tamper_drill.py` begins to prove that replay verifiers
  detect artifact mutation.
- `tests/ztest_ct_smoke/`, `scripts/analyze_ct_samples.py`, and
  `scripts/verify_ct_instruction_policy.py` add side-channel regression smoke
  evidence and label it honestly.
- `scripts/run_benchmark_campaign.py`,
  `scripts/verify_benchmark_campaign.py`, and
  `scripts/verify_benchmark_confidence.py` are moving the benchmark story from
  single values toward distributions and replayed metadata.

### What is not yet strong enough

- The existing benchmark CSV in `benchmark_results/release_check/` has one row
  per primitive/implementation group, so it cannot support a serious
  distributional performance claim by itself.
- QEMU and native simulator evidence are useful for regression. They are not
  physical hardware performance claims and should not be presented as such.
- MCU evidence is currently mostly build-only ROM/RAM footprint for selected
  targets, not executed timing, energy, UART reliability, or side-channel
  evidence.
- ACVP JSON interop is a local translator/replay bridge. It is not a live ACVP
  client, not a full server-session implementation, and not a validation
  certificate path.
- The CBOM is useful and traceable, but it is not yet schema-validated against
  a pinned CycloneDX schema in the release gate.
- The in-toto/SLSA-shaped attestation is unsigned. It is hash-bound, not
  identity-bound.
- Reference values and device-evidence markers are preparatory. There is no
  hardware root of trust, no nonce protocol, no transport binding, and no
  relying-party verification service.
- CT smoke and instruction scans catch narrow regressions. They do not
  establish constant-time behavior on silicon.
- Product documentation is good for maintainers but not yet enough for partner
  onboarding at scale: there is no compatibility matrix with pass/fail history,
  no release support policy, no security advisory workflow beyond
  `SECURITY.md`, and no conformance report template.
- The research story is not yet experimentally isolated. A paper needs
  hypotheses, baselines, ablations, threat model, artifact evaluation plan, and
  enough data to show that the assurance system finds bugs or prevents drift
  better than simpler alternatives.

## Plain-English Diagnosis

The repository currently answers: "Can this project build and locally produce
a coherent evidence pack that links claims to artifacts?" The answer is mostly
yes.

A serious paper or partner product also needs to answer harder questions:

- "Does the system catch real classes of mistakes that existing CI/SBOM tools
  miss?"
- "Does it scale when more boards, parameter sets, firmware profiles, and
  external evidence sources are added?"
- "Are the performance numbers credible against accepted benchmarking
  methodology?"
- "Can a partner reproduce results on their hardware?"
- "Can a security reviewer trust the evidence without trusting the developer's
  machine?"
- "Can a downstream firmware team adopt this without accidentally enabling a
  lab-only path in production?"
- "Can the system handle version drift, backend drift, and policy drift over
  time?"

The rest of this document maps each gap to repository files and concrete
implementation work.

## Current Architecture Map

### Algorithm and backend layer

Current files:

- `include/pqcp_zephyr/mlkem.h`
- `include/pqcp_zephyr/mldsa.h`
- `src/mlkem_zephyr.c`
- `src/mldsa_zephyr.c`
- `src/mldsa_streaming.c`
- `src/psa_mlkem_driver.c`
- `src/psa_mldsa_driver.c`
- `CMakeLists.txt`
- `Kconfig`
- `west.yml`
- `.gitmodules`
- `ext/mlkem-native`
- `ext/mldsa-native`

Current behavior:

- ML-KEM parameter sets 512/768/1024 are exposed through Zephyr-facing wrapper
  functions and PSA driver shims.
- ML-DSA parameter sets 44/65/87 are exposed through keygen/sign/verify and
  streaming helper paths.
- `Kconfig` supports multi-level and single-level builds, backend selection,
  reduced-RAM mode, monolithic host builds, and RNG mode selection.
- `CMakeLists.txt` discovers either in-repo `ext/` checkouts or west-managed
  `modules/crypto/*` backends.
- `west.yml` pins Zephyr plus both native backend repositories by exact SHA.
- `scripts/verify_backend_currency.py` and
  `scripts/verify_backend_contract.py` replay-check backend pins and provider
  policy.

Current weakness:

- The backend contract is structurally checked, but the repository does not yet
  run an exhaustive matrix proving every `Kconfig` provider/profile selection
  maps to the intended C object files and generated compile definitions.
- The repository has wrappers around native implementations; it does not prove
  that compiler options, LTO, monolithic mode, reduced-RAM mode, and
  single-level/multi-level selection preserve every KAT and negative property
  across the full matrix.
- The public API is documented, but ABI/API stability is not yet enforced by a
  symbol/version diff tool.

Required incorporation:

- Add `scripts/verify_build_configuration_matrix.py`.
- Inputs:
  - `Kconfig`
  - `CMakeLists.txt`
  - `west.yml`
  - `.gitmodules`
  - `scripts/profile_validation_matrix.json`
  - generated `compile_commands.json` for representative builds
- Outputs:
  - `build_configuration_matrix_result.json`
  - `build_configuration_matrix.md`
- Checks:
  - every profile selects exactly one RNG mode unless a test overlay states
    otherwise;
  - every ML-KEM-only profile includes only expected native source paths;
  - every ML-DSA-only profile includes only expected native source paths;
  - no lab-only deterministic RNG symbol appears in production profile
    compile commands;
  - single-level builds define exactly one level per family;
  - multi-level builds define the multi-level wrapper path and not a stale
    single-level parameter macro;
  - baseline comparison builds remain QEMU-only;
  - force-native/force-C knobs are marked as comparison evidence and not
    production defaults.
- Tests:
  - `scripts/test_build_configuration_matrix.py`
  - synthetic `compile_commands.json` fixtures that intentionally mix
    deterministic RNG into production, omit a backend, or enable multiple
    single-level macros without multi-level mode.
- Release integration:
  - full local `release_check.py` should run this script after profile
    validation and before CBOM export;
  - `verify_release_evidence_pack.py` should require the result for the next
    schema version.

### Validation and ACVP layer

Current files:

- `include/pqcp_zephyr/acvp_cmd.h`
- `src/acvp_cmd.c`
- `samples/pqcp_serial_acvp/src/main.c`
- `tests/ztest_acvp_serial/src/main.c`
- `tests/ztest_acvp_serial_negative/src/main.c`
- `scripts/acvp_negative_scenarios.json`
- `scripts/acvp_negative_scenario_floor.json`
- `scripts/validate_acvp_negative_scenarios.py`
- `scripts/generate_acvp_negative_header.py`
- `scripts/run_acvp_json_vectors.py`
- `scripts/validate_acvp_json_schema.py`
- `scripts/verify_acvp_json_interop.py`
- `scripts/testdata/acvp_json/*.json`

Current behavior:

- The serial parser accepts command lines, decodes hex, dispatches ML-KEM and
  ML-DSA operations, returns `RESULT:*` or `ERROR:*`, and enforces a readline
  timeout through the shared line helper.
- Negative scenario fixtures include malformed hex, wrong size, invalid
  levels, oversize payloads, timeout recovery, and malformed-then-valid
  recovery.
- The negative scenario floor prevents deletion or response weakening.
- ACVP JSON interop translates a subset of NIST-style JSON vector groups into
  serial-command evidence and transcript hashes.

Current weakness:

- The ACVP JSON bridge is not a real ACVP client. It does not implement test
  session negotiation, vector-set retrieval, response upload, registration
  metadata, or official server workflow.
- Supported JSON operations are local fixtures and synthetic translations. They
  are useful but not sufficient for claiming standards-lab interoperability.
- The parser performance is not currently measured under large randomized
  valid/invalid workloads.
- The serial harness is tested mostly as a function/ztest path. There is no
  long-running UART soak test with noisy framing, line resets, backpressure,
  and malformed traffic rates.
- There is no grammar fuzzer or property-based parser test that proves
  boundedness for arbitrary byte sequences.

Required incorporation:

- Add `scripts/fuzz_acvp_parser_cases.py` as a pure-Python generator for
  deterministic malformed command corpora.
- Add `tests/ztest_acvp_serial_fuzz/` that compiles a generated corpus header
  and feeds every case through `pqcp_acvp_process_command()` and the serial
  line helper.
- Add `scripts/run_acvp_parser_campaign.py`.
- Inputs:
  - generated corpus JSON
  - `scripts/acvp_negative_scenarios.json`
  - `scripts/acvp_smoke_scenarios.json`
  - optional QEMU transcript
- Outputs:
  - `acvp_parser_campaign_result.json`
  - `acvp_parser_campaign.md`
  - `acvp_parser_latency.csv`
- Metrics:
  - commands per second on host helper path;
  - maximum command length accepted/rejected;
  - decode latency per byte;
  - error-code distribution;
  - timeout recovery count;
  - valid-after-malformed recovery count;
  - maximum stack/heap footprint if measurable from Zephyr build artifacts.
- Add `scripts/verify_acvp_json_conformance.py`.
- Checks:
  - ACVP JSON result contains vector-set metadata;
  - every group includes algorithm, mode, parameter set, test type, test ID,
    and response class;
  - required operation classes are covered separately;
  - malformed-then-valid recovery is represented in the same transcript
    manifest;
  - unsupported fields are rejected with explicit failure rather than ignored.
- Release integration:
  - full local gate should include parser campaign and JSON conformance result;
  - CI fast gate should keep only floor and negative ztests.

### KAT and boot self-test layer

Current files:

- `tests/ztest_acvp_kat/nist_vectors/*.json`
- `tests/ztest_acvp_kat/src/kat_vectors.h`
- `tests/ztest_acvp_kat/src/main.c`
- `scripts/verify_kat_provenance.py`
- `src/kat_boot_verify.c`
- `tests/ztest_kat_boot_verify/src/main.c`
- `samples/pqcp_kat_deterministic/src/main.c`

Current behavior:

- Vendored vector JSON files are checked against generated header constants.
- KAT smoke mode exists for PR-fast validation.
- Boot KAT self-verify can run a deterministic startup self-test when
  configured.

Current weakness:

- KAT provenance validates checked-in fixtures, not the process by which the
  fixtures were generated or updated.
- Boot self-test is useful but not currently tied to a production policy for
  when startup self-test is required versus disabled.
- The deterministic KAT sample is pedagogical; it should be guarded carefully
  so partners cannot confuse it with production entropy.
- There is no mutation test proving that one-byte changes in each vector field
  fail the correct claim ID.

Required incorporation:

- Add `scripts/kat_fixture_manifest.json`.
- Fields:
  - source URL or source commit for each vector file;
  - vector-set identifier;
  - algorithm and parameter set;
  - expected number of groups and test cases;
  - SHA-256 of raw JSON;
  - generated header symbol list;
  - generation command and generator version.
- Add `scripts/verify_kat_fixture_manifest.py`.
- Add mutation tests:
  - `scripts/test_kat_fixture_manifest.py`
  - generate a temporary copy with a flipped byte in one ML-KEM vector and
    assert the verifier names the parameter-set-specific claim;
  - same for ML-DSA signature verification vectors;
  - remove a test group and assert row-count mismatch.
- Release integration:
  - generate `kat_fixture_manifest_result.json`;
  - add claim `kat.fixture_manifest_integrity`;
  - update evidence graph so KAT assets map to raw JSON, generated header,
    ztest, and claim.

### Benchmark and performance layer

Current files:

- `src/bench_primitive.c`
- `src/bench_protocol.c`
- `include/pqcp_zephyr/bench.h`
- `samples/pqcp_bench_protocol/`
- `scripts/run_benchmarks.py`
- `scripts/parse_logs.py`
- `scripts/export_results.py`
- `scripts/run_benchmark_campaign.py`
- `scripts/verify_benchmark_campaign.py`
- `scripts/verify_benchmark_confidence.py`
- `scripts/run_paper_comparison_campaign.py`
- `scripts/run_hardware_benchmarks.py`
- `scripts/optimize_metric_campaign.py`
- `scripts/benchmark_matrix.json`
- `scripts/cost_of_assurance_matrix.json`
- `scripts/resource_budgets.json`
- `scripts/qemu_cost_of_assurance_regression.json`
- `benchmark_results/release_check/benchmark_results.csv`

Current behavior:

- Primitive and protocol benchmarks emit stable `PQCP_METRIC` lines.
- CSV export includes provenance and comparison context.
- Benchmark campaign tooling can summarize repeated rows into min/median/p90/
  p99/max/MAD/sample count.
- Confidence replay now requires coherent max-bounded distributions.
- Optimization campaign logic records keep/reject decisions from evidence
  rather than mutating production code.

Current weakness:

- Existing committed/recent release CSV has one observation per group, so
  claims remain regression smoke evidence rather than paper-grade performance.
- There is no physical board execution campaign with repeated runs, energy, and
  UART transcript binding.
- QEMU timing is not calibrated against physical boards.
- There is no baseline against accepted embedded benchmark frameworks using the
  same target, clock, compiler, and measurement semantics.
- There is no automated variance analysis across build options, CPU frequency,
  optimization level, cache state, or board temperature.
- Protocol metrics are not yet connected to an end-to-end network workload.
- ROM/RAM footprint is measured, but peak stack and heap behavior are not fully
  tied to call paths and profiles.

Required incorporation:

- Add `scripts/benchmark_campaign_matrix.json`.
- Each row should specify:
  - board;
  - profile;
  - sample;
  - algorithm family;
  - parameter set;
  - operation;
  - implementation;
  - backend policy;
  - repetitions;
  - warmups;
  - optimization overlay;
  - expected environment type;
  - required transcript markers;
  - whether the row is release-gating, paper-candidate, or exploratory.
- Extend `scripts/run_benchmark_campaign.py` so it can drive west builds and
  QEMU/hardware runs directly, not only consume a CSV.
- Add physical-board lanes:
  - `nucleo_h743zi` timing with UART capture;
  - Cortex-M4-class board aligned with pqm4-style reporting;
  - optional Cortex-M0+/RP2040-style lane for constrained comparison.
- Add output artifacts:
  - `benchmark_campaign_raw_samples.csv`;
  - `benchmark_campaign_distribution.csv`;
  - `benchmark_campaign_environment.json`;
  - `benchmark_campaign_transcript_manifest.json`;
  - `benchmark_campaign_plots.json` with plot-ready series but no generated
    images committed;
  - `benchmark_campaign_report.md`.
- Add `scripts/verify_benchmark_campaign_matrix.py`.
- Checks:
  - at least N samples for paper-candidate rows;
  - balanced sample counts for candidate/baseline comparisons;
  - every row has board, compiler, SDK, Zephyr revision, clock assumptions,
    optimization flags, and backend family;
  - QEMU rows cannot be labeled hardware;
  - hardware rows require physical transcript metadata;
  - external reference rows require source URL, statistic type, clock,
    platform, compiler, and environment type.
- Add `scripts/compare_benchmark_against_reference.py`.
- Inputs:
  - local distribution CSV;
  - normalized reference CSV;
  - mapping file from operation names to reference names.
- Outputs:
  - ratios by operation;
  - confidence intervals;
  - "not comparable" reasons for mismatched clocks/platforms.
- Research threshold:
  - do not claim competitiveness unless the same class of hardware and
    comparable compiler flags are used.

### Side-channel and implementation-risk layer

Current files:

- `tests/ztest_ct_smoke/src/main.c`
- `scripts/analyze_ct_samples.py`
- `scripts/run_ct_campaign.py`
- `scripts/verify_ct_instruction_policy.py`
- `scripts/test_ct_sample_analysis.py`
- `scripts/test_ct_campaign.py`

Current behavior:

- Runtime CT smoke measures valid versus invalid ML-KEM decapsulation timing
  with 32 samples per class and emits `PQCP_CT_SMOKE`, `PQCP_CT_TTEST`, and
  optional `PQCP_CT_SAMPLE` markers.
- Offline analysis checks sample count, valid/invalid balance, index
  contiguity, median deltas, p90/p99 deltas, and a Welch-style smoke statistic.
- Static policy scans disassembly for variable-latency division instructions in
  ML-KEM decapsulation-related symbols and rejects harness-only coverage.

Current weakness:

- QEMU timing cannot prove silicon leakage behavior.
- Sample count is too small for serious leakage claims.
- The Welch-style statistic is smoke-level and lacks calibration for timer
  noise, autocorrelation, or fixed-versus-random test design.
- There is no physical trace capture path for power, EM, GPIO trigger, or
  cycle-accurate DWT counters.
- There is no formal constant-time verification of source/assembly.
- The instruction scanner checks a narrow class of known mistakes; it does not
  inspect memory access patterns, table lookups, compiler transforms, or
  branches correlated with secrets.

Required incorporation:

- Add `scripts/side_channel_campaign_matrix.json`.
- Add `scripts/run_side_channel_campaign.py`.
- Modes:
  - `qemu-smoke`: current transcript markers;
  - `cycle-counter-hardware`: board DWT/cycle counter where supported;
  - `uart-triggered-capture`: emits trigger markers for external capture;
  - `import-traces`: imports CSV traces from lab equipment.
- Add `scripts/analyze_side_channel_campaign.py`.
- Metrics:
  - fixed-versus-random t-statistics;
  - valid-versus-invalid decapsulation class deltas;
  - sample count;
  - autocorrelation warning;
  - effect size;
  - confidence interval;
  - trace source metadata;
  - acquisition rate;
  - trigger alignment quality.
- Add `scripts/verify_static_ct_policy.py`.
- Checks:
  - branch mnemonic scan on selected object symbols;
  - memory-table access pattern warnings;
  - compiler helper calls;
  - symbol coverage map;
  - compile flag capture;
  - disassembly hash binding.
- Add tests:
  - duplicate index fails;
  - missing symbol group fails;
  - branch-on-secret synthetic disassembly fails;
  - table lookup synthetic disassembly warns;
  - imported trace without acquisition metadata fails.
- Release integration:
  - QEMU smoke remains required;
  - hardware side-channel campaign is "required for product-ready hardware
    profile" but `not_available` for QEMU release profile.

### Assurance, Passport, reference values, and attestation layer

Current files:

- `scripts/generate_assurance_ledger.py`
- `scripts/verify_assurance_ledger.py`
- `scripts/export_pqc_cbom.py`
- `scripts/generate_pqc_attestation.py`
- `scripts/generate_pqc_build_provenance.py`
- `scripts/generate_pqc_reference_values.py`
- `scripts/verify_pqc_reference_values.py`
- `scripts/verify_release_reference_values.py`
- `scripts/export_firmware_assurance_digest.py`
- `scripts/verify_firmware_assurance_status.py`
- `scripts/verify_device_evidence_token.py`
- `scripts/generate_pqc_appraisal_evidence.py`
- `scripts/verify_pqc_appraisal_evidence.py`
- `scripts/generate_partner_review_scorecard.py`
- `scripts/verify_partner_review_scorecard.py`
- `scripts/run_evidence_tamper_drill.py`

Current behavior:

- The project produces a local evidence pack and replay verifiers.
- The CBOM-style artifact inventories crypto assets and properties.
- The attestation and build provenance use in-toto/SLSA-shaped JSON.
- Reference values bind release metadata, artifact hashes, CBOM IDs, claims,
  and digest roots.
- Firmware status sample prints digest/artifact markers.
- Tamper drill mutates a temporary pack and checks detection.

Current weakness:

- The attestation is unsigned, so it proves hash coherence but not identity,
  timestamp authority, or controlled build environment.
- The CBOM-style JSON is not currently validated against a pinned official
  schema in the release gate.
- The in-toto/SLSA-shaped JSON is shape-checked by local scripts but not tested
  against a third-party validator.
- The RATS-like reference-value path is local and not connected to a real
  verifier/relying-party protocol.
- The evidence pack has many artifacts, but no formal artifact schema registry
  with versioned JSON schemas for every file.
- The tamper drill covers selected mutations, not a systematic mutation matrix
  across every artifact/claim relationship.

Required incorporation:

- Add `schemas/` at repository root.
- Proposed schemas:
  - `schemas/assurance-ledger.schema.json`
  - `schemas/pqc-cbom-profile.schema.json`
  - `schemas/pqc-attestation-predicate.schema.json`
  - `schemas/pqc-reference-values.schema.json`
  - `schemas/pqc-policy-result.schema.json`
  - `schemas/pqc-appraisal-result.schema.json`
  - `schemas/benchmark-campaign.schema.json`
  - `schemas/acvp-interop-result.schema.json`
  - `schemas/ct-campaign-result.schema.json`
  - `schemas/partner-scorecard.schema.json`
- Add `scripts/validate_release_schemas.py`.
- Checks:
  - every generated JSON artifact declares schema version;
  - artifact schema version maps to a checked-in schema;
  - every required property is present;
  - no unexpected enum values;
  - hash fields match 64 lowercase hex characters;
  - file paths are relative to output root;
  - no generated artifact claims signed status unless signature is present.
- Add `scripts/sign_release_evidence.py` later, after key custody is defined.
  Do not add signing first. First add schema and policy discipline.
- Add `scripts/verify_evidence_signature.py` later.
- Proposed signature strategy:
  - DSSE envelope around digest manifest;
  - maintainer key ID;
  - transparency log optional;
  - offline key support for proprietary partner sharing.
- Add `scripts/run_evidence_mutation_campaign.py`.
- It should generate mutations for every required artifact relationship:
  - missing file;
  - zero-byte file;
  - stale hash;
  - stale claim ID;
  - stale CBOM component ID;
  - stale release commit;
  - dirty-tree disagreement;
  - timestamp outside release window;
  - not-applicable claim not allowlisted;
  - missing transcript marker;
  - changed transcript bytes;
  - missing backend contract;
  - altered profile decision;
  - altered reference-value digest root.
- Output:
  - `evidence_mutation_campaign_result.json`
  - `evidence_mutation_campaign.md`
- Research value:
  - This becomes publishable evidence that the Passport detects classes of
    artifact tampering and policy drift, not just that it emits files.

### Product and maintainer workflow layer

Current files:

- `README.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `LICENSE`
- `.github/workflows/*.yml`
- `docs/release.md`
- `docs/maintainer-release-checklist.md`
- `scripts/consumer_smoke.py`
- `scripts/verify_product_readiness.py`
- `scripts/local_workflow.py`

Current behavior:

- There is a proprietary license and contribution terms.
- There is a responsible disclosure document.
- Consumer west onboarding is documented.
- Local release and product-readiness wrappers exist.
- CI fast gate separates expensive local release generation from fast checks.

Current weakness:

- The repository still reads as a research-heavy toolkit, not a packaged SDK
  with a strict partner support contract.
- There is no release artifact checklist template for partners to sign off.
- There is no compatibility matrix showing which Zephyr SDK, Zephyr revision,
  host OS, boards, and profiles have passed recently.
- There is no "minimum supported partner environment" contract.
- There is no changelog category separating API changes, assurance schema
  changes, evidence-pack changes, and experimental tools.
- There is no published schema migration guide for evidence packs.
- There is no "known limitations by profile" page that is short enough for a
  partner engineering manager.
- The dashboard/GUI work is outside the repository or not yet integrated as a
  production app with data loading, tests, and pack import.

Required incorporation:

- Add `docs/partner-evaluation-guide.md`.
- Include:
  - exact command to build a clean consumer workspace;
  - exact command to run a QEMU smoke;
  - exact command to generate a release pack;
  - exact command to replay a pack;
  - exact evidence files to review;
  - what is QEMU-only;
  - what requires hardware;
  - what is not claimed.
- Add `docs/release-schema-migration.md`.
- Include:
  - schema v1 through v7 differences;
  - artifact additions;
  - replay compatibility;
  - when old packs degrade versus fail.
- Add `docs/support-policy.md`.
- Include:
  - supported Zephyr baseline;
  - supported SDK baseline;
  - supported boards;
  - supported profiles;
  - support window for v1.0.x;
  - security fix process;
  - evidence schema deprecation policy.
- Add `scripts/generate_compatibility_matrix.py`.
- Inputs:
  - workflow YAML;
  - `west.yml`;
  - release pack artifacts;
  - benchmark/provenance environment fields;
  - profile validation results.
- Outputs:
  - `compatibility_matrix.json`
  - `compatibility_matrix.md`
- Release integration:
  - full release includes compatibility matrix;
  - README links to generated matrix shape without committing release outputs.

## Why The Current Project Is Not Yet A Novel Paper

The current repository has many pieces that sound publishable:
claim-to-evidence ledger, CBOM, attestation, ACVP JSON bridge, CT smoke,
reference values, evidence graph, profile policy, and replay verification.
However, paper novelty requires a defensible contribution against prior work,
not a list of artifacts. The paper cannot simply say "we built a Zephyr PQC
stack" because the underlying algorithms and backend implementations are
standardized or external. It also cannot simply say "we produce an evidence
pack" unless the paper proves that the evidence pack catches important classes
of failure and scales better than obvious alternatives.

### Paper weakness 1: no sharply stated research question

Current state:

- `docs/publications.md` is a strong short brief.
- It explains what the repository proves and how to replay claims.
- It does not define research questions, hypotheses, metrics, baselines, or
  evaluation protocol.

Required paper framing:

- RQ1: Can claim-to-evidence replay detect release-artifact drift that CI logs,
  SBOMs, and unstructured release notes miss?
- RQ2: Can an embedded PQC module expose enough evidence for partner review
  without requiring reviewers to rebuild Zephyr?
- RQ3: How much overhead does this evidence discipline add to release time,
  artifact size, and maintainer complexity?
- RQ4: How does physical-board performance and memory footprint change across
  native backend selections, profiles, and parameter sets?
- RQ5: Which side-channel regression classes are caught by runtime smoke,
  instruction policy, and mutation tests, and which remain out of scope?

Repository incorporation:

- Add `docs/paper-evaluation-plan.md`.
- Add `scripts/paper_experiment_matrix.json`.
- Add `scripts/run_paper_experiments.py` as an orchestrator that calls existing
  scripts rather than reimplementing logic.
- Add `scripts/verify_paper_experiment_pack.py`.
- Add `paper_artifacts/README.md` explaining that generated outputs are ignored
  and not committed.

### Paper weakness 2: no baseline comparison for the assurance layer

Current state:

- Evidence replay is internally coherent.
- There is no comparison against "simple CI log only", "SBOM only",
  "provenance only", or "manual release checklist" baselines.

Required experiment:

- Create a mutation suite with at least 50 injected faults:
  - stale benchmark CSV hash;
  - missing KAT vector;
  - stale CBOM component;
  - changed release manifest commit;
  - missing transcript;
  - altered ACVP response;
  - disabled negative scenario;
  - backend pin mismatch;
  - deterministic RNG marked production;
  - CT transcript marker removed;
  - device evidence digest changed;
  - profile result tampered;
  - attestation subject hash stale.
- Run each fault against:
  - `verify_release_evidence_pack.py`;
  - schema-only validation;
  - local release checklist presence;
  - benchmark provenance validation only;
  - CBOM presence only.
- Report detection matrix.

Repository incorporation:

- Extend `scripts/run_evidence_tamper_drill.py` into a campaign mode.
- Add `scripts/evidence_mutation_matrix.json`.
- Add `scripts/summarize_evidence_mutation_campaign.py`.
- Output:
  - `evidence_mutation_detection_matrix.csv`
  - `evidence_mutation_campaign_result.json`
  - `evidence_mutation_campaign.md`
- Add tests:
  - every mutation must be detected by at least one intended verifier;
  - verifier coverage map cannot have empty rows;
  - false-pass mutations fail the campaign.

### Paper weakness 3: no serious hardware benchmark campaign

Current state:

- QEMU and native simulator evidence are extensive.
- `nucleo_h743zi` footprint rows exist.
- Hardware capture helper exists, but physical execution is optional and not
  a required evidence tier.

Required experiment:

- Run ML-KEM and ML-DSA on at least three board classes:
  - STM32H7-class board for high-end MCU gateway profile;
  - Cortex-M4-class board comparable to pqm4-style reporting;
  - constrained Cortex-M0+/RP2040-style board if feasible for memory.
- For each board:
  - keygen/encaps/decaps/sign/verify;
  - all supported parameter sets that fit memory;
  - 100+ repetitions per operation;
  - warmup separation;
  - median, p90, p99, max, MAD;
  - ROM, RAM, stack;
  - toolchain, flags, clock, board revision;
  - UART transcript hash;
  - failure and timeout counts.

Repository incorporation:

- Extend `scripts/run_hardware_benchmarks.py` from helper into campaign runner.
- Add `boards/` documentation for each hardware lane.
- Add `scripts/hardware_board_registry.json`.
- Add `scripts/hardware_benchmark_campaign.json`.
- Add `scripts/verify_hardware_benchmark_campaign.py`.
- Add `docs/hardware-benchmark-methodology.md`.

### Paper weakness 4: no energy or network-level protocol evaluation

Current state:

- Protocol benchmark emits handshake-like metrics and RTOS jitter fields.
- It does not measure energy.
- It does not run a real network/TLS interop session with external peers.

Required experiment:

- Add energy measurement support:
  - external power monitor CSV import;
  - board voltage/current metadata;
  - operation window markers;
  - joules per operation;
  - energy per TLS-like handshake.
- Add network-level protocol evaluation:
  - mbedTLS integration test with local peer where feasible;
  - packet counts;
  - bytes in/out;
  - handshake latency distribution;
  - failure/retry behavior under packet loss if supported by emulator.

Repository incorporation:

- Add `scripts/import_power_trace.py`.
- Add `scripts/analyze_energy_campaign.py`.
- Add `scripts/run_protocol_interop_campaign.py`.
- Add `docs/protocol-energy-methodology.md`.
- Add claims:
  - `benchmark.energy_campaign`;
  - `protocol.tls_interop_campaign`;
  - `protocol.failure_injection`.
- Add release artifacts:
  - `energy_campaign_result.json`;
  - `protocol_interop_campaign_result.json`.

### Paper weakness 5: side-channel evidence is honest but too weak

Current state:

- CT smoke is correctly labeled as smoke.
- Instruction scanner targets known variable-latency division class.
- Raw sample capture exists behind a Kconfig flag.

Required experiment:

- Add hardware capture mode with enough samples for a real statistical test.
- Add fixed-versus-random test design.
- Add cross-build comparison: `-O2`, `-O3`, `-Os`, LTO, reduced RAM,
  single-level, multi-level.
- Add assembly coverage report for every compiled decapsulation object.
- Add a "not proven" statement that remains machine-checkable.

Repository incorporation:

- Add `scripts/ct_experiment_matrix.json`.
- Add `scripts/run_ct_hardware_capture.py`.
- Add `scripts/verify_ct_experiment_claims.py`.
- Add `docs/side-channel-evidence-methodology.md`.
- Add claims:
  - `security.ct_hardware_campaign`;
  - `security.static_ct_coverage`;
  - `security.side_channel_non_claims`.

### Paper weakness 6: ACVP is not validated against a real server workflow

Current state:

- ACVP JSON fixtures and serial bridge exist.
- Positive and negative parser tests are good.

Required experiment:

- Implement an offline ACVP session emulator:
  - registration object;
  - vector-set object;
  - response object;
  - verdict object;
  - unsupported field behavior;
  - malformed group behavior.
- Later, add optional real-server integration if credentials are available.

Repository incorporation:

- Add `scripts/acvp_session_emulator.py`.
- Add `scripts/verify_acvp_session_artifacts.py`.
- Add `scripts/test_acvp_session_emulator.py`.
- Add `docs/acvp-interop-methodology.md`.
- Add output:
  - `acvp_session_result.json`;
  - `acvp_session_transcript_manifest.json`;
  - `acvp_session_coverage.md`.

## Why The Current Project Is Not Yet A Convincing Product

The repository can be shared with technical collaborators, but a product needs
more than technical depth. It needs a predictable adoption path, support model,
versioning model, compatibility guarantees, security-response workflow,
evidence-pack stability, and a user experience that does not require reading
100 scripts.

### Product weakness 1: unclear install and support contract

Current state:

- README has west setup and consumer integration.
- `docs/release.md` explains local release packaging.
- `SECURITY.md` and `CONTRIBUTING.md` exist.

Missing product evidence:

- exact supported host OS matrix;
- exact supported Zephyr SDK version;
- exact supported Zephyr revision and upgrade policy;
- exact supported board list by profile;
- compatibility guarantee for 1.0.x;
- deprecation policy for scripts/artifacts;
- support response tiers for partners.

Implementation:

- Add `docs/support-policy.md`.
- Add `scripts/support_matrix.json`.
- Add `scripts/verify_support_matrix.py`.
- Release output:
  - `support_matrix_result.json`.
- README:
  - link support policy near quickstart.

### Product weakness 2: too many scripts without role-based entry points

Current state:

- There are 101 top-level Python scripts.
- `run_local_tool_tests.py`, `release_check.py`, and
  `verify_product_readiness.py` help, but the repo still feels complex.

Missing product evidence:

- role-based commands:
  - "I am a consumer";
  - "I am a reviewer";
  - "I am a maintainer";
  - "I am a hardware evaluator";
  - "I am a security reviewer".

Implementation:

- Add `scripts/pqcp_tool.py` with subcommands:
  - `consumer-smoke`;
  - `release-pack`;
  - `replay-pack`;
  - `hardware-campaign`;
  - `security-campaign`;
  - `paper-pack`;
  - `support-matrix`.
- Internally call existing scripts.
- Do not reimplement validation logic.
- Tests:
  - `scripts/test_pqcp_tool_cli.py`.
- Docs:
  - update `docs/partner-evaluation-guide.md`.

### Product weakness 3: no production dashboard in repo

Current state:

- There has been design work outside the repository.
- The repo has JSON artifacts that are perfect for a dashboard.
- There is no integrated, tested dashboard app.

Missing product evidence:

- local static dashboard that imports an evidence pack;
- no backend server required;
- schema-aware parser;
- red/yellow/green policy view;
- drill-down from claim to source/test/artifact/hash;
- hardware-vs-QEMU badges;
- exportable partner report.

Implementation:

- Add `ui/assurance-dashboard/`.
- Use React/TypeScript or plain static TypeScript build, but keep it
  optional and isolated.
- Inputs:
  - release output directory upload;
  - `assurance_ledger.json`;
  - `pqc_cbom.cdx.json`;
  - `pqc_policy_result.json`;
  - `pqc_reference_values.json`;
  - `benchmark_campaign_result.json`;
  - `partner_review_scorecard.json`.
- Outputs:
  - local-only rendered dashboard;
  - no telemetry;
  - exportable HTML summary.
- Tests:
  - parser unit tests against synthetic packs;
  - fixture pack with deliberate missing artifact;
  - visual smoke if browser tooling is available.

### Product weakness 4: no artifact package contract

Current state:

- Release output is a directory with many generated files.
- `verify_release_evidence_pack.py` knows which files to expect.

Missing product evidence:

- a stable package manifest for partners;
- compressed bundle format;
- versioned artifact list;
- minimum required artifacts by profile;
- optional artifact list by environment;
- evidence pack README generated into each pack.

Implementation:

- Add `scripts/package_evidence_pack.py`.
- It should:
  - verify pack first;
  - write `EVIDENCE_PACK_README.md`;
  - write `artifact-index.json`;
  - create `.tar.gz`;
  - hash tarball;
  - optionally produce detached signature later.
- Add `scripts/verify_pack_archive.py`.
- Add docs:
  - `docs/evidence-pack-format.md`.

## Roadmap Overview

The roadmap is split into five tracks. Each track should produce code,
tests, release artifacts, and documentation. The tracks are ordered by
research/product leverage.

### Track A: Evidence integrity and schema discipline

Goal: make every generated artifact schema-validated and mutation-tested.

Why first:

- It strengthens the existing unique asset: claim-to-evidence replay.
- It can be done locally without hardware.
- It creates paper-ready evidence that the Passport catches real drift.

Tasks:

1. Add `schemas/` for every generated artifact.
2. Add `scripts/validate_release_schemas.py`.
3. Add `scripts/evidence_mutation_matrix.json`.
4. Extend `scripts/run_evidence_tamper_drill.py` into campaign mode.
5. Add `scripts/summarize_evidence_mutation_campaign.py`.
6. Add `docs/evidence-integrity-methodology.md`.
7. Add claims:
   - `release.schema_validation`;
   - `release.evidence_mutation_campaign`;
   - `release.artifact_schema_registry`.

Expected outputs:

- `schema_validation_result.json`
- `evidence_mutation_campaign_result.json`
- `evidence_mutation_detection_matrix.csv`
- `evidence_mutation_campaign.md`

Pass criteria:

- 100 percent of required release JSON artifacts validate against schemas.
- Every configured mutation is detected by at least one intended verifier.
- False-pass mutations fail the campaign.

### Track B: Physical benchmark and hardware campaign

Goal: replace QEMU-only performance claims with physically measured,
distributional, comparable evidence.

Tasks:

1. Add board registry and campaign matrix.
2. Extend hardware runner to execute repeated operations.
3. Capture UART transcripts and environment metadata.
4. Record clock source and compiler flags.
5. Measure stack and ROM/RAM per profile.
6. Normalize external reference rows.
7. Add comparison report.

Expected outputs:

- `hardware_benchmark_campaign_result.json`
- `hardware_benchmark_distribution.csv`
- `hardware_benchmark_transcript_manifest.json`
- `hardware_benchmark_report.md`
- `benchmark_reference_comparison.json`

Pass criteria:

- Each paper-candidate hardware row has at least 100 samples.
- Each row has median, p90, p99, max, MAD, ROM, RAM, stack, and transcript
  hash.
- Reference comparisons with missing clock/platform/compiler metadata fail.

### Track C: ACVP and parser adversarial campaign

Goal: turn ACVP from harness tests into an interop and robustness campaign.

Tasks:

1. Add deterministic parser fuzzer.
2. Add generated corpus ztest.
3. Add offline ACVP session emulator.
4. Add parser latency campaign.
5. Add serial soak test mode.

Expected outputs:

- `acvp_parser_campaign_result.json`
- `acvp_parser_latency.csv`
- `acvp_session_result.json`
- `acvp_session_coverage.md`
- `acvp_soak_transcript_manifest.json`

Pass criteria:

- All floor scenarios preserved.
- Fuzzer corpus has no hangs, no unbounded buffer growth, no wrong recovery
  state.
- JSON session emulator covers keyGen, encap, decap, sigGen, sigVer,
  malformed-then-valid recovery, unsupported parameter set, invalid hex, and
  wrong sizes.

### Track D: Side-channel evidence escalation

Goal: separate smoke, static policy, and physical evidence tiers.

Tasks:

1. Add side-channel campaign matrix.
2. Add hardware sample capture mode.
3. Add fixed-versus-random analysis.
4. Extend static disassembly scanner.
5. Add non-claim policy artifact.

Expected outputs:

- `side_channel_campaign_result.json`
- `side_channel_trace_manifest.json`
- `static_ct_coverage_result.json`
- `side_channel_non_claims.json`

Pass criteria:

- QEMU smoke can pass without hardware.
- Hardware profile cannot be marked fully side-channel-reviewed without
  physical evidence.
- Static scanner records symbol coverage for every required object.

### Track E: Productization and partner adoption

Goal: make the repository consumable by external teams without hand-holding.

Tasks:

1. Add support policy and compatibility matrix.
2. Add role-based CLI wrapper.
3. Add evidence pack archive format.
4. Add optional dashboard app.
5. Add partner evaluation guide.

Expected outputs:

- `support_matrix_result.json`
- `artifact-index.json`
- `EVIDENCE_PACK_README.md`
- `pqcp-evidence-pack-<tag>.tar.gz`
- dashboard import smoke tests

Pass criteria:

- A partner can run one command to consume, one command to generate, one
  command to replay.
- Evidence-pack archive verifies after extraction.
- Dashboard never labels QEMU evidence as hardware evidence.

## Implementation Backlog By File

### `scripts/release_check.py`

Add new full-local steps only; keep `--ci` fast.

Add after current Passport/appraisal generation:

- schema validation step;
- evidence mutation campaign step;
- compatibility matrix step;
- support matrix verification step;
- optional hardware benchmark campaign if explicitly requested;
- optional side-channel hardware campaign if explicitly requested.

Do not add physical hardware requirements to default CI or QEMU release mode.

### `scripts/verify_release_evidence_pack.py`

Add schema-version-gated requirements:

- if pack schema >= 8:
  - require `schema_validation_result.json`;
  - require `evidence_mutation_campaign_result.json`;
  - require `compatibility_matrix_result.json`;
  - require `support_matrix_result.json`;
  - require `artifact-index.json` if pack archive mode is used.

Replay each artifact from primary files, not summary booleans.

### `scripts/assurance_claims.json`

Add additive claims for next schema:

- `release.schema_validation`
- `release.evidence_mutation_campaign`
- `release.artifact_schema_registry`
- `benchmark.hardware_campaign`
- `benchmark.energy_campaign`
- `acvp.parser_campaign`
- `acvp.session_emulation`
- `security.side_channel_campaign`
- `security.static_ct_coverage`
- `product.support_matrix`
- `product.partner_packaging`
- `product.consumer_smoke_archive`

Each claim must name a concrete script and output artifact.

### `scripts/pqc_assurance_policy.json`

Add new required claim IDs only for full local and partner-review modes.
Do not require hardware-only claims for QEMU release mode unless they are
explicitly allowed as `not_available` with a recorded reason.

### `scripts/pqc_evidence_quality.json`

Add evidence classes:

- `schema_replay`
- `mutation_campaign`
- `hardware_distribution`
- `energy_measurement`
- `serial_soak`
- `physical_side_channel`
- `support_matrix`
- `archive_replay`

### `scripts/pqc_asset_trace_map.json`

Add trace assets:

- `evidence.schema_registry`
- `evidence.mutation_campaign`
- `benchmark.hardware_campaign`
- `acvp.parser_campaign`
- `security.side_channel_campaign`
- `product.evidence_pack_archive`
- `product.compatibility_matrix`

### `docs/assurance-model.md`

Add a "Limits of replay" section:

- replay proves artifact coherence;
- replay does not prove physical execution unless physical transcripts exist;
- unsigned evidence is tamper-evident after generation, not origin-authentic;
- schema validation and mutation campaigns are required for stronger claims.

### `docs/pqc-assurance-passport.md`

Add a "Passport tiers" section:

- Tier 0: CI fast gate;
- Tier 1: QEMU local release;
- Tier 2: partner-review QEMU plus mutation campaign;
- Tier 3: hardware benchmark and side-channel campaign;
- Tier 4: signed and remotely appraised pack.

### `docs/performance-methodology.md`

Add:

- physical board campaign rules;
- sample counts;
- confidence interval requirements;
- what counts as paper-comparable;
- how external reference rows are normalized;
- why QEMU rows are regression evidence only.

### `docs/api-overview.md`

Add:

- explicit "API stability test" section;
- explain how to run symbol diff once implemented;
- define what can change in 1.0.x.

### `docs/release.md`

Add:

- evidence pack archive workflow;
- schema validation workflow;
- mutation campaign workflow;
- hardware campaign optional workflow.

### `README.md`

Do not add more long technical content. Add a small "Evidence tiers" table
after "What is novel here?" once implemented.

## Concrete Experiment Plan For A Strong Paper

### Experiment 1: Evidence mutation detection

Question:

Can the Passport replay system detect common release-evidence failures better
than simpler alternatives?

Implementation:

- Use `scripts/run_evidence_tamper_drill.py` campaign mode.
- Generate at least 50 mutations.
- Compare detection by:
  - full evidence pack verifier;
  - ledger verifier only;
  - benchmark provenance verifier only;
  - schema validator only;
  - manual checklist presence.

Metrics:

- detection rate;
- false-pass count;
- false-fail count;
- diagnostic specificity;
- time to verify;
- artifact count.

Paper table:

| Mutation class | Full replay | Ledger only | Schema only | CSV provenance only | Checklist |
|---|---:|---:|---:|---:|---:|
| Transcript removed | pass/fail | pass/fail | pass/fail | pass/fail | pass/fail |
| CBOM stale component | pass/fail | pass/fail | pass/fail | pass/fail | pass/fail |
| Backend pin drift | pass/fail | pass/fail | pass/fail | pass/fail | pass/fail |

Expected repository outputs:

- `evidence_mutation_detection_matrix.csv`
- `evidence_mutation_campaign_result.json`
- `evidence_mutation_campaign.md`

### Experiment 2: Hardware performance campaign

Question:

What is the physical performance/footprint cost of the Zephyr wrapper,
profiles, and assurance instrumentation?

Implementation:

- Use hardware campaign matrix.
- Boards:
  - high-end MCU gateway board;
  - Cortex-M4-class board;
  - constrained Cortex-M0+/RP2040-style board if memory permits.
- Operations:
  - ML-KEM keygen, encaps, decaps;
  - ML-DSA keygen, sign, verify;
  - protocol handshake path;
  - ACVP parser throughput.
- Profiles:
  - qemu release;
  - constrained MCU;
  - gateway;
  - native lab only where appropriate.

Metrics:

- cycles;
- microseconds;
- ROM;
- RAM;
- stack;
- energy where available;
- transcript hash;
- failure count.

Expected repository outputs:

- `hardware_benchmark_distribution.csv`
- `hardware_benchmark_campaign_result.json`
- `hardware_benchmark_report.md`

### Experiment 3: Backend and build-option ablation

Question:

Which build options improve speed, memory, or stack without weakening replayed
evidence?

Implementation:

- Extend `scripts/optimize_metric_campaign.py`.
- Candidate options:
  - optimization level;
  - LTO;
  - monolithic host build;
  - single-level build;
  - force native backend;
  - force portable C backend;
  - reduced RAM;
  - stack right sizing.
- Keep/reject policy:
  - median improves by threshold;
  - p90/p99 do not regress beyond threshold;
  - ROM/RAM within budget;
  - CT smoke remains clean;
  - negative scenarios preserved;
  - backend contract passes.

Expected repository outputs:

- `optimization_campaign_result.json`
- `optimization_candidate_matrix.csv`
- `optimization_report.md`

### Experiment 4: ACVP parser adversarial campaign

Question:

Does the bounded ACVP parser remain correct and recoverable under high-volume
malformed input?

Implementation:

- Generate deterministic fuzz corpus.
- Run corpus through C ztest and host translator.
- Add UART soak mode.

Metrics:

- accepted valid commands;
- rejected invalid commands by error class;
- recovery success;
- timeouts;
- maximum latency;
- no hang;
- no memory overrun;
- no scenario floor regression.

Expected repository outputs:

- `acvp_parser_campaign_result.json`
- `acvp_parser_latency.csv`
- `acvp_soak_transcript_manifest.json`

### Experiment 5: Side-channel evidence tiers

Question:

Which side-channel regression classes can the repo detect automatically, and
which require external lab measurement?

Implementation:

- Run QEMU smoke.
- Run hardware cycle counter campaign.
- Import optional traces from lab equipment.
- Run static scanner.

Metrics:

- valid/invalid class count;
- t-statistic;
- median delta;
- p90/p99 delta;
- symbol coverage;
- division/helper findings;
- branch/table warnings.

Expected repository outputs:

- `side_channel_campaign_result.json`
- `static_ct_coverage_result.json`
- `side_channel_non_claims.json`

## Product Strategy In Ten Pages Of Substance

### Target users

Primary users:

- embedded security teams evaluating PQC migration on Zephyr;
- firmware vendors needing partner-review evidence;
- product security teams reviewing cryptographic inventory and release
  evidence;
- academic/system-security reviewers who need reproducible artifacts;
- internal compliance teams preparing for PQC migration inventories.

Secondary users:

- hardware labs measuring side-channel behavior;
- protocol teams testing PQC TLS or serial validation;
- board-support teams validating stack/ROM/RAM feasibility;
- security architects defining crypto-agility profiles.

### Product promise

The product should not promise "certified PQC" or "formally constant-time."
The defensible promise is:

> A Zephyr PQC module that produces replay-verifiable local evidence tying
> source, configuration, crypto inventory, tests, transcripts, benchmarks,
> profiles, and policy decisions into a partner-review package.

That is credible because the repo already has most of the skeleton.

### Differentiation

Compared with a raw cryptographic library:

- this project includes Zephyr integration;
- profile-specific Kconfig;
- ACVP serial validation;
- local release evidence;
- replay verification;
- asset traceability;
- profile policy.

Compared with a benchmark framework:

- this project has release claims and partner policy;
- it can bind benchmark transcripts to release artifacts;
- it can integrate CBOM and reference values;
- it can distinguish regression evidence from physical performance.

Compared with an SBOM-only tool:

- this project can run and bind tests;
- it can connect claim IDs to artifacts and transcripts;
- it can detect mutations;
- it can express crypto-specific policy.

Compared with a CI-only release gate:

- this project can replay evidence without CI access;
- it can be shared with external partners;
- it can record local hardware evidence.

### Product packaging model

Minimum product package:

- source repository access under proprietary evaluation license;
- pinned west manifest;
- release evidence pack archive;
- support matrix;
- partner evaluation guide;
- security disclosure policy;
- one-command replay verifier;
- dashboard or static HTML report;
- known limitations and non-claims.

Partner deliverable:

- `pqcp-evidence-pack-<tag>.tar.gz`;
- `artifact-index.json`;
- `EVIDENCE_PACK_README.md`;
- `assurance_report.html`;
- `partner_review_scorecard.md`;
- `compatibility_matrix.md`;
- `support-policy.md`.

### Pricing and commercialization direction

The repository should not be positioned as a general open library. It is
better positioned as:

- engineering evaluation kit;
- embedded PQC evidence toolkit;
- partner-review package generator;
- Zephyr PQC integration accelerator;
- consulting-supported validation stack.

Possible paid offerings:

- partner-specific board validation campaign;
- evidence-pack generation and review;
- PQC migration profile mapping;
- side-channel lab integration;
- custom ACVP workflow support;
- release-signing and provenance integration.

### Product risks

- If physical hardware evidence is missing, partners will treat performance
  claims as non-final.
- If schema validation is missing, partners may view the evidence pack as
  ad-hoc JSON.
- If attestation remains unsigned, partners must trust the transport of the
  evidence pack.
- If external provider policy is not communicated clearly, reviewers may worry
  that implementation sources drift.
- If the dashboard is not connected to real artifacts, it becomes marketing
  rather than product evidence.

### Product milestones

Milestone 1: "Replayable local evidence"

- Already mostly complete.
- Finish schema registry and mutation campaign.

Milestone 2: "Partner evaluation kit"

- Add support matrix, partner guide, pack archive, dashboard import.

Milestone 3: "Hardware-validated profile"

- Add physical benchmark campaign and hardware CT evidence tier.

Milestone 4: "Signed evidence release"

- Add DSSE/signature path after key custody policy.

Milestone 5: "Research artifact"

- Add paper experiment runner, mutation matrix, hardware results, and
  reproducible artifact bundle.

## Architecture Gaps And Concrete Fixes

### Gap: no artifact schema registry

Risk:

- Reviewers cannot distinguish intentional artifact shape from accidental JSON.
- Schema drift may pass if verifier logic only checks selected fields.

Fix:

- Add `schemas/`.
- Add schema validation step.
- Add schema result to release pack.

Files:

- new: `schemas/*.schema.json`
- new: `scripts/validate_release_schemas.py`
- update: `scripts/release_check.py`
- update: `scripts/verify_release_evidence_pack.py`
- update: `scripts/assurance_claims.json`

### Gap: physical evidence is optional and under-specified

Risk:

- QEMU numbers are overinterpreted.
- Hardware partners cannot compare results.

Fix:

- Add hardware campaign matrix and report.
- Make physical evidence required for hardware profile, optional for QEMU
  profile.

Files:

- new: `scripts/hardware_board_registry.json`
- new: `scripts/hardware_benchmark_campaign.json`
- update: `scripts/run_hardware_benchmarks.py`
- new: `scripts/verify_hardware_benchmark_campaign.py`
- new: `docs/hardware-benchmark-methodology.md`

### Gap: ACVP JSON interop is not full session evidence

Risk:

- A reviewer may mistake fixture translation for official server validation.

Fix:

- Add ACVP session emulator and conformance report.
- Clearly label "offline interop" versus "server validation."

Files:

- new: `scripts/acvp_session_emulator.py`
- new: `scripts/verify_acvp_session_artifacts.py`
- new: `docs/acvp-interop-methodology.md`

### Gap: side-channel evidence is smoke-only

Risk:

- CT smoke could be misread as a security proof.

Fix:

- Add machine-readable side-channel non-claims.
- Add hardware campaign tier.
- Add static coverage report.

Files:

- new: `scripts/side_channel_campaign_matrix.json`
- new: `scripts/run_side_channel_campaign.py`
- new: `scripts/verify_side_channel_non_claims.py`
- new: `docs/side-channel-evidence-methodology.md`

### Gap: no API/ABI drift enforcement

Risk:

- Public headers can change accidentally without a clear compatibility signal.

Fix:

- Add symbol/API snapshot generator.
- Compare public headers and exported symbols between releases.

Files:

- new: `scripts/generate_api_snapshot.py`
- new: `scripts/verify_api_snapshot.py`
- new: `api/pqcp-api-v1.0.0.json`
- update: `docs/api-overview.md`

### Gap: generated release docs are not packaged as a stable archive

Risk:

- Partners receive a directory without a formal package boundary.

Fix:

- Add pack archive creation and verification.

Files:

- new: `scripts/package_evidence_pack.py`
- new: `scripts/verify_pack_archive.py`
- new: `docs/evidence-pack-format.md`

### Gap: research experiments are not orchestrated

Risk:

- Paper results become manually curated and non-reproducible.

Fix:

- Add paper experiment runner and matrix.

Files:

- new: `scripts/paper_experiment_matrix.json`
- new: `scripts/run_paper_experiments.py`
- new: `scripts/verify_paper_experiment_pack.py`
- new: `docs/paper-evaluation-plan.md`

## Priority Implementation Plan

### Patch 1: Schema registry and artifact-shape replay

Why:

- Highest leverage without hardware.
- Strengthens current Passport.

Implementation:

1. Add JSON schemas for current required artifacts.
2. Add validator.
3. Add tests with missing fields, wrong enums, stale hashes.
4. Integrate full release only.

Validation:

- `python3 -m py_compile scripts/*.py`
- `python3 scripts/test_release_schema_validation.py`
- `python3 scripts/release_check.py --tag v1.0.0 --output-root /tmp/pqcp-schema-pack`
- `python3 scripts/verify_release_evidence_pack.py /tmp/pqcp-schema-pack --tag v1.0.0`

### Patch 2: Evidence mutation campaign

Why:

- Converts assurance from "we emit artifacts" into "we detect tampering and
  drift."

Implementation:

1. Add mutation matrix.
2. Extend tamper drill.
3. Add detection matrix summary.
4. Add paper-ready markdown.

Validation:

- `python3 scripts/test_evidence_mutation_campaign.py`
- full local release.

### Patch 3: Hardware benchmark campaign scaffold

Why:

- Product and paper both need physical evidence.

Implementation:

1. Add board registry.
2. Extend hardware runner.
3. Add transcript binding.
4. Add no-hardware not-available mode.

Validation:

- synthetic transcript tests;
- QEMU lane;
- hardware lane when board present.

### Patch 4: ACVP parser campaign

Why:

- Parser robustness is a concrete product differentiator.

Implementation:

1. Add corpus generator.
2. Add ztest generated header.
3. Add latency/reporting.
4. Add JSON session emulator.

Validation:

- ztest on QEMU;
- Python parser campaign tests.

### Patch 5: Product package archive and partner guide

Why:

- Makes external sharing easier.

Implementation:

1. Add archive packer.
2. Add verifier.
3. Add generated README.
4. Add partner guide.

Validation:

- generate archive;
- extract to temp directory;
- verify pack.

### Patch 6: API stability snapshot

Why:

- Needed for credible product versioning.

Implementation:

1. Generate public header/API snapshot.
2. Check against current release.
3. Add changelog gate.

Validation:

- tests for breaking symbol removal.

### Patch 7: Paper experiment runner

Why:

- Needed to avoid manual, cherry-picked results.

Implementation:

1. Add experiment matrix.
2. Orchestrate mutation, benchmark, ACVP, CT, and replay experiments.
3. Produce tables.

Validation:

- synthetic experiment pack test.

## Minimum Criteria For "Paper-Ready"

The project becomes paper-ready when the repository can generate an artifact
bundle that includes:

- a clear research question and threat model;
- hardware benchmark data on at least two physical board classes;
- repeated measurements with distributions;
- comparison against at least one accepted benchmark framework or normalized
  external dataset;
- evidence mutation campaign showing detection rates;
- ACVP parser adversarial campaign;
- side-channel evidence tiering with explicit non-claims;
- schema-validated evidence pack;
- replay command that works from a clean checkout;
- archived artifact bundle with exact source commit and dependency pins.

Minimum paper tables:

- Claim coverage by evidence class.
- Mutation detection matrix.
- Hardware performance distribution by board/profile/parameter set.
- ROM/RAM/stack by profile.
- ACVP parser robustness and recovery matrix.
- Side-channel smoke/static/hardware evidence tier matrix.
- Release pack size and replay time.
- Comparison against QEMU-only and checklist-only baselines.

## Minimum Criteria For "Product-Ready"

The project becomes product-ready when it can support an external partner with:

- clear proprietary evaluation terms;
- support policy;
- compatibility matrix;
- one-command consumer smoke;
- one-command evidence pack generation;
- one-command replay;
- packaged archive with artifact index;
- dashboard or HTML report that reads a real pack;
- security disclosure process;
- versioned schema migration guide;
- physical board validation for at least one supported hardware profile;
- documented non-claims;
- no ambiguous test-only/production path.

## Current Readiness Classification

Code readiness:

- Strong for local development and QEMU validation.
- Not yet fully product-ready for external hardware adoption.

Evidence readiness:

- Strong for local artifact coherence.
- Weak for physical performance, side-channel, and official validation claims.

Research readiness:

- Promising research direction.
- Not yet enough experimental data or baseline comparison for a strong paper.

Product readiness:

- Good for controlled collaborator review.
- Not yet a polished SDK/evidence product.

Partner shareability:

- Shareable with careful caveats.
- Should include `README.md`, `LICENSE`, `SECURITY.md`,
  `docs/release.md`, `docs/assurance-model.md`,
  `docs/pqc-assurance-passport.md`, and this audit.

Do not tell partners:

- that QEMU numbers are hardware performance;
- that CT smoke proves constant-time security;
- that local ACVP JSON interop is official validation;
- that unsigned attestations prove identity;
- that the evidence pack is a certification.

Do tell partners:

- the repo gives a replayable local evidence package;
- every release claim maps to concrete artifacts;
- transcripts and hashes make drift visible;
- production/test profile separation is executable;
- hardware evidence is the next validation tier.

## Detailed Implementation Epics

This section converts the roadmap into concrete repository epics. Each epic is
intended to become one or more patch sets. Do not treat these as vague ideas:
each item names files, inputs, outputs, tests, and promotion criteria.

### Epic 1: Versioned artifact schema registry

Problem:

- The release pack has many JSON artifacts.
- Each verifier currently checks the subset of fields it needs.
- A reviewer cannot inspect one place and learn the complete expected shape of
  every artifact.

Repository changes:

- Add directory `schemas/`.
- Add one JSON schema per generated artifact.
- Add `scripts/validate_release_schemas.py`.
- Add `scripts/test_release_schema_validation.py`.
- Add `docs/evidence-pack-format.md`.
- Update `scripts/release_check.py`.
- Update `scripts/verify_release_evidence_pack.py`.

Initial schema list:

- `assurance-ledger.schema.json`
- `transcript-manifest.schema.json`
- `pqc-cbom-profile.schema.json`
- `pqc-policy-result.schema.json`
- `pqc-attestation-predicate.schema.json`
- `pqc-build-provenance.schema.json`
- `pqc-reference-values.schema.json`
- `pqc-assurance-digest.schema.json`
- `benchmark-campaign.schema.json`
- `benchmark-confidence.schema.json`
- `acvp-json-interop.schema.json`
- `ct-sample-analysis.schema.json`
- `backend-contract.schema.json`
- `provider-scope.schema.json`
- `partner-scorecard.schema.json`

Implementation notes:

- Use only Python standard library unless a JSON schema dependency is already
  accepted for the project.
- If full JSON Schema validation would add a dependency, implement a minimal
  local structural validator first and document the subset.
- Every schema must define:
  - `schema_version`;
  - `generated_at`;
  - `generator` where applicable;
  - `passed` where applicable;
  - `failures`;
  - hash field pattern;
  - relative path field rules.
- Do not allow absolute host paths in shareable artifacts unless explicitly
  marked as local-only.

Tests:

- valid synthetic artifact passes;
- missing required field fails;
- wrong schema version fails;
- malformed hash fails;
- unexpected pass/fail enum fails;
- absolute path in shareable artifact fails;
- stale generated artifact with older schema emits degraded replay only when
  allowlisted.

Acceptance criteria:

- Full local release emits `schema_validation_result.json`.
- `verify_release_evidence_pack.py` independently validates every artifact
  listed in the release manifest.
- The partner scorecard includes schema validation status.

### Epic 2: Evidence mutation campaign

Problem:

- The current tamper drill proves selected relationships.
- It does not yet quantify detection coverage across the whole evidence graph.

Repository changes:

- Add `scripts/evidence_mutation_matrix.json`.
- Extend `scripts/run_evidence_tamper_drill.py` with `--campaign`.
- Add `scripts/summarize_evidence_mutation_campaign.py`.
- Add `scripts/test_evidence_mutation_campaign.py`.
- Add `docs/evidence-integrity-methodology.md`.

Mutation classes:

- remove required transcript file;
- truncate transcript file to zero bytes;
- alter transcript byte while preserving filename;
- change transcript hash in manifest;
- remove QEMU stdout transcript row;
- alter benchmark CSV without updating provenance;
- update benchmark provenance without updating CSV;
- remove one benchmark campaign statistic field;
- set `p99` greater than `max`;
- remove one KAT vector file;
- alter one generated KAT constant;
- remove one ACVP negative scenario floor row;
- weaken one ACVP error response;
- duplicate one ACVP negative scenario name;
- mark deterministic RNG as production-enabled;
- remove backend contract artifact;
- change native backend SHA in release manifest;
- alter CBOM component ID;
- remove required CBOM property;
- change policy result from fail to pass;
- remove not-applicable reason;
- alter reference-value digest root;
- alter firmware status digest;
- remove CT sample manifest;
- duplicate CT sample index;
- remove device evidence nonce;
- alter partner scorecard finding count;
- remove evidence graph edge;
- change release tag in manifest;
- change release source commit;
- toggle dirty flag.

Expected result:

- Every mutation must be detected by at least one intended verifier.
- The campaign must record which verifier caught it.
- If a mutation is intentionally out of scope, the matrix must say why.

Outputs:

- `evidence_mutation_campaign_result.json`
- `evidence_mutation_detection_matrix.csv`
- `evidence_mutation_campaign.md`

Research value:

- This supplies a measurable contribution: detection coverage under controlled
  artifact drift.

Product value:

- Partners can see that the pack is not just many files; its links are tested
  against adversarial edits.

### Epic 3: Physical hardware benchmark campaign

Problem:

- QEMU results are not physical performance evidence.
- Existing MCU rows are footprint-oriented and build-only.

Repository changes:

- Add `scripts/hardware_board_registry.json`.
- Add `scripts/hardware_benchmark_campaign.json`.
- Extend `scripts/run_hardware_benchmarks.py`.
- Add `scripts/verify_hardware_benchmark_campaign.py`.
- Add `scripts/import_hardware_reference_csv.py`.
- Add `docs/hardware-benchmark-methodology.md`.

Board registry fields:

- board ID;
- Zephyr board name;
- MCU family;
- core architecture;
- clock source;
- nominal frequency;
- flash size;
- RAM size;
- UART device;
- flash command;
- reset command;
- whether DWT/cycle counter is available;
- whether energy capture is available;
- profile support list.

Campaign row fields:

- board ID;
- profile;
- sample path;
- parameter set;
- operation;
- implementation;
- backend policy;
- repetitions;
- warmups;
- timeout;
- expected success marker;
- transcript marker list;
- measurement source;
- paper-comparable flag.

Outputs:

- `hardware_benchmark_raw.csv`
- `hardware_benchmark_distribution.csv`
- `hardware_benchmark_campaign_result.json`
- `hardware_benchmark_environment.json`
- `hardware_benchmark_transcript_manifest.json`
- `hardware_benchmark_report.md`

Acceptance criteria:

- Hardware absence is `not_available` unless hardware mode is explicitly
  required.
- A hardware row cannot be marked paper-comparable without at least 100 samples
  or an explicitly justified threshold.
- Every hardware row records board, clock, compiler, flags, Zephyr revision,
  SDK version, backend family, and transcript hash.
- QEMU rows cannot satisfy hardware-only claims.

### Epic 4: Stack, heap, and memory-pressure analysis

Problem:

- ROM/RAM budgets exist, but peak stack and heap pressure are not yet first
  class across all operations and profiles.

Repository changes:

- Add `scripts/analyze_stack_usage.py`.
- Add `scripts/run_memory_pressure_campaign.py`.
- Add `scripts/verify_memory_pressure.py`.
- Add `docs/memory-footprint-methodology.md`.

Inputs:

- Zephyr map files;
- size output;
- stack analyzer output if available;
- benchmark transcripts;
- profile matrix;
- resource budgets.

Outputs:

- `memory_pressure_result.json`
- `stack_usage_by_symbol.csv`
- `memory_pressure_report.md`

Checks:

- all production profiles within ROM/RAM budget;
- stack margin above configured threshold;
- no operation uses test-only stack settings in production profile;
- single-level builds demonstrate expected footprint reduction;
- multi-level builds record expected footprint cost.

Research value:

- Embedded PQC papers often report cycles but under-report stack and memory
  pressure. This repo can compete by making memory pressure reproducible and
  profile-specific.

### Epic 5: ACVP parser fuzz and session emulation

Problem:

- Parser negative tests are strong but finite.
- JSON interop is local translation, not session-level workflow.

Repository changes:

- Add `scripts/fuzz_acvp_parser_cases.py`.
- Add `tests/ztest_acvp_serial_fuzz/`.
- Add `scripts/acvp_session_emulator.py`.
- Add `scripts/verify_acvp_session_artifacts.py`.
- Add `docs/acvp-interop-methodology.md`.

Fuzz corpus dimensions:

- unknown command;
- lowercase command;
- mixed-case algorithm;
- odd-length hex;
- non-hex byte;
- empty payload;
- missing field;
- extra field;
- very long field;
- boundary-minus-one;
- exact boundary;
- boundary-plus-one;
- valid after invalid;
- timeout then valid;
- repeated separators;
- embedded whitespace;
- command with trailing data.

Outputs:

- `acvp_fuzz_corpus.json`
- `acvp_parser_campaign_result.json`
- `acvp_session_result.json`
- `acvp_session_coverage.md`

Acceptance criteria:

- No scenario from the existing floor is removed.
- Every generated malformed command maps to a documented error class.
- Recovery cases prove the parser returns to idle state.
- Session emulator distinguishes unsupported, invalid, and successful cases.

### Epic 6: Side-channel evidence tiers

Problem:

- Current CT smoke is honest but not enough for product-grade assurance.

Repository changes:

- Add `scripts/side_channel_campaign_matrix.json`.
- Add `scripts/run_side_channel_campaign.py`.
- Add `scripts/analyze_side_channel_campaign.py`.
- Add `scripts/verify_static_ct_coverage.py`.
- Add `scripts/verify_side_channel_non_claims.py`.
- Add `docs/side-channel-evidence-methodology.md`.

Evidence tiers:

- Tier 0: no side-channel claim.
- Tier 1: QEMU/runtime smoke.
- Tier 2: static instruction coverage.
- Tier 3: hardware cycle-counter campaign.
- Tier 4: lab trace import with acquisition metadata.
- Tier 5: external evaluation or formal proof.

Acceptance criteria:

- Release pack states the highest achieved tier per profile.
- QEMU release profile can pass at Tier 1/2.
- Hardware profile cannot claim Tier 3 without physical transcript metadata.
- Product docs never turn Tier 1 into a formal security proof.

### Epic 7: Product support matrix and evidence-pack archive

Problem:

- Partner adoption requires a stable package and support promise.

Repository changes:

- Add `docs/support-policy.md`.
- Add `docs/partner-evaluation-guide.md`.
- Add `docs/evidence-pack-format.md`.
- Add `scripts/support_matrix.json`.
- Add `scripts/verify_support_matrix.py`.
- Add `scripts/package_evidence_pack.py`.
- Add `scripts/verify_pack_archive.py`.

Support matrix fields:

- host OS;
- Python version;
- west version;
- Zephyr revision;
- SDK version;
- board;
- profile;
- sample;
- status;
- last verified commit;
- evidence artifact path.

Archive contents:

- `EVIDENCE_PACK_README.md`;
- `artifact-index.json`;
- all required evidence artifacts;
- release notes;
- schema validation result;
- scorecard;
- optional dashboard export.

Acceptance criteria:

- Archive verifies after extraction in a temp directory.
- Artifact index hashes every included file.
- Archive README states non-claims.

### Epic 8: API and ABI stability evidence

Problem:

- Public headers are documented but compatibility is not enforced
  mechanically.

Repository changes:

- Add `scripts/generate_api_snapshot.py`.
- Add `scripts/verify_api_snapshot.py`.
- Add `api/pqcp-api-v1.0.0.json`.
- Add `docs/api-stability-policy.md`.

Snapshot fields:

- header path;
- public macros;
- typedefs;
- enum values;
- public function names;
- parameter names and high-level types;
- size constants;
- stability tag;
- doc coverage status.

Acceptance criteria:

- Removing or renaming a public symbol fails unless a breaking-change flag is
  supplied.
- Adding a new symbol is allowed but must include doc comments.
- Changing wire-format constants fails unless explicitly approved.

### Epic 9: Release signing and origin authenticity

Problem:

- Current evidence is hash-bound but unsigned.

Repository changes:

- Add `docs/signing-policy.md`.
- Add `scripts/sign_evidence_digest.py`.
- Add `scripts/verify_evidence_signature.py`.

Do this only after:

- key custody is defined;
- signer identity is approved;
- offline signing workflow is documented;
- rotation/revocation policy exists.

Acceptance criteria:

- Signed digest can be verified without rebuilding.
- Unsigned packs remain allowed for local development but cannot be labeled as
  signed partner-release packs.

### Epic 10: Research artifact bundle

Problem:

- A paper needs reproducible experiment artifacts, not just project docs.

Repository changes:

- Add `scripts/paper_experiment_matrix.json`.
- Add `scripts/run_paper_experiments.py`.
- Add `scripts/verify_paper_artifact_bundle.py`.
- Add `docs/paper-evaluation-plan.md`.

Paper bundle contents:

- experiment matrix;
- release pack;
- mutation campaign;
- hardware benchmark campaign;
- ACVP campaign;
- side-channel campaign;
- comparison datasets;
- scripts and commit hashes;
- generated tables.

Acceptance criteria:

- One command regenerates all tables that do not require hardware.
- Hardware-required rows are marked unavailable unless transcripts are present.
- Paper figures are generated from CSV/JSON, not hand-edited.

## Threat Model Gaps

The current project has many verifiers but no single explicit threat model
document. Add one. It should distinguish at least these adversaries.

### Adversary A: accidental maintainer drift

Examples:

- changes benchmark CSV but not provenance;
- deletes ACVP negative case;
- updates backend SHA inconsistently;
- edits release notes without bundle manifest update.

Current coverage:

- strong.

Missing:

- systematic mutation campaign.

### Adversary B: malicious artifact editor after release generation

Examples:

- changes ledger claim status;
- removes failing policy output;
- edits HTML report only;
- changes scorecard summary.

Current coverage:

- partial through replay and tamper drill.

Missing:

- full mutation matrix;
- archive-level index;
- signatures.

### Adversary C: compromised local build host

Examples:

- build host emits fake transcripts;
- malicious toolchain compiles different code;
- local Python script lies.

Current coverage:

- weak.

Needed:

- signed provenance from controlled builders;
- reproducible build comparison;
- independent verifier run by partner;
- toolchain hash capture;
- optional two-party evidence generation.

### Adversary D: runtime attacker on serial ACVP interface

Examples:

- malformed command flood;
- slow partial frame;
- oversize payload;
- recovery-state confusion;
- valid command after malformed input.

Current coverage:

- good finite negative tests.

Needed:

- fuzz campaign;
- UART soak;
- parser latency and resource bounds.

### Adversary E: side-channel observer

Examples:

- timing valid versus invalid decapsulation;
- cache/memory access observation;
- branch predictor leakage;
- power/EM leakage.

Current coverage:

- smoke only.

Needed:

- hardware campaign;
- formal/static coverage;
- lab trace import;
- non-claims policy.

### Adversary F: downstream integrator misconfiguration

Examples:

- deterministic RNG in production;
- lab profile in product image;
- baseline provider used outside intended environment;
- wrong Zephyr revision;
- stale backend pin.

Current coverage:

- good policy foundations.

Needed:

- build configuration matrix;
- support matrix;
- dashboard warnings;
- consumer smoke archive.

## Data Model Additions

### `schema_validation_result.json`

Required fields:

- `schema_version`
- `generated_at`
- `generator`
- `passed`
- `artifact_count`
- `schemas`
- `artifacts`
- `failures`

Each artifact row:

- `path`
- `schema`
- `schema_version`
- `sha256`
- `passed`
- `failure_count`

### `evidence_mutation_campaign_result.json`

Required fields:

- `schema_version`
- `generated_at`
- `generator`
- `source_pack`
- `mutation_count`
- `detected_count`
- `undetected_count`
- `mutations`
- `failures`

Each mutation row:

- `id`
- `class`
- `artifact`
- `edit_description`
- `expected_detector`
- `actual_detectors`
- `detected`
- `diagnostic_fragment`

### `hardware_benchmark_campaign_result.json`

Required fields:

- `schema_version`
- `generated_at`
- `generator`
- `environment`
- `boards`
- `statistics`
- `transcript_manifest`
- `summary`
- `failures`

Each statistic row:

- `board`
- `profile`
- `parameter_set`
- `operation`
- `implementation`
- `backend`
- `sample_count`
- `min`
- `median`
- `p90`
- `p99`
- `max`
- `mad`
- `rom_bytes`
- `ram_bytes`
- `stack_bytes`
- `clock_hz`
- `compiler`
- `flags`
- `transcript_sha256`
- `paper_comparable`

### `acvp_parser_campaign_result.json`

Required fields:

- `schema_version`
- `generated_at`
- `generator`
- `corpus_sha256`
- `case_count`
- `passed`
- `cases`
- `summary`
- `failures`

Each case:

- `name`
- `category`
- `command`
- `expected_response_class`
- `actual_response`
- `latency_us`
- `recovered`
- `transcript_sha256`

### `side_channel_campaign_result.json`

Required fields:

- `schema_version`
- `generated_at`
- `generator`
- `tier`
- `environment`
- `algorithms`
- `non_claims`
- `failures`

Each algorithm:

- `algorithm`
- `parameter_set`
- `sample_count_valid`
- `sample_count_invalid`
- `median_delta`
- `p90_delta`
- `p99_delta`
- `welch_statistic`
- `effect_size`
- `passed_smoke`
- `hardware_evidence`
- `trace_manifest`

## Expected Paper Outline

### Abstract

State that the work presents a Zephyr-based embedded PQC module with a
replay-verifiable release evidence pipeline. The contribution is not a new
primitive. The contribution is an evidence architecture and evaluation showing
that claim-to-artifact replay detects release drift while supporting embedded
PQC validation and measurement.

### Introduction

Motivate:

- PQC migration is now standards-driven.
- Embedded/IoT systems need reproducible validation evidence.
- Existing libraries and benchmark frameworks do not fully solve partner
  review of firmware releases.
- Release evidence often lives in CI logs that reviewers cannot replay.

### Background

Cover:

- ML-KEM and ML-DSA standards;
- Zephyr module model;
- ACVP-style validation;
- CBOM and cryptographic inventory;
- in-toto/SLSA provenance;
- RATS appraisal concepts;
- embedded benchmarking practice;
- side-channel evidence limits.

### System design

Describe:

- backend contract;
- Zephyr wrapper architecture;
- ACVP serial harness;
- benchmark emitters;
- Assurance Ledger;
- Passport artifacts;
- reference values;
- policy replay;
- evidence pack verifier.

### Threat model

Use the adversary classes above.

### Evaluation

Experiments:

- mutation detection;
- QEMU release replay;
- hardware benchmark campaign;
- ACVP parser campaign;
- side-channel smoke/static/hardware tier;
- product replay time and artifact size.

### Results

Tables:

- claim coverage;
- mutation detection matrix;
- benchmark distributions;
- footprint;
- ACVP campaign;
- side-channel tiers;
- replay overhead.

### Limitations

State:

- no certification;
- no formal constant-time proof;
- QEMU is not hardware;
- unsigned evidence until signing policy;
- limited algorithm scope;
- partner hardware may need board-specific tuning.

### Conclusion

Conclude that the project demonstrates a repeatable evidence pattern for
embedded PQC releases and identifies a path to hardware-validated partner
packs.

## Expected Product Collateral

### One-page partner brief

Must include:

- what the module does;
- supported algorithms and profiles;
- how to generate and replay evidence;
- what artifacts are included;
- what is not claimed;
- how to start a consumer workspace.

### Security review packet

Must include:

- `SECURITY.md`;
- threat model;
- backend contract result;
- RNG policy result;
- ACVP negative scenario result;
- side-channel non-claims;
- mutation campaign result;
- support matrix.

### Engineering evaluation packet

Must include:

- west setup;
- consumer smoke command;
- hardware benchmark command;
- release pack command;
- replay command;
- compatibility matrix.

### Management-facing summary

Must include:

- why this reduces review risk;
- what is ready;
- what still requires hardware;
- expected partner effort;
- support boundaries.

## Acceptance Checklist For The Next Three Patch Sets

Patch set A is accepted only if:

- schema registry exists;
- all schema tests pass;
- full release emits schema result;
- replay verifier requires schema result for new schema;
- docs explain schema versioning.

Patch set B is accepted only if:

- mutation matrix has at least 30 meaningful mutations;
- mutation campaign detects every configured mutation or marks it out of
  scope with a reason;
- campaign outputs JSON, CSV, and Markdown;
- partner scorecard includes mutation campaign status.

Patch set C is accepted only if:

- hardware board registry exists;
- QEMU lane still passes without hardware;
- hardware absence is explicit;
- synthetic hardware transcript tests pass;
- physical campaign can be run with a documented command;
- QEMU results cannot be mislabeled hardware.

## Red Flags To Avoid

- Do not add more claim IDs without validators.
- Do not add more generated JSON without schemas.
- Do not add hardware claims without physical transcripts.
- Do not add side-channel claims without tier labels and non-claims.
- Do not add external benchmark rows without source, clock, compiler, platform,
  and statistic metadata.
- Do not add dashboard views that invent values absent from evidence artifacts.
- Do not update README with broad claims before artifacts exist.
- Do not weaken negative tests to make new validators pass.
- Do not mix lab/test profile assets into production profile decisions.

## Closing Assessment

This repository has crossed the line from "sample code" into "assurance
prototype." The next line is harder: it must become an experimentally evaluated
assurance system and a supportable partner package. The strongest path is not
to add more claim names. The strongest path is to add:

- schema validation;
- mutation experiments;
- physical benchmark campaigns;
- ACVP parser campaigns;
- side-channel evidence tiering;
- packaged partner evidence archives;
- support and compatibility contracts.

If those are implemented with the same replay discipline already present in
`scripts/release_check.py` and `scripts/verify_release_evidence_pack.py`, the
project can make a credible paper claim:

> Embedded PQC releases can be made reviewable by binding crypto inventory,
> profile policy, validation transcripts, benchmark distributions, and release
> metadata into a replay-verifiable evidence package, and the package detects
> concrete classes of drift that ordinary CI logs and inventory files miss.

That is the research/product direction worth pursuing.

## Correction Expansion: Measurable Paper And Product Depth

This section expands the audit to the requested measurable long-form depth. It is not a
replacement for the earlier audit; it is the missing detail layer. Every subsection
below is tied to repository artifacts that currently exist on main: claim catalogs,
validators, release-check scripts, ztests, samples, evidence schemas, benchmark campaign
tooling, and partner-facing documents. The purpose is to turn the earlier severe
diagnosis into an implementation-grade research and product backlog that can be audited
file by file.

The central correction is that the previous audit described the shape of the missing
work but did not enumerate enough concrete experiments, evidence contracts, failure
modes, acceptance criteria, and repository integration points to satisfy the requested
long-form requirement. The current repository is already sophisticated, but a paper
reviewer or product partner would still ask for stronger baselines, physical-board
execution, data-schema stability, negative controls, replay evidence, and customer
support boundaries. The following sections answer those questions with explicit,
actionable content.


## Claim-Level Research And Product Closure Matrix

The claim catalog is the most important internal product primitive because it defines
what the release pack says is true. For paper-grade work, each claim must be evaluated
as a hypothesis with an executable validator, a falsification route, a dataset or
transcript, and an explanation of why it matters. For product-grade work, each claim
must have a support owner, profile applicability, and a failure message that a partner
can understand without reading source code.


### Claim closure item 1: `release.version_consistency`

This claim belongs to the `release` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is:
version.h, CMakeLists.txt, CHANGELOG.md, and the optional release tag agree on the same
semantic version..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `release.version_consistency` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `release.version_consistency` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `release.version_consistency` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `release.version_consistency` in the ledger, locate its supporting artifact, alter
  that artifact in a temporary copy, and observe a non-zero replay failure naming the
  claim or the artifact relationship.

### Claim closure item 2: `release.tag_integrity`

This claim belongs to the `release` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is:
When a release tag is supplied, the local annotated tag exists and peels to a concrete
source commit..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `release.tag_integrity` passes, a negative or tamper run where the supporting artifact
  is removed or corrupted, and a replay log proving that the verifier reports this exact
  claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `release.tag_integrity` with status, evidence class, execution environment, artifact
  path, transcript hash if applicable, and a short remediation note that tells a
  firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `release.tag_integrity` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see `release.tag_integrity` in
  the ledger, locate its supporting artifact, alter that artifact in a temporary copy,
  and observe a non-zero replay failure naming the claim or the artifact relationship.

### Claim closure item 3: `kat.offline_provenance`

This claim belongs to the `kat` evidence family and should be treated as a separately
falsifiable statement, not as a line item hidden inside an aggregate release check. The
current repository gives it an identifier in `scripts/assurance_claims.json`, which is
necessary but not sufficient for paper-grade evaluation. The claim text is: Vendored
NIST ACVP fixtures match the checked-in KAT header constants (aggregate over every
parameter set)..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `kat.offline_provenance` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `kat.offline_provenance` with status, evidence class, execution environment, artifact
  path, transcript hash if applicable, and a short remediation note that tells a
  firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `kat.offline_provenance` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see `kat.offline_provenance` in
  the ledger, locate its supporting artifact, alter that artifact in a temporary copy,
  and observe a non-zero replay failure naming the claim or the artifact relationship.

### Claim closure item 4: `kat.mlkem_512`

This claim belongs to the `kat` evidence family and should be treated as a separately
falsifiable statement, not as a line item hidden inside an aggregate release check. The
current repository gives it an identifier in `scripts/assurance_claims.json`, which is
necessary but not sufficient for paper-grade evaluation. The claim text is: ML-KEM-512
keygen and encaps NIST ACVP vectors match the checked-in KAT header constants..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `kat.mlkem_512` passes, a negative or tamper run where the supporting artifact is
  removed or corrupted, and a replay log proving that the verifier reports this exact
  claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `kat.mlkem_512` with status, evidence class, execution environment, artifact path,
  transcript hash if applicable, and a short remediation note that tells a firmware
  engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `kat.mlkem_512` directly, then ensure the schema contract and release
  evidence verifier fail when the claim is missing, stale, or marked not applicable
  without profile permission.
- Acceptance criterion: a reviewer can run one command, see `kat.mlkem_512` in the
  ledger, locate its supporting artifact, alter that artifact in a temporary copy, and
  observe a non-zero replay failure naming the claim or the artifact relationship.

### Claim closure item 5: `kat.mlkem_768`

This claim belongs to the `kat` evidence family and should be treated as a separately
falsifiable statement, not as a line item hidden inside an aggregate release check. The
current repository gives it an identifier in `scripts/assurance_claims.json`, which is
necessary but not sufficient for paper-grade evaluation. The claim text is: ML-KEM-768
keygen and encaps NIST ACVP vectors match the checked-in KAT header constants..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `kat.mlkem_768` passes, a negative or tamper run where the supporting artifact is
  removed or corrupted, and a replay log proving that the verifier reports this exact
  claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `kat.mlkem_768` with status, evidence class, execution environment, artifact path,
  transcript hash if applicable, and a short remediation note that tells a firmware
  engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `kat.mlkem_768` directly, then ensure the schema contract and release
  evidence verifier fail when the claim is missing, stale, or marked not applicable
  without profile permission.
- Acceptance criterion: a reviewer can run one command, see `kat.mlkem_768` in the
  ledger, locate its supporting artifact, alter that artifact in a temporary copy, and
  observe a non-zero replay failure naming the claim or the artifact relationship.

### Claim closure item 6: `kat.mlkem_1024`

This claim belongs to the `kat` evidence family and should be treated as a separately
falsifiable statement, not as a line item hidden inside an aggregate release check. The
current repository gives it an identifier in `scripts/assurance_claims.json`, which is
necessary but not sufficient for paper-grade evaluation. The claim text is: ML-KEM-1024
keygen and encaps NIST ACVP vectors match the checked-in KAT header constants..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `kat.mlkem_1024` passes, a negative or tamper run where the supporting artifact is
  removed or corrupted, and a replay log proving that the verifier reports this exact
  claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `kat.mlkem_1024` with status, evidence class, execution environment, artifact path,
  transcript hash if applicable, and a short remediation note that tells a firmware
  engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `kat.mlkem_1024` directly, then ensure the schema contract and release
  evidence verifier fail when the claim is missing, stale, or marked not applicable
  without profile permission.
- Acceptance criterion: a reviewer can run one command, see `kat.mlkem_1024` in the
  ledger, locate its supporting artifact, alter that artifact in a temporary copy, and
  observe a non-zero replay failure naming the claim or the artifact relationship.

### Claim closure item 7: `kat.mldsa_44`

This claim belongs to the `kat` evidence family and should be treated as a separately
falsifiable statement, not as a line item hidden inside an aggregate release check. The
current repository gives it an identifier in `scripts/assurance_claims.json`, which is
necessary but not sufficient for paper-grade evaluation. The claim text is: ML-DSA-44
siggen and sigver NIST ACVP vectors match the checked-in KAT header constants..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `kat.mldsa_44` passes, a negative or tamper run where the supporting artifact is
  removed or corrupted, and a replay log proving that the verifier reports this exact
  claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `kat.mldsa_44` with status, evidence class, execution environment, artifact path,
  transcript hash if applicable, and a short remediation note that tells a firmware
  engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `kat.mldsa_44` directly, then ensure the schema contract and release
  evidence verifier fail when the claim is missing, stale, or marked not applicable
  without profile permission.
- Acceptance criterion: a reviewer can run one command, see `kat.mldsa_44` in the
  ledger, locate its supporting artifact, alter that artifact in a temporary copy, and
  observe a non-zero replay failure naming the claim or the artifact relationship.

### Claim closure item 8: `kat.mldsa_65`

This claim belongs to the `kat` evidence family and should be treated as a separately
falsifiable statement, not as a line item hidden inside an aggregate release check. The
current repository gives it an identifier in `scripts/assurance_claims.json`, which is
necessary but not sufficient for paper-grade evaluation. The claim text is: ML-DSA-65
siggen and sigver NIST ACVP vectors match the checked-in KAT header constants..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `kat.mldsa_65` passes, a negative or tamper run where the supporting artifact is
  removed or corrupted, and a replay log proving that the verifier reports this exact
  claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `kat.mldsa_65` with status, evidence class, execution environment, artifact path,
  transcript hash if applicable, and a short remediation note that tells a firmware
  engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `kat.mldsa_65` directly, then ensure the schema contract and release
  evidence verifier fail when the claim is missing, stale, or marked not applicable
  without profile permission.
- Acceptance criterion: a reviewer can run one command, see `kat.mldsa_65` in the
  ledger, locate its supporting artifact, alter that artifact in a temporary copy, and
  observe a non-zero replay failure naming the claim or the artifact relationship.

### Claim closure item 9: `kat.mldsa_87`

This claim belongs to the `kat` evidence family and should be treated as a separately
falsifiable statement, not as a line item hidden inside an aggregate release check. The
current repository gives it an identifier in `scripts/assurance_claims.json`, which is
necessary but not sufficient for paper-grade evaluation. The claim text is: ML-DSA-87
siggen and sigver NIST ACVP vectors match the checked-in KAT header constants..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `kat.mldsa_87` passes, a negative or tamper run where the supporting artifact is
  removed or corrupted, and a replay log proving that the verifier reports this exact
  claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `kat.mldsa_87` with status, evidence class, execution environment, artifact path,
  transcript hash if applicable, and a short remediation note that tells a firmware
  engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `kat.mldsa_87` directly, then ensure the schema contract and release
  evidence verifier fail when the claim is missing, stale, or marked not applicable
  without profile permission.
- Acceptance criterion: a reviewer can run one command, see `kat.mldsa_87` in the
  ledger, locate its supporting artifact, alter that artifact in a temporary copy, and
  observe a non-zero replay failure naming the claim or the artifact relationship.

### Claim closure item 10: `benchmark.csv_validity`

This claim belongs to the `benchmark` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
benchmark CSV has the expected schema, required rows, positive numeric fields, and
bounded PQCP/baseline timing ratios..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `benchmark.csv_validity` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `benchmark.csv_validity` with status, evidence class, execution environment, artifact
  path, transcript hash if applicable, and a short remediation note that tells a
  firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `benchmark.csv_validity` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see `benchmark.csv_validity` in
  the ledger, locate its supporting artifact, alter that artifact in a temporary copy,
  and observe a non-zero replay failure naming the claim or the artifact relationship.

### Claim closure item 11: `benchmark.provenance_binding`

This claim belongs to the `benchmark` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
benchmark_provenance.json sidecar cryptographically binds to the benchmark CSV bytes..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `benchmark.provenance_binding` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `benchmark.provenance_binding` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `benchmark.provenance_binding` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `benchmark.provenance_binding` in the ledger, locate its supporting artifact, alter
  that artifact in a temporary copy, and observe a non-zero replay failure naming the
  claim or the artifact relationship.

### Claim closure item 12: `benchmark.mlkem_throughput`

This claim belongs to the `benchmark` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
benchmark CSV contains valid ML-KEM rows for every configured parameter set with
positive cycles and time values..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `benchmark.mlkem_throughput` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `benchmark.mlkem_throughput` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `benchmark.mlkem_throughput` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see `benchmark.mlkem_throughput`
  in the ledger, locate its supporting artifact, alter that artifact in a temporary
  copy, and observe a non-zero replay failure naming the claim or the artifact
  relationship.

### Claim closure item 13: `benchmark.mldsa_throughput`

This claim belongs to the `benchmark` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
benchmark CSV contains valid ML-DSA rows for every configured parameter set with
positive cycles and time values..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `benchmark.mldsa_throughput` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `benchmark.mldsa_throughput` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `benchmark.mldsa_throughput` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see `benchmark.mldsa_throughput`
  in the ledger, locate its supporting artifact, alter that artifact in a temporary
  copy, and observe a non-zero replay failure naming the claim or the artifact
  relationship.

### Claim closure item 14: `benchmark.distribution_quality`

This claim belongs to the `benchmark` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
benchmark export includes additive min, median, p90, p99, max, MAD, and sample-count
rows for every supported ML-KEM and ML-DSA parameter set without changing the legacy
metric contract..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `benchmark.distribution_quality` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `benchmark.distribution_quality` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `benchmark.distribution_quality` directly, then ensure the schema contract
  and release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `benchmark.distribution_quality` in the ledger, locate its supporting artifact, alter
  that artifact in a temporary copy, and observe a non-zero replay failure naming the
  claim or the artifact relationship.

### Claim closure item 15: `cost_of_assurance.guardrails`

This claim belongs to the `cost_of_assurance` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is:
Every configured cost-of-assurance guardrail metric was evaluated and passed..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `cost_of_assurance.guardrails` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `cost_of_assurance.guardrails` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `cost_of_assurance.guardrails` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `cost_of_assurance.guardrails` in the ledger, locate its supporting artifact, alter
  that artifact in a temporary copy, and observe a non-zero replay failure naming the
  claim or the artifact relationship.

### Claim closure item 16: `release.local_bundle`

This claim belongs to the `release` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: A
local release bundle manifest exists and hashes the extracted release notes for the
selected version..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `release.local_bundle` passes, a negative or tamper run where the supporting artifact
  is removed or corrupted, and a replay log proving that the verifier reports this exact
  claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `release.local_bundle` with status, evidence class, execution environment, artifact
  path, transcript hash if applicable, and a short remediation note that tells a
  firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `release.local_bundle` directly, then ensure the schema contract and release
  evidence verifier fail when the claim is missing, stale, or marked not applicable
  without profile permission.
- Acceptance criterion: a reviewer can run one command, see `release.local_bundle` in
  the ledger, locate its supporting artifact, alter that artifact in a temporary copy,
  and observe a non-zero replay failure naming the claim or the artifact relationship.

### Claim closure item 17: `release.transcript_binding`

This claim belongs to the `release` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is:
Release evidence claims are bound to captured release-check stdout transcripts with
recorded SHA-256 hashes..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `release.transcript_binding` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `release.transcript_binding` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `release.transcript_binding` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see `release.transcript_binding`
  in the ledger, locate its supporting artifact, alter that artifact in a temporary
  copy, and observe a non-zero replay failure naming the claim or the artifact
  relationship.

### Claim closure item 18: `acvp.negative_path_rejection`

This claim belongs to the `acvp` evidence family and should be treated as a separately
falsifiable statement, not as a line item hidden inside an aggregate release check. The
current repository gives it an identifier in `scripts/assurance_claims.json`, which is
necessary but not sufficient for paper-grade evaluation. The claim text is: The ACVP
serial harness rejects malformed inputs (bad hex, unknown commands, wrong sizes,
oversize payloads) with the documented ERROR:* responses, as exercised by
ztest_acvp_serial and bound to acvp_negative_scenarios.json..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `acvp.negative_path_rejection` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `acvp.negative_path_rejection` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `acvp.negative_path_rejection` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `acvp.negative_path_rejection` in the ledger, locate its supporting artifact, alter
  that artifact in a temporary copy, and observe a non-zero replay failure naming the
  claim or the artifact relationship.

### Claim closure item 19: `acvp.timeout_recovery`

This claim belongs to the `acvp` evidence family and should be treated as a separately
falsifiable statement, not as a line item hidden inside an aggregate release check. The
current repository gives it an identifier in `scripts/assurance_claims.json`, which is
necessary but not sufficient for paper-grade evaluation. The claim text is: The ACVP
serial readline timeout fires under stalled-frame conditions, emits ERROR:TIMEOUT, and
recovers cleanly for the next command (proven by
ztest_acvp_serial::test_readline_timeout in the captured ACVP serial transcript)..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `acvp.timeout_recovery` passes, a negative or tamper run where the supporting artifact
  is removed or corrupted, and a replay log proving that the verifier reports this exact
  claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `acvp.timeout_recovery` with status, evidence class, execution environment, artifact
  path, transcript hash if applicable, and a short remediation note that tells a
  firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `acvp.timeout_recovery` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see `acvp.timeout_recovery` in
  the ledger, locate its supporting artifact, alter that artifact in a temporary copy,
  and observe a non-zero replay failure naming the claim or the artifact relationship.

### Claim closure item 20: `acvp.negative_scenarios_replay`

This claim belongs to the `acvp` evidence family and should be treated as a separately
falsifiable statement, not as a line item hidden inside an aggregate release check. The
current repository gives it an identifier in `scripts/assurance_claims.json`, which is
necessary but not sufficient for paper-grade evaluation. The claim text is: Every
replay-eligible case from scripts/acvp_negative_scenarios.json is exercised directly
through pqcp_acvp_process_command() by tests/ztest_acvp_serial_negative and produces the
documented ERROR:* response on the wire..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `acvp.negative_scenarios_replay` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `acvp.negative_scenarios_replay` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `acvp.negative_scenarios_replay` directly, then ensure the schema contract
  and release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `acvp.negative_scenarios_replay` in the ledger, locate its supporting artifact, alter
  that artifact in a temporary copy, and observe a non-zero replay failure naming the
  claim or the artifact relationship.

### Claim closure item 21: `acvp.mlkem_negative_paths`

This claim belongs to the `acvp` evidence family and should be treated as a separately
falsifiable statement, not as a line item hidden inside an aggregate release check. The
current repository gives it an identifier in `scripts/assurance_claims.json`, which is
necessary but not sufficient for paper-grade evaluation. The claim text is: ML-KEM-
specific negative paths (INVALID_LEVEL for unsupported levels, WRONG_SIZE for
truncated/oversize encaps and decaps payloads, INVALID_HEX for non-hex encaps payloads)
are rejected with the documented ERROR:* responses by tests/ztest_acvp_serial_negative..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `acvp.mlkem_negative_paths` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `acvp.mlkem_negative_paths` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `acvp.mlkem_negative_paths` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see `acvp.mlkem_negative_paths`
  in the ledger, locate its supporting artifact, alter that artifact in a temporary
  copy, and observe a non-zero replay failure naming the claim or the artifact
  relationship.

### Claim closure item 22: `acvp.mldsa_negative_paths`

This claim belongs to the `acvp` evidence family and should be treated as a separately
falsifiable statement, not as a line item hidden inside an aggregate release check. The
current repository gives it an identifier in `scripts/assurance_claims.json`, which is
necessary but not sufficient for paper-grade evaluation. The claim text is: ML-DSA-
specific negative paths (WRONG_SIZE for short SIGN payload, INVALID_HEX for non-hex SIGN
payload, WRONG_SIZE for truncated VERIFY payload, INVALID_CMD for too-many VERIFY
fields) are rejected with the documented ERROR:* responses by
tests/ztest_acvp_serial_negative..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `acvp.mldsa_negative_paths` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `acvp.mldsa_negative_paths` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `acvp.mldsa_negative_paths` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see `acvp.mldsa_negative_paths`
  in the ledger, locate its supporting artifact, alter that artifact in a temporary
  copy, and observe a non-zero replay failure naming the claim or the artifact
  relationship.

### Claim closure item 23: `acvp.negative_scenario_floor`

This claim belongs to the `acvp` evidence family and should be treated as a separately
falsifiable statement, not as a line item hidden inside an aggregate release check. The
current repository gives it an identifier in `scripts/assurance_claims.json`, which is
necessary but not sufficient for paper-grade evaluation. The claim text is:
scripts/acvp_negative_scenario_floor.json locks every compatibility-floor negative
scenario so malformed ACVP cases cannot be removed, renamed, duplicated, or weakened
without a release-gate failure..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `acvp.negative_scenario_floor` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `acvp.negative_scenario_floor` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `acvp.negative_scenario_floor` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `acvp.negative_scenario_floor` in the ledger, locate its supporting artifact, alter
  that artifact in a temporary copy, and observe a non-zero replay failure naming the
  claim or the artifact relationship.

### Claim closure item 24: `security.asan_clean`

This claim belongs to the `security` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is:
Every sanitizer-enabled native_sim ztest run captured by scripts/run_sanitizer_checks.py
finished without an AddressSanitizer error report..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `security.asan_clean` passes, a negative or tamper run where the supporting artifact
  is removed or corrupted, and a replay log proving that the verifier reports this exact
  claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `security.asan_clean` with status, evidence class, execution environment, artifact
  path, transcript hash if applicable, and a short remediation note that tells a
  firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `security.asan_clean` directly, then ensure the schema contract and release
  evidence verifier fail when the claim is missing, stale, or marked not applicable
  without profile permission.
- Acceptance criterion: a reviewer can run one command, see `security.asan_clean` in the
  ledger, locate its supporting artifact, alter that artifact in a temporary copy, and
  observe a non-zero replay failure naming the claim or the artifact relationship.

### Claim closure item 25: `security.ubsan_clean`

This claim belongs to the `security` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is:
Every sanitizer-enabled native_sim ztest run captured by scripts/run_sanitizer_checks.py
finished without an UndefinedBehaviorSanitizer runtime error report..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `security.ubsan_clean` passes, a negative or tamper run where the supporting artifact
  is removed or corrupted, and a replay log proving that the verifier reports this exact
  claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `security.ubsan_clean` with status, evidence class, execution environment, artifact
  path, transcript hash if applicable, and a short remediation note that tells a
  firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `security.ubsan_clean` directly, then ensure the schema contract and release
  evidence verifier fail when the claim is missing, stale, or marked not applicable
  without profile permission.
- Acceptance criterion: a reviewer can run one command, see `security.ubsan_clean` in
  the ledger, locate its supporting artifact, alter that artifact in a temporary copy,
  and observe a non-zero replay failure naming the claim or the artifact relationship.

### Claim closure item 26: `boot.kat_self_verify`

This claim belongs to the `boot` evidence family and should be treated as a separately
falsifiable statement, not as a line item hidden inside an aggregate release check. The
current repository gives it an identifier in `scripts/assurance_claims.json`, which is
necessary but not sufficient for paper-grade evaluation. The claim text is: When
CONFIG_PQCP_KAT_BOOT_VERIFY=y is set, the SYS_INIT(APPLICATION) hook in
src/kat_boot_verify.c runs a deterministic keygen/encaps/decaps for every enabled ML-KEM
level and keygen/sign/verify for every enabled ML-DSA level, and the system reaches
ztest main without calling k_panic(). Proven by tests/ztest_kat_boot_verify on
qemu_x86_64..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `boot.kat_self_verify` passes, a negative or tamper run where the supporting artifact
  is removed or corrupted, and a replay log proving that the verifier reports this exact
  claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `boot.kat_self_verify` with status, evidence class, execution environment, artifact
  path, transcript hash if applicable, and a short remediation note that tells a
  firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `boot.kat_self_verify` directly, then ensure the schema contract and release
  evidence verifier fail when the claim is missing, stale, or marked not applicable
  without profile permission.
- Acceptance criterion: a reviewer can run one command, see `boot.kat_self_verify` in
  the ledger, locate its supporting artifact, alter that artifact in a temporary copy,
  and observe a non-zero replay failure naming the claim or the artifact relationship.

### Claim closure item 27: `security.ct_smoke`

This claim belongs to the `security` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: ML-
KEM-512/768/1024 decapsulation, each run 32 times against a valid and 32 times against a
deliberately corrupted ciphertext, produces median cycle counts whose relative variance
stays under a documented bound. This is a runtime smoke test, not a constant-time proof;
the assurance documentation (docs/assurance-model.md, docs/publications.md) states the
same caveats. Proven by tests/ztest_ct_smoke on qemu_x86_64..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `security.ct_smoke` passes, a negative or tamper run where the supporting artifact is
  removed or corrupted, and a replay log proving that the verifier reports this exact
  claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `security.ct_smoke` with status, evidence class, execution environment, artifact path,
  transcript hash if applicable, and a short remediation note that tells a firmware
  engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `security.ct_smoke` directly, then ensure the schema contract and release
  evidence verifier fail when the claim is missing, stale, or marked not applicable
  without profile permission.
- Acceptance criterion: a reviewer can run one command, see `security.ct_smoke` in the
  ledger, locate its supporting artifact, alter that artifact in a temporary copy, and
  observe a non-zero replay failure naming the claim or the artifact relationship.

### Claim closure item 28: `security.mlkem_decap_instruction_policy`

This claim belongs to the `security` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
built ML-KEM decapsulation code path is scanned for variable-latency division
instructions associated with KyberSlash-class regressions. This is static regression
evidence, not a formal side-channel proof..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `security.mlkem_decap_instruction_policy` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `security.mlkem_decap_instruction_policy` with status, evidence class, execution
  environment, artifact path, transcript hash if applicable, and a short remediation
  note that tells a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `security.mlkem_decap_instruction_policy` directly, then ensure the schema
  contract and release evidence verifier fail when the claim is missing, stale, or
  marked not applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `security.mlkem_decap_instruction_policy` in the ledger, locate its supporting
  artifact, alter that artifact in a temporary copy, and observe a non-zero replay
  failure naming the claim or the artifact relationship.

### Claim closure item 29: `supply_chain.cbom_crypto_inventory`

This claim belongs to the `supply_chain` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
release pack includes a CycloneDX-style PQC CBOM that inventories supported ML-KEM, ML-
DSA, RNG, validation, Zephyr, SDK, mlkem-native, and mldsa-native assets..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `supply_chain.cbom_crypto_inventory` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `supply_chain.cbom_crypto_inventory` with status, evidence class, execution
  environment, artifact path, transcript hash if applicable, and a short remediation
  note that tells a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `supply_chain.cbom_crypto_inventory` directly, then ensure the schema
  contract and release evidence verifier fail when the claim is missing, stale, or
  marked not applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `supply_chain.cbom_crypto_inventory` in the ledger, locate its supporting artifact,
  alter that artifact in a temporary copy, and observe a non-zero replay failure naming
  the claim or the artifact relationship.

### Claim closure item 30: `supply_chain.pqc_assurance_attestation`

This claim belongs to the `supply_chain` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
release pack includes an unsigned in-toto Statement-style PQC assurance attestation
binding release evidence artifact hashes to the ledger metadata..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `supply_chain.pqc_assurance_attestation` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `supply_chain.pqc_assurance_attestation` with status, evidence class, execution
  environment, artifact path, transcript hash if applicable, and a short remediation
  note that tells a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `supply_chain.pqc_assurance_attestation` directly, then ensure the schema
  contract and release evidence verifier fail when the claim is missing, stale, or
  marked not applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `supply_chain.pqc_assurance_attestation` in the ledger, locate its supporting
  artifact, alter that artifact in a temporary copy, and observe a non-zero replay
  failure naming the claim or the artifact relationship.

### Claim closure item 31: `supply_chain.crypto_asset_traceability`

This claim belongs to the `supply_chain` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
release pack includes a verified PQC asset trace map linking cryptographic assets to
source files, Kconfig symbols, assurance claims, ztests, transcript markers, and CBOM
components..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `supply_chain.crypto_asset_traceability` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `supply_chain.crypto_asset_traceability` with status, evidence class, execution
  environment, artifact path, transcript hash if applicable, and a short remediation
  note that tells a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `supply_chain.crypto_asset_traceability` directly, then ensure the schema
  contract and release evidence verifier fail when the claim is missing, stale, or
  marked not applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `supply_chain.crypto_asset_traceability` in the ledger, locate its supporting
  artifact, alter that artifact in a temporary copy, and observe a non-zero replay
  failure naming the claim or the artifact relationship.

### Claim closure item 32: `supply_chain.evidence_graph_integrity`

This claim belongs to the `supply_chain` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
release pack includes a PQC evidence graph whose asset, claim, source, test, marker, and
CBOM links resolve without missing graph edges..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `supply_chain.evidence_graph_integrity` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `supply_chain.evidence_graph_integrity` with status, evidence class, execution
  environment, artifact path, transcript hash if applicable, and a short remediation
  note that tells a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `supply_chain.evidence_graph_integrity` directly, then ensure the schema
  contract and release evidence verifier fail when the claim is missing, stale, or
  marked not applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `supply_chain.evidence_graph_integrity` in the ledger, locate its supporting artifact,
  alter that artifact in a temporary copy, and observe a non-zero replay failure naming
  the claim or the artifact relationship.

### Claim closure item 33: `release.policy_pass`

This claim belongs to the `release` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
partner-review PQC assurance policy evaluated the ledger, CBOM, attestation, and release
metadata and passed without failures..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `release.policy_pass` passes, a negative or tamper run where the supporting artifact
  is removed or corrupted, and a replay log proving that the verifier reports this exact
  claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `release.policy_pass` with status, evidence class, execution environment, artifact
  path, transcript hash if applicable, and a short remediation note that tells a
  firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `release.policy_pass` directly, then ensure the schema contract and release
  evidence verifier fail when the claim is missing, stale, or marked not applicable
  without profile permission.
- Acceptance criterion: a reviewer can run one command, see `release.policy_pass` in the
  ledger, locate its supporting artifact, alter that artifact in a temporary copy, and
  observe a non-zero replay failure naming the claim or the artifact relationship.

### Claim closure item 34: `firmware.assurance_digest_manifest`

This claim belongs to the `firmware` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
release pack exposes a stable SHA-256 digest manifest over the ledger, CBOM,
attestation, transcript manifest, benchmark provenance, and release manifest for future
firmware attestation binding..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `firmware.assurance_digest_manifest` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `firmware.assurance_digest_manifest` with status, evidence class, execution
  environment, artifact path, transcript hash if applicable, and a short remediation
  note that tells a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `firmware.assurance_digest_manifest` directly, then ensure the schema
  contract and release evidence verifier fail when the claim is missing, stale, or
  marked not applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `firmware.assurance_digest_manifest` in the ledger, locate its supporting artifact,
  alter that artifact in a temporary copy, and observe a non-zero replay failure naming
  the claim or the artifact relationship.

### Claim closure item 35: `firmware.assurance_digest_embeddable`

This claim belongs to the `firmware` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
release pack exports the assurance digest into a generated C header and verifies that
samples/pqcp_assurance_status can compile it into firmware..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `firmware.assurance_digest_embeddable` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `firmware.assurance_digest_embeddable` with status, evidence class, execution
  environment, artifact path, transcript hash if applicable, and a short remediation
  note that tells a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `firmware.assurance_digest_embeddable` directly, then ensure the schema
  contract and release evidence verifier fail when the claim is missing, stale, or
  marked not applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `firmware.assurance_digest_embeddable` in the ledger, locate its supporting artifact,
  alter that artifact in a temporary copy, and observe a non-zero replay failure naming
  the claim or the artifact relationship.

### Claim closure item 36: `supply_chain.assurance_profile_policy`

This claim belongs to the `supply_chain` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
release pack includes a verified assurance profile result that classifies supported,
validation-only, lab-only, smoke-only, and test-only assets across local release
profiles..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `supply_chain.assurance_profile_policy` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `supply_chain.assurance_profile_policy` with status, evidence class, execution
  environment, artifact path, transcript hash if applicable, and a short remediation
  note that tells a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `supply_chain.assurance_profile_policy` directly, then ensure the schema
  contract and release evidence verifier fail when the claim is missing, stale, or
  marked not applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `supply_chain.assurance_profile_policy` in the ledger, locate its supporting artifact,
  alter that artifact in a temporary copy, and observe a non-zero replay failure naming
  the claim or the artifact relationship.

### Claim closure item 37: `supply_chain.evidence_quality_index`

This claim belongs to the `supply_chain` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
release pack includes an evidence quality result that assigns each required assurance
claim to a concrete validation class and environment..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `supply_chain.evidence_quality_index` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `supply_chain.evidence_quality_index` with status, evidence class, execution
  environment, artifact path, transcript hash if applicable, and a short remediation
  note that tells a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `supply_chain.evidence_quality_index` directly, then ensure the schema
  contract and release evidence verifier fail when the claim is missing, stale, or
  marked not applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `supply_chain.evidence_quality_index` in the ledger, locate its supporting artifact,
  alter that artifact in a temporary copy, and observe a non-zero replay failure naming
  the claim or the artifact relationship.

### Claim closure item 38: `crypto_agility.profile_separation`

This claim belongs to the `crypto_agility` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
assurance profile separates native-lab, QEMU release, constrained MCU, and gateway
profiles so validation-only and test-only assets are not represented as production-
enabled assets..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `crypto_agility.profile_separation` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `crypto_agility.profile_separation` with status, evidence class, execution
  environment, artifact path, transcript hash if applicable, and a short remediation
  note that tells a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `crypto_agility.profile_separation` directly, then ensure the schema
  contract and release evidence verifier fail when the claim is missing, stale, or
  marked not applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `crypto_agility.profile_separation` in the ledger, locate its supporting artifact,
  alter that artifact in a temporary copy, and observe a non-zero replay failure naming
  the claim or the artifact relationship.

### Claim closure item 39: `release.migration_readiness`

This claim belongs to the `release` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
release pack includes a migration-readiness report derived from the assurance profile,
evidence quality result, and CBOM profile properties..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `release.migration_readiness` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `release.migration_readiness` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `release.migration_readiness` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `release.migration_readiness` in the ledger, locate its supporting artifact, alter
  that artifact in a temporary copy, and observe a non-zero replay failure naming the
  claim or the artifact relationship.

### Claim closure item 40: `security.production_rng_policy`

This claim belongs to the `security` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
assurance profile and CBOM mark deterministic RNG as test-only and forbid it from
production-oriented profiles..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `security.production_rng_policy` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `security.production_rng_policy` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `security.production_rng_policy` directly, then ensure the schema contract
  and release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `security.production_rng_policy` in the ledger, locate its supporting artifact, alter
  that artifact in a temporary copy, and observe a non-zero replay failure naming the
  claim or the artifact relationship.

### Claim closure item 41: `release.reference_values`

This claim belongs to the `release` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
release pack includes replayable PQC reference values that bind release metadata,
artifact hashes, required claims, CBOM component IDs, and the expected firmware
assurance digest root..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `release.reference_values` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `release.reference_values` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `release.reference_values` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see `release.reference_values`
  in the ledger, locate its supporting artifact, alter that artifact in a temporary
  copy, and observe a non-zero replay failure naming the claim or the artifact
  relationship.

### Claim closure item 42: `firmware.assurance_status_report`

This claim belongs to the `firmware` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
assurance status firmware sample reports the expected digest, artifact count, and
artifact hashes, and the transcript is verified against the release reference values..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `firmware.assurance_status_report` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `firmware.assurance_status_report` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `firmware.assurance_status_report` directly, then ensure the schema contract
  and release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `firmware.assurance_status_report` in the ledger, locate its supporting artifact,
  alter that artifact in a temporary copy, and observe a non-zero replay failure naming
  the claim or the artifact relationship.

### Claim closure item 43: `acvp.json_interop`

This claim belongs to the `acvp` evidence family and should be treated as a separately
falsifiable statement, not as a line item hidden inside an aggregate release check. The
current repository gives it an identifier in `scripts/assurance_claims.json`, which is
necessary but not sufficient for paper-grade evaluation. The claim text is: NIST-style
ACVP ML-KEM and ML-DSA JSON vector groups are translated into serial-command evidence
with per-test transcript hashes and response classifications..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `acvp.json_interop` passes, a negative or tamper run where the supporting artifact is
  removed or corrupted, and a replay log proving that the verifier reports this exact
  claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `acvp.json_interop` with status, evidence class, execution environment, artifact path,
  transcript hash if applicable, and a short remediation note that tells a firmware
  engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `acvp.json_interop` directly, then ensure the schema contract and release
  evidence verifier fail when the claim is missing, stale, or marked not applicable
  without profile permission.
- Acceptance criterion: a reviewer can run one command, see `acvp.json_interop` in the
  ledger, locate its supporting artifact, alter that artifact in a temporary copy, and
  observe a non-zero replay failure naming the claim or the artifact relationship.

### Claim closure item 44: `supply_chain.slsa_build_provenance`

This claim belongs to the `supply_chain` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
release pack includes a SLSA-shaped in-toto build provenance statement whose subjects,
dependencies, external parameters, and byproducts replay-check against local artifacts..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `supply_chain.slsa_build_provenance` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `supply_chain.slsa_build_provenance` with status, evidence class, execution
  environment, artifact path, transcript hash if applicable, and a short remediation
  note that tells a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `supply_chain.slsa_build_provenance` directly, then ensure the schema
  contract and release evidence verifier fail when the claim is missing, stale, or
  marked not applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `supply_chain.slsa_build_provenance` in the ledger, locate its supporting artifact,
  alter that artifact in a temporary copy, and observe a non-zero replay failure naming
  the claim or the artifact relationship.

### Claim closure item 45: `security.ct_sample_analysis`

This claim belongs to the `security` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
constant-time smoke path can emit raw valid/invalid ML-KEM decapsulation timing samples,
and local analysis checks sample counts, distribution deltas, and Welch-style
statistics..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `security.ct_sample_analysis` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `security.ct_sample_analysis` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `security.ct_sample_analysis` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `security.ct_sample_analysis` in the ledger, locate its supporting artifact, alter
  that artifact in a temporary copy, and observe a non-zero replay failure naming the
  claim or the artifact relationship.

### Claim closure item 46: `release.evidence_appraisal_profile`

This claim belongs to the `release` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
release pack includes a mode-specific evidence appraisal result that replay-checks post-
Passport artifacts without relying on GitHub Actions..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `release.evidence_appraisal_profile` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `release.evidence_appraisal_profile` with status, evidence class, execution
  environment, artifact path, transcript hash if applicable, and a short remediation
  note that tells a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `release.evidence_appraisal_profile` directly, then ensure the schema
  contract and release evidence verifier fail when the claim is missing, stale, or
  marked not applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `release.evidence_appraisal_profile` in the ledger, locate its supporting artifact,
  alter that artifact in a temporary copy, and observe a non-zero replay failure naming
  the claim or the artifact relationship.

### Claim closure item 47: `supply_chain.backend_update_evaluation`

This claim belongs to the `supply_chain` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
release pack records a comparison-only backend update evaluation for mlkem-native and
mldsa-native, including pinned revisions, license metadata, META.yml metadata, and
optional upstream drift information..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `supply_chain.backend_update_evaluation` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `supply_chain.backend_update_evaluation` with status, evidence class, execution
  environment, artifact path, transcript hash if applicable, and a short remediation
  note that tells a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `supply_chain.backend_update_evaluation` directly, then ensure the schema
  contract and release evidence verifier fail when the claim is missing, stale, or
  marked not applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `supply_chain.backend_update_evaluation` in the ledger, locate its supporting
  artifact, alter that artifact in a temporary copy, and observe a non-zero replay
  failure naming the claim or the artifact relationship.

### Claim closure item 48: `benchmark.campaign_reproducibility`

This claim belongs to the `benchmark` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
release pack includes benchmark-campaign evidence with reproducible statistics and
validated comparison context derived from the generated benchmark CSV and provenance
sidecar..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `benchmark.campaign_reproducibility` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `benchmark.campaign_reproducibility` with status, evidence class, execution
  environment, artifact path, transcript hash if applicable, and a short remediation
  note that tells a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `benchmark.campaign_reproducibility` directly, then ensure the schema
  contract and release evidence verifier fail when the claim is missing, stale, or
  marked not applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `benchmark.campaign_reproducibility` in the ledger, locate its supporting artifact,
  alter that artifact in a temporary copy, and observe a non-zero replay failure naming
  the claim or the artifact relationship.

### Claim closure item 49: `benchmark.external_reference_context`

This claim belongs to the `benchmark` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is:
Imported external reference benchmark rows are normalized with source ecosystem,
platform class, clock assumptions, statistic type, and environment metadata before
comparison..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `benchmark.external_reference_context` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `benchmark.external_reference_context` with status, evidence class, execution
  environment, artifact path, transcript hash if applicable, and a short remediation
  note that tells a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `benchmark.external_reference_context` directly, then ensure the schema
  contract and release evidence verifier fail when the claim is missing, stale, or
  marked not applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `benchmark.external_reference_context` in the ledger, locate its supporting artifact,
  alter that artifact in a temporary copy, and observe a non-zero replay failure naming
  the claim or the artifact relationship.

### Claim closure item 50: `security.ct_campaign_analysis`

This claim belongs to the `security` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
release pack includes CT campaign evidence that replay-checks raw CT sample manifests
for balanced valid/invalid counts and contiguous per-class sample indexes..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `security.ct_campaign_analysis` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `security.ct_campaign_analysis` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `security.ct_campaign_analysis` directly, then ensure the schema contract
  and release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `security.ct_campaign_analysis` in the ledger, locate its supporting artifact, alter
  that artifact in a temporary copy, and observe a non-zero replay failure naming the
  claim or the artifact relationship.

### Claim closure item 51: `acvp.json_schema_coverage`

This claim belongs to the `acvp` evidence family and should be treated as a separately
falsifiable statement, not as a line item hidden inside an aggregate release check. The
current repository gives it an identifier in `scripts/assurance_claims.json`, which is
necessary but not sufficient for paper-grade evaluation. The claim text is: The ACVP
JSON interop evidence covers keyGen, encap, decap, sigGen, sigVer, transcript hashing,
and malformed-then-valid recovery cases..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `acvp.json_schema_coverage` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `acvp.json_schema_coverage` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `acvp.json_schema_coverage` directly, then ensure the schema contract and
  release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see `acvp.json_schema_coverage`
  in the ledger, locate its supporting artifact, alter that artifact in a temporary
  copy, and observe a non-zero replay failure naming the claim or the artifact
  relationship.

### Claim closure item 52: `firmware.device_evidence_token`

This claim belongs to the `firmware` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
assurance status firmware sample emits an additive device-evidence marker that binds a
nonce, digest, artifact count, schema, and transcript-binding hint to the release
reference values..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `firmware.device_evidence_token` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `firmware.device_evidence_token` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `firmware.device_evidence_token` directly, then ensure the schema contract
  and release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `firmware.device_evidence_token` in the ledger, locate its supporting artifact, alter
  that artifact in a temporary copy, and observe a non-zero replay failure naming the
  claim or the artifact relationship.

### Claim closure item 53: `release.strict_partner_policy`

This claim belongs to the `release` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
partner-review appraisal policy rejects missing or silently not-applicable v7 evidence
unless a less strict mode explicitly permits it..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `release.strict_partner_policy` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `release.strict_partner_policy` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `release.strict_partner_policy` directly, then ensure the schema contract
  and release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `release.strict_partner_policy` in the ledger, locate its supporting artifact, alter
  that artifact in a temporary copy, and observe a non-zero replay failure naming the
  claim or the artifact relationship.

### Claim closure item 54: `supply_chain.backend_contract`

This claim belongs to the `supply_chain` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is: The
release pack proves the backend contract: native backend pins are present, repo-owned
files pass provider-policy scanning, and no forbidden implementation provider is
selected..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `supply_chain.backend_contract` passes, a negative or tamper run where the supporting
  artifact is removed or corrupted, and a replay log proving that the verifier reports
  this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `supply_chain.backend_contract` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `supply_chain.backend_contract` directly, then ensure the schema contract
  and release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `supply_chain.backend_contract` in the ledger, locate its supporting artifact, alter
  that artifact in a temporary copy, and observe a non-zero replay failure naming the
  claim or the artifact relationship.

### Claim closure item 55: `supply_chain.liboqs_non_native_scope`

This claim belongs to the `supply_chain` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is:
Optional external-provider inventory is restricted to non-native schemes, marked
experimental, and rejected from production-oriented profiles unless policy explicitly
permits it..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `supply_chain.liboqs_non_native_scope` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `supply_chain.liboqs_non_native_scope` with status, evidence class, execution
  environment, artifact path, transcript hash if applicable, and a short remediation
  note that tells a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `supply_chain.liboqs_non_native_scope` directly, then ensure the schema
  contract and release evidence verifier fail when the claim is missing, stale, or
  marked not applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `supply_chain.liboqs_non_native_scope` in the ledger, locate its supporting artifact,
  alter that artifact in a temporary copy, and observe a non-zero replay failure naming
  the claim or the artifact relationship.

### Claim closure item 56: `benchmark.paper_comparison_export`

This claim belongs to the `benchmark` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is:
Benchmark campaign evidence is exported to a paper-comparable CSV/JSON shape with
explicit platform, clock, compiler, statistic, backend, and transcript-hash metadata..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `benchmark.paper_comparison_export` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `benchmark.paper_comparison_export` with status, evidence class, execution
  environment, artifact path, transcript hash if applicable, and a short remediation
  note that tells a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `benchmark.paper_comparison_export` directly, then ensure the schema
  contract and release evidence verifier fail when the claim is missing, stale, or
  marked not applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `benchmark.paper_comparison_export` in the ledger, locate its supporting artifact,
  alter that artifact in a temporary copy, and observe a non-zero replay failure naming
  the claim or the artifact relationship.

### Claim closure item 57: `release.reference_provider_scope`

This claim belongs to the `release` evidence family and should be treated as a
separately falsifiable statement, not as a line item hidden inside an aggregate release
check. The current repository gives it an identifier in `scripts/assurance_claims.json`,
which is necessary but not sufficient for paper-grade evaluation. The claim text is:
Release reference values replay against backend-contract, provider-scope, release
manifest, and CBOM metadata so provider-family drift cannot pass silently..

- Current repository hook: the claim should be emitted by
  `scripts/generate_assurance_ledger.py`, consumed by
  `scripts/verify_assurance_policy.py`, summarized by partner scorecard tooling, and
  replayed by `scripts/verify_release_evidence_pack.py` when the generated release pack
  is present.
- Missing paper evidence: the paper artifact should show a positive run where
  `release.reference_provider_scope` passes, a negative or tamper run where the
  supporting artifact is removed or corrupted, and a replay log proving that the
  verifier reports this exact claim rather than a generic failure.
- Missing product evidence: the dashboard and partner report should display
  `release.reference_provider_scope` with status, evidence class, execution environment,
  artifact path, transcript hash if applicable, and a short remediation note that tells
  a firmware engineer what to regenerate or fix.
- Implementation direction: add or strengthen a fixture under `scripts/testdata/` that
  exercises `release.reference_provider_scope` directly, then ensure the schema contract
  and release evidence verifier fail when the claim is missing, stale, or marked not
  applicable without profile permission.
- Acceptance criterion: a reviewer can run one command, see
  `release.reference_provider_scope` in the ledger, locate its supporting artifact,
  alter that artifact in a temporary copy, and observe a non-zero replay failure naming
  the claim or the artifact relationship.

## Asset Traceability Closure Matrix

The asset trace map turns crypto and validation components into reviewable objects. For
a serious paper, this map becomes an experimental inventory: every asset can be traced
to source, configuration, tests, transcript markers, and claims. For a product, this map
becomes the customer-facing crypto inventory boundary.


### Asset trace item 1: `crypto.mlkem_512`

The asset `crypto.mlkem_512` is part of the current asset trace map in
`scripts/pqc_asset_trace_map.json`. Its listed source coverage begins with
include/pqcp_zephyr/mlkem.h, src/mlkem_zephyr.c, tests/ztest_acvp_kat/src/kat_vectors.h,
tests/ztest_acvp_kat/src/main.c. Its linked claims include claims not listed. This is
useful because it prevents a partner review from treating the release as a single opaque
binary; the asset can be followed through source, Kconfig, tests, transcript markers,
CBOM components, and policy decisions.

- Research gap: `crypto.mlkem_512` needs at least one experiment that isolates its
  behavior from unrelated assets. If the asset is an algorithm family, the experiment
  should include KAT correctness, benchmark distribution, and failure injection. If the
  asset is validation infrastructure, the experiment should include malformed input and
  recovery behavior.
- Product gap: `crypto.mlkem_512` should have a stable customer-facing status:
  production allowed, validation only, test only, experimental, or hardware pending. The
  status should appear consistently in CBOM properties, profile results, migration
  readiness output, and partner scorecard summaries.
- Implementation direction: extend the trace-map verifier so every source path for
  `crypto.mlkem_512` must exist, every referenced claim must be in the ledger for the
  selected profile, and every dashboard view can show the path from asset to artifact
  hash.
- Acceptance criterion: removing a source path, claim link, CBOM component, or
  transcript marker for `crypto.mlkem_512` from a synthetic fixture causes a targeted
  verifier failure rather than silently reducing coverage.

### Asset trace item 2: `crypto.mlkem_768`

The asset `crypto.mlkem_768` is part of the current asset trace map in
`scripts/pqc_asset_trace_map.json`. Its listed source coverage begins with
include/pqcp_zephyr/mlkem.h, src/mlkem_zephyr.c, src/psa_mlkem_driver.c,
tests/ztest_acvp_kat/src/kat_vectors.h. Its linked claims include claims not listed.
This is useful because it prevents a partner review from treating the release as a
single opaque binary; the asset can be followed through source, Kconfig, tests,
transcript markers, CBOM components, and policy decisions.

- Research gap: `crypto.mlkem_768` needs at least one experiment that isolates its
  behavior from unrelated assets. If the asset is an algorithm family, the experiment
  should include KAT correctness, benchmark distribution, and failure injection. If the
  asset is validation infrastructure, the experiment should include malformed input and
  recovery behavior.
- Product gap: `crypto.mlkem_768` should have a stable customer-facing status:
  production allowed, validation only, test only, experimental, or hardware pending. The
  status should appear consistently in CBOM properties, profile results, migration
  readiness output, and partner scorecard summaries.
- Implementation direction: extend the trace-map verifier so every source path for
  `crypto.mlkem_768` must exist, every referenced claim must be in the ledger for the
  selected profile, and every dashboard view can show the path from asset to artifact
  hash.
- Acceptance criterion: removing a source path, claim link, CBOM component, or
  transcript marker for `crypto.mlkem_768` from a synthetic fixture causes a targeted
  verifier failure rather than silently reducing coverage.

### Asset trace item 3: `crypto.mlkem_1024`

The asset `crypto.mlkem_1024` is part of the current asset trace map in
`scripts/pqc_asset_trace_map.json`. Its listed source coverage begins with
include/pqcp_zephyr/mlkem.h, src/mlkem_zephyr.c, tests/ztest_acvp_kat/src/kat_vectors.h,
tests/ztest_acvp_kat/src/main.c. Its linked claims include claims not listed. This is
useful because it prevents a partner review from treating the release as a single opaque
binary; the asset can be followed through source, Kconfig, tests, transcript markers,
CBOM components, and policy decisions.

- Research gap: `crypto.mlkem_1024` needs at least one experiment that isolates its
  behavior from unrelated assets. If the asset is an algorithm family, the experiment
  should include KAT correctness, benchmark distribution, and failure injection. If the
  asset is validation infrastructure, the experiment should include malformed input and
  recovery behavior.
- Product gap: `crypto.mlkem_1024` should have a stable customer-facing status:
  production allowed, validation only, test only, experimental, or hardware pending. The
  status should appear consistently in CBOM properties, profile results, migration
  readiness output, and partner scorecard summaries.
- Implementation direction: extend the trace-map verifier so every source path for
  `crypto.mlkem_1024` must exist, every referenced claim must be in the ledger for the
  selected profile, and every dashboard view can show the path from asset to artifact
  hash.
- Acceptance criterion: removing a source path, claim link, CBOM component, or
  transcript marker for `crypto.mlkem_1024` from a synthetic fixture causes a targeted
  verifier failure rather than silently reducing coverage.

### Asset trace item 4: `crypto.mldsa_44`

The asset `crypto.mldsa_44` is part of the current asset trace map in
`scripts/pqc_asset_trace_map.json`. Its listed source coverage begins with
include/pqcp_zephyr/mldsa.h, src/mldsa_zephyr.c, src/mldsa_streaming.c,
tests/ztest_acvp_kat/src/kat_vectors.h. Its linked claims include claims not listed.
This is useful because it prevents a partner review from treating the release as a
single opaque binary; the asset can be followed through source, Kconfig, tests,
transcript markers, CBOM components, and policy decisions.

- Research gap: `crypto.mldsa_44` needs at least one experiment that isolates its
  behavior from unrelated assets. If the asset is an algorithm family, the experiment
  should include KAT correctness, benchmark distribution, and failure injection. If the
  asset is validation infrastructure, the experiment should include malformed input and
  recovery behavior.
- Product gap: `crypto.mldsa_44` should have a stable customer-facing status: production
  allowed, validation only, test only, experimental, or hardware pending. The status
  should appear consistently in CBOM properties, profile results, migration readiness
  output, and partner scorecard summaries.
- Implementation direction: extend the trace-map verifier so every source path for
  `crypto.mldsa_44` must exist, every referenced claim must be in the ledger for the
  selected profile, and every dashboard view can show the path from asset to artifact
  hash.
- Acceptance criterion: removing a source path, claim link, CBOM component, or
  transcript marker for `crypto.mldsa_44` from a synthetic fixture causes a targeted
  verifier failure rather than silently reducing coverage.

### Asset trace item 5: `crypto.mldsa_65`

The asset `crypto.mldsa_65` is part of the current asset trace map in
`scripts/pqc_asset_trace_map.json`. Its listed source coverage begins with
include/pqcp_zephyr/mldsa.h, src/mldsa_zephyr.c, src/mldsa_streaming.c,
src/psa_mldsa_driver.c. Its linked claims include claims not listed. This is useful
because it prevents a partner review from treating the release as a single opaque
binary; the asset can be followed through source, Kconfig, tests, transcript markers,
CBOM components, and policy decisions.

- Research gap: `crypto.mldsa_65` needs at least one experiment that isolates its
  behavior from unrelated assets. If the asset is an algorithm family, the experiment
  should include KAT correctness, benchmark distribution, and failure injection. If the
  asset is validation infrastructure, the experiment should include malformed input and
  recovery behavior.
- Product gap: `crypto.mldsa_65` should have a stable customer-facing status: production
  allowed, validation only, test only, experimental, or hardware pending. The status
  should appear consistently in CBOM properties, profile results, migration readiness
  output, and partner scorecard summaries.
- Implementation direction: extend the trace-map verifier so every source path for
  `crypto.mldsa_65` must exist, every referenced claim must be in the ledger for the
  selected profile, and every dashboard view can show the path from asset to artifact
  hash.
- Acceptance criterion: removing a source path, claim link, CBOM component, or
  transcript marker for `crypto.mldsa_65` from a synthetic fixture causes a targeted
  verifier failure rather than silently reducing coverage.

### Asset trace item 6: `crypto.mldsa_87`

The asset `crypto.mldsa_87` is part of the current asset trace map in
`scripts/pqc_asset_trace_map.json`. Its listed source coverage begins with
include/pqcp_zephyr/mldsa.h, src/mldsa_zephyr.c, src/mldsa_streaming.c,
tests/ztest_acvp_kat/src/kat_vectors.h. Its linked claims include claims not listed.
This is useful because it prevents a partner review from treating the release as a
single opaque binary; the asset can be followed through source, Kconfig, tests,
transcript markers, CBOM components, and policy decisions.

- Research gap: `crypto.mldsa_87` needs at least one experiment that isolates its
  behavior from unrelated assets. If the asset is an algorithm family, the experiment
  should include KAT correctness, benchmark distribution, and failure injection. If the
  asset is validation infrastructure, the experiment should include malformed input and
  recovery behavior.
- Product gap: `crypto.mldsa_87` should have a stable customer-facing status: production
  allowed, validation only, test only, experimental, or hardware pending. The status
  should appear consistently in CBOM properties, profile results, migration readiness
  output, and partner scorecard summaries.
- Implementation direction: extend the trace-map verifier so every source path for
  `crypto.mldsa_87` must exist, every referenced claim must be in the ledger for the
  selected profile, and every dashboard view can show the path from asset to artifact
  hash.
- Acceptance criterion: removing a source path, claim link, CBOM component, or
  transcript marker for `crypto.mldsa_87` from a synthetic fixture causes a targeted
  verifier failure rather than silently reducing coverage.

### Asset trace item 7: `validation.acvp_serial`

The asset `validation.acvp_serial` is part of the current asset trace map in
`scripts/pqc_asset_trace_map.json`. Its listed source coverage begins with
include/pqcp_zephyr/acvp_cmd.h, src/acvp_cmd.c, samples/pqcp_serial_acvp/src/main.c,
scripts/acvp_negative_scenarios.json. Its linked claims include claims not listed. This
is useful because it prevents a partner review from treating the release as a single
opaque binary; the asset can be followed through source, Kconfig, tests, transcript
markers, CBOM components, and policy decisions.

- Research gap: `validation.acvp_serial` needs at least one experiment that isolates its
  behavior from unrelated assets. If the asset is an algorithm family, the experiment
  should include KAT correctness, benchmark distribution, and failure injection. If the
  asset is validation infrastructure, the experiment should include malformed input and
  recovery behavior.
- Product gap: `validation.acvp_serial` should have a stable customer-facing status:
  production allowed, validation only, test only, experimental, or hardware pending. The
  status should appear consistently in CBOM properties, profile results, migration
  readiness output, and partner scorecard summaries.
- Implementation direction: extend the trace-map verifier so every source path for
  `validation.acvp_serial` must exist, every referenced claim must be in the ledger for
  the selected profile, and every dashboard view can show the path from asset to
  artifact hash.
- Acceptance criterion: removing a source path, claim link, CBOM component, or
  transcript marker for `validation.acvp_serial` from a synthetic fixture causes a
  targeted verifier failure rather than silently reducing coverage.

### Asset trace item 8: `validation.tls_selftest`

The asset `validation.tls_selftest` is part of the current asset trace map in
`scripts/pqc_asset_trace_map.json`. Its listed source coverage begins with
include/pqcp_zephyr/tls_selftest.h, src/tls_selftest.c,
samples/pqcp_tls_mbedtls_psa/src/main.c, tests/ztest_tls_selftest/src/main.c. Its linked
claims include claims not listed. This is useful because it prevents a partner review
from treating the release as a single opaque binary; the asset can be followed through
source, Kconfig, tests, transcript markers, CBOM components, and policy decisions.

- Research gap: `validation.tls_selftest` needs at least one experiment that isolates
  its behavior from unrelated assets. If the asset is an algorithm family, the
  experiment should include KAT correctness, benchmark distribution, and failure
  injection. If the asset is validation infrastructure, the experiment should include
  malformed input and recovery behavior.
- Product gap: `validation.tls_selftest` should have a stable customer-facing status:
  production allowed, validation only, test only, experimental, or hardware pending. The
  status should appear consistently in CBOM properties, profile results, migration
  readiness output, and partner scorecard summaries.
- Implementation direction: extend the trace-map verifier so every source path for
  `validation.tls_selftest` must exist, every referenced claim must be in the ledger for
  the selected profile, and every dashboard view can show the path from asset to
  artifact hash.
- Acceptance criterion: removing a source path, claim link, CBOM component, or
  transcript marker for `validation.tls_selftest` from a synthetic fixture causes a
  targeted verifier failure rather than silently reducing coverage.

### Asset trace item 9: `rng.zephyr_entropy`

The asset `rng.zephyr_entropy` is part of the current asset trace map in
`scripts/pqc_asset_trace_map.json`. Its listed source coverage begins with
include/pqcp_zephyr/rng.h, src/rng_common.c, src/rng_zephyr_entropy.c,
tests/ztest_rng/src/main.c. Its linked claims include claims not listed. This is useful
because it prevents a partner review from treating the release as a single opaque
binary; the asset can be followed through source, Kconfig, tests, transcript markers,
CBOM components, and policy decisions.

- Research gap: `rng.zephyr_entropy` needs at least one experiment that isolates its
  behavior from unrelated assets. If the asset is an algorithm family, the experiment
  should include KAT correctness, benchmark distribution, and failure injection. If the
  asset is validation infrastructure, the experiment should include malformed input and
  recovery behavior.
- Product gap: `rng.zephyr_entropy` should have a stable customer-facing status:
  production allowed, validation only, test only, experimental, or hardware pending. The
  status should appear consistently in CBOM properties, profile results, migration
  readiness output, and partner scorecard summaries.
- Implementation direction: extend the trace-map verifier so every source path for
  `rng.zephyr_entropy` must exist, every referenced claim must be in the ledger for the
  selected profile, and every dashboard view can show the path from asset to artifact
  hash.
- Acceptance criterion: removing a source path, claim link, CBOM component, or
  transcript marker for `rng.zephyr_entropy` from a synthetic fixture causes a targeted
  verifier failure rather than silently reducing coverage.

### Asset trace item 10: `rng.psa`

The asset `rng.psa` is part of the current asset trace map in
`scripts/pqc_asset_trace_map.json`. Its listed source coverage begins with
include/pqcp_zephyr/rng.h, src/rng_common.c, src/rng_psa.c, tests/ztest_rng/src/main.c.
Its linked claims include claims not listed. This is useful because it prevents a
partner review from treating the release as a single opaque binary; the asset can be
followed through source, Kconfig, tests, transcript markers, CBOM components, and policy
decisions.

- Research gap: `rng.psa` needs at least one experiment that isolates its behavior from
  unrelated assets. If the asset is an algorithm family, the experiment should include
  KAT correctness, benchmark distribution, and failure injection. If the asset is
  validation infrastructure, the experiment should include malformed input and recovery
  behavior.
- Product gap: `rng.psa` should have a stable customer-facing status: production
  allowed, validation only, test only, experimental, or hardware pending. The status
  should appear consistently in CBOM properties, profile results, migration readiness
  output, and partner scorecard summaries.
- Implementation direction: extend the trace-map verifier so every source path for
  `rng.psa` must exist, every referenced claim must be in the ledger for the selected
  profile, and every dashboard view can show the path from asset to artifact hash.
- Acceptance criterion: removing a source path, claim link, CBOM component, or
  transcript marker for `rng.psa` from a synthetic fixture causes a targeted verifier
  failure rather than silently reducing coverage.

### Asset trace item 11: `rng.deterministic_test`

The asset `rng.deterministic_test` is part of the current asset trace map in
`scripts/pqc_asset_trace_map.json`. Its listed source coverage begins with
include/pqcp_zephyr/rng.h, src/rng_common.c, src/rng_deterministic.c,
samples/pqcp_kat_deterministic/src/main.c. Its linked claims include claims not listed.
This is useful because it prevents a partner review from treating the release as a
single opaque binary; the asset can be followed through source, Kconfig, tests,
transcript markers, CBOM components, and policy decisions.

- Research gap: `rng.deterministic_test` needs at least one experiment that isolates its
  behavior from unrelated assets. If the asset is an algorithm family, the experiment
  should include KAT correctness, benchmark distribution, and failure injection. If the
  asset is validation infrastructure, the experiment should include malformed input and
  recovery behavior.
- Product gap: `rng.deterministic_test` should have a stable customer-facing status:
  production allowed, validation only, test only, experimental, or hardware pending. The
  status should appear consistently in CBOM properties, profile results, migration
  readiness output, and partner scorecard summaries.
- Implementation direction: extend the trace-map verifier so every source path for
  `rng.deterministic_test` must exist, every referenced claim must be in the ledger for
  the selected profile, and every dashboard view can show the path from asset to
  artifact hash.
- Acceptance criterion: removing a source path, claim link, CBOM component, or
  transcript marker for `rng.deterministic_test` from a synthetic fixture causes a
  targeted verifier failure rather than silently reducing coverage.

### Asset trace item 12: `boot.kat_self_verify`

The asset `boot.kat_self_verify` is part of the current asset trace map in
`scripts/pqc_asset_trace_map.json`. Its listed source coverage begins with
src/kat_boot_verify.c, tests/ztest_kat_boot_verify/src/main.c. Its linked claims include
claims not listed. This is useful because it prevents a partner review from treating the
release as a single opaque binary; the asset can be followed through source, Kconfig,
tests, transcript markers, CBOM components, and policy decisions.

- Research gap: `boot.kat_self_verify` needs at least one experiment that isolates its
  behavior from unrelated assets. If the asset is an algorithm family, the experiment
  should include KAT correctness, benchmark distribution, and failure injection. If the
  asset is validation infrastructure, the experiment should include malformed input and
  recovery behavior.
- Product gap: `boot.kat_self_verify` should have a stable customer-facing status:
  production allowed, validation only, test only, experimental, or hardware pending. The
  status should appear consistently in CBOM properties, profile results, migration
  readiness output, and partner scorecard summaries.
- Implementation direction: extend the trace-map verifier so every source path for
  `boot.kat_self_verify` must exist, every referenced claim must be in the ledger for
  the selected profile, and every dashboard view can show the path from asset to
  artifact hash.
- Acceptance criterion: removing a source path, claim link, CBOM component, or
  transcript marker for `boot.kat_self_verify` from a synthetic fixture causes a
  targeted verifier failure rather than silently reducing coverage.

### Asset trace item 13: `security.ct_smoke`

The asset `security.ct_smoke` is part of the current asset trace map in
`scripts/pqc_asset_trace_map.json`. Its listed source coverage begins with
tests/ztest_ct_smoke/src/main.c, scripts/verify_ct_instruction_policy.py. Its linked
claims include claims not listed. This is useful because it prevents a partner review
from treating the release as a single opaque binary; the asset can be followed through
source, Kconfig, tests, transcript markers, CBOM components, and policy decisions.

- Research gap: `security.ct_smoke` needs at least one experiment that isolates its
  behavior from unrelated assets. If the asset is an algorithm family, the experiment
  should include KAT correctness, benchmark distribution, and failure injection. If the
  asset is validation infrastructure, the experiment should include malformed input and
  recovery behavior.
- Product gap: `security.ct_smoke` should have a stable customer-facing status:
  production allowed, validation only, test only, experimental, or hardware pending. The
  status should appear consistently in CBOM properties, profile results, migration
  readiness output, and partner scorecard summaries.
- Implementation direction: extend the trace-map verifier so every source path for
  `security.ct_smoke` must exist, every referenced claim must be in the ledger for the
  selected profile, and every dashboard view can show the path from asset to artifact
  hash.
- Acceptance criterion: removing a source path, claim link, CBOM component, or
  transcript marker for `security.ct_smoke` from a synthetic fixture causes a targeted
  verifier failure rather than silently reducing coverage.

### Asset trace item 14: `crypto.slhdsa.external`

The asset `crypto.slhdsa.external` is part of the current asset trace map in
`scripts/pqc_asset_trace_map.json`. Its listed source coverage begins with
scripts/export_liboqs_inventory.py, scripts/verify_provider_scope.py. Its linked claims
include claims not listed. This is useful because it prevents a partner review from
treating the release as a single opaque binary; the asset can be followed through
source, Kconfig, tests, transcript markers, CBOM components, and policy decisions.

- Research gap: `crypto.slhdsa.external` needs at least one experiment that isolates its
  behavior from unrelated assets. If the asset is an algorithm family, the experiment
  should include KAT correctness, benchmark distribution, and failure injection. If the
  asset is validation infrastructure, the experiment should include malformed input and
  recovery behavior.
- Product gap: `crypto.slhdsa.external` should have a stable customer-facing status:
  production allowed, validation only, test only, experimental, or hardware pending. The
  status should appear consistently in CBOM properties, profile results, migration
  readiness output, and partner scorecard summaries.
- Implementation direction: extend the trace-map verifier so every source path for
  `crypto.slhdsa.external` must exist, every referenced claim must be in the ledger for
  the selected profile, and every dashboard view can show the path from asset to
  artifact hash.
- Acceptance criterion: removing a source path, claim link, CBOM component, or
  transcript marker for `crypto.slhdsa.external` from a synthetic fixture causes a
  targeted verifier failure rather than silently reducing coverage.

### Asset trace item 15: `crypto.hqc.external`

The asset `crypto.hqc.external` is part of the current asset trace map in
`scripts/pqc_asset_trace_map.json`. Its listed source coverage begins with
scripts/export_liboqs_inventory.py, scripts/verify_provider_scope.py. Its linked claims
include claims not listed. This is useful because it prevents a partner review from
treating the release as a single opaque binary; the asset can be followed through
source, Kconfig, tests, transcript markers, CBOM components, and policy decisions.

- Research gap: `crypto.hqc.external` needs at least one experiment that isolates its
  behavior from unrelated assets. If the asset is an algorithm family, the experiment
  should include KAT correctness, benchmark distribution, and failure injection. If the
  asset is validation infrastructure, the experiment should include malformed input and
  recovery behavior.
- Product gap: `crypto.hqc.external` should have a stable customer-facing status:
  production allowed, validation only, test only, experimental, or hardware pending. The
  status should appear consistently in CBOM properties, profile results, migration
  readiness output, and partner scorecard summaries.
- Implementation direction: extend the trace-map verifier so every source path for
  `crypto.hqc.external` must exist, every referenced claim must be in the ledger for the
  selected profile, and every dashboard view can show the path from asset to artifact
  hash.
- Acceptance criterion: removing a source path, claim link, CBOM component, or
  transcript marker for `crypto.hqc.external` from a synthetic fixture causes a targeted
  verifier failure rather than silently reducing coverage.

## Evidence Artifact Contract Closure Matrix

The new evidence schema contract is the product data boundary. A research artifact needs
the same boundary because reviewers must know what files are expected before they can
reproduce or mutate them. Each artifact below should have a producer, a schema, a replay
consumer, and a failure-mode test.


### Evidence artifact 1: `acvp_json_interop_result`

Artifact `acvp_json_interop_result` is expected at `acvp_json_interop_result.json` and
belongs to the ACVP interop and negative-path validation family. It is required for
these evidence profiles: partner_review, product_mvp. Its producer is recorded in the
schema catalog as release evidence tooling, and its primary consumer is offline release
verifier.

- Paper-grade role: `acvp_json_interop_result` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `acvp_json_interop_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `acvp_json_interop_result.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `acvp_json_interop_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 2: `acvp_json_schema_result`

Artifact `acvp_json_schema_result` is expected at `acvp_json_schema_result.json` and
belongs to the ACVP interop and negative-path validation family. It is required for
these evidence profiles: partner_review, product_mvp. Its producer is recorded in the
schema catalog as release evidence tooling, and its primary consumer is release replay
verifier.

- Paper-grade role: `acvp_json_schema_result` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `acvp_json_schema_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `acvp_json_schema_result.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `acvp_json_schema_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 3: `acvp_json_transcript_manifest`

Artifact `acvp_json_transcript_manifest` is expected at
`acvp_json_transcript_manifest.json` and belongs to the ACVP interop and negative-path
validation family. It is required for these evidence profiles: partner_review,
product_mvp. Its producer is recorded in the schema catalog as scripts/release_check.py,
and its primary consumer is offline release verifier.

- Paper-grade role: `acvp_json_transcript_manifest` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `acvp_json_transcript_manifest` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `acvp_json_transcript_manifest.json`, malformed digest fields, unsafe paths, stale
  release metadata, or missing required columns are detected before a partner consumes
  the artifact.
- Implementation direction: keep `acvp_json_transcript_manifest` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 4: `acvp_negative_scenario_floor_result`

Artifact `acvp_negative_scenario_floor_result` is expected at
`acvp_negative_scenario_floor_result.json` and belongs to the ACVP interop and negative-
path validation family. It is required for these evidence profiles: partner_review,
product_mvp. Its producer is recorded in the schema catalog as release evidence tooling,
and its primary consumer is offline release verifier.

- Paper-grade role: `acvp_negative_scenario_floor_result` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `acvp_negative_scenario_floor_result` should be stable enough that
  a dashboard, partner verifier, or customer integration can parse it without reading
  the producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `acvp_negative_scenario_floor_result.json`, malformed digest fields, unsafe paths,
  stale release metadata, or missing required columns are detected before a partner
  consumes the artifact.
- Implementation direction: keep `acvp_negative_scenario_floor_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 5: `assurance_ledger`

Artifact `assurance_ledger` is expected at `assurance_ledger.json` and belongs to the
claim-to-artifact traceability family. It is required for these evidence profiles:
qemu_release, partner_review, product_mvp. Its producer is recorded in the schema
catalog as scripts/generate_assurance_ledger.py, and its primary consumer is partner
reviewer and dashboard.

- Paper-grade role: `assurance_ledger` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `assurance_ledger` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing `assurance_ledger.json`,
  malformed digest fields, unsafe paths, stale release metadata, or missing required
  columns are detected before a partner consumes the artifact.
- Implementation direction: keep `assurance_ledger` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 6: `assurance_ledger_markdown`

Artifact `assurance_ledger_markdown` is expected at `assurance_ledger.md` and belongs to
the claim-to-artifact traceability family. It is required for these evidence profiles:
qemu_release, partner_review. Its producer is recorded in the schema catalog as
scripts/generate_assurance_ledger.py, and its primary consumer is offline release
verifier.

- Paper-grade role: `assurance_ledger_markdown` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `assurance_ledger_markdown` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing `assurance_ledger.md`,
  malformed digest fields, unsafe paths, stale release metadata, or missing required
  columns are detected before a partner consumes the artifact.
- Implementation direction: keep `assurance_ledger_markdown` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 7: `assurance_report_html`

Artifact `assurance_report_html` is expected at `assurance_report.html` and belongs to
the release evidence contract family. It is required for these evidence profiles:
partner_review, product_mvp. Its producer is recorded in the schema catalog as release
evidence tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `assurance_report_html` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `assurance_report_html` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing `assurance_report.html`,
  malformed digest fields, unsafe paths, stale release metadata, or missing required
  columns are detected before a partner consumes the artifact.
- Implementation direction: keep `assurance_report_html` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 8: `backend_contract_result`

Artifact `backend_contract_result` is expected at `backend_contract_result.json` and
belongs to the supply-chain and provider scope family. It is required for these evidence
profiles: partner_review, product_mvp. Its producer is recorded in the schema catalog as
release evidence tooling, and its primary consumer is security reviewer.

- Paper-grade role: `backend_contract_result` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `backend_contract_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `backend_contract_result.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `backend_contract_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 9: `backend_update_evaluation`

Artifact `backend_update_evaluation` is expected at `backend_update_evaluation.json` and
belongs to the supply-chain and provider scope family. It is required for these evidence
profiles: partner_review. Its producer is recorded in the schema catalog as release
evidence tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `backend_update_evaluation` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `backend_update_evaluation` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `backend_update_evaluation.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `backend_update_evaluation` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 10: `benchmark_campaign_result`

Artifact `benchmark_campaign_result` is expected at `benchmark_campaign_result.json` and
belongs to the benchmark and performance evidence family. It is required for these
evidence profiles: partner_review, product_mvp. Its producer is recorded in the schema
catalog as benchmark tooling, and its primary consumer is benchmark reviewer and paper
appendix.

- Paper-grade role: `benchmark_campaign_result` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `benchmark_campaign_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `benchmark_campaign_result.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `benchmark_campaign_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 11: `benchmark_campaign_verify_result`

Artifact `benchmark_campaign_verify_result` is expected at
`benchmark_campaign_verify_result.json` and belongs to the benchmark and performance
evidence family. It is required for these evidence profiles: partner_review,
product_mvp. Its producer is recorded in the schema catalog as benchmark tooling, and
its primary consumer is release replay verifier.

- Paper-grade role: `benchmark_campaign_verify_result` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `benchmark_campaign_verify_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `benchmark_campaign_verify_result.json`, malformed digest fields, unsafe paths, stale
  release metadata, or missing required columns are detected before a partner consumes
  the artifact.
- Implementation direction: keep `benchmark_campaign_verify_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 12: `benchmark_confidence_result`

Artifact `benchmark_confidence_result` is expected at `benchmark_confidence_result.json`
and belongs to the benchmark and performance evidence family. It is required for these
evidence profiles: partner_review, product_mvp. Its producer is recorded in the schema
catalog as benchmark tooling, and its primary consumer is benchmark reviewer and paper
appendix.

- Paper-grade role: `benchmark_confidence_result` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `benchmark_confidence_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `benchmark_confidence_result.json`, malformed digest fields, unsafe paths, stale
  release metadata, or missing required columns are detected before a partner consumes
  the artifact.
- Implementation direction: keep `benchmark_confidence_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 13: `benchmark_provenance`

Artifact `benchmark_provenance` is expected at `benchmark_provenance.json` and belongs
to the benchmark and performance evidence family. It is required for these evidence
profiles: qemu_release, partner_review, product_mvp. Its producer is recorded in the
schema catalog as benchmark tooling, and its primary consumer is benchmark reviewer and
paper appendix.

- Paper-grade role: `benchmark_provenance` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `benchmark_provenance` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `benchmark_provenance.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `benchmark_provenance` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 14: `benchmark_results_csv`

Artifact `benchmark_results_csv` is expected at `benchmark_results.csv` and belongs to
the benchmark and performance evidence family. It is required for these evidence
profiles: qemu_release, partner_review, product_mvp. Its producer is recorded in the
schema catalog as benchmark tooling, and its primary consumer is benchmark reviewer and
paper appendix.

- Paper-grade role: `benchmark_results_csv` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `benchmark_results_csv` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing `benchmark_results.csv`,
  malformed digest fields, unsafe paths, stale release metadata, or missing required
  columns are detected before a partner consumes the artifact.
- Implementation direction: keep `benchmark_results_csv` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 15: `benchmark_summary_markdown`

Artifact `benchmark_summary_markdown` is expected at `benchmark_summary.md` and belongs
to the benchmark and performance evidence family. It is required for these evidence
profiles: partner_review. Its producer is recorded in the schema catalog as benchmark
tooling, and its primary consumer is benchmark reviewer and paper appendix.

- Paper-grade role: `benchmark_summary_markdown` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `benchmark_summary_markdown` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing `benchmark_summary.md`,
  malformed digest fields, unsafe paths, stale release metadata, or missing required
  columns are detected before a partner consumes the artifact.
- Implementation direction: keep `benchmark_summary_markdown` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 16: `cost_of_assurance_evidence`

Artifact `cost_of_assurance_evidence` is expected at `cost_of_assurance_evidence.json`
and belongs to the release evidence contract family. It is required for these evidence
profiles: qemu_release, partner_review, product_mvp. Its producer is recorded in the
schema catalog as release evidence tooling, and its primary consumer is offline release
verifier.

- Paper-grade role: `cost_of_assurance_evidence` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `cost_of_assurance_evidence` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `cost_of_assurance_evidence.json`, malformed digest fields, unsafe paths, stale
  release metadata, or missing required columns are detected before a partner consumes
  the artifact.
- Implementation direction: keep `cost_of_assurance_evidence` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 17: `ct_campaign_result`

Artifact `ct_campaign_result` is expected at `ct_campaign_result.json` and belongs to
the side-channel smoke evidence family. It is required for these evidence profiles:
partner_review. Its producer is recorded in the schema catalog as release evidence
tooling, and its primary consumer is security reviewer.

- Paper-grade role: `ct_campaign_result` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `ct_campaign_result` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `ct_campaign_result.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `ct_campaign_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 18: `ct_instruction_policy_result`

Artifact `ct_instruction_policy_result` is expected at
`ct_instruction_policy_result.json` and belongs to the policy replay and partner
appraisal family. It is required for these evidence profiles: partner_review,
product_mvp. Its producer is recorded in the schema catalog as
scripts/verify_assurance_policy.py, and its primary consumer is security reviewer.

- Paper-grade role: `ct_instruction_policy_result` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `ct_instruction_policy_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `ct_instruction_policy_result.json`, malformed digest fields, unsafe paths, stale
  release metadata, or missing required columns are detected before a partner consumes
  the artifact.
- Implementation direction: keep `ct_instruction_policy_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 19: `ct_sample_analysis_result`

Artifact `ct_sample_analysis_result` is expected at `ct_sample_analysis_result.json` and
belongs to the side-channel smoke evidence family. It is required for these evidence
profiles: partner_review. Its producer is recorded in the schema catalog as release
evidence tooling, and its primary consumer is security reviewer.

- Paper-grade role: `ct_sample_analysis_result` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `ct_sample_analysis_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `ct_sample_analysis_result.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `ct_sample_analysis_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 20: `device_evidence_token`

Artifact `device_evidence_token` is expected at `device_evidence_token.json` and belongs
to the reference values and device-evidence preparation family. It is required for these
evidence profiles: partner_review. Its producer is recorded in the schema catalog as
release evidence tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `device_evidence_token` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `device_evidence_token` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `device_evidence_token.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `device_evidence_token` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 21: `device_evidence_token_result`

Artifact `device_evidence_token_result` is expected at
`device_evidence_token_result.json` and belongs to the reference values and device-
evidence preparation family. It is required for these evidence profiles: partner_review.
Its producer is recorded in the schema catalog as release evidence tooling, and its
primary consumer is offline release verifier.

- Paper-grade role: `device_evidence_token_result` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `device_evidence_token_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `device_evidence_token_result.json`, malformed digest fields, unsafe paths, stale
  release metadata, or missing required columns are detected before a partner consumes
  the artifact.
- Implementation direction: keep `device_evidence_token_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 22: `evidence_tamper_drill_result`

Artifact `evidence_tamper_drill_result` is expected at
`evidence_tamper_drill_result.json` and belongs to the release evidence contract family.
It is required for these evidence profiles: partner_review, product_mvp. Its producer is
recorded in the schema catalog as release evidence tooling, and its primary consumer is
offline release verifier.

- Paper-grade role: `evidence_tamper_drill_result` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `evidence_tamper_drill_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `evidence_tamper_drill_result.json`, malformed digest fields, unsafe paths, stale
  release metadata, or missing required columns are detected before a partner consumes
  the artifact.
- Implementation direction: keep `evidence_tamper_drill_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 23: `evidence_transcript_manifest`

Artifact `evidence_transcript_manifest` is expected at
`transcripts/evidence_transcript_manifest.json` and belongs to the claim-to-artifact
traceability family. It is required for these evidence profiles: qemu_release,
partner_review, product_mvp. Its producer is recorded in the schema catalog as
scripts/release_check.py, and its primary consumer is offline release verifier.

- Paper-grade role: `evidence_transcript_manifest` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `evidence_transcript_manifest` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `transcripts/evidence_transcript_manifest.json`, malformed digest fields, unsafe
  paths, stale release metadata, or missing required columns are detected before a
  partner consumes the artifact.
- Implementation direction: keep `evidence_transcript_manifest` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 24: `external_non_native_inventory`

Artifact `external_non_native_inventory` is expected at
`liboqs_non_native_inventory.json` and belongs to the release evidence contract family.
It is required for these evidence profiles: partner_review. Its producer is recorded in
the schema catalog as release evidence tooling, and its primary consumer is offline
release verifier.

- Paper-grade role: `external_non_native_inventory` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `external_non_native_inventory` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `liboqs_non_native_inventory.json`, malformed digest fields, unsafe paths, stale
  release metadata, or missing required columns are detected before a partner consumes
  the artifact.
- Implementation direction: keep `external_non_native_inventory` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 25: `firmware_assurance_status_result`

Artifact `firmware_assurance_status_result` is expected at
`firmware_assurance_status_result.json` and belongs to the reference values and device-
evidence preparation family. It is required for these evidence profiles: partner_review.
Its producer is recorded in the schema catalog as release evidence tooling, and its
primary consumer is offline release verifier.

- Paper-grade role: `firmware_assurance_status_result` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `firmware_assurance_status_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `firmware_assurance_status_result.json`, malformed digest fields, unsafe paths, stale
  release metadata, or missing required columns are detected before a partner consumes
  the artifact.
- Implementation direction: keep `firmware_assurance_status_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 26: `firmware_digest_header`

Artifact `firmware_digest_header` is expected at
`generated/pqcp_assurance_digest_generated.h` and belongs to the reference values and
device-evidence preparation family. It is required for these evidence profiles:
partner_review. Its producer is recorded in the schema catalog as release evidence
tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `firmware_digest_header` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `firmware_digest_header` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `generated/pqcp_assurance_digest_generated.h`, malformed digest fields, unsafe paths,
  stale release metadata, or missing required columns are detected before a partner
  consumes the artifact.
- Implementation direction: keep `firmware_digest_header` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 27: `mcu_protocol_footprint_csv`

Artifact `mcu_protocol_footprint_csv` is expected at
`mcu_protocol_footprint/cost_of_assurance_protocols_mcu.csv` and belongs to the release
evidence contract family. It is required for these evidence profiles: partner_review,
product_mvp. Its producer is recorded in the schema catalog as release evidence tooling,
and its primary consumer is offline release verifier.

- Paper-grade role: `mcu_protocol_footprint_csv` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `mcu_protocol_footprint_csv` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `mcu_protocol_footprint/cost_of_assurance_protocols_mcu.csv`, malformed digest fields,
  unsafe paths, stale release metadata, or missing required columns are detected before
  a partner consumes the artifact.
- Implementation direction: keep `mcu_protocol_footprint_csv` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 28: `paper_comparison_campaign_csv`

Artifact `paper_comparison_campaign_csv` is expected at `paper_comparison_campaign.csv`
and belongs to the release evidence contract family. It is required for these evidence
profiles: partner_review. Its producer is recorded in the schema catalog as benchmark
tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `paper_comparison_campaign_csv` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `paper_comparison_campaign_csv` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `paper_comparison_campaign.csv`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `paper_comparison_campaign_csv` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 29: `paper_comparison_campaign_json`

Artifact `paper_comparison_campaign_json` is expected at
`paper_comparison_campaign.json` and belongs to the release evidence contract family. It
is required for these evidence profiles: partner_review. Its producer is recorded in the
schema catalog as benchmark tooling, and its primary consumer is offline release
verifier.

- Paper-grade role: `paper_comparison_campaign_json` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `paper_comparison_campaign_json` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `paper_comparison_campaign.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `paper_comparison_campaign_json` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 30: `partner_review_scorecard`

Artifact `partner_review_scorecard` is expected at `partner_review_scorecard.json` and
belongs to the release evidence contract family. It is required for these evidence
profiles: partner_review, product_mvp. Its producer is recorded in the schema catalog as
scripts/generate_partner_review_scorecard.py, and its primary consumer is partner
reviewer and dashboard.

- Paper-grade role: `partner_review_scorecard` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `partner_review_scorecard` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `partner_review_scorecard.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `partner_review_scorecard` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 31: `partner_review_scorecard_markdown`

Artifact `partner_review_scorecard_markdown` is expected at
`partner_review_scorecard.md` and belongs to the release evidence contract family. It is
required for these evidence profiles: partner_review, product_mvp. Its producer is
recorded in the schema catalog as scripts/generate_partner_review_scorecard.py, and its
primary consumer is offline release verifier.

- Paper-grade role: `partner_review_scorecard_markdown` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `partner_review_scorecard_markdown` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `partner_review_scorecard.md`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `partner_review_scorecard_markdown` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 32: `partner_review_scorecard_result`

Artifact `partner_review_scorecard_result` is expected at
`partner_review_scorecard_result.json` and belongs to the release evidence contract
family. It is required for these evidence profiles: partner_review, product_mvp. Its
producer is recorded in the schema catalog as
scripts/generate_partner_review_scorecard.py, and its primary consumer is offline
release verifier.

- Paper-grade role: `partner_review_scorecard_result` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `partner_review_scorecard_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `partner_review_scorecard_result.json`, malformed digest fields, unsafe paths, stale
  release metadata, or missing required columns are detected before a partner consumes
  the artifact.
- Implementation direction: keep `partner_review_scorecard_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 33: `pqc_appraisal_evidence`

Artifact `pqc_appraisal_evidence` is expected at `pqc_appraisal_evidence.json` and
belongs to the policy replay and partner appraisal family. It is required for these
evidence profiles: partner_review, product_mvp. Its producer is recorded in the schema
catalog as release evidence tooling, and its primary consumer is offline release
verifier.

- Paper-grade role: `pqc_appraisal_evidence` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `pqc_appraisal_evidence` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `pqc_appraisal_evidence.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `pqc_appraisal_evidence` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 34: `pqc_appraisal_result`

Artifact `pqc_appraisal_result` is expected at `pqc_appraisal_result.json` and belongs
to the policy replay and partner appraisal family. It is required for these evidence
profiles: partner_review, product_mvp. Its producer is recorded in the schema catalog as
release evidence tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `pqc_appraisal_result` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `pqc_appraisal_result` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `pqc_appraisal_result.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `pqc_appraisal_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 35: `pqc_asset_trace_result`

Artifact `pqc_asset_trace_result` is expected at `pqc_asset_trace_result.json` and
belongs to the release evidence contract family. It is required for these evidence
profiles: partner_review, product_mvp. Its producer is recorded in the schema catalog as
release evidence tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `pqc_asset_trace_result` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `pqc_asset_trace_result` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `pqc_asset_trace_result.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `pqc_asset_trace_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 36: `pqc_assurance_digest`

Artifact `pqc_assurance_digest` is expected at `pqc_assurance_digest.json` and belongs
to the release evidence contract family. It is required for these evidence profiles:
partner_review, product_mvp. Its producer is recorded in the schema catalog as release
evidence tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `pqc_assurance_digest` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `pqc_assurance_digest` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `pqc_assurance_digest.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `pqc_assurance_digest` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 37: `pqc_assurance_profile_result`

Artifact `pqc_assurance_profile_result` is expected at
`pqc_assurance_profile_result.json` and belongs to the release evidence contract family.
It is required for these evidence profiles: partner_review, product_mvp. Its producer is
recorded in the schema catalog as release evidence tooling, and its primary consumer is
offline release verifier.

- Paper-grade role: `pqc_assurance_profile_result` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `pqc_assurance_profile_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `pqc_assurance_profile_result.json`, malformed digest fields, unsafe paths, stale
  release metadata, or missing required columns are detected before a partner consumes
  the artifact.
- Implementation direction: keep `pqc_assurance_profile_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 38: `pqc_attestation`

Artifact `pqc_attestation` is expected at `pqc_attestation.intoto.json` and belongs to
the claim-to-artifact traceability family. It is required for these evidence profiles:
partner_review, product_mvp. Its producer is recorded in the schema catalog as
scripts/generate_pqc_attestation.py, and its primary consumer is offline release
verifier.

- Paper-grade role: `pqc_attestation` should be cited as part of the artifact-evaluation
  bundle, with a clear explanation of what experiment or replay relationship it proves.
  For example, an artifact in the benchmark family should provide enough metadata to
  compare rows only under matching board, compiler, backend, and statistic assumptions.
- Product-grade role: `pqc_attestation` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `pqc_attestation.intoto.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `pqc_attestation` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 39: `pqc_build_provenance`

Artifact `pqc_build_provenance` is expected at `pqc_build_provenance.slsa.json` and
belongs to the release evidence contract family. It is required for these evidence
profiles: partner_review, product_mvp. Its producer is recorded in the schema catalog as
release evidence tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `pqc_build_provenance` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `pqc_build_provenance` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `pqc_build_provenance.slsa.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `pqc_build_provenance` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 40: `pqc_build_provenance_result`

Artifact `pqc_build_provenance_result` is expected at `pqc_build_provenance_result.json`
and belongs to the release evidence contract family. It is required for these evidence
profiles: partner_review, product_mvp. Its producer is recorded in the schema catalog as
release evidence tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `pqc_build_provenance_result` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `pqc_build_provenance_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `pqc_build_provenance_result.json`, malformed digest fields, unsafe paths, stale
  release metadata, or missing required columns are detected before a partner consumes
  the artifact.
- Implementation direction: keep `pqc_build_provenance_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 41: `pqc_cbom`

Artifact `pqc_cbom` is expected at `pqc_cbom.cdx.json` and belongs to the supply-chain
and provider scope family. It is required for these evidence profiles: partner_review,
product_mvp. Its producer is recorded in the schema catalog as
scripts/export_pqc_cbom.py, and its primary consumer is partner reviewer and dashboard.

- Paper-grade role: `pqc_cbom` should be cited as part of the artifact-evaluation
  bundle, with a clear explanation of what experiment or replay relationship it proves.
  For example, an artifact in the benchmark family should provide enough metadata to
  compare rows only under matching board, compiler, backend, and statistic assumptions.
- Product-grade role: `pqc_cbom` should be stable enough that a dashboard, partner
  verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing `pqc_cbom.cdx.json`,
  malformed digest fields, unsafe paths, stale release metadata, or missing required
  columns are detected before a partner consumes the artifact.
- Implementation direction: keep `pqc_cbom` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 42: `pqc_claim_closure_result`

Artifact `pqc_claim_closure_result` is expected at `pqc_claim_closure_result.json` and
belongs to the release evidence contract family. It is required for these evidence
profiles: partner_review, product_mvp. Its producer is recorded in the schema catalog as
release evidence tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `pqc_claim_closure_result` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `pqc_claim_closure_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `pqc_claim_closure_result.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `pqc_claim_closure_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 43: `pqc_environment_result`

Artifact `pqc_environment_result` is expected at `pqc_environment_result.json` and
belongs to the release evidence contract family. It is required for these evidence
profiles: partner_review, product_mvp. Its producer is recorded in the schema catalog as
release evidence tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `pqc_environment_result` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `pqc_environment_result` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `pqc_environment_result.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `pqc_environment_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 44: `pqc_evidence_graph_json`

Artifact `pqc_evidence_graph_json` is expected at `pqc_evidence_graph.json` and belongs
to the release evidence contract family. It is required for these evidence profiles:
partner_review, product_mvp. Its producer is recorded in the schema catalog as release
evidence tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `pqc_evidence_graph_json` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `pqc_evidence_graph_json` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `pqc_evidence_graph.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `pqc_evidence_graph_json` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 45: `pqc_evidence_graph_markdown`

Artifact `pqc_evidence_graph_markdown` is expected at `pqc_evidence_graph.md` and
belongs to the release evidence contract family. It is required for these evidence
profiles: partner_review. Its producer is recorded in the schema catalog as release
evidence tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `pqc_evidence_graph_markdown` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `pqc_evidence_graph_markdown` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing `pqc_evidence_graph.md`,
  malformed digest fields, unsafe paths, stale release metadata, or missing required
  columns are detected before a partner consumes the artifact.
- Implementation direction: keep `pqc_evidence_graph_markdown` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 46: `pqc_evidence_quality_result`

Artifact `pqc_evidence_quality_result` is expected at `pqc_evidence_quality_result.json`
and belongs to the release evidence contract family. It is required for these evidence
profiles: partner_review, product_mvp. Its producer is recorded in the schema catalog as
release evidence tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `pqc_evidence_quality_result` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `pqc_evidence_quality_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `pqc_evidence_quality_result.json`, malformed digest fields, unsafe paths, stale
  release metadata, or missing required columns are detected before a partner consumes
  the artifact.
- Implementation direction: keep `pqc_evidence_quality_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 47: `pqc_migration_readiness_json`

Artifact `pqc_migration_readiness_json` is expected at `pqc_migration_readiness.json`
and belongs to the release evidence contract family. It is required for these evidence
profiles: partner_review, product_mvp. Its producer is recorded in the schema catalog as
release evidence tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `pqc_migration_readiness_json` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `pqc_migration_readiness_json` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `pqc_migration_readiness.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `pqc_migration_readiness_json` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 48: `pqc_migration_readiness_markdown`

Artifact `pqc_migration_readiness_markdown` is expected at `pqc_migration_readiness.md`
and belongs to the release evidence contract family. It is required for these evidence
profiles: partner_review. Its producer is recorded in the schema catalog as release
evidence tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `pqc_migration_readiness_markdown` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `pqc_migration_readiness_markdown` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `pqc_migration_readiness.md`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `pqc_migration_readiness_markdown` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 49: `pqc_policy_result`

Artifact `pqc_policy_result` is expected at `pqc_policy_result.json` and belongs to the
policy replay and partner appraisal family. It is required for these evidence profiles:
partner_review, product_mvp. Its producer is recorded in the schema catalog as
scripts/verify_assurance_policy.py, and its primary consumer is partner reviewer and
dashboard.

- Paper-grade role: `pqc_policy_result` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `pqc_policy_result` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `pqc_policy_result.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `pqc_policy_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 50: `pqc_reference_values`

Artifact `pqc_reference_values` is expected at `pqc_reference_values.json` and belongs
to the reference values and device-evidence preparation family. It is required for these
evidence profiles: partner_review, product_mvp. Its producer is recorded in the schema
catalog as reference-value tooling, and its primary consumer is offline release
verifier.

- Paper-grade role: `pqc_reference_values` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `pqc_reference_values` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `pqc_reference_values.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `pqc_reference_values` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 51: `pqc_reference_values_result`

Artifact `pqc_reference_values_result` is expected at `pqc_reference_values_result.json`
and belongs to the reference values and device-evidence preparation family. It is
required for these evidence profiles: partner_review, product_mvp. Its producer is
recorded in the schema catalog as reference-value tooling, and its primary consumer is
offline release verifier.

- Paper-grade role: `pqc_reference_values_result` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `pqc_reference_values_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `pqc_reference_values_result.json`, malformed digest fields, unsafe paths, stale
  release metadata, or missing required columns are detected before a partner consumes
  the artifact.
- Implementation direction: keep `pqc_reference_values_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 52: `provider_scope_result`

Artifact `provider_scope_result` is expected at `provider_scope_result.json` and belongs
to the supply-chain and provider scope family. It is required for these evidence
profiles: partner_review, product_mvp. Its producer is recorded in the schema catalog as
release evidence tooling, and its primary consumer is offline release verifier.

- Paper-grade role: `provider_scope_result` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `provider_scope_result` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `provider_scope_result.json`, malformed digest fields, unsafe paths, stale release
  metadata, or missing required columns are detected before a partner consumes the
  artifact.
- Implementation direction: keep `provider_scope_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 53: `release_manifest`

Artifact `release_manifest` is expected at `local_release_bundle/{tag}/release-
manifest-{tag}.json` and belongs to the release evidence contract family. It is required
for these evidence profiles: qemu_release, partner_review, product_mvp. Its producer is
recorded in the schema catalog as release evidence tooling, and its primary consumer is
offline release verifier.

- Paper-grade role: `release_manifest` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `release_manifest` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `local_release_bundle/{tag}/release-manifest-{tag}.json`, malformed digest fields,
  unsafe paths, stale release metadata, or missing required columns are detected before
  a partner consumes the artifact.
- Implementation direction: keep `release_manifest` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 54: `release_notes_markdown`

Artifact `release_notes_markdown` is expected at `local_release_bundle/{tag}/release-
notes-{tag}.md` and belongs to the release evidence contract family. It is required for
these evidence profiles: partner_review, product_mvp. Its producer is recorded in the
schema catalog as release evidence tooling, and its primary consumer is offline release
verifier.

- Paper-grade role: `release_notes_markdown` should be cited as part of the artifact-
  evaluation bundle, with a clear explanation of what experiment or replay relationship
  it proves. For example, an artifact in the benchmark family should provide enough
  metadata to compare rows only under matching board, compiler, backend, and statistic
  assumptions.
- Product-grade role: `release_notes_markdown` should be stable enough that a dashboard,
  partner verifier, or customer integration can parse it without reading the producer
  implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `local_release_bundle/{tag}/release-notes-{tag}.md`, malformed digest fields, unsafe
  paths, stale release metadata, or missing required columns are detected before a
  partner consumes the artifact.
- Implementation direction: keep `release_notes_markdown` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

### Evidence artifact 55: `release_reference_values_result`

Artifact `release_reference_values_result` is expected at
`release_reference_values_result.json` and belongs to the reference values and device-
evidence preparation family. It is required for these evidence profiles: partner_review,
product_mvp. Its producer is recorded in the schema catalog as reference-value tooling,
and its primary consumer is offline release verifier.

- Paper-grade role: `release_reference_values_result` should be cited as part of the
  artifact-evaluation bundle, with a clear explanation of what experiment or replay
  relationship it proves. For example, an artifact in the benchmark family should
  provide enough metadata to compare rows only under matching board, compiler, backend,
  and statistic assumptions.
- Product-grade role: `release_reference_values_result` should be stable enough that a
  dashboard, partner verifier, or customer integration can parse it without reading the
  producer implementation. Any schema break must be versioned and documented in
  `schemas/evidence/README.md`.
- Failure-mode requirement: a fixture should prove that missing
  `release_reference_values_result.json`, malformed digest fields, unsafe paths, stale
  release metadata, or missing required columns are detected before a partner consumes
  the artifact.
- Implementation direction: keep `release_reference_values_result` in
  `schemas/evidence/evidence_schema_catalog.json`, maintain its schema under
  `schemas/evidence/artifacts/`, and add product-MVP fixture coverage when the artifact
  is required for customer review.

## Tooling Surface Audit By Script

The repository has a large Python tooling surface. For paper-grade use, scripts must be
categorized as experiment runners, artifact generators, replay validators, or support
utilities. For product-grade use, scripts must have stable inputs, stable outputs,
failure messages, and a place in the release workflow.


### Script audit item 1: `analyze_ct_samples.py`

`analyze_ct_samples.py` is classified as a support utility. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """Analyze PQCP_CT_SAMPLE transcript markers for timing-smoke
regressions.""" from __future__ import annotations import argparse import json import
math import re import statistics import sys from datetime import datetime, timezone from
pathlib. This classification matters because the paper and product story should not
treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `analyze_ct_samples.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `analyze_ct_samples.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `analyze_ct_samples.py` succeeds on a synthetic fixture and one path where a realistic
  invalid input fails non-zero. If the script depends on west or hardware, the unit test
  should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `analyze_ct_samples.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 2: `check_resource_budgets.py`

`check_resource_budgets.py` is classified as a release check. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """ Run MCU protocol build-only cost-of-assurance rows and
enforce ROM/RAM budgets. """ from __future__ import annotations import argparse import
csv import json import os import re import shlex import shutil. This classification
matters because the paper and product story should not treat all scripts equally.
Runners create evidence, generators shape evidence, validators replay evidence, and
tests preserve contract behavior.

- Research-grade expectation: `check_resource_budgets.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `check_resource_budgets.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `check_resource_budgets.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `check_resource_budgets.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 3: `check_version_consistency.py`

`check_version_consistency.py` is classified as a release check. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """ Validate version consistency across version.h,
CMakeLists.txt, CHANGELOG.md (optional), and an optional git tag. """ from __future__
import annotations import argparse import re import sys from pathlib import Path
SCRIPT_DIR. This classification matters because the paper and product story should not
treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `check_version_consistency.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `check_version_consistency.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `check_version_consistency.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `check_version_consistency.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 4: `consumer_smoke.py`

`consumer_smoke.py` is classified as a support utility. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """Run the smallest west-based consumer smoke check for this
module.""" from __future__ import annotations import argparse import sys from pathlib
import Path SCRIPT_DIR = Path(__file__).resolve().parent if str(SCRIPT_DIR) not in
sys.path:. This classification matters because the paper and product story should not
treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `consumer_smoke.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `consumer_smoke.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `consumer_smoke.py` succeeds on a synthetic fixture and one path where a realistic
  invalid input fails non-zero. If the script depends on west or hardware, the unit test
  should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `consumer_smoke.py` to a release, benchmark, ACVP, side-
  channel, provider, schema, or product workflow lane so maintainers know whether it
  belongs in CI fast gate, full local release, hardware review, or partner-only replay.

### Script audit item 5: `evaluate_backend_update.py`

`evaluate_backend_update.py` is classified as a support utility. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Evaluate PQ Code Package backend update
candidates without vendoring code.""" from __future__ import annotations import argparse
import hashlib import json import shutil import subprocess import tempfile from datetime
import datetime,. This classification matters because the paper and product story should
not treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `evaluate_backend_update.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `evaluate_backend_update.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `evaluate_backend_update.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `evaluate_backend_update.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 6: `export_firmware_assurance_digest.py`

`export_firmware_assurance_digest.py` is classified as a artifact generator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Export pqc_assurance_digest.json into a
firmware-embeddable C header.""" from __future__ import annotations import argparse
import hashlib import json import re import sys from datetime import datetime, timezone
from pathlib import Path. This classification matters because the paper and product
story should not treat all scripts equally. Runners create evidence, generators shape
evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `export_firmware_assurance_digest.py` should be callable
  in a clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `export_firmware_assurance_digest.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `export_firmware_assurance_digest.py` succeeds on a synthetic fixture and one path
  where a realistic invalid input fails non-zero. If the script depends on west or
  hardware, the unit test should validate argument parsing and replay behavior with
  fixtures.
- Integration direction: map `export_firmware_assurance_digest.py` to a release,
  benchmark, ACVP, side-channel, provider, schema, or product workflow lane so
  maintainers know whether it belongs in CI fast gate, full local release, hardware
  review, or partner-only replay.

### Script audit item 7: `export_liboqs_inventory.py`

`export_liboqs_inventory.py` is classified as a artifact generator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Export an experimental non-native scheme
inventory for provider-scope review.""" from __future__ import annotations import
argparse import hashlib import json import subprocess from datetime import datetime,
timezone from pathlib import Path. This classification matters because the paper and
product story should not treat all scripts equally. Runners create evidence, generators
shape evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `export_liboqs_inventory.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `export_liboqs_inventory.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `export_liboqs_inventory.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `export_liboqs_inventory.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 8: `export_pqc_cbom.py`

`export_pqc_cbom.py` is classified as a artifact generator. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """Export a CycloneDX-style cryptography BOM for the PQCP
assurance pack.""" from __future__ import annotations import argparse import json import
re import subprocess import sys import uuid from datetime import datetime,. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `export_pqc_cbom.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `export_pqc_cbom.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `export_pqc_cbom.py` succeeds on a synthetic fixture and one path where a realistic
  invalid input fails non-zero. If the script depends on west or hardware, the unit test
  should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `export_pqc_cbom.py` to a release, benchmark, ACVP, side-
  channel, provider, schema, or product workflow lane so maintainers know whether it
  belongs in CI fast gate, full local release, hardware review, or partner-only replay.

### Script audit item 9: `export_results.py`

`export_results.py` is classified as a artifact generator. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """ Export PQCP benchmark matrix results into a publication-
friendly CSV. """ from __future__ import annotations import argparse import csv import
hashlib import json import math import os import platform as. This classification
matters because the paper and product story should not treat all scripts equally.
Runners create evidence, generators shape evidence, validators replay evidence, and
tests preserve contract behavior.

- Research-grade expectation: `export_results.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `export_results.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `export_results.py` succeeds on a synthetic fixture and one path where a realistic
  invalid input fails non-zero. If the script depends on west or hardware, the unit test
  should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `export_results.py` to a release, benchmark, ACVP, side-
  channel, provider, schema, or product workflow lane so maintainers know whether it
  belongs in CI fast gate, full local release, hardware review, or partner-only replay.

### Script audit item 10: `extract_changelog_section.py`

`extract_changelog_section.py` is classified as a support utility. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Extract Keep a Changelog sections for release
automation.""" from __future__ import annotations import argparse import re from pathlib
import Path SECTION_RE = re.compile(r"^## \[([^\]]+)\](?:[ \t]+-[ \t]+[^\r\n]*)?$",
re.MULTILINE) def parse_args() ->. This classification matters because the paper and
product story should not treat all scripts equally. Runners create evidence, generators
shape evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `extract_changelog_section.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `extract_changelog_section.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `extract_changelog_section.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `extract_changelog_section.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 11: `generate_acvp_negative_header.py`

`generate_acvp_negative_header.py` is classified as a artifact generator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Render scripts/acvp_negative_scenarios.json into
a C header. The generated header backs tests/ztest_acvp_serial_negative, which exercises
the ACVP serial harness against every documented negative scenario directly through
pqcp_acvp_process_command() rather than by grepping a. This classification matters
because the paper and product story should not treat all scripts equally. Runners create
evidence, generators shape evidence, validators replay evidence, and tests preserve
contract behavior.

- Research-grade expectation: `generate_acvp_negative_header.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `generate_acvp_negative_header.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `generate_acvp_negative_header.py` succeeds on a synthetic fixture and one path where
  a realistic invalid input fails non-zero. If the script depends on west or hardware,
  the unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `generate_acvp_negative_header.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 12: `generate_assurance_ledger.py`

`generate_assurance_ledger.py` is classified as a artifact generator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Generate a local release assurance ledger from
validated artifacts.""" from __future__ import annotations import argparse import csv
import hashlib import json import subprocess import sys from datetime import datetime,
timezone. This classification matters because the paper and product story should not
treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `generate_assurance_ledger.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `generate_assurance_ledger.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `generate_assurance_ledger.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `generate_assurance_ledger.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 13: `generate_migration_readiness_report.py`

`generate_migration_readiness_report.py` is classified as a artifact generator. Its
opening implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier:
LicenseRef-Proprietary-Collaborative-Evaluation """Generate JSON and Markdown migration-
readiness summaries from Passport checks.""" from __future__ import annotations import
argparse import json import sys from datetime import datetime, timezone from pathlib
import Path from typing. This classification matters because the paper and product story
should not treat all scripts equally. Runners create evidence, generators shape
evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `generate_migration_readiness_report.py` should be
  callable in a clean workspace or explicitly marked as requiring Zephyr, hardware,
  network, or generated pack inputs. The expected output files should be stated in docs
  or in the schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `generate_migration_readiness_report.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `generate_migration_readiness_report.py` succeeds on a synthetic fixture and one path
  where a realistic invalid input fails non-zero. If the script depends on west or
  hardware, the unit test should validate argument parsing and replay behavior with
  fixtures.
- Integration direction: map `generate_migration_readiness_report.py` to a release,
  benchmark, ACVP, side-channel, provider, schema, or product workflow lane so
  maintainers know whether it belongs in CI fast gate, full local release, hardware
  review, or partner-only replay.

### Script audit item 14: `generate_partner_review_scorecard.py`

`generate_partner_review_scorecard.py` is classified as a artifact generator. Its
opening implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier:
LicenseRef-Proprietary-Collaborative-Evaluation """Generate a partner-facing release
evidence scorecard. The scorecard is intentionally a derived artifact: it does not
replace the ledger, CBOM, policy result, or replay verifiers. It reads those artifacts
and. This classification matters because the paper and product story should not treat
all scripts equally. Runners create evidence, generators shape evidence, validators
replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `generate_partner_review_scorecard.py` should be callable
  in a clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `generate_partner_review_scorecard.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `generate_partner_review_scorecard.py` succeeds on a synthetic fixture and one path
  where a realistic invalid input fails non-zero. If the script depends on west or
  hardware, the unit test should validate argument parsing and replay behavior with
  fixtures.
- Integration direction: map `generate_partner_review_scorecard.py` to a release,
  benchmark, ACVP, side-channel, provider, schema, or product workflow lane so
  maintainers know whether it belongs in CI fast gate, full local release, hardware
  review, or partner-only replay.

### Script audit item 15: `generate_pqc_appraisal_evidence.py`

`generate_pqc_appraisal_evidence.py` is classified as a artifact generator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Generate a compact appraisal index over post-
Passport evidence artifacts.""" from __future__ import annotations import argparse
import hashlib import json from datetime import datetime, timezone from pathlib import
Path from typing. This classification matters because the paper and product story should
not treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `generate_pqc_appraisal_evidence.py` should be callable in
  a clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `generate_pqc_appraisal_evidence.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `generate_pqc_appraisal_evidence.py` succeeds on a synthetic fixture and one path
  where a realistic invalid input fails non-zero. If the script depends on west or
  hardware, the unit test should validate argument parsing and replay behavior with
  fixtures.
- Integration direction: map `generate_pqc_appraisal_evidence.py` to a release,
  benchmark, ACVP, side-channel, provider, schema, or product workflow lane so
  maintainers know whether it belongs in CI fast gate, full local release, hardware
  review, or partner-only replay.

### Script audit item 16: `generate_pqc_attestation.py`

`generate_pqc_attestation.py` is classified as a artifact generator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Generate an unsigned hash-bound PQC assurance
attestation.""" from __future__ import annotations import argparse import hashlib import
json import subprocess import sys from datetime import datetime, timezone from pathlib
import Path. This classification matters because the paper and product story should not
treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `generate_pqc_attestation.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `generate_pqc_attestation.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `generate_pqc_attestation.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `generate_pqc_attestation.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 17: `generate_pqc_build_provenance.py`

`generate_pqc_build_provenance.py` is classified as a artifact generator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Generate an unsigned SLSA-shaped build
provenance statement.""" from __future__ import annotations import argparse import
hashlib import json import subprocess import sys from datetime import datetime, timezone
from pathlib import Path. This classification matters because the paper and product
story should not treat all scripts equally. Runners create evidence, generators shape
evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `generate_pqc_build_provenance.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `generate_pqc_build_provenance.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `generate_pqc_build_provenance.py` succeeds on a synthetic fixture and one path where
  a realistic invalid input fails non-zero. If the script depends on west or hardware,
  the unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `generate_pqc_build_provenance.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 18: `generate_pqc_evidence_graph.py`

`generate_pqc_evidence_graph.py` is classified as a artifact generator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Generate a PQC assurance evidence graph from the
asset trace map.""" from __future__ import annotations import argparse import json
import sys from datetime import datetime, timezone from pathlib import Path. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `generate_pqc_evidence_graph.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `generate_pqc_evidence_graph.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `generate_pqc_evidence_graph.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `generate_pqc_evidence_graph.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 19: `generate_pqc_reference_values.py`

`generate_pqc_reference_values.py` is classified as a artifact generator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Generate replayable PQC release reference
values. The reference-values artifact is the compact bridge between a release evidence
pack and a future device/appraisal workflow: it records the expected release metadata,
artifact. This classification matters because the paper and product story should not
treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `generate_pqc_reference_values.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `generate_pqc_reference_values.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `generate_pqc_reference_values.py` succeeds on a synthetic fixture and one path where
  a realistic invalid input fails non-zero. If the script depends on west or hardware,
  the unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `generate_pqc_reference_values.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 20: `generate_research_product_dossier.py`

`generate_research_product_dossier.py` is classified as a artifact generator. Its
opening implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier:
LicenseRef-Proprietary-Collaborative-Evaluation """Generate repo-grounded research and
product hardening dossiers. The dossier is a derived release artifact. It does not
invent claims and it does not replace the Assurance Passport. It reads the. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `generate_research_product_dossier.py` should be callable
  in a clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `generate_research_product_dossier.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `generate_research_product_dossier.py` succeeds on a synthetic fixture and one path
  where a realistic invalid input fails non-zero. If the script depends on west or
  hardware, the unit test should validate argument parsing and replay behavior with
  fixtures.
- Integration direction: map `generate_research_product_dossier.py` to a release,
  benchmark, ACVP, side-channel, provider, schema, or product workflow lane so
  maintainers know whether it belongs in CI fast gate, full local release, hardware
  review, or partner-only replay.

### Script audit item 21: `local_workflow.py`

`local_workflow.py` is classified as a support utility. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """Shared helpers for local PQCP maintainer workflows.""" from
__future__ import annotations import os import shlex import shutil import signal import
subprocess import sys from pathlib import Path HOST_ENV_BLACKLIST = (. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `local_workflow.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `local_workflow.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `local_workflow.py` succeeds on a synthetic fixture and one path where a realistic
  invalid input fails non-zero. If the script depends on west or hardware, the unit test
  should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `local_workflow.py` to a release, benchmark, ACVP, side-
  channel, provider, schema, or product workflow lane so maintainers know whether it
  belongs in CI fast gate, full local release, hardware review, or partner-only replay.

### Script audit item 22: `measure_resource_budgets.py`

`measure_resource_budgets.py` is classified as a support utility. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """ Measure non-MCU resource-budget rows and print
reviewed JSON updates. The release gate enforces measured nucleo_h743zi protocol budgets
via check_resource_budgets.py. This helper gives maintainers the same disciplined re-
baselining path for. This classification matters because the paper and product story
should not treat all scripts equally. Runners create evidence, generators shape
evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `measure_resource_budgets.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `measure_resource_budgets.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `measure_resource_budgets.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `measure_resource_budgets.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 23: `optimize_metric_campaign.py`

`optimize_metric_campaign.py` is classified as a support utility. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Decide whether safe optimization candidates
improve PQCP metrics. The optimizer is intentionally evidence-first: it consumes
benchmark-campaign JSON files that were generated and replay-verified by the existing
tooling, then records keep/reject. This classification matters because the paper and
product story should not treat all scripts equally. Runners create evidence, generators
shape evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `optimize_metric_campaign.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `optimize_metric_campaign.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `optimize_metric_campaign.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `optimize_metric_campaign.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 24: `parse_logs.py`

`parse_logs.py` is classified as a support utility. Its opening implementation context
is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """ PQCP Benchmark Log Parser Parses serial output logs from
PQCP benchmarks and generates CSV files. Supports two log formats: 1. Legacy:
PRIM,MLKEM768,KEYGEN,cycles=12345,stack=2048,text=4096,bss=256,backend=C 2. New:
PQCP_METRIC,primitive,keygen,MLKEM,768,cycles,12345,cyc Usage: python parse_logs.py
<log_file>. This classification matters because the paper and product story should not
treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `parse_logs.py` should be callable in a clean workspace or
  explicitly marked as requiring Zephyr, hardware, network, or generated pack inputs.
  The expected output files should be stated in docs or in the schema catalog if a
  partner-facing artifact is produced.
- Product-grade expectation: `parse_logs.py` should fail with a message that identifies
  the missing input, invalid artifact, or unsupported environment. If it belongs behind
  a future product CLI, the stable command should wrap it rather than exposing every
  internal flag to customers.
- Test expectation: add or maintain at least one regression path where `parse_logs.py`
  succeeds on a synthetic fixture and one path where a realistic invalid input fails
  non-zero. If the script depends on west or hardware, the unit test should validate
  argument parsing and replay behavior with fixtures.
- Integration direction: map `parse_logs.py` to a release, benchmark, ACVP, side-
  channel, provider, schema, or product workflow lane so maintainers know whether it
  belongs in CI fast gate, full local release, hardware review, or partner-only replay.

### Script audit item 25: `prepare_release_bundle.py`

`prepare_release_bundle.py` is classified as a support utility. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Prepare local release artifacts without
depending on GitHub Actions.""" from __future__ import annotations import argparse
import hashlib import json import re import shutil import subprocess import sys from
pathlib import. This classification matters because the paper and product story should
not treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `prepare_release_bundle.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `prepare_release_bundle.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `prepare_release_bundle.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `prepare_release_bundle.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 26: `release_check.py`

`release_check.py` is classified as a support utility. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """ Run the project release validation sequence with clear per-
step PASS/FAIL output. """ from __future__ import annotations import argparse import
hashlib import json import os import re import selectors import. This classification
matters because the paper and product story should not treat all scripts equally.
Runners create evidence, generators shape evidence, validators replay evidence, and
tests preserve contract behavior.

- Research-grade expectation: `release_check.py` should be callable in a clean workspace
  or explicitly marked as requiring Zephyr, hardware, network, or generated pack inputs.
  The expected output files should be stated in docs or in the schema catalog if a
  partner-facing artifact is produced.
- Product-grade expectation: `release_check.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `release_check.py` succeeds on a synthetic fixture and one path where a realistic
  invalid input fails non-zero. If the script depends on west or hardware, the unit test
  should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `release_check.py` to a release, benchmark, ACVP, side-
  channel, provider, schema, or product workflow lane so maintainers know whether it
  belongs in CI fast gate, full local release, hardware review, or partner-only replay.

### Script audit item 27: `render_assurance_report.py`

`render_assurance_report.py` is classified as a support utility. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Render a dependency-free HTML assurance report
from an assurance ledger.""" from __future__ import annotations import argparse import
html import json import sys from pathlib import Path from typing import Any. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `render_assurance_report.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `render_assurance_report.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `render_assurance_report.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `render_assurance_report.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 28: `run_acvp_json_vectors.py`

`run_acvp_json_vectors.py` is classified as a experiment runner. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Translate NIST-style ACVP ML-KEM/ML-DSA JSON
vectors to serial-command evidence. This bridge does not replace the existing serial
ACVP harness. It preserves the wire command model by recording the command that. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `run_acvp_json_vectors.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `run_acvp_json_vectors.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `run_acvp_json_vectors.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `run_acvp_json_vectors.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 29: `run_acvp_serial_session.py`

`run_acvp_serial_session.py` is classified as a experiment runner. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """ Drive the pqcp_serial_acvp sample over either a
serial port or a subprocess. This is intentionally a thin host-side harness rather than
a full NIST ACVP client. Its purpose is. This classification matters because the paper
and product story should not treat all scripts equally. Runners create evidence,
generators shape evidence, validators replay evidence, and tests preserve contract
behavior.

- Research-grade expectation: `run_acvp_serial_session.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `run_acvp_serial_session.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `run_acvp_serial_session.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `run_acvp_serial_session.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 30: `run_benchmark_campaign.py`

`run_benchmark_campaign.py` is classified as a experiment runner. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Build benchmark-campaign evidence from local
CSV/provenance artifacts.""" from __future__ import annotations import argparse import
csv import json import math import statistics from datetime import datetime, timezone
from pathlib import Path. This classification matters because the paper and product
story should not treat all scripts equally. Runners create evidence, generators shape
evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `run_benchmark_campaign.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `run_benchmark_campaign.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `run_benchmark_campaign.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `run_benchmark_campaign.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 31: `run_benchmarks.py`

`run_benchmarks.py` is classified as a experiment runner. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """ PQCP benchmark orchestration. Builds and runs a
configurable board/profile/sample matrix, captures per-run logs, parses PQCP_METRIC
output, and writes consolidated CSV/JSON artifacts. """ from __future__ import
annotations import argparse import. This classification matters because the paper and
product story should not treat all scripts equally. Runners create evidence, generators
shape evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `run_benchmarks.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `run_benchmarks.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `run_benchmarks.py` succeeds on a synthetic fixture and one path where a realistic
  invalid input fails non-zero. If the script depends on west or hardware, the unit test
  should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `run_benchmarks.py` to a release, benchmark, ACVP, side-
  channel, provider, schema, or product workflow lane so maintainers know whether it
  belongs in CI fast gate, full local release, hardware review, or partner-only replay.

### Script audit item 32: `run_ct_campaign.py`

`run_ct_campaign.py` is classified as a experiment runner. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """Promote CT sample analysis into a campaign-level replay
artifact.""" from __future__ import annotations import argparse import json from
datetime import datetime, timezone from pathlib import Path from typing import Any. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `run_ct_campaign.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `run_ct_campaign.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `run_ct_campaign.py` succeeds on a synthetic fixture and one path where a realistic
  invalid input fails non-zero. If the script depends on west or hardware, the unit test
  should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `run_ct_campaign.py` to a release, benchmark, ACVP, side-
  channel, provider, schema, or product workflow lane so maintainers know whether it
  belongs in CI fast gate, full local release, hardware review, or partner-only replay.

### Script audit item 33: `run_evidence_tamper_drill.py`

`run_evidence_tamper_drill.py` is classified as a experiment runner. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Run controlled tamper drills against a generated
release evidence pack.""" from __future__ import annotations import argparse import json
import shutil import subprocess import sys import tempfile from datetime import
datetime,. This classification matters because the paper and product story should not
treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `run_evidence_tamper_drill.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `run_evidence_tamper_drill.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `run_evidence_tamper_drill.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `run_evidence_tamper_drill.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 34: `run_extended_checks.py`

`run_extended_checks.py` is classified as a experiment runner. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """ Developer-oriented extended checks for the PQCP
Zephyr module. This helper keeps heavier static-analysis style checks out of the fast
smoke CI while making them easy to run locally or. This classification matters because
the paper and product story should not treat all scripts equally. Runners create
evidence, generators shape evidence, validators replay evidence, and tests preserve
contract behavior.

- Research-grade expectation: `run_extended_checks.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `run_extended_checks.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `run_extended_checks.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `run_extended_checks.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 35: `run_hardware_benchmarks.py`

`run_hardware_benchmarks.py` is classified as a experiment runner. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Capture or normalize QEMU/MCU benchmark evidence
for paper-style comparisons.""" from __future__ import annotations import argparse
import csv import hashlib import json import math import os import platform import re
import. This classification matters because the paper and product story should not treat
all scripts equally. Runners create evidence, generators shape evidence, validators
replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `run_hardware_benchmarks.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `run_hardware_benchmarks.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `run_hardware_benchmarks.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `run_hardware_benchmarks.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 36: `run_local_tool_tests.py`

`run_local_tool_tests.py` is classified as a experiment runner. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Run pure-Python local tooling regression
tests.""" from __future__ import annotations import argparse import subprocess import
sys from pathlib import Path SCRIPT_DIR = Path(__file__).resolve().parent REPO_ROOT =
SCRIPT_DIR.parent TOOL_TESTS = ( "test_acvp_negative_scenario_floor.py",. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `run_local_tool_tests.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `run_local_tool_tests.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `run_local_tool_tests.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `run_local_tool_tests.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 37: `run_paper_comparison_campaign.py`

`run_paper_comparison_campaign.py` is classified as a experiment runner. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Export paper-comparable benchmark rows from
local campaign evidence.""" from __future__ import annotations import argparse import
csv import hashlib import json import sys from datetime import datetime, timezone from
pathlib import. This classification matters because the paper and product story should
not treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `run_paper_comparison_campaign.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `run_paper_comparison_campaign.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `run_paper_comparison_campaign.py` succeeds on a synthetic fixture and one path where
  a realistic invalid input fails non-zero. If the script depends on west or hardware,
  the unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `run_paper_comparison_campaign.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 38: `run_sanitizer_checks.py`

`run_sanitizer_checks.py` is classified as a experiment runner. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """ Run focused sanitizer builds for the highest-
risk PQCP harnesses. This helper is intentionally separate from the fast CI and static-
analysis paths so maintainers can run ASan/UBSan checks on demand. This classification
matters because the paper and product story should not treat all scripts equally.
Runners create evidence, generators shape evidence, validators replay evidence, and
tests preserve contract behavior.

- Research-grade expectation: `run_sanitizer_checks.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `run_sanitizer_checks.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `run_sanitizer_checks.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `run_sanitizer_checks.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 39: `summarize_cost_of_assurance.py`

`summarize_cost_of_assurance.py` is classified as a support utility. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """ Summarize cost-of-assurance benchmark runs into
comparison-friendly CSVs. This helper consumes the JSON artifacts written by
scripts/run_benchmarks.py and emits: - one build/resource row per run, - one primitive
row per. This classification matters because the paper and product story should not
treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `summarize_cost_of_assurance.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `summarize_cost_of_assurance.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `summarize_cost_of_assurance.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `summarize_cost_of_assurance.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 40: `test_acvp_json_interop.py`

`test_acvp_json_interop.py` is classified as a test harness. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """Regression tests for ACVP JSON interop translation.""" from
__future__ import annotations import json import tempfile import unittest from pathlib
import Path import run_acvp_json_vectors class AcvpJsonInteropTests(unittest.TestCase):
def write(self, root: Path, payload:. This classification matters because the paper and
product story should not treat all scripts equally. Runners create evidence, generators
shape evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `test_acvp_json_interop.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_acvp_json_interop.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_acvp_json_interop.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_acvp_json_interop.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 41: `test_acvp_json_interop_verifier.py`

`test_acvp_json_interop_verifier.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Regression tests for ACVP JSON interop artifact
replay verification.""" from __future__ import annotations import json import tempfile
import unittest from argparse import Namespace from pathlib import Path import
run_acvp_json_vectors import. This classification matters because the paper and product
story should not treat all scripts equally. Runners create evidence, generators shape
evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `test_acvp_json_interop_verifier.py` should be callable in
  a clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_acvp_json_interop_verifier.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_acvp_json_interop_verifier.py` succeeds on a synthetic fixture and one path
  where a realistic invalid input fails non-zero. If the script depends on west or
  hardware, the unit test should validate argument parsing and replay behavior with
  fixtures.
- Integration direction: map `test_acvp_json_interop_verifier.py` to a release,
  benchmark, ACVP, side-channel, provider, schema, or product workflow lane so
  maintainers know whether it belongs in CI fast gate, full local release, hardware
  review, or partner-only replay.

### Script audit item 42: `test_acvp_json_schema.py`

`test_acvp_json_schema.py` is classified as a test harness. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """Tests for ACVP JSON schema coverage replay.""" from
__future__ import annotations import hashlib import json import tempfile import unittest
from argparse import Namespace from pathlib import Path import validate_acvp_json_schema
def. This classification matters because the paper and product story should not treat
all scripts equally. Runners create evidence, generators shape evidence, validators
replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `test_acvp_json_schema.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_acvp_json_schema.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_acvp_json_schema.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_acvp_json_schema.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 43: `test_acvp_negative_scenario_floor.py`

`test_acvp_negative_scenario_floor.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Tests for ACVP negative-scenario floor
validation.""" from __future__ import annotations import copy import json import
tempfile import unittest from pathlib import Path import
validate_acvp_negative_scenarios as validator class
ACVPNegativeScenarioFloorTests(unittest.TestCase): def write_json(self,. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `test_acvp_negative_scenario_floor.py` should be callable
  in a clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_acvp_negative_scenario_floor.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_acvp_negative_scenario_floor.py` succeeds on a synthetic fixture and one path
  where a realistic invalid input fails non-zero. If the script depends on west or
  hardware, the unit test should validate argument parsing and replay behavior with
  fixtures.
- Integration direction: map `test_acvp_negative_scenario_floor.py` to a release,
  benchmark, ACVP, side-channel, provider, schema, or product workflow lane so
  maintainers know whether it belongs in CI fast gate, full local release, hardware
  review, or partner-only replay.

### Script audit item 44: `test_assurance_ledger.py`

`test_assurance_ledger.py` is classified as a test harness. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """Focused tests for the local assurance ledger generator."""
from __future__ import annotations import csv import hashlib import json import tempfile
import unittest from argparse import Namespace from pathlib import Path. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `test_assurance_ledger.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_assurance_ledger.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_assurance_ledger.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_assurance_ledger.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 45: `test_backend_contract.py`

`test_backend_contract.py` is classified as a test harness. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """Regression tests for backend-contract verification.""" from
__future__ import annotations import tempfile import unittest from argparse import
Namespace from pathlib import Path import verify_backend_contract MLKEM_SHA =
"e07bff537f38b457601e524038f2395e235b011b" MLDSA_SHA =
"0f8b8e074b2525eb844b022b03b962bf888d51aa" def. This classification matters because the
paper and product story should not treat all scripts equally. Runners create evidence,
generators shape evidence, validators replay evidence, and tests preserve contract
behavior.

- Research-grade expectation: `test_backend_contract.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_backend_contract.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_backend_contract.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_backend_contract.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 46: `test_backend_currency.py`

`test_backend_currency.py` is classified as a test harness. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """Regression tests for backend-currency verification.""" from
__future__ import annotations import tempfile import unittest from argparse import
Namespace from pathlib import Path from unittest.mock import patch import
verify_backend_currency MLKEM_SHA = "e07bff537f38b457601e524038f2395e235b011b". This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `test_backend_currency.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_backend_currency.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_backend_currency.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_backend_currency.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 47: `test_backend_update_evaluation.py`

`test_backend_update_evaluation.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Tests for backend update evaluation.""" from
__future__ import annotations import tempfile import unittest from argparse import
Namespace from pathlib import Path import evaluate_backend_update WEST = """ manifest:
remotes: - name:. This classification matters because the paper and product story should
not treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `test_backend_update_evaluation.py` should be callable in
  a clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_backend_update_evaluation.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_backend_update_evaluation.py` succeeds on a synthetic fixture and one path where
  a realistic invalid input fails non-zero. If the script depends on west or hardware,
  the unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_backend_update_evaluation.py` to a release,
  benchmark, ACVP, side-channel, provider, schema, or product workflow lane so
  maintainers know whether it belongs in CI fast gate, full local release, hardware
  review, or partner-only replay.

### Script audit item 48: `test_benchmark_campaign.py`

`test_benchmark_campaign.py` is classified as a test harness. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """Tests for benchmark campaign replay.""" from __future__
import annotations import json import tempfile import unittest from pathlib import Path
import verify_benchmark_campaign import run_benchmark_campaign class
BenchmarkCampaignTests(unittest.TestCase): def write_campaign(self, root: Path, *,. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `test_benchmark_campaign.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_benchmark_campaign.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_benchmark_campaign.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_benchmark_campaign.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 49: `test_benchmark_confidence.py`

`test_benchmark_confidence.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Tests for benchmark confidence replay.""" from
__future__ import annotations import json import tempfile import unittest from pathlib
import Path import verify_benchmark_confidence def campaign_payload( *, sample_count:
int = 20, p90: float. This classification matters because the paper and product story
should not treat all scripts equally. Runners create evidence, generators shape
evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `test_benchmark_confidence.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_benchmark_confidence.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_benchmark_confidence.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_benchmark_confidence.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 50: `test_ct_campaign.py`

`test_ct_campaign.py` is classified as a test harness. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """Tests for CT campaign replay.""" from __future__ import
annotations import json import tempfile import unittest from argparse import Namespace
from pathlib import Path import run_ct_campaign class
CtCampaignTests(unittest.TestCase): def write_inputs(self, root:. This classification
matters because the paper and product story should not treat all scripts equally.
Runners create evidence, generators shape evidence, validators replay evidence, and
tests preserve contract behavior.

- Research-grade expectation: `test_ct_campaign.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_ct_campaign.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_ct_campaign.py` succeeds on a synthetic fixture and one path where a realistic
  invalid input fails non-zero. If the script depends on west or hardware, the unit test
  should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_ct_campaign.py` to a release, benchmark, ACVP, side-
  channel, provider, schema, or product workflow lane so maintainers know whether it
  belongs in CI fast gate, full local release, hardware review, or partner-only replay.

### Script audit item 51: `test_ct_sample_analysis.py`

`test_ct_sample_analysis.py` is classified as a test harness. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """Regression tests for CT sample transcript analysis.""" from
__future__ import annotations import tempfile import unittest from argparse import
Namespace from pathlib import Path import analyze_ct_samples class
CtSampleAnalysisTests(unittest.TestCase): def run_analysis(self, body:. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `test_ct_sample_analysis.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_ct_sample_analysis.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_ct_sample_analysis.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_ct_sample_analysis.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 52: `test_device_evidence_token.py`

`test_device_evidence_token.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Tests for firmware device-evidence token
replay.""" from __future__ import annotations import json import tempfile import
unittest from argparse import Namespace from pathlib import Path import
verify_device_evidence_token DIGEST = "a" *. This classification matters because the
paper and product story should not treat all scripts equally. Runners create evidence,
generators shape evidence, validators replay evidence, and tests preserve contract
behavior.

- Research-grade expectation: `test_device_evidence_token.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_device_evidence_token.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_device_evidence_token.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_device_evidence_token.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 53: `test_evidence_schema_contract.py`

`test_evidence_schema_contract.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Regression tests for the product-facing evidence
schema contract.""" from __future__ import annotations import json import shutil import
subprocess import sys import tempfile import unittest from pathlib import Path
SCRIPT_DIR =. This classification matters because the paper and product story should not
treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `test_evidence_schema_contract.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_evidence_schema_contract.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_evidence_schema_contract.py` succeeds on a synthetic fixture and one path where
  a realistic invalid input fails non-zero. If the script depends on west or hardware,
  the unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_evidence_schema_contract.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 54: `test_evidence_tamper_drill.py`

`test_evidence_tamper_drill.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Focused tests for the release evidence tamper
drill.""" from __future__ import annotations import json import tempfile import textwrap
import unittest from argparse import Namespace from pathlib import Path import
run_evidence_tamper_drill. This classification matters because the paper and product
story should not treat all scripts equally. Runners create evidence, generators shape
evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `test_evidence_tamper_drill.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_evidence_tamper_drill.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_evidence_tamper_drill.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_evidence_tamper_drill.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 55: `test_firmware_assurance_digest.py`

`test_firmware_assurance_digest.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Regression tests for firmware assurance digest
header export.""" from __future__ import annotations import json import tempfile import
unittest from pathlib import Path import export_firmware_assurance_digest GOOD_SHA = "0"
* 64 class. This classification matters because the paper and product story should not
treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `test_firmware_assurance_digest.py` should be callable in
  a clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_firmware_assurance_digest.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_firmware_assurance_digest.py` succeeds on a synthetic fixture and one path where
  a realistic invalid input fails non-zero. If the script depends on west or hardware,
  the unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_firmware_assurance_digest.py` to a release,
  benchmark, ACVP, side-channel, provider, schema, or product workflow lane so
  maintainers know whether it belongs in CI fast gate, full local release, hardware
  review, or partner-only replay.

### Script audit item 56: `test_firmware_assurance_status.py`

`test_firmware_assurance_status.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Regression tests for firmware assurance status
verification.""" from __future__ import annotations import json import tempfile import
unittest from argparse import Namespace from pathlib import Path import
verify_firmware_assurance_status class FirmwareStatusTests(unittest.TestCase): def. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `test_firmware_assurance_status.py` should be callable in
  a clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_firmware_assurance_status.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_firmware_assurance_status.py` succeeds on a synthetic fixture and one path where
  a realistic invalid input fails non-zero. If the script depends on west or hardware,
  the unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_firmware_assurance_status.py` to a release,
  benchmark, ACVP, side-channel, provider, schema, or product workflow lane so
  maintainers know whether it belongs in CI fast gate, full local release, hardware
  review, or partner-only replay.

### Script audit item 57: `test_local_release_workflows.py`

`test_local_release_workflows.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Focused tests for local release and consumer
workflow helpers.""" from __future__ import annotations import tempfile import unittest
from argparse import Namespace from pathlib import Path import consumer_smoke import
prepare_release_bundle import. This classification matters because the paper and product
story should not treat all scripts equally. Runners create evidence, generators shape
evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `test_local_release_workflows.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_local_release_workflows.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_local_release_workflows.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_local_release_workflows.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 58: `test_migration_readiness_report.py`

`test_migration_readiness_report.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Regression tests for migration-readiness report
generation.""" from __future__ import annotations import json import tempfile import
unittest from pathlib import Path import generate_migration_readiness_report def
cbom_fixture() -> dict: return { "components": [. This classification matters because
the paper and product story should not treat all scripts equally. Runners create
evidence, generators shape evidence, validators replay evidence, and tests preserve
contract behavior.

- Research-grade expectation: `test_migration_readiness_report.py` should be callable in
  a clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_migration_readiness_report.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_migration_readiness_report.py` succeeds on a synthetic fixture and one path
  where a realistic invalid input fails non-zero. If the script depends on west or
  hardware, the unit test should validate argument parsing and replay behavior with
  fixtures.
- Integration direction: map `test_migration_readiness_report.py` to a release,
  benchmark, ACVP, side-channel, provider, schema, or product workflow lane so
  maintainers know whether it belongs in CI fast gate, full local release, hardware
  review, or partner-only replay.

### Script audit item 59: `test_optimize_metric_campaign.py`

`test_optimize_metric_campaign.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Tests for metric-by-metric optimization campaign
decisions.""" from __future__ import annotations import argparse import json import
tempfile import unittest from pathlib import Path import optimize_metric_campaign def
stat(parameter_set: str, operation: str, median:. This classification matters because
the paper and product story should not treat all scripts equally. Runners create
evidence, generators shape evidence, validators replay evidence, and tests preserve
contract behavior.

- Research-grade expectation: `test_optimize_metric_campaign.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_optimize_metric_campaign.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_optimize_metric_campaign.py` succeeds on a synthetic fixture and one path where
  a realistic invalid input fails non-zero. If the script depends on west or hardware,
  the unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_optimize_metric_campaign.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 60: `test_paper_comparison_campaign.py`

`test_paper_comparison_campaign.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Regression tests for paper-comparison benchmark
export.""" from __future__ import annotations import json import tempfile import
unittest from argparse import Namespace from pathlib import Path import
run_paper_comparison_campaign def campaign_payload() -> dict:. This classification
matters because the paper and product story should not treat all scripts equally.
Runners create evidence, generators shape evidence, validators replay evidence, and
tests preserve contract behavior.

- Research-grade expectation: `test_paper_comparison_campaign.py` should be callable in
  a clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_paper_comparison_campaign.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_paper_comparison_campaign.py` succeeds on a synthetic fixture and one path where
  a realistic invalid input fails non-zero. If the script depends on west or hardware,
  the unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_paper_comparison_campaign.py` to a release,
  benchmark, ACVP, side-channel, provider, schema, or product workflow lane so
  maintainers know whether it belongs in CI fast gate, full local release, hardware
  review, or partner-only replay.

### Script audit item 61: `test_partner_review_scorecard.py`

`test_partner_review_scorecard.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Regression tests for partner review scorecard
generation.""" from __future__ import annotations import json import tempfile import
unittest from argparse import Namespace from pathlib import Path import
generate_partner_review_scorecard import verify_partner_review_scorecard class. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `test_partner_review_scorecard.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_partner_review_scorecard.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_partner_review_scorecard.py` succeeds on a synthetic fixture and one path where
  a realistic invalid input fails non-zero. If the script depends on west or hardware,
  the unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_partner_review_scorecard.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 62: `test_pqc_appraisal_evidence.py`

`test_pqc_appraisal_evidence.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Tests for PQC appraisal evidence generation and
replay.""" from __future__ import annotations import json import tempfile import
unittest from argparse import Namespace from pathlib import Path import
generate_pqc_appraisal_evidence import verify_pqc_appraisal_evidence. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `test_pqc_appraisal_evidence.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_pqc_appraisal_evidence.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_pqc_appraisal_evidence.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_pqc_appraisal_evidence.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 63: `test_pqc_asset_trace_map.py`

`test_pqc_asset_trace_map.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Regression tests for the PQC asset trace map
verifier.""" from __future__ import annotations import json import tempfile import
unittest from pathlib import Path import verify_pqc_asset_trace_map SCRIPT_DIR =
Path(__file__).resolve().parent REPO_ROOT =. This classification matters because the
paper and product story should not treat all scripts equally. Runners create evidence,
generators shape evidence, validators replay evidence, and tests preserve contract
behavior.

- Research-grade expectation: `test_pqc_asset_trace_map.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_pqc_asset_trace_map.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_pqc_asset_trace_map.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_pqc_asset_trace_map.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 64: `test_pqc_assurance_passport.py`

`test_pqc_assurance_passport.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Pure-Python tests for the PQC Assurance Passport
tooling.""" from __future__ import annotations import json import tempfile import
unittest from argparse import Namespace from pathlib import Path import export_pqc_cbom
import generate_pqc_attestation. This classification matters because the paper and
product story should not treat all scripts equally. Runners create evidence, generators
shape evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `test_pqc_assurance_passport.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_pqc_assurance_passport.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_pqc_assurance_passport.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_pqc_assurance_passport.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 65: `test_pqc_assurance_profile.py`

`test_pqc_assurance_profile.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Regression tests for PQC assurance profile
verification.""" from __future__ import annotations import json import tempfile import
unittest from pathlib import Path import export_pqc_cbom import
verify_pqc_assurance_profile SCRIPT_DIR = Path(__file__).resolve().parent REPO_ROOT =.
This classification matters because the paper and product story should not treat all
scripts equally. Runners create evidence, generators shape evidence, validators replay
evidence, and tests preserve contract behavior.

- Research-grade expectation: `test_pqc_assurance_profile.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_pqc_assurance_profile.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_pqc_assurance_profile.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_pqc_assurance_profile.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 66: `test_pqc_build_provenance.py`

`test_pqc_build_provenance.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Regression tests for SLSA-shaped PQC build
provenance.""" from __future__ import annotations import json import tempfile import
unittest from argparse import Namespace from pathlib import Path import
generate_pqc_build_provenance import verify_pqc_build_provenance class. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `test_pqc_build_provenance.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_pqc_build_provenance.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_pqc_build_provenance.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_pqc_build_provenance.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 67: `test_pqc_claim_closure.py`

`test_pqc_claim_closure.py` is classified as a test harness. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """Pure-Python tests for post-ledger PQC Passport claim
closure.""" from __future__ import annotations import hashlib import json import
tempfile import unittest from argparse import Namespace from pathlib import Path import
verify_pqc_claim_closure. This classification matters because the paper and product
story should not treat all scripts equally. Runners create evidence, generators shape
evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `test_pqc_claim_closure.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_pqc_claim_closure.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_pqc_claim_closure.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_pqc_claim_closure.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 68: `test_pqc_evidence_graph.py`

`test_pqc_evidence_graph.py` is classified as a test harness. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """Regression tests for the PQC evidence graph generator."""
from __future__ import annotations import json import tempfile import unittest from
pathlib import Path import generate_pqc_evidence_graph SCRIPT_DIR =
Path(__file__).resolve().parent REPO_ROOT = SCRIPT_DIR.parent. This classification
matters because the paper and product story should not treat all scripts equally.
Runners create evidence, generators shape evidence, validators replay evidence, and
tests preserve contract behavior.

- Research-grade expectation: `test_pqc_evidence_graph.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_pqc_evidence_graph.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_pqc_evidence_graph.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_pqc_evidence_graph.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 69: `test_pqc_evidence_quality.py`

`test_pqc_evidence_quality.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Regression tests for PQC evidence quality
verification.""" from __future__ import annotations import json import tempfile import
unittest from pathlib import Path import verify_pqc_evidence_quality SCRIPT_DIR =
Path(__file__).resolve().parent def write_json(path: Path, payload:. This classification
matters because the paper and product story should not treat all scripts equally.
Runners create evidence, generators shape evidence, validators replay evidence, and
tests preserve contract behavior.

- Research-grade expectation: `test_pqc_evidence_quality.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_pqc_evidence_quality.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_pqc_evidence_quality.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_pqc_evidence_quality.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 70: `test_pqc_performance_hardening.py`

`test_pqc_performance_hardening.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Tests for performance-methodology and CT-policy
helper tooling.""" from __future__ import annotations import csv import os import sys
import tempfile import unittest from argparse import Namespace from pathlib import Path
import. This classification matters because the paper and product story should not treat
all scripts equally. Runners create evidence, generators shape evidence, validators
replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `test_pqc_performance_hardening.py` should be callable in
  a clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_pqc_performance_hardening.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_pqc_performance_hardening.py` succeeds on a synthetic fixture and one path where
  a realistic invalid input fails non-zero. If the script depends on west or hardware,
  the unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_pqc_performance_hardening.py` to a release,
  benchmark, ACVP, side-channel, provider, schema, or product workflow lane so
  maintainers know whether it belongs in CI fast gate, full local release, hardware
  review, or partner-only replay.

### Script audit item 71: `test_pqc_reference_values.py`

`test_pqc_reference_values.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Regression tests for PQC reference values."""
from __future__ import annotations import json import tempfile import unittest from
argparse import Namespace from pathlib import Path import generate_pqc_reference_values
import verify_pqc_reference_values class ReferenceValuesTests(unittest.TestCase):. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `test_pqc_reference_values.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_pqc_reference_values.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_pqc_reference_values.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_pqc_reference_values.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 72: `test_provider_scope.py`

`test_provider_scope.py` is classified as a test harness. Its opening implementation
context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-Proprietary-
Collaborative-Evaluation """Regression tests for provider-scope verification.""" from
__future__ import annotations import json import tempfile import unittest from argparse
import Namespace from pathlib import Path import verify_provider_scope def prop(name:
str, value: object). This classification matters because the paper and product story
should not treat all scripts equally. Runners create evidence, generators shape
evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `test_provider_scope.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_provider_scope.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_provider_scope.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_provider_scope.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 73: `test_release_environment.py`

`test_release_environment.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Tests for release environment metadata
verification.""" from __future__ import annotations import json import tempfile import
unittest from pathlib import Path import verify_release_environment ZEPHYR_SHA = "a" *
40 MLKEM_SHA = "b". This classification matters because the paper and product story
should not treat all scripts equally. Runners create evidence, generators shape
evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `test_release_environment.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_release_environment.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_release_environment.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_release_environment.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 74: `test_release_evidence_pack.py`

`test_release_evidence_pack.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Focused tests for release evidence pack
verification.""" from __future__ import annotations import csv import hashlib import
json import tempfile import unittest from argparse import Namespace from pathlib import
Path import. This classification matters because the paper and product story should not
treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `test_release_evidence_pack.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_release_evidence_pack.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_release_evidence_pack.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_release_evidence_pack.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 75: `test_release_reference_values.py`

`test_release_reference_values.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Regression tests for provider-bound reference-
value replay.""" from __future__ import annotations import json import tempfile import
unittest from argparse import Namespace from pathlib import Path import
verify_release_reference_values def write_json(path: Path, payload:. This classification
matters because the paper and product story should not treat all scripts equally.
Runners create evidence, generators shape evidence, validators replay evidence, and
tests preserve contract behavior.

- Research-grade expectation: `test_release_reference_values.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_release_reference_values.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_release_reference_values.py` succeeds on a synthetic fixture and one path where
  a realistic invalid input fails non-zero. If the script depends on west or hardware,
  the unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_release_reference_values.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 76: `test_research_product_dossier.py`

`test_research_product_dossier.py` is classified as a test harness. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Tests for the research/product dossier
generator.""" from __future__ import annotations import json import tempfile import
unittest from pathlib import Path import generate_research_product_dossier as dossier
class ResearchProductDossierTests(unittest.TestCase): def setUp(self) -> None:. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `test_research_product_dossier.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `test_research_product_dossier.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `test_research_product_dossier.py` succeeds on a synthetic fixture and one path where
  a realistic invalid input fails non-zero. If the script depends on west or hardware,
  the unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `test_research_product_dossier.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 77: `validate_acvp_json_schema.py`

`validate_acvp_json_schema.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Validate ACVP JSON interop evidence shape and
operation coverage.""" from __future__ import annotations import argparse import hashlib
import json from datetime import datetime, timezone from pathlib import Path from
typing. This classification matters because the paper and product story should not treat
all scripts equally. Runners create evidence, generators shape evidence, validators
replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `validate_acvp_json_schema.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `validate_acvp_json_schema.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `validate_acvp_json_schema.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `validate_acvp_json_schema.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 78: `validate_acvp_negative_scenarios.py`

`validate_acvp_negative_scenarios.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Validate ACVP negative-scenario coverage against
a compatibility floor.""" from __future__ import annotations import argparse import json
import sys from pathlib import Path from typing import Any SCRIPT_DIR =
Path(__file__).resolve().parent DEFAULT_SCENARIOS. This classification matters because
the paper and product story should not treat all scripts equally. Runners create
evidence, generators shape evidence, validators replay evidence, and tests preserve
contract behavior.

- Research-grade expectation: `validate_acvp_negative_scenarios.py` should be callable
  in a clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `validate_acvp_negative_scenarios.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `validate_acvp_negative_scenarios.py` succeeds on a synthetic fixture and one path
  where a realistic invalid input fails non-zero. If the script depends on west or
  hardware, the unit test should validate argument parsing and replay behavior with
  fixtures.
- Integration direction: map `validate_acvp_negative_scenarios.py` to a release,
  benchmark, ACVP, side-channel, provider, schema, or product workflow lane so
  maintainers know whether it belongs in CI fast gate, full local release, hardware
  review, or partner-only replay.

### Script audit item 79: `validate_evidence_schemas.py`

`validate_evidence_schemas.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Validate release evidence packs against the
repository schema contract. The existing replay verifier checks many semantic
relationships after a full release pack is generated. This script adds the product-
facing contract. This classification matters because the paper and product story should
not treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `validate_evidence_schemas.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `validate_evidence_schemas.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `validate_evidence_schemas.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `validate_evidence_schemas.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 80: `verify_acvp_json_interop.py`

`verify_acvp_json_interop.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Replay-check ACVP JSON interop response and
transcript-manifest artifacts.""" from __future__ import annotations import argparse
import json import sys from datetime import datetime, timezone from pathlib import Path
from typing import. This classification matters because the paper and product story
should not treat all scripts equally. Runners create evidence, generators shape
evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_acvp_json_interop.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_acvp_json_interop.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_acvp_json_interop.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_acvp_json_interop.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 81: `verify_assurance_ledger.py`

`verify_assurance_ledger.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Verify a generated PQCP assurance ledger without
rerunning Zephyr builds.""" from __future__ import annotations import argparse import
hashlib import json import sys from pathlib import Path from typing import Any. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `verify_assurance_ledger.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_assurance_ledger.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_assurance_ledger.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_assurance_ledger.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 82: `verify_assurance_policy.py`

`verify_assurance_policy.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Verify a PQC Assurance Passport against a
partner-review policy.""" from __future__ import annotations import argparse import
hashlib import json import sys from datetime import datetime, timezone from pathlib
import Path. This classification matters because the paper and product story should not
treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_assurance_policy.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_assurance_policy.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_assurance_policy.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_assurance_policy.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 83: `verify_backend_contract.py`

`verify_backend_contract.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Verify the release backend contract for native
and experimental providers.""" from __future__ import annotations import argparse import
json import sys from datetime import datetime, timezone from pathlib import Path from.
This classification matters because the paper and product story should not treat all
scripts equally. Runners create evidence, generators shape evidence, validators replay
evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_backend_contract.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_backend_contract.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_backend_contract.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_backend_contract.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 84: `verify_backend_currency.py`

`verify_backend_currency.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Verify PQ Code Package backend pin currency and
local submodule wiring.""" from __future__ import annotations import argparse import
hashlib import json import re import subprocess import sys from datetime import. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `verify_backend_currency.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_backend_currency.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_backend_currency.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_backend_currency.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 85: `verify_benchmark_campaign.py`

`verify_benchmark_campaign.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Replay-check benchmark-campaign evidence."""
from __future__ import annotations import argparse import json from datetime import
datetime, timezone from pathlib import Path from typing import Any def parse_args() ->
argparse.Namespace: parser =. This classification matters because the paper and product
story should not treat all scripts equally. Runners create evidence, generators shape
evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_benchmark_campaign.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_benchmark_campaign.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_benchmark_campaign.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_benchmark_campaign.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 86: `verify_benchmark_confidence.py`

`verify_benchmark_confidence.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Replay-check benchmark distribution confidence.
This verifier is intentionally stricter about shape than about performance. It catches
broken or under-sampled benchmark evidence without changing the existing benchmark wire
format or making. This classification matters because the paper and product story should
not treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_benchmark_confidence.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_benchmark_confidence.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_benchmark_confidence.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_benchmark_confidence.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 87: `verify_ct_instruction_policy.py`

`verify_ct_instruction_policy.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Scan ML-KEM decapsulation disassembly for
variable-latency division.""" from __future__ import annotations import argparse import
json import re import shutil import subprocess import sys from datetime import datetime,
timezone from pathlib. This classification matters because the paper and product story
should not treat all scripts equally. Runners create evidence, generators shape
evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_ct_instruction_policy.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_ct_instruction_policy.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_ct_instruction_policy.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_ct_instruction_policy.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 88: `verify_device_evidence_token.py`

`verify_device_evidence_token.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Verify additive PQCP_DEVICE_EVIDENCE markers
from assurance-status firmware.""" from __future__ import annotations import argparse
import hashlib import json import re from datetime import datetime, timezone from
pathlib import Path from typing. This classification matters because the paper and
product story should not treat all scripts equally. Runners create evidence, generators
shape evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_device_evidence_token.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_device_evidence_token.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_device_evidence_token.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_device_evidence_token.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 89: `verify_firmware_assurance_status.py`

`verify_firmware_assurance_status.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Verify firmware-reported assurance status lines
against reference values.""" from __future__ import annotations import argparse import
json import re import sys from datetime import datetime, timezone from pathlib import
Path from. This classification matters because the paper and product story should not
treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_firmware_assurance_status.py` should be callable
  in a clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_firmware_assurance_status.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_firmware_assurance_status.py` succeeds on a synthetic fixture and one path
  where a realistic invalid input fails non-zero. If the script depends on west or
  hardware, the unit test should validate argument parsing and replay behavior with
  fixtures.
- Integration direction: map `verify_firmware_assurance_status.py` to a release,
  benchmark, ACVP, side-channel, provider, schema, or product workflow lane so
  maintainers know whether it belongs in CI fast gate, full local release, hardware
  review, or partner-only replay.

### Script audit item 90: `verify_kat_provenance.py`

`verify_kat_provenance.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Verify checked-in ACVP KAT vectors against
vendored NIST ACVP fixtures.""" from __future__ import annotations import argparse
import json import re import sys from dataclasses import dataclass from pathlib import
Path. This classification matters because the paper and product story should not treat
all scripts equally. Runners create evidence, generators shape evidence, validators
replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_kat_provenance.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_kat_provenance.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_kat_provenance.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_kat_provenance.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 91: `verify_partner_review_scorecard.py`

`verify_partner_review_scorecard.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Replay-check a generated partner review
scorecard.""" from __future__ import annotations import argparse import json import sys
from datetime import datetime, timezone from pathlib import Path from typing import Any
import. This classification matters because the paper and product story should not treat
all scripts equally. Runners create evidence, generators shape evidence, validators
replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_partner_review_scorecard.py` should be callable in
  a clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_partner_review_scorecard.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_partner_review_scorecard.py` succeeds on a synthetic fixture and one path
  where a realistic invalid input fails non-zero. If the script depends on west or
  hardware, the unit test should validate argument parsing and replay behavior with
  fixtures.
- Integration direction: map `verify_partner_review_scorecard.py` to a release,
  benchmark, ACVP, side-channel, provider, schema, or product workflow lane so
  maintainers know whether it belongs in CI fast gate, full local release, hardware
  review, or partner-only replay.

### Script audit item 92: `verify_pqc_appraisal_evidence.py`

`verify_pqc_appraisal_evidence.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Replay-check PQC appraisal evidence against a
mode-specific policy.""" from __future__ import annotations import argparse import
hashlib import json from datetime import datetime, timezone from pathlib import Path
from typing import. This classification matters because the paper and product story
should not treat all scripts equally. Runners create evidence, generators shape
evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_pqc_appraisal_evidence.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_pqc_appraisal_evidence.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_pqc_appraisal_evidence.py` succeeds on a synthetic fixture and one path where
  a realistic invalid input fails non-zero. If the script depends on west or hardware,
  the unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_pqc_appraisal_evidence.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 93: `verify_pqc_asset_trace_map.py`

`verify_pqc_asset_trace_map.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Verify the PQC asset-to-evidence trace map used
by the Assurance Passport.""" from __future__ import annotations import argparse import
json import sys from datetime import datetime, timezone from pathlib import Path. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `verify_pqc_asset_trace_map.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_pqc_asset_trace_map.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_pqc_asset_trace_map.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_pqc_asset_trace_map.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 94: `verify_pqc_assurance_profile.py`

`verify_pqc_assurance_profile.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Verify profile-specific PQC asset policy against
Passport artifacts.""" from __future__ import annotations import argparse import json
import sys from datetime import datetime, timezone from pathlib import Path from typing
import. This classification matters because the paper and product story should not treat
all scripts equally. Runners create evidence, generators shape evidence, validators
replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_pqc_assurance_profile.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_pqc_assurance_profile.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_pqc_assurance_profile.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_pqc_assurance_profile.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 95: `verify_pqc_build_provenance.py`

`verify_pqc_build_provenance.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Verify the SLSA-shaped PQC build provenance
artifact.""" from __future__ import annotations import argparse import hashlib import
json import sys from datetime import datetime, timezone from pathlib import Path from
typing. This classification matters because the paper and product story should not treat
all scripts equally. Runners create evidence, generators shape evidence, validators
replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_pqc_build_provenance.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_pqc_build_provenance.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_pqc_build_provenance.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_pqc_build_provenance.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 96: `verify_pqc_claim_closure.py`

`verify_pqc_claim_closure.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Verify that post-ledger Passport claims are
closed by generated artifacts.""" from __future__ import annotations import argparse
import hashlib import json from datetime import datetime, timezone from pathlib import
Path from. This classification matters because the paper and product story should not
treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_pqc_claim_closure.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_pqc_claim_closure.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_pqc_claim_closure.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_pqc_claim_closure.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 97: `verify_pqc_evidence_quality.py`

`verify_pqc_evidence_quality.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Verify claim evidence quality metadata against a
generated ledger.""" from __future__ import annotations import argparse import json
import sys from datetime import datetime, timezone from pathlib import Path from typing.
This classification matters because the paper and product story should not treat all
scripts equally. Runners create evidence, generators shape evidence, validators replay
evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_pqc_evidence_quality.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_pqc_evidence_quality.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_pqc_evidence_quality.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_pqc_evidence_quality.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 98: `verify_pqc_reference_values.py`

`verify_pqc_reference_values.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Replay-check PQC reference values against a
release evidence pack.""" from __future__ import annotations import argparse import
hashlib import json import sys from datetime import datetime, timezone from pathlib
import Path. This classification matters because the paper and product story should not
treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_pqc_reference_values.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_pqc_reference_values.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_pqc_reference_values.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_pqc_reference_values.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 99: `verify_product_readiness.py`

`verify_product_readiness.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Run the local product-readiness verification
sequence.""" from __future__ import annotations import argparse import subprocess import
sys from dataclasses import dataclass from pathlib import Path SCRIPT_DIR =
Path(__file__).resolve().parent REPO_ROOT = SCRIPT_DIR.parent. This classification
matters because the paper and product story should not treat all scripts equally.
Runners create evidence, generators shape evidence, validators replay evidence, and
tests preserve contract behavior.

- Research-grade expectation: `verify_product_readiness.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_product_readiness.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_product_readiness.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_product_readiness.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 100: `verify_provider_scope.py`

`verify_provider_scope.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Verify provider-scope metadata across CBOM and
backend-contract artifacts.""" from __future__ import annotations import argparse import
json import re import sys from datetime import datetime, timezone from pathlib import
Path from. This classification matters because the paper and product story should not
treat all scripts equally. Runners create evidence, generators shape evidence,
validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_provider_scope.py` should be callable in a clean
  workspace or explicitly marked as requiring Zephyr, hardware, network, or generated
  pack inputs. The expected output files should be stated in docs or in the schema
  catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_provider_scope.py` should fail with a message that
  identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_provider_scope.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_provider_scope.py` to a release, benchmark, ACVP,
  side-channel, provider, schema, or product workflow lane so maintainers know whether
  it belongs in CI fast gate, full local release, hardware review, or partner-only
  replay.

### Script audit item 101: `verify_release_environment.py`

`verify_release_environment.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Verify release environment metadata across west,
workflows, manifest, and CBOM.""" from __future__ import annotations import argparse
import json import re from datetime import datetime, timezone from pathlib import Path
from. This classification matters because the paper and product story should not treat
all scripts equally. Runners create evidence, generators shape evidence, validators
replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_release_environment.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_release_environment.py` should fail with a message
  that identifies the missing input, invalid artifact, or unsupported environment. If it
  belongs behind a future product CLI, the stable command should wrap it rather than
  exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_release_environment.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_release_environment.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 102: `verify_release_evidence_pack.py`

`verify_release_evidence_pack.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Verify a local release_check.py output directory
as a coherent evidence pack.""" from __future__ import annotations import argparse
import csv import hashlib import json import sys from pathlib import Path from. This
classification matters because the paper and product story should not treat all scripts
equally. Runners create evidence, generators shape evidence, validators replay evidence,
and tests preserve contract behavior.

- Research-grade expectation: `verify_release_evidence_pack.py` should be callable in a
  clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_release_evidence_pack.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_release_evidence_pack.py` succeeds on a synthetic fixture and one path where a
  realistic invalid input fails non-zero. If the script depends on west or hardware, the
  unit test should validate argument parsing and replay behavior with fixtures.
- Integration direction: map `verify_release_evidence_pack.py` to a release, benchmark,
  ACVP, side-channel, provider, schema, or product workflow lane so maintainers know
  whether it belongs in CI fast gate, full local release, hardware review, or partner-
  only replay.

### Script audit item 103: `verify_release_reference_values.py`

`verify_release_reference_values.py` is classified as a replay validator. Its opening
implementation context is: #!/usr/bin/env python3 # SPDX-License-Identifier: LicenseRef-
Proprietary-Collaborative-Evaluation """Replay-check release reference values against
provider-scope evidence.""" from __future__ import annotations import argparse import
json import sys from datetime import datetime, timezone from pathlib import Path from
typing import Any. This classification matters because the paper and product story
should not treat all scripts equally. Runners create evidence, generators shape
evidence, validators replay evidence, and tests preserve contract behavior.

- Research-grade expectation: `verify_release_reference_values.py` should be callable in
  a clean workspace or explicitly marked as requiring Zephyr, hardware, network, or
  generated pack inputs. The expected output files should be stated in docs or in the
  schema catalog if a partner-facing artifact is produced.
- Product-grade expectation: `verify_release_reference_values.py` should fail with a
  message that identifies the missing input, invalid artifact, or unsupported
  environment. If it belongs behind a future product CLI, the stable command should wrap
  it rather than exposing every internal flag to customers.
- Test expectation: add or maintain at least one regression path where
  `verify_release_reference_values.py` succeeds on a synthetic fixture and one path
  where a realistic invalid input fails non-zero. If the script depends on west or
  hardware, the unit test should validate argument parsing and replay behavior with
  fixtures.
- Integration direction: map `verify_release_reference_values.py` to a release,
  benchmark, ACVP, side-channel, provider, schema, or product workflow lane so
  maintainers know whether it belongs in CI fast gate, full local release, hardware
  review, or partner-only replay.

## Public Header And API Contract Audit


### Header contract item 1: `include/pqcp_zephyr/acvp_cmd.h`

This public header is part of the stable integration surface. A quick symbol scan finds
approximately 18 function-like `pqcp_` declarations or uses. Product-grade documentation
must state which declarations are stable, which are validation-oriented, which are
sample-facing, and which require board-specific entropy or memory assumptions.

- Research requirement: experiments that use this header should specify the exact
  function entry points and parameter-set configuration so reviewers can reproduce the
  API path rather than merely rerunning a sample.
- Product requirement: downstream integrators should be able to understand buffer
  ownership, output-size expectations, RNG dependency, failure semantics, and stability
  level without opening the corresponding C source file.
- Implementation direction: keep Doxygen comments synchronized with tests and add a
  header-level stability table to `docs/api-overview.md` when a new public symbol is
  introduced.

### Header contract item 2: `include/pqcp_zephyr/bench.h`

This public header is part of the stable integration surface. A quick symbol scan finds
approximately 16 function-like `pqcp_` declarations or uses. Product-grade documentation
must state which declarations are stable, which are validation-oriented, which are
sample-facing, and which require board-specific entropy or memory assumptions.

- Research requirement: experiments that use this header should specify the exact
  function entry points and parameter-set configuration so reviewers can reproduce the
  API path rather than merely rerunning a sample.
- Product requirement: downstream integrators should be able to understand buffer
  ownership, output-size expectations, RNG dependency, failure semantics, and stability
  level without opening the corresponding C source file.
- Implementation direction: keep Doxygen comments synchronized with tests and add a
  header-level stability table to `docs/api-overview.md` when a new public symbol is
  introduced.

### Header contract item 3: `include/pqcp_zephyr/mldsa.h`

This public header is part of the stable integration surface. A quick symbol scan finds
approximately 22 function-like `pqcp_` declarations or uses. Product-grade documentation
must state which declarations are stable, which are validation-oriented, which are
sample-facing, and which require board-specific entropy or memory assumptions.

- Research requirement: experiments that use this header should specify the exact
  function entry points and parameter-set configuration so reviewers can reproduce the
  API path rather than merely rerunning a sample.
- Product requirement: downstream integrators should be able to understand buffer
  ownership, output-size expectations, RNG dependency, failure semantics, and stability
  level without opening the corresponding C source file.
- Implementation direction: keep Doxygen comments synchronized with tests and add a
  header-level stability table to `docs/api-overview.md` when a new public symbol is
  introduced.

### Header contract item 4: `include/pqcp_zephyr/mlkem.h`

This public header is part of the stable integration surface. A quick symbol scan finds
approximately 15 function-like `pqcp_` declarations or uses. Product-grade documentation
must state which declarations are stable, which are validation-oriented, which are
sample-facing, and which require board-specific entropy or memory assumptions.

- Research requirement: experiments that use this header should specify the exact
  function entry points and parameter-set configuration so reviewers can reproduce the
  API path rather than merely rerunning a sample.
- Product requirement: downstream integrators should be able to understand buffer
  ownership, output-size expectations, RNG dependency, failure semantics, and stability
  level without opening the corresponding C source file.
- Implementation direction: keep Doxygen comments synchronized with tests and add a
  header-level stability table to `docs/api-overview.md` when a new public symbol is
  introduced.

### Header contract item 5: `include/pqcp_zephyr/rng.h`

This public header is part of the stable integration surface. A quick symbol scan finds
approximately 10 function-like `pqcp_` declarations or uses. Product-grade documentation
must state which declarations are stable, which are validation-oriented, which are
sample-facing, and which require board-specific entropy or memory assumptions.

- Research requirement: experiments that use this header should specify the exact
  function entry points and parameter-set configuration so reviewers can reproduce the
  API path rather than merely rerunning a sample.
- Product requirement: downstream integrators should be able to understand buffer
  ownership, output-size expectations, RNG dependency, failure semantics, and stability
  level without opening the corresponding C source file.
- Implementation direction: keep Doxygen comments synchronized with tests and add a
  header-level stability table to `docs/api-overview.md` when a new public symbol is
  introduced.

### Header contract item 6: `include/pqcp_zephyr/tls_selftest.h`

This public header is part of the stable integration surface. A quick symbol scan finds
approximately 4 function-like `pqcp_` declarations or uses. Product-grade documentation
must state which declarations are stable, which are validation-oriented, which are
sample-facing, and which require board-specific entropy or memory assumptions.

- Research requirement: experiments that use this header should specify the exact
  function entry points and parameter-set configuration so reviewers can reproduce the
  API path rather than merely rerunning a sample.
- Product requirement: downstream integrators should be able to understand buffer
  ownership, output-size expectations, RNG dependency, failure semantics, and stability
  level without opening the corresponding C source file.
- Implementation direction: keep Doxygen comments synchronized with tests and add a
  header-level stability table to `docs/api-overview.md` when a new public symbol is
  introduced.

### Header contract item 7: `include/pqcp_zephyr/version.h`

This public header is part of the stable integration surface. A quick symbol scan finds
approximately 0 function-like `pqcp_` declarations or uses. Product-grade documentation
must state which declarations are stable, which are validation-oriented, which are
sample-facing, and which require board-specific entropy or memory assumptions.

- Research requirement: experiments that use this header should specify the exact
  function entry points and parameter-set configuration so reviewers can reproduce the
  API path rather than merely rerunning a sample.
- Product requirement: downstream integrators should be able to understand buffer
  ownership, output-size expectations, RNG dependency, failure semantics, and stability
  level without opening the corresponding C source file.
- Implementation direction: keep Doxygen comments synchronized with tests and add a
  header-level stability table to `docs/api-overview.md` when a new public symbol is
  introduced.

## Sample And Ztest Productization Audit


### Sample audit item 1: `samples/pqcp_assurance_status`

The sample `pqcp_assurance_status` is a customer-facing learning path as well as a
validation target. A product reader will interpret samples as recommended integration
patterns, so every sample needs an explicit label: production-style, validation-only,
benchmark-only, or digest/status demonstration.

- Research-grade use: sample output should be capturable as a transcript and, where
  relevant, bound into the release evidence pack so it becomes reproducible evidence
  rather than an informal demo.
- Product-grade use: the README or sample documentation should name the board
  assumptions, Kconfig toggles, expected output markers, and failure cases that a
  customer should expect.
- Implementation direction: add a sample manifest file or generated table that maps each
  sample to purpose, supported boards, output markers, required claims, and release-
  check inclusion status.

### Sample audit item 2: `samples/pqcp_basic_kem`

The sample `pqcp_basic_kem` is a customer-facing learning path as well as a validation
target. A product reader will interpret samples as recommended integration patterns, so
every sample needs an explicit label: production-style, validation-only, benchmark-only,
or digest/status demonstration.

- Research-grade use: sample output should be capturable as a transcript and, where
  relevant, bound into the release evidence pack so it becomes reproducible evidence
  rather than an informal demo.
- Product-grade use: the README or sample documentation should name the board
  assumptions, Kconfig toggles, expected output markers, and failure cases that a
  customer should expect.
- Implementation direction: add a sample manifest file or generated table that maps each
  sample to purpose, supported boards, output markers, required claims, and release-
  check inclusion status.

### Sample audit item 3: `samples/pqcp_basic_sig`

The sample `pqcp_basic_sig` is a customer-facing learning path as well as a validation
target. A product reader will interpret samples as recommended integration patterns, so
every sample needs an explicit label: production-style, validation-only, benchmark-only,
or digest/status demonstration.

- Research-grade use: sample output should be capturable as a transcript and, where
  relevant, bound into the release evidence pack so it becomes reproducible evidence
  rather than an informal demo.
- Product-grade use: the README or sample documentation should name the board
  assumptions, Kconfig toggles, expected output markers, and failure cases that a
  customer should expect.
- Implementation direction: add a sample manifest file or generated table that maps each
  sample to purpose, supported boards, output markers, required claims, and release-
  check inclusion status.

### Sample audit item 4: `samples/pqcp_bench_protocol`

The sample `pqcp_bench_protocol` is a customer-facing learning path as well as a
validation target. A product reader will interpret samples as recommended integration
patterns, so every sample needs an explicit label: production-style, validation-only,
benchmark-only, or digest/status demonstration.

- Research-grade use: sample output should be capturable as a transcript and, where
  relevant, bound into the release evidence pack so it becomes reproducible evidence
  rather than an informal demo.
- Product-grade use: the README or sample documentation should name the board
  assumptions, Kconfig toggles, expected output markers, and failure cases that a
  customer should expect.
- Implementation direction: add a sample manifest file or generated table that maps each
  sample to purpose, supported boards, output markers, required claims, and release-
  check inclusion status.

### Sample audit item 5: `samples/pqcp_kat_deterministic`

The sample `pqcp_kat_deterministic` is a customer-facing learning path as well as a
validation target. A product reader will interpret samples as recommended integration
patterns, so every sample needs an explicit label: production-style, validation-only,
benchmark-only, or digest/status demonstration.

- Research-grade use: sample output should be capturable as a transcript and, where
  relevant, bound into the release evidence pack so it becomes reproducible evidence
  rather than an informal demo.
- Product-grade use: the README or sample documentation should name the board
  assumptions, Kconfig toggles, expected output markers, and failure cases that a
  customer should expect.
- Implementation direction: add a sample manifest file or generated table that maps each
  sample to purpose, supported boards, output markers, required claims, and release-
  check inclusion status.

### Sample audit item 6: `samples/pqcp_serial_acvp`

The sample `pqcp_serial_acvp` is a customer-facing learning path as well as a validation
target. A product reader will interpret samples as recommended integration patterns, so
every sample needs an explicit label: production-style, validation-only, benchmark-only,
or digest/status demonstration.

- Research-grade use: sample output should be capturable as a transcript and, where
  relevant, bound into the release evidence pack so it becomes reproducible evidence
  rather than an informal demo.
- Product-grade use: the README or sample documentation should name the board
  assumptions, Kconfig toggles, expected output markers, and failure cases that a
  customer should expect.
- Implementation direction: add a sample manifest file or generated table that maps each
  sample to purpose, supported boards, output markers, required claims, and release-
  check inclusion status.

### Sample audit item 7: `samples/pqcp_streaming_hash_mldsa`

The sample `pqcp_streaming_hash_mldsa` is a customer-facing learning path as well as a
validation target. A product reader will interpret samples as recommended integration
patterns, so every sample needs an explicit label: production-style, validation-only,
benchmark-only, or digest/status demonstration.

- Research-grade use: sample output should be capturable as a transcript and, where
  relevant, bound into the release evidence pack so it becomes reproducible evidence
  rather than an informal demo.
- Product-grade use: the README or sample documentation should name the board
  assumptions, Kconfig toggles, expected output markers, and failure cases that a
  customer should expect.
- Implementation direction: add a sample manifest file or generated table that maps each
  sample to purpose, supported boards, output markers, required claims, and release-
  check inclusion status.

### Sample audit item 8: `samples/pqcp_tls_mbedtls_psa`

The sample `pqcp_tls_mbedtls_psa` is a customer-facing learning path as well as a
validation target. A product reader will interpret samples as recommended integration
patterns, so every sample needs an explicit label: production-style, validation-only,
benchmark-only, or digest/status demonstration.

- Research-grade use: sample output should be capturable as a transcript and, where
  relevant, bound into the release evidence pack so it becomes reproducible evidence
  rather than an informal demo.
- Product-grade use: the README or sample documentation should name the board
  assumptions, Kconfig toggles, expected output markers, and failure cases that a
  customer should expect.
- Implementation direction: add a sample manifest file or generated table that maps each
  sample to purpose, supported boards, output markers, required claims, and release-
  check inclusion status.

### Ztest audit item 1: `tests/ztest_acvp_kat`

The ztest directory `ztest_acvp_kat` is part of the executable evidence floor. Product-
grade validation needs to know whether this test is correctness, parser robustness,
timeout recovery, CT smoke, boot self-test, RNG, or TLS integration evidence.

- Research-grade use: include both positive and negative controls when possible, and
  record the transcript marker that proves the relevant test actually executed.
- Product-grade use: connect each ztest to one or more claim IDs, an evidence class, and
  a release profile so missing tests cannot silently disappear from a partner pack.
- Implementation direction: generate a ztest coverage map from directory names, Kconfig
  overlays, and release-check transcript steps; make the map fail if a required test has
  no claim link.

### Ztest audit item 2: `tests/ztest_acvp_serial`

The ztest directory `ztest_acvp_serial` is part of the executable evidence floor.
Product-grade validation needs to know whether this test is correctness, parser
robustness, timeout recovery, CT smoke, boot self-test, RNG, or TLS integration
evidence.

- Research-grade use: include both positive and negative controls when possible, and
  record the transcript marker that proves the relevant test actually executed.
- Product-grade use: connect each ztest to one or more claim IDs, an evidence class, and
  a release profile so missing tests cannot silently disappear from a partner pack.
- Implementation direction: generate a ztest coverage map from directory names, Kconfig
  overlays, and release-check transcript steps; make the map fail if a required test has
  no claim link.

### Ztest audit item 3: `tests/ztest_acvp_serial_negative`

The ztest directory `ztest_acvp_serial_negative` is part of the executable evidence
floor. Product-grade validation needs to know whether this test is correctness, parser
robustness, timeout recovery, CT smoke, boot self-test, RNG, or TLS integration
evidence.

- Research-grade use: include both positive and negative controls when possible, and
  record the transcript marker that proves the relevant test actually executed.
- Product-grade use: connect each ztest to one or more claim IDs, an evidence class, and
  a release profile so missing tests cannot silently disappear from a partner pack.
- Implementation direction: generate a ztest coverage map from directory names, Kconfig
  overlays, and release-check transcript steps; make the map fail if a required test has
  no claim link.

### Ztest audit item 4: `tests/ztest_ct_smoke`

The ztest directory `ztest_ct_smoke` is part of the executable evidence floor. Product-
grade validation needs to know whether this test is correctness, parser robustness,
timeout recovery, CT smoke, boot self-test, RNG, or TLS integration evidence.

- Research-grade use: include both positive and negative controls when possible, and
  record the transcript marker that proves the relevant test actually executed.
- Product-grade use: connect each ztest to one or more claim IDs, an evidence class, and
  a release profile so missing tests cannot silently disappear from a partner pack.
- Implementation direction: generate a ztest coverage map from directory names, Kconfig
  overlays, and release-check transcript steps; make the map fail if a required test has
  no claim link.

### Ztest audit item 5: `tests/ztest_kat_boot_verify`

The ztest directory `ztest_kat_boot_verify` is part of the executable evidence floor.
Product-grade validation needs to know whether this test is correctness, parser
robustness, timeout recovery, CT smoke, boot self-test, RNG, or TLS integration
evidence.

- Research-grade use: include both positive and negative controls when possible, and
  record the transcript marker that proves the relevant test actually executed.
- Product-grade use: connect each ztest to one or more claim IDs, an evidence class, and
  a release profile so missing tests cannot silently disappear from a partner pack.
- Implementation direction: generate a ztest coverage map from directory names, Kconfig
  overlays, and release-check transcript steps; make the map fail if a required test has
  no claim link.

### Ztest audit item 6: `tests/ztest_primitive`

The ztest directory `ztest_primitive` is part of the executable evidence floor. Product-
grade validation needs to know whether this test is correctness, parser robustness,
timeout recovery, CT smoke, boot self-test, RNG, or TLS integration evidence.

- Research-grade use: include both positive and negative controls when possible, and
  record the transcript marker that proves the relevant test actually executed.
- Product-grade use: connect each ztest to one or more claim IDs, an evidence class, and
  a release profile so missing tests cannot silently disappear from a partner pack.
- Implementation direction: generate a ztest coverage map from directory names, Kconfig
  overlays, and release-check transcript steps; make the map fail if a required test has
  no claim link.

### Ztest audit item 7: `tests/ztest_rng`

The ztest directory `ztest_rng` is part of the executable evidence floor. Product-grade
validation needs to know whether this test is correctness, parser robustness, timeout
recovery, CT smoke, boot self-test, RNG, or TLS integration evidence.

- Research-grade use: include both positive and negative controls when possible, and
  record the transcript marker that proves the relevant test actually executed.
- Product-grade use: connect each ztest to one or more claim IDs, an evidence class, and
  a release profile so missing tests cannot silently disappear from a partner pack.
- Implementation direction: generate a ztest coverage map from directory names, Kconfig
  overlays, and release-check transcript steps; make the map fail if a required test has
  no claim link.

### Ztest audit item 8: `tests/ztest_tls_selftest`

The ztest directory `ztest_tls_selftest` is part of the executable evidence floor.
Product-grade validation needs to know whether this test is correctness, parser
robustness, timeout recovery, CT smoke, boot self-test, RNG, or TLS integration
evidence.

- Research-grade use: include both positive and negative controls when possible, and
  record the transcript marker that proves the relevant test actually executed.
- Product-grade use: connect each ztest to one or more claim IDs, an evidence class, and
  a release profile so missing tests cannot silently disappear from a partner pack.
- Implementation direction: generate a ztest coverage map from directory names, Kconfig
  overlays, and release-check transcript steps; make the map fail if a required test has
  no claim link.

## Research Experiment Program

A novel paper cannot rest on the existence of many tools. It needs controlled
experiments that answer research questions. The following experiment program turns the
repository into an artifact-evaluable system. Each family names the hypothesis,
implementation hook, outputs, negative control, and product relevance.


### Experiment family 1: `hardware_promotion`

Promote QEMU regression evidence into physical-board evidence with UART transcript
capture, board metadata, and resource budgets.

- Hypothesis: `hardware_promotion` improves reviewability because it converts an
  implicit maintainer claim into a replayable artifact with a stable schema, clear
  execution environment, and falsifiable acceptance rule.
- Repository hooks: use the existing release-check, schema-contract, benchmark-campaign,
  ztest, Passport, and replay-verifier paths rather than creating a parallel workflow.
- Positive control: generate a clean fixture or release pack and prove the relevant
  verifier passes with exact artifact names and hash bindings.
- Negative control: corrupt the smallest artifact that supports the claim, such as one
  transcript, one CSV column, one digest, one claim ID, one profile decision, or one
  source/path link.
- Expected output: a JSON result, a Markdown summary, a transcript hash, a schema-
  validated artifact entry, and a replay failure mode documented in the research
  appendix.
- Product acceptance: the same experiment can be explained to a partner as a concrete
  assurance check, with a remediation path when it fails.
- Paper acceptance: the experiment includes enough metadata to be rerun by an artifact
  evaluator without access to private CI minutes or the original developer machine.

### Experiment family 2: `benchmark_distribution`

Convert single-observation benchmark rows into repeated distribution campaigns with min,
median, p90, p99, max, MAD, and sample count.

- Hypothesis: `benchmark_distribution` improves reviewability because it converts an
  implicit maintainer claim into a replayable artifact with a stable schema, clear
  execution environment, and falsifiable acceptance rule.
- Repository hooks: use the existing release-check, schema-contract, benchmark-campaign,
  ztest, Passport, and replay-verifier paths rather than creating a parallel workflow.
- Positive control: generate a clean fixture or release pack and prove the relevant
  verifier passes with exact artifact names and hash bindings.
- Negative control: corrupt the smallest artifact that supports the claim, such as one
  transcript, one CSV column, one digest, one claim ID, one profile decision, or one
  source/path link.
- Expected output: a JSON result, a Markdown summary, a transcript hash, a schema-
  validated artifact entry, and a replay failure mode documented in the research
  appendix.
- Product acceptance: the same experiment can be explained to a partner as a concrete
  assurance check, with a remediation path when it fails.
- Paper acceptance: the experiment includes enough metadata to be rerun by an artifact
  evaluator without access to private CI minutes or the original developer machine.

### Experiment family 3: `acvp_interop`

Exercise JSON-to-serial ACVP workflows across valid, invalid, malformed-then-valid, and
recovery cases.

- Hypothesis: `acvp_interop` improves reviewability because it converts an implicit
  maintainer claim into a replayable artifact with a stable schema, clear execution
  environment, and falsifiable acceptance rule.
- Repository hooks: use the existing release-check, schema-contract, benchmark-campaign,
  ztest, Passport, and replay-verifier paths rather than creating a parallel workflow.
- Positive control: generate a clean fixture or release pack and prove the relevant
  verifier passes with exact artifact names and hash bindings.
- Negative control: corrupt the smallest artifact that supports the claim, such as one
  transcript, one CSV column, one digest, one claim ID, one profile decision, or one
  source/path link.
- Expected output: a JSON result, a Markdown summary, a transcript hash, a schema-
  validated artifact entry, and a replay failure mode documented in the research
  appendix.
- Product acceptance: the same experiment can be explained to a partner as a concrete
  assurance check, with a remediation path when it fails.
- Paper acceptance: the experiment includes enough metadata to be rerun by an artifact
  evaluator without access to private CI minutes or the original developer machine.

### Experiment family 4: `kat_provenance`

Bind vendored vector fixtures to generated headers and boot self-verify paths.

- Hypothesis: `kat_provenance` improves reviewability because it converts an implicit
  maintainer claim into a replayable artifact with a stable schema, clear execution
  environment, and falsifiable acceptance rule.
- Repository hooks: use the existing release-check, schema-contract, benchmark-campaign,
  ztest, Passport, and replay-verifier paths rather than creating a parallel workflow.
- Positive control: generate a clean fixture or release pack and prove the relevant
  verifier passes with exact artifact names and hash bindings.
- Negative control: corrupt the smallest artifact that supports the claim, such as one
  transcript, one CSV column, one digest, one claim ID, one profile decision, or one
  source/path link.
- Expected output: a JSON result, a Markdown summary, a transcript hash, a schema-
  validated artifact entry, and a replay failure mode documented in the research
  appendix.
- Product acceptance: the same experiment can be explained to a partner as a concrete
  assurance check, with a remediation path when it fails.
- Paper acceptance: the experiment includes enough metadata to be rerun by an artifact
  evaluator without access to private CI minutes or the original developer machine.

### Experiment family 5: `side_channel_smoke`

Combine CT sample markers with disassembly policy and clear non-proof labeling.

- Hypothesis: `side_channel_smoke` improves reviewability because it converts an
  implicit maintainer claim into a replayable artifact with a stable schema, clear
  execution environment, and falsifiable acceptance rule.
- Repository hooks: use the existing release-check, schema-contract, benchmark-campaign,
  ztest, Passport, and replay-verifier paths rather than creating a parallel workflow.
- Positive control: generate a clean fixture or release pack and prove the relevant
  verifier passes with exact artifact names and hash bindings.
- Negative control: corrupt the smallest artifact that supports the claim, such as one
  transcript, one CSV column, one digest, one claim ID, one profile decision, or one
  source/path link.
- Expected output: a JSON result, a Markdown summary, a transcript hash, a schema-
  validated artifact entry, and a replay failure mode documented in the research
  appendix.
- Product acceptance: the same experiment can be explained to a partner as a concrete
  assurance check, with a remediation path when it fails.
- Paper acceptance: the experiment includes enough metadata to be rerun by an artifact
  evaluator without access to private CI minutes or the original developer machine.

### Experiment family 6: `provider_currency`

Track native backend pins, upstream drift, license metadata, source inventory, and
provider-scope policy.

- Hypothesis: `provider_currency` improves reviewability because it converts an implicit
  maintainer claim into a replayable artifact with a stable schema, clear execution
  environment, and falsifiable acceptance rule.
- Repository hooks: use the existing release-check, schema-contract, benchmark-campaign,
  ztest, Passport, and replay-verifier paths rather than creating a parallel workflow.
- Positive control: generate a clean fixture or release pack and prove the relevant
  verifier passes with exact artifact names and hash bindings.
- Negative control: corrupt the smallest artifact that supports the claim, such as one
  transcript, one CSV column, one digest, one claim ID, one profile decision, or one
  source/path link.
- Expected output: a JSON result, a Markdown summary, a transcript hash, a schema-
  validated artifact entry, and a replay failure mode documented in the research
  appendix.
- Product acceptance: the same experiment can be explained to a partner as a concrete
  assurance check, with a remediation path when it fails.
- Paper acceptance: the experiment includes enough metadata to be rerun by an artifact
  evaluator without access to private CI minutes or the original developer machine.

### Experiment family 7: `schema_contract`

Prove partner-facing release artifacts have stable shapes before dashboard ingestion.

- Hypothesis: `schema_contract` improves reviewability because it converts an implicit
  maintainer claim into a replayable artifact with a stable schema, clear execution
  environment, and falsifiable acceptance rule.
- Repository hooks: use the existing release-check, schema-contract, benchmark-campaign,
  ztest, Passport, and replay-verifier paths rather than creating a parallel workflow.
- Positive control: generate a clean fixture or release pack and prove the relevant
  verifier passes with exact artifact names and hash bindings.
- Negative control: corrupt the smallest artifact that supports the claim, such as one
  transcript, one CSV column, one digest, one claim ID, one profile decision, or one
  source/path link.
- Expected output: a JSON result, a Markdown summary, a transcript hash, a schema-
  validated artifact entry, and a replay failure mode documented in the research
  appendix.
- Product acceptance: the same experiment can be explained to a partner as a concrete
  assurance check, with a remediation path when it fails.
- Paper acceptance: the experiment includes enough metadata to be rerun by an artifact
  evaluator without access to private CI minutes or the original developer machine.

### Experiment family 8: `tamper_drill`

Mutate release-pack artifacts and prove replay checks fail with targeted messages.

- Hypothesis: `tamper_drill` improves reviewability because it converts an implicit
  maintainer claim into a replayable artifact with a stable schema, clear execution
  environment, and falsifiable acceptance rule.
- Repository hooks: use the existing release-check, schema-contract, benchmark-campaign,
  ztest, Passport, and replay-verifier paths rather than creating a parallel workflow.
- Positive control: generate a clean fixture or release pack and prove the relevant
  verifier passes with exact artifact names and hash bindings.
- Negative control: corrupt the smallest artifact that supports the claim, such as one
  transcript, one CSV column, one digest, one claim ID, one profile decision, or one
  source/path link.
- Expected output: a JSON result, a Markdown summary, a transcript hash, a schema-
  validated artifact entry, and a replay failure mode documented in the research
  appendix.
- Product acceptance: the same experiment can be explained to a partner as a concrete
  assurance check, with a remediation path when it fails.
- Paper acceptance: the experiment includes enough metadata to be rerun by an artifact
  evaluator without access to private CI minutes or the original developer machine.

### Experiment family 9: `dashboard_ingest`

Load the pack into a local dashboard using only schema-validated artifacts and no
invented values.

- Hypothesis: `dashboard_ingest` improves reviewability because it converts an implicit
  maintainer claim into a replayable artifact with a stable schema, clear execution
  environment, and falsifiable acceptance rule.
- Repository hooks: use the existing release-check, schema-contract, benchmark-campaign,
  ztest, Passport, and replay-verifier paths rather than creating a parallel workflow.
- Positive control: generate a clean fixture or release pack and prove the relevant
  verifier passes with exact artifact names and hash bindings.
- Negative control: corrupt the smallest artifact that supports the claim, such as one
  transcript, one CSV column, one digest, one claim ID, one profile decision, or one
  source/path link.
- Expected output: a JSON result, a Markdown summary, a transcript hash, a schema-
  validated artifact entry, and a replay failure mode documented in the research
  appendix.
- Product acceptance: the same experiment can be explained to a partner as a concrete
  assurance check, with a remediation path when it fails.
- Paper acceptance: the experiment includes enough metadata to be rerun by an artifact
  evaluator without access to private CI minutes or the original developer machine.

### Experiment family 10: `product_cli`

Wrap internal scripts with stable user-facing commands and consistent failure output.

- Hypothesis: `product_cli` improves reviewability because it converts an implicit
  maintainer claim into a replayable artifact with a stable schema, clear execution
  environment, and falsifiable acceptance rule.
- Repository hooks: use the existing release-check, schema-contract, benchmark-campaign,
  ztest, Passport, and replay-verifier paths rather than creating a parallel workflow.
- Positive control: generate a clean fixture or release pack and prove the relevant
  verifier passes with exact artifact names and hash bindings.
- Negative control: corrupt the smallest artifact that supports the claim, such as one
  transcript, one CSV column, one digest, one claim ID, one profile decision, or one
  source/path link.
- Expected output: a JSON result, a Markdown summary, a transcript hash, a schema-
  validated artifact entry, and a replay failure mode documented in the research
  appendix.
- Product acceptance: the same experiment can be explained to a partner as a concrete
  assurance check, with a remediation path when it fails.
- Paper acceptance: the experiment includes enough metadata to be rerun by an artifact
  evaluator without access to private CI minutes or the original developer machine.

### Experiment family 11: `customer_policy`

Allow customer-specific policy overlays without modifying repository defaults.

- Hypothesis: `customer_policy` improves reviewability because it converts an implicit
  maintainer claim into a replayable artifact with a stable schema, clear execution
  environment, and falsifiable acceptance rule.
- Repository hooks: use the existing release-check, schema-contract, benchmark-campaign,
  ztest, Passport, and replay-verifier paths rather than creating a parallel workflow.
- Positive control: generate a clean fixture or release pack and prove the relevant
  verifier passes with exact artifact names and hash bindings.
- Negative control: corrupt the smallest artifact that supports the claim, such as one
  transcript, one CSV column, one digest, one claim ID, one profile decision, or one
  source/path link.
- Expected output: a JSON result, a Markdown summary, a transcript hash, a schema-
  validated artifact entry, and a replay failure mode documented in the research
  appendix.
- Product acceptance: the same experiment can be explained to a partner as a concrete
  assurance check, with a remediation path when it fails.
- Paper acceptance: the experiment includes enough metadata to be rerun by an artifact
  evaluator without access to private CI minutes or the original developer machine.

### Experiment family 12: `signed_pack`

Add detached signature support and key-custody documentation once policy is defined.

- Hypothesis: `signed_pack` improves reviewability because it converts an implicit
  maintainer claim into a replayable artifact with a stable schema, clear execution
  environment, and falsifiable acceptance rule.
- Repository hooks: use the existing release-check, schema-contract, benchmark-campaign,
  ztest, Passport, and replay-verifier paths rather than creating a parallel workflow.
- Positive control: generate a clean fixture or release pack and prove the relevant
  verifier passes with exact artifact names and hash bindings.
- Negative control: corrupt the smallest artifact that supports the claim, such as one
  transcript, one CSV column, one digest, one claim ID, one profile decision, or one
  source/path link.
- Expected output: a JSON result, a Markdown summary, a transcript hash, a schema-
  validated artifact entry, and a replay failure mode documented in the research
  appendix.
- Product acceptance: the same experiment can be explained to a partner as a concrete
  assurance check, with a remediation path when it fails.
- Paper acceptance: the experiment includes enough metadata to be rerun by an artifact
  evaluator without access to private CI minutes or the original developer machine.

## Product Hardening Roadmap With File-Level Acceptance


### Roadmap item 1: `schemas/evidence/`

Maintain product-facing evidence schemas and catalog entries for every partner-visible
artifact.

- Before product presentation: define the user-facing promise this file supports, the
  failure it catches, and the profile where it is mandatory.
- Before paper submission: define the experiment or ablation that proves this file
  changes the outcome compared with a simpler baseline.
- Before partner handoff: ensure command examples, schemas, or generated outputs are
  stable enough that the partner can rerun them without private maintainer context.
- Acceptance: a reviewer can point to this file, a generated output, and a test or
  verifier that proves the file is not just documentation but part of the evidence
  chain.

### Roadmap item 2: `scripts/validate_evidence_schemas.py`

Validate artifact shape, paths, hashes, CSV columns, and cross-artifact release metadata
before dashboard or partner ingestion.

- Before product presentation: define the user-facing promise this file supports, the
  failure it catches, and the profile where it is mandatory.
- Before paper submission: define the experiment or ablation that proves this file
  changes the outcome compared with a simpler baseline.
- Before partner handoff: ensure command examples, schemas, or generated outputs are
  stable enough that the partner can rerun them without private maintainer context.
- Acceptance: a reviewer can point to this file, a generated output, and a test or
  verifier that proves the file is not just documentation but part of the evidence
  chain.

### Roadmap item 3: `scripts/release_check.py`

Keep fast CI mode separate from full local evidence generation while preserving
transcript hashing and mandatory claims.

- Before product presentation: define the user-facing promise this file supports, the
  failure it catches, and the profile where it is mandatory.
- Before paper submission: define the experiment or ablation that proves this file
  changes the outcome compared with a simpler baseline.
- Before partner handoff: ensure command examples, schemas, or generated outputs are
  stable enough that the partner can rerun them without private maintainer context.
- Acceptance: a reviewer can point to this file, a generated output, and a test or
  verifier that proves the file is not just documentation but part of the evidence
  chain.

### Roadmap item 4: `scripts/verify_release_evidence_pack.py`

Remain the semantic replay verifier and call schema validation when product profiles are
requested.

- Before product presentation: define the user-facing promise this file supports, the
  failure it catches, and the profile where it is mandatory.
- Before paper submission: define the experiment or ablation that proves this file
  changes the outcome compared with a simpler baseline.
- Before partner handoff: ensure command examples, schemas, or generated outputs are
  stable enough that the partner can rerun them without private maintainer context.
- Acceptance: a reviewer can point to this file, a generated output, and a test or
  verifier that proves the file is not just documentation but part of the evidence
  chain.

### Roadmap item 5: `scripts/run_benchmark_campaign.py`

Produce distribution-grade benchmark artifacts and comparison metadata for paper-grade
performance claims.

- Before product presentation: define the user-facing promise this file supports, the
  failure it catches, and the profile where it is mandatory.
- Before paper submission: define the experiment or ablation that proves this file
  changes the outcome compared with a simpler baseline.
- Before partner handoff: ensure command examples, schemas, or generated outputs are
  stable enough that the partner can rerun them without private maintainer context.
- Acceptance: a reviewer can point to this file, a generated output, and a test or
  verifier that proves the file is not just documentation but part of the evidence
  chain.

### Roadmap item 6: `scripts/run_hardware_benchmarks.py`

Become the physical-board promotion lane with UART transcript capture and hardware
absence handled explicitly.

- Before product presentation: define the user-facing promise this file supports, the
  failure it catches, and the profile where it is mandatory.
- Before paper submission: define the experiment or ablation that proves this file
  changes the outcome compared with a simpler baseline.
- Before partner handoff: ensure command examples, schemas, or generated outputs are
  stable enough that the partner can rerun them without private maintainer context.
- Acceptance: a reviewer can point to this file, a generated output, and a test or
  verifier that proves the file is not just documentation but part of the evidence
  chain.

### Roadmap item 7: `scripts/run_acvp_json_vectors.py`

Bridge NIST-style vector JSON to the existing serial command path without changing wire
format.

- Before product presentation: define the user-facing promise this file supports, the
  failure it catches, and the profile where it is mandatory.
- Before paper submission: define the experiment or ablation that proves this file
  changes the outcome compared with a simpler baseline.
- Before partner handoff: ensure command examples, schemas, or generated outputs are
  stable enough that the partner can rerun them without private maintainer context.
- Acceptance: a reviewer can point to this file, a generated output, and a test or
  verifier that proves the file is not just documentation but part of the evidence
  chain.

### Roadmap item 8: `scripts/analyze_ct_samples.py`

Keep CT sample analysis explicitly framed as smoke/regression evidence, not formal
proof.

- Before product presentation: define the user-facing promise this file supports, the
  failure it catches, and the profile where it is mandatory.
- Before paper submission: define the experiment or ablation that proves this file
  changes the outcome compared with a simpler baseline.
- Before partner handoff: ensure command examples, schemas, or generated outputs are
  stable enough that the partner can rerun them without private maintainer context.
- Acceptance: a reviewer can point to this file, a generated output, and a test or
  verifier that proves the file is not just documentation but part of the evidence
  chain.

### Roadmap item 9: `scripts/verify_backend_contract.py`

Keep provider policy executable and make provider-scope drift fail release replay.

- Before product presentation: define the user-facing promise this file supports, the
  failure it catches, and the profile where it is mandatory.
- Before paper submission: define the experiment or ablation that proves this file
  changes the outcome compared with a simpler baseline.
- Before partner handoff: ensure command examples, schemas, or generated outputs are
  stable enough that the partner can rerun them without private maintainer context.
- Acceptance: a reviewer can point to this file, a generated output, and a test or
  verifier that proves the file is not just documentation but part of the evidence
  chain.

### Roadmap item 10: `docs/evidence-schema-contract.md`

Explain the product data boundary so dashboard builders and partners can consume the
pack safely.

- Before product presentation: define the user-facing promise this file supports, the
  failure it catches, and the profile where it is mandatory.
- Before paper submission: define the experiment or ablation that proves this file
  changes the outcome compared with a simpler baseline.
- Before partner handoff: ensure command examples, schemas, or generated outputs are
  stable enough that the partner can rerun them without private maintainer context.
- Acceptance: a reviewer can point to this file, a generated output, and a test or
  verifier that proves the file is not just documentation but part of the evidence
  chain.

### Roadmap item 11: `docs/market-product-strategy.md`

Keep customer segments, packaging, pricing, and product boundaries tied to actual repo
capabilities.

- Before product presentation: define the user-facing promise this file supports, the
  failure it catches, and the profile where it is mandatory.
- Before paper submission: define the experiment or ablation that proves this file
  changes the outcome compared with a simpler baseline.
- Before partner handoff: ensure command examples, schemas, or generated outputs are
  stable enough that the partner can rerun them without private maintainer context.
- Acceptance: a reviewer can point to this file, a generated output, and a test or
  verifier that proves the file is not just documentation but part of the evidence
  chain.

### Roadmap item 12: `docs/research-product-hardening-audit.md`

Remain the long-form paper/product backlog and update when new evidence gaps are
discovered.

- Before product presentation: define the user-facing promise this file supports, the
  failure it catches, and the profile where it is mandatory.
- Before paper submission: define the experiment or ablation that proves this file
  changes the outcome compared with a simpler baseline.
- Before partner handoff: ensure command examples, schemas, or generated outputs are
  stable enough that the partner can rerun them without private maintainer context.
- Acceptance: a reviewer can point to this file, a generated output, and a test or
  verifier that proves the file is not just documentation but part of the evidence
  chain.
