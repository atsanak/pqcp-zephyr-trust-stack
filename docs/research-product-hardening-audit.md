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
