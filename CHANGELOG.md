# Changelog

All notable changes to this module are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
with entries grouped so downstream Zephyr integrators can quickly map a
release tag to the validation and provider surface it introduced.

## [Unreleased]

### Changed

- Sources are grouped by family under `src/`; the fleet, sovereign and
  adaptive families moved to `src/experimental/` and select `EXPERIMENTAL`.
- The runtime and protected-channel decision catalogs are generated at
  CMake configure time instead of being committed under `src/`.
- The README is shorter; reference material moved to `docs/`.

### Added

- ML-KEM decapsulation compiler matrix and a release check that compares
  traced Cortex-M3 instructions with the firmware disassembly.
- Allocation-free policy-bound crypto broker with tenant principals, quotas,
  grants, attenuable capabilities, opaque-key dispatch, exact idempotency,
  cancellation, custody and deadline enforcement, chained receipts, HMAC
  authentication, and optional ML-DSA receipt signatures.
- Canonical bounded-CBOR fleet protocol for signed enrollment requests,
  ownership vouchers, operational credentials, policy bundles, revocation
  updates, rotation authorization, update manifests, and command results.
- Durable two-slot device trust state with an in-memory development backend
  and optional PSA Internal Trusted Storage backend.
- Device lifecycle integration for local operational-key generation, policy
  epochs, replay protection, exporter-bound channel identity, overlapping key
  rotation, firmware authorization, revocation, recovery, and persistent
  decommissioning.
- Rust `pqcp-fleet` coordinator with SQLite/WAL inventory, signed
  firmware-compatible artifacts, deterministic canary cohorts, rollout
  appraisal, explicit promotion/drain completion states, signed revocation
  publication, REST/SSE endpoints, operator CLI, and an encrypted ML-DSA-65
  policy root.
- `samples/pqcp_fleet_trust` demonstrating factory admission through
  decommissioning with opaque runtime key handles.
- Fleet operations and resilience plane covering deterministic device policy,
  idempotent command execution, update probation and rollback, tamper-evident
  audit, telemetry summaries, signed attestation, reconciliation, uncertain
  secure time, exact bounded revocations, rollout cohorts, health circuit
  breaking, offline leases, evidence-chained recovery, peer trust, admission
  control, correlated risk scoring, and maintenance conflict scheduling.
- Allocation-free zero-trust edge security plane with bounded service mesh
  identity and routing, composite admission, durable authenticated messaging,
  confidential versioned object storage, incident response, evidence,
  containment, continuity, posture and attestation, policy distribution,
  secret rotation, anomaly and resource controls, DLP, trust federation,
  credential caching, isolation zones, tamper-evident provenance, deadline
  scheduling, SLA monitoring, transactional configuration, and canonical
  compliance summaries.
- Assurance claims catalog now exposes per-primitive KAT claims
  (`kat.mlkem_512/768/1024`, `kat.mldsa_44/65/87`), per-primitive
  benchmark claims (`benchmark.mlkem_throughput`,
  `benchmark.mldsa_throughput`), and ACVP robustness claims
  (`acvp.negative_path_rejection`, `acvp.timeout_recovery`).
- `acvp.negative_path_rejection` binds to
  `scripts/acvp_negative_scenarios.json` and the captured ACVP serial
  ztest run transcript, requiring the documented ztest markers for
  malformed-command, invalid-hex/wrong-size, and serial-garbage-recovery
  cases.
- `acvp.timeout_recovery` requires the `test_readline_timeout` and
  `ERROR:TIMEOUT` markers in the same transcript.

### Changed

- Runtime key-store providers now execute ML-DSA, ML-KEM, HKDF, and AES-GCM
  operations through opaque handles; executors no longer need raw private-key
  access for those paths.
- Assurance claims catalog schema bumped from `schema_version=1` to
  `schema_version=2`. Both generator and verifier accept either version;
  v1 catalogs and v1 replay-only ledgers warn that they cover the
  reduced legacy claim set.
- `release_check.py` and `run_extended_checks.py` now share
  `HOST_ENV_BLACKLIST`, `detect_west_root`, `discover_west`, `clean_env`,
  and `command_to_text` from `scripts/local_workflow.py`.

### Security

- Fleet signatures use the `PQCP-FLEET-CBOR-V1` ML-DSA context over exact
  canonical payload bytes. Decoders reject trailing or non-canonical data,
  and device state rejects stale policy, revocation, update, enrollment, and
  rotation sequences.
- Coordinator root keys are encrypted with XChaCha20-Poly1305 using an
  Argon2id-derived key and remain permission-restricted at rest.
- Coordinator-issued artifacts use a durable monotonic sequence allocator
  seeded above observed device counters, preventing valid policy or
  revocation epochs from being rejected as replayed messages.

## [1.0.0] - 2026-04-26

First production-quality release of the Zephyr PQC trust stack. Supports
ML-KEM-512/768/1024 (FIPS 203) and ML-DSA-44/65/87 (FIPS 204) through a
PSA Crypto + mbedTLS provider surface, with an ACVP serial harness, KAT
verification, a cost-of-assurance regression suite, MCU resource-budget
enforcement, sanitizer coverage, and an auditable benchmark provenance
sidecar.

### Added

- Production-grade PQCP provider family covering ML-KEM-512/768/1024 and
  ML-DSA-44/65/87 via a PSA Crypto driver layer (`psa_mlkem_driver`,
  `psa_mldsa_driver`) and a Zephyr-facing `pqcp_mlkem_*` / `pqcp_mldsa_*`
  API backed by the `mlkem-native` and `mldsa-native` modules pinned in
  `west.yml`.
- Vendored offline NIST ACVP fixtures for ML-KEM-512/768/1024 key
  generation and encapsulation plus ML-DSA-44/65/87 deterministic
  signing and verification, all under `tests/ztest_acvp_kat/nist_vectors/`.
- Expanded `tests/ztest_acvp_kat` coverage to all FIPS 203 / FIPS 204
  parameter sets with 12 ZTEST cases and offline provenance verification
  via `scripts/verify_kat_provenance.py`.
- ACVP serial harness with bounded-line validation, garbage and
  oversized frame rejection, partial-frame timeout recovery, and a full
  set of negative-scenario ztests (`tests/ztest_acvp_serial`).
- TLS-level cost-of-assurance regression suite in
  `scripts/qemu_cost_of_assurance_regression.json` with enforced
  `handshake_latency_ratio`, `rom_ratio`, `ram_ratio`, `auth_time`, and
  `key_exchange_time` thresholds for both ML-KEM-768+ML-DSA-65 and
  ML-KEM-512+ML-DSA-87 protocol suites, plus RTOS/TLS decomposition
  guardrails for provider overhead, transport overhead, and RTOS jitter
  columns emitted by the protocol benchmark.
- `scripts/export_results.py` for benchmark extraction,
  generating `results/benchmark_results.csv` and
  `results/benchmark_summary.md` from the checked-in cost-of-assurance
  matrix, with paired `avg_cycles` and `avg_us` columns.
- Benchmark provenance sidecar (`benchmark_provenance.json`,
  `PROVENANCE_SCHEMA_VERSION = 1`) written next to every CSV, recording
  csv sha256, host, toolchain, git SHAs, CI flag, and per-layer row
  stats. Verified via `export_results.py --validate-only
  --verify-provenance`.
- MCU resource-budget enforcement: `scripts/check_resource_budgets.py`
  builds the `pqcp_bench_protocol` configurations for `nucleo_h743zi`
  and fails the release gate if ROM or RAM exceeds the envelopes
  declared in `scripts/resource_budgets.json`.
- Version-triple consistency gate: `scripts/check_version_consistency.py`
  cross-checks `PQCP_VERSION_STRING` in `include/pqcp_zephyr/version.h`,
  `PQCP_PROJECT_VERSION` in `CMakeLists.txt`, and (optionally) the
  release tag. The top-level `CMakeLists.txt` also raises a
  configure-time `FATAL_ERROR` when the header and project versions
  disagree.
- Sanitizer integration: `scripts/run_sanitizer_checks.py` builds and
  runs `ztest_acvp_serial`, `ztest_primitive`, and `pqcp_bench_protocol`
  under ASan/UBSan on `native_sim/native/64`. Strict in CI
  (`CI=1`/`GITHUB_ACTIONS`/`PQCP_STRICT_SANITIZERS`), graceful locally
  on unsupported hosts.
- Native TLS selftest smoke coverage in PR CI, including a Linux-only
  sanitizer overlay path for the mbedTLS-backed TLS selftest.
- QEMU baseline coverage for ML-KEM-1024 and ML-DSA-44 so every
  ML-KEM and ML-DSA parameter set has a PQCP-vs-baseline primitive
  comparison path.
- A `release-dry-run.yml` workflow that exercises the full release
  pipeline on `main` without publishing a GitHub Release.
- A dedicated CI build lane for the `nucleo_h743zi` protocol benchmark
  sample, covering both ML-KEM-768+ML-DSA-65 and ML-KEM-512+ML-DSA-87
  build-only MCU configurations.
- A measured QEMU performance table in `README.md`, generated from real
  exporter output rather than hand-written or placeholder benchmark
  figures.
- `CONTRIBUTING.md` documenting benchmark regeneration, the single
  authoritative release gate, and IDE metadata policy.

### Changed

- `release_check.py` is now the single authoritative release gate, with
  a multi-step sequence: version consistency, cppcheck, strict extended
  checks, sanitizers, cost-of-assurance smoke, ACVP serial regression,
  KAT provenance, KAT build/run, benchmark CSV export,
  `--validate-only --verify-provenance`, MCU resource budgets, profile
  validation.
- The `release-gate` GitHub Actions job is blocking on `main` pushes,
  PRs targeting `main`, and tag pushes. `continue-on-error: true` was
  removed.
- `CONFIG_PQCP_ACVP_READLINE_TIMEOUT_MS` range narrowed to `100..60000`
  (previously `100..600000`), rejecting unusable upper values.
- Primitive benchmark timing records cycles and microseconds
  independently; `pqcp_bench_end_timing` returns raw hardware cycles,
  and `pqcp_bench_cycles_to_us` performs the explicit conversion.

### Security

- KAT provenance no longer depends on live network fetches during
  release validation; the release gate verifies checked-in vectors
  against vendored official NIST ACVP fixtures.
- Every FIPS 203 / FIPS 204 parameter set now has deterministic KAT
  coverage in CI, closing the previous correctness gap for
  ML-KEM-512/1024 and ML-DSA-44/87.
- PSA drivers can no longer write past output buffer bounds: output
  lengths are validated before any write or copy into caller-provided
  buffers.
- Unsupported PSA key types are rejected before any internal state is
  modified.
- ACVP serial interface recovers cleanly after garbage, oversized, or
  partial-timed-out frames and returns stable `ERROR:*` wire responses;
  the per-frame readline timeout is enforced in the shared ACVP line
  helper so sample users and library users share the same protection.

### Fixed

- The release pipeline now has a non-publishing dry-run path, so
  maintainers can validate the entire release workflow before any tag
  is pushed.
- Release-gate bulk-build matrices in `release.yml` and
  `release-dry-run.yml` are aligned; both include `tests/ztest_acvp_kat`.
- README links and example commands are portable, all absolute
  `/Users/...` paths have been replaced with repo-relative paths and
  environment-variable placeholders.
- Cost-of-assurance regression validation now fails clearly when a
  configured metric key does not exist in the generated benchmark CSV,
  preventing RTOS/TLS guardrail typos from silently passing.

## [0.9.0] - 2026-04-18

### Added

- Root `west.yml` for standalone `west init`, using Zephyr `v4.3.0` plus
   pinned `mlkem-native` and `mldsa-native` revisions that match the local
   bootstrap helper.
- Tag-triggered release workflow with `release_check.py` gating, JUnit upload,
   changelog extraction, build-log artifacts, and GitHub Release publication.
- Twister `testcase.yaml` manifests for all five ztest suites so downstream
  `west twister` pipelines can discover the module tests directly.
- A production-oriented PQCP provider family for ML-KEM and ML-DSA with RNG
   abstraction, PSA driver shims, deterministic KAT coverage, and stable
   `PQCP_METRIC` logging for primitive and protocol samples.
- A QEMU-only native-C baseline provider for ML-KEM-512/768 and ML-DSA-65/87,
   wired through the same Zephyr-facing APIs and shared RNG hooks for
   cost-of-assurance comparisons.
- A shared TLS self-test and protocol benchmark harness with RTOS-aware jitter
   counters, TLS layer-decomposition metrics, and a three-CSV
   cost-of-assurance pipeline for runnable QEMU slices plus build-only MCU
   footprint captures.
- ACVP serial bounded line validation, garbage and oversize frame rejection,
   partial-frame timeout handling, and recovery coverage in the host smoke
   driver and ztests.
- PSA ML-KEM driver hardening with early buffer validation, unsupported key
   type rejection, and specific `PSA_ERROR_*` status mapping.
- PSA ML-DSA driver hardening with entry-time parameter-set validation for
   ML-DSA-44/65/87, signature-size checks, and specific `PSA_ERROR_*` status
   mapping.
- `cppcheck` enforced in CI and in `scripts/release_check.py`, with the
   release gate exporting sanitized JUnit XML.
- Protocol-level PQCP vs baseline regression guardrails on QEMU for handshake
   latency, ROM/RAM footprint, and RTOS/TLS decomposition metrics.
- `nucleo_h743zi` build-only cost-of-assurance matrix entries for
   ML-KEM+ML-DSA protocol suites, including ROM/RAM reporting in the builds CSV.
- `scripts/release_check.py` as the one-command release gate, integrating
   strict extended checks, cost-of-assurance smoke, ACVP ztests, and
   budget-enforced profile validation.

### Security

- PSA drivers can no longer write past output buffer bounds because output
  lengths are validated before any write or copy into caller-provided buffers.
- Unsupported PSA key types are rejected before any internal state is modified.
- ACVP serial interface recovers cleanly after garbage, oversized, or
  partial-timed-out frames and returns stable `ERROR:*` wire responses.

### Fixed

- ANSI escape bytes and other control characters no longer corrupt
  `release_check_results.xml` when QEMU-driven release-gate output is captured.
