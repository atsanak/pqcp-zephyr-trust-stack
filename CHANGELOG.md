# Changelog

All notable changes to this module are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
with entries grouped so downstream Zephyr integrators can quickly map a
release tag to the validation and provider surface it introduced.

## [Unreleased]

## [1.0.0] - 2026-04-18

### Added

- Vendored offline NIST ACVP fixtures for ML-KEM-512/768/1024 key generation
  and encapsulation plus ML-DSA-44/65/87 deterministic signing and
  verification, all under `tests/ztest_acvp_kat/nist_vectors/`.
- Expanded `tests/ztest_acvp_kat` coverage to all FIPS 203 / FIPS 204 parameter
  sets with 12 ZTEST cases and offline provenance verification via
  `scripts/verify_kat_provenance.py`.
- `scripts/export_results.py` for publication-ready benchmark extraction,
  generating `results/benchmark_results.csv` and
  `results/benchmark_summary.md` from the checked-in cost-of-assurance matrix.
- QEMU baseline coverage for ML-KEM-1024 and ML-DSA-44 so every ML-KEM and
  ML-DSA parameter set now has a PQCP-vs-baseline primitive comparison path.
- A `release-dry-run.yml` workflow that exercises the full release pipeline on
  `main` without publishing a GitHub Release.
- A dedicated CI build lane for the `nucleo_h743zi` protocol benchmark sample,
  covering both ML-KEM-768 + ML-DSA-65 and ML-KEM-512 + ML-DSA-87 build-only
  MCU configurations.
- A measured QEMU performance table in `README.md`, generated from real exporter
  output rather than hand-written or placeholder benchmark figures.

### Security

- KAT provenance no longer depends on live network fetches during release
  validation; the release gate now verifies checked-in vectors against vendored
  official NIST ACVP fixtures.
- Every FIPS 203 / FIPS 204 parameter set now has deterministic KAT coverage in
  CI, closing the previous correctness gap for ML-KEM-512/1024 and
  ML-DSA-44/87.

### Fixed

- The release pipeline now has a non-publishing dry-run path, so maintainers
  can validate the entire release workflow before any tag is pushed.

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
- A QEMU-only PQClean-derived baseline provider for ML-KEM-512/768 and
   ML-DSA-65/87, wired through the same Zephyr-facing APIs and shared RNG hooks
   for cost-of-assurance comparisons.
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
