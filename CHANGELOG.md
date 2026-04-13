# Changelog

All notable changes to this module are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
with entries grouped so downstream Zephyr integrators can quickly map a
release tag to the validation and provider surface it introduced.

## [Unreleased]

### Changed

- Pinned `mlkem-native` and `mldsa-native` to reproducible commit SHAs in the
  root `west.yml` manifest and `ext/setup_libs.py` bootstrap helper.

### Migration Guide

- New `CONFIG_PQCP_*` symbols and defaults introduced on the 0.9.0 pre-release
  line:
  - `CONFIG_PQCP_IMPLEMENTATION_PQCP=y` by default via the provider-family
    choice; this remains the production-oriented implementation family.
  - `CONFIG_PQCP_IMPLEMENTATION_BASELINE=n` by default; this is the QEMU-only
    clean baseline provider used for cost-of-assurance comparisons.
  - `CONFIG_PQCP_BACKEND_CLEAN=n` by default; it is the metadata label paired
    with the baseline provider family.
  - `CONFIG_PQCP_TLS_SELFTEST=n` by default and `y` automatically under
    `CONFIG_PQCP_PROFILE_GATEWAY`.
  - `CONFIG_PQCP_BENCH_PROTOCOL_RTOS_METRICS=n` by default.
  - `CONFIG_PQCP_BENCH_PROTOCOL_RTOS_LOAD_PERIOD_MS=2` when the RTOS metric
    option is enabled.
  - `CONFIG_PQCP_BENCH_PROTOCOL_RTOS_LOAD_BUSY_WAIT_US=250` when the RTOS
    metric option is enabled.
  - `CONFIG_PQCP_ACVP_READLINE_TIMEOUT_MS=5000` when `CONFIG_PQCP_ACVP=y`.
- New public header symbols that downstream code may now encounter:
  - `include/pqcp_zephyr/version.h`: `PQCP_ZEPHYR_VERSION_MAJOR`,
    `PQCP_ZEPHYR_VERSION_MINOR`, `PQCP_ZEPHYR_VERSION_PATCH`,
    `PQCP_ZEPHYR_VERSION_HEX`, `PQCP_ZEPHYR_VERSION_STRING`, plus the
    backward-compatible `PQCP_VERSION_*` aliases.
  - `include/pqcp_zephyr/tls_selftest.h`:
    `pqcp_tls_selftest_config_t`, `pqcp_tls_selftest_report_t`,
    `PQCP_TLS_SELFTEST_CONFIG_DEFAULT`, `pqcp_tls_selftest_init_psa()`,
    `pqcp_tls_selftest_run()`, and `pqcp_tls_selftest_log_metrics()`.
  - `include/pqcp_zephyr/acvp_cmd.h`: `PQCP_ACVP_ERR_TIMEOUT`,
    `PQCP_ACVP_MAX_MESSAGE_BYTES`, the `PQCP_ACVP_MLKEM_*` and
    `PQCP_ACVP_MLDSA_*` request/response bound macros,
    `PQCP_ACVP_INPUT_BYTES_MAX`, `PQCP_ACVP_RESPONSE_BYTES_MAX`,
    `PQCP_ACVP_COMMAND_LINE_CHARS_MAX`, `struct pqcp_acvp_serial_line_state`,
    `pqcp_acvp_validate_command_line()`, `pqcp_acvp_serial_line_reset()`,
    `pqcp_acvp_serial_line_consume_char()`, and
    `pqcp_acvp_serial_line_timeout()`.
- ACVP wire-format additions remain backward-compatible:
  - The existing `ERROR:<code>` grammar is unchanged, but host/device flows may
    now emit `ERROR:TIMEOUT` when the serial ACVP sample drops a partial frame
    after `CONFIG_PQCP_ACVP_READLINE_TIMEOUT_MS` expires.

## [0.9.0] - 2026-04-13

### Added

- A production-oriented PQCP provider family for ML-KEM and ML-DSA together
  with RNG abstraction, PSA driver shims, deterministic KAT coverage, and the
  stable `PQCP_METRIC` logging surface used by the primitive and protocol
  samples.
- A QEMU-only clean baseline provider for ML-KEM-512/768 and ML-DSA-65/87 so
  cost-of-assurance runs can compare PQCP against a second implementation
  through the same Zephyr-facing APIs and shared RNG hooks.
- A shared TLS self-test / protocol benchmark harness with RTOS-aware jitter
  counters, TLS layer-decomposition metrics, and a three-CSV
  cost-of-assurance pipeline for runnable QEMU slices plus build-only MCU
  footprint captures.
- A reusable ACVP command library, serial ACVP sample, host-side smoke driver,
  negative scenario set, and ztest coverage for malformed commands, oversize
  frames, and partial-frame timeout recovery.
- `scripts/release_check.py` for one-command release validation, plus checked-in
  ROM/RAM resource budgets and QEMU cost-of-assurance regression thresholds.
- A root `west.yml` manifest so new users can bootstrap a Zephyr workspace
  directly from this repository.

### Changed

- Extended Checks now enforce resource budgets, version/changelog alignment,
  cost-of-assurance smoke coverage, and conservative PQCP-vs-baseline
  protocol/primitive regression guardrails on QEMU.
- The README now documents production profiles, stable API expectations,
  release criteria, west workspace setup, and the current pre-release version
  anchor for downstream consumers.
