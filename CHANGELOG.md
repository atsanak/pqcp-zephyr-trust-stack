# Changelog

All notable changes to this module are documented in this file.

The format is intentionally lightweight and geared toward downstream Zephyr
integrators who want a concise release-oriented summary of what changed.

## [1.0.0] - 2026-04-09

### Added

- Stable ML-KEM and ML-DSA wrapper APIs with selectable RNG backends for
  production, PSA-backed, custom, and deterministic test flows.
- Deterministic KAT coverage, streaming ML-DSA support, PSA driver shims, and
  ztest coverage for primitives, RNG backends, ACVP command handling, and the
  shared TLS self-test harness.
- Structured `PQCP_METRIC` logging across primitive, KAT, streaming, TLS, and
  protocol benchmark paths together with `scripts/parse_logs.py` and the
  curated `scripts/run_benchmarks.py` matrix runner.
- Shared TLS self-test / protocol benchmark helpers used by the TLS sample, the
  dedicated protocol benchmark sample, and the TLS ztests.
- Refactored ACVP command library with a stable `RESULT:*` / `ERROR:*` wire
  grammar, optional fuzz-oriented overlays, and a thin host-side ACVP smoke
  driver for lab integration.
- Weekly/manual extended checks with graphviz generation, focused `cppcheck`,
  optional sanitizer builds, and selective ARM-profile validation.

### Changed

- Profile validation now covers both primitive-oriented and protocol-oriented
  NATIVE_LAB paths while keeping MCU_MINIMAL conservative and GATEWAY aligned
  with PSA/TLS use cases.
- Documentation now includes a version header, changelog, extended checks,
  curated benchmark/profile cookbook guidance, and explicit Zephyr version
  validation notes.
