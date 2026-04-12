# Changelog

All notable changes to this module are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
with entries grouped so downstream Zephyr integrators can quickly map a
release tag to the validation and provider surface it introduced.

## [Unreleased]

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
