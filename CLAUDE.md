# CLAUDE.md — pqcp-zephyr-trust-stack session memory

> Auto-managed context for AI coding sessions.
> Last updated: 2026-04-13 by review agent.
> HEAD: 7685546 (main)

---

## Project identity

Zephyr RTOS module providing Post-Quantum Cryptography (PQC) primitives
(ML-KEM, ML-DSA) via a layered stack: PSA Crypto / mbedTLS provider →
protocol benchmark → ACVP serial test harness → TLS self-test.
Target: embedded MCUs (primary: nucleo_h743zi class) + QEMU for CI.
Version: 0.9.0-pre1. Goal: ship 0.9.0 as a product-ready, reproducible,
externally consumable Zephyr module.

---

## Repo map (top-level)

CMakeLists.txt       ← top-level, module entry point
Kconfig              ← top-level, all CONFIG_PQCP_* symbols live here
west.yml             ← repo-root manifest (Zephyr v4.3.0 + pinned deps)
zephyr/              ← MISSING: needs module.yml (see Task 2)
include/pqcp_zephyr/ ← public stable API headers
  acvp_cmd.h         ← ACVP wire protocol, sizing constants, error codes
  tls_selftest.h     ← TLS/PSA/PQC selftest API (declared, needs impl)
  version.h          ← PQCP_VERSION = "0.9.0"
src/
  acvp_cmd.c         ← validate_line, timeout/reset, receive loop
  tls_selftest.c     ← INCOMPLETE — must implement 3 declared functions
samples/
  pqcp_serial_acvp/  ← k_msgq + k_timer ACVP harness, ERROR:TIMEOUT
  pqcp_bench_protocol/
  pqcp_tls_mbedtls_psa/
tests/
  ztest_acvp_serial/ ← garbage/oversize/timeout ztests (all passing)
  ztest_tls_selftest/
scripts/
  release_check.py
  run_extended_checks.py
  cost_of_assurance_matrix.json
  qemu_cost_of_assurance_regression.json
  acvp_negative_scenarios.json
  run_acvp_serial_session.py
.github/workflows/ci.yml
CHANGELOG.md

---

## Immutable contracts — NEVER break these

- acvp_cmd.h public symbols: ACVP_LINE_MAX_BYTES, all ACVP_MLKEM_* constants,
  acvp_validate_line(), pqcp_acvp_results_t, pqcp_acvp_format_response_line(),
  PQCP_ACVP_ERR_TIMEOUT, acvp_line_state_t. Do not change signatures.
- ACVP wire format: command names, OK:/ERROR: prefixes, hex encoding.
- PQCP_METRIC log record format (parsed by run_extended_checks.py).
- Regression JSON field names: handshake_latency_ratio, rom_ratio, ram_ratio.
- k_msgq + k_timer pattern in serial sample (Zephyr scheduling requirement).
- All existing CONFIG_PQCP_* Kconfig symbols: no renames, no removals.
- New C code: must compile -Wall -Wextra -Werror on ARM + x86 toolchains.

---

## Completed — verified HEAD 1c50d4f

Infrastructure:
- west.yml: pinned SHAs for mlkem-native + mldsa-native
- zephyr/module.yml: minimal west external module registration
- cmake/pqcp_local_module.cmake: local in-tree development bootstrap
- All CMakeLists.txt updated for local bootstrap

Implementations:
- src/tls_selftest.c: 11KB, real PSA init + mbedTLS handshake + metric logging
- src/acvp_cmd.c: 26KB, garbage/timeout/recovery hardened, bounded line validator
- src/psa_mlkem_driver.c + src/psa_mldsa_driver.c: PSA drivers, error paths hardened
- src/bench_protocol.c: 16KB protocol benchmark with RTOS metric emission

CI/Tooling:
- JUnit XML from release_check.py, artifact upload in ci.yml
- cost_of_assurance_matrix.json: nucleo_h743zi build-only protocol entries
- Regression guardrails: ratio checks + RTOS/TLS decomposition, all intact
- Tag-triggered release.yml: release artifacts on v* tags
- Twister testcase.yaml files: all ztest suites discoverable by west twister
- cppcheck enforced in CI (no --skip-cppcheck)

Version: 0.9.0-pre1. Next: bump CHANGELOG [Unreleased] → [0.9.0], tag v0.9.0.

## TASKS — none. Tag v0.9.0 when release_check.py exits 0.
