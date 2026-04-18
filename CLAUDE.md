# CLAUDE.md — pqcp-zephyr-trust-stack session memory

> Auto-managed context for AI coding sessions.
> Last updated: 2026-04-18 by Codex.
> HEAD: b6a71f6 (main)

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
zephyr/module.yml    ← west external module registration
include/pqcp_zephyr/ ← public stable API headers
  acvp_cmd.h         ← ACVP wire protocol, sizing constants, error codes
  tls_selftest.h     ← TLS/PSA/PQC selftest API (implemented in src/tls_selftest.c)
  version.h          ← PQCP_VERSION = "0.9.0"
src/
  acvp_cmd.c         ← validate_line, timeout/reset, receive loop
  tls_selftest.c     ← implemented PSA init + offline handshake + metric logging
  psa_mlkem_driver.c ← hardened PSA ML-KEM driver entry points
  psa_mldsa_driver.c ← hardened PSA ML-DSA driver entry points
samples/
  pqcp_serial_acvp/  ← k_msgq + k_timer ACVP harness, ERROR:TIMEOUT
  pqcp_bench_protocol/
  pqcp_tls_mbedtls_psa/
tests/
  ztest_acvp_serial/ ← garbage/oversize/timeout ztests (all passing)
  ztest_acvp_kat/    ← ML-KEM-768 + ML-DSA-65 deterministic smoke vectors
  ztest_tls_selftest/
  ztest_primitive/
  ztest_rng/
scripts/
  extract_changelog_section.py
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

## Completed — verified HEAD b6a71f6

Infrastructure:
- west.yml: repo-root manifest for standalone `west init -m`
- west.yml: pinned SHAs for mlkem-native + mldsa-native
- zephyr/module.yml: minimal west external module registration
- cmake/pqcp_local_module.cmake: local in-tree development bootstrap
- All CMakeLists.txt updated for local bootstrap
- CHANGELOG.md: `0.9.0` release notes populated, fresh empty `Unreleased` block added
- samples/pqcp_serial_acvp/README.md + samples/pqcp_tls_mbedtls_psa/README.md:
  standalone sample docs with real build/run output

Implementations:
- src/tls_selftest.c: 11KB, real PSA init + mbedTLS handshake + metric logging
- src/acvp_cmd.c: 26KB, garbage/timeout/recovery hardened, bounded line validator
- src/psa_mlkem_driver.c + src/psa_mldsa_driver.c: PSA drivers, error paths hardened
- src/bench_protocol.c: 16KB protocol benchmark with RTOS metric emission
- tests/ztest_acvp_kat/: deterministic ML-KEM-768 + ML-DSA-65 KAT smoke using
  upstream vector material, wired into `release_check.py`

CI/Tooling:
- JUnit XML from release_check.py, artifact upload in ci.yml
- cost_of_assurance_matrix.json: nucleo_h743zi build-only protocol entries
- Regression guardrails: ratio checks + RTOS/TLS decomposition, all intact
- Tag-triggered release.yml: release artifacts on v* tags
- Twister testcase.yaml files: all ztest suites discoverable by west twister
- cppcheck enforced in CI (no --skip-cppcheck)
- .github/workflows/release.yml: tag v* → gate → GitHub Release (7661a25)
- scripts/extract_changelog_section.py: [Unreleased] extractor (7661a25)
- tests/ztest_*/testcase.yaml: all four suites Twister-discoverable (185067b)
- src/psa_mlkem_driver.c + psa_mldsa_driver.c: buffer pre-validated, specific
  PSA error codes, key type + parameter set rejected at entry (baf12b4)
- cppcheck enforced in CI and release gate, no --skip-cppcheck (bfe4fea)
- JUnit XML ANSI-sanitised, 9 named release-gate steps (bfe4fea)
- README.md: security properties section documenting correctness, side-channel
  posture, PSA guarantees, and out-of-scope boundaries
- release_check.py: ACVP KAT build/run added as named release step

Version: 0.9.0-pre1. Next: run `release_check.py`, tag `v0.9.0`, and verify
the tag-triggered GitHub Release workflow publishes artifacts successfully.

## TASKS — next session

1. Tag `v0.9.0` from a clean main branch once `python3 scripts/release_check.py`
   exits 0.
2. Push the tag and confirm `.github/workflows/release.yml` creates the GitHub
   Release with the changelog-derived body and uploaded artifacts.
