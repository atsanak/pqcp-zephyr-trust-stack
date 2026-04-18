# CLAUDE.md — pqcp-zephyr-trust-stack session memory

> Auto-managed context for AI coding sessions.
> Last updated: 2026-04-18 by Codex.
> HEAD: c0b865a (main)

---

## Project identity

Zephyr RTOS module providing Post-Quantum Cryptography (PQC) primitives
(ML-KEM, ML-DSA) via a layered stack: PSA Crypto / mbedTLS provider →
protocol benchmark → ACVP serial test harness → TLS self-test.
Target: embedded MCUs (primary: nucleo_h743zi class) + QEMU for CI.
Version: 0.9.0 released. Goal: land the remaining CI, KAT, and robustness
work needed for a production `v1.0.0`.

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
  ztest_acvp_kat/    ← ML-KEM-768 + ML-DSA-65 NIST ACVP smoke vectors
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

## Completed — verified HEAD c0b865a

Infrastructure:
- west.yml: repo-root manifest for standalone `west init -m`
- west.yml: pinned SHAs for mlkem-native + mldsa-native
- zephyr/module.yml: minimal west external module registration
- cmake/pqcp_local_module.cmake: local in-tree development bootstrap
- All CMakeLists.txt updated for local bootstrap
- .github/workflows/release.yml: tag ref bootstrap fixed, workflow_dispatch ref
  input added, and changelog extraction now follows the versioned tag section
- CHANGELOG.md: `0.9.0` release notes populated, fresh empty `Unreleased` block added
- samples/pqcp_serial_acvp/README.md + samples/pqcp_tls_mbedtls_psa/README.md:
  standalone sample docs with real build/run output
   - scripts/verify_kat_provenance.py: 248 lines, downloads NIST ACVP JSON,
    verifies kat_vectors.h hex values (replaces runtime download with
    vendored nist_vectors/ in next session) (c0b865a)
  - ci(twister): west twister --build-only job in ci.yml (1eca7e5)
  - docs(roadmap): v1.0.0 planned items in CHANGELOG + README (8449a2c)
  - fix(ci): cppcheck flags aligned between release gate and strict checks,
    release pipeline green end-to-end (a2a55b2 + bd77abd + 1019dce + 41ee9c4)
  - v0.9.0 GitHub Release published successfully


Implementations:
- src/tls_selftest.c: 11KB, real PSA init + mbedTLS handshake + metric logging
- src/acvp_cmd.c: 26KB, garbage/timeout/recovery hardened, bounded line validator
- src/psa_mlkem_driver.c + src/psa_mldsa_driver.c: PSA drivers, error paths hardened
- src/bench_protocol.c: 16KB protocol benchmark with RTOS metric emission
- tests/ztest_acvp_kat/: ML-KEM-768 keygen/encaps and ML-DSA-65 sign/verify
  smoke using official NIST ACVP vectors, wired into `release_check.py`
- fix(ci): align cppcheck flags in release_check.py with run_extended_checks.py (a2a55b2)
- ci(twister): add west twister --build-only discovery job to ci.yml (1eca7e5)
- test(kat): add NIST provenance verifier script (live download, 768/65 only) (c0b865a)
- docs(roadmap): populate v1.0.0 milestone in CHANGELOG + README + CLAUDE (8449a2c)
- v0.9.0 GitHub Release published (pipeline required 3 repair commits after tag)
- KNOWN: scripts/release_check.py benchmark_csv step is BROKEN on remote main
  (calls export_results.py which does not exist on remote) — fix is Task 0


CI/Tooling:
- JUnit XML from release_check.py, artifact upload in ci.yml
- cost_of_assurance_matrix.json: nucleo_h743zi build-only protocol entries
- Regression guardrails: ratio checks + RTOS/TLS decomposition, all intact
- Tag-triggered release.yml: release artifacts on v* tags
- Twister testcase.yaml files: all ztest suites discoverable by west twister
- cppcheck enforced in CI (no --skip-cppcheck)
- .github/workflows/release.yml: tag v* → gate → GitHub Release (7661a25)
- scripts/extract_changelog_section.py: [Unreleased] extractor (7661a25)
- tests/ztest_*/testcase.yaml: all five suites Twister-discoverable
- src/psa_mlkem_driver.c + psa_mldsa_driver.c: buffer pre-validated, specific
  PSA error codes, key type + parameter set rejected at entry (baf12b4)
- cppcheck enforced in CI and release gate, no --skip-cppcheck (bfe4fea)
- JUnit XML ANSI-sanitised, 11 named release-gate steps
- README.md: security properties section documenting correctness, side-channel
  posture, PSA guarantees, and out-of-scope boundaries
- .github/workflows/ci.yml: west Twister discovery job added for build-only
  test manifest validation on qemu_x86_64
- scripts/verify_kat_provenance.py: official ACVP JSON verifier for checked-in
  ML-KEM-768 and ML-DSA-65 KAT vectors
- release_check.py: cppcheck enforced within strict extended checks, plus
  `kat_provenance` and ACVP KAT build/run as named release steps

Version: 0.9.0 released. Next: confirm the published `v0.9.0` release
artifacts and close the remaining `v1.0.0` roadmap items.

## TASKS — v1.0.0 work

## TASKS — v1.0.0 publication-quality work

## TASKS — v1.0.0 publication-quality work

TASK 0 [BLOCKER]: Fix release gate — push scripts/export_results.py to main
  (release_check.py benchmark_csv step calls it but it doesn't exist on remote)

TASK 1: vendor NIST KAT vectors offline + expand to all FIPS 203/204 param sets
  (ML-KEM-512/768/1024, ML-DSA-44/65/87 in nist_vectors/ + kat_vectors.h + ztests)

TASK 2: scripts/export_results.py → results/benchmark_results.csv + summary.md
  (thin layer over existing matrix runner; --smoke flag for release gate)

TASK 3: verify/complete baseline coverage (mlkem_baseline.c 1024, mldsa_baseline.c 44)
  and corresponding runnable matrix entries in cost_of_assurance_matrix.json

TASK 4: README.md Performance table with real measured QEMU numbers from CSV export

TASK 5: release-dry-run.yml workflow → validate → tag v1.0.0 → update CHANGELOG

RULE: push to origin/main after every commit. Never end a session with local-only commits.
