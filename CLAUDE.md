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

## Completed work (do not redo)

1bdd9e1 — Protocol QEMU cost-of-assurance (4 rows); ACVP garbage/oversize
           validator; negative scenario ztests.
2e5bc1d — Extended Checks broadened; tls_selftest.h declared; NATIVE_LAB
           primitive path; matrix updates.
7685546 — west.yml at root; CI release-gate job; CONFIG_PQCP_ACVP_READLINE_TIMEOUT_MS;
           partial-frame timeout + recovery; version.h 0.9.0; CHANGELOG started.

---

## Validation sequence (run after EVERY change, all 5 must exit 0)

python3 -m py_compile scripts/release_check.py \
  scripts/run_extended_checks.py \
  scripts/run_acvp_serial_session.py

python3 scripts/run_extended_checks.py \
  --skip-graphviz --skip-cppcheck --strict

python3 scripts/run_extended_checks.py \
  --strict --run-cost-of-assurance-smoke

west build -p always -b qemu_x86_64 \
  tests/ztest_acvp_serial && west build -d build -t run

python3 scripts/release_check.py

---

## TASKS — complete in order, one commit per task

### TASK 1 · Fix west.yml dependency pinning [BLOCKING]
mlkem-native and mldsa-native use revision: main — not reproducible.
1. Find latest stable commit SHA for each, compatible with Zephyr v4.3.0.
2. Replace both revision: main with the 40-char SHA.
3. Fresh workspace: west init -m . && west update -n zephyr mlkem-native mldsa-native && west manifest --resolve → must succeed.
4. Append to CHANGELOG.md [0.9.0-pre1]: "Pinned mlkem-native and mldsa-native to reproducible SHAs."
5. Run validation sequence.

### TASK 2 · Create zephyr/module.yml [BLOCKING]
Without this, downstream projects cannot use this repo as a Zephyr module.
1. Create zephyr/module.yml:
   build:
     cmake: .
     kconfig: Kconfig
2. Verify: build a trivial Zephyr app with this repo as a module and CONFIG_PQCP_ACVP=y.
3. Add "Module Integration" section to README.md explaining cmake/kconfig paths,
   how a consumer's west.yml should declare this repo, and required CONFIG_ symbols.
4. Run validation sequence.

### TASK 3 · Implement src/tls_selftest.c [BLOCKING]
tls_selftest.h declares 3 functions with no verified C implementation.
1. Read include/pqcp_zephyr/tls_selftest.h in full before writing any code.
2. Implement src/tls_selftest.c:
   - pqcp_tls_selftest_init_psa() → psa_crypto_init(), return PQCP_ERR_PSA_INIT on failure.
   - pqcp_tls_selftest_run() → offline ML-KEM + ML-DSA mbedTLS handshake, return typed result.
   - pqcp_tls_selftest_log_metrics() → emit PQCP_METRIC records for:
     handshake_cycles, kem_keygen_cycles, kem_encaps_cycles,
     sig_sign_cycles, sig_verify_cycles, peak_heap_bytes.
3. CMakeLists.txt: compile tls_selftest.c when CONFIG_PQCP_TLS_SELFTEST=y.
4. Kconfig: add CONFIG_PQCP_TLS_SELFTEST with depends on PQCP_MBEDTLS_PSA.
5. Wire tests/ztest_tls_selftest to build with CONFIG_PQCP_TLS_SELFTEST=y.
6. west build -p always -b qemu_x86_64 tests/ztest_tls_selftest && west build -d build -t run → all pass.
7. Run validation sequence.

### TASK 4 · MCU protocol build-only entries [IMPORTANT]
No evidence that protocol suites compile for a real MCU.
1. Find MCU board name in scripts/resource_budgets.json.
2. Add two build-only entries to cost_of_assurance_matrix.json:
   { "suite": "ML-KEM-768+ML-DSA-65", "board": "<board>", "impl": "pqcp", "run": false, "build": true }
   { "suite": "ML-KEM-512+ML-DSA-87", "board": "<board>", "impl": "pqcp", "run": false, "build": true }
3. Wire into release_check.py as a west build --cmake-only step.
4. Add "MCU Protocol Footprint" subsection to README.md with ROM/RAM numbers and build command.
5. Run validation sequence.

### TASK 5 · RTOS/TLS decomposition guardrails [IMPORTANT]
RTOS_JITTER_US, TLS_PROVIDER_CYCLES, TLS_TRANSPORT_CYCLES emitted to CSV but not checked.
1. Read cost_of_assurance_protocols.csv — confirm exact column headers.
2. Add absolute threshold entries for those 3 fields to qemu_cost_of_assurance_regression.json.
3. Extend regression loop in run_extended_checks.py to enforce them.
4. Document under README "Cost-of-Assurance Regression".
5. python3 scripts/run_extended_checks.py --strict --run-cost-of-assurance-smoke → must pass.

### TASK 6 · Polish for 0.9.0 release [REQUIRED BEFORE TAG]

6a — Kconfig guard:
Add depends on PQCP_SERIAL_ACVP (or correct parent) to
CONFIG_PQCP_ACVP_READLINE_TIMEOUT_MS.

6b — CI structured artifacts:
- release_check.py must write release_check_results.xml (JUnit, one testcase per step).
- ci.yml release-gate job: upload release_check_results.xml as artifact,
  add mikepenz/action-junit-report@v4 step.

6c — CHANGELOG Migration Guide:
Under [Unreleased] add "Migration Guide" listing:
- All new CONFIG_PQCP_* symbols with defaults
- All new public header symbols
- Any ACVP wire-format additions

---

## Definition of done for 0.9.0

- [ ] Tasks 1–6 complete
- [ ] python3 scripts/release_check.py exits 0, all steps PASS
- [ ] west manifest --resolve resolves to pinned SHAs
- [ ] zephyr/module.yml present and validated
- [ ] TLS selftest ztests pass on qemu_x86_64
- [ ] MCU protocol-level build succeeds
- [ ] CHANGELOG.md has complete Migration Guide
- [ ] CI release-gate uploads JUnit artifact
