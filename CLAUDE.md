# CLAUDE.md — pqcp-zephyr-trust-stack session memory

> Auto-managed context for AI coding sessions.
> Last updated: 2026-04-21 by Codex.
> HEAD: ed525589a8c1575beb375e8e99767209f0dd6a43 (main, 2026-04-18)

---

## Project identity

Zephyr RTOS module providing Post-Quantum Cryptography (PQC) primitives
(ML-KEM, ML-DSA) via a layered stack: PSA Crypto / mbedTLS provider →
protocol benchmark → ACVP serial test harness → TLS self-test.
Target: embedded MCUs (primary: nucleo_h743zi class) + QEMU for CI.
Version: 1.0.0 release track. Goal: land the remaining CI, KAT, hardening,
benchmark provenance, and robustness work needed for a production v1.0.0.

The end goal is a polished, robust, professional Zephyr-native PQC stack
that is product-ready, reproducible, release-safe, and novel enough to
stand out through stronger measurement semantics and provenance-aware
benchmarking.

The repository should not drift into a prototype or benchmark toy.
Every meaningful change should improve product readiness, engineering rigor,
or novelty.

---

## Repo map (top-level)

CMakeLists.txt       ← top-level, module entry point
Kconfig              ← top-level, all CONFIG_PQCP_* symbols live here
west.yml             ← repo-root manifest (Zephyr + pinned deps)
zephyr/module.yml    ← west external module registration
include/pqcp_zephyr/ ← public stable API headers
  acvp_cmd.h         ← ACVP wire protocol, sizing constants, error codes
  tls_selftest.h     ← TLS/PSA/PQC selftest API
  version.h          ← PQCP_VERSION
src/
  acvp_cmd.c         ← validate_line, timeout/reset, receive loop
  tls_selftest.c     ← PSA init + offline handshake + metric logging
  psa_mlkem_driver.c ← hardened PSA ML-KEM driver entry points
  psa_mldsa_driver.c ← hardened PSA ML-DSA driver entry points
  bench_primitive.c  ← primitive benchmark and metric emission
  bench_protocol.c   ← protocol benchmark with RTOS metric emission
samples/
  pqcp_serial_acvp/  ← k_msgq + k_timer ACVP harness, ERROR:TIMEOUT
  pqcp_bench_protocol/
  pqcp_tls_mbedtls_psa/
tests/
  ztest_acvp_serial/ ← garbage/oversize/timeout/recovery ztests
  ztest_acvp_kat/    ← ML-KEM-768 + ML-DSA-65 NIST ACVP smoke vectors
  ztest_tls_selftest/
  ztest_primitive/
  ztest_rng/
scripts/
  extract_changelog_section.py
  release_check.py
  run_extended_checks.py
  run_sanitizer_checks.py
  cost_of_assurance_matrix.json
  qemu_cost_of_assurance_regression.json
  resource_budgets.json
  acvp_negative_scenarios.json
  run_acvp_serial_session.py
  verify_kat_provenance.py
.github/workflows/ci.yml
.github/workflows/release.yml
.github/workflows/release-dry-run.yml
CHANGELOG.md
README.md
CLAUDE.md

---

## Immutable contracts — NEVER break these

- acvp_cmd.h public symbols: ACVP_LINE_MAX_BYTES, all ACVP_MLKEM_* constants,
  acvp_validate_line(), pqcp_acvp_results_t, pqcp_acvp_format_response_line(),
  PQCP_ACVP_ERR_TIMEOUT, acvp_line_state_t. Do not change signatures.
- ACVP wire format: command names, OK:/ERROR: prefixes, hex encoding.
- PQCP_METRIC log record format (parsed by run_extended_checks.py).
- Regression JSON field names used by the gate: handshake_latency_ratio,
  rom_ratio, ram_ratio, plus any explicitly added RTOS/TLS decomposition fields.
- k_msgq + k_timer pattern in the serial sample.
- All existing CONFIG_PQCP_* Kconfig symbols: no renames, no removals.
- New C code: must compile -Wall -Wextra -Werror on ARM + x86 toolchains.
- Benchmark semantics must remain layer-separated and provenance-aware.
- Any change to release checking must preserve the strong release gate behavior.

---

## Sprint — Product Readiness and Novelty

### Mission

Make this repository genuinely better as a product and as a benchmark platform:
- stronger Zephyr integration,
- cleaner and more honest measurement semantics,
- more realistic embedded and protocol coverage,
- tighter release discipline,
- stronger verification,
- at least one practical novelty improvement.

Novelty should come from better engineering, not from gimmicks.
Preferred novelty themes:
- provenance-aware benchmark metadata,
- clearer primitive vs protocol vs RTOS separation,
- stronger release artifact generation,
- better reproducibility and auditability,
- more useful resource and regression guardrails,
- layer-separated TLS/provider/transport accounting.

### Collaboration model

There are two agents:

1. **Opus 4.7**
   - Primary builder.
   - Implements changes.
   - Commits and pushes to GitHub under the `atsana01` profile.
   - Works in small, reviewable steps.
   - Must verify against the real repository state before coding.

2. **Composer**
   - Verification-first reviewer.
   - Does not build features first.
   - Fact-checks Opus line by line against the repo.
   - Challenges missing, weak, misleading, or overclaimed work.
   - Focuses on correctness, product readiness, and release trustworthiness.

Composer exists to prevent drift. Opus exists to move the repo forward.

### Output discipline for Opus

Opus must:
- inspect the actual repository before acting,
- use conventional commits,
- push completed work,
- report exact SHAs,
- explain what was verified versus what was improved,
- favor real fixes over broad but shallow churn.

### Output discipline for Composer

Composer must:
- verify claims directly in the repo,
- inspect exact files, functions, and diffs,
- confirm what is actually implemented,
- identify gaps and risks,
- say clearly when something is only partial or not present,
- push for stronger architecture and release safety.

---

## Verified state and key direction

The project is already moving in the right direction:
- QEMU cost-of-assurance exists for primitive + protocol level comparisons.
- ACVP rejection/recovery hardening exists.
- release_check.py exists as the main sequential gate.
- README and workflows already document release and benchmark behavior.
- The next step is to harden, verify, and improve trustworthiness and novelty.

Important project direction:
- This is not just a benchmark harness.
- This is not just a sample collection.
- This is intended to become a product-quality Zephyr PQC stack.

---

## Open defects and quality focus

Focus on fixing or strengthening, in priority order:
1. Benchmark truthfulness and provenance.
2. Release gate reliability and version consistency.
3. Embedded protocol footprint and resource budgets.
4. RTOS/TLS decomposition guardrails.
5. Sanitizer integration and hardening.
6. ACVP edge-case robustness.
7. Clearer README claims and validation-backed metrics.
8. A practical novelty improvement that makes the repo stand out.

Avoid:
- docs-only progress with no code value,
- fabricated or unverified numbers,
- hiding unsupported behavior behind silent passes,
- weakening strict checks,
- changing stable contracts without reason.

---

## TASKS — v1.0.0 publication-quality work

- [x] T1: Benchmark CSV smoke hardened
  - row count checks,
  - numeric / parse sanity on cycles, time_us, rom, ram,
  - PQCP/baseline time_us ratio bounds,
  - `export_results.py --validate-only` with header + data checks,
  - `parse_logs.py` consumes the new `us=` emitter.

- [x] T2: MCU protocol build-only entries
  - nucleo_h743zi coverage for both ML-KEM-768+ML-DSA-65 and ML-KEM-512+ML-DSA-87,
  - ROM/RAM extracted from `west build`'s size output,
  - resource budget enforcement via `scripts/resource_budgets.json`,
  - `scripts/check_resource_budgets.py` wired into release_check.py,
  - README section explaining the measured MCU protocol footprint.

- [x] T3: RTOS/TLS decomposition fields
  - `auth_time` and `key_exchange_time` regression thresholds added,
  - regression failures aggregated (no first-fail short-circuit),
  - cost-of-assurance smoke exercises the new decomposition limits.

- [x] T4: Sanitizer and hardening integration
  - `run_sanitizer_checks.py` wired into `release_check.py` and `release-dry-run.yml`,
  - extended coverage to `ztest_primitive` and `pqcp_bench_protocol`,
  - unsupported host is graceful locally but strict under CI / `PQCP_STRICT_SANITIZERS`.

- [x] T5: ACVP timeout and recovery coherence
  - readline stall / timeout behavior preserved,
  - `ERROR:TIMEOUT` semantics consistent across tests, Kconfig, docs,
  - backward-compatible `PQCP_ACVP_ERR_LINE_TIMEOUT` alias retained.

- [x] T6: Root manifest and consistency checks
  - `west.yml` at root,
  - `scripts/check_version_consistency.py` enforces version.h vs CMake vs optional tag,
  - release gate runs the consistency check as its first step.

- [x] T7: Novelty and differentiation
  - `benchmark_provenance.json` sidecar written next to every CSV,
  - records CSV sha256, git SHAs, host, toolchain, CI flag, and row-layer stats,
  - `--verify-provenance` gate in release_check.py and release-dry-run.yml,
  - documented in README as "Benchmark Provenance".

---

## Known blockers / watch list

- Any workflow that hardcodes release version strings is fragile.
- Any benchmark export path that can lose provenance or merge layers incorrectly is risky.
- Any release gate that does not validate all important outputs is too weak.
- Any metric that is logged but not enforced is only half-done.
- Any README performance table without CI-backed provenance should be treated cautiously.
- Any missing root west.yml or consistency check is a structural gap.
- Any local-only commit at the end of a session is unacceptable.

---

## Verification requirements

Before claiming a task is complete, verify it with the repo itself:
- exact file contents,
- exact line changes,
- exact build/test outputs,
- exact CI or release workflow logic.

Minimum validation expectations:
- python3 -m py_compile on changed scripts
- python3 scripts/run_extended_checks.py --strict
- python3 scripts/run_extended_checks.py --strict --run-cost-of-assurance-smoke

Use additional targeted checks for whatever files were touched.

---

## Release criteria

Before tagging v1.0.0:
- run scripts/release_check.py,
- all steps must print PASS,
- verify the version / changelog / tag alignment,
- verify benchmark and test artifacts are coherent,
- commit and push the final state to GitHub using atsana01.

---

## Final rule

Do not confuse motion with progress.
The repository should get harder to misuse, easier to trust, and more valuable as a real product.
