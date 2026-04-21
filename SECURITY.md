# Security Policy

This document describes how to report security issues in
`pqcp-zephyr-trust-stack` and what we consider in-scope for a coordinated
disclosure. The stack implements NIST post-quantum primitives (FIPS 203
ML-KEM, FIPS 204 ML-DSA) for Zephyr via a PSA Crypto + mbedTLS provider
surface, so correctness and protocol-level issues are treated seriously.

## Supported versions

Only the most recent stable release line receives security fixes.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | Yes                |
| < 1.0   | No (development)   |

The `main` branch is considered the pre-release stream for the next
point release. Security fixes land on `main` first and are backported
to the supported release line when a patch release is cut.

## Reporting a vulnerability

Please report suspected vulnerabilities through GitHub's private
Security Advisories, **not** through a public issue or pull request:

  https://github.com/atsana01/pqcp-zephyr-trust-stack/security/advisories/new

When filing an advisory, please include:

- A short description of the issue and the affected component
  (for example: `psa_mlkem_driver`, `src/tls_selftest.c`,
  `tests/ztest_acvp_serial`).
- The version or commit SHA you tested against.
- Build flags and target board (for example: `native_sim/native/64`,
  `qemu_x86_64`, `nucleo_h743zi`, profile `pqcp`/`baseline`).
- A reproducer (test input, KAT vector, ACVP frame, or a pointer to a
  specific ztest) if you have one.
- Your assessment of impact and, if applicable, a proposed fix.

**Response SLA (best effort):**

- Acknowledgement: within 3 business days.
- Initial triage / severity classification: within 14 calendar days.
- Coordinated fix and public advisory: timeline agreed with the
  reporter based on severity, typically within 90 days.

If you require PGP-encrypted communication, mention this in the
advisory and we will provide a key out-of-band.

Please do **not** open a public GitHub issue or pull request for a
security vulnerability until a coordinated advisory has been published.

## Scope

### In scope

- Memory-safety issues (OOB reads/writes, use-after-free, integer
  overflow, uninitialized reads) in the PQCP module sources:
  `src/`, `include/pqcp_zephyr/`.
- Correctness issues in the ML-KEM and ML-DSA provider layer
  (`src/mlkem_*.c`, `src/mldsa_*.c`, `src/psa_mlkem_driver.c`,
  `src/psa_mldsa_driver.c`) that cause a genuine deviation from the
  FIPS 203 / FIPS 204 specifications, including KAT failures and
  known-ciphertext decapsulation errors.
- ACVP serial wire protocol issues in `src/acvp_cmd.c` and
  `samples/pqcp_serial_acvp` (frame parsing, timeout handling,
  recovery after garbage / oversize / partial frames).
- PSA Crypto driver boundary issues (unsupported key types accepted,
  output-buffer length validation gaps, `PSA_ERROR_*` status
  misrouting) in `src/psa_mlkem_driver.c` and `src/psa_mldsa_driver.c`.
- TLS self-test / cost-of-assurance metric accuracy as exposed through
  `src/tls_selftest.c`, `samples/pqcp_bench_protocol`, and the
  `PQCP_METRIC` record format consumed by
  `scripts/run_extended_checks.py`.
- Release-gate evasion: any path that causes `scripts/release_check.py`
  or `.github/workflows/ci.yml` / `release.yml` to silently pass a
  real regression.

### Out of scope

- Vulnerabilities in the Zephyr RTOS kernel, drivers, subsystems, or
  native_sim runtime. Please report these upstream to the Zephyr
  project: https://github.com/zephyrproject-rtos/zephyr/security.
- Vulnerabilities in mbedTLS, the Zephyr SDK, the host Python
  toolchain, or third-party modules vendored via `west.yml`
  (`mlkem-native`, `mldsa-native`, etc.). Please report these to the
  respective upstream projects.
- Host benchmark host output (`results/*.csv`,
  `results/*.md`). These files are regenerated artefacts and carry
  no integrity claim beyond the `benchmark_provenance.json`
  sidecar.

## Post-quantum specific note

`pqcp-zephyr-trust-stack` targets the finalised NIST PQC standards:

- FIPS 203 — ML-KEM at levels 512, 768, and 1024.
- FIPS 204 — ML-DSA at levels 44, 65, and 87.

Side-channel resistance (timing, power, EM) is **not** claimed for
`qemu_x86_64` or `native_sim/native/64` builds. These targets are
development and validation environments; the sanitizer and
cost-of-assurance gates run there purely for memory-safety, timing
decomposition, and functional regression detection.

The `MCU_MINIMAL` and `GATEWAY` profiles target hardware deployments
(for example `nucleo_h743zi` in build-only form today). Any production
adopter is expected to layer platform-specific hardening on top:
TrustZone or secure-boot isolation, storage for long-term ML-DSA
private keys, constant-time countermeasures beyond what is provided by
`mlkem-native` / `mldsa-native`, and a matching entropy source for
`rng_zephyr_entropy.c` or `rng_psa.c`. Please review those adapter
files before deploying.

If you believe a side-channel issue in the PQCP module itself
(independent of the platform layer) reveals key material or shared
secrets, treat it as in scope under "memory-safety issues" above.

## Credit

Reporters are credited in the relevant GitHub Security Advisory and,
for reports that result in a user-visible change, in `CHANGELOG.md`
under the release that contains the fix. If you prefer to remain
anonymous, please say so in the advisory.
