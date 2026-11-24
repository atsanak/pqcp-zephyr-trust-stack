# Security notes

See the [README](../README.md) for the project overview.

## Security Properties

### Cryptographic Correctness
- ML-KEM-512/768/1024 implemented per FIPS 203 (final)
- ML-DSA-44/65/87 implemented per FIPS 204 (final)
- NIST KAT vectors verified in CI ([`tests/ztest_acvp_kat`](../tests/ztest_acvp_kat))
- Baseline provider is QEMU-only; not a production path

### Side-Channel Posture
- The PQCP provider implementations are the `mlkem-native` and `mldsa-native` modules (see [`west.yml`](../west.yml) for pinned revisions). Consult those modules' documentation for their constant-time guarantees.
- The baseline provider makes no constant-time guarantees.

### PSA Driver Guarantees
- Output buffer bounds validated before any write
- Unsupported key types rejected before internal state mutation
- All error paths return specific `PSA_ERROR_*` codes

### Out of Scope for This Module
- Hardware RNG quality (depends on platform entropy source)
- TLS record-layer security (provided by mbedTLS)

## Security Considerations

### RNG Safety

**CRITICAL**: This module uses `sys_csrand_get()` for all cryptographic operations. This is the ONLY safe Zephyr RNG for cryptography. Never use `sys_rand_get()` or `sys_rand32_get()` for security-sensitive operations.

### Deterministic Mode

The `CONFIG_PQCP_RNG_DETERMINISTIC_TEST` option enables deterministic RNG for testing (KAT, ACVP). This MUST NEVER be enabled in production:

```
# WARNING: Test builds only!
CONFIG_PQCP_RNG_DETERMINISTIC_TEST=y
```

### Memory Considerations

PQC algorithms require significant stack space:

| Algorithm   | Stack (keygen) | Stack (sign/encaps) |
|-------------|----------------|---------------------|
| ML-KEM-768  | ~18 KB         | ~16 KB              |
| ML-KEM-1024 | ~24 KB         | ~20 KB              |
| ML-DSA-65   | ~86 KB         | ~80 KB              |
| ML-DSA-87   | ~100 KB        | ~95 KB              |

Configure adequate stack sizes:

```
CONFIG_MAIN_STACK_SIZE=131072  # 128KB for ML-DSA-65
```

### Stable API Surface

Headers intended for external application use and versioned dependency:

- `include/pqcp_zephyr/mlkem.h`: stable ML-KEM keypair / encapsulate / decapsulate API and size helpers.
- `include/pqcp_zephyr/mldsa.h`: stable ML-DSA sign / verify / hash / streaming API plus size helpers.
- `include/pqcp_zephyr/rng.h`: stable RNG abstraction hooks for Zephyr entropy, PSA RNG, or a caller-supplied RNG backend.
- `include/pqcp_zephyr/version.h`: stable version macros such as `PQCP_VERSION_STRING` for downstream integration and release pinning.

Headers that are intentionally more specialized and should be treated as
lab-oriented or internal-module surfaces unless you own both sides of the
integration:

- `include/pqcp_zephyr/acvp_cmd.h`: stable wire grammar for the serial ACVP harness, but still a lab/test command API rather than a production transport interface.
- `include/pqcp_zephyr/bench.h`: structured `PQCP_METRIC` logging helpers used by samples, profiling, and thesis-style analysis flows.
- `include/pqcp_zephyr/tls_selftest.h`: reusable TLS self-test helpers shared by the offline TLS sample and ztests; suitable for harness integration, but still primarily a validation surface rather than a general-purpose application API.

If you change a stable header, public Kconfig option, or production profile
meaning, update this README, the affected samples/tests, and the relevant
cost-of-assurance or resource-budget documentation in the same change.

### Release Checklist / v1.0 Criteria

Before tagging a release, we should be able to say all of the following are
true:

- `MCU_MINIMAL` and `GATEWAY` still match the documented production-supported
  profile intent, while `NATIVE_LAB`, ACVP helpers, and the QEMU-only
  `baseline` provider remain lab/analysis-only.
- The stable external API surface is still limited to
  `include/pqcp_zephyr/mlkem.h`, `include/pqcp_zephyr/mldsa.h`,
  `include/pqcp_zephyr/rng.h`, and `include/pqcp_zephyr/version.h`, with any
  change shipped alongside updated samples, tests, and README guidance.
- Fast CI passes, including the existing ztests, ACVP/QEMU smokes, and the
  profile-validation budget checks.
- `python scripts/run_extended_checks.py --strict` passes, including the
  focused static-analysis and release-metadata checks.
- `python scripts/run_extended_checks.py --strict --run-cost-of-assurance-smoke`
  passes, proving that the PQCP-vs-baseline QEMU comparison slice still builds,
  summarizes, and stays within the conservative regression guardrails.
- `python scripts/release_check.py` passes before tagging, so the strict
  extended checks, cost-of-assurance smoke, ACVP ztest run, and budget-enforced
  profile validation have all been exercised in one repeatable sequence.
- The baseline provider is still clearly documented as QEMU-only and
  benchmarking-only. It is never a supported production provider and must not
  be used to justify deterministic RNG or MCU-only shortcuts in production
  firmware.
