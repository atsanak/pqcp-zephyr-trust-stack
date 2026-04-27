# PQCP Zephyr Public API Overview

The stable consumer-facing API is the header set under `include/pqcp_zephyr/`.
Downstream applications should include these headers directly instead of using
symbols from `src/`.

## Stable Production Headers

- `mlkem.h`: ML-KEM key generation, encapsulation, decapsulation, and size
  helpers for FIPS 203 parameter sets 512, 768, and 1024.
- `mldsa.h`: ML-DSA key generation, pure signing, verification, hash-helper,
  and streaming helper entry points for FIPS 204 parameter sets 44, 65, and 87.
- `rng.h`: RNG registration and byte-generation hooks. Production builds should
  use Zephyr entropy, PSA RNG, or a platform-reviewed custom RNG.
- `version.h`: compile-time version macros for downstream manifest pinning and
  compatibility checks.

## Validation And Analysis Headers

- `acvp_cmd.h`: lab/test-oriented ACVP command parser, formatter, and serial
  line-state helpers. The wire grammar is stable, but this is not a production
  transport protocol.
- `bench.h`: benchmark result structures and stable `PQCP_METRIC` emission
  helpers used by samples, release tooling, and cost-of-assurance analysis.
- `tls_selftest.h`: offline TLS/PSA/PQCP self-test harness shared by samples,
  protocol benchmarks, and ztests. It is intended for validation and benchmark
  flows, not as a general TLS session API.

## Ownership And Lifetime Rules

All cryptographic buffers are caller-owned. Functions write into caller-provided
output buffers whose minimum sizes are documented by the matching size helpers
or `*_SIZE_MAX` macros. Secret-key, shared-secret, and signature buffers remain
owned by the caller after the function returns; production applications should
zeroize secret material when it is no longer needed.

Unless a function explicitly documents otherwise, calls are synchronous and do
not retain pointers to caller-provided buffers after returning.
