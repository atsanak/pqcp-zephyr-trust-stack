# PQCP Zephyr Public API Overview

The stable consumer-facing API is the header set under `include/pqcp_zephyr/`.
Downstream applications should include these headers directly instead of using
symbols from `src/`.

## Stable Production Headers

These headers are tagged as stable in their file-level comments. Downstream
applications may rely on their symbol names and buffer-size contracts across
the 1.0.x line unless a future changelog explicitly announces a breaking
change.

- `mlkem.h`: ML-KEM key generation, encapsulation, decapsulation, and size
  helpers for FIPS 203 parameter sets 512, 768, and 1024.
- `mldsa.h`: ML-DSA key generation, pure signing, verification, hash-helper,
  and streaming helper entry points for FIPS 204 parameter sets 44, 65, and 87.
- `rng.h`: RNG registration and byte-generation hooks. Production builds should
  use Zephyr entropy, PSA RNG, or a platform-reviewed custom RNG.
- `version.h`: compile-time version macros for downstream manifest pinning and
  compatibility checks.

## Validation And Analysis Headers

These headers are stable for validation, test, benchmark, or host-integration
workflows. They are not general-purpose production transport or TLS session
APIs unless explicitly documented by the header.

- `acvp_cmd.h`: lab/test-oriented ACVP command parser, formatter, and serial
  line-state helpers. The wire grammar is stable, but this is not a production
  transport protocol.
- `assurance.h`: firmware-side assurance manifest validation and stable
  `PQCP_ASSURANCE_*` / `PQCP_DEVICE_EVIDENCE` marker emission. This is a
  device-evidence reporting API, not a cryptographic attestation or signing
  protocol.
- `provider.h`: firmware-side provider contract reporting. It exposes the
  compiled provider family, native implementation source, backend selector, and
  external-provider policy for release transcript binding.
- `build_manifest.h`: firmware-side build manifest reporting. It exposes the
  PQCP version, Zephyr version, board, enabled algorithm-level masks, active
  profile flags, RNG mode, and provider-contract availability.
- `evidence_session.h`: firmware-side evidence-session reporting. It wraps
  build manifest, provider contract, assurance status, and device-evidence
  markers with begin/event/end records so transcript replay can detect missing,
  failed, or duplicate evidence markers.
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

## Use-case groupings

The following groupings describe the typical consumer paths through the
public headers. Refer to the doxygen reference under `docs/html/` for
exact signatures and parameter contracts; this section answers
"which functions do I call to accomplish *X*".

### Performing an ML-KEM key encapsulation (`mlkem.h`)

1. Pick a parameter set: ML-KEM-512, ML-KEM-768, or ML-KEM-1024.
2. Use the matching `pqcp_mlkem_<level>_*_size` helpers (or
   `*_SIZE_MAX` macros) to allocate caller-owned output buffers for the
   public key, secret key, ciphertext, and shared secret.
3. Call `pqcp_mlkem_<level>_keygen()` on the receiving side, then
   `pqcp_mlkem_<level>_encaps()` on the initiating side, then
   `pqcp_mlkem_<level>_decaps()` on the receiving side.
4. Zeroize secret-key and shared-secret buffers when no longer needed.

### Performing an ML-DSA detached signature (`mldsa.h`)

1. Pick a parameter set: ML-DSA-44, ML-DSA-65, or ML-DSA-87.
2. Allocate caller-owned buffers using the size helpers.
3. Call `pqcp_mldsa_<level>_keygen()`, then `pqcp_mldsa_<level>_sign()`
   for "pure" mode, or use the streaming API
   (`pqcp_mldsa_<level>_sign_stream_*`) when the message arrives in
   chunks. Verify with `pqcp_mldsa_<level>_verify()`.
4. The streaming API is non-reentrant: a single context object cannot
   be shared across threads.

### Selecting and seeding the RNG (`rng.h`)

- For production, register the Zephyr entropy or PSA RNG hook before
  using any `pqcp_*` keygen function.
- For deterministic test vectors (KAT-only paths), use the
  deterministic RNG and seed it with the documented test seed. These
  paths are explicitly *not* for production use.

### Running the ACVP validation harness (`acvp_cmd.h`)

1. Drive the ACVP serial wire grammar (`KEYGEN:MLKEM:768:...`,
   `ENCAPS:MLKEM:768:...`, etc.) through the receive loop in
   `acvp_validate_line()` / `pqcp_acvp_format_response_line()`.
2. The harness emits `OK:` for accepted commands and one of
   `ERROR:INVALID_CMD`, `ERROR:INVALID_HEX`, `ERROR:INVALID_LEVEL`,
   `ERROR:WRONG_SIZE`, `ERROR:MISSING_ARGS`, or `ERROR:TIMEOUT` for
   rejected ones. The wire format is stable and is part of the public
   contract.
3. Negative scenarios live in
   [`scripts/acvp_negative_scenarios.json`](../scripts/acvp_negative_scenarios.json)
   and are exercised by `tests/ztest_acvp_serial`.

### Emitting and consuming benchmark metrics (`bench.h`)

- Sample code emits `PQCP_METRIC,...` lines on stdout. The format and
  column ordering are part of the public contract — `parse_logs.py`,
  `export_results.py`, and the cost-of-assurance regression suite all
  depend on it.
- New benchmarks should reuse the existing emission helpers rather than
  inventing their own format string.

### Reporting firmware-visible assurance evidence (`assurance.h`)

- Release tooling can generate a digest manifest header for
  `samples/pqcp_assurance_status`. Firmware code maps that generated data into
  `struct pqcp_assurance_manifest`.
- Call `pqcp_assurance_manifest_validate()` before reporting evidence. It
  rejects malformed root hashes, artifact hashes, empty versions, missing
  artifact names, and zero schema versions.
- Call `pqcp_assurance_emit_status()` and
  `pqcp_assurance_emit_device_evidence()` to print the stable markers consumed
  by release-pack replay tools. These helpers bind firmware output to an
  already-generated hash manifest; they do not sign evidence or prove hardware
  identity.

### Reporting provider contract evidence (`provider.h`)

- Call `pqcp_provider_contract_get()` to inspect the build-time provider
  contract compiled into the firmware image.
- Call `pqcp_provider_contract_validate()` before consuming or reporting the
  contract. Enabled ML-KEM must report `mlkem-native`; enabled ML-DSA must
  report `mldsa-native`; external providers are not allowed for those native
  families.
- Call `pqcp_provider_emit_contract()` to emit a stable
  `PQCP_PROVIDER_CONTRACT` marker that release tooling can bind into QEMU or
  device transcripts.

### Reporting build manifest evidence (`build_manifest.h`)

- Call `pqcp_build_manifest_get()` to inspect firmware-visible build facts
  derived from Kconfig and Zephyr build metadata.
- Call `pqcp_build_manifest_validate()` before consuming a manifest. It rejects
  empty version/board/RNG fields and unknown profile or algorithm-level bits.
- Call `pqcp_build_manifest_emit()` to emit the stable
  `PQCP_BUILD_MANIFEST` marker consumed by release evidence transcripts.

### Checking transcript completeness (`evidence_session.h`)

- Call `pqcp_evidence_session_begin()` with the high-level evidence markers a
  firmware sample must emit, such as build manifest, provider contract,
  assurance status, and device evidence.
- After each evidence helper returns, call `pqcp_evidence_session_record()` with
  the matching event bit and return code. The session rejects duplicate events
  and records failed helper calls.
- Call `pqcp_evidence_session_end()` before reporting success. It emits a
  `PQCP_EVIDENCE_SESSION_END` marker that includes required, observed, failed,
  and missing event masks for transcript replay.

### Running the offline TLS / PSA self-test (`tls_selftest.h`)

- Used by samples, ztests, and the cost-of-assurance smoke. Starts up
  the PSA driver, performs an offline ML-KEM + ML-DSA handshake, and
  emits a `PQCP_METRIC,handshake,...` line. Not a general TLS session
  API: the entry point exists to drive deterministic measurement
  flows.

### Pinning a downstream consumer (`version.h`)

- `PQCP_VERSION_STRING` is the authoritative semver. `west.yml`,
  `CMakeLists.txt`, and `CHANGELOG.md` are kept in lock-step by
  `scripts/check_version_consistency.py`. Downstream Zephyr modules
  should compare against `PQCP_VERSION_STRING` rather than against
  individual symbols.
