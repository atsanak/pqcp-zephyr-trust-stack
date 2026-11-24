# Feature overview

Long form description of the module features. The short summary is in the top level README.


The module combines the following parts.

- **Signed audit delivery across subsystems.** Nine typed adapters project
  broker, fleet, edge and sovereign snapshots into one tenant-scoped event
  chain. The exporter supports ML-DSA-signed CBOR/CEF/OCSF batches, frozen
  retransmission and exact acknowledgements. QEMU tests exercise source
  tampering, tenant isolation and redaction. State is currently volatile;
  see [the protocol and trust boundaries](docs/sovereign-audit-export.md).
- **Claim-to-evidence assurance ledger.** Every release-relevant
  behaviour ("ML-DSA-65 KAT vectors match the header", "the ACVP
  harness rejects malformed input", "the benchmark CSV is bound to its
  provenance sidecar") is encoded as a typed claim in
  [`scripts/assurance_claims.json`](scripts/assurance_claims.json) with
  a dedicated evaluator. The release gate produces a JSON ledger
  ([`assurance_ledger.json`](docs/assurance-model.md)) and a
  self-contained HTML report that can be handed to a reviewer or
  attached to a paper. The ledger has a versioned schema with a
  documented backward-compatibility shim, old packs degrade
  gracefully instead of hard-failing.
- **PQC Assurance Passport for partner review.** The full local release
  gate now wraps the ledger with a CycloneDX-style cryptography BOM
  (`pqc_cbom.cdx.json`), an unsigned in-toto Statement-style evidence
  attestation (`pqc_attestation.intoto.json`), a partner policy result
  (`pqc_policy_result.json`), and a stable digest manifest
  (`pqc_assurance_digest.json`). Passport v2 also adds an append-only
  ACVP negative scenario floor, an asset trace map, an evidence graph,
  and a generated firmware digest header. This is not a certification
  claim; it is a replay-verifiable bridge between PQC inventory,
  release metadata, transcript hashes, and local validation evidence.
- **Offline KAT provenance binding.** The `tests/ztest_acvp_kat`
  vectors are vendored from NIST ACVP fixtures and pinned to
  `kat_vectors.h` constants by
  [`scripts/verify_kat_provenance.py`](scripts/verify_kat_provenance.py).
  Per-parameter-set claims (`kat.mlkem_512`, `kat.mlkem_768`,
  `kat.mlkem_1024`, `kat.mldsa_44`, `kat.mldsa_65`, `kat.mldsa_87`)
  decompose KAT verification so a regression in a single primitive is
  named directly in the failure reason rather than hidden in an
  aggregate.
- **QEMU-only local release gate with transcript-hash assurance.**
  [`scripts/release_check.py`](scripts/release_check.py) runs the
  entire validation sequence locally, no GitHub Actions required, 
  and captures stdout transcripts for every required step. Each
  transcript is SHA-256-hashed into
  `transcripts/evidence_transcript_manifest.json`. The replay verifier
  re-hashes every file and rejects the pack if any transcript is
  missing, empty, size-drifted, or hash-drifted. This makes the
  release pack tamper-evident.
- **ACVP serial validation on embedded Zephyr targets.** The serial
  wire format (`KEYGEN:MLKEM:768:...`, `ERROR:TIMEOUT`,
  `ERROR:INVALID_HEX`, `ERROR:WRONG_SIZE`) is exercised under
  `qemu_x86_64` ztests and bound to two assurance claims
  (`acvp.negative_path_rejection`, `acvp.timeout_recovery`) that
  require specific markers in the captured transcript. The same wire
  format runs unmodified on `nucleo_h743zi`-class hardware.
- **Executable runtime and exporter-bound protected channel.** The module
  includes allocation-free key/session governance, scheduling, checkpoints,
  recovery, multiplexing, flow control, rekeying, resumption, and path
  migration. Composite planners reconcile lifecycle, resource/recovery, path,
  and fault policy into one executable outcome. Optional generated catalogs
  add direct witnesses, two-step scenarios, authorization/continuity and
  epoch/stream guards, and eight-step transition traces without adding
  validation-only data to normal production builds. See
  [`docs/patch-set-20-runtime-channel.md`](docs/patch-set-20-runtime-channel.md).
- **Policy-bound multi-tenant crypto broker.** Principals receive bounded
  quotas, grants, and attenuable capabilities over opaque ML-KEM, ML-DSA,
  HKDF, HMAC, and AES-GCM key handles. The broker provides exact idempotency,
  cancellation, deadline and custody enforcement, chained execution receipts,
  and optional ML-DSA receipt signatures without exposing private key
  material.
- **Live PQC fleet trust fabric.** Factory ML-DSA identities authorize local
  operational-key generation, ownership vouchers, short-lived credentials,
  signed policy, revocation, key rotation, firmware authorization, and
  decommissioning. Its operations plane adds idempotent commands, deterministic
  device policy, firmware probation and rollback, tamper-evident audit,
  telemetry summaries, signed attestation, secure-time uncertainty, offline
  leases, exact revocations, health circuit breaking, admission control,
  correlated risk scoring, recovery evidence, and conflict-aware maintenance.
  Canonical CBOR artifacts are shared with an offline-first Rust coordinator
  that provides SQLite inventory, deterministic canaries, measured rollout
  decisions, signed revocation publication, a durable anti-replay sequence
  allocator, REST/SSE, and an operator CLI. See
  [`samples/pqcp_fleet_trust`](samples/pqcp_fleet_trust) and
  [`tools/pqcp_fleet_coordinator`](tools/pqcp_fleet_coordinator).

For the underlying architecture see
[`docs/assurance-model.md`](docs/assurance-model.md). For the Passport
artifact model see [`docs/pqc-assurance-passport.md`](docs/pqc-assurance-passport.md).
For the public C API surface see [`docs/api-overview.md`](docs/api-overview.md).

