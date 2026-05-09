# PQC Assurance Passport

The PQC Assurance Passport is the partner-review layer above the Assurance
Ledger. The ledger answers "which claims passed and which artifacts back them?"
The passport answers "can a reviewer verify the crypto inventory, build-style
attestation, policy result, and evidence hashes as one coherent package?"

It is intentionally local-first and unsigned in this version. It does not claim
FIPS 140-3 validation, formal constant-time proof, hardware attestation, or a
public certification. It is a replay-verifiable evidence pack for embedded PQC
release review.

## Generated Artifacts

`scripts/release_check.py --tag v1.0.0 --output-root <dir>` writes:

- `pqc_cbom.cdx.json` — CycloneDX 1.7-style cryptography BOM covering ML-KEM,
  ML-DSA, RNG backends, ACVP/TLS validation paths, Zephyr, Zephyr SDK,
  `mlkem-native`, and `mldsa-native`.
- `pqc_attestation.intoto.json` — unsigned in-toto Statement-style attestation
  binding ledger, CBOM, transcript manifest, benchmark provenance, release
  manifest, `west.yml`, and `CMakeLists.txt` hashes.
- `pqc_policy_result.json` — partner-review policy result that fails on missing
  required claims, missing crypto assets, stale hashes, inconsistent metadata,
  or deterministic RNG being represented as production-capable.
- `pqc_assurance_digest.json` — stable SHA-256 digest manifest over the core
  passport artifacts. This is the future bridge to firmware/device attestation.

## Local Commands

Generate the full release pack:

```sh
python3 scripts/release_check.py \
  --tag v1.0.0 \
  --output-root /tmp/pqcp-passport
```

Replay-check without rebuilding Zephyr or running QEMU:

```sh
python3 scripts/verify_release_evidence_pack.py \
  /tmp/pqcp-passport \
  --tag v1.0.0
```

Run the policy verifier directly:

```sh
python3 scripts/verify_assurance_policy.py \
  --policy scripts/pqc_assurance_policy.json \
  --ledger /tmp/pqcp-passport/assurance_ledger.json \
  --cbom /tmp/pqcp-passport/pqc_cbom.cdx.json \
  --attestation /tmp/pqcp-passport/pqc_attestation.intoto.json \
  --release-manifest /tmp/pqcp-passport/local_release_bundle/v1.0.0/release-manifest-v1.0.0.json \
  --output /tmp/pqcp-passport/pqc_policy_result.json
```

## Review Model

The passport is designed for a collaborator who receives a generated release
directory and wants deterministic answers to concrete questions:

- Which PQC algorithms and parameter sets are present?
- Which claims passed, failed, or were explicitly not applicable?
- Which NIST KAT, ACVP negative-path, sanitizer, benchmark, and
  cost-of-assurance artifacts support those claims?
- Do the ledger, CBOM, attestation, release manifest, and transcript hashes
  agree on version, tag, source commit, and dirty-tree state?
- Is deterministic RNG clearly marked as test-only rather than production
  usable?

If any answer is inconsistent, `verify_release_evidence_pack.py` exits non-zero
and reports the exact file, claim, or artifact hash that failed.

## Non-Claims

- The attestation is unsigned. It is hash-bound, not identity-signed.
- The CBOM is CycloneDX-style and uses repo-specific `pqcp:*` properties where
  CycloneDX does not yet model an embedded PQC evidence link directly.
- The digest manifest is ready for future firmware embedding, but the current
  patch set does not add device-side remote attestation.
- QEMU/local evidence does not prove side-channel behavior on physical silicon.
