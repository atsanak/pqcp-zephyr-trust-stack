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
- `pqc_environment_result.json` — local replay result checking that west
  dependency pins, workflow Zephyr/SDK settings, release manifest dependencies,
  and CBOM dependency components agree.
- `pqc_assurance_digest.json` — stable SHA-256 digest manifest over the core
  passport artifacts. This is the future bridge to firmware/device attestation.
- `pqc_assurance_profile_result.json` — profile replay result that checks which
  assets are production-allowed, validation-only, test-only, or profile-scoped.
- `pqc_evidence_quality_result.json` — claim quality replay result that assigns
  every required claim to a validation class and execution environment.
- `pqc_migration_readiness.json` / `pqc_migration_readiness.md` — generated
  profile summary for partner review and maintenance planning.
- `ct_instruction_policy_result.json` — disassembly policy result checking
  ML-KEM decapsulation-related symbols for variable-latency division
  instructions.
- `pqc_claim_closure_result.json` — post-policy closure result proving that
  generated profile, evidence-quality, migration, attestation, digest, and
  firmware-digest artifacts still agree after the full Passport is assembled.
- `acvp_negative_scenario_floor_result.json` — proof that every compatibility
  floor ACVP negative scenario is still present, uniquely named, and still
  expects an `ERROR:*` or explicitly marked recovery response.
- `pqc_asset_trace_result.json` — verification that the PQC asset trace map
  resolves each crypto/validation/RNG asset to source files, Kconfig symbols,
  claims, ztests, transcript markers, and CBOM components.
- `pqc_evidence_graph.json` / `pqc_evidence_graph.md` — graph-form evidence
  showing asset-to-source, asset-to-test, asset-to-claim, asset-to-marker, and
  asset-to-CBOM relationships.
- `generated/pqcp_assurance_digest_generated.h` — a generated C header that
  carries the assurance digest root hash for future firmware attestation
  binding.

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
  --asset-trace-result /tmp/pqcp-passport/pqc_asset_trace_result.json \
  --evidence-graph /tmp/pqcp-passport/pqc_evidence_graph.json \
  --assurance-digest /tmp/pqcp-passport/pqc_assurance_digest.json \
  --firmware-digest-header /tmp/pqcp-passport/generated/pqcp_assurance_digest_generated.h \
  --assurance-profile-result /tmp/pqcp-passport/pqc_assurance_profile_result.json \
  --evidence-quality-result /tmp/pqcp-passport/pqc_evidence_quality_result.json \
  --migration-readiness-json /tmp/pqcp-passport/pqc_migration_readiness.json \
  --migration-readiness-md /tmp/pqcp-passport/pqc_migration_readiness.md \
  --ct-instruction-policy-result /tmp/pqcp-passport/ct_instruction_policy_result.json \
  --output /tmp/pqcp-passport/pqc_policy_result.json
```

Run the post-policy closure verifier directly:

```sh
python3 scripts/verify_pqc_claim_closure.py \
  --ledger /tmp/pqcp-passport/assurance_ledger.json \
  --attestation /tmp/pqcp-passport/pqc_attestation.intoto.json \
  --assurance-digest /tmp/pqcp-passport/pqc_assurance_digest.json \
  --policy-result /tmp/pqcp-passport/pqc_policy_result.json \
  --assurance-profile-result /tmp/pqcp-passport/pqc_assurance_profile_result.json \
  --evidence-quality-result /tmp/pqcp-passport/pqc_evidence_quality_result.json \
  --migration-readiness-json /tmp/pqcp-passport/pqc_migration_readiness.json \
  --migration-readiness-md /tmp/pqcp-passport/pqc_migration_readiness.md \
  --firmware-digest-header /tmp/pqcp-passport/generated/pqcp_assurance_digest_generated.h \
  --ct-instruction-policy-result /tmp/pqcp-passport/ct_instruction_policy_result.json \
  --output /tmp/pqcp-passport/pqc_claim_closure_result.json
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
- Do west.yml pins, workflow Zephyr/SDK settings, release manifest dependency
  revisions, and CBOM dependency components agree?
- Is deterministic RNG clearly marked as test-only rather than production
  usable?
- Can every crypto asset be traced back to concrete source files, Kconfig,
  tests, transcript markers, and assurance claims?
- Did the ACVP negative scenario set preserve the compatibility floor, including
  timeout recovery and post-timeout valid-command recovery?
- Which assets are production-allowed in each local profile, and which are
  explicitly limited to validation, lab, smoke, or test use?
- Does every required claim have a declared evidence class and execution
  environment?
- Do benchmark artifacts include distribution rows and build metadata in
  addition to the legacy single-value metrics?
- Does the ML-KEM decapsulation instruction-policy scan pass for the built
  CT-smoke ELF?
- Do post-ledger artifacts still close cleanly after policy replay, attestation
  generation, digest creation, and firmware digest export?

If any answer is inconsistent, `verify_release_evidence_pack.py` exits non-zero
and reports the exact file, claim, or artifact hash that failed.

## Non-Claims

- The attestation is unsigned. It is hash-bound, not identity-signed.
- The CBOM is CycloneDX-style and uses repo-specific `pqcp:*` properties where
  CycloneDX does not yet model an embedded PQC evidence link directly.
- The digest manifest is ready for future firmware embedding, but the current
  patch set only proves the digest compiles into firmware via
  `samples/pqcp_assurance_status`; it does not add device-side remote
  attestation.
- QEMU/local evidence does not prove side-channel behavior on physical silicon.
- The instruction-policy scan is a regression check for a narrow class of
  variable-latency arithmetic mistakes; it is not a substitute for
  implementation review or physical leakage testing.

## Performance And Side-Channel Evidence

See [`performance-methodology.md`](performance-methodology.md) for the benchmark
distribution rows, metadata rows, CT transcript markers, instruction-policy
scan, and optional hardware/reference-capture workflow.

## Negative Scenario Compatibility Floor

Passport v2 treats `scripts/acvp_negative_scenarios.json` as an append-only
compatibility surface. `scripts/acvp_negative_scenario_floor.json` records the
floor of existing scenario names and expected responses, and
`scripts/validate_acvp_negative_scenarios.py` fails if any floor scenario is
removed, renamed, duplicated, or weakened. New malformed-input cases should be
added on top of the floor, never substituted for it.

The current additive set includes odd-length hex, empty payload, lowercase
algorithm rejection, boundary-minus-one verify input, oversize verify input,
timeout partial frame, and a valid `HELP` command after timeout recovery.

## Asset Trace Map And Evidence Graph

`scripts/pqc_asset_trace_map.json` is the human-curated bridge between the CBOM
and the actual repository. It links assets such as `ML-KEM-768`,
`ML-DSA-65`, the ACVP serial harness, the TLS self-test path, RNG backends, the
boot KAT self-verify hook, and the constant-time smoke test to:

- source files;
- Kconfig symbols;
- assurance claim IDs;
- ztest directories;
- transcript markers;
- CBOM component names.

`scripts/verify_pqc_asset_trace_map.py` checks that those links resolve.
`scripts/generate_pqc_evidence_graph.py` then emits a JSON/Markdown graph over
the same links. The graph is intentionally review-oriented: it is not a formal
proof system, but it makes drift visible when a source file, claim ID, test path,
or CBOM component disappears.

## Assurance Profile And Evidence Quality

Passport schema v5 adds two policy inputs and one generated report:

- `scripts/pqc_assurance_profile.json` defines the local review profiles:
  `native_lab`, `qemu_release`, `mcu_minimal`, and `gateway`.
- `scripts/pqc_evidence_quality.json` maps each required claim to the
  validation class and environment that supports it.
- `scripts/generate_migration_readiness_report.py` turns the profile and
  quality replay results into `pqc_migration_readiness.json` and
  `pqc_migration_readiness.md`.

The profile verifier rejects stale CBOM profile properties, missing trace-map
assets, missing required claims, deterministic RNG in production-oriented
profiles, and test-only assets represented as production-capable.

`scripts/verify_pqc_claim_closure.py` is the final local replay check for the
assembled pack. It verifies post-ledger claims, policy result status, profile
and evidence-quality status, migration readiness Markdown coverage, firmware
digest header macros, and SHA-256 hashes in `pqc_assurance_digest.json`.
