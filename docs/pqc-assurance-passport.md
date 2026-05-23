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
- `pqc_reference_values.json` / `pqc_reference_values_result.json` — replayable
  reference values and verifier output binding release metadata, artifact
  hashes, required claim IDs, CBOM component IDs, and the expected firmware
  digest root.
- `firmware_assurance_status_result.json` — verifier output for the
  `PQCP_ASSURANCE_STATUS` and `PQCP_ASSURANCE_ARTIFACT` lines emitted by
  `samples/pqcp_assurance_status`.
- `acvp_json_interop_result.json` /
  `acvp_json_transcript_manifest.json` — ACVP JSON vector translation evidence
  with per-test serial-command transcript hashes.
- `pqc_build_provenance.slsa.json` /
  `pqc_build_provenance_result.json` — unsigned in-toto Statement using a
  SLSA provenance predicate shape for local release inputs and byproducts.
- `ct_sample_analysis_result.json` — replay result for optional raw
  `PQCP_CT_SAMPLE` timing-smoke transcript markers.
- `backend_update_evaluation.json` — comparison-only review of pinned native
  backend metadata and optional upstream drift.
- `backend_contract_result.json` — release backend-contract result showing
  native backend pins, provider-policy scan coverage, denied references, and
  the allowed external-provider scope.
- `liboqs_non_native_inventory.json` — experimental external-provider inventory
  for schemes outside the native provider families. It is inventory and policy
  evidence, not a production default.
- `provider_scope_result.json` — replay result checking that CBOM provider
  metadata agrees with the backend contract and external-provider inventory.
- `benchmark_campaign_result.json` /
  `benchmark_campaign_verify_result.json` — benchmark campaign statistics and
  replay result.
- `paper_comparison_campaign.csv` /
  `paper_comparison_campaign.json` — normalized benchmark export with explicit
  source, platform, clock, compiler, statistic, backend, and transcript-hash
  metadata for comparison workflows.
- `ct_campaign_result.json` — replay result over the CT sample manifest.
- `acvp_json_schema_result.json` — ACVP JSON operation-coverage replay result.
- `device_evidence_token.json` /
  `device_evidence_token_result.json` — firmware device-evidence marker and
  replay result.
- `pqc_appraisal_evidence.json` /
  `pqc_appraisal_result.json` — mode-specific evidence appraisal inputs and
  replay result.
- `release_reference_values_result.json` — replay result checking reference
  values against the release manifest, CBOM, backend contract, and provider
  scope.

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

Replay-check ACVP JSON interop artifacts directly:

```sh
python3 scripts/verify_acvp_json_interop.py \
  --result /tmp/pqcp-passport/acvp_json_interop_result.json \
  --transcript-manifest /tmp/pqcp-passport/acvp_json_transcript_manifest.json \
  --output /tmp/pqcp-passport/acvp_json_interop_verify_result.json
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
- Do the generated reference values match the ledger, CBOM, attestation,
  release manifest, policy result, profile result, transcript manifest, and
  firmware digest root?
- Does the assurance-status firmware sample report the expected digest and
  artifact count?
- Can ACVP JSON vector groups be mapped to the existing serial-command evidence
  vocabulary without changing the ACVP serial wire format?
- Does the SLSA-shaped build provenance statement replay-check its subjects,
  resolved dependencies, external parameters, and byproduct hashes?
- If raw CT sample capture is enabled, do valid/invalid ML-KEM decapsulation
  samples satisfy the configured smoke thresholds?

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

## Evidence Appraisal Layer

Passport schema v7 adds `pqc_appraisal_evidence.json` and
`pqc_appraisal_result.json`. They replay-check the post-Passport artifacts using
`scripts/pqc_appraisal_policy.json` in one of four modes: `ci_fast`,
`local_release`, `partner_review`, or `hardware_review`.

The full local release path uses `partner_review`. It requires backend update
evaluation, benchmark campaign replay, CT campaign replay, ACVP JSON schema
coverage, and device-evidence token replay to pass. The CI fast gate does not
generate these artifacts.

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

## Partner Review Scorecard

The full local release gate also emits `partner_review_scorecard.json`,
`partner_review_scorecard.md`, and `partner_review_scorecard_result.json`. This
is a derived review layer over the Passport: it does not introduce new evidence,
and it does not replace replay verification. It reads the ledger, CBOM,
policy/profile/quality results, backend-contract result, provider-scope result,
benchmark campaign, CT campaign, ACVP schema coverage, device-evidence result,
reference values, and appraisal result.

The scorecard converts those artifacts into a concise partner-review decision:

- `blocker`: a release artifact failed, a required claim failed, a forbidden
  provider path appeared, or a test-only asset was marked production-capable.
- `warning`: evidence is reviewable but incomplete for stronger claims, such as
  QEMU-only benchmark context when no physical hardware promotion has run.
- `score` and `readiness`: deterministic summary fields for triage. These are
  review aids, not certification claims.

Use the scorecard as the first file to read during partner review, then drill
into the referenced Passport artifacts for the underlying replay evidence.
`scripts/verify_partner_review_scorecard.py` recomputes the scorecard from the
underlying artifacts, checks the input artifact SHA-256 values, and confirms the
Markdown contains the same finding IDs.

## Tamper Drill

The full local release gate ends with `scripts/run_evidence_tamper_drill.py`.
This step copies the generated evidence pack into temporary workspaces, applies
small controlled corruptions, and verifies that replay checks reject each
mutated pack. The default policy covers benchmark CSV/provenance binding,
assurance digest artifact hashes, reference-value head binding, SLSA/in-toto
subject hashes, and partner scorecard artifact hashes.

The output, `evidence_tamper_drill_result.json`, is intentionally not a new
security claim. It is a verifier-quality check: it proves that the current pack
does not merely contain artifacts, but that important artifact relationships are
actively enforced by replay verification.
