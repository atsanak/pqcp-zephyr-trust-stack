# Assurance Model

This document describes the architecture of the assurance subsystem that
backs every local release of `pqcp-zephyr-trust-stack`. It is intended as
a short technical reference for maintainers, reviewers, and integrators
who want to understand exactly what evidence the project produces, how
that evidence is bound to source artifacts, and how to verify a release
pack later without rerunning Zephyr or QEMU.

## Goals

- **Auditability.** Every release-relevant claim ("the benchmark CSV is
  valid", "the ACVP harness rejects malformed input", "the ML-DSA-65 KAT
  vectors match the header") has an explicit identifier, an evaluator,
  and a list of evidence artifacts with recorded SHA-256 hashes.
- **Replayability.** A maintainer who hands an evidence pack to a
  reviewer, or who comes back to it months later, can run a single
  command to re-verify the pack without rebuilding any binaries.
- **Local-first.** None of this depends on GitHub Actions. The release
  gate, the assurance ledger, and the replay verifier all run on a
  developer's workstation against a working Zephyr SDK.

## Components

```
            ┌────────────────────────┐
            │   release_check.py     │  authoritative release gate
            │   (sequential steps)   │  writes JUnit + transcripts
            └─────────┬──────────────┘
                      │ generates
       ┌──────────────┼─────────────────────────────┐
       ▼              ▼                             ▼
 transcripts/   benchmark_results.csv     local_release_bundle/
   *.log        + benchmark_provenance       + release-manifest-*.json
   manifest     cost_of_assurance_evidence
                mcu_protocol_footprint/
                      │
                      ▼
            ┌────────────────────────────┐
            │ generate_assurance_ledger  │  reads claims catalog +
            │ (per-claim evaluators)     │  evidence, emits ledger
            └─────────┬──────────────────┘
                      ▼
              assurance_ledger.json   <── machine-readable
              assurance_ledger.md     <── human-readable
              assurance_report.html   <── self-contained, shareable
                      │
                      ▼
            ┌────────────────────────────┐
            │ verify_assurance_ledger    │  schema, claim coverage,
            │ verify_release_evidence_   │  artifact existence + sha256,
            │ pack                       │  HTML report, transcript
            └────────────────────────────┘     hashes
```

| Script | Role |
|--------|------|
| `scripts/local_workflow.py` | Shared helpers: west discovery, host-env scrubbing, marker-aware subprocess timeout. |
| `scripts/release_check.py` | Sequential release gate: builds, ACVP/KAT runs, benchmark CSV, cost-of-assurance, sanitizers, MCU footprint, release bundle, ledger generation, ledger verification, pack verification, HTML report. |
| `scripts/prepare_release_bundle.py` | Produces `release-manifest-*.json` + extracted release notes, with optional `--require-clean` and `--verify-remote-tag` discipline. |
| `scripts/generate_assurance_ledger.py` | Per-claim evaluators that turn raw evidence into a JSON ledger. |
| `scripts/verify_assurance_ledger.py` | Replay-only schema + sha256 + claim-coverage check on an existing ledger. |
| `scripts/verify_release_evidence_pack.py` | Pack-level replay: ledger, benchmark, cost-of-assurance, MCU footprint, release bundle, HTML report. |
| `scripts/render_assurance_report.py` | Pure-Python HTML renderer for the JSON ledger. |
| `scripts/export_pqc_cbom.py` | Produces `pqc_cbom.cdx.json`, a CycloneDX-style cryptography BOM for the release pack. |
| `scripts/generate_pqc_attestation.py` | Produces `pqc_attestation.intoto.json` and `pqc_assurance_digest.json` for unsigned hash-bound release evidence. |
| `scripts/verify_assurance_policy.py` | Applies the partner-review policy in `scripts/pqc_assurance_policy.json` to the ledger, CBOM, attestation, and release manifest. |
| `scripts/validate_acvp_negative_scenarios.py` | Enforces the append-only ACVP negative scenario compatibility floor. |
| `scripts/verify_pqc_asset_trace_map.py` | Verifies asset-to-source/Kconfig/claim/test/marker/CBOM traceability. |
| `scripts/generate_pqc_evidence_graph.py` | Emits JSON and Markdown graph views of the trace map against the ledger and CBOM. |
| `scripts/export_firmware_assurance_digest.py` | Converts `pqc_assurance_digest.json` into a generated C header for firmware binding. |

## Ledger vs Passport

The **Assurance Ledger** is the claim engine: each claim has an id, a status,
validators, commands, and evidence artifacts.

The **PQC Assurance Passport** is the partner-review package built around that
ledger. It consists of:

- `assurance_ledger.json` / `assurance_ledger.md`
- `assurance_report.html`
- `pqc_cbom.cdx.json`
- `pqc_attestation.intoto.json`
- `pqc_policy_result.json`
- `pqc_assurance_digest.json`
- `acvp_negative_scenario_floor_result.json`
- `pqc_asset_trace_result.json`
- `pqc_evidence_graph.json` / `pqc_evidence_graph.md`
- `pqc_assurance_profile_result.json`
- `pqc_evidence_quality_result.json`
- `pqc_migration_readiness.json` / `pqc_migration_readiness.md`
- `generated/pqcp_assurance_digest_generated.h`
- transcript, benchmark, cost-of-assurance, MCU footprint, and release-bundle
  artifacts

The passport is replay-verifiable with `verify_release_evidence_pack.py`.
It is not a signed certificate and does not claim hardware attestation; it is a
local, deterministic bridge between PQC crypto inventory, release claims,
validation transcripts, and build/release metadata.

## Claim catalog

The catalog at [`scripts/assurance_claims.json`](../scripts/assurance_claims.json)
is the source of truth for what the project actually claims. Each entry
has an `id`, a `category` (`release`, `kat`, `benchmark`,
`cost_of_assurance`, `acvp`), a one-sentence `claim` describing the
behaviour being asserted, and a `required` flag.

Highlights:

- `kat.mlkem_512`, `kat.mlkem_768`, `kat.mlkem_1024`,
  `kat.mldsa_44`, `kat.mldsa_65`, `kat.mldsa_87` —
  per-parameter-set KAT decomposition. A regression in ML-DSA-65 names
  ML-DSA-65 in the failure reason rather than disappearing into an
  aggregate.
- `benchmark.mlkem_throughput`, `benchmark.mldsa_throughput` —
  per-primitive benchmark CSV checks.
- `acvp.negative_path_rejection` — proves the ACVP serial harness
  rejects malformed inputs (bad hex, unknown commands, wrong sizes,
  oversize payloads) by binding `scripts/acvp_negative_scenarios.json`
  to the captured `ACVP serial ztest run` transcript and requiring the
  documented ztest markers (`test_rejects_malformed_commands`,
  `test_rejects_invalid_hex_and_wrong_sizes`,
  `test_serial_line_garbage_rejected_and_recovered`).
- `acvp.timeout_recovery` — proves the stalled-frame timeout path is
  exercised by requiring the `test_readline_timeout` ztest marker and
  successful `pqcp_acvp_serial` suite marker in the same transcript.
  The ledger details record that the ztest asserts the locked
  `ERROR:TIMEOUT` wire response, even when the test runner does not
  echo the UART payload literally.
- `release.transcript_binding` — every required release-check step has
  a captured stdout transcript with a recorded SHA-256, plus QEMU
  cost-of-assurance run logs.

## Constant-time smoke (`security.ct_smoke`) — what it does and does not prove

`tests/ztest_ct_smoke` runs ML-KEM-512, ML-KEM-768, and ML-KEM-1024
decapsulation 32 times against a valid ciphertext and 32 times against a
deliberately corrupted one for each parameter set,
records `k_cycle_get_64()` deltas, computes the absolute difference of
the two median cycle counts, and asserts the relative variance falls
under a documented loose bound. The captured transcript records the
measurement on a stable marker line:

```
PQCP_CT_SMOKE alg=MLKEM-768 iters=32 median_valid=<C> \
    median_invalid=<C> delta=<C> relative_pct=<P> bound_pct=<B>
```

The `security.ct_smoke` assurance evaluator re-parses that line and
records the medians, delta, relative variance, and the bound in the
ledger details + HTML report.

**What this proves:** that the public ML-KEM decapsulation API has a
*first-order* timing profile that does not visibly bifurcate on
ciphertext validity, which is exactly the failure mode introduced when
a maintainer accidentally short-circuits decapsulation on an invalid
CT. A regression here is named directly in the ledger instead of
disappearing into "decap still works".

**What this does NOT prove:** it is not a formal constant-time proof.
A real attacker has access to far better measurement infrastructure
than `k_cycle_get_64` on a simulated CPU. On qemu_x86_64 the cycle
counter is itself coarse, so a "pass" here does not extend to physical
hardware. It does not exercise data-dependent memory access patterns,
cache footprint, or microarchitectural side channels. Side-channel
resistance to fault injection, EM, or power analysis is explicitly out
of scope and called out the same way in
[`docs/publications.md`](publications.md).

The claim is required because the stable marker line is a useful
regression target; the smoke nature of the test is itself a stated
assurance property — visibly admitting the limit is part of the
credibility story.

## Schema versioning and the compatibility shim

The catalog and the ledger carry a `schema_version`.

- **schema_version = 1** is the legacy 8-claim set shipped with the
  initial assurance work. It contained `kat.offline_provenance` and
  `benchmark.csv_validity` as aggregate claims.
- **schema_version = 2** adds the per-primitive KAT claims,
  per-primitive benchmark claims, and the two ACVP robustness claims.
- **schema_version = 3** adds Passport-oriented supply-chain and
  firmware-preparation claims for CBOM inventory, PQC assurance attestation,
  policy result, and the digest manifest used by future device attestation.
- **schema_version = 4** strengthens Passport replay with the ACVP
  negative scenario compatibility floor, crypto asset traceability, evidence
  graph integrity, and firmware digest embeddability.
- **schema_version = 5** (current) adds profile policy, evidence quality, asset
  profile separation, migration-readiness reporting, and production RNG policy
  checks.

`generate_assurance_ledger.py` and `verify_assurance_ledger.py` both
accept supported historical versions. Loading a v1 catalog or replaying a v1 ledger
emits a single `[warn]` line that names the path and explains the
reduced coverage. Older evidence packs therefore degrade gracefully
instead of hard-failing — a maintainer can hand an old pack to a
reviewer and the verifier will still pass while clearly labelling it as
legacy.

## Passport v2 / schema v4 replay checks

Schema v4 adds checks that are deliberately additive:

- `acvp.negative_scenario_floor` binds
  `scripts/acvp_negative_scenario_floor.json` to
  `scripts/acvp_negative_scenarios.json` and fails on removed, renamed,
  duplicated, or weakened floor scenarios.
- `supply_chain.crypto_asset_traceability` is backed by
  `pqc_asset_trace_result.json`, generated by
  `scripts/verify_pqc_asset_trace_map.py`.
- `supply_chain.evidence_graph_integrity` is backed by
  `pqc_evidence_graph.json` and `pqc_evidence_graph.md`, generated by
  `scripts/generate_pqc_evidence_graph.py`.
- `firmware.assurance_digest_embeddable` is backed by
  `generated/pqcp_assurance_digest_generated.h` and the build-only
  `samples/pqcp_assurance_status` path.

Some Passport artifacts are generated after the initial ledger because the CBOM,
attestation, policy result, and digest themselves consume the ledger. To avoid a
circular hash dependency, the pack-level replay verifier and policy verifier
enforce those generated artifacts directly. This is the intentional split:
ledger claims describe support; the Passport verifier prevents artifact drift.

## Assurance Profile / schema v5 replay checks

Schema v5 adds a profile layer above the Passport artifacts:

- `supply_chain.assurance_profile_policy` is backed by
  `pqc_assurance_profile_result.json`, generated by
  `scripts/verify_pqc_assurance_profile.py`.
- `supply_chain.evidence_quality_index` is backed by
  `pqc_evidence_quality_result.json`, generated by
  `scripts/verify_pqc_evidence_quality.py`.
- `crypto_agility.profile_separation` and `security.production_rng_policy`
  are enforced by the same profile result and by the CBOM `pqcp:*` properties.
- `release.migration_readiness` is backed by
  `pqc_migration_readiness.json` and `pqc_migration_readiness.md`.

These artifacts do not change the C API or wire formats. They make the release
pack clearer for local review by separating production-allowed crypto assets
from validation-only, lab-only, smoke-only, and test-only assets.

## How transcript hashing works

`release_check.py` runs every gate step under a transcript-capturing
wrapper. For each step it writes
`transcripts/<NN>-<slug>.log` containing the full stdout/stderr stream
plus a header recording the command, working directory, return code,
and duration. Just before the assurance ledger step runs, the gate
writes
`transcripts/evidence_transcript_manifest.json`
containing one entry per *required* evidence-producing step
(`Extended Checks (strict cost-of-assurance smoke)`, `ACVP serial ztest
run`, `ACVP KAT ztest run`, `benchmark_csv`, `benchmark_csv_validate`,
`resource_budgets`) plus one entry per QEMU stdout log under
`cost_of_assurance_smoke/runs/*/run.log`. Each entry records the file
path, its SHA-256, and its size in bytes.

When `evaluate_transcript_binding` runs, it re-hashes every referenced
file and rejects the manifest if any required step is missing,
returncode-non-zero, size-drifted, or hash-drifted. The negative-ACVP
and timeout-recovery evaluators perform a similar check but additionally
grep the transcript body for the documented ztest markers. For timeout
recovery, the ledger records that `test_readline_timeout` asserts the
locked `ERROR:TIMEOUT` wire response; the transcript does not need to
duplicate the UART payload as a literal `ERROR:TIMEOUT` line.

## Producing vs replaying an evidence pack

**Producing** — run the full gate. This requires a working Zephyr SDK,
`west`, `cppcheck`, `qemu-system-x86`, and (optionally) an ARM toolchain
for the MCU protocol footprint step:

```sh
python3 scripts/release_check.py \
    --tag v1.0.0 \
    --output-root /tmp/pqcp-release-pack
```

The output root will contain the JUnit report, the JSON+MD ledger, the
HTML assurance report, the captured transcripts, the local release
bundle, the benchmark CSV with provenance sidecar, the cost-of-assurance
evidence, and the MCU footprint CSV.

**Replaying** — verify a previously produced pack. This requires only
Python 3.12; no Zephyr SDK, no QEMU, no compilation:

```sh
python3 scripts/verify_release_evidence_pack.py /tmp/pqcp-release-pack \
    --tag v1.0.0
```

The replay verifier checks that the ledger schema is supported, every
required claim is present and has a valid status, every recorded
SHA-256 still matches the file on disk, the benchmark CSV is
schema-valid and bound to its provenance sidecar, the cost-of-assurance
metrics all passed, the MCU footprint rows have positive ROM/RAM, the
release bundle manifest agrees with the ledger on version + commit + tag
+ dirty-tree, every claim id appears in the HTML assurance report, and
no transcript file has been tampered with since generation. Any failure
exits non-zero and lists the offending claim, file, and reason.

## Extending the claim set

To add a new claim:

1. Append an entry to [`scripts/assurance_claims.json`](../scripts/assurance_claims.json)
   with a stable `id`, a `category`, and a one-sentence `claim`.
2. Add an evaluator in `scripts/generate_assurance_ledger.py` that
   takes the spec plus its inputs and returns either `pass_claim`,
   `fail_claim`, or `not_applicable_claim`.
3. Wire the evaluator into `build_claim_evaluators()`.
4. Add a focused test in `scripts/test_assurance_ledger.py` that
   exercises the pass and fail paths.
5. If the claim depends on a new release-check artifact, also add the
   generating step to `scripts/release_check.py` and (where relevant)
   to `REQUIRED_EVIDENCE_TRANSCRIPT_STEPS` so the new transcript is
   bound by `release.transcript_binding`.

The replay verifier needs no changes for category- and claim-level
additions: it iterates the catalog and checks the recorded artifacts
generically. It only needs touching when a new *artifact type*
(comparable to the HTML report or the benchmark CSV) is introduced.
