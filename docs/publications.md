# pqcp-zephyr-trust-stack — Publication-Ready Technical Brief

> Two-page workshop-style brief describing what this repository proves
> and how a reviewer can re-verify every claim. Intended as the abstract
> a maintainer hands to a program committee, an internal security
> review, or a downstream integrator. Every command and output file
> referenced below exists in the repository at the version indicated by
> [CITATION.cff](../CITATION.cff).

## 1. Motivation

Production embedded deployments need post-quantum cryptography (PQC)
*and* a credible argument that the deployed module behaves as advertised
in the binary that actually shipped. Many open-source PQC reference
implementations exist, but very few are packaged as a Zephyr RTOS module
that is both (a) consumable as a pinned dependency by a downstream
firmware project and (b) auditable end-to-end by a third party who only
has the released artifact and a Python interpreter. This repository
addresses both requirements.

## 2. System description

The trust stack is an out-of-tree Zephyr RTOS module providing
[ML-KEM (FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final) at
parameter sets 512/768/1024 and
[ML-DSA (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final) at
parameter sets 44/65/87. The C surface is layered as:

- A vendored, pinned upstream of `mlkem-native` and `mldsa-native`
  (declared in `west.yml`).
- A PSA Crypto + mbedTLS provider layer (`src/psa_mlkem_driver.c`,
  `src/psa_mldsa_driver.c`).
- A Zephyr-facing API in `include/pqcp_zephyr/{mlkem,mldsa,rng,
  acvp_cmd, bench, tls_selftest, version}.h`.
- An ACVP serial validation harness (`src/acvp_cmd.c`) implementing the
  documented wire format described in
  [`docs/api-overview.md`](api-overview.md).
- A TLS self-test (`src/tls_selftest.c`) that performs a deterministic
  PSA + ML-KEM + ML-DSA handshake and emits a stable
  `PQCP_METRIC,...` accounting line.

The validation pipeline is encoded in a single sequential gate,
[`scripts/release_check.py`](../scripts/release_check.py), that
maintainers run locally before tagging a release. Every step writes a
SHA-256-hashed transcript under the chosen `--output-root` and the
gate emits both a JSON Assurance Ledger and a self-contained HTML
report.

## 3. Key technical claims

### 3.1 Claim-to-evidence Assurance Ledger

[`scripts/assurance_claims.json`](../scripts/assurance_claims.json) is a
versioned catalog of typed claims (release, kat, benchmark,
cost-of-assurance, acvp, security). Every claim has an `id`, a
one-sentence `claim` string, and a dedicated evaluator in
[`scripts/generate_assurance_ledger.py`](../scripts/generate_assurance_ledger.py)
that returns `pass`, `fail`, or `not_applicable` together with the
specific artifact paths and SHA-256 hashes that were inspected. The
catalog uses an explicit `schema_version` field with a documented
backward-compatibility shim: legacy v1 packs replay-validate with a
clearly-labelled `[warn]` line noting the reduced coverage so older
evidence packs degrade gracefully rather than hard-failing. The full
architecture is described in [`docs/assurance-model.md`](assurance-model.md).

### 3.2 Per-primitive KAT and benchmark decomposition

The aggregate `kat.offline_provenance` claim is now joined by
parameter-set-specific siblings (`kat.mlkem_512`, `kat.mlkem_768`,
`kat.mlkem_1024`, `kat.mldsa_44`, `kat.mldsa_65`, `kat.mldsa_87`).
Each verifies only the
[`scripts/verify_kat_provenance.py`](../scripts/verify_kat_provenance.py)
`VECTOR_SPECS` rows for its parameter set. A regression in a single
primitive names that primitive directly in the failure reason rather
than disappearing into the aggregate. The same decomposition exists at
the benchmark layer (`benchmark.mlkem_throughput`,
`benchmark.mldsa_throughput`), which assert positive `cycles` and
`time_us` values per parameter set in the released CSV.

### 3.3 ACVP negative-path replay against a vendored fixture

Beyond the positive ACVP harness, a dedicated ztest at
[`tests/ztest_acvp_serial_negative`](../tests/ztest_acvp_serial_negative/)
loads every replay-eligible case from
[`scripts/acvp_negative_scenarios.json`](../scripts/acvp_negative_scenarios.json)
through a generated C header
([`scripts/generate_acvp_negative_header.py`](../scripts/generate_acvp_negative_header.py)
with `--check` for drift detection) and asserts that
`pqcp_acvp_process_command()` produces the documented `ERROR:*` wire
response. The C test prints
`PQCP_ACVP_NEG case=<name> command=<input> response=<wire>` per
iteration so the captured transcript documents which negative
scenarios actually ran. This allows three claims (`acvp.negative_scenarios_replay`,
`acvp.mlkem_negative_paths`, `acvp.mldsa_negative_paths`) to bind to a
suite expressly built to be adversarial, instead of grepping the
positive-run transcript for marker substrings.

### 3.4 QEMU-only local release gate with transcript-hash assurance

The release gate runs locally on a developer's workstation. No part of
the assurance pipeline depends on GitHub Actions. Every required step
writes a transcript file; transcripts are listed in
`transcripts/evidence_transcript_manifest.json` with `sha256`,
`size_bytes`, `returncode`, and `duration_seconds`. The replay
verifier
([`scripts/verify_release_evidence_pack.py`](../scripts/verify_release_evidence_pack.py))
re-hashes every file and rejects the pack if any required transcript is
missing, empty, size-drifted, or hash-drifted. Sanitizer evidence is
named: `security.asan_clean` and `security.ubsan_clean` re-grep the
captured `sanitizers` step transcript for AddressSanitizer and
UndefinedBehaviorSanitizer error markers, and degrade to a clearly
labelled `not_applicable` on hosts where sanitizer execution is
deliberately skipped.

## 4. Reproducibility statement

To reproduce every claim from a clean checkout:

```bash
# 1. Run the full release gate. Produces ledger, HTML report,
#    transcripts, benchmark CSV, cost evidence, MCU footprint, bundle.
python3 scripts/release_check.py \
    --tag v1.0.0 \
    --output-root /tmp/pqcp-release-pack

# 2. Replay-verify the produced pack with only Python 3.12 — no
#    Zephyr SDK, no QEMU, no compilation.
python3 scripts/verify_release_evidence_pack.py \
    /tmp/pqcp-release-pack \
    --tag v1.0.0
```

The released artifacts under `/tmp/pqcp-release-pack` are:

```
assurance_ledger.json     # machine-readable claim list
assurance_ledger.md       # human-readable claim list
assurance_report.html     # self-contained, dependency-free HTML report
benchmark_results.csv     # primitive-level benchmark data
benchmark_provenance.json # SHA-256-bound to the CSV bytes
cost_of_assurance_evidence.json
mcu_protocol_footprint/   # nucleo_h743zi build-only ROM/RAM
local_release_bundle/     # release notes + bundle manifest
transcripts/              # per-step stdout transcripts + manifest
release_check_results.xml # JUnit
```

A reviewer who only has the pack runs `verify_release_evidence_pack.py`
and gets either an exit-zero "pass" with the version, head SHA, and
ledger summary, or a non-zero exit with the exact offending claim id,
file path, and reason. There is no manual interpretation step.

## 5. Honest non-claims

What this repository explicitly does **not** prove:

- **Constant-time guarantees.** The runtime CT smoke harness
  (`security.ct_smoke`, where present) is a documented smoke test, not
  a formal proof. It measures gross cycle-count variance and is
  deliberately labelled as such. Side-channel resistance requires
  formal proof or instruction-level analysis that is out of scope.
- **Side-channel resistance to physical attacks.** No fault injection,
  EM, or power analysis is in scope. The threat model is honest-host /
  protocol-level adversary on the wire.
- **GitHub Release-page publication.** The repository is currently
  release-pack-ready and consumer-onboarding-ready; the GitHub Release
  page itself depends on the release workflow running on GitHub-hosted runners.

## 6. Pointers

- Architecture: [`docs/assurance-model.md`](assurance-model.md)
- Public C API: [`docs/api-overview.md`](api-overview.md)
- Maintainer release path: [`docs/release.md`](release.md) and
  [`docs/maintainer-release-checklist.md`](maintainer-release-checklist.md)
- Citation metadata: [`CITATION.cff`](../CITATION.cff)
- Source: [github.com/atsana01/pqcp-zephyr-trust-stack](https://github.com/atsana01/pqcp-zephyr-trust-stack)
