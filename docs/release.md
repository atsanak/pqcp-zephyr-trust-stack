# Local Release Packaging

This repository can prepare release artifacts locally without GitHub Actions.
Use this path when Actions minutes, billing, or the GitHub Release workflow are
unavailable but the code/tag side has already been validated.

## How to cut a release and prove it (TL;DR)

Three commands, in order:

```bash
# 1. Run the full release gate locally. Produces JUnit, ledger, HTML report,
#    transcripts, benchmark CSV + provenance, MCU footprint, release bundle.
python3 scripts/release_check.py --tag v1.0.0 \
    --output-root /tmp/pqcp-release-pack

# 2. (only when publishing assets exactly aligned with a tag)
git checkout v1.0.0
python3 scripts/prepare_release_bundle.py --exact-tag --verify-remote-tag

# 3. Hand the pack to a reviewer (or come back to it later) and replay-verify
#    it without rebuilding anything. Requires only Python 3.12.
python3 scripts/verify_release_evidence_pack.py /tmp/pqcp-release-pack \
    --tag v1.0.0
```

Step (1) writes `assurance_ledger.json`, `assurance_ledger.md`,
`assurance_report.html`, `pqc_cbom.cdx.json`,
`pqc_attestation.intoto.json`, `pqc_policy_result.json`,
`pqc_assurance_digest.json`, and
`transcripts/evidence_transcript_manifest.json` under the output root. Passport
v2 release roots also contain `acvp_negative_scenario_floor_result.json`,
`pqc_asset_trace_result.json`, `pqc_evidence_graph.json`,
`pqc_evidence_graph.md`, and
`generated/pqcp_assurance_digest_generated.h`.
Step (3) re-checks every recorded SHA-256, every required claim id, every
Passport subject hash, and every transcript hash, and exits non-zero with the
exact offending file/claim if anything has drifted. See
[`assurance-model.md`](assurance-model.md) for the architecture.

## What This Produces

`scripts/prepare_release_bundle.py` writes an ignored local bundle under
`output/release/<tag>/` containing:

- `release-notes-<tag>.md`, extracted from the matching `CHANGELOG.md` section
- `release-manifest-<tag>.json`, recording version, tag object, tag commit,
  current source commit, release date, Zephyr revision, and dependency pins
- `api-docs/html/`, generated from `docs/Doxyfile`

The script does not mutate repository source files.

## Exact-Tag Release Bundle

For artifacts that exactly match the release tag, run from a checkout of the
tag itself:

```bash
git fetch origin --tags
git checkout v1.0.0
python3 scripts/prepare_release_bundle.py --exact-tag --verify-remote-tag
```

The `--exact-tag` flag requires a clean checkout and fails if the selected tag
does not point to the current checkout. `--verify-remote-tag` additionally
checks that `origin` has the same annotated tag object and peeled commit. That
is the recommended mode for publishing replacement assets for a tagged release.

## Maintainer-Branch Bundle

For post-tag maintainer hardening work, run from `main` without
`--exact-tag`:

```bash
python3 scripts/prepare_release_bundle.py --tag v1.0.0
```

When the current branch has moved beyond the tag, the manifest records both
`source_commit` and `tag_commit` and sets `tag_points_to_head=false`. This is
useful for auditing local documentation/package work, but it should not be
presented as the exact tagged source bundle.

## Validation

Before relying on a local bundle, run:

```bash
python3 -m py_compile scripts/*.py
python3 scripts/test_local_release_workflows.py
python3 scripts/check_version_consistency.py --changelog CHANGELOG.md --tag v1.0.0
python3 scripts/release_check.py --tag v1.0.0
python3 scripts/prepare_release_bundle.py --tag v1.0.0
```

## Assurance Ledger

`scripts/release_check.py --tag v1.0.0` now writes an Assurance Ledger under
its output root:

- `assurance_ledger.json`: machine-readable claim/evidence status
- `assurance_ledger.md`: human-readable summary of the same claim IDs
- `cost_of_assurance_evidence.json`: per-metric guardrail evidence consumed by
  the ledger
- `transcripts/evidence_transcript_manifest.json`: SHA-256 binding for
  release-check stdout transcripts from ACVP, KAT, benchmark, and resource
  evidence steps, plus raw QEMU stdout logs from cost-of-assurance runs

The ledger is intentionally local and QEMU-oriented. It links release metadata,
offline KAT provenance, benchmark CSV validity, benchmark provenance binding,
cost-of-assurance guardrails, release-check transcript hashes, raw QEMU stdout
hashes, and the local release bundle manifest. Any required claim failure makes
`release_check.py` fail.

`release_check.py` also verifies the generated ledger before it reports PASS.
That replay check validates the JSON schema, claim coverage, Markdown/JSON
claim parity, artifact existence, and recorded SHA-256 values without rerunning
the expensive Zephyr builds.

After the ledger replay check, `release_check.py` verifies the whole release
evidence pack as a coherent directory. That pack-level check validates the
benchmark CSV/provenance pair, benchmark summary, cost-of-assurance evidence,
MCU footprint CSV, local release manifest, release notes hash, transcript
hashes, and ledger/bundle commit metadata alignment.

To regenerate and verify only the ledger from existing artifacts:

```bash
python3 scripts/generate_assurance_ledger.py \
  --tag v1.0.0 \
  --benchmark-csv benchmark_results/release_check/benchmark_results.csv \
  --benchmark-provenance benchmark_results/release_check/benchmark_provenance.json \
  --cost-of-assurance-evidence benchmark_results/release_check/cost_of_assurance_evidence.json \
  --release-bundle-root benchmark_results/release_check/local_release_bundle \
  --transcript-manifest benchmark_results/release_check/transcripts/evidence_transcript_manifest.json \
  --output-json benchmark_results/release_check/assurance_ledger.json \
  --output-md benchmark_results/release_check/assurance_ledger.md

python3 scripts/verify_assurance_ledger.py \
  benchmark_results/release_check/assurance_ledger.json \
  --markdown benchmark_results/release_check/assurance_ledger.md
```

To verify a complete existing release-check output directory:

```bash
python3 scripts/verify_release_evidence_pack.py \
  benchmark_results/release_check \
  --tag v1.0.0
```

If GitHub Actions is later restored, rerun the normal release workflow and
compare the generated release notes with `output/release/v1.0.0/release-notes-v1.0.0.md`.

## PQC Assurance Passport

The full local release gate now emits the Passport artifacts described in
[`pqc-assurance-passport.md`](pqc-assurance-passport.md):

- `pqc_cbom.cdx.json`: CycloneDX-style cryptography BOM.
- `pqc_attestation.intoto.json`: unsigned in-toto Statement-style evidence
  attestation.
- `pqc_policy_result.json`: partner-review policy result.
- `pqc_assurance_digest.json`: stable SHA-256 digest manifest for future
  firmware attestation binding.
- `acvp_negative_scenario_floor_result.json`: append-only ACVP negative
  scenario compatibility-floor validation.
- `pqc_asset_trace_result.json`: asset-to-source/Kconfig/claim/test/marker/CBOM
  trace-map validation.
- `pqc_evidence_graph.json` / `pqc_evidence_graph.md`: graph view of the same
  traceability links.
- `generated/pqcp_assurance_digest_generated.h`: firmware-embeddable assurance
  digest header generated from `pqc_assurance_digest.json`.

The CI fast gate intentionally skips the full Passport because it would require
the expensive benchmark, sanitizer, MCU footprint, and release-bundle evidence
path. Use the local release gate when producing partner-review artifacts.
