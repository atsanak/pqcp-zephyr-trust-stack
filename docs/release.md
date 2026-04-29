# Local Release Packaging

This repository can prepare release artifacts locally without GitHub Actions.
Use this path when Actions minutes, billing, or the GitHub Release workflow are
unavailable but the code/tag side has already been validated.

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
