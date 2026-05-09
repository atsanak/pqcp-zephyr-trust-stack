# Maintainer Release Verification Checklist

Use this checklist when preparing or auditing a release without relying on
GitHub Actions. It distinguishes local code/tag readiness from GitHub Release
publication, which may be blocked by account billing or Actions availability.

## Required Local Tools

- Python 3.12 or newer
- `west`
- Zephyr SDK compatible with the workspace baseline
- `cppcheck`
- `doxygen`
- `git`
- QEMU support from the Zephyr SDK host tools

Confirm the active workspace before running release checks:

```bash
echo "$ZEPHYR_BASE"
echo "$ZEPHYR_SDK_INSTALL_DIR"
west topdir
west --version
```

## 1. Verify Local And Remote Git State

```bash
git fetch origin --tags
git status --short --branch
git rev-parse HEAD
git ls-remote origin refs/heads/main
git ls-remote origin refs/tags/v1.0.0 'refs/tags/v1.0.0^{}'
```

For a branch to be fully pushed, `git rev-parse HEAD` must match
`git ls-remote origin refs/heads/main`. For a tag to be published, the
`refs/tags/<tag>` query must return a tag object and, for annotated tags, the
peeled `refs/tags/<tag>^{}` commit.

## 2. Verify Version And Changelog Consistency

```bash
python3 scripts/check_version_consistency.py \
  --changelog CHANGELOG.md \
  --tag v1.0.0
```

This checks `include/pqcp_zephyr/version.h`, `CMakeLists.txt`,
`CHANGELOG.md`, and the provided tag name for the same semantic version.

## 3. Run Local Source And Release Gates

```bash
python3 -m py_compile scripts/*.py
python3 scripts/test_local_release_workflows.py

python3 scripts/run_extended_checks.py --strict

python3 scripts/run_extended_checks.py \
  --strict \
  --run-cost-of-assurance-smoke

python3 scripts/release_check.py --tag v1.0.0
```

For a single command that sequences those existing checks, plus the consumer
smoke and local release bundle generation, run:

```bash
python3 scripts/verify_product_readiness.py --tag v1.0.0
```

Use `--skip-release-check` only when iterating on the wrapper itself; the full
release gate remains the authoritative readiness signal.

On non-Linux hosts, `scripts/run_sanitizer_checks.py` may skip native
ASan/UBSan execution by design. Do not weaken the release gate for that; use a
Linux host for strict sanitizer confirmation when required.

The release gate also produces an Assurance Ledger under the selected
`--output-root`:

```text
assurance_ledger.json
assurance_ledger.md
assurance_report.html
cost_of_assurance_evidence.json
transcripts/evidence_transcript_manifest.json
```

Inspect `assurance_ledger.md` before publishing or sharing a local bundle. It
must show no failing required claims. The JSON form is intended for scripts and
paper/release artifact review because it binds claims to concrete validators,
commands, artifact paths, release-check transcript files, raw QEMU stdout
logs, and hashes. `assurance_report.html` is a self-contained,
dependency-free HTML view of the same JSON ledger and is the
recommended artifact to share with reviewers or attach to a release pack.

The ledger schema is `schema_version=3`. Beyond the original release/KAT/
benchmark/cost-of-assurance/transcript-binding claims, every release pack
must also report `pass` or an explicitly documented `not_applicable` for:

- `kat.mlkem_512`, `kat.mlkem_768`, `kat.mlkem_1024` — per-parameter-set
  ML-KEM KAT decomposition.
- `kat.mldsa_44`, `kat.mldsa_65`, `kat.mldsa_87` — per-parameter-set
  ML-DSA KAT decomposition.
- `benchmark.mlkem_throughput`, `benchmark.mldsa_throughput` —
  per-primitive benchmark CSV row coverage.
- `acvp.negative_path_rejection`, `acvp.timeout_recovery` — bound to the
  `ACVP serial ztest run` transcript markers.
- `acvp.negative_scenarios_replay`, `acvp.mlkem_negative_paths`,
  `acvp.mldsa_negative_paths` — bound to the new
  `ACVP serial negative ztest run` transcript markers from
  `tests/ztest_acvp_serial_negative`.
- `security.asan_clean`, `security.ubsan_clean` — re-grep the captured
  `sanitizers` step transcript for AddressSanitizer / runtime-error
  markers and degrade to `not_applicable` on hosts that skip
  sanitizer execution (PQCP_STRICT_SANITIZERS unset and not under CI).
- `boot.kat_self_verify` — bound to the new `boot KAT self-verify
  ztest run` transcript from `tests/ztest_kat_boot_verify`. Requires
  the `PQCP_KAT_BOOT_VERIFY: starting power-on self-test`,
  `PQCP_KAT_BOOT_VERIFY: all enabled primitives passed`, and
  `TESTSUITE pqcp_kat_boot_verify succeeded` markers, plus the
  `PQCP_KAT_BOOT_VERIFY: ztest reached main without panic` line proving
  the SYS_INIT hook returned 0.
- `security.ct_smoke` — bound to the new `ct smoke ztest run`
  transcript from `tests/ztest_ct_smoke`. Re-parses the stable
  `PQCP_CT_SMOKE alg=... median_valid=... median_invalid=... delta=...
  relative_pct=... bound_pct=...` line and stores the measurement in
  the ledger details. Marked `is_smoke_test_only=true` and accompanied
  by an explicit non-claim section in
  [`assurance-model.md`](assurance-model.md).

A failing required claim names the offending parameter set, primitive, or
case directly in `failure_reason` rather than disappearing into the older
aggregate `kat.offline_provenance` / `benchmark.csv_validity` rows.

Current full release packs use ledger `schema_version=3`, which adds the PQC
Assurance Passport layer. In addition to the ledger and HTML report, inspect:

- `pqc_cbom.cdx.json`
- `pqc_attestation.intoto.json`
- `pqc_policy_result.json`
- `pqc_assurance_digest.json`

`pqc_policy_result.json` must have `"passed": true`. The policy verifier checks
required claim statuses, required PQC crypto assets, deterministic RNG
test-only labelling, attestation subject hashes, and version/tag/source
metadata consistency across the ledger, CBOM, attestation, and release
manifest.

If the ACVP negative scenario fixture is updated, regenerate the
matching C header before running the gate:

```bash
python3 scripts/generate_acvp_negative_header.py
```

`release_check.py` runs the same command with `--check` as a release-gate
step, so a stale header is caught at gate time.

To replay-check an already generated ledger without rerunning QEMU builds:

```bash
python3 scripts/verify_assurance_ledger.py \
  benchmark_results/release_check/assurance_ledger.json \
  --markdown benchmark_results/release_check/assurance_ledger.md
```

This catches stale Markdown summaries, missing claim IDs, missing artifacts,
missing release-check transcripts, missing raw QEMU stdout logs, and SHA-256
drift in evidence artifacts. Legacy `schema_version=1` packs replay with a
clearly-labelled `[warn]` line noting the reduced claim coverage.

To replay-check the full release output root without rerunning Zephyr builds:

```bash
python3 scripts/verify_release_evidence_pack.py \
  benchmark_results/release_check \
  --tag v1.0.0
```

This validates the ledger, benchmark CSV/provenance, benchmark summary,
cost-of-assurance evidence, MCU footprint CSV, local release manifest, release
notes hash, transcript hashes, ledger/bundle commit metadata alignment, and
(for `schema_version >= 2` packs) that `assurance_report.html` exists and
contains every claim id from the ledger. For `schema_version >= 3` packs it also
replays the PQC Assurance Passport policy and digest checks.

## 4. Run Focused Consumer And Harness Smokes

```bash
python3 scripts/consumer_smoke.py --module-mode manifest

west build -p always -b qemu_x86_64 tests/ztest_acvp_serial
west build -d build -t run

west build -p always -b qemu_x86_64 tests/ztest_primitive

west build -p always -b qemu_x86_64 tests/ztest_rng

west build -p always -b qemu_x86_64 tests/ztest_tls_selftest
```

Use `--module-mode extra-module` only for a local development checkout that is
not listed in the active west manifest.

If a QEMU run prints `PROJECT EXECUTION SUCCESSFUL` but does not exit promptly
on macOS, prefer the repository wrappers (`release_check.py` or
`consumer_smoke.py`) because they handle success-marker timeouts explicitly.

## 5. Generate API Documentation Locally

```bash
doxygen docs/Doxyfile
```

Generated HTML lives under `docs/html/`, which is intentionally gitignored.
Warnings should be treated as documentation defects before a product release.

## 6. Prepare A Local Release Bundle

For a maintainer-branch bundle:

```bash
python3 scripts/prepare_release_bundle.py --tag v1.0.0
```

For an exact bundle of the tagged source:

```bash
git checkout v1.0.0
python3 scripts/prepare_release_bundle.py --exact-tag --verify-remote-tag
```

The bundle is written under `output/release/<tag>/` and contains release notes,
API docs, and a JSON manifest binding version, tag object, tag commit, source
commit, Zephyr revision, release date, and dependency pins.

## 7. Interpret Readiness Correctly

Code/tag readiness means all local validation commands pass and the annotated
tag is present on `origin`.

GitHub Release publishing readiness additionally requires the tag-triggered
GitHub Actions workflow to run successfully and create the public Release page
with its uploaded artifacts.

If GitHub Actions is blocked by billing, spending limits, or unavailable
minutes, the repository can still be code/tag ready and locally packageable, but
it is not GitHub-Release-page ready. In that state:

- keep the remote tag intact;
- do not force-push or recreate the tag;
- use `scripts/prepare_release_bundle.py` for local artifacts;
- rerun the GitHub release workflow after Actions availability is restored.
