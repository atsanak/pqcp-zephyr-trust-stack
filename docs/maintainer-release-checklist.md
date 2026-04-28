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
cost_of_assurance_evidence.json
```

Inspect `assurance_ledger.md` before publishing or sharing a local bundle. It
must show no failing required claims. The JSON form is intended for scripts and
paper/release artifact review because it binds claims to concrete validators,
commands, artifact paths, and hashes.

To replay-check an already generated ledger without rerunning QEMU builds:

```bash
python3 scripts/verify_assurance_ledger.py \
  benchmark_results/release_check/assurance_ledger.json \
  --markdown benchmark_results/release_check/assurance_ledger.md
```

This catches stale Markdown summaries, missing claim IDs, missing artifacts, and
SHA-256 drift in evidence artifacts.

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
