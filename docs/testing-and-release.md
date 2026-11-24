# Testing, CI and release

See the [README](../README.md) for the project overview.

## Testing

```bash
# Run primitive tests
west build -p always -b qemu_x86_64 tests/ztest_primitive
west build -t run

# Run primitive tests with PSA drivers
west build -p always -b qemu_x86_64 tests/ztest_primitive -- -DOVERLAY_CONFIG=overlay-psa.conf
west build -t run

# Run RNG tests
west build -p always -b qemu_x86_64 tests/ztest_rng
west build -t run

# Run ACVP command-library tests
west build -p always -b qemu_x86_64 tests/ztest_acvp_serial
west build -t run

# Run shared TLS self-test helper tests
west build -p always -b qemu_x86_64 tests/ztest_tls_selftest
west build -t run

# Optional stress-oriented ACVP parser coverage
west build -p always -b qemu_x86_64 tests/ztest_acvp_serial -- \
  -DOVERLAY_CONFIG=overlay-fuzz.conf
west build -t run

# Optional stress-oriented TLS self-test coverage
west build -p always -b qemu_x86_64 tests/ztest_tls_selftest -- \
  -DOVERLAY_CONFIG=overlay-fuzz.conf
west build -t run

# Optional ASan/UBSan coverage on native_sim/native/64
python scripts/run_sanitizer_checks.py \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD"

# Run primitive tests on mps2/an385 without entropy hardware
west build -p always -b mps2/an385 tests/ztest_primitive -- -DOVERLAY_CONFIG=overlay-no-entropy.conf
west build -t run
```

`CONFIG_PQCP_FUZZ_TESTS` is disabled by default and only enabled by the
`overlay-fuzz.conf` test overlays. It is intended for local hardening runs and
extended workflows, not for the default smoke CI path.

The optional ACVP fuzz overlay keeps the normal command-coverage suite intact
while adding randomized valid and invalid command sequences plus direct wire
format stress checks. The TLS fuzz overlay adds repeated self-test runs across
the enabled KEM/DSA levels to catch state-leak and reinitialization regressions
without affecting the default qemu smoke path.

The sanitizer runner uses dedicated `overlay-sanitize.conf` files for
`tests/ztest_acvp_serial` and `tests/ztest_tls_selftest` on
`native_sim/native/64`, which makes it easy to get ASan/UBSan coverage for the
highest-risk glue code without changing the default `qemu_x86_64` smoke flow.
Because Zephyr's POSIX/native architecture is Linux-only, this sanitizer helper
is intended for Linux hosts (including GitHub Actions) rather than macOS or
Windows shells.

## Extended Checks

For slower pre-release or refactor-oriented checks, run:

```bash
python scripts/run_extended_checks.py \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD" \
  --strict
```

This helper:

- configures a lightweight Zephyr target and writes a CMake graphviz file
- runs focused `cppcheck` analysis on the ACVP, TLS self-test, protocol bench,
  primitive benchmark, streaming helper, PSA driver glue, selected RNG wrapper
  sources, and the module header/version glue
- verifies that `PQCP_VERSION_STRING` and the top release entry in
  `CHANGELOG.md` stay in sync
- checks that the example west manifest snippet still reminds integrators to
  pin a tag or commit that matches `PQCP_VERSION_STRING` and `CHANGELOG.md`
- strips common host compiler environment variables before invoking `west`
- runs a tiny cost-of-assurance smoke on `qemu_x86_64` that exercises both the
  PQCP and baseline implementations for ML-KEM and ML-DSA, keeps the protocol
  path alive, and checks conservative PQCP-vs-baseline numeric guardrails from
  `scripts/qemu_cost_of_assurance_regression.json`

Use it before large refactors, before cutting a release, or when touching the
shared ACVP/TLS/benchmark infrastructure.

For a maintainer-oriented local sequence that calls the existing checks instead
of reimplementing them, run:

```bash
python scripts/verify_product_readiness.py --tag v1.0.0
```

That wrapper runs script compilation, version/changelog/tag consistency, the
pure-Python release-tool regression suite, strict extended checks, the
cost-of-assurance smoke, the consumer smoke helper, local release-bundle
generation, and the full `release_check.py` gate. By default the consumer smoke
auto-detects whether this checkout is a west manifest project; pass
`--consumer-module-mode manifest` to require true module discovery or
`--consumer-module-mode extra-module` for local development workspaces.

For memory-safety oriented hardening, pair it with the sanitizer runner:

```bash
python scripts/run_sanitizer_checks.py \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD"
```

By default this builds and runs the ACVP and TLS harness ztests on
`native_sim/native/64` with ASan and UBSan enabled. Run it from Linux, or use
the manual `run_sanitizers` toggle in `.github/workflows/extended-checks.yml`.

To probe a newer Zephyr branch or tag before bumping the documented baseline,
run:

```bash
python scripts/run_extended_checks.py \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD" \
  --zephyr-ref v4.4.0 \
  --skip-graphviz \
  --run-compatibility-smoke \
  --strict
```

That compatibility smoke builds a small, explicit set of PQCP targets against
the selected Zephyr ref and reports success or failure separately from the
static-analysis work. By default it covers the primitive, ACVP, and TLS
self-test harness targets on `qemu_x86_64`.

To probe both the default QEMU path and the STM32H7 build-only path for an
upcoming Zephyr revision, use:

```bash
python scripts/run_extended_checks.py \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD" \
  --zephyr-ref v4.4.0 \
  --skip-graphviz \
  --run-compatibility-smoke \
  --compatibility-board-list qemu_x86_64,nucleo_h743zi \
  --strict
```

## CI

GitHub Actions coverage is defined in `.github/workflows/ci.yml`. The workflow
sets up a Zephyr workspace, installs the Zephyr SDK toolchains needed for
`qemu_x86_64`, and runs on `ubuntu-22.04` with Python 3.12, Zephyr v4.4.0,
and Zephyr SDK 1.0.1.
The fast CI path runs:

- `tests/ztest_rng`
- `tests/ztest_primitive`
- `tests/ztest_acvp_serial`
- `tests/ztest_tls_selftest`
- `samples/pqcp_basic_kem`
- `samples/pqcp_basic_sig`
- build-only `samples/pqcp_bench_protocol` for `nucleo_h743zi` in both the
  default ML-KEM-768 + ML-DSA-65 lane and the single-level ML-KEM-512 +
  ML-DSA-87 lane
- a filtered `--benchmark-matrix` smoke run
- a filtered `--profile-validation` build-only smoke run with
  `scripts/resource_budgets.json`

In addition, a `release-gate` advisory job now runs on every push to `main` and
every pull request targeting `main`. It executes `python scripts/release_check.py`
and uploads the resulting log/artifact bundle, including the structured
`release_check_results.xml` JUnit report, so maintainers can spot release
workflow regressions early without turning the full release sequence into a
brittle hard gate for every branch push.

The sample runs are bounded with `timeout` and checked for expected
`PQCP_METRIC` lines so CI can validate metric emission without waiting for QEMU
samples to exit on their own.

For deeper maintenance checks, `.github/workflows/extended-checks.yml` provides
a scheduled/manual workflow that runs `scripts/run_extended_checks.py` to:

- configure a lightweight Zephyr target and emit a CMake dependency graph
- run focused `cppcheck` analysis on the ACVP, TLS self-test, protocol bench,
  primitive benchmark, selected RNG wrappers, PSA driver glue, and primitive
  wrapper sources
- smoke the serial ACVP sample through the host-side driver script on
  `qemu_x86_64`
- enforce the checked-in ROM/RAM budgets for the full `qemu_x86_64`
  profile-validation matrix
- build-validate the `mps2/an385` MCU profile path through
  `tests/ztest_primitive` with `overlay-no-entropy.conf` and matching budgets

The advisory `release-gate` job in `.github/workflows/ci.yml` now runs
`python scripts/release_check.py` with a standalone `cppcheck` step before the
broader extended-checks sequence, so the uploaded JUnit report shows static
analysis as its own release criterion instead of burying it inside a larger job.
- build-validate the `nucleo_h743zi` MCU profile path through
  `tests/ztest_primitive` and `samples/pqcp_basic_kem`, again with matching
  resource budgets
- optionally probe a newer Zephyr ref by rebuilding the primitive, ACVP, and
  TLS self-test harnesses through the compatibility-smoke mode

When launched manually, the extended-checks workflow also accepts:

- a `zephyr_ref` input for trying a newer Zephyr tag/branch/commit
- a `run_sanitizers` toggle for native_sim ASan/UBSan coverage

If the manual `zephyr_ref` differs from the baseline `v4.4.0`, the workflow
also runs an explicit compatibility-smoke build step so Zephyr drift is called
out separately from the default static-analysis output.

## Releasing

Keep the next release notes in the `## [Unreleased]` block in
[`CHANGELOG.md`](../CHANGELOG.md).
Before tagging, run the full release gate locally:

```bash
python scripts/release_check.py --tag v1.0.0
```

Then validate the full GitHub Actions release path without publishing:

```bash
gh workflow run release-dry-run.yml --ref main -f release_ref=main
```

Wait for `release-dry-run.yml` to complete successfully on `main`, then create
and push the annotated release tag:

```bash
git tag -a v1.0.0 -m "Release v1.0.0: publication-quality PQC stack"
git push origin v1.0.0
```

The tag-triggered workflow at
[`release.yml`](../.github/workflows/release.yml)
automatically:

- runs `python scripts/release_check.py` and stops the release if it fails;
- builds every sample and ztest on `qemu_x86_64`;
- uploads `release_check_results.xml`, `build_summary.txt`, the release log, and the per-build logs as workflow artifacts;
- creates a GitHub Release titled with the tag name and populated from the
  matching versioned changelog section, with the empty `## [Unreleased]`
  placeholder preserved for the next cycle.

The companion
[`release-dry-run.yml`](../.github/workflows/release-dry-run.yml)
workflow runs the same gate, QEMU builds, and changelog extraction steps
without publishing a GitHub Release. Use it to validate the release pipeline on
`main` before pushing any release tag.

When GitHub Actions or GitHub Releases are unavailable, maintainers can still
prepare local, auditable release artifacts without mutating the source tree:

```bash
python scripts/prepare_release_bundle.py --tag v1.0.0
```

For an exact source bundle, check out the tag first and require the selected tag
to point at the current checkout:

```bash
git checkout v1.0.0
python scripts/prepare_release_bundle.py --exact-tag --verify-remote-tag
```

The local bundle is written under `output/release/<tag>/` and includes release
notes extracted from `CHANGELOG.md`, API documentation generated from
`docs/Doxyfile`, and a JSON manifest recording the version, tag object, tag
commit, source commit, Zephyr revision, release date, and dependency pins. See
[`docs/release.md`](release.md) for the full local packaging workflow.
For a command-by-command maintainer checklist, see
[`docs/maintainer-release-checklist.md`](maintainer-release-checklist.md).

Once the tagged release is out, move the `## [Unreleased]` content into a
versioned heading such as `## [0.9.0] - 2026-04-17`, add a fresh empty
`## [Unreleased]` section above it, and commit that rollover to start the next
cycle cleanly.

Fast CI is therefore pinned to a known-good baseline, while extended checks can
be used to probe upcoming Zephyr drift before it reaches downstream consumers.

## Release Metadata

Downstream consumers can track the formal module version through:

- `include/pqcp_zephyr/version.h`
- `CHANGELOG.md`

The current release version is `1.0.0`, exported through both
`PQCP_ZEPHYR_VERSION_STRING` and the compatibility alias `PQCP_VERSION_STRING`.
The extended-checks helper verifies that the compatibility macro and the top
release entry in `CHANGELOG.md` stay aligned. It also checks that the README's
example west manifest snippet keeps the release pinning guidance intact for
integrators.

### Release Candidate Checklist

For a release-candidate pass, run the following sequence from the module root:

```bash
python scripts/run_extended_checks.py \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD" \
  --strict

python scripts/run_benchmarks.py \
  --profile-validation \
  --build-only \
  --resource-budgets scripts/resource_budgets.json \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD" \
  --output benchmark_results/profile-budget-rc

python scripts/run_extended_checks.py \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD" \
  --zephyr-ref v4.4.0 \
  --skip-graphviz \
  --run-compatibility-smoke \
  --compatibility-board-list qemu_x86_64,nucleo_h743zi \
  --strict

python scripts/run_sanitizer_checks.py \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD" \
  --build-only

west build -p always -d build-acvp-release -b qemu_x86_64 samples/pqcp_serial_acvp -- \
  -DZEPHYR_EXTRA_MODULES="$PWD"
python scripts/run_acvp_serial_session.py \
  --cwd /path/to/zephyrproject \
  --run-command "west build -d build-acvp-release -t run" \
  --scenario-file scripts/acvp_smoke_scenarios.json \
  --json-out acvp-release-smoke.json
```

## v1.0.0 Release Status

- [x] CI: west Twister discovery job
- [x] CI: KAT vector NIST provenance verification
- [x] CI: `nucleo_h743zi` protocol suite builds on CI runners
- [x] Completeness: ML-KEM-1024 + ML-DSA-87 KAT vectors
- [x] Robustness: ACVP readline timeout / deeper mid-frame stall detection coverage
