# Contributing to pqcp-zephyr-trust-stack

Thank you for helping improve this Zephyr PQC module. This document
focuses on the operational contracts that are easy to get wrong: how
benchmark artifacts are generated, how the release gate is expected to
behave, and what is intentionally *not* committed.

## Commit style

We use [Conventional Commits](https://www.conventionalcommits.org/)
prefixes: `feat`, `fix`, `docs`, `ci`, `chore`, `refactor`, `test`,
`perf`. The subject line should describe intent, not mechanics.

## Regenerating `benchmark_results.csv` and its provenance sidecar

The file `results/benchmark_results.csv` is deliberately **not**
checked into the repository. `results/*.csv` is in `.gitignore`, and
the only tracked file under `results/` is `.gitkeep`. We do not commit
benchmark CSVs because:

1. They are machine-, toolchain-, and timestamp-dependent, so any
   committed copy becomes stale the moment Zephyr, the SDK, or a
   provider module bumps.
2. The release gate (`scripts/release_check.py`) regenerates the CSV
   and its provenance sidecar on every run and validates them with
   the same tooling a reviewer would use.
3. Any committed numeric benchmark artifact would be indistinguishable
   from fabrication at review time.

To regenerate the CSV locally you need:

- A Linux or macOS host with a working Zephyr workspace and the
  Zephyr SDK installed (`$ZEPHYR_SDK_INSTALL_DIR` set).
- The `west` tool on `PATH` (or invocable via `python3 -m west`).
- QEMU for `qemu_x86_64` available to Zephyr (the host must be able
  to run `west build ... -p qemu_x86_64` and `west twister` for the
  same platform).

Then, from the workspace root that contains this module:

```bash
# Full matrix (uses scripts/cost_of_assurance_matrix.json):
python3 scripts/export_results.py \
  --platform qemu_x86_64 \
  --output results/benchmark_results.csv

# Validate the freshly-written CSV and its auto-generated
# benchmark_provenance.json sidecar:
python3 scripts/export_results.py \
  --validate-only results/benchmark_results.csv \
  --verify-provenance
```

The second invocation reads `results/benchmark_provenance.json` next
to the CSV and verifies that the recorded `csv.sha256` matches the
actual CSV on disk. Both the CSV and the sidecar are gitignored; you
should not commit them. Share them as CI artifacts instead.

For a fast, deterministic subset (36 rows of ML-KEM / ML-DSA primitive
runs) use `--smoke`:

```bash
python3 scripts/export_results.py \
  --smoke \
  --output benchmark_smoke.csv \
  --provenance-output benchmark_provenance.json
```

This is the mode used by `release-dry-run.yml` and `release_check.py`.

## Release gate

`scripts/release_check.py` is the single authoritative release gate.
It chains: version consistency → cppcheck → strict extended checks →
sanitizer builds (`run_sanitizer_checks.py`) → cost-of-assurance smoke
→ ACVP serial regression → KAT provenance → KAT build/run → benchmark
CSV export → `--validate-only --verify-provenance` → MCU resource
budget build → profile validation.

Do not add a step that can fail silently, and do not make any
existing step advisory (`|| true`, `continue-on-error: true`, caught
exceptions that print but return success, etc.). The GitHub Actions
`release-gate` job in `.github/workflows/ci.yml` is explicitly
blocking on `main` pushes, PRs targeting `main`, and tag pushes — do
not re-add `continue-on-error` to that job.

## Local verification before opening a PR

At a minimum, run:

```bash
python3 -m py_compile $(git ls-files 'scripts/*.py')
python3 scripts/run_extended_checks.py --strict
```

Sanitizer and MCU budget builds require a Linux host with the Zephyr
SDK. `run_sanitizer_checks.py` is strict on CI (returns non-zero on
unsupported hosts if `CI=1`, `GITHUB_ACTIONS=true`, or
`PQCP_STRICT_SANITIZERS=1` is set) and graceful locally.

## Re-baselining MCU resource budgets

`scripts/resource_budgets.json` declares ROM/RAM envelopes that
`scripts/check_resource_budgets.py` enforces for the `nucleo_h743zi`
`pqcp_bench_protocol` rows, and that `scripts/run_extended_checks.py`
inspects informationally for qemu/mps2 rows. Each entry carries a
`status` field:

- `"measured"` — the limit comes from a real build captured on a host
  with the Zephyr SDK (see `measured_sdk`, `measured_toolchain`,
  `measured_at`, `measured_rom_bytes`, `measured_ram_bytes`).
- `"estimated_pending_ci_baseline"` — the limit is a safe upper bound
  carried over from an earlier release and has not yet been re-measured
  on the current toolchain. Treat it as a ceiling, not a performance
  claim.

Before tagging a new major release:

1. Activate the Zephyr workspace (`source zephyr/zephyr-env.sh`, ensure
   `west`, `arm-zephyr-eabi-gcc`, and the SDK are all present).
2. Run `python3 scripts/check_resource_budgets.py --board nucleo_h743zi
   --output-root benchmark_results/mcu_baseline`.
3. The tool prints the measured ROM and RAM per `run_id`. For each
   matching entry in `scripts/resource_budgets.json`, update
   `measured_rom_bytes`, `measured_ram_bytes`, `measured_sdk`,
   `measured_toolchain`, `measured_at`, and recompute
   `rom_bytes_max = ceil(measured_rom_bytes * 1.10)` and
   `ram_bytes_max = ceil(measured_ram_bytes * 1.10)`.
4. Convert any remaining `"estimated_pending_ci_baseline"` entries that
   you have a measurement lane for into `"measured"` entries.
5. Commit the update with rationale in the commit body (build host,
   SDK version, why any entry deliberately remains estimated).

The `benchmark-smoke` CI job uploads the qemu `benchmark_smoke.csv`
and its provenance sidecar as an artifact on every successful run, but
does not gate the release — it is reference data, not truth. Do not
treat CI artifacts as a substitute for the explicit re-baselining
step above.

## IDE metadata

Do not commit IDE or editor metadata. `.cursor/`, `.vscode/`, and
`.idea/` are gitignored. Keep them that way.
