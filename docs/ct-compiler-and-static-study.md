# Compiler and static/dynamic constant-time study

## Registered hypotheses

The workload is ML-KEM-768 decapsulation in `tests/ztest_ct_trace`. The
comparison uses QEMU on Zephyr 4.5.0 with Zephyr SDK 1.0.1, covering x86_64
and Cortex-M3 at multiple compiler and optimisation settings.

- **H1.** On x86_64 every variant produces a clean relational result on the
  instruction-address, data-address, cache-line and division channels.
- **H2.** On Cortex-M3 every variant retains a secret-varying long multiply
  attributable to the 32×32-to-64-bit product in `compress_d10`.
- **H3.** LTO introduces no additional secret-varying site or divergent channel
  compared with the matching non-LTO build.
- **H4.** The static inventory contains every dynamically executed Cortex-M
  variable-latency site (100% recall).
- **H5.** Fewer than 10% of inventoried variable-latency instructions show
  secret-correlated operand or model variation in the sampled traces. Static
  conditional branch counts are positive and the dynamic trace detects zero
  secret-dependent control-flow divergences.

Report refutations as observed. Report unbuildable cells as `BUILD_FAIL` with
an error excerpt. A cell without a validated trace cannot confirm a hypothesis.
An empty dynamic or static denominator yields an undefined rate. Compare LTO
sites by source location and instruction kind, with unresolved attribution
recorded as such, since link-time optimisation can change addresses and names.

## Results

Zephyr 4.5.0 (`41d10b5973`), SDK 1.0.1 with GCC 14.3.0 and Clang 19.1.7,
and QEMU 10.0.2 on macOS. The firmware used the same eight deterministic
keys and six ciphertexts per key in each cell. All 13 runnable cells
captured 48 regions and shared the workload digest `0x83296830`.

The table reports the minimum and maximum number of guest instructions in
one region. Candidate sites had differing exact operands within a key
group and constant latency under the documented model. Source attribution
used the inlined location of the multiply in `mlk_scalar_compress_d10`
(`ext/mlkem-native/mlkem/src/compress.h:248`).

| Target | Variant | Result | Instructions per region | Candidate sites | Static precision | Recall |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| x86_64 | gcc-Os | CLEAN | 813,804–814,718 | 0 | n/a | n/a |
| x86_64 | gcc-O2 | CLEAN | 786,918–787,748 | 0 | n/a | n/a |
| x86_64 | gcc-O3 | CLEAN | 635,483–636,268 | 0 | n/a | n/a |
| x86_64 | gcc-Og | CLEAN | 973,867–974,992 | 0 | n/a | n/a |
| x86_64 | gcc-Os-lto | CLEAN | 812,136–813,050 | 0 | n/a | n/a |
| x86_64 | clang-Os | BUILD_FAIL | n/a | n/a | n/a | n/a |
| x86_64 | clang-O2 | BUILD_FAIL | n/a | n/a | n/a | n/a |
| x86_64 | clang-O3 | BUILD_FAIL | n/a | n/a | n/a | n/a |
| cortex-m3 | gcc-Os | CANDIDATE | 1,321,316–1,321,901 | 1 | 1.000 | 1.000 |
| cortex-m3 | gcc-O2 | CANDIDATE | 1,291,189–1,291,828 | 1 | 1.000 | 1.000 |
| cortex-m3 | gcc-O3 | CANDIDATE | 1,244,350–1,244,986 | 4 | 1.000 | 1.000 |
| cortex-m3 | gcc-Og | CANDIDATE | 1,327,539–1,328,338 | 1 | 0.250 | 1.000 |
| cortex-m3 | gcc-Os-lto | CANDIDATE | 1,325,977–1,326,562 | 1 | 1.000 | 1.000 |
| cortex-m3 | clang-Os | CANDIDATE | 1,331,486–1,332,388 | 1 | 0.167 | 1.000 |
| cortex-m3 | clang-O2 | CANDIDATE | 1,283,753–1,284,783 | 8 | 1.000 | 1.000 |
| cortex-m3 | clang-O3 | CANDIDATE | 1,219,304–1,220,334 | 24 | 1.000 | 1.000 |

The three x86_64 Clang cells failed to build. The SDK Clang driver
initially selected its host-oriented AArch64 default and lacked the
target's C headers. A probe with an explicit x86_64 triple and Zephyr's
minimal libc failed with `No available targets are compatible with triple
"x86_64-unknown-none-elf"`. The SDK Clang target list contained ARM,
AArch64 and RISC-V. The matrix records the build diagnostics and
`--strict-build` makes an unbuilt cell fail the run.

The effective flag check detected Zephyr's `-Oz` default for Clang. The
measured Clang size cell explicitly selects `-Os`. GCC LTO folded the
identical trace entry and exit markers in the first run. Distinct marker
addresses restored all 48 regions in the rerun.

### Hypothesis outcomes

- **H1 supported for the five measured x86_64 cells.** All four channels
  were clean in the four GCC optimisation levels and the GCC LTO build.
  The three unbuilt Clang cells remain untested.
- **H2 confirmed on the measured Cortex-M3 builds.** All eight builds
  showed exact operand variation at the d10 compression product. The site
  count ranged from 1 to 24. None crossed the documented latency predicate.
- **H3 confirmed for matched GCC size builds.** LTO added zero divergent
  channels and zero source-attributed candidate sites on both targets.
  On Cortex-M3 the product moved into `indcpa_enc` while retaining the same
  source location and instruction kind.
- **H4 confirmed on Cortex-M3.** In all eight runs every dynamic site
  matched the static address and instruction kind. The default GCC image
  had one observed site, 111 conditional branches and seven IT directives.
  The project-only baseline covers 12 linked functions.
- **H5 refuted.** Precision ranged from 16.7% to 100%, above the registered
  10% threshold in every Cortex-M3 cell. All measured images had static
  conditional branches and zero observed instruction-address divergence.

The denominator for precision is the count of in-scope, statically
inventoried variable-latency instructions. The numerator is the subset
with measured operand or model variation. Recall uses dynamically observed
variable-latency sites as its reference. x86_64 records division
fingerprints without site addresses, so the per-site metrics apply to
Cortex-M3. The static ratchet counts instructions in linked project
functions in the default Cortex-M3 trace image.

These measurements cover the sampled inputs under emulation and the
documented Cortex-M3 latency model. They establish neither silicon timing
nor a constant-time proof. Ciphertext changes within a fixed-key group
can also change public values, so operand variation alone cannot establish
secret dependence. The workload digest checks reproducibility of outputs.

Reproduce the matrix from the module directory with
`python3 scripts/run_ct_compiler_matrix.py`. The output directory retains
per-cell binaries, traces, logs, SHA-256 digests and `compiler_matrix.json`.
