# Performance Methodology

This document describes how local performance evidence is produced and
interpreted. It is intended for maintainers and reviewers comparing release
packs across toolchains, boards, or implementation backends.

## Benchmark Rows

The benchmark log contract remains additive. Existing `PQCP_METRIC` rows keep
their field order. New rows add distribution and build-context evidence:

- `cycles_min`, `cycles_median`, `cycles_p90`, `cycles_p99`, `cycles_max`, and
  `cycles_mad` summarize primitive cycle distributions.
- `sample_count` records how many samples contributed to a distribution.
- `build,metadata` rows record compiler, Zephyr version, board, backend
  selector, benchmark profile, and distribution sample cap where available.
- Protocol benchmark rows additionally report min/max/sample-count around the
  existing handshake latency percentiles.

The CSV exporter accepts these rows without requiring older consumers to know
about them. Baseline validation still checks the original required primitive
and protocol rows first.

Legacy single-observation samples are exported with a one-sample distribution
(`min = median = p90 = p99 = max`, `mad = 0`, `sample_count = 1`) so the
release pack remains explicit about the statistic available. Treat those rows
as compatibility evidence, not as a substitute for repeated hardware
measurement.

## Comparing Results

Use the following rules when comparing generated numbers:

- Prefer medians and p90/p99 values over single-run totals.
- Compare only rows with the same board, compiler, Zephyr revision, SDK
  revision, backend, and benchmark profile.
- Treat QEMU and `native_sim` as regression environments, not hardware
  performance substitutes.
- Treat imported reference CSVs as external context. They should identify the
  source, target board/class, clock assumptions, operation name, and cycle
  statistic used.

## Side-Channel Smoke Evidence

`tests/ztest_ct_smoke` emits two transcript markers:

- `PQCP_CT_SMOKE` records valid/invalid decapsulation median deltas.
- `PQCP_CT_TTEST` records a Welch-style statistic over valid/invalid timing
  samples.

These markers are regression smoke evidence only. They can catch obvious
control-flow regressions, such as returning early on invalid ciphertexts. They
are not a formal constant-time proof and do not replace physical side-channel
evaluation.

`scripts/verify_ct_instruction_policy.py` complements the runtime smoke by
scanning ML-KEM decapsulation-related disassembly for variable-latency division
instructions associated with KyberSlash-class implementation mistakes. The
default scan excludes ztest/test-harness symbols so arithmetic used by the
measurement code does not pollute the library policy result.

## Hardware And Reference Capture

`scripts/run_hardware_benchmarks.py` provides a local helper for three lanes:

- `qemu`: run the existing benchmark matrix through repository tooling.
- `transcript`: parse an already captured UART/QEMU transcript.
- `import-reference`: normalize an external reference CSV into a common report
  shape for side-by-side review.

Hardware capture is optional. Absence of a connected board must not fail a
normal local release gate unless the maintainer explicitly requests a hardware
run.
