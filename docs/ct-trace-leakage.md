# Relational leakage testing of ML-KEM decapsulation

`tests/ztest_ct_trace` decapsulates, for each of 8 deterministic keys, one
valid and five corrupted ciphertexts from a single buffer, each bracketed by
`pqcp_ct_region_begin/end` under irq lock. `tools/tcg_ct_plugin`
(`libpqcp_ct_trace`) writes one `PQCP_CT_TRACE region=... label=...
h_pc= h_addr= h_line= h_div=` line per region. `label = key << 8 | ct`.

`scripts/ct_trace_analysis.py` requires one distinct fingerprint per channel
within every key group, reports `bits = log2(distinct)` and the 95% rule-of-
three bound `3/N`. `scripts/run_ct_trace_checks.py` builds, runs and prints
`PQCP_CT_TRACE PASS ... distinct=1 bits=0.00`.

`--rediscover` (`scripts/ct_leak_rediscovery.py`) copies the module, injects
L1-L5 (leaks) and B1-B3 (harmless) into the copy of mlkem-native, rebuilds
and classifies each as rediscovered / missed / false_positive / STALE /
ERROR, then prints `PQCP_CT_TRACE_REDISCOVERY PASS leaks=5/5
benign_flagged=0/3 missed_by_counts_only=2/5`. The baseline
(`scripts/ct_leak_rediscovery_baseline.json`) can only rise.

Implementation notes learned the hard way: the SDK QEMU exports no glib
symbols (the plugin links glib itself) and has no disassembler (x86 div is
decoded from opcode bytes); traces of different keys differ because the
public matrix is expanded by rejection sampling, so the relation is checked
within a key. See docs/novelty-claims.md claim 9 for scope and non-claims.

Optimisation levels: the clean test runs at Zephyr's default (-Os), speed
(-O2) and debug (-Og); instruction counts per region differ (about 814k,
787k, 974k) so these are genuinely different builds. An earlier `size`
level was the same build as the default and was removed.

## ML-DSA signing (declassification-aware mode)

`run_ct_trace_checks.py --alg mldsa` builds `tests/ztest_ct_trace_mldsa`. The
plugin takes `event=<addr>`; each call of `pqcp_ct_event(site, len, class)`
(reached from mldsa-native's `MLD_CT_TESTING_DECLASSIFY` through the shim
valgrind header) closes a segment and prints a `PQCP_CT_SEG` line.
`ct_trace_analysis.analyze_declassified` compares, within a message group, all
segments whose declassified prefix is identical; marker
`PQCP_CT_TRACE_DECLASS PASS ... segments=600 testable=546 violations=0`.
`--rediscover --alg mldsa` runs `ct_leak_rediscovery_mldsa.py` (4 leaks, 3
benign; baseline `ct_leak_rediscovery_mldsa_baseline.json`). See
docs/novelty-claims.md claim 12.

Pitfall found: an injected `if (secret) { __asm__ volatile(""); }` compiles to
nothing (empty asm, empty branch) and looked like a missed leak; the body needs
a real volatile store.

## Cortex-M3 operand-latency channel

`run_ct_trace_checks.py --target cortex-m3` builds `tests/ztest_ct_trace` for
`mps2/an385` and runs it under `qemu-system-arm` with the same plugin. On the
`arm` target the plugin reads r0..r2 for the marker arguments, masks the Thumb
bit of the marker addresses and emits `PQCP_CT_VLAT` lines (one per region and
instruction address) for Thumb-2 UDIV/SDIV/UMULL/SMULL/UMLAL/SMLAL.
`ct_trace_analysis.analyze_vlat` applies the two-model verdict and the
candidate inventory; marker
`PQCP_CT_TRACE_VLAT PASS ... sites=1 fail_sites=0 candidate_sites=1 base=clean`.
`--target cortex-m3 --rediscover` runs `ct_leak_rediscovery_m3.py` (3 leaks, 3
benign; baseline `ct_leak_rediscovery_m3_baseline.json`). See
docs/novelty-claims.md claim 13.

## Cortex-M signing (M3 and M4)

`run_ct_trace_checks.py --target cortex-m4 --alg mldsa` must pass;
`--target cortex-m3 --alg mldsa --measure` exits 0 when the only findings are
long-multiply predicate violations (an inventory, with a positive control).
Markers: `PQCP_CT_TRACE_VLAT_DECLASS PASS|FAIL ... vdiv_violations=
vmul_violations= other_violations= candidate_segments= attributed_sites=`.
Per-core channels: `ct_trace_analysis.CORE_CHANNELS`. The marker function
`pqcp_ct_event` takes 32-bit arguments (r0..r2 on ARM). See
docs/novelty-claims.md claim 14.

## Verified Cortex-M3 mitigation

`python3 scripts/mldsa_fixed_latency.py --selftest|--check|--apply DEST`
patches a private copy of mldsa-native with a fixed-latency 32x32->64 helper.
`run_ct_trace_checks.py --target cortex-m3 --alg mldsa --mitigated` builds
stock and patched images and prints `PQCP_CT_TRACE_VLAT_MITIGATION PASS ...
stock_vmul_violations= patched_violations=0 patched_sites=0
sig_digest_match=1 insn_overhead_pct=`. See docs/novelty-claims.md claim 15.
