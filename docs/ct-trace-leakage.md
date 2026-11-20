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
