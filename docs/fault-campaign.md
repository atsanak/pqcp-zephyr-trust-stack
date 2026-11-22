# Emulated fault campaign

`tests/ztest_fault_oracle` prints one observation line per scenario (genuine
and corrupted ML-KEM ciphertexts, genuine and tampered ML-DSA signatures and
messages). `scripts/fault_inject.py` lists instruction sites (nm/objdump of
the SDK), builds SKIP and JCC_INV faults and patches a copy of
`zephyr-qemu-main.elf` (ELF32 PT_LOAD mapping, bytes verified before
patching). `scripts/fault_oracle.py` classifies each run: KEM_FO_BYPASS and
SIG_VERIFY_BYPASS (exploitable), FAIL_SAFE, DETECTED_BOOT, CORRUPT,
NO_EFFECT, CRASH, TIMEOUT. `scripts/run_fault_campaign.py --variant
plain|boot|boot-negative` runs everything (4 parallel QEMU runs) and prints
`PQCP_FAULT_CAMPAIGN ...`; `scripts/run_fault_gate.py` runs the boot and
boot-negative variants and judges them against
`scripts/fault_campaign_baseline.json`.

Calibration: three unfaulted runs identical and valid; six identity patches
NO_EFFECT. The campaign takes about 10 minutes per variant on a laptop.

Measured (388 faults): plain 9 exploitable; valid-only boot test 8;
negative-vector boot test 0. See docs/novelty-claims.md claim 10 for prior
art and non-claims. Why QEMU plugins are not used: the SDK QEMU is plugin
API v4, which cannot write registers or memory.

## Fault timing and countermeasures (claim 11)

`--timing at-boot|post-boot|transient` selects how the fault is applied.
at-boot patches the image copy (permanent from reset); post-boot writes the
patch through the QEMU gdbstub (`scripts/fault_gdb.py`, a stdlib RSP client)
at `pqcp_fault_arm(1)`; transient breaks on a site after the arm point of one
scenario (ML-KEM scenarios 2, 3; ML-DSA 5, 6, 7), patches, steps over the
patched bytes and restores. Variants: `boot-negative`, `canary`, `duplicate`,
`hardened` (canary + duplicate). `scripts/run_fault_timing_gate.py` re-runs
the base and hardened cells; the full table below was measured once.

| Variant | post-boot: faults / exploitable | transient: faults / exploitable |
|---|---|---|
| boot-negative | 350 / 9 | 932 / 9 |
| canary | 562 / 0 | 1469 / 8 |
| duplicate | 463 / 9 | 1202 / 0 |
| hardened | 593 / 0 | 1530 / 0 |

All eight campaigns: identical golden runs, 6/6 identity controls, zero
harness errors.

Pitfalls found and fixed while building it, kept here because they change how
results should be read:
- QEMU's gdbstub re-reports the same breakpoint when told to continue while
  stopped on it, so an early version of the transient injector faulted the
  first execution regardless of scenario or hit. It produced a plausible but
  wrong table (including a spurious "FO bypass" that was a faulted frame
  unwinding into mismatched callee-saved registers and redirecting the next
  scenario's input). Every continue from a breakpoint stop is now preceded by
  one step, and the oracle workload reloads its arguments from volatile
  globals.
- A site in code that never runs makes the debugger wait forever; that now
  means "the fault never happened", not a harness error. Identity controls
  also caught a step count that was wrong for non-NOP patches.
