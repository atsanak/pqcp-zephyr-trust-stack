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
