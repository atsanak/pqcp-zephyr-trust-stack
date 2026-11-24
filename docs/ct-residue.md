# Memory residue after the call returns

Hypotheses and protocol, registered before any measurement.

## Question

When ML-DSA signing or ML-KEM decapsulation returns, does the memory below the
caller's stack pointer still hold data that depends on the secret key? The
leakage tests so far observe only the trace while the call runs. They say
nothing about what the call leaves behind in callee frames.

## Method

The trace plugin gets a `residue=1` option. It records, for every store inside
a traced region that lands below the stack pointer at the begin marker, the
word address and the program counter of the last writer. At the end marker it
reads each recorded word back and emits `PQCP_CT_RESIDUE` lines with the
non-zero values. Regions of one group share every public input and differ only
in the secret (the crafted key variants of the signing test), so a word whose
value differs inside a group depends on the secret. The output buffers are
global, not on the stack, and are therefore excluded by construction. Each
differing word is attributed to the function of its last writer.

## Hypotheses

- H15. Stock ML-DSA-65 signing leaves at least one secret dependent word below
  the caller's stack pointer, at every optimisation level, on x86_64 and on
  the Cortex-M4 image. Falsified if no word differs.
- H16. No differing word lies in a frame of a function that the library
  claims to zeroize by name. A differing word attributed to such a function is
  reported as an upstream defect. Falsified by any such word.
- H17. A stack wipe of the measured depth after each call (an opt-in wrapper)
  brings the differing words to zero. Falsified if any word still differs.
  The wipe cost is measured in instructions.

## Non-claims

Emulation, not silicon. Caches, DMA and other threads are not covered. Sampled
inputs, crafted key variants that are not valid key pairs. Residue is not an
exploit and none is shown. Heap and static data are covered only where the
region writes to them below the stack pointer. The wipe depth is measured, not
proven.
