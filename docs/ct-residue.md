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

## Results

ML-DSA-65 signing, 6 key variants for each of 3 messages, three optimisation
levels. The window is the 200 KiB below the begin marker's stack pointer
(inside the 256 KiB test stack). A first Cortex-M4 run used a 1 MiB window and
counted about 820 words that were really the global signature buffer sitting
just below the stack object, so the window was narrowed; the x86_64 numbers did
not change.

| target | level | non-zero words after return | words that differ between secret variants |
|---|---|---|---|
| x86_64 | -Os / -O2 / -Og | 328 / 329 / 302 | 2 / 2 / 2 |
| Cortex-M4 | -Os / -O2 / -Og | 396 / 399 / 332 | 4 / 7 / 5 |

Manual attribution of every differing word (the analysis lists the last
writing function and the values):

- x86_64, all levels. Two words in the prologue frame of the library entry
  point. They hold the harness loop index (0 to 5) and the saved CPU flags,
  which are caller state, not library data.
- Cortex-M4, all levels. One word holding the harness loop index in the frame
  of the signing wrapper.
- Cortex-M4. Hint position words (values such as 0x29, 0x1f, 0x2b) left in the
  frames of the hint packing and `memset`. They are part of the signature and
  therefore public.
- Cortex-M4. Words holding flash addresses such as 0x5dfd8 or 0x57d9b in the
  frames of the signing core and the z packing. They are saved return
  addresses that depend on the control flow.
- Cortex-M4 at -O2 only. Two words in the frame of the norm check
  (`polyveck_chknorm`) with coefficient like values (for example 0xfffffb21,
  0x2448, 0x48bd) and a sign mask. They look like the last coefficient examined
  by the check. Which vector it came from (z, w0 minus c s2, or c t0) was not
  determined, so this is the single residue candidate that may depend on the
  secret.

H15 is not supported on x86_64 (no library data differs) and only weakly
supported on the Cortex-M4 (one candidate pair at -O2). H16 holds: no
differing word lies in a frame the library zeroizes by name. H17 was not run,
because the stack wipe is only worth building if the candidate is confirmed.
After the call the library leaves about 300 to 400 non-zero words in the
window, a small fraction of the stack it used (about 21,000 words were written).

The residue check is not part of the release gate. A confirmed leak of
coefficients from the norm check would need a decision about a wipe wrapper
and a gate claim.


## ML-KEM-768 decapsulation (registered before the run)

The same method applies to decapsulation, with a weaker relation. Regions of
one group share the key and differ in the ciphertext (valid and corrupted), so
a differing word depends on the ciphertext or on values derived from the
secret key and the ciphertext, such as the decrypted message or the implicit
rejection key. The two causes cannot be separated by this relation alone, so
every differing word is attributed to its writer and read by hand. The shared
secret and the working ciphertext buffer are excluded (output and public input).

- H18. ML-KEM-768 decapsulation leaves fewer than 400 non-zero words below the
  caller's stack pointer on x86_64 and on the Cortex-M4 image at every level.
  Falsified otherwise.
- H19. Every differing word is attributable to caller state, a code address or
  a function that handles only public data. A differing word in the frame of a
  function that processes the decrypted message or the rejection key
  (`indcpa_dec`, `poly_tomsg`, the key derivation) is reported as a residue
  candidate.
