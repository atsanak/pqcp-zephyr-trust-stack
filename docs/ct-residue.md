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

### ML-KEM-768 decapsulation, results

Eight keys with six ciphertexts each (one valid, five corrupted), three
optimisation levels.

| target | non-zero words after return | words that differ between ciphertexts | writers of the differing words |
|---|---|---|---|
| x86_64 | 246 to 265 | 109 to 124 | the Keccak permutation, the compression functions, the decapsulate frame |
| Cortex-M4 | 301 to 306 | 126 to 137 | the same |

H18 holds, since fewer than 400 non-zero words remain. Most differing words
are Keccak lane spills, which depend on the ciphertext, so H19 cannot be
settled by the relation alone. Two dictionary checks settle the question that
matters:

- Words of the secret key bytes in the residue. The key bytes of each key are
  printed by the test and every 32 bit word of them (above 0xffff) is looked
  up in the residue of that key's regions. Result 0 matches on x86_64 and on
  the Cortex-M4 at all levels, so no key word survives in its stored form.
  Keccak lanes that mix the rejection seed with the ciphertext are not
  recognisable by this check, so it excludes only the literal copy.
- Words of the call's own shared secret. Result on the Cortex-M4 at all three
  levels is 320 matches over 40 of the 48 regions, which is a complete copy of
  the 8 words in every corrupted ciphertext region (on x86_64 default it is the
  same 240 matches over 40 regions). The valid ciphertext regions show none.
  The copies are in the frames of the Keccak permutation. The output buffer
  itself is excluded. So the session key of an implicit rejection survives
  below the caller after the call returns.

### Repair and re-check

`CONFIG_PQCP_STACK_SCRUB` (default off, with `CONFIG_PQCP_STACK_SCRUB_DEPTH`,
default 16384 bytes) makes the decapsulation wrapper overwrite the stack below
the caller with 32 bit stores. On the Cortex-M4 image at the three levels:

| level | shared secret matches stock to scrubbed | non-zero words | instruction overhead |
|---|---|---|---|
| -Os | 320 to 0 | 306 to 103 | 1.25% |
| -O2 | 320 to 0 | 293 to 86 | 1.29% |
| -Og | 320 to 0 | 304 to 100 | 1.52% |

The scrub needs the configured number of bytes of stack headroom. A first
version with byte stores cost 5 to 6 percent. The depth is measured, not
proven, and ML-DSA signing used about 21,000 stack words, so it would need a
much larger depth and no wrapper exists for it yet. The check is not part of
the release gate.

### ML-DSA-65 signing wipe and the release gate

The same header (`src/crypto/stack_scrub.h`) now provides a wipe after
`pqcp_mldsa_sign` with its own depth (`CONFIG_PQCP_STACK_SCRUB_SIGN_DEPTH`,
default 108 KiB, because signing used about 21,000 stack words). On the
Cortex-M4 image the non-zero words after the call fall from 332 to 399 to 4 or
5, the only differing word is the harness loop index, the coefficient like pair
seen at -O2 is gone, the declassification aware verdict is unchanged (546
comparable segments, zero violations at all three levels) and the instruction
overhead is 1.1 to 1.2 percent.

The release gate runs `run_ct_trace_checks.py --residue-verify` on the
Cortex-M4 image. It builds the stock and the scrubbed image for decapsulation
and signing at three levels and checks the ledger claim
`security.ct_residue_scrub` (schema 23): stock residue present, no shared
secret word and less than half of the words after the wipe, the leakage verdict
intact and an overhead under the ceiling in `scripts/ct_residue_baseline.json`.
Measured overhead is 1.25 to 1.52 percent for decapsulation and 1.09 to 1.19
percent for signing.

