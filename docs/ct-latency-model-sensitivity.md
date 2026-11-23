# How much do emulation-based constant-time verdicts depend on the latency model?

Status: hypotheses registered before any measurement (commit order is the
record). Results are added below the line "Results" in a later commit.

## Question

Claims 13-15 judge Cortex-M3 operand-dependent latency against ARM's
documented rule (a long multiply finishes early when both operands are below
65536, ARM DDI 0337; a divide takes time that follows operand bit lengths).
CMEmu (Mimuw distributed systems group, MSWiM 2025; a cycle-exact model of a
Cortex-M3 r2p1 derived from timing measurements on a TI CC2650) uses different
rules:

- UMULL/SMULL/UMLAL/SMLAL latency depends on which 16-bit halves of each
  operand are non-zero (and, for the signed forms, on operand signs). A zero
  operand is fastest.
- UDIV/SDIV take 2 cycles if either operand is zero, 3 if the dividend has
  fewer significant bits than the divisor, else 5 + (bitlen difference)/4.

Question: for the SAME traces of deployed ML-KEM-768 decapsulation and
ML-DSA-65 signing, how often do the two models disagree on which instruction
sites leak, and does the claim-15 fixed-latency patch stay clean under the
second model?

Why the existing tools cannot answer it: Valgrind-based checks (KyberSlash),
TIMECOP, Binsec/Rel and LmTest each commit to one model or flag whole
instruction classes. None compares latency models per site on a deployed PQC
image.

## Models compared

- `documented`: the current verdict (claims 13-15).
- `cmemu`: the rules above, re-implemented here from the published
  description and checked in `scripts/ct_latency_models.py`; no CMEmu code is
  used or vendored (the CMEmu repository carries no licence file). The model
  is a third party's measurement of one chip revision; it is not validated
  here against silicon.

## Hypotheses (falsifiable)

- H1. The ML-KEM-768 decapsulation site `mlk_scalar_compress_d10`
  (`(uint64_t)u * 2642263040`, both 16-bit halves of the constant non-zero)
  is constant under `documented` but varies with the secret under `cmemu`,
  because u = 0 is one cycle faster than u != 0. Falsified if no site in the
  decapsulation trace changes verdict between the models.
- H2. At every optimisation level the number of ML-DSA-65 signing sites that
  fail under `cmemu` on the stock Cortex-M3 image is larger than the number
  that fail under `documented` (8 / 12 / 4 at -Os / -O2 / -Og). Falsified if
  the counts are equal or smaller at any level.
- H3. The claim-15 fixed-latency patch stays clean under `cmemu` at all three
  levels (no violation on any channel). Falsified if any patched site varies
  under `cmemu` (for example a long multiply by a constant outside the
  patched helper).
- If all three hold the finding is that the documented model understates the
  M3 exposure. If H1 and H2 fail the finding is a negative result: the
  documented-model verdicts of claims 13-15 are robust to this second model.

## Protocol

One trace per image and optimisation level; both models are evaluated on the
same trace (the plugin records a per-site and per-segment hash of each
model's latency class). The per-site disagreement matrix is: sites failing
under both / only `documented` / only `cmemu` / neither. Image set:
ML-KEM-768 decapsulation (stock), ML-DSA-65 signing (stock and patched), each
at default, speed and debug optimisation.

Non-claims: a model disagreement is not an exploit; one-cycle effects may be
hidden by flash wait states, prefetch and pipeline stalls (see ePrint
2026/2744 on measurement-harness effects); no silicon measurement; one chip
revision; sampled inputs; not a constant-time proof.

---

## Results

Measured on `mps2/an385` (Cortex-M3) under QEMU 10.0.2, one trace per image
and level, both models evaluated on the same trace. C and Python classifiers
agree on 315,678 operand cases (`scripts/ct_latency_models.py --crosscheck`);
note both were written from the same published rule set, so this guards
against transcription errors, not against errors in the rules.

| image | level | documented sites | cmemu sites | both | only cmemu |
|---|---|---|---|---|---|
| ML-KEM-768 decapsulation, stock | -Os | 0 | 1 | 0 | 1 |
| ML-KEM-768 decapsulation, stock | -O2 | 0 | 1 | 0 | 1 |
| ML-KEM-768 decapsulation, stock | -Og | 0 | 1 | 0 | 1 |
| ML-DSA-65 signing, stock | -Os / -O2 / -Og | 8 / 12 / 4 | 8 / 12 / 4 | 8 / 12 / 4 | 0 |
| ML-DSA-65 signing, claim-15 patch | -Os / -O2 / -Og | 0 | 0 | 0 | 0 |

- **H1 confirmed.** The only site on which the models disagree is a `UMULL`
  in `mlk_poly_compress_d10_c` at all three levels. It computes
  `(uint64_t)u * 2642263040`, the multiply-and-shift that replaced the
  secret-dependent division after KyberSlash. Under the documented model it is
  constant (both operands' halves are not examined), under CMEmu it takes one
  cycle less when u = 0, and u is the re-encrypted coefficient, so the
  difference follows the secret for a corrupted ciphertext. About 21% of
  decapsulations contain at least one zero coefficient (1 - (1 - 1/3329)^768).
- **H2 falsified.** The registered prediction (the CMEmu model flags more
  ML-DSA sites than the documented one) is wrong: all 8 / 12 / 4 stock sites
  fail under both models and no site fails only under CMEmu. Every leaking
  ML-DSA multiply already has operands that straddle the 65536 boundary, so
  the second model adds nothing there.
- **H3 confirmed.** The claim-15 patch has no violation and no failing site
  under CMEmu at all three levels (546 comparable segments, zero violations).
  It is clean under both models, which is stronger evidence than claim 15
  gave.

Reading: the documented-model verdicts of claims 13-15 are robust for
ML-DSA signing and for the patch, and understate ML-KEM decapsulation by one
site, the post-KyberSlash multiply. That site is a measured-model candidate,
not an exploit: one cycle, one chip revision's measurements (CMEmu, TI
CC2650), no silicon check here, and flash wait states or pipeline effects may
hide it.

