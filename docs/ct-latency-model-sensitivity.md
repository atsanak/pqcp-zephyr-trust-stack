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

## Follow-up: a cheap repair verified under both models

`scripts/mlkem_fixed_latency.py` offsets the operand of the one disagreeing
multiply: `ub = u + 0x10001` (both 16-bit halves always non-zero), product
`ub * C - 0x10001 * C`, an empty asm statement against constant folding. Host
check over all 3329 inputs: identical value, one CMEmu latency class instead
of two. Cortex-M3 image, three levels: the stock image still shows the site,
the repaired image has no failing site under either model, the shared-secret
digest (including implicit-rejection outputs) is identical, and the whole
decapsulation costs +0.03% / +0.06% / +0.12% instructions (-Os / -O2 / -Og),
against +34% to +75% for the full 16x16 split of claim 15 on ML-DSA. The
split is needed there because operands span the full 32-bit range; here the
operand domain is only [0, 3328], which is what makes an offset sufficient.

## Second registration: do the findings generalise across ML-KEM parameter sets?

Registered before any 512 / 1024 measurement. The 768 image uses the 10-bit
compression (`mlk_scalar_compress_d10`, constant 2642263040); ML-KEM-1024 uses
the 11-bit one (constant 5284526080, which does not fit 32 bits).

- H5. ML-KEM-1024 decapsulation on the Cortex-M3 image has at least one
  CMEmu-only site (the d11 multiply) and no documented-model site, at all three
  optimisation levels. Falsified if the compiler lowers the 33-bit constant
  without a variable-latency long multiply and no site appears.
- H6. ML-KEM-512 shows the same pattern as 768 (exactly one CMEmu-only site,
  in the d10 compression). Falsified if the count or the function differs.
- H7. Extending the operand-offset repair to the d11 multiply leaves no failing
  site under either model for 1024, with an unchanged shared-secret digest and
  under 0.5% instruction overhead. Falsified otherwise.

### Results of the second registration

Cortex-M3 image, QEMU, three optimisation levels, stock versus repaired:

| parameter set | multiply | stock CMEmu-only sites | repaired failing sites (both models) | digest | instruction overhead |
|---|---|---|---|---|---|
| ML-KEM-512 | d10 | 1 | 0 | equal | +0.03 / +0.06 / +0.12% |
| ML-KEM-768 | d10 | 1 | 0 | equal | +0.03 / +0.06 / +0.12% |
| ML-KEM-1024 | d11 | 1 | 0 | equal | -0.01 / +0.06 / +0.11% |

H5, H6 and H7 all hold. The documented model reports no site at any parameter
set, so the disagreement is the same one-per-image pattern everywhere: the
post-KyberSlash compression multiply, in `mlk_poly_compress_d10_c` for 512 and
768 and `mlk_poly_compress_d11_c` for 1024. The negative figure at 1024 -O is
a code-generation difference of a few instructions, not a saving.

## Third registration: how large is the modelled leak?

Registered before measuring. The verdicts so far are binary (a site's latency
class varies or not). A reviewer's first question is "one cycle, so what?".
The plugin will additionally sum, per site, the CMEmu latency of every
executed variable-latency instruction (completion cycle of the result), and
the analysis compares the per-region totals across ciphertext classes within
one key.

- H8. On the stock Cortex-M3 image the modelled variable-latency cycle total of
  a decapsulation differs between ciphertexts of one key (maximum spread of at
  least 1 cycle) for ML-KEM-512, 768 and 1024 at every optimisation level, and
  is exactly 0 on the repaired image. Falsified if the stock spread is 0
  anywhere or the repaired spread is non-zero anywhere.
- H9. The spread is small: at most 8 cycles in a decapsulation of more than a
  million instructions, i.e. a relative amplitude below 1e-5. Falsified if
  larger. This is a scale statement about what the model implies, not a claim
  that the difference is observable or exploitable.

### Results of the third registration

Modelled variable-latency cycle totals of one decapsulation, per key group
(8 keys), Cortex-M3 image, all three optimisation levels:

| parameter set | stock spread | repaired spread | instructions per decapsulation |
|---|---|---|---|
| ML-KEM-512 | 1 cycle | 0 | about 0.82-0.87 million |
| ML-KEM-768 | 2 cycles | 0 | about 1.29-1.33 million |
| ML-KEM-1024 | 2 cycles | 0 | about 1.89-1.93 million |

H8 holds (stock spread at least 1 everywhere, repaired exactly 0 everywhere)
and H9 holds (at most 2 cycles on more than 800 thousand instructions, a
relative amplitude of about 1e-6). The honest reading is that under the CMEmu
model the secret-dependent part of a decapsulation is one or two cycles, the
number of zero coefficients in the re-encrypted polynomial. That is far below
what a remote timing measurement could resolve; it is a statement about the
model's scale, not about observability, and it is the reason this finding is
presented as a model disagreement and not as an attack. The repaired image
spends a constant, secret-independent number of variable-latency cycles
(for example 4608 against 2302-2304 for 768).

## Fourth registration: does the signing-attempt count depend on the key?

A different question, with a measurement instead of a model: ML-DSA signing
repeats until the checks pass, and the number of attempts is visible to a
timing observer. FIPS 204 and the Dilithium analysis argue that the z-norm
check accepts with a key-independent probability (z = y + c*s1 with y uniform
over a range wider than the bound on c*s1), while the r0, c*t0 and hint-count
checks depend on s2 and t0 and are only argued to be close to key-independent.
`scripts/mldsa_rejection_study.py` counts attempts on a host build of the real
mldsa-native (ML-DSA-65, deterministic signing, a private patched copy that
exports the attempt counter) over K keys and M messages per key and tests the
per-key attempt distributions for homogeneity (chi-square) and the per-key mean
for correlation with key statistics (sum of |s1|, |s2|, |t0| coefficients).

Prediction from the theory: key-independent to within sampling noise.

- H10. The attempt-count distribution differs between keys more than sampling
  noise allows (chi-square homogeneity over K = 200 keys, M = 5000 messages,
  p < 1e-3). Falsified if p >= 1e-3: the data are then consistent with a
  key-independent attempt distribution at this resolution.
- H11. Conditional on H10, the per-key mean attempt count correlates with at
  least one key statistic with |Pearson r| >= 0.2. Falsified otherwise.

Either outcome is reported: a significant dependence would be a finding about
the rejection channel, a null result is a measured bound on it.

### Results of the fourth registration

Host build of mldsa-native, ML-DSA-65, deterministic signing, 200 keys x 5000
messages (one million signatures):

- pooled mean 5.144 attempts per signature;
- chi-square homogeneity of the per-key attempt distributions: chi2 = 5481.9
  on 5373 degrees of freedom, p = 0.147;
- spread of the per-key means 1.30% (relative standard deviation), against
  about 1.27% expected from sampling noise alone for a distribution of this
  width, so no key-to-key variation is resolved beyond noise (the excess is
  below roughly 0.5%);
- correlation of the per-key mean with sum|s1|, sum|s2|, sum|t0|: r = 0.054,
  -0.010, 0.128 (|r| = 0.139 is the 5% two-sided limit for 200 keys).

H10 is falsified (p >= 1e-3) and H11 does not apply. The measured reading
matches the theory: at this resolution the signing-attempt count is
key-independent for this implementation. This is a null result with a stated
resolution, not a proof: a dependence below about 0.5% of the mean, or one
specific to rare keys, would not show up in 200 keys; it covers ML-DSA-65 only,
a host build (not the Cortex-M image), deterministic signing, random keys (not
adversarial ones) and random messages.

