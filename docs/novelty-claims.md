# Novelty claims and prior art

This document states, precisely, what is novel in this repository and what
is not. Each claim names the prior art it builds on and the exact thing
that is new, plus explicit non-claims. The intent is that a skeptical
reviewer can check every sentence against the code and the captured
evidence rather than against marketing.

Everything below is validated locally on macOS with Zephyr v4.4.0 and
Zephyr SDK 1.0.1 (QEMU 10.0.2). GitHub Actions hosted runners remain
blocked by account billing, so local validation is authoritative; the
release gate (`scripts/release_check.py`) re-runs every check listed here.

## Background: what already existed here

Before this work the repository already had a firmware-native deployment
evidence chain — verdict, seal, and assurance passport modules with their
replay verifiers and audit aggregators — and a host-side assurance ledger
(`scripts/assurance_claims.json`, schema 7, 57 claims) that bound build,
KAT, ACVP, benchmark, sanitizer, boot-POST, CT-smoke, CBOM, and attestation
evidence. The host passport was hash-bound and replay-verifiable but **not
signed**, and the host ledger bound **zero** firmware `PQCP_DEPLOYMENT_*`
markers: the on-device evidence chain and the host assurance system were
two disjoint trust systems.

## Claim 1 — Single-source host replay of on-device evidence

**Prior art.** in-toto and SLSA attestations, SLSA provenance, and
reproducible-build verifiers all let a third party check a build artifact.
Embedded test frameworks (Zephyr ztest, Twister) parse device serial output
on a host.

**What is new.** The host verifier `tools/evidence_verifier` is compiled
from the *unmodified firmware replay-verifier C* — the same
`deployment_evidence_verdict_replay.c`, `deployment_evidence_seal_replay.c`,
and `deployment_assurance_passport_replay.c` that run on the device —
behind a two-macro `printk`→`stdio` shim. A reviewer with only a C compiler
replays a captured device transcript, recomputes every terminal digest, and
checks the verdict→seal→passport digest bindings. Because the verifier *is*
the firmware code, there is no second implementation to drift from the
device behavior. The new ledger claim `firmware.evidence_chain_replay`
binds the captured device transcript and the host CHAIN OK verdict into one
hash-bound step, finally connecting the firmware markers to the host ledger.

**Non-claims.** This does not establish that the device is genuine or
uncompromised; it establishes that a given transcript is internally
consistent and tamper-evident under the same digest algorithm the device
used.

## Claim 2 — A PQC stack that signs its own assurance evidence

**Prior art.** in-toto/Sigstore sign attestations with (classical or PQC)
keys managed off-device. PSA Attestation and DICE produce device identity
tokens rooted in hardware. mldsa-native provides ML-DSA.

**What is new.** The firmware signs *its own* assurance passport with the
ML-DSA-65 it ships (`deployment_passport_signature`), and the host verifier
re-verifies that signature with the *same vendored mldsa-native build*. The
signing key generation is gated by the stack's own ML-DSA power-on
self-test (`boot_post_gated`). The signature is emitted over a serial
console as indexed chunk markers and reassembled host-side. This is a
closed dogfooding loop: the PQC the stack provides is the PQC that attests
the stack's evidence, end to end, with no external signing service.

**Non-claims.** The custody profile is fixed to `demo`
(`docs/passport-signing-custody.md`): a boot-ephemeral, single-use,
anonymous key. This is explicitly **not** device identity, **not** hardware
attestation, **not** revocable, and **not** resistant to a compromised
device. A production custody profile (hardware entropy, sealed storage,
provisioning, revocation) does not exist and the marker schema refuses any
value other than `custody=demo`.

## Claim 3 — Instruction-count constant-time evidence

**Prior art.** dudect and `ctgrind`/Valgrind measure timing or memory-access
constancy; the existing `security.ct_smoke` here uses a wall-clock-cycle
median bound. Compilers and tools like `binsec/rel` reason about
constant-timeness statically.

**What is new (incremental).** A QEMU TCG plugin (`tools/tcg_ct_plugin`)
counts guest instructions AND guest data memory accesses (loads and stores
separately) executed between two marker addresses resolved from the ELF
symbol table, and `scripts/run_ct_instruction_checks.py` requires every
valid-ciphertext and every corrupted-ciphertext ML-KEM-768 decapsulation
region to share one exact (insns, loads, stores) tuple (measured: 814304
instructions, 133443 loads, 106992 stores per region, identical across
both classes). This is input-independence of both the decapsulation
control flow and its memory-operation counts — two rungs above the
wall-clock bound.

**Non-claims.** This is **not** a formal constant-time proof. It does not
observe data-dependent memory *addresses* (only operation counts), nor
microarchitectural timing (caches, ports, prefetch). The project does not
claim ML-KEM is constant-time; it claims a measured, reproducible
instruction-count and memory-access-count equality under one emulator.

## Claim 4 — The evidence grammar is a fuzzed security surface

**Prior art.** libFuzzer/AFL fuzz parsers routinely; OSS-Fuzz runs them in
CI.

**What is new (modest).** The marker parsers are treated as the
attacker-visible surface they are: `tools/evidence_fuzzer` drives the
*unmodified firmware* verdict/seal parsers plus the host passport and
signature reassembler with mutated lines from real device transcripts,
under ASan+UBSan with `-fno-sanitize-recover=all`. It is a self-contained
deterministic C driver (not libFuzzer), so it runs identically on any host
with a C compiler and a fixed seed reproduces any run — and it is
coverage-guided without a fuzzer runtime: the target parsers carry
SanitizerCoverage edge instrumentation, the harness implements the
`trace_pc_guard` callbacks itself, and any input reaching a new edge is
promoted into the corpus. The same driver also fuzzes the host-portable
fleet wire parsers (deterministic CBOR, COSE_Sign1, COSE_Key, and the
policy module codec with its verifier and VM) with binary inputs seeded
from the real encoders. Those targets assert decode(encode(x)) round
trips, rejected-input hygiene and verifier/VM agreement on top of the
sanitizers (measured: ~1,400 covered edges and ~370 evolved corpus
entries per 200k-iteration campaign across all 10 targets). Its first
runs found four defects in `src/fleet_cose_sign1.c`: an unprotected-bucket
map head parsed with a one-byte rewind (so a `map(160)` bucket decoded as
an empty bucket), embedded NULs in a content-type string, an empty `kid`
that decoded to "no kid", and half-built output left behind on rejection.
All are fixed with regression cases in `tests/ztest_fleet_artifact_core`.

**Non-claims.** Coverage-guided evolution explores deeper parser states
than a fixed corpus, but absence of findings is still not absence of
bugs; the crypto backend is deliberately uninstrumented and is not the
fuzz target. The protected-channel and sovereign-channel frame codecs are
not fuzzed: they reach `runtime_internal.h`, which needs a fake
`zephyr/kernel.h` and PSA-backed helpers, a larger shim than the
printk-only alias this harness permits.

## Claim 5 — In-image adversarial self-validation of the evidence chain

**Claim.** The firmware does not only prove that its replay verifiers
accept genuine evidence; it proves, inside the same image and boot, that
they REJECT forged evidence. The tamper detection matrix renders each
terminal marker (final verdict, terminal seal, assurance passport) with
`deployment_marker_render`, applies every deterministic attack class from
`deployment_tamper_engine` (digest nibble flip, status forge, score
inflate, schema bump, nonce swap, profile swap, required-field strip,
truncation, value noise, duplicate marker, omitted marker), feeds the
result back into the UNMODIFIED replay verifier for that stage, and
requires rejection. One control cell per stage feeds the unmodified
marker and requires acceptance, so a reject-everything verifier cannot
fake coverage. The 3×12 matrix (3 controls + 33 attacks) is emitted as
`PQCP_DEPLOYMENT_TAMPER_CELL` markers plus one digest-bound
`PQCP_DEPLOYMENT_TAMPER_MATRIX` summary, replayed and audited by its own
verifier pair, and re-verified on host from the captured transcript.

**Prior art.** Negative testing of verifiers is standard practice
off-device (Wycheproof-style test vectors, fault-injection campaigns,
mutation testing). We are not aware of an embedded PQC stack that runs a
complete attack-class × verifier detection matrix in-image as runtime
evidence, with detection coverage emitted as a hash-bound, replayable
marker that a release gate can require to be 1000 permille.

**Non-claims.** The matrix proves the verifiers reject these eleven
deterministic transformation classes of their own markers; it is not a
proof of resistance against arbitrary forgery, does not cover physical or
fault attacks, and the digests involved are integrity checksums, not
cryptographic MACs.

## Claim 6 — Hash-chained evidence trail (sequence + completeness commitment)

**Claim.** The terminal chain stages already bind to each other through
embedded digests, but nothing committed to the ORDER and COMPLETENESS of
the terminal artifacts as a sequence. The evidence trail is an
append-only, forward-linked commitment in the Schneier–Kelsey secure
audit log tradition: each terminal stage digest (verdict, seal, seal
audit, passport, tamper matrix) becomes a sequenced entry whose link
digest covers the previous link, with a genesis link bound to the chain
identity (profile, top candidate, nonce). Removing, reordering, or
splicing any entry breaks the chain head; the host CLI re-derives the
genesis and every link from the captured transcript and rejects all four
manipulations (verified by `scripts/test_evidence_verifier.py` cases
14–17).

**Prior art.** Hash-chained audit logs and transparency logs are
well-established (Schneier–Kelsey, Certificate Transparency, in-toto
layouts). The contribution is the integration depth, not the data
structure: the trail is generated by the same firmware that generated the
evidence, covers an adversarial self-validation artifact, and is
replayable from a printk transcript with the same C on host.

**Non-claims.** The trail uses the project's evidence digest, not a
cryptographic hash; it is tamper-evident against accidental and
transcript-level manipulation, not against an adversary who can recompute
digests. It is scoped to one boot; cross-boot continuity remains future
work. Signing the trail head falls under the existing demo-custody
signature discussion.

## Claim 7 — Transparent appraisal receipts (a logged, verifier-bound verdict)

**Claim.** Every artifact in the stack used to be checked by one party,
the host verifier, and nothing made that verifier's VERDICT accountable:
a relying party could not tell which verifier build said "CHAIN OK", nor
whether an operator showed different verdicts to different auditors. The
host appraisal of firmware-emitted evidence is now a registered,
RATS-style Attestation Result. `pqcp-evidence-verify --emit-statement`
writes a deterministic CBOR statement binding the passport digest, the
SHA-256 of the device ML-DSA public key, the evidence trail head, the
verdict (CHAIN OK or REJECT), the SHA-256 of the verifier binary that
produced it, and the SHA-256 of the transcript. `pqcp-evidence-register`
appends statements to an RFC 9162 Merkle log built from the unmodified
firmware transparency code (`fleet_transparency_*`), signs its
checkpoints with ML-DSA-65 (the vendored mldsa-native, FIPS 204
deterministic variant), and emits inclusion receipts and
release-to-release consistency proofs. The verifier re-checks a receipt
offline against a pinned log key AND against a fresh replay of the
supplied transcript, and rejects equivocation (two validly signed
checkpoints of one log that disagree), history rewrite and rollback.
`scripts/run_transparent_appraisal.py` then runs two independently
written Merkle verifiers (the single-source C and
`scripts/rfc9162_reference.py`, stdlib only, no shared code) on every
case, requires accept/reject agreement, and requires each forgery in a
fixed list to be rejected with the expected reason, with one positive
control per class (`docs/transparent-appraisal-format.md` is the
byte-level contract both sides implement). Python cannot verify ML-DSA, so
signature-byte flips must be rejected by the C verifier while python
reports the signature as delegated; those cases sit outside the
differential count. A mutation run removes each receipt and consistency
security check in turn and the driver must notice.

**Prior art.** SCITT (IETF transparency for signed statements), Sigstore
Rekor and Certificate Transparency / Trillian log signed statements,
signatures or certificates in Merkle logs with inclusion and consistency
proofs; RFC 9162 specifies the log. IETF RATS defines Attestation Results
but no transparency or anti-equivocation story for them. SCITT receipt
profiles and Rekor use classical signatures. Differential testing of two
independent implementations is established practice (Frankencerts for
certificate validation, Cryptofuzz, Wycheproof). The contribution is
integration depth, not a new data structure: an appraisal result bound to
the identity of the verifier that produced it, logged, countersigned with
the PQC the stack ships, and cross-checked by a second Merkle
implementation inside the release gate.

**Non-claims.** The log key is a demo key derived from a fixed public
seed, not production custody. There is no witness cosigning and no
quorum: the log is single-operator, so a split view is detected only by a
party that holds two of its checkpoints. The verifier binary hash
identifies the verifier; it does not prove the verifier correct. A
receipt shows the verdict was logged, not that the device is genuine
(the device passport signature is still demo custody, see claim 2).
Python agreement covers structure and Merkle math, not authenticity.

## Combined novelty

Taken together, the repository demonstrates — to our knowledge for the
first time in an open Zephyr PQC module — a firmware-emitted, host-
replayable, **ML-DSA-self-signed** deployment assurance passport whose
every terminal artifact is independently re-verifiable from a serial
transcript with nothing but a C compiler, backed by instruction-count CT
evidence, a fuzzed parser surface, an in-image adversarial detection
matrix over its own verifiers, and a hash-chained sequence commitment
over the terminal artifacts, and whose host verdict is itself logged in a
post-quantum-countersigned Merkle log, bound to the verifier build and
cross-checked by a second, independent Merkle implementation. The honest
framing of each
non-claim is itself part of the contribution: the stack is designed to be
hard to overclaim.

## Reproducing the evidence

| Claim | Build/run | Marker |
|-------|-----------|--------|
| 1 | `python3 scripts/run_evidence_chain_replay.py` | `pqcp-evidence-verify: CHAIN OK` |
| 2 | `tests/ztest_deployment_passport_signature` + `pqcp-evidence-verify --require-signature` | `signature_present=true ... verified=true` |
| 3 | `python3 scripts/run_ct_instruction_checks.py` | `PQCP_CT_INSTRUCTION_COUNT PASS` |
| 4 | `python3 scripts/run_fuzz_checks.py` | `PQCP_FUZZ PASS` per seed |
| 5 | `samples/pqcp_deployment_advisor` + host replay | `PQCP_DEPLOYMENT_TAMPER_MATRIX ... coverage_permille=1000` |
| 6 | `samples/pqcp_deployment_advisor` + host replay | `trail_replay=true ... trail_identity_binding=true` |
| 7 | `python3 scripts/run_transparent_appraisal.py` | `PQCP_APPRAISAL_RECEIPT PASS consistency=ok differential_agree=169/169 forgeries_rejected=156/156 controls=11/11` |
| 8 | `python3 scripts/run_model_checks.py --rediscover` | `PQCP_MODEL_REDISCOVERY PASS rediscovered=10/10` |
| 9 | `python3 scripts/run_ct_trace_checks.py --opt default --opt speed --opt debug` and `--rediscover` | `PQCP_CT_TRACE PASS ... distinct=1` and `PQCP_CT_TRACE_REDISCOVERY PASS leaks=5/5 benign_flagged=0/3` |
| 10 | `python3 scripts/run_fault_gate.py --output-dir <dir>` | `PQCP_FAULT_GATE PASS exploitable_boot=8 exploitable_boot_negative=0` |
| 11 | `python3 scripts/run_fault_timing_gate.py --output-dir <dir>` | `PQCP_FAULT_TIMING_GATE PASS base_postboot=9 base_transient=9 hardened_postboot=0 hardened_transient=0` |

Claims 1–4 are required steps in `scripts/release_check.py` and required
claims in `scripts/assurance_claims.json` (schema 8). Claims 5 and 6 ride
the same `evidence chain host replay` gate step: the host verifier fails
the step if tamper matrix or trail markers are present but inconsistent.
Claim 7 is the required claim `supply_chain.transparent_appraisal_receipt`
(schema 10) and the `transparent appraisal receipt` step of
`scripts/release_check.py`, which runs after `evidence chain host replay`.
Claim 8 is the required claim `security.state_machine_model_conformance`
(schema 11) and the `edge model conformance` step, which is full-gate only
because rediscovery needs ten QEMU builds.

## Claim 8: measured defect-finding power of in-image model-based testing

The stack tests its zero-trust edge state machines against abstract models
inside the firmware image (qemu_x86_64), shrinks any counterexample on the
device and prints it as a replayable marker. The power of the oracle is
measured, not assumed: ten defects this project found by hand
(commit `b7d4cc1`) are re-injected one at a time into a private copy of the
sources, and the models must rediscover each one automatically. The count
(10/10) is ratcheted by `scripts/model_rediscovery_baseline.json`.

Prior art: QuickCheck state-machine testing, Hypothesis stateful testing,
Jepsen/Knossos, and re-injected-fault studies (Defects4J, Magma, Just et
al. FSE 2014). Not new: model-based testing itself. New here: it runs in
the target image against PQC trust-plane firmware, and its sensitivity is a
ledger claim that can fail.

Non-claims: bounded traces (at most 64 ops, 64 seeds per module); four
modules only (principal directory, session registry, credential cache,
policy distributor); abstract models are not full specifications; no
concurrency interleavings; rediscovery of known bug classes shows
sensitivity, not absence of other defects.
Claim 9 is the required claim `security.ct_trace_relational` (schema 12);
its two gate steps (`ct trace relational`, `ct leak rediscovery`) run in the
full gate only.

## Claim 9: relational leakage testing of the deployed image, with measured power

A QEMU TCG plugin fingerprints four observation channels while the shipped
qemu_x86_64 image decapsulates ML-KEM-768: executed instruction addresses,
exact data addresses, data addresses at cache-line granularity, and the
dividend of every `div`/`idiv` (decoded from opcode bytes). For a fixed key,
a valid ciphertext and several corruptions must leave an identical
fingerprint on every channel. Variation across keys (rejection sampling of
the public matrix) is reported, not judged.

The detector is calibrated: five known PQC timing-leak patterns (clangover-
style secret branch, secret-indexed table lookup, KyberSlash-style division,
early-exit ciphertext compare, secret-dependent early `continue`) are
injected into a private copy of mlkem-native and must each be rediscovered,
while three harmless rewrites must not be flagged. Measured: 5/5
rediscovered, 0/3 false positives. The earlier counts-only evidence
(claim 3) would have missed 2/5 (the table lookup and the division), which
quantifies what the address and div channels add.

Prior art, to the best of a literature search (2024-2026): KyberSlash
(Bernstein et al., TCHES 2025) found the division leaks with a patched
Valgrind on host builds; LmSpec/LmTest (Barthe et al., CCS 2024) tests host
libraries under hypothetical leakage models; "Breaking Bad" (Schneider et
al., ASIA CCS 2025) shows compilers introduce violations; MicroWalk and DATA
compare binary traces on host binaries. Not new: trace comparison, fault
injection into detectors, declassification. New here: relational multi-channel
testing of the cross-compiled Zephyr image under whole-system emulation,
with the detector's sensitivity and specificity measured by re-injected PQC
leak patterns and enforced in the release ledger.

Non-claims: not a constant-time proof; sampled keys and ciphertexts only
(8 keys x 6 ciphertexts); x86_64 under emulation, no cache replacement,
speculation or power model, no Cortex-M timing; ML-KEM decapsulation only
(ML-DSA needs upstream declassification points and is future work); the
the clean test holds at three optimisation levels (Zephyr's default -Os, -O2, -Og; 48 regions each) but the leak re-injection runs at the default level only;
clangover itself is a Clang code-generation bug and the SDK uses GCC, so
only its source pattern is injected; the leak list is the project's own and
shows sensitivity to those patterns, not to every leak class.
Claim 10 is the required claim `security.fault_campaign_boot_selftest`
(schema 13); its gate step `fault campaign` runs in the full gate only.

## Claim 10: an emulated, crypto-aware fault campaign that measures the boot self-test

The campaign patches a copy of the deployed qemu_x86_64 image (the SDK QEMU
plugin API v4 cannot write guest state, so instruction bytes are patched
instead) at every instruction of the mlkem-native ML-KEM-768 decapsulation
and mldsa-native ML-DSA-65 verify code, with two models (skip, branch
inversion), and judges each run by cryptographic meaning: a corrupted
ciphertext yielding the genuine key (FO bypass) or a tampered signature
being accepted. It is calibrated (identical golden runs, identity patches
must be NO_EFFECT) and it measures the countermeasure instead of assuming it.

Measured over 388 faults: 9 exploitable sites on the plain image (3 FO
bypass: skipping the `mlk_ct_memcmp` call, the `neg` after it, or a `mov`
feeding the key select; 6 signature bypass, including skipping the
`mld_ct_memcmp` call), no exploitable branch inversion; the existing
valid-only power-on self-test still leaves 8 of the 9; with negative vectors
(`CONFIG_PQCP_KAT_BOOT_VERIFY_NEGATIVE`) 0 remain and 121 faults are caught
at boot instead of 111.

Prior art (verified in a 2024-2026 literature search): Krahmer et al.,
"Correction Fault Attacks on Randomized CRYSTALS-Dilithium" (TCHES 2024(3));
Glabush, Günther, Hövelmanns, Stebila, "Verifiable Decapsulation" (CRYPTO
2025), which changes the FO transform so a skipped check breaks correctness;
Kosuge and Xagawa, "The Security of ML-DSA against Fault-Injection Attacks"
(ASIACRYPT 2025), a proof-level analysis; Pesin et al., "Formally Verified
Hardening of C Programs against Hardware Fault Injection" (CPP 2025);
Xagawa et al. (ePrint 2021/840), who showed one skip bypasses the
decapsulation equality check. Not new: the fault models, emulated fault
simulation, the FO-bypass attack, negative self-test vectors. New here: a
campaign on the shipped, cross-compiled standards-track image with
cryptographic-meaning verdicts, calibration, and the boot self-test's
detection measured by ablation and enforced in the release ledger.

Non-claims: permanent single faults only, x86_64 under emulation, no
hardware fault physics, no multi-fault or data bit-flip models; callees such
as Keccak and NTT are outside the target set; no key recovery; a boot
self-test does not defend against faults injected after boot, and a fault
that also disables the self-test defeats it; fault sites that crash are not
counted as exploitable. The valid-only boot test detects 1 of the 9
exploitable sites, so it was far from sufficient, but not useless.
Claim 11 is the required claim `security.fault_timing_countermeasure`
(schema 14); its gate step `fault timing campaign` runs in the full gate only
(about 1.5 hours).

## Claim 11: fault timing as a measured axis, and a countermeasure ablation

Claim 10 left a stated gap: a boot self-test does not defend against faults
that appear after boot. This closes it with measurement. The campaign gains
two timings (permanent after boot, written through the QEMU gdbstub at an
arm point; single-shot transient, applied on one execution, stepped over and
restored) and two opt-in wrapper countermeasures:
`CONFIG_PQCP_FAULT_CANARY` (after every operation the same backend function
must reject a stored negative input) and `CONFIG_PQCP_FAULT_DUPLICATE` (two
runs must agree). Measured, every instruction of the ML-KEM-768 decapsulation
and ML-DSA-65 verify code, skip and branch-inversion models:

| Image | permanent after boot | transient single-shot |
|---|---|---|
| boot self-test with negative vectors only | 9 exploitable | 9 |
| + canary | **0** | 8 |
| + duplication | 9 | **0** |
| + canary + duplication | **0** | **0** |

Each countermeasure covers exactly the timing its design predicts: the
canary shares the fault with the real operation (a permanent fault defeats
both, which is how it is detected) but not a transient one; duplication
detects a transient fault because two runs disagree but not a permanent one
(both runs are corrupted identically). Only the combination is clean on both.
Predictions were written down before the measurement (see
docs/fault-campaign.md); they held, after the measurement tool was fixed.

Prior art (verified in the 2024-2026 literature search): Verifiable
Decapsulation (Glabush et al., CRYPTO 2025) changes the transform so a
skipped check breaks correctness, which this does not and cannot do for a
standardised ML-KEM; Pesin et al. (CPP 2025) verify duplication-style
hardening for C programs; Kosuge and Xagawa (ASIACRYPT 2025) analyse ML-DSA
fault security at proof level; Krahmer et al. (TCHES 2024) attack signing.
Not new: temporal duplication, negative self-test vectors, the FO-bypass
attack. New here: fault timing measured on the shipped image with
cryptographic verdicts, the countermeasure ablation by timing, and its
enforcement in the release ledger with a sensitivity floor.

Non-claims: single faults only (two faults can defeat the compare itself, and
a fault in a callee's frame setup can unwind past the wrapper's checks: the
wrappers now compute into a private buffer and hand the caller zeros unless
every check passes, but this is not a proof); the transient model faults the
first execution of each site; x86_64 under emulation; no hardware fault
physics; callees such as Keccak and NTT are outside the target set; results
depend on this build's layout and compiler; the countermeasures cost about
one extra operation per call each, plus about 8 KB of RAM for the canary; the
ML-DSA duplicate compares return codes only.

## Claim 12: relational leakage testing of ML-DSA signing, modulo declassification

Claim 9 compares whole traces, which cannot work for signing: ML-DSA retries
until its norm checks pass, so the number of iterations (12 to 43 declassified
events per signature in the sampled inputs) legitimately depends on the
secret. mldsa-native already marks every point where secret-derived data
becomes public with `MLD_CT_TESTING_DECLASSIFY` (used upstream with valgrind).
This claim reuses those annotations as boundaries: a shim `<valgrind/memcheck.h>`
(tests/ztest_ct_trace_mldsa/shim) routes the macro to a marker the TCG plugin
hooks (`event=`), which cuts each signing into segments. The relation is
relational noninterference modulo declassification: two executions that agree
on every declassified value so far (call site, length, value class) must run
the next segment identically on pc, exact data address, cache line and
div/idiv dividend, and reach the same next site. Disagreement is behaviour
the upstream policy does not explain. The vendored library is not modified.

The input family fixes rho, K, tr, the message and the hedging randomness and
varies only s1, s2, t0, so commitment and first challenge coincide across
variants and the secret-dependent segments (c*s1, z, the norm checks) are
actually compared, including past a rejection when two runs reject
identically. Measured: 18 signings, 600 segments, 546 comparable (91%), 8
declassification sites, 0 violations at -Os, -O2 and -Og. Detector power:
four injected leaks on the secret path (branch, table lookup, KyberSlash-style
division, early continue) are all reported (4/4) and three benign changes are
not flagged (0/3); a totals-only check (insns, loads, stores) would have
missed 2 of the 4 (the table lookup and the division).

Prior art: declassification-based noninterference is classical (Sabelfeld and
Sands); ctgrind/valgrind-style secret tracking is how upstream uses the
annotations; Binsec/Rel and similar tools check relational properties
symbolically on binaries. Not new: the property, the annotations. New here: the
annotations used as trace segment boundaries in a differential, four-channel
trace test of the deployed Zephyr image, input design that makes rejection
loops comparable, and measured sensitivity/specificity enforced by the release
ledger (`security.ct_trace_declassified`, schema 15; steps `ct trace
declassified` and `ct leak rediscovery declassified`, full gate only).

Non-claims: the declassification policy is upstream's and is trusted, not
proven; segments that follow a declassified large buffer are public-data
processing and compare only when their inputs coincide (singletons, 9% here,
are untested); the crafted keys are not valid key pairs; sampled inputs on an
emulated x86_64 image, no microarchitecture, no ARM timing; the relation is
stricter than upstream in one way (an early exit inside a norm check that
upstream says could be leaked would be reported). Not a constant-time proof.

## Claim 13: operand-dependent latency on Cortex-M3, a channel the x86 trace test cannot see

Claims 9 and 12 observe an x86_64 image, where the only variable-latency
instruction modelled is `div`. The deployed targets of a Zephyr PQC stack are
Cortex-M cores, and a Cortex-M3 has two such instruction classes: `UDIV` and
`SDIV`, and the long multiplies `UMULL`, `SMULL`, `UMLAL` and `SMLAL`, which
ARM documents as terminating early on the size of the operands (DDI 0337,
instruction timing; BearSSL's measurements add that real M3 devices deviate
from that rule). The pqcp_ct_trace plugin now runs against `qemu-system-arm`:
it masks the Thumb bit of the marker symbols, decodes the Thumb-2 encodings
(the SDK's QEMU has no disassembler) and, for every such instruction executed
in a decapsulation region, accumulates per instruction address a hash of the
exact operands, of their bit lengths, and of the documented long-multiply
predicate (both operands below 65536). `tests/ztest_ct_trace` is reused
unchanged on `mps2/an385`.

Verdict model: a division fails on any bit-length variation between the valid
and corrupted ciphertexts of one key; a long multiply fails on a change of the
documented predicate; a site executed a different number of times fails; the
address-level channels must also be identical. The conservative reading is
kept as an inventory instead of being hidden: a site whose exact operands vary
while the documented model is constant is a *candidate*, and the release
ledger ratchets the candidate count against
`scripts/ct_vlat_inventory_baseline.json`.

Measured on the shipped ML-KEM-768: address channels are clean on the M3 image
and the verdict passes at -Os, -O2 and -Og. The only variable-latency
instruction reached inside decapsulation is one `UMULL` in
`mlk_poly_compress_d10` (768 executions per decapsulation) whose operand is the
re-encrypted, secret-derived coefficient; the other operand is a constant above
65536, so the documented predicate is constant and the site is reported as a
candidate, not a failure. That is a finding about the build, not a clean bill:
whether it leaks on silicon depends on how the multiplier really terminates,
which an emulator cannot say.

Detector power: a UDIV and an SDIV of a decrypted coefficient by a runtime
divisor and a UMULL whose operand magnitude follows a decrypted message bit are
all reported (3/3); a UDIV on public loop operands, a UMULL of a secret
coefficient by a small constant and a dead store are not flagged (0/3). None of
the three leaks changes a branch, an address or an instruction count, so the
address-level channels of claim 9 would have missed all three. The first
version of the decoder missed the divisions because `UDIV r3, r3, lr` names
`lr`, which the register table did not cover; the rediscovery run caught it, a
concrete instance of the detector testing itself.

Prior art: early-terminating multipliers as a side channel are classical
(Grossschaedl, Oswald, Page, Tunstall, ePrint 2009/538); BearSSL's `ctmul`
notes document the M3 caveat; KyberSlash is the division instance. Not new: the
hazard, the instruction facts. New here: a differential, operand-recording
test of the deployed Zephyr image on the Cortex-M3 target with a two-model
verdict plus a ratcheted conservative inventory, and measured sensitivity and
specificity enforced by the release ledger
(`security.ct_trace_cortex_m_latency`, schema 16; steps `ct trace cortex-m
latency` and `ct leak rediscovery cortex-m latency`, full gate only).

Non-claims: operands are recorded, latency is not simulated; no hardware
measurement; one core (a Cortex-M4 or M33 has single-cycle long multiplies and
shares the divider rule, so its model differs and is not tested); ML-KEM only,
not ML-DSA on Cortex-M; conditional execution inside Thumb IT blocks is
counted when the instruction is reached; sampled inputs. Not a constant-time
proof.

## Claim 14: ML-DSA signing on two Cortex-M cores, and a core-selection finding

Claims 12 and 13 meet here. The declassification-aware signing test now runs
on 32-bit ARM, and the operand-latency fingerprints are kept per segment, so
rejection loops (whose per-site execution counts legitimately vary) are
compared segment by segment, only when the declassified prefixes coincide. The
same `tests/ztest_ct_trace_mldsa` image is built for `mps2/an385` (Cortex-M3)
and `mps2/an386` (Cortex-M4). The verdict is core-aware: an M3 long multiply
terminates early on operand size (ARM DDI 0337), so the documented predicate
(both operands below 65536) is a channel there; an M4 long multiply is
single-cycle, so it is not; both share the variable-latency divider. Exact
operand differences that the core's model does not explain are counted as
candidates, not hidden.

Measured on the shipped ML-DSA-65 (18 signings, 600 segments, 546 comparable):

- Cortex-M4 model: 0 violations at -Os, -O2 and -Og (370 candidate segments,
  where exact operands vary but the M4 model is constant).
- Cortex-M3 model: instruction addresses, data addresses, cache lines and the
  divider are clean, but the long-multiply predicate varies with the secret in
  the Montgomery reduction and NTT arithmetic (`mld_montgomery_reduce`,
  `mld_fqmul`, `mld_fqscale`, `mld_poly_pointwise_montgomery_c`): 8, 12 and 4
  instruction sites at -Os, -O2 and -Og. The gate requires the M4 run clean,
  the M3 run to show no violation on any other channel and at least one such
  finding (a positive control that the core distinction is live), and the
  site counts not to exceed `scripts/ct_vlat_signing_baseline.json`; a fix
  can only shrink them.

The practical reading is a core-selection finding: on the documented model,
this build of ML-DSA signing is only reasonable to deploy on a core with
single-cycle long multiplies. That follows ARM's documented rule; BearSSL
measured real M3 devices deviating from it, so the M3 result is a documented-
model finding, not a measured exploit.

Two harness bugs the ARM run exposed and the gate now prevents: 64-bit marker
arguments occupy register pairs on 32-bit ARM, which silently dropped the
declassified value class and made the segment comparison too lenient (the
marker now passes 32-bit arguments and the plugin masks them); and a 64-bit
FNV multiply in the harness itself compiled to a `UMULL`, a false finding
inside the test code (the digest is now 32-bit shifts and adds).

Prior art: as in claims 12 and 13 (declassification-based noninterference;
early-terminating multipliers, ePrint 2009/538; BearSSL ctmul notes).
Not new: the hazard, the instruction facts. New here: segment-wise,
declassification-aware operand-latency testing of a rejection-sampling
scheme on two cores with core-specific verdicts, an inventory ratcheted by
the release ledger (`security.ct_trace_cortex_m_signing`, schema 17; steps
`ct trace cortex-m4 signing` and `ct trace cortex-m3 signing inventory`, full
gate only).

Non-claims: operands are recorded, latency is not simulated; no hardware
measurement; two cores only (M33, M7 and M0+ are not modelled); ML-DSA-65 only;
crafted non-valid keys; the declassification policy is upstream's; sampled
inputs. Not a constant-time proof.

## Claim 15: a verified fixed-latency fix for the Cortex-M3 finding

Claim 14 left the Cortex-M3 result as a finding. This claim closes the loop:
mitigate, then verify the mitigation with the same instrument.

`scripts/mldsa_fixed_latency.py` patches a **private copy** of mldsa-native
(the vendored tree is never edited; the patch is six exact-match anchors that
fail loudly if upstream moves) so that every signed 32x32-to-64 product in the
Montgomery reduction, `mld_fqmul`, `mld_fqscale`, the pointwise product and
the matrix-vector accumulator is built from four 16x16 partial products
computed with the 32-bit `MUL` (single-cycle on Cortex-M3/M4, constant-time on every Cortex-M) plus shifts
and adds, instead of `SMULL`. Build the copy with
`-DZEPHYR_EXTRA_MODULES=<copy>`; it is opt-in, not the default build.

`run_ct_trace_checks.py --target cortex-m3 --alg mldsa --mitigated` builds the
stock and patched images for each optimisation level and requires:

- the patched image has no violation and no attributed variable-latency site
  on any Cortex-M3 channel over 546 comparable segments;
- the stock image in the same run still shows the finding (a positive
  control: a clean result cannot come from a dead detector);
- both images produce the same FNV-1a digest over every signature of the run
  (`PQCP_CT_SIGDIGEST`), so the patch changes neither output nor control flow;
- the helper equals native 64-bit multiplication on edge values and 20
  million random pairs under UBSan (`--selftest`).

Measured (instruction counts from the trace, whole signing, no cycle model):

| level | stock M3 sites | patched sites | instruction overhead |
|---|---|---|---|
| default (-Os) | 8 | 0 | +75.1% |
| speed (-O2) | 12 | 0 | +56.4% |
| debug (-Og) | 4 | 0 | +34.3% |

The overhead is the honest price: a `SMULL` is one instruction, the fixed
helper is about a dozen. On a real M3 the cycle cost is smaller than the
instruction count suggests (an `SMULL` takes up to five cycles, a `MUL` one),
but that is not measured here. The overhead is ratcheted by
`scripts/ct_vlat_mitigation_baseline.json` so it may only shrink.

Prior art: fixed-latency multiplication from 16-bit partial products is
standard practice (BearSSL `ctmul`); Greconici, Kannwischer and Sprenkels
(ePrint 2020/1278, TCHES 2021) already observed that `smull`/`smlal` are not
constant time on the Cortex-M3 and ship a constant-time M3 Dilithium. Claim 14's
core-selection finding is therefore a known result re-measured on this
image, and this claim's technique is not new.
New here: the mitigation is machine-verified by the leak detector that found
the problem, with a positive control and an output-equivalence digest in the
same run, gated by the release ledger
(`security.ct_trace_cortex_m_mitigation`, schema 18; steps
`mldsa fixed-latency multiply selftest` and
`ct trace cortex-m3 signing mitigation`, full gate only).

Non-claims: documented-model verification under emulation with recorded
operands; no hardware, no cycle count; only multiplies are replaced (other
arithmetic is covered by the trace test on sampled inputs only); opt-in, not
default; ML-DSA-65 on Cortex-M3 only. Not a constant-time proof.

## Claim 16: latency-model sensitivity of emulation-based verdicts

An honest novelty audit of claims 1-15 (against the literature, including
CMEmu, KyberSlash, Greconici et al. ePrint 2020/1278, DATA, MicroWalk,
LmTest, "Breaking Bad") found the technique in each of them is known and the
repository's contribution is mostly measurement and gating on a deployed
Zephyr image. This claim is a measurement the existing tools do not make:
the same traces, judged by two latency models, per instruction site.

The plugin now also records a CMEmu latency-class hash per site and per
segment (`ct_latency_models.h`; the rules are re-implemented from CMEmu's
published description, no CMEmu code is used) and the analysis compares the
documented ARM model with the CMEmu model on one trace
(`PQCP_CT_TRACE_LATENCY_MODELS`). Hypotheses were committed before the run
(`docs/ct-latency-model-sensitivity.md`): H1 and H3 confirmed, H2 falsified.
Result: the models agree on every ML-DSA-65 signing site (8 / 12 / 4 stock,
0 patched) and disagree on exactly one ML-KEM-768 decapsulation site, the
`UMULL` of the post-KyberSlash multiply-and-shift in
`mlk_poly_compress_d10_c`, constant under ARM's documented rule and
data-dependent (a zero operand is one cycle faster) under CMEmu's measured
one. The claim-15 patch is clean under both.

Prior art: CMEmu (MSWiM 2025) is the model; KyberSlash (ePrint 2024/1049)
and Valgrind-based variable-time checks fix one model; Phantom Timing Leaks
(ePrint 2026/2744) warns that few-cycle effects can come from the
measurement harness. Not new: the models, the instrument. New here: a
per-site disagreement matrix between latency models on deployed PQC images,
gated by the release ledger (`security.ct_trace_cortex_m_latency_models`,
schema 19; step `ct latency model crosscheck`, the existing M3 steps supply
the traces; the ML-KEM site count can only shrink against
`scripts/ct_vlat_models_baseline.json`).

Non-claims: no exploit and no key recovery; one-cycle effect; CMEmu models
one chip revision (TI CC2650) and is not validated against silicon here; the
two classifiers share a source of rules; no cycle-accurate execution (the
CMEmu function-level simulation is future work and needs a third-party
checkout); sampled inputs. Not a constant-time proof.

## Claim 17: a cheaper repair, verified under both latency models

Claim 16 left one ML-KEM decapsulation site that only the CMEmu model flags.
This claim repairs it and verifies the repair with the instrument that found
it. The repair is an operand offset (`u + 0x10001`, removed from the 64-bit
product afterwards) that makes both 16-bit halves non-zero for every input,
applied to a private copy of mlkem-native by `scripts/mlkem_fixed_latency.py`
(the d10 compression of ML-KEM-512/768 and the d11 compression of
ML-KEM-1024). A host test covers all 3329 inputs of both (value equality; one
CMEmu latency class instead of two). On the Cortex-M3 image at all three
parameter sets the repaired decapsulation has no
failing site under the documented or the CMEmu model, the shared-secret
digest is unchanged, and the overhead is +0.03% / +0.06% / +0.12%
instructions at -Os / -O2 / -Og (at most 0.12% at any parameter set), against
+34% to +75% for the full 16x16 split used for ML-DSA in claim 15 (there the operands span 32 bits; here the domain
is [0, 3328], which is what makes an offset sufficient). Ledger claim
`security.ct_trace_cortex_m_kem_mitigation` (schema 20; steps
`mlkem fixed-latency selftest` and `ct trace cortex-m3 kem mitigation`, full
gate only; ceilings in `scripts/ct_kem_mitigation_baseline.json`).

Prior art: operand-blinding and fixed-latency multiplication are known;
Rosita and SC-Eliminator repair power and control-flow/memory leakage, not
operand-dependent latency, and none verify a repair under several latency
models. Not new: the idea of offsetting an operand. New here: a latency-model
disagreement found, repaired for a few instructions and re-verified under both
models in the same run.

Non-claims: CMEmu rules are a third party's measurements of one chip revision,
not validated against silicon here; instruction counts, not cycles; one
multiply site; opt-in, not the default build; not a constant-time proof.

