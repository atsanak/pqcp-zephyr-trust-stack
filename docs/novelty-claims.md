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

## Combined novelty

Taken together, the repository demonstrates — to our knowledge for the
first time in an open Zephyr PQC module — a firmware-emitted, host-
replayable, **ML-DSA-self-signed** deployment assurance passport whose
every terminal artifact is independently re-verifiable from a serial
transcript with nothing but a C compiler, backed by instruction-count CT
evidence, a fuzzed parser surface, an in-image adversarial detection
matrix over its own verifiers, and a hash-chained sequence commitment
over the terminal artifacts. The honest framing of each
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

Claims 1–4 are required steps in `scripts/release_check.py` and required
claims in `scripts/assurance_claims.json` (schema 8). Claims 5 and 6 ride
the same `evidence chain host replay` gate step: the host verifier fails
the step if tamper matrix or trail markers are present but inconsistent.
