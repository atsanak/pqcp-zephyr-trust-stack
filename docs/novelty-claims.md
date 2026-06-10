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
with a C compiler and a fixed seed reproduces any run. 2M mutated inputs
across four seeds produced zero findings.

**Non-claims.** Deterministic mutational fuzzing with a fixed corpus is
weaker than coverage-guided fuzzing; absence of findings is not absence of
bugs.

## Combined novelty

Taken together, the repository demonstrates — to our knowledge for the
first time in an open Zephyr PQC module — a firmware-emitted, host-
replayable, **ML-DSA-self-signed** deployment assurance passport whose
every terminal artifact is independently re-verifiable from a serial
transcript with nothing but a C compiler, backed by instruction-count CT
evidence and a fuzzed parser surface. The honest framing of each
non-claim is itself part of the contribution: the stack is designed to be
hard to overclaim.

## Reproducing the evidence

| Claim | Build/run | Marker |
|-------|-----------|--------|
| 1 | `python3 scripts/run_evidence_chain_replay.py` | `pqcp-evidence-verify: CHAIN OK` |
| 2 | `tests/ztest_deployment_passport_signature` + `pqcp-evidence-verify --require-signature` | `signature_present=true ... verified=true` |
| 3 | `python3 scripts/run_ct_instruction_checks.py` | `PQCP_CT_INSTRUCTION_COUNT PASS` |
| 4 | `python3 scripts/run_fuzz_checks.py` | `PQCP_FUZZ PASS` per seed |

All four are required steps in `scripts/release_check.py` and required
claims in `scripts/assurance_claims.json` (schema 8).
