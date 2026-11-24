# Passport signing key custody

This document is the key-custody decision required before any signing code
exists in this repository. It defines exactly what the ML-DSA passport
signature proves, how the key lives and dies, and what this feature
deliberately does **not** claim. Code that contradicts this document is a
bug.

## Decision

The deployment assurance passport may be signed on-device with
**ML-DSA-65** under a **demo-grade, boot-ephemeral key**:

- The keypair is generated in RAM by `pqcp_mldsa_keypair()` at the moment
  the signature is created, after the firmware has already reached
  `main()`. When `CONFIG_PQCP_KAT_BOOT_VERIFY=y`, reaching `main()` implies
  the ML-DSA power-on self-test passed (the boot hook panics otherwise),
  and the signature record carries `boot_post_gated=1`. Without the boot
  POST the signature is still produced but is honestly marked
  `boot_post_gated=0`.
- The secret key signs **exactly one message**, the passport digest, and
  is zeroized before the signing call returns to the caller. It is never
  stored, exported, reused, or printed.
- The public key is emitted next to the signature in the device transcript.
  It has no provenance beyond that transcript.

## What the signature proves

The signed message is the 64-character passport digest (domain-separated
with the context string `PQCP-ASSURANCE-PASSPORT-V1`), which is itself
hash-bound over the entire terminal evidence chain. A valid signature
therefore proves:

- the passport contents were not altered after the moment of signing, and
- the signer possessed an ML-DSA-65 secret key on the same boot, on the
  same image, that produced the evidence chain.

## What the signature does NOT prove (non-claims)

- **Not device identity.** The key is anonymous and ephemeral. Anyone with
  the firmware can produce a different key signing different evidence.
- **Not hardware attestation.** There is no root of trust, no measured
  boot, no secure element, no DICE/PSA identity binding.
- **Not revocable or enrollable.** There is no PKI, no certificate, no
  registration, no revocation path.
- **Not resistant to a compromised device.** A device that lies in its
  evidence chain will happily sign its lies.

## Demo RNG caveat

On QEMU validation targets the test configurations may use the
deterministic test RNG, which makes keys and signatures reproducible. That
is acceptable only because this custody profile is demo-grade. Any
deployment beyond local validation MUST use a hardware entropy source.

## Requirements before any production custody profile

A future production profile would require, at minimum: hardware entropy,
sealed key storage or key derivation from a hardware root, a provisioning
and identity-binding story, certificate or transparency-log distribution of
public keys, and a revocation mechanism. None of these exist here, and the
code must keep saying so: the marker schema reserves `custody=demo` and no
other value is currently legal.
