/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - ML-DSA-signed deployment assurance passport
 *
 * Stability: experimental evidence API. This module signs the deployment
 * assurance passport digest with a demo-grade boot-ephemeral ML-DSA-65 key
 * and emits the public key and signature as chunked transcript markers. The
 * custody profile is fixed to "demo" and is documented in
 * docs/passport-signing-custody.md: the key proves passport integrity at
 * the moment of signing, not device identity, and the secret key signs one
 * message before being zeroized.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_PASSPORT_SIGNATURE_H_
#define PQCP_ZEPHYR_DEPLOYMENT_PASSPORT_SIGNATURE_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_assurance_passport.h>
#include <pqcp_zephyr/mldsa.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment passport signature records and markers. */
#define PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_SCHEMA_VERSION 1U

/** Domain-separation context bound into every passport signature. */
#define PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_CONTEXT "PQCP-ASSURANCE-PASSPORT-V1"

/** Raw payload bytes carried per chunk marker (256 hex characters). */
#define PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_CHUNK_BYTES 128U

/** Number of public-key chunk markers emitted per signature record. */
#define PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_PK_CHUNKS \
	((PQCP_MLDSA_65_PK_SIZE + \
	  PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_CHUNK_BYTES - 1U) / \
	 PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_CHUNK_BYTES)

/** Number of signature chunk markers emitted per signature record. */
#define PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_SIG_CHUNKS \
	((PQCP_MLDSA_65_SIG_SIZE + \
	  PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_CHUNK_BYTES - 1U) / \
	 PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_CHUNK_BYTES)

/**
 * Caller-owned signing workspace.
 *
 * Holds the ephemeral secret key for the duration of one
 * pqcp_deployment_passport_signature_create() call. The call zeroizes the
 * workspace before returning, success or failure; the caller never needs
 * to (and must not) read it.
 */
struct pqcp_deployment_passport_signing_state {
	/** Ephemeral ML-DSA-65 secret key; zeroized by the signing call. */
	uint8_t secret_key[PQCP_MLDSA_65_SK_SIZE];
};

/** ML-DSA-signed deployment assurance passport record. */
struct pqcp_deployment_passport_signature {
	/** Record schema version. */
	uint32_t schema_version;
	/** ML-DSA parameter set; always 65 in this schema version. */
	uint32_t mldsa_level;
	/** Public key size in bytes; always PQCP_MLDSA_65_PK_SIZE. */
	uint32_t public_key_bytes;
	/** Signature size in bytes; always PQCP_MLDSA_65_SIG_SIZE. */
	uint32_t signature_bytes;
	/** True when CONFIG_PQCP_KAT_BOOT_VERIFY gated key generation. */
	bool boot_post_gated;
	/** Passport digest that was signed. */
	char passport_digest_hex[
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS + 1U];
	/** Ephemeral ML-DSA-65 public key. */
	uint8_t public_key[PQCP_MLDSA_65_PK_SIZE];
	/** ML-DSA-65 signature over the domain-separated passport digest. */
	uint8_t signature[PQCP_MLDSA_65_SIG_SIZE];
};

/**
 * Sign one deployment assurance passport with a fresh ephemeral key.
 *
 * Generates an ML-DSA-65 keypair, signs the passport digest under the
 * domain-separation context, and zeroizes the secret key before returning.
 * The passport must carry a structurally valid digest; callers are expected
 * to have replay-verified it first.
 *
 * @retval 0        Signature record populated.
 * @retval -EINVAL  Invalid pointers or malformed passport record.
 * @retval -EIO     The ML-DSA backend failed (RNG not ready, keygen or
 *                  signing failure). The workspace is still zeroized.
 */
int pqcp_deployment_passport_signature_create(
	const struct pqcp_deployment_assurance_passport *passport,
	struct pqcp_deployment_passport_signing_state *state,
	struct pqcp_deployment_passport_signature *signature);

/**
 * Verify a passport signature record on-device.
 *
 * @retval 0        Signature is valid for this passport.
 * @retval -EINVAL  Invalid pointers or malformed record.
 * @retval -EBADMSG Digest mismatch or signature verification failure.
 */
int pqcp_deployment_passport_signature_verify(
	const struct pqcp_deployment_assurance_passport *passport,
	const struct pqcp_deployment_passport_signature *signature);

/**
 * Emit the signature record as stable transcript markers.
 *
 * Emits one PQCP_DEPLOYMENT_PASSPORT_SIGNATURE header marker followed by
 * the public key and signature as indexed PQCP_DEPLOYMENT_PASSPORT_PK_CHUNK
 * and PQCP_DEPLOYMENT_PASSPORT_SIG_CHUNK markers of at most 256 hex
 * characters each.
 *
 * @retval 0        Markers emitted.
 * @retval -EINVAL  Invalid or malformed record.
 */
int pqcp_deployment_passport_signature_emit(
	const struct pqcp_deployment_passport_signature *signature);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_PASSPORT_SIGNATURE_H_ */
