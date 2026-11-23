/*
 * SPDX-License-Identifier: MIT
 *
 * ML-DSA-signed deployment assurance passport (demo custody profile).
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util_macro.h>

#include <pqcp_zephyr/deployment_passport_signature.h>

#define SIGNATURE_CONTEXT PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_CONTEXT
#define CHUNK_BYTES PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_CHUNK_BYTES
#define CHUNK_HEX_CHARS (2U * CHUNK_BYTES)

static bool digest_hex_valid(const char *value)
{
	if (value == NULL ||
	    strlen(value) !=
		    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS) {
		return false;
	}

	for (size_t i = 0U;
	     i < PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS; ++i) {
		const char c = value[i];

		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
			return false;
		}
	}

	return true;
}

static bool record_shape_valid(
	const struct pqcp_deployment_passport_signature *signature)
{
	return signature != NULL &&
	       signature->schema_version ==
		       PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_SCHEMA_VERSION &&
	       signature->mldsa_level == 65U &&
	       signature->public_key_bytes == PQCP_MLDSA_65_PK_SIZE &&
	       signature->signature_bytes == PQCP_MLDSA_65_SIG_SIZE &&
	       digest_hex_valid(signature->passport_digest_hex);
}

static void secure_zero(void *buffer, size_t size)
{
	volatile uint8_t *p = buffer;

	while (size-- != 0U) {
		*p++ = 0U;
	}
}

static void hex_encode_chunk(const uint8_t *data, size_t len,
			     char out[CHUNK_HEX_CHARS + 1U])
{
	static const char digits[] = "0123456789abcdef";

	for (size_t i = 0U; i < len; ++i) {
		out[2U * i] = digits[data[i] >> 4];
		out[2U * i + 1U] = digits[data[i] & 0x0FU];
	}
	out[2U * len] = '\0';
}

static void emit_chunks(const char *marker, const uint8_t *data,
			uint32_t data_len, uint32_t total_chunks)
{
	char hex[CHUNK_HEX_CHARS + 1U];

	for (uint32_t index = 0U; index < total_chunks; ++index) {
		const uint32_t offset = index * CHUNK_BYTES;
		const uint32_t remaining = data_len - offset;
		const uint32_t this_len =
			remaining < CHUNK_BYTES ? remaining : CHUNK_BYTES;

		hex_encode_chunk(&data[offset], this_len, hex);
		printk("%s idx=%u total=%u data=%s\n",
		       marker, index, total_chunks, hex);
	}
}

int pqcp_deployment_passport_signature_create(
	const struct pqcp_deployment_assurance_passport *passport,
	struct pqcp_deployment_passport_signing_state *state,
	struct pqcp_deployment_passport_signature *signature)
{
	int ret;

	if (passport == NULL || state == NULL || signature == NULL) {
		return -EINVAL;
	}
	if (passport->schema_version !=
		    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_SCHEMA_VERSION ||
	    !digest_hex_valid(passport->passport_digest_hex)) {
		return -EINVAL;
	}

	memset(signature, 0, sizeof(*signature));
	signature->schema_version =
		PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_SCHEMA_VERSION;
	signature->mldsa_level = 65U;
	signature->public_key_bytes = PQCP_MLDSA_65_PK_SIZE;
	signature->signature_bytes = PQCP_MLDSA_65_SIG_SIZE;
	signature->boot_post_gated =
		IS_ENABLED(CONFIG_PQCP_KAT_BOOT_VERIFY);
	memcpy(signature->passport_digest_hex, passport->passport_digest_hex,
	       sizeof(signature->passport_digest_hex));

	ret = pqcp_mldsa_keypair(PQCP_MLDSA_65, signature->public_key,
				 state->secret_key);
	if (ret != PQCP_MLDSA_SUCCESS) {
		secure_zero(state->secret_key, sizeof(state->secret_key));
		memset(signature, 0, sizeof(*signature));
		return -EIO;
	}

	ret = pqcp_mldsa_sign(
		PQCP_MLDSA_65, state->secret_key,
		(const uint8_t *)signature->passport_digest_hex,
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS,
		(const uint8_t *)SIGNATURE_CONTEXT,
		sizeof(SIGNATURE_CONTEXT) - 1U,
		signature->signature);

	/* Single-use ephemeral key: gone before the caller sees control. */
	secure_zero(state->secret_key, sizeof(state->secret_key));

	if (ret != PQCP_MLDSA_SUCCESS) {
		memset(signature, 0, sizeof(*signature));
		return -EIO;
	}

	return 0;
}

int pqcp_deployment_passport_signature_verify(
	const struct pqcp_deployment_assurance_passport *passport,
	const struct pqcp_deployment_passport_signature *signature)
{
	int ret;

	if (passport == NULL || !record_shape_valid(signature)) {
		return -EINVAL;
	}
	if (passport->schema_version !=
		    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_SCHEMA_VERSION ||
	    !digest_hex_valid(passport->passport_digest_hex)) {
		return -EINVAL;
	}
	if (strcmp(passport->passport_digest_hex,
		   signature->passport_digest_hex) != 0) {
		return -EBADMSG;
	}

	ret = pqcp_mldsa_verify(
		PQCP_MLDSA_65, signature->public_key,
		(const uint8_t *)signature->passport_digest_hex,
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS,
		(const uint8_t *)SIGNATURE_CONTEXT,
		sizeof(SIGNATURE_CONTEXT) - 1U,
		signature->signature);

	return ret == PQCP_MLDSA_SUCCESS ? 0 : -EBADMSG;
}

int pqcp_deployment_passport_signature_emit(
	const struct pqcp_deployment_passport_signature *signature)
{
	if (!record_shape_valid(signature)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_PASSPORT_SIGNATURE schema=%u alg=ML-DSA-65 custody=demo boot_post_gated=%u passport_digest=%s pk_bytes=%u sig_bytes=%u pk_chunks=%u sig_chunks=%u\n",
	       signature->schema_version,
	       signature->boot_post_gated ? 1U : 0U,
	       signature->passport_digest_hex,
	       signature->public_key_bytes,
	       signature->signature_bytes,
	       (uint32_t)PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_PK_CHUNKS,
	       (uint32_t)PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_SIG_CHUNKS);
	emit_chunks("PQCP_DEPLOYMENT_PASSPORT_PK_CHUNK",
		    signature->public_key, signature->public_key_bytes,
		    PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_PK_CHUNKS);
	emit_chunks("PQCP_DEPLOYMENT_PASSPORT_SIG_CHUNK",
		    signature->signature, signature->signature_bytes,
		    PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_SIG_CHUNKS);

	return 0;
}
