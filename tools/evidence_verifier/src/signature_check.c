/*
 * SPDX-License-Identifier: MIT
 *
 * Passport signature capture and ML-DSA-65 verification (host side).
 */

#include <errno.h>
#include <string.h>

#include <mldsa_native.h>

#include "signature_check.h"

#define HEADER_PREFIX "PQCP_DEPLOYMENT_PASSPORT_SIGNATURE "
#define PK_CHUNK_PREFIX "PQCP_DEPLOYMENT_PASSPORT_PK_CHUNK "
#define SIG_CHUNK_PREFIX "PQCP_DEPLOYMENT_PASSPORT_SIG_CHUNK "

#define SIGNATURE_CONTEXT "PQCP-ASSURANCE-PASSPORT-V1"

#define FIELD_MAX_CHARS 384U

static int field_value(const char *line, const char *key, char *out,
		       size_t out_len)
{
	size_t key_len;
	const char *p = line;

	if (line == NULL || key == NULL || out == NULL || out_len == 0U) {
		return -EINVAL;
	}
	key_len = strlen(key);

	while (*p != '\0') {
		if ((p == line || *(p - 1) == ' ') &&
		    strncmp(p, key, key_len) == 0 && p[key_len] == '=') {
			const char *value = p + key_len + 1U;
			size_t len = 0U;

			while (value[len] != '\0' && value[len] != ' ') {
				len++;
			}
			if (len == 0U || len >= out_len) {
				return -EINVAL;
			}
			memcpy(out, value, len);
			out[len] = '\0';
			return 0;
		}
		p++;
	}

	return -ENOENT;
}

static int parse_u32(const char *line, const char *key, uint32_t *out)
{
	char value[FIELD_MAX_CHARS];
	uint32_t result = 0U;

	if (field_value(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}
	for (const char *p = value; *p != '\0'; ++p) {
		if (*p < '0' || *p > '9' ||
		    result > (UINT32_MAX - (uint32_t)(*p - '0')) / 10U) {
			return -EINVAL;
		}
		result = (result * 10U) + (uint32_t)(*p - '0');
	}

	*out = result;
	return 0;
}

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}

	return -1;
}

static int hex_decode(const char *hex, uint8_t *out, size_t out_max,
		      size_t *out_len)
{
	size_t hex_len = strlen(hex);

	if ((hex_len & 1U) != 0U || hex_len / 2U > out_max) {
		return -EINVAL;
	}
	for (size_t i = 0U; i < hex_len; i += 2U) {
		int hi = hex_nibble(hex[i]);
		int lo = hex_nibble(hex[i + 1U]);

		if (hi < 0 || lo < 0) {
			return -EINVAL;
		}
		out[i / 2U] = (uint8_t)((hi << 4) | lo);
	}

	*out_len = hex_len / 2U;
	return 0;
}

static bool digest_hex_valid(const char *value)
{
	if (strlen(value) != SIGNATURE_DIGEST_HEX_CHARS) {
		return false;
	}
	for (size_t i = 0U; i < SIGNATURE_DIGEST_HEX_CHARS; ++i) {
		if (hex_nibble(value[i]) < 0) {
			return false;
		}
	}

	return true;
}

void signature_capture_init(struct signature_capture *capture)
{
	memset(capture, 0, sizeof(*capture));
}

static int ingest_header(struct signature_capture *capture, const char *line)
{
	char text[FIELD_MAX_CHARS];
	uint32_t value;

	capture->header_markers++;
	if (capture->header_markers > 1U) {
		return -EINVAL;
	}
	if (parse_u32(line, "schema", &value) != 0 || value != 1U) {
		return -EINVAL;
	}
	if (field_value(line, "alg", text, sizeof(text)) != 0 ||
	    strcmp(text, "ML-DSA-65") != 0) {
		return -EINVAL;
	}
	if (field_value(line, "custody", text, sizeof(text)) != 0 ||
	    strcmp(text, "demo") != 0) {
		return -EINVAL;
	}
	if (parse_u32(line, "boot_post_gated", &value) != 0 || value > 1U) {
		return -EINVAL;
	}
	capture->boot_post_gated = value != 0U;
	if (field_value(line, "passport_digest", capture->passport_digest_hex,
			sizeof(capture->passport_digest_hex)) != 0 ||
	    !digest_hex_valid(capture->passport_digest_hex)) {
		return -EINVAL;
	}
	if (parse_u32(line, "pk_bytes", &value) != 0 ||
	    value != SIGNATURE_PK_BYTES) {
		return -EINVAL;
	}
	if (parse_u32(line, "sig_bytes", &value) != 0 ||
	    value != SIGNATURE_SIG_BYTES) {
		return -EINVAL;
	}
	if (parse_u32(line, "pk_chunks", &value) != 0 ||
	    value != SIGNATURE_PK_CHUNKS) {
		return -EINVAL;
	}
	if (parse_u32(line, "sig_chunks", &value) != 0 ||
	    value != SIGNATURE_SIG_CHUNKS) {
		return -EINVAL;
	}

	return 0;
}

static int ingest_chunk(const char *line, uint8_t *buffer,
			uint32_t buffer_bytes, uint32_t expected_chunks,
			uint32_t *seen_mask)
{
	char data[FIELD_MAX_CHARS];
	uint32_t index;
	uint32_t total;
	uint32_t offset;
	uint32_t expected_len;
	size_t decoded_len;
	uint8_t decoded[SIGNATURE_CHUNK_BYTES];

	if (parse_u32(line, "idx", &index) != 0 ||
	    parse_u32(line, "total", &total) != 0 ||
	    total != expected_chunks || index >= total) {
		return -EINVAL;
	}
	if ((*seen_mask & (1U << index)) != 0U) {
		return -EINVAL;
	}
	if (field_value(line, "data", data, sizeof(data)) != 0 ||
	    hex_decode(data, decoded, sizeof(decoded), &decoded_len) != 0) {
		return -EINVAL;
	}

	offset = index * SIGNATURE_CHUNK_BYTES;
	expected_len = buffer_bytes - offset < SIGNATURE_CHUNK_BYTES ?
		buffer_bytes - offset : SIGNATURE_CHUNK_BYTES;
	if (decoded_len != expected_len) {
		return -EINVAL;
	}

	memcpy(&buffer[offset], decoded, decoded_len);
	*seen_mask |= 1U << index;
	return 0;
}

int signature_capture_ingest_line(struct signature_capture *capture,
				  const char *line)
{
	int ret = 0;

	if (capture == NULL || line == NULL) {
		return 0;
	}

	if (strncmp(line, HEADER_PREFIX, strlen(HEADER_PREFIX)) == 0) {
		capture->present = true;
		ret = ingest_header(capture, line);
	} else if (strncmp(line, PK_CHUNK_PREFIX,
			   strlen(PK_CHUNK_PREFIX)) == 0) {
		capture->present = true;
		ret = ingest_chunk(line, capture->public_key,
				   SIGNATURE_PK_BYTES, SIGNATURE_PK_CHUNKS,
				   &capture->pk_chunks_seen);
	} else if (strncmp(line, SIG_CHUNK_PREFIX,
			   strlen(SIG_CHUNK_PREFIX)) == 0) {
		capture->present = true;
		ret = ingest_chunk(line, capture->signature,
				   SIGNATURE_SIG_BYTES, SIGNATURE_SIG_CHUNKS,
				   &capture->sig_chunks_seen);
	}

	if (ret != 0) {
		capture->malformed = true;
	}

	return 0;
}

bool signature_capture_complete(const struct signature_capture *capture)
{
	const uint32_t pk_full = (1U << SIGNATURE_PK_CHUNKS) - 1U;
	const uint32_t sig_full = (1U << SIGNATURE_SIG_CHUNKS) - 1U;

	return capture->present && !capture->malformed &&
	       capture->header_markers == 1U &&
	       capture->pk_chunks_seen == pk_full &&
	       capture->sig_chunks_seen == sig_full;
}

int signature_capture_verify(const struct signature_capture *capture,
			     const char *passport_digest_hex)
{
	int ret;

	if (capture == NULL || passport_digest_hex == NULL ||
	    !signature_capture_complete(capture)) {
		return -EINVAL;
	}
	if (!digest_hex_valid(passport_digest_hex) ||
	    strcmp(capture->passport_digest_hex, passport_digest_hex) != 0) {
		return -EBADMSG;
	}

	ret = crypto_sign_verify(
		capture->signature, SIGNATURE_SIG_BYTES,
		(const uint8_t *)capture->passport_digest_hex,
		SIGNATURE_DIGEST_HEX_CHARS,
		(const uint8_t *)SIGNATURE_CONTEXT,
		sizeof(SIGNATURE_CONTEXT) - 1U,
		capture->public_key);

	return ret == 0 ? 0 : -EBADMSG;
}
