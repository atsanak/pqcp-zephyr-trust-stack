/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Deterministic single-line tamper engine for evidence markers.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_tamper_engine.h>

static uint32_t xorshift32(uint32_t *state)
{
	uint32_t x = *state;

	/* Zero would lock the generator; remap deterministically. */
	if (x == 0U) {
		x = 0x6b8b4567U;
	}
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	*state = x;

	return x;
}

static void set_text(char *dst, size_t dst_size, const char *src)
{
	if (dst == NULL || dst_size == 0U) {
		return;
	}
	(void)snprintk(dst, dst_size, "%s", src != NULL ? src : "");
}

static void record_init(struct pqcp_deployment_tamper_record *record,
			enum pqcp_deployment_tamper_class tamper_class)
{
	memset(record, 0, sizeof(*record));
	record->schema_version = PQCP_DEPLOYMENT_TAMPER_ENGINE_SCHEMA_VERSION;
	record->tamper_class = tamper_class;
}

/*
 * Locate the value of "key=" in the line. Returns the value offset and
 * length, or -ENOENT. Also reports the offset where the field (including
 * its leading separator space, if any) starts, for FIELD_STRIP.
 */
static int find_field(const char *line, const char *key,
		      size_t *field_start, size_t *value_start,
		      size_t *value_len)
{
	size_t key_len = strlen(key);
	const char *p = line;

	while (*p != '\0') {
		if ((p == line || *(p - 1) == ' ') &&
		    strncmp(p, key, key_len) == 0 && p[key_len] == '=') {
			const char *value = p + key_len + 1U;
			size_t len = 0U;

			while (value[len] != '\0' && value[len] != ' ') {
				len++;
			}
			if (len == 0U) {
				return -ENOENT;
			}
			*field_start = (size_t)(p - line);
			*value_start = (size_t)(value - line);
			*value_len = len;
			return 0;
		}
		p++;
	}

	return -ENOENT;
}

static char flip_hex_nibble(char c, uint32_t step)
{
	static const char charset[] = "0123456789abcdef";
	size_t index = 0U;

	for (size_t i = 0U; i < 16U; ++i) {
		if (charset[i] == c) {
			index = i;
			break;
		}
	}

	/* step is forced into 1..15 so the output always differs. */
	return charset[(index + (step % 15U) + 1U) % 16U];
}

static int copy_line(const char *line, char *out, size_t out_size)
{
	size_t len = strlen(line);

	if (len >= out_size) {
		return -ENOSPC;
	}
	memcpy(out, line, len + 1U);

	return 0;
}

static int apply_value_char_mutation(
	const char *line, const char *key, uint32_t seed, bool hex_only,
	char *out, size_t out_size,
	struct pqcp_deployment_tamper_record *record)
{
	size_t field_start;
	size_t value_start;
	size_t value_len;
	size_t target;
	uint32_t prng = seed;
	int ret;

	ret = find_field(line, key, &field_start, &value_start, &value_len);
	if (ret != 0) {
		return ret;
	}
	ret = copy_line(line, out, out_size);
	if (ret != 0) {
		return ret;
	}

	target = value_start + (xorshift32(&prng) % value_len);
	record->offset = (uint32_t)target;
	record->original_char = out[target];
	if (hex_only) {
		out[target] = flip_hex_nibble(out[target], xorshift32(&prng));
	} else {
		/* Rotate within the printable marker charset. */
		char c = out[target];

		out[target] = (char)(c == 'z' ? 'a' : c + 1);
		if (out[target] == ' ' || out[target] == '=') {
			out[target] = (char)(out[target] + 2);
		}
		if (out[target] == record->original_char) {
			out[target] = (char)(c == '0' ? '1' : '0');
		}
	}
	record->mutated_char = out[target];
	record->applied = out[target] != record->original_char;
	set_text(record->field_key, sizeof(record->field_key), key);

	return record->applied ? 0 : -EINVAL;
}

static int apply_token_swap(
	const char *line, const char *key, const char *const *tokens,
	size_t token_count, char *out, size_t out_size,
	struct pqcp_deployment_tamper_record *record)
{
	size_t field_start;
	size_t value_start;
	size_t value_len;
	size_t line_len = strlen(line);
	const char *replacement = NULL;
	size_t replacement_len;
	int ret;

	ret = find_field(line, key, &field_start, &value_start, &value_len);
	if (ret != 0) {
		return ret;
	}

	for (size_t i = 0U; i < token_count; ++i) {
		if (strlen(tokens[i]) == value_len &&
		    strncmp(&line[value_start], tokens[i], value_len) == 0) {
			replacement = tokens[(i + 1U) % token_count];
			break;
		}
	}
	if (replacement == NULL) {
		/* Unknown current token: swap to the first known token. */
		replacement = tokens[0];
		if (strlen(replacement) == value_len &&
		    strncmp(&line[value_start], replacement,
			    value_len) == 0) {
			replacement = tokens[1U % token_count];
		}
	}
	replacement_len = strlen(replacement);

	if (line_len - value_len + replacement_len >= out_size) {
		return -ENOSPC;
	}

	memcpy(out, line, value_start);
	memcpy(&out[value_start], replacement, replacement_len);
	memcpy(&out[value_start + replacement_len],
	       &line[value_start + value_len],
	       line_len - value_start - value_len + 1U);

	record->offset = (uint32_t)value_start;
	record->original_char = line[value_start];
	record->mutated_char = out[value_start];
	record->applied = true;
	set_text(record->field_key, sizeof(record->field_key), key);

	return 0;
}

static int apply_field_strip(
	const char *line, const char *key, char *out, size_t out_size,
	struct pqcp_deployment_tamper_record *record)
{
	size_t field_start;
	size_t value_start;
	size_t value_len;
	size_t field_end;
	size_t copy_start;
	size_t line_len = strlen(line);
	int ret;

	ret = find_field(line, key, &field_start, &value_start, &value_len);
	if (ret != 0) {
		return ret;
	}
	field_end = value_start + value_len;

	/* Consume the separator space before the field when present. */
	copy_start = field_start;
	if (copy_start > 0U && line[copy_start - 1U] == ' ') {
		copy_start--;
	} else if (line[field_end] == ' ') {
		field_end++;
	}

	if (line_len - (field_end - copy_start) >= out_size) {
		return -ENOSPC;
	}

	memcpy(out, line, copy_start);
	memcpy(&out[copy_start], &line[field_end], line_len - field_end + 1U);

	record->offset = (uint32_t)copy_start;
	record->original_char = line[copy_start];
	record->mutated_char = out[copy_start];
	record->applied = true;
	set_text(record->field_key, sizeof(record->field_key), key);

	return 0;
}

static int apply_truncate(const char *line, char *out, size_t out_size,
			  struct pqcp_deployment_tamper_record *record)
{
	size_t line_len = strlen(line);
	size_t keep = (line_len * 2U) / 3U;

	if (line_len < 3U) {
		return -EINVAL;
	}
	if (keep >= out_size) {
		return -ENOSPC;
	}

	memcpy(out, line, keep);
	out[keep] = '\0';

	record->offset = (uint32_t)keep;
	record->original_char = line[keep];
	record->mutated_char = '\0';
	record->applied = true;

	return 0;
}

static int apply_nonce_swap(const char *line, char *out, size_t out_size,
			    struct pqcp_deployment_tamper_record *record)
{
	size_t field_start;
	size_t value_start;
	size_t value_len;
	int ret;

	ret = find_field(line, "nonce", &field_start, &value_start,
			 &value_len);
	if (ret != 0) {
		return ret;
	}
	ret = copy_line(line, out, out_size);
	if (ret != 0) {
		return ret;
	}

	/* Shift every nibble by one: valid shape, different value. */
	for (size_t i = 0U; i < value_len; ++i) {
		out[value_start + i] = flip_hex_nibble(out[value_start + i],
						       0U);
	}

	record->offset = (uint32_t)value_start;
	record->original_char = line[value_start];
	record->mutated_char = out[value_start];
	record->applied = true;
	set_text(record->field_key, sizeof(record->field_key), "nonce");

	return 0;
}

static int apply_schema_bump(const char *line, char *out, size_t out_size,
			     struct pqcp_deployment_tamper_record *record)
{
	static const char *const tokens[] = { "99" };

	return apply_token_swap(line, "schema", tokens, 1U, out, out_size,
				record);
}

static int apply_status_forge(const char *line, char *out, size_t out_size,
			      struct pqcp_deployment_tamper_record *record)
{
	static const char *const tokens[] = { "PASS", "WARN", "FAIL" };

	return apply_token_swap(line, "status", tokens, 3U, out, out_size,
				record);
}

static int apply_profile_swap(const char *line, char *out, size_t out_size,
			      struct pqcp_deployment_tamper_record *record)
{
	static const char *const tokens[] = {
		"product", "paper", "prototype", "partner"
	};

	return apply_token_swap(line, "profile", tokens, 4U, out, out_size,
				record);
}

static int apply_score_inflate(const char *line, char *out, size_t out_size,
			       struct pqcp_deployment_tamper_record *record)
{
	size_t field_start;
	size_t value_start;
	size_t value_len;
	int ret;

	ret = find_field(line, "score", &field_start, &value_start,
			 &value_len);
	if (ret != 0) {
		return ret;
	}
	ret = copy_line(line, out, out_size);
	if (ret != 0) {
		return ret;
	}

	/* Rewrite the leading digit so the claimed score changes while the
	 * field stays numerically valid and in 0..100 whenever possible.
	 */
	record->offset = (uint32_t)value_start;
	record->original_char = out[value_start];
	if (value_len >= 3U) {
		/* "100" or similar: drop to a different two-digit shape. */
		out[value_start] = '9';
		out[value_start + 1U] = '8';
		out[value_start + 2U] = '\0';
		memmove(&out[value_start + 2U], &line[value_start + value_len],
			strlen(&line[value_start + value_len]) + 1U);
	} else {
		out[value_start] = record->original_char == '9' ? '1' : '9';
	}
	record->mutated_char = out[value_start];
	record->applied = true;
	set_text(record->field_key, sizeof(record->field_key), "score");

	return 0;
}

const char *pqcp_deployment_tamper_class_str(
	enum pqcp_deployment_tamper_class tamper_class)
{
	switch (tamper_class) {
	case PQCP_DEPLOYMENT_TAMPER_NONE:
		return "control";
	case PQCP_DEPLOYMENT_TAMPER_DIGEST_FLIP:
		return "digest_flip";
	case PQCP_DEPLOYMENT_TAMPER_STATUS_FORGE:
		return "status_forge";
	case PQCP_DEPLOYMENT_TAMPER_SCORE_INFLATE:
		return "score_inflate";
	case PQCP_DEPLOYMENT_TAMPER_SCHEMA_BUMP:
		return "schema_bump";
	case PQCP_DEPLOYMENT_TAMPER_NONCE_SWAP:
		return "nonce_swap";
	case PQCP_DEPLOYMENT_TAMPER_PROFILE_SWAP:
		return "profile_swap";
	case PQCP_DEPLOYMENT_TAMPER_FIELD_STRIP:
		return "field_strip";
	case PQCP_DEPLOYMENT_TAMPER_TRUNCATE:
		return "truncate";
	case PQCP_DEPLOYMENT_TAMPER_BIT_NOISE:
		return "bit_noise";
	case PQCP_DEPLOYMENT_TAMPER_DUPLICATE:
		return "duplicate";
	case PQCP_DEPLOYMENT_TAMPER_OMIT:
		return "omit";
	default:
		return "unknown";
	}
}

bool pqcp_deployment_tamper_class_mutates_line(
	enum pqcp_deployment_tamper_class tamper_class)
{
	switch (tamper_class) {
	case PQCP_DEPLOYMENT_TAMPER_NONE:
	case PQCP_DEPLOYMENT_TAMPER_DUPLICATE:
	case PQCP_DEPLOYMENT_TAMPER_OMIT:
		return false;
	case PQCP_DEPLOYMENT_TAMPER_DIGEST_FLIP:
	case PQCP_DEPLOYMENT_TAMPER_STATUS_FORGE:
	case PQCP_DEPLOYMENT_TAMPER_SCORE_INFLATE:
	case PQCP_DEPLOYMENT_TAMPER_SCHEMA_BUMP:
	case PQCP_DEPLOYMENT_TAMPER_NONCE_SWAP:
	case PQCP_DEPLOYMENT_TAMPER_PROFILE_SWAP:
	case PQCP_DEPLOYMENT_TAMPER_FIELD_STRIP:
	case PQCP_DEPLOYMENT_TAMPER_TRUNCATE:
	case PQCP_DEPLOYMENT_TAMPER_BIT_NOISE:
		return true;
	default:
		return false;
	}
}

int pqcp_deployment_tamper_apply(
	enum pqcp_deployment_tamper_class tamper_class,
	uint32_t seed,
	const char *field_key,
	const char *line,
	char *out, size_t out_size,
	struct pqcp_deployment_tamper_record *record)
{
	int ret;

	if (line == NULL || out == NULL || out_size == 0U ||
	    record == NULL) {
		return -EINVAL;
	}

	record_init(record, tamper_class);

	switch (tamper_class) {
	case PQCP_DEPLOYMENT_TAMPER_NONE:
	case PQCP_DEPLOYMENT_TAMPER_DUPLICATE:
	case PQCP_DEPLOYMENT_TAMPER_OMIT:
		ret = copy_line(line, out, out_size);
		break;
	case PQCP_DEPLOYMENT_TAMPER_DIGEST_FLIP:
		if (field_key == NULL || field_key[0] == '\0') {
			return -EINVAL;
		}
		ret = apply_value_char_mutation(line, field_key, seed, true,
						out, out_size, record);
		break;
	case PQCP_DEPLOYMENT_TAMPER_STATUS_FORGE:
		ret = apply_status_forge(line, out, out_size, record);
		break;
	case PQCP_DEPLOYMENT_TAMPER_SCORE_INFLATE:
		ret = apply_score_inflate(line, out, out_size, record);
		break;
	case PQCP_DEPLOYMENT_TAMPER_SCHEMA_BUMP:
		ret = apply_schema_bump(line, out, out_size, record);
		break;
	case PQCP_DEPLOYMENT_TAMPER_NONCE_SWAP:
		ret = apply_nonce_swap(line, out, out_size, record);
		break;
	case PQCP_DEPLOYMENT_TAMPER_PROFILE_SWAP:
		ret = apply_profile_swap(line, out, out_size, record);
		break;
	case PQCP_DEPLOYMENT_TAMPER_FIELD_STRIP:
		if (field_key == NULL || field_key[0] == '\0') {
			return -EINVAL;
		}
		ret = apply_field_strip(line, field_key, out, out_size,
					record);
		break;
	case PQCP_DEPLOYMENT_TAMPER_TRUNCATE:
		ret = apply_truncate(line, out, out_size, record);
		break;
	case PQCP_DEPLOYMENT_TAMPER_BIT_NOISE:
		if (field_key == NULL || field_key[0] == '\0') {
			return -EINVAL;
		}
		ret = apply_value_char_mutation(line, field_key, seed, false,
						out, out_size, record);
		break;
	default:
		return -EINVAL;
	}

	return ret;
}
