/*
 * SPDX-License-Identifier: MIT
 *
 * Passport marker line -> struct reconstruction (host side).
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "passport_parse.h"

#define FIELD_MAX_CHARS 96U

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

static int get_u32_dec(const char *line, const char *key, uint32_t *out)
{
	char value[FIELD_MAX_CHARS];
	char *end = NULL;
	unsigned long parsed;

	if (field_value(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}
	parsed = strtoul(value, &end, 10);
	if (end == NULL || *end != '\0' || parsed > UINT32_MAX) {
		return -EINVAL;
	}
	*out = (uint32_t)parsed;
	return 0;
}

static int get_u32_hex(const char *line, const char *key, uint32_t *out)
{
	char value[FIELD_MAX_CHARS];
	char *end = NULL;
	unsigned long parsed;

	if (field_value(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}
	parsed = strtoul(value, &end, 16);
	if (end == NULL || *end != '\0' || parsed > UINT32_MAX) {
		return -EINVAL;
	}
	*out = (uint32_t)parsed;
	return 0;
}

static int get_bool_flag(const char *line, const char *key, bool *out)
{
	uint32_t value;

	if (get_u32_dec(line, key, &value) != 0 || value > 1U) {
		return -EINVAL;
	}
	*out = value != 0U;
	return 0;
}

static int get_text(const char *line, const char *key, char *out,
		    size_t out_len)
{
	return field_value(line, key, out, out_len) == 0 ? 0 : -EINVAL;
}

static int parse_profile(const char *value,
			 enum pqcp_deployment_release_gate_profile *out)
{
	if (strcmp(value, "prototype") == 0) {
		*out = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE;
		return 0;
	}
	if (strcmp(value, "paper") == 0) {
		*out = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER;
		return 0;
	}
	if (strcmp(value, "product") == 0) {
		*out = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
		return 0;
	}
	if (strcmp(value, "partner") == 0) {
		*out = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER;
		return 0;
	}

	return -EINVAL;
}

static int parse_tri_status(const char *value, uint32_t *out)
{
	if (strcmp(value, "PASS") == 0) {
		*out = 2U;
		return 0;
	}
	if (strcmp(value, "WARN") == 0) {
		*out = 1U;
		return 0;
	}
	if (strcmp(value, "FAIL") == 0) {
		*out = 0U;
		return 0;
	}

	return -EINVAL;
}

int parse_passport_marker(
	const char *line,
	struct pqcp_deployment_assurance_passport *passport)
{
	char text[FIELD_MAX_CHARS];
	uint32_t tri;

	memset(passport, 0, sizeof(*passport));

	if (get_u32_dec(line, "schema", &passport->schema_version) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "profile", text, sizeof(text)) != 0 ||
	    parse_profile(text, &passport->profile) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "status", text, sizeof(text)) != 0 ||
	    parse_tri_status(text, &tri) != 0) {
		return -EINVAL;
	}
	passport->status = (enum pqcp_deployment_assurance_passport_status)tri;
	if (get_text(line, "seal_status", text, sizeof(text)) != 0 ||
	    parse_tri_status(text, &tri) != 0) {
		return -EINVAL;
	}
	passport->seal_status = (enum pqcp_deployment_evidence_seal_status)tri;
	if (get_text(line, "seal_audit_status", text, sizeof(text)) != 0 ||
	    parse_tri_status(text, &tri) != 0) {
		return -EINVAL;
	}
	passport->seal_audit_status =
		(enum pqcp_deployment_evidence_seal_audit_status)tri;
	if (get_u32_hex(line, "errors", &passport->error_mask) != 0 ||
	    get_u32_hex(line, "warnings", &passport->warning_mask) != 0 ||
	    get_u32_dec(line, "score", &passport->passport_score) != 0 ||
	    get_u32_dec(line, "min_score",
			&passport->min_terminal_score) != 0 ||
	    get_u32_dec(line, "capability_score",
			&passport->capability_readiness_score) != 0 ||
	    get_u32_dec(line, "audited_results",
			&passport->audited_result_count) != 0 ||
	    get_u32_dec(line, "chain_stages",
			&passport->chain_stage_count) != 0 ||
	    get_u32_hex(line, "evidence_all",
			&passport->evidence_capabilities_all) != 0 ||
	    get_u32_hex(line, "evidence_any",
			&passport->evidence_capabilities_any) != 0 ||
	    get_u32_hex(line, "mlkem_levels",
			&passport->mlkem_level_mask) != 0 ||
	    get_u32_hex(line, "mldsa_levels",
			&passport->mldsa_level_mask) != 0) {
		return -EINVAL;
	}
	if (get_bool_flag(line, "seal_replay_passed",
			  &passport->seal_replay_passed) != 0 ||
	    get_bool_flag(line, "top_consistent",
			  &passport->top_consistent) != 0 ||
	    get_bool_flag(line, "nonce_consistent",
			  &passport->nonce_consistent) != 0 ||
	    get_bool_flag(line, "digest_consistent",
			  &passport->seal_digest_consistent) != 0 ||
	    get_bool_flag(line, "profile_consistent",
			  &passport->profile_consistent) != 0 ||
	    get_bool_flag(line, "production_allowed",
			  &passport->production_allowed) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "pqcp_version", passport->pqcp_version,
		     sizeof(passport->pqcp_version)) != 0 ||
	    get_text(line, "zephyr_version", passport->zephyr_version,
		     sizeof(passport->zephyr_version)) != 0 ||
	    get_text(line, "board", passport->board,
		     sizeof(passport->board)) != 0 ||
	    get_text(line, "top", passport->top_candidate_id,
		     sizeof(passport->top_candidate_id)) != 0 ||
	    get_text(line, "nonce", passport->nonce_hex,
		     sizeof(passport->nonce_hex)) != 0 ||
	    get_text(line, "seal_digest", passport->seal_digest_hex,
		     sizeof(passport->seal_digest_hex)) != 0 ||
	    get_text(line, "seal_audit_digest",
		     passport->seal_audit_digest_hex,
		     sizeof(passport->seal_audit_digest_hex)) != 0 ||
	    get_text(line, "passport_digest", passport->passport_digest_hex,
		     sizeof(passport->passport_digest_hex)) != 0) {
		return -EINVAL;
	}

	return 0;
}

