/*
 * SPDX-License-Identifier: MIT
 *
 * Adversarial evidence tamper detection matrix.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_tamper_matrix.h>

static bool text_present(const char *value)
{
	return value != NULL && value[0] != '\0';
}

static bool profile_valid(enum pqcp_deployment_release_gate_profile profile)
{
	return profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER;
}

static bool matrix_status_valid(
	enum pqcp_deployment_tamper_matrix_status status)
{
	return status == PQCP_DEPLOYMENT_TAMPER_MATRIX_PASS ||
	       status == PQCP_DEPLOYMENT_TAMPER_MATRIX_WARN ||
	       status == PQCP_DEPLOYMENT_TAMPER_MATRIX_FAIL;
}

static bool stage_valid(enum pqcp_deployment_tamper_stage stage)
{
	return stage == PQCP_DEPLOYMENT_TAMPER_STAGE_VERDICT ||
	       stage == PQCP_DEPLOYMENT_TAMPER_STAGE_SEAL ||
	       stage == PQCP_DEPLOYMENT_TAMPER_STAGE_PASSPORT;
}

static bool tamper_class_valid(enum pqcp_deployment_tamper_class tamper_class)
{
	return (uint32_t)tamper_class < PQCP_DEPLOYMENT_TAMPER_CLASS_COUNT;
}

static bool is_lower_hex_len(const char *value, size_t expected_len)
{
	if (value == NULL || strlen(value) != expected_len) {
		return false;
	}

	for (size_t i = 0U; i < expected_len; ++i) {
		const char c = value[i];

		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
			return false;
		}
	}

	return true;
}

static bool nonce_valid(const char *value)
{
	return is_lower_hex_len(value,
				PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS);
}

static bool digest_valid(const char *value)
{
	return is_lower_hex_len(
		value, PQCP_DEPLOYMENT_TAMPER_MATRIX_DIGEST_HEX_CHARS);
}

static void set_text(char *dst, size_t dst_size, const char *src)
{
	if (dst == NULL || dst_size == 0U) {
		return;
	}
	(void)snprintk(dst, dst_size, "%s", src != NULL ? src : "");
}

static void set_zero_digest(char *dst, size_t dst_size)
{
	set_text(dst, dst_size,
		 "0000000000000000000000000000000000000000000000000000000000000000");
}

static void set_zero_nonce(char *dst, size_t dst_size)
{
	set_text(dst, dst_size, "00000000000000000000000000000000");
}

/* ------------------------------------------------------------------ */
/* Matrix digest                                                       */
/* ------------------------------------------------------------------ */

static void digest_init(uint64_t digest[4])
{
	digest[0] = 0xa3c59dc1e7b40f25ULL;
	digest[1] = 0x51d0c8e7a9b3f6acULL;
	digest[2] = 0x9e3779b97f4a7c15ULL;
	digest[3] = 0xc2b2ae3d27d4eb4fULL;
}

static uint64_t rotl64(uint64_t value, uint32_t bits)
{
	return (value << bits) | (value >> (64U - bits));
}

static void digest_update_byte(uint64_t digest[4], uint8_t value)
{
	digest[0] ^= (uint64_t)value + 0x100000001b3ULL;
	digest[0] *= 0x100000001b3ULL;
	digest[1] += digest[0] ^ ((uint64_t)value << 9U);
	digest[1] = rotl64(digest[1], 21U) * 0x9e3779b185ebca87ULL;
	digest[2] ^= digest[1] + digest[0] + 0x94d049bb133111ebULL;
	digest[2] = rotl64(digest[2], 33U);
	digest[3] += digest[2] ^ (digest[1] >> 15U);
	digest[3] = rotl64(digest[3], 45U);
}

static void digest_update_u32(uint64_t digest[4], uint32_t value)
{
	for (uint32_t shift = 0U; shift < 32U; shift += 8U) {
		digest_update_byte(digest, (uint8_t)(value >> shift));
	}
}

static void digest_update_text(uint64_t digest[4], const char *value)
{
	if (value == NULL) {
		value = "";
	}
	for (const char *p = value; *p != '\0'; ++p) {
		digest_update_byte(digest, (uint8_t)*p);
	}
	digest_update_byte(digest, (uint8_t)'|');
}

static void digest_to_hex(
	const uint64_t digest[4],
	char out[PQCP_DEPLOYMENT_TAMPER_MATRIX_DIGEST_HEX_CHARS + 1U])
{
	(void)snprintk(
		out,
		PQCP_DEPLOYMENT_TAMPER_MATRIX_DIGEST_HEX_CHARS + 1U,
		"%016llx%016llx%016llx%016llx",
		(unsigned long long)digest[0],
		(unsigned long long)digest[1],
		(unsigned long long)digest[2],
		(unsigned long long)digest[3]);
}

static void compute_matrix_digest(
	struct pqcp_deployment_tamper_matrix_report *report)
{
	uint64_t digest[4];

	digest_init(digest);
	digest_update_u32(digest, report->schema_version);
	digest_update_u32(digest, (uint32_t)report->status);
	digest_update_u32(digest, report->error_mask);
	digest_update_u32(digest, report->warning_mask);
	digest_update_u32(digest, (uint32_t)report->profile);
	digest_update_u32(digest, report->stage_mask);
	digest_update_u32(digest, report->cell_count);
	digest_update_u32(digest, report->control_count);
	digest_update_u32(digest, report->attack_count);
	digest_update_u32(digest, report->detected_count);
	digest_update_u32(digest, report->missed_count);
	digest_update_u32(digest, report->control_pass_count);
	digest_update_u32(digest, report->coverage_permille);
	digest_update_u32(digest, report->verdict_class_mask);
	digest_update_u32(digest, report->seal_class_mask);
	digest_update_u32(digest, report->passport_class_mask);
	digest_update_text(digest, report->top_candidate_id);
	digest_update_text(digest, report->nonce_hex);
	digest_update_text(digest, report->verdict_digest_hex);
	digest_update_text(digest, report->seal_digest_hex);
	digest_update_text(digest, report->passport_digest_hex);
	digest_to_hex(digest, report->matrix_digest_hex);
}

/* ------------------------------------------------------------------ */
/* Stage replay drivers                                                */
/* ------------------------------------------------------------------ */

static const char *stage_digest_key(enum pqcp_deployment_tamper_stage stage)
{
	switch (stage) {
	case PQCP_DEPLOYMENT_TAMPER_STAGE_VERDICT:
		return "verdict_digest";
	case PQCP_DEPLOYMENT_TAMPER_STAGE_SEAL:
		return "seal_digest";
	case PQCP_DEPLOYMENT_TAMPER_STAGE_PASSPORT:
		return "passport_digest";
	default:
		return "digest";
	}
}

/*
 * Feed the cell input lines into the stage replay verifier and report
 * whether the verifier accepted (passed) and which error token it raised.
 */
static int run_stage_replay(
	enum pqcp_deployment_tamper_stage stage,
	const char *line, uint32_t feed_count,
	struct pqcp_deployment_tamper_matrix_workspace *workspace,
	bool *passed, const char **error_token)
{
	int ret;

	switch (stage) {
	case PQCP_DEPLOYMENT_TAMPER_STAGE_VERDICT:
		ret = pqcp_deployment_evidence_verdict_replay_init(
			&workspace->verdict_state);
		if (ret != 0) {
			return ret;
		}
		for (uint32_t i = 0U; i < feed_count; ++i) {
			(void)pqcp_deployment_evidence_verdict_replay_ingest_line(
				&workspace->verdict_state, line);
		}
		ret = pqcp_deployment_evidence_verdict_replay_finish(
			&workspace->verdict_state, &workspace->verdict_result);
		*passed = ret == 0 && workspace->verdict_result.passed;
		*error_token =
			pqcp_deployment_evidence_verdict_replay_error_str(
				workspace->verdict_result.first_error);
		return 0;
	case PQCP_DEPLOYMENT_TAMPER_STAGE_SEAL:
		ret = pqcp_deployment_evidence_seal_replay_init(
			&workspace->seal_state);
		if (ret != 0) {
			return ret;
		}
		for (uint32_t i = 0U; i < feed_count; ++i) {
			(void)pqcp_deployment_evidence_seal_replay_ingest_line(
				&workspace->seal_state, line);
		}
		ret = pqcp_deployment_evidence_seal_replay_finish(
			&workspace->seal_state, &workspace->seal_result);
		*passed = ret == 0 && workspace->seal_result.passed;
		*error_token = pqcp_deployment_evidence_seal_replay_error_str(
			workspace->seal_result.first_error);
		return 0;
	case PQCP_DEPLOYMENT_TAMPER_STAGE_PASSPORT:
		ret = pqcp_deployment_assurance_passport_replay_init(
			&workspace->passport_state);
		if (ret != 0) {
			return ret;
		}
		for (uint32_t i = 0U; i < feed_count; ++i) {
			(void)pqcp_deployment_assurance_passport_replay_ingest_line(
				&workspace->passport_state, line);
		}
		ret = pqcp_deployment_assurance_passport_replay_finish(
			&workspace->passport_state,
			&workspace->passport_result);
		*passed = ret == 0 && workspace->passport_result.passed;
		*error_token =
			pqcp_deployment_assurance_passport_replay_error_str(
				workspace->passport_result.first_error);
		return 0;
	default:
		return -EINVAL;
	}
}

static int render_stage_marker(
	enum pqcp_deployment_tamper_stage stage,
	const struct pqcp_deployment_evidence_verdict *verdict,
	const struct pqcp_deployment_evidence_seal *seal,
	const struct pqcp_deployment_assurance_passport *passport,
	struct pqcp_deployment_tamper_matrix_workspace *workspace)
{
	switch (stage) {
	case PQCP_DEPLOYMENT_TAMPER_STAGE_VERDICT:
		return pqcp_deployment_marker_render_verdict(
			verdict, workspace->line, sizeof(workspace->line));
	case PQCP_DEPLOYMENT_TAMPER_STAGE_SEAL:
		return pqcp_deployment_marker_render_seal(
			seal, workspace->line, sizeof(workspace->line));
	case PQCP_DEPLOYMENT_TAMPER_STAGE_PASSPORT:
		return pqcp_deployment_marker_render_passport(
			passport, workspace->line, sizeof(workspace->line));
	default:
		return -EINVAL;
	}
}

static uint32_t stage_bit(enum pqcp_deployment_tamper_stage stage)
{
	return 1U << (uint32_t)stage;
}

static uint32_t *stage_class_mask(
	struct pqcp_deployment_tamper_matrix_report *report,
	enum pqcp_deployment_tamper_stage stage)
{
	switch (stage) {
	case PQCP_DEPLOYMENT_TAMPER_STAGE_VERDICT:
		return &report->verdict_class_mask;
	case PQCP_DEPLOYMENT_TAMPER_STAGE_SEAL:
		return &report->seal_class_mask;
	case PQCP_DEPLOYMENT_TAMPER_STAGE_PASSPORT:
	default:
		return &report->passport_class_mask;
	}
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

const char *pqcp_deployment_tamper_matrix_status_str(
	enum pqcp_deployment_tamper_matrix_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_TAMPER_MATRIX_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_TAMPER_MATRIX_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_TAMPER_MATRIX_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

const char *pqcp_deployment_tamper_stage_str(
	enum pqcp_deployment_tamper_stage stage)
{
	switch (stage) {
	case PQCP_DEPLOYMENT_TAMPER_STAGE_VERDICT:
		return "verdict";
	case PQCP_DEPLOYMENT_TAMPER_STAGE_SEAL:
		return "seal";
	case PQCP_DEPLOYMENT_TAMPER_STAGE_PASSPORT:
		return "passport";
	default:
		return "unknown";
	}
}

int pqcp_deployment_tamper_matrix_default_policy(
	enum pqcp_deployment_release_gate_profile profile,
	struct pqcp_deployment_tamper_matrix_policy *policy)
{
	if (policy == NULL || !profile_valid(profile)) {
		return -EINVAL;
	}

	memset(policy, 0, sizeof(*policy));
	policy->profile = profile;
	policy->stage_mask = PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_KNOWN_MASK;
	policy->tamper_seed = 0x70617370U; /* deterministic, documented */
	policy->min_coverage_permille = 1000U;
	policy->require_controls_pass = true;

	switch (profile) {
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE:
		policy->min_coverage_permille = 800U;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER:
		policy->require_full_detection = true;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT:
		policy->require_full_detection = true;
		policy->coverage_floor_blocks = true;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER:
		policy->require_full_detection = true;
		policy->coverage_floor_blocks = true;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static void matrix_invalid(
	struct pqcp_deployment_tamper_matrix_report *report,
	enum pqcp_deployment_release_gate_profile profile,
	uint32_t error_mask)
{
	if (report == NULL) {
		return;
	}

	memset(report, 0, sizeof(*report));
	report->schema_version = PQCP_DEPLOYMENT_TAMPER_MATRIX_SCHEMA_VERSION;
	report->status = PQCP_DEPLOYMENT_TAMPER_MATRIX_FAIL;
	report->error_mask = error_mask;
	report->profile = profile;
	set_text(report->top_candidate_id, sizeof(report->top_candidate_id),
		 "none");
	set_zero_nonce(report->nonce_hex, sizeof(report->nonce_hex));
	set_zero_digest(report->verdict_digest_hex,
			sizeof(report->verdict_digest_hex));
	set_zero_digest(report->seal_digest_hex,
			sizeof(report->seal_digest_hex));
	set_zero_digest(report->passport_digest_hex,
			sizeof(report->passport_digest_hex));
	compute_matrix_digest(report);
}

int pqcp_deployment_tamper_matrix_run(
	const struct pqcp_deployment_evidence_verdict *verdict,
	const struct pqcp_deployment_evidence_seal *seal,
	const struct pqcp_deployment_assurance_passport *passport,
	const struct pqcp_deployment_tamper_matrix_policy *policy,
	struct pqcp_deployment_tamper_matrix_workspace *workspace,
	struct pqcp_deployment_tamper_cell *cells,
	size_t max_cells,
	struct pqcp_deployment_tamper_matrix_report *report)
{
	size_t cell_index = 0U;
	uint32_t selected_stages = 0U;

	if (report == NULL) {
		return -EINVAL;
	}
	if (policy == NULL || workspace == NULL || cells == NULL ||
	    !profile_valid(policy->profile) ||
	    (policy->stage_mask &
	     ~PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_KNOWN_MASK) != 0U ||
	    policy->min_coverage_permille > 1000U) {
		matrix_invalid(report,
			       policy != NULL ? policy->profile :
				       PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE,
			       PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_INVALID_INPUT);
		return -EINVAL;
	}
	if (policy->stage_mask == 0U) {
		matrix_invalid(report, policy->profile,
			       PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_NO_STAGES);
		return -EINVAL;
	}
	if ((policy->stage_mask &
	     PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_VERDICT_BIT) != 0U &&
	    verdict == NULL) {
		matrix_invalid(report, policy->profile,
			       PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_INVALID_INPUT);
		return -EINVAL;
	}
	if ((policy->stage_mask &
	     PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_SEAL_BIT) != 0U &&
	    seal == NULL) {
		matrix_invalid(report, policy->profile,
			       PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_INVALID_INPUT);
		return -EINVAL;
	}
	if ((policy->stage_mask &
	     PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_PASSPORT_BIT) != 0U &&
	    passport == NULL) {
		matrix_invalid(report, policy->profile,
			       PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_INVALID_INPUT);
		return -EINVAL;
	}

	for (uint32_t s = 0U; s < PQCP_DEPLOYMENT_TAMPER_STAGE_COUNT; ++s) {
		if ((policy->stage_mask & (1U << s)) != 0U) {
			selected_stages++;
		}
	}
	if (max_cells <
	    (size_t)selected_stages * PQCP_DEPLOYMENT_TAMPER_CLASS_COUNT) {
		matrix_invalid(report, policy->profile,
			       PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_INVALID_INPUT);
		return -EINVAL;
	}

	memset(report, 0, sizeof(*report));
	report->schema_version = PQCP_DEPLOYMENT_TAMPER_MATRIX_SCHEMA_VERSION;
	report->profile = policy->profile;
	report->stage_mask = policy->stage_mask;

	/* Chain binding identity, taken from the strongest selected stage. */
	if (verdict != NULL &&
	    (policy->stage_mask &
	     PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_VERDICT_BIT) != 0U) {
		set_text(report->top_candidate_id,
			 sizeof(report->top_candidate_id),
			 verdict->top_candidate_id);
		set_text(report->nonce_hex, sizeof(report->nonce_hex),
			 verdict->nonce_hex);
	} else if (seal != NULL &&
		   (policy->stage_mask &
		    PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_SEAL_BIT) != 0U) {
		set_text(report->top_candidate_id,
			 sizeof(report->top_candidate_id),
			 seal->top_candidate_id);
		set_text(report->nonce_hex, sizeof(report->nonce_hex),
			 seal->nonce_hex);
	} else if (passport != NULL) {
		set_text(report->top_candidate_id,
			 sizeof(report->top_candidate_id),
			 passport->top_candidate_id);
		set_text(report->nonce_hex, sizeof(report->nonce_hex),
			 passport->nonce_hex);
	}
	if (!text_present(report->top_candidate_id)) {
		set_text(report->top_candidate_id,
			 sizeof(report->top_candidate_id), "none");
	}
	if (!nonce_valid(report->nonce_hex)) {
		set_zero_nonce(report->nonce_hex, sizeof(report->nonce_hex));
	}

	if (verdict != NULL &&
	    (policy->stage_mask &
	     PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_VERDICT_BIT) != 0U) {
		set_text(report->verdict_digest_hex,
			 sizeof(report->verdict_digest_hex),
			 verdict->verdict_digest_hex);
	} else {
		set_zero_digest(report->verdict_digest_hex,
				sizeof(report->verdict_digest_hex));
	}
	if (seal != NULL &&
	    (policy->stage_mask &
	     PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_SEAL_BIT) != 0U) {
		set_text(report->seal_digest_hex,
			 sizeof(report->seal_digest_hex),
			 seal->seal_digest_hex);
	} else {
		set_zero_digest(report->seal_digest_hex,
				sizeof(report->seal_digest_hex));
	}
	if (passport != NULL &&
	    (policy->stage_mask &
	     PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_PASSPORT_BIT) != 0U) {
		set_text(report->passport_digest_hex,
			 sizeof(report->passport_digest_hex),
			 passport->passport_digest_hex);
	} else {
		set_zero_digest(report->passport_digest_hex,
				sizeof(report->passport_digest_hex));
	}

	for (uint32_t s = 0U; s < PQCP_DEPLOYMENT_TAMPER_STAGE_COUNT; ++s) {
		enum pqcp_deployment_tamper_stage stage =
			(enum pqcp_deployment_tamper_stage)s;
		int render_ret;

		if ((policy->stage_mask & stage_bit(stage)) == 0U) {
			continue;
		}

		render_ret = render_stage_marker(stage, verdict, seal,
						 passport, workspace);
		if (render_ret < 0) {
			report->error_mask |=
				PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_RENDER_FAILED;
			continue;
		}

		for (uint32_t c = 0U;
		     c < PQCP_DEPLOYMENT_TAMPER_CLASS_COUNT; ++c) {
			enum pqcp_deployment_tamper_class tamper_class =
				(enum pqcp_deployment_tamper_class)c;
			struct pqcp_deployment_tamper_cell *cell =
				&cells[cell_index];
			const char *input_line = workspace->line;
			const char *error_token = "none";
			uint32_t feed_count = 1U;
			bool passed = false;
			bool tamper_ok = true;
			int ret;

			memset(cell, 0, sizeof(*cell));
			cell->schema_version =
				PQCP_DEPLOYMENT_TAMPER_MATRIX_SCHEMA_VERSION;
			cell->stage = stage;
			cell->tamper_class = tamper_class;
			cell->expected_detection =
				tamper_class != PQCP_DEPLOYMENT_TAMPER_NONE;

			if (tamper_class == PQCP_DEPLOYMENT_TAMPER_DUPLICATE) {
				feed_count = 2U;
			} else if (tamper_class ==
				   PQCP_DEPLOYMENT_TAMPER_OMIT) {
				feed_count = 0U;
			} else if (pqcp_deployment_tamper_class_mutates_line(
					   tamper_class)) {
				const char *field_key = NULL;

				if (tamper_class ==
					    PQCP_DEPLOYMENT_TAMPER_DIGEST_FLIP ||
				    tamper_class ==
					    PQCP_DEPLOYMENT_TAMPER_FIELD_STRIP) {
					field_key = stage_digest_key(stage);
				} else if (tamper_class ==
					   PQCP_DEPLOYMENT_TAMPER_BIT_NOISE) {
					field_key = "top";
				}
				ret = pqcp_deployment_tamper_apply(
					tamper_class,
					policy->tamper_seed ^
						((s << 8U) | c),
					field_key, workspace->line,
					workspace->mutated,
					sizeof(workspace->mutated),
					&workspace->record);
				if (ret != 0) {
					tamper_ok = false;
				} else {
					input_line = workspace->mutated;
				}
			}

			if (!tamper_ok) {
				report->error_mask |=
					PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_TAMPER_FAILED;
				cell->detected = false;
				cell->ok = false;
				set_text(cell->error_token,
					 sizeof(cell->error_token),
					 "tamper_error");
			} else {
				ret = run_stage_replay(stage, input_line,
						       feed_count, workspace,
						       &passed, &error_token);
				if (ret != 0) {
					report->error_mask |=
						PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_INVALID_INPUT;
					cell->detected = false;
					cell->ok = false;
					set_text(cell->error_token,
						 sizeof(cell->error_token),
						 "replay_error");
				} else {
					cell->detected = !passed;
					cell->ok = cell->expected_detection ?
						cell->detected :
						!cell->detected;
					set_text(cell->error_token,
						 sizeof(cell->error_token),
						 error_token);
				}
			}

			if (cell->expected_detection) {
				report->attack_count++;
				if (cell->detected) {
					report->detected_count++;
				} else {
					report->missed_count++;
					if (policy->require_full_detection) {
						report->error_mask |=
							PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_DETECTION_MISS;
					}
				}
			} else {
				report->control_count++;
				if (cell->ok) {
					report->control_pass_count++;
				} else if (policy->require_controls_pass) {
					report->error_mask |=
						PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_CONTROL_FAILED;
				}
			}
			if (cell->ok) {
				*stage_class_mask(report, stage) |= 1U << c;
			}
			report->cell_count++;
			cell_index++;
		}
	}

	report->coverage_permille = report->attack_count == 0U ? 0U :
		(report->detected_count * 1000U) / report->attack_count;

	if (report->coverage_permille < policy->min_coverage_permille) {
		if (policy->coverage_floor_blocks) {
			report->error_mask |=
				PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_COVERAGE_FLOOR;
		} else {
			report->warning_mask |=
				PQCP_DEPLOYMENT_TAMPER_MATRIX_WARNING_COVERAGE_FLOOR;
		}
	}
	if (report->stage_mask !=
	    PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_KNOWN_MASK) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_TAMPER_MATRIX_WARNING_PARTIAL_STAGES;
	}

	if (report->error_mask != 0U) {
		report->status = PQCP_DEPLOYMENT_TAMPER_MATRIX_FAIL;
	} else if (report->warning_mask != 0U) {
		report->status = PQCP_DEPLOYMENT_TAMPER_MATRIX_WARN;
	} else {
		report->status = PQCP_DEPLOYMENT_TAMPER_MATRIX_PASS;
	}

	compute_matrix_digest(report);

	return report->status == PQCP_DEPLOYMENT_TAMPER_MATRIX_FAIL ?
		-EBADMSG : 0;
}

int pqcp_deployment_tamper_cell_emit(
	const struct pqcp_deployment_tamper_cell *cell)
{
	if (cell == NULL ||
	    cell->schema_version !=
		    PQCP_DEPLOYMENT_TAMPER_MATRIX_SCHEMA_VERSION ||
	    !stage_valid(cell->stage) ||
	    !tamper_class_valid(cell->tamper_class) ||
	    !text_present(cell->error_token)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_TAMPER_CELL schema=%u stage=%s class=%s expected_detect=%u detected=%u ok=%u error=%s\n",
	       cell->schema_version,
	       pqcp_deployment_tamper_stage_str(cell->stage),
	       pqcp_deployment_tamper_class_str(cell->tamper_class),
	       cell->expected_detection ? 1U : 0U,
	       cell->detected ? 1U : 0U,
	       cell->ok ? 1U : 0U,
	       cell->error_token);

	return cell->ok ? 0 : -EBADMSG;
}

int pqcp_deployment_tamper_matrix_emit(
	const struct pqcp_deployment_tamper_matrix_report *report)
{
	if (report == NULL ||
	    report->schema_version !=
		    PQCP_DEPLOYMENT_TAMPER_MATRIX_SCHEMA_VERSION ||
	    !matrix_status_valid(report->status) ||
	    !profile_valid(report->profile) ||
	    (report->error_mask &
	     ~PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_KNOWN_MASK) != 0U ||
	    (report->warning_mask &
	     ~PQCP_DEPLOYMENT_TAMPER_MATRIX_WARNING_KNOWN_MASK) != 0U ||
	    (report->stage_mask &
	     ~PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_KNOWN_MASK) != 0U ||
	    report->coverage_permille > 1000U ||
	    !text_present(report->top_candidate_id) ||
	    !nonce_valid(report->nonce_hex) ||
	    !digest_valid(report->verdict_digest_hex) ||
	    !digest_valid(report->seal_digest_hex) ||
	    !digest_valid(report->passport_digest_hex) ||
	    !digest_valid(report->matrix_digest_hex)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_TAMPER_MATRIX schema=%u profile=%s status=%s errors=0x%08x warnings=0x%08x stage_mask=0x%02x cells=%u controls=%u attacks=%u detected=%u missed=%u controls_passed=%u coverage_permille=%u verdict_class_mask=0x%08x seal_class_mask=0x%08x passport_class_mask=0x%08x top=%s nonce=%s verdict_digest=%s seal_digest=%s passport_digest=%s matrix_digest=%s\n",
	       report->schema_version,
	       pqcp_deployment_release_gate_profile_str(report->profile),
	       pqcp_deployment_tamper_matrix_status_str(report->status),
	       report->error_mask,
	       report->warning_mask,
	       report->stage_mask,
	       report->cell_count,
	       report->control_count,
	       report->attack_count,
	       report->detected_count,
	       report->missed_count,
	       report->control_pass_count,
	       report->coverage_permille,
	       report->verdict_class_mask,
	       report->seal_class_mask,
	       report->passport_class_mask,
	       report->top_candidate_id,
	       report->nonce_hex,
	       report->verdict_digest_hex,
	       report->seal_digest_hex,
	       report->passport_digest_hex,
	       report->matrix_digest_hex);

	return report->status == PQCP_DEPLOYMENT_TAMPER_MATRIX_FAIL ?
		-EBADMSG : 0;
}
