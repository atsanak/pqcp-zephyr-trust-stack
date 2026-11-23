/*
 * SPDX-License-Identifier: MIT
 *
 * Render-to-buffer support for the terminal deployment evidence markers.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_marker_render.h>

static bool text_present(const char *value)
{
	return value != NULL && value[0] != '\0';
}

static bool text_marker_safe(const char *value)
{
	if (!text_present(value)) {
		return false;
	}
	for (const char *p = value; *p != '\0'; ++p) {
		if (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') {
			return false;
		}
	}

	return true;
}

static bool profile_valid(enum pqcp_deployment_release_gate_profile profile)
{
	return profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER;
}

static bool verdict_status_valid(
	enum pqcp_deployment_evidence_verdict_status status)
{
	return status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARN ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_FAIL;
}

static bool seal_status_valid(enum pqcp_deployment_evidence_seal_status status)
{
	return status == PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARN ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_SEAL_FAIL;
}

static bool verdict_audit_status_valid(
	enum pqcp_deployment_evidence_verdict_audit_status status)
{
	return status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_PASS ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_WARN ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_FAIL;
}

static bool passport_status_valid(
	enum pqcp_deployment_assurance_passport_status status)
{
	return status == PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS ||
	       status == PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARN ||
	       status == PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL;
}

static bool seal_audit_status_valid(
	enum pqcp_deployment_evidence_seal_audit_status status)
{
	return status == PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_PASS ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_WARN ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_FAIL;
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

static bool digest64_valid(const char *value)
{
	return is_lower_hex_len(value, 64U);
}

static int finish_render(int written, size_t out_size)
{
	if (written < 0 || (size_t)written >= out_size) {
		return -ENOSPC;
	}

	return written;
}

int pqcp_deployment_marker_render_verdict(
	const struct pqcp_deployment_evidence_verdict *verdict,
	char *out, size_t out_size)
{
	int written;

	if (out == NULL || out_size == 0U) {
		return -EINVAL;
	}
	if (verdict == NULL ||
	    verdict->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_VERDICT_SCHEMA_VERSION ||
	    !verdict_status_valid(verdict->status) ||
	    !profile_valid(verdict->profile) ||
	    (verdict->error_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_KNOWN_MASK) != 0U ||
	    (verdict->warning_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_KNOWN_MASK) != 0U ||
	    verdict->verdict_score > 100U ||
	    verdict->min_chain_score > 100U ||
	    !text_marker_safe(verdict->top_candidate_id) ||
	    !nonce_valid(verdict->nonce_hex) ||
	    !digest64_valid(verdict->trace_digest_hex) ||
	    !digest64_valid(verdict->review_packet_digest_hex) ||
	    !digest64_valid(verdict->device_packet_digest_hex) ||
	    !digest64_valid(verdict->token_digest_hex) ||
	    !digest64_valid(verdict->packet_audit_digest_hex) ||
	    !digest64_valid(verdict->verdict_digest_hex)) {
		return -EINVAL;
	}

	written = snprintk(
		out, out_size,
		"PQCP_DEPLOYMENT_EVIDENCE_VERDICT schema=%u profile=%s status=%s errors=0x%08x warnings=0x%08x score=%u min_score=%u stages=%u pass=%u warn=%u fail=%u consistency=%u consistency_pass=%u evidence_all=0x%08x evidence_any=0x%08x top_consistent=%u nonce_consistent=%u trace_consistent=%u review_digest_consistent=%u device_digest_consistent=%u token_digest_consistent=%u top=%s nonce=%s trace_digest=%s review_digest=%s device_digest=%s token_digest=%s packet_audit_digest=%s verdict_digest=%s",
		verdict->schema_version,
		pqcp_deployment_release_gate_profile_str(verdict->profile),
		pqcp_deployment_evidence_verdict_status_str(verdict->status),
		verdict->error_mask,
		verdict->warning_mask,
		verdict->verdict_score,
		verdict->min_chain_score,
		verdict->stage_count,
		verdict->pass_count,
		verdict->warn_count,
		verdict->fail_count,
		verdict->consistency_checks,
		verdict->consistency_pass_count,
		verdict->evidence_capabilities_all,
		verdict->evidence_capabilities_any,
		verdict->top_consistent ? 1U : 0U,
		verdict->nonce_consistent ? 1U : 0U,
		verdict->trace_digest_consistent ? 1U : 0U,
		verdict->review_packet_digest_consistent ? 1U : 0U,
		verdict->device_packet_digest_consistent ? 1U : 0U,
		verdict->token_digest_consistent ? 1U : 0U,
		verdict->top_candidate_id,
		verdict->nonce_hex,
		verdict->trace_digest_hex,
		verdict->review_packet_digest_hex,
		verdict->device_packet_digest_hex,
		verdict->token_digest_hex,
		verdict->packet_audit_digest_hex,
		verdict->verdict_digest_hex);

	return finish_render(written, out_size);
}

int pqcp_deployment_marker_render_seal(
	const struct pqcp_deployment_evidence_seal *seal,
	char *out, size_t out_size)
{
	int written;

	if (out == NULL || out_size == 0U) {
		return -EINVAL;
	}
	if (seal == NULL ||
	    seal->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_SEAL_SCHEMA_VERSION ||
	    !seal_status_valid(seal->status) ||
	    !profile_valid(seal->profile) ||
	    !verdict_status_valid(seal->verdict_status) ||
	    !verdict_audit_status_valid(seal->audit_status) ||
	    (seal->error_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_KNOWN_MASK) != 0U ||
	    (seal->warning_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_KNOWN_MASK) != 0U ||
	    seal->seal_score > 100U ||
	    seal->min_terminal_score > 100U ||
	    !text_marker_safe(seal->top_candidate_id) ||
	    !nonce_valid(seal->nonce_hex) ||
	    !digest64_valid(seal->verdict_digest_hex) ||
	    !digest64_valid(seal->audit_digest_hex) ||
	    !digest64_valid(seal->seal_digest_hex)) {
		return -EINVAL;
	}

	written = snprintk(
		out, out_size,
		"PQCP_DEPLOYMENT_EVIDENCE_SEAL schema=%u profile=%s status=%s errors=0x%08x warnings=0x%08x score=%u min_score=%u verdict_status=%s audit_status=%s replay_passed=%u audited_results=%u chain_stages=%u chain_consistency=%u evidence_all=0x%08x evidence_any=0x%08x top_consistent=%u nonce_consistent=%u digest_consistent=%u profile_consistent=%u status_consistent=%u top=%s nonce=%s verdict_digest=%s audit_digest=%s seal_digest=%s",
		seal->schema_version,
		pqcp_deployment_release_gate_profile_str(seal->profile),
		pqcp_deployment_evidence_seal_status_str(seal->status),
		seal->error_mask,
		seal->warning_mask,
		seal->seal_score,
		seal->min_terminal_score,
		pqcp_deployment_evidence_verdict_status_str(
			seal->verdict_status),
		pqcp_deployment_evidence_verdict_audit_status_str(
			seal->audit_status),
		seal->replay_passed ? 1U : 0U,
		seal->audited_result_count,
		seal->chain_stage_count,
		seal->chain_consistency_checks,
		seal->evidence_capabilities_all,
		seal->evidence_capabilities_any,
		seal->top_consistent ? 1U : 0U,
		seal->nonce_consistent ? 1U : 0U,
		seal->verdict_digest_consistent ? 1U : 0U,
		seal->profile_consistent ? 1U : 0U,
		seal->status_consistent ? 1U : 0U,
		seal->top_candidate_id,
		seal->nonce_hex,
		seal->verdict_digest_hex,
		seal->audit_digest_hex,
		seal->seal_digest_hex);

	return finish_render(written, out_size);
}

int pqcp_deployment_marker_render_passport(
	const struct pqcp_deployment_assurance_passport *passport,
	char *out, size_t out_size)
{
	int written;

	if (out == NULL || out_size == 0U) {
		return -EINVAL;
	}
	if (passport == NULL ||
	    passport->schema_version !=
		    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_SCHEMA_VERSION ||
	    !passport_status_valid(passport->status) ||
	    !profile_valid(passport->profile) ||
	    !seal_status_valid(passport->seal_status) ||
	    !seal_audit_status_valid(passport->seal_audit_status) ||
	    (passport->error_mask &
	     ~PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_KNOWN_MASK) != 0U ||
	    (passport->warning_mask &
	     ~PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_KNOWN_MASK) != 0U ||
	    passport->passport_score > 100U ||
	    passport->min_terminal_score > 100U ||
	    passport->capability_readiness_score > 100U ||
	    !text_marker_safe(passport->pqcp_version) ||
	    !text_marker_safe(passport->zephyr_version) ||
	    !text_marker_safe(passport->board) ||
	    !text_marker_safe(passport->top_candidate_id) ||
	    !nonce_valid(passport->nonce_hex) ||
	    !digest64_valid(passport->seal_digest_hex) ||
	    !digest64_valid(passport->seal_audit_digest_hex) ||
	    !digest64_valid(passport->passport_digest_hex)) {
		return -EINVAL;
	}

	written = snprintk(
		out, out_size,
		"PQCP_DEPLOYMENT_ASSURANCE_PASSPORT schema=%u profile=%s status=%s errors=0x%08x warnings=0x%08x score=%u min_score=%u capability_score=%u seal_status=%s seal_audit_status=%s seal_replay_passed=%u audited_results=%u chain_stages=%u evidence_all=0x%08x evidence_any=0x%08x mlkem_levels=0x%08x mldsa_levels=0x%08x top_consistent=%u nonce_consistent=%u digest_consistent=%u profile_consistent=%u production_allowed=%u pqcp_version=%s zephyr_version=%s board=%s top=%s nonce=%s seal_digest=%s seal_audit_digest=%s passport_digest=%s",
		passport->schema_version,
		pqcp_deployment_release_gate_profile_str(passport->profile),
		pqcp_deployment_assurance_passport_status_str(passport->status),
		passport->error_mask,
		passport->warning_mask,
		passport->passport_score,
		passport->min_terminal_score,
		passport->capability_readiness_score,
		pqcp_deployment_evidence_seal_status_str(passport->seal_status),
		pqcp_deployment_evidence_seal_audit_status_str(
			passport->seal_audit_status),
		passport->seal_replay_passed ? 1U : 0U,
		passport->audited_result_count,
		passport->chain_stage_count,
		passport->evidence_capabilities_all,
		passport->evidence_capabilities_any,
		passport->mlkem_level_mask,
		passport->mldsa_level_mask,
		passport->top_consistent ? 1U : 0U,
		passport->nonce_consistent ? 1U : 0U,
		passport->seal_digest_consistent ? 1U : 0U,
		passport->profile_consistent ? 1U : 0U,
		passport->production_allowed ? 1U : 0U,
		passport->pqcp_version,
		passport->zephyr_version,
		passport->board,
		passport->top_candidate_id,
		passport->nonce_hex,
		passport->seal_digest_hex,
		passport->seal_audit_digest_hex,
		passport->passport_digest_hex);

	return finish_render(written, out_size);
}
