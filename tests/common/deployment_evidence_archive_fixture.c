/*
 * SPDX-License-Identifier: MIT
 *
 * Shared authentic fixture construction for deployment archive ztests.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include "deployment_evidence_archive_fixture.h"

static const char default_verdict_digest[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char default_audit_digest[] =
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

static void set_text(char *destination, size_t capacity, const char *source)
{
	if (destination == NULL || capacity == 0U) {
		return;
	}
	if (source == NULL) {
		destination[0] = '\0';
		return;
	}
	(void)snprintk(destination, capacity, "%s", source);
}

static uint32_t full_caps(void)
{
	return PQCP_CAPABILITY_EVIDENCE_KNOWN_MASK;
}

static void fill_capability(
	struct pqcp_capability_descriptor *capability,
	const char *board,
	bool production_allowed)
{
	memset(capability, 0, sizeof(*capability));
	capability->schema_version =
		PQCP_CAPABILITY_DESCRIPTOR_SCHEMA_VERSION;
	capability->pqcp_version = "1.0.0";
	capability->zephyr_version = "4.4.0";
	capability->board = board;
	capability->profile =
		production_allowed ?
			PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL :
			PQCP_FIRMWARE_POLICY_PROFILE_EVIDENCE_LAB;
	capability->mlkem_level_mask = 0x00000300U;
	capability->mldsa_level_mask = 0x00000041U;
	capability->rng_mode =
		production_allowed ? "zephyr_entropy" : "custom";
	capability->provider_summary =
		PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE;
	capability->backend_selector = "auto";
	capability->evidence_capabilities = full_caps();
	capability->policy_passed = true;
	capability->production_allowed = production_allowed;
	capability->evidence_readiness_score =
		production_allowed ? 96U : 82U;
}

static void fill_seal(
	struct pqcp_deployment_evidence_seal *seal,
	const char *top_candidate,
	const char *nonce)
{
	memset(seal, 0, sizeof(*seal));
	seal->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_SCHEMA_VERSION;
	seal->status = PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS;
	seal->profile =
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	seal->seal_score = 87U;
	seal->min_terminal_score = 87U;
	seal->verdict_status =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS;
	seal->audit_status =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_PASS;
	seal->audited_result_count = 2U;
	seal->chain_stage_count = 16U;
	seal->chain_consistency_checks = 7U;
	seal->evidence_capabilities_all = full_caps();
	seal->evidence_capabilities_any = full_caps();
	seal->replay_passed = true;
	seal->top_consistent = true;
	seal->nonce_consistent = true;
	seal->verdict_digest_consistent = true;
	seal->profile_consistent = true;
	seal->status_consistent = true;
	set_text(seal->top_candidate_id,
		 sizeof(seal->top_candidate_id), top_candidate);
	set_text(seal->nonce_hex, sizeof(seal->nonce_hex), nonce);
	set_text(seal->verdict_digest_hex,
		 sizeof(seal->verdict_digest_hex),
		 default_verdict_digest);
	set_text(seal->audit_digest_hex,
		 sizeof(seal->audit_digest_hex), default_audit_digest);
	set_text(seal->seal_digest_hex,
		 sizeof(seal->seal_digest_hex), default_verdict_digest);
}

static void fill_seal_replay(
	struct pqcp_deployment_evidence_seal_replay_result *replay,
	const char *top_candidate,
	const char *nonce)
{
	memset(replay, 0, sizeof(*replay));
	replay->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_SCHEMA_VERSION;
	replay->lines_seen = 1U;
	replay->marker_mask =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_REQUIRED_MASK;
	replay->first_error =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_NONE;
	replay->seal_status = PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS;
	replay->profile =
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	replay->seal_score = 87U;
	replay->min_terminal_score = 87U;
	replay->verdict_status =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS;
	replay->audit_status =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_PASS;
	replay->sealed_replay_passed = true;
	replay->audited_result_count = 2U;
	replay->chain_stage_count = 16U;
	replay->chain_consistency_checks = 7U;
	replay->evidence_capabilities_all = full_caps();
	replay->evidence_capabilities_any = full_caps();
	replay->passed = true;
	set_text(replay->top_candidate_id,
		 sizeof(replay->top_candidate_id), top_candidate);
	set_text(replay->nonce_hex, sizeof(replay->nonce_hex), nonce);
	set_text(replay->verdict_digest_hex,
		 sizeof(replay->verdict_digest_hex),
		 default_verdict_digest);
	set_text(replay->audit_digest_hex,
		 sizeof(replay->audit_digest_hex), default_audit_digest);
	set_text(replay->computed_digest_hex,
		 sizeof(replay->computed_digest_hex),
		 default_verdict_digest);
}

static void fill_seal_audit(
	struct pqcp_deployment_evidence_seal_audit_report *audit,
	const char *top_candidate,
	const char *nonce)
{
	memset(audit, 0, sizeof(*audit));
	audit->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_SCHEMA_VERSION;
	audit->status =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_PASS;
	audit->result_count = 2U;
	audit->replay_pass_count = 2U;
	audit->seal_pass_count = 2U;
	audit->unique_seal_digest_count = 1U;
	audit->min_seal_score = 87U;
	audit->max_seal_score = 87U;
	audit->avg_seal_score = 87U;
	audit->min_terminal_score = 87U;
	audit->max_terminal_score = 87U;
	audit->avg_terminal_score = 87U;
	audit->evidence_capabilities_all = full_caps();
	audit->evidence_capabilities_any = full_caps();
	audit->stable_top_candidate = true;
	audit->stable_nonce = true;
	audit->stable_seal_digest = true;
	audit->stable_capabilities = true;
	audit->stable_seal_status = true;
	audit->stable_profile = true;
	audit->profile =
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	set_text(audit->top_candidate_id,
		 sizeof(audit->top_candidate_id), top_candidate);
	set_text(audit->nonce_hex, sizeof(audit->nonce_hex), nonce);
	set_text(audit->seal_digest_hex,
		 sizeof(audit->seal_digest_hex), default_verdict_digest);
	set_text(audit->audit_digest_hex,
		 sizeof(audit->audit_digest_hex), default_audit_digest);
}

int pqcp_archive_test_build_passport(
	struct pqcp_archive_test_fixture *fixture,
	const char *board,
	const char *top_candidate,
	const char *nonce,
	bool production_allowed)
{
	int ret;

	if (fixture == NULL || board == NULL ||
	    top_candidate == NULL || nonce == NULL) {
		return -EINVAL;
	}
	memset(fixture, 0, sizeof(*fixture));
	fill_capability(&fixture->capability, board,
			production_allowed);
	fill_seal(&fixture->seal, top_candidate, nonce);
	fill_seal_replay(&fixture->seal_replay,
			 top_candidate, nonce);
	fill_seal_audit(&fixture->seal_audit,
			top_candidate, nonce);
	ret = pqcp_deployment_assurance_passport_default_policy(
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
		&fixture->passport_policy);
	if (ret != 0) {
		return ret;
	}
	if (!production_allowed) {
		fixture->passport_policy.require_production_allowed = false;
	}
	ret = pqcp_deployment_assurance_passport_run(
		&fixture->capability, &fixture->seal,
		&fixture->seal_replay, &fixture->seal_audit,
		&fixture->passport_policy, &fixture->passport);
	if (ret != 0 && ret != -EBADMSG) {
		return ret;
	}
	return pqcp_deployment_assurance_passport_replay_verify(
		&fixture->passport, &fixture->passport_replay);
}

void pqcp_archive_test_increment_digest(
	char digest[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U],
	uint32_t increment)
{
	static const char alphabet[] = "0123456789abcdef";

	if (digest == NULL) {
		return;
	}
	for (size_t index = 0U;
	     index < PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS - 8U;
	     ++index) {
		digest[index] =
			alphabet[(index + (increment >> 4U)) & 0x0fU];
	}
	for (size_t index = 0U; index < 8U; ++index) {
		const uint32_t shift = (7U - (uint32_t)index) * 4U;

		digest[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS -
		       8U + index] = alphabet[(increment >> shift) & 0x0fU];
	}
	digest[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS] = '\0';
}

void pqcp_archive_test_fill_capsule_replay(
	struct pqcp_deployment_evidence_capsule_replay_result *result,
	const char *board,
	const char *top_candidate,
	const char *nonce,
	const char *passport_digest,
	const char *capsule_digest,
	uint32_t score,
	bool signed_verified,
	bool production_allowed)
{
	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_SCHEMA_VERSION;
	result->passed = true;
	result->first_error =
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_NONE;
	result->codec_error = PQCP_DEPLOYMENT_EVIDENCE_CODEC_OK;
	result->flags =
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_REPLAY_PASSED |
		(signed_verified ?
			 PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_SIGNED : 0U) |
		(production_allowed ?
			 PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_PRODUCTION : 0U) |
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_PASSPORT_PASS;
	result->records_expected = signed_verified ? 8U : 5U;
	result->records_seen = result->records_expected;
	result->bytes_consumed = signed_verified ? 5600U : 420U;
	result->record_mask = signed_verified ? 0x000000feU : 0x0000001eU;
	result->passport_status =
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS;
	result->profile =
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	result->passport_score = score;
	result->passport_replayed = true;
	result->signature_present = signed_verified;
	result->signature_verified = signed_verified;
	result->digest_verified = true;
	result->production_allowed = production_allowed;
	set_text(result->board, sizeof(result->board), board);
	set_text(result->top_candidate_id,
		 sizeof(result->top_candidate_id), top_candidate);
	set_text(result->nonce_hex, sizeof(result->nonce_hex), nonce);
	set_text(result->passport_digest_hex,
		 sizeof(result->passport_digest_hex), passport_digest);
	set_text(result->capsule_digest_hex,
		 sizeof(result->capsule_digest_hex), capsule_digest);
}

void pqcp_archive_test_fill_journal_replay(
	struct pqcp_deployment_evidence_journal_replay_result *result,
	const char *device_id,
	const char *board,
	const char *top_candidate,
	const char *root_digest,
	const char *capsule_digest,
	uint32_t entries,
	uint32_t score,
	bool signed_verified,
	bool production_allowed)
{
	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_SCHEMA_VERSION;
	result->passed = true;
	result->first_error =
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_NONE;
	result->entries_checked = entries;
	result->pass_count = entries;
	result->signed_count = signed_verified ? entries : 0U;
	result->production_count =
		production_allowed ? entries : 0U;
	result->distinct_capsule_count = entries;
	result->first_boot_counter = 1U;
	result->last_boot_counter = entries;
	result->first_capture_time_ms = 1000U;
	result->last_capture_time_ms =
		1000U + (uint64_t)entries * 100U;
	result->latest_passport_status =
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS;
	result->latest_profile =
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	result->latest_passport_score = score;
	result->latest_signature_verified = signed_verified;
	result->latest_production_allowed = production_allowed;
	result->sequence_valid = true;
	result->boot_counters_valid = true;
	result->capture_times_valid = true;
	result->device_stable = true;
	result->board_stable = true;
	result->capsules_unique = true;
	result->entry_chain_valid = true;
	result->summary_valid = true;
	result->root_digest_valid = true;
	set_text(result->device_id, sizeof(result->device_id), device_id);
	set_text(result->board, sizeof(result->board), board);
	set_text(result->latest_top_candidate_id,
		 sizeof(result->latest_top_candidate_id), top_candidate);
	set_text(result->latest_capsule_digest_hex,
		 sizeof(result->latest_capsule_digest_hex), capsule_digest);
	set_text(result->first_entry_digest_hex,
		 sizeof(result->first_entry_digest_hex), root_digest);
	set_text(result->last_entry_digest_hex,
		 sizeof(result->last_entry_digest_hex), root_digest);
	set_text(result->computed_journal_digest_hex,
		 sizeof(result->computed_journal_digest_hex), root_digest);
}

void pqcp_archive_test_fill_journal_audit(
	struct pqcp_deployment_evidence_journal_audit_report *report,
	const char *device_id,
	const char *board,
	const char *first_root,
	const char *last_root,
	const char *audit_digest,
	uint32_t snapshots,
	uint32_t entries,
	uint32_t score,
	enum pqcp_deployment_evidence_journal_audit_status status)
{
	memset(report, 0, sizeof(*report));
	report->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_SCHEMA_VERSION;
	report->status = status;
	report->snapshot_count = snapshots;
	report->replay_pass_count = snapshots;
	report->min_entries = entries;
	report->max_entries = entries;
	report->total_entries = snapshots * entries;
	report->min_score = score;
	report->max_score = score;
	report->average_score = score;
	report->signed_entries = snapshots * entries;
	report->production_entries = snapshots * entries;
	report->distinct_root_count = snapshots;
	report->first_boot_counter = 1U;
	report->last_boot_counter = entries;
	report->first_capture_time_ms = 1000U;
	report->last_capture_time_ms = 2000U;
	report->stable_device_id = true;
	report->stable_board = true;
	report->monotonic_entry_growth = true;
	report->monotonic_boot_counter = true;
	report->monotonic_capture_time = true;
	report->unique_roots = true;
	report->signature_non_regression = true;
	report->production_non_regression = true;
	set_text(report->device_id, sizeof(report->device_id), device_id);
	set_text(report->board, sizeof(report->board), board);
	set_text(report->first_root_digest_hex,
		 sizeof(report->first_root_digest_hex), first_root);
	set_text(report->last_root_digest_hex,
		 sizeof(report->last_root_digest_hex), last_root);
	set_text(report->audit_digest_hex,
		 sizeof(report->audit_digest_hex), audit_digest);
}
