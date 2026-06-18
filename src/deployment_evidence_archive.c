/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * End-to-end firmware deployment evidence archive capture.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_evidence_archive.h>

#define ARCHIVE_DOMAIN UINT64_C(0x5051435041524348)

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

static void set_error(
	struct pqcp_deployment_evidence_archive_result *result,
	uint32_t error)
{
	if (result == NULL) {
		return;
	}
	result->error_mask |= error;
	result->status = PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_FAIL;
}

static int digest_result(
	const struct pqcp_deployment_evidence_archive_result *result,
	char output[PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	if (result == NULL || output == NULL) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_init(&digest, ARCHIVE_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)result->status);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->error_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->warning_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->capsule_bytes);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->capsule_records);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->journal_entries);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, result->boot_counter);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, result->capture_time_ms);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, result->capsule_built);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, result->capsule_replayed);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, result->journal_appended);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, result->journal_finalized);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, result->journal_replayed);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, result->capsule_digest_bound);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, result->passport_digest_bound);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, result->signature_verified);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, result->production_allowed);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)result->passport_status);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)result->profile);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->passport_score);
	pqcp_deployment_evidence_digest_update_text(
		&digest, result->device_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, result->board);
	pqcp_deployment_evidence_digest_update_text(
		&digest, result->top_candidate_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, result->passport_digest_hex);
	pqcp_deployment_evidence_digest_update_text(
		&digest, result->capsule_digest_hex);
	pqcp_deployment_evidence_digest_update_text(
		&digest, result->journal_digest_hex);
	return pqcp_deployment_evidence_digest_final_hex(&digest, output);
}

static bool bindings_valid(
	const struct pqcp_deployment_evidence_archive_workspace *workspace)
{
	if (workspace == NULL ||
	    workspace->finalized_snapshot.entry_count == 0U) {
		return false;
	}
	const struct pqcp_deployment_evidence_journal_entry *last =
		&workspace->finalized_snapshot.entries[
			workspace->finalized_snapshot.entry_count - 1U];

	return strcmp(last->capsule_digest_hex,
		      workspace->capsule_replay.capsule_digest_hex) == 0 &&
	       strcmp(last->passport_digest_hex,
		      workspace->capsule_replay.passport_digest_hex) == 0 &&
	       strcmp(workspace->journal_replay.latest_capsule_digest_hex,
		      workspace->capsule_replay.capsule_digest_hex) == 0;
}

const char *pqcp_deployment_evidence_archive_status_str(
	enum pqcp_deployment_evidence_archive_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_FAIL:
	default:
		return "FAIL";
	}
}

int pqcp_deployment_evidence_archive_capture(
	const struct pqcp_deployment_assurance_passport *passport,
	const struct pqcp_deployment_assurance_passport_replay_result *passport_replay,
	const struct pqcp_deployment_passport_signature *signature,
	const char *device_id,
	uint64_t boot_counter,
	uint64_t capture_time_ms,
	uint8_t *capsule_buffer,
	size_t capsule_capacity,
	struct pqcp_deployment_evidence_journal *journal,
	struct pqcp_deployment_evidence_archive_workspace *workspace,
	struct pqcp_deployment_evidence_archive_result *result)
{
	int ret;

	if (result == NULL) {
		return -EINVAL;
	}
	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_SCHEMA_VERSION;
	result->status = PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_FAIL;
	if (passport == NULL || passport_replay == NULL ||
	    device_id == NULL || capsule_buffer == NULL ||
	    capsule_capacity == 0U || journal == NULL ||
	    workspace == NULL) {
		set_error(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_INVALID_INPUT);
		return -EINVAL;
	}
	memset(workspace, 0, sizeof(*workspace));
	result->boot_counter = boot_counter;
	result->capture_time_ms = capture_time_ms;
	set_text(result->device_id, sizeof(result->device_id), device_id);
	if (journal->schema_version == 0U) {
		ret = pqcp_deployment_evidence_journal_init(
			journal, device_id);
		if (ret != 0) {
			set_error(
				result,
				PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_JOURNAL_INIT);
			return ret;
		}
	} else if (journal->schema_version !=
		   PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_SCHEMA_VERSION ||
		   strcmp(journal->device_id, device_id) != 0) {
		set_error(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_JOURNAL_INIT);
		return -EINVAL;
	}
	ret = pqcp_deployment_evidence_capsule_build(
		passport, passport_replay, signature,
		capsule_buffer, capsule_capacity,
		&workspace->capsule);
	if (ret != 0) {
		set_error(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_CAPSULE_BUILD);
		return ret;
	}
	result->capsule_built = true;
	result->capsule_bytes = workspace->capsule.byte_count;
	result->capsule_records = workspace->capsule.record_count;
	ret = pqcp_deployment_evidence_capsule_replay_verify(
		capsule_buffer, workspace->capsule.byte_count,
		&workspace->capsule_workspace,
		&workspace->capsule_replay);
	if (ret != 0 || !workspace->capsule_replay.passed) {
		set_error(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_CAPSULE_REPLAY);
		return ret != 0 ? ret : -EBADMSG;
	}
	result->capsule_replayed = true;
	ret = pqcp_deployment_evidence_journal_append(
		journal, &workspace->capsule_replay,
		boot_counter, capture_time_ms);
	if (ret != 0) {
		set_error(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_JOURNAL_APPEND);
		return ret;
	}
	result->journal_appended = true;
	memcpy(&workspace->finalized_snapshot, journal,
	       sizeof(workspace->finalized_snapshot));
	ret = pqcp_deployment_evidence_journal_finalize(
		&workspace->finalized_snapshot);
	if (ret != 0) {
		set_error(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_JOURNAL_FINALIZE);
		return ret;
	}
	result->journal_finalized = true;
	ret = pqcp_deployment_evidence_journal_replay_verify(
		&workspace->finalized_snapshot,
		&workspace->journal_replay);
	if (ret != 0 || !workspace->journal_replay.passed) {
		set_error(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_JOURNAL_REPLAY);
		return ret != 0 ? ret : -EBADMSG;
	}
	result->journal_replayed = true;
	result->journal_entries =
		workspace->journal_replay.entries_checked;
	result->capsule_digest_bound = bindings_valid(workspace);
	result->passport_digest_bound =
		strcmp(workspace->capsule.passport_digest_hex,
		       workspace->capsule_replay.passport_digest_hex) == 0;
	if (!result->capsule_digest_bound ||
	    !result->passport_digest_bound) {
		set_error(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_BINDING);
		return -EBADMSG;
	}
	result->signature_verified =
		workspace->capsule_replay.signature_verified;
	result->production_allowed =
		workspace->capsule_replay.production_allowed;
	result->passport_status =
		workspace->capsule_replay.passport_status;
	result->profile = workspace->capsule_replay.profile;
	result->passport_score =
		workspace->capsule_replay.passport_score;
	set_text(result->board, sizeof(result->board),
		  workspace->capsule_replay.board);
	set_text(result->top_candidate_id,
		  sizeof(result->top_candidate_id),
		  workspace->capsule_replay.top_candidate_id);
	set_text(result->passport_digest_hex,
		  sizeof(result->passport_digest_hex),
		  workspace->capsule_replay.passport_digest_hex);
	set_text(result->capsule_digest_hex,
		  sizeof(result->capsule_digest_hex),
		  workspace->capsule_replay.capsule_digest_hex);
	set_text(result->journal_digest_hex,
		  sizeof(result->journal_digest_hex),
		  workspace->journal_replay.computed_journal_digest_hex);
	if (result->passport_status !=
	    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS) {
		result->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_WARNING_PASSPORT_NOT_PASS;
	}
	if (!result->signature_verified) {
		result->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_WARNING_UNSIGNED;
	}
	if (!result->production_allowed) {
		result->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_WARNING_NON_PRODUCTION;
	}
	result->status = result->warning_mask != 0U ?
				 PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_WARN :
				 PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_PASS;
	ret = digest_result(result, result->archive_digest_hex);
	if (ret != 0) {
		set_error(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_DIGEST);
		return ret;
	}
	return 0;
}

int pqcp_deployment_evidence_archive_emit(
	const struct pqcp_deployment_evidence_archive_result *result)
{
	if (result == NULL ||
	    result->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_SCHEMA_VERSION ||
	    (result->error_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_KNOWN_MASK) != 0U ||
	    (result->warning_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_WARNING_KNOWN_MASK) != 0U) {
		return -EINVAL;
	}
	printk("PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE schema=%u status=%s "
	       "errors=0x%08x warnings=0x%08x capsule_bytes=%u "
	       "capsule_records=%u journal_entries=%u boot=%llu "
	       "time_ms=%llu capsule_built=%u capsule_replayed=%u "
	       "journal_appended=%u journal_finalized=%u journal_replayed=%u "
	       "capsule_bound=%u passport_bound=%u signature_verified=%u "
	       "production=%u passport_status=%u profile=%u score=%u "
	       "device=%s board=%s top=%s passport_digest=%s "
	       "capsule_digest=%s journal_digest=%s archive_digest=%s\n",
	       result->schema_version,
	       pqcp_deployment_evidence_archive_status_str(result->status),
	       result->error_mask, result->warning_mask,
	       result->capsule_bytes, result->capsule_records,
	       result->journal_entries,
	       (unsigned long long)result->boot_counter,
	       (unsigned long long)result->capture_time_ms,
	       result->capsule_built ? 1U : 0U,
	       result->capsule_replayed ? 1U : 0U,
	       result->journal_appended ? 1U : 0U,
	       result->journal_finalized ? 1U : 0U,
	       result->journal_replayed ? 1U : 0U,
	       result->capsule_digest_bound ? 1U : 0U,
	       result->passport_digest_bound ? 1U : 0U,
	       result->signature_verified ? 1U : 0U,
	       result->production_allowed ? 1U : 0U,
	       (uint32_t)result->passport_status,
	       (uint32_t)result->profile, result->passport_score,
	       result->device_id, result->board,
	       result->top_candidate_id, result->passport_digest_hex,
	       result->capsule_digest_hex, result->journal_digest_hex,
	       result->archive_digest_hex);
	return 0;
}
