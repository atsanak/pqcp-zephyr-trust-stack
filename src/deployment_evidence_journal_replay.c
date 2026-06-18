/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Independent replay verification for deployment evidence journals.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_evidence_journal_replay.h>

#define JOURNAL_ENTRY_DOMAIN UINT64_C(0x505143504a454e54)
#define JOURNAL_ROOT_DOMAIN UINT64_C(0x505143504a524f4f)

static const char zero_digest[] =
	"0000000000000000000000000000000000000000000000000000000000000000";

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

static bool text_valid(const char *text, size_t capacity)
{
	return text != NULL && text[0] != '\0' &&
	       strnlen(text, capacity) < capacity;
}

static bool digest_valid(const char *digest)
{
	return pqcp_deployment_evidence_codec_is_lower_hex(
		digest, PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS);
}

static bool passport_status_valid(
	enum pqcp_deployment_assurance_passport_status status)
{
	return status == PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL ||
	       status == PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARN ||
	       status == PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS;
}

static bool profile_valid(enum pqcp_deployment_release_gate_profile profile)
{
	return profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER;
}

static void replay_fail(
	struct pqcp_deployment_evidence_journal_replay_result *result,
	enum pqcp_deployment_evidence_journal_replay_error error,
	uint32_t entry)
{
	if (result == NULL) {
		return;
	}
	result->passed = false;
	if (result->first_error ==
	    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_NONE) {
		result->first_error = error;
		result->first_error_entry = entry;
	}
}

static int fail_with(
	struct pqcp_deployment_evidence_journal_replay_result *result,
	enum pqcp_deployment_evidence_journal_replay_error error,
	uint32_t entry,
	int ret)
{
	replay_fail(result, error, entry);
	return ret;
}

static bool entry_shape_valid(
	const struct pqcp_deployment_evidence_journal_entry *entry)
{
	return entry != NULL &&
	       entry->schema_version ==
		       PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_SCHEMA_VERSION &&
	       entry->sequence != 0U &&
	       passport_status_valid(entry->passport_status) &&
	       profile_valid(entry->profile) &&
	       entry->passport_score <= 100U &&
	       entry->capsule_bytes >=
		       PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_HEADER_BYTES &&
	       entry->capsule_bytes <=
		       PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_BYTES &&
	       entry->capsule_records != 0U &&
	       entry->capsule_records <=
		       PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_RECORDS &&
	       entry->capsule_replayed &&
	       (!entry->signature_present || entry->signature_verified) &&
	       text_valid(entry->device_id, sizeof(entry->device_id)) &&
	       text_valid(entry->board, sizeof(entry->board)) &&
	       text_valid(entry->top_candidate_id,
			  sizeof(entry->top_candidate_id)) &&
	       pqcp_deployment_evidence_codec_is_lower_hex(
		       entry->nonce_hex,
		       PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS) &&
	       digest_valid(entry->passport_digest_hex) &&
	       digest_valid(entry->capsule_digest_hex) &&
	       digest_valid(entry->previous_entry_digest_hex) &&
	       digest_valid(entry->entry_digest_hex);
}

static int digest_entry(
	const struct pqcp_deployment_evidence_journal_entry *entry,
	char output[PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	if (entry == NULL || output == NULL) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_init(
		&digest, JOURNAL_ENTRY_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, entry->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, entry->sequence);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, entry->boot_counter);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, entry->capture_time_ms);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)entry->passport_status);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)entry->profile);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, entry->passport_score);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, entry->capsule_bytes);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, entry->capsule_records);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, entry->capsule_replayed);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, entry->signature_present);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, entry->signature_verified);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, entry->production_allowed);
	pqcp_deployment_evidence_digest_update_text(
		&digest, entry->device_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, entry->board);
	pqcp_deployment_evidence_digest_update_text(
		&digest, entry->top_candidate_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, entry->nonce_hex);
	pqcp_deployment_evidence_digest_update_text(
		&digest, entry->passport_digest_hex);
	pqcp_deployment_evidence_digest_update_text(
		&digest, entry->capsule_digest_hex);
	pqcp_deployment_evidence_digest_update_text(
		&digest, entry->previous_entry_digest_hex);
	return pqcp_deployment_evidence_digest_final_hex(&digest, output);
}

static int digest_journal(
	const struct pqcp_deployment_evidence_journal *journal,
	char output[PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	if (journal == NULL || output == NULL) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_init(
		&digest, JOURNAL_ROOT_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, journal->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, journal->entry_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, journal->pass_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, journal->warn_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, journal->fail_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, journal->signed_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, journal->production_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, journal->distinct_capsule_count);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, journal->first_boot_counter);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, journal->last_boot_counter);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, journal->first_capture_time_ms);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, journal->last_capture_time_ms);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, journal->monotonic_boot_counters);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, journal->monotonic_capture_times);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, journal->unique_capsules);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, journal->stable_device_id);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, journal->stable_board);
	pqcp_deployment_evidence_digest_update_text(
		&digest, journal->device_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, journal->board);
	for (size_t index = 0U; index < journal->entry_count; ++index) {
		pqcp_deployment_evidence_digest_update_text(
			&digest,
			journal->entries[index].entry_digest_hex);
	}
	return pqcp_deployment_evidence_digest_final_hex(&digest, output);
}

static void count_status(
	struct pqcp_deployment_evidence_journal_replay_result *result,
	enum pqcp_deployment_assurance_passport_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS:
		result->pass_count++;
		break;
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARN:
		result->warn_count++;
		break;
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL:
	default:
		result->fail_count++;
		break;
	}
}

static bool capsule_digest_seen(
	const struct pqcp_deployment_evidence_journal *journal,
	size_t before,
	const char *digest)
{
	for (size_t index = 0U; index < before; ++index) {
		if (strcmp(journal->entries[index].capsule_digest_hex,
			   digest) == 0) {
			return true;
		}
	}
	return false;
}

static int verify_entry(
	const struct pqcp_deployment_evidence_journal *journal,
	size_t index,
	struct pqcp_deployment_evidence_journal_replay_result *result)
{
	const struct pqcp_deployment_evidence_journal_entry *entry =
		&journal->entries[index];
	char computed[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS + 1U];
	const char *expected_previous =
		index == 0U ? zero_digest :
			journal->entries[index - 1U].entry_digest_hex;
	int ret;

	if (!entry_shape_valid(entry)) {
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_ENTRY_SCHEMA,
			(uint32_t)(index + 1U), -EBADMSG);
	}
	if (entry->sequence != index + 1U) {
		result->sequence_valid = false;
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_SEQUENCE,
			(uint32_t)(index + 1U), -EBADMSG);
	}
	if (index != 0U &&
	    entry->boot_counter <=
		    journal->entries[index - 1U].boot_counter) {
		result->boot_counters_valid = false;
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_BOOT_COUNTER,
			(uint32_t)(index + 1U), -EBADMSG);
	}
	if (index != 0U &&
	    entry->capture_time_ms <
		    journal->entries[index - 1U].capture_time_ms) {
		result->capture_times_valid = false;
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_TIME_ORDER,
			(uint32_t)(index + 1U), -EBADMSG);
	}
	if (strcmp(entry->device_id, journal->device_id) != 0) {
		result->device_stable = false;
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_DEVICE_DRIFT,
			(uint32_t)(index + 1U), -EBADMSG);
	}
	if (strcmp(entry->board, journal->board) != 0) {
		result->board_stable = false;
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_BOARD_DRIFT,
			(uint32_t)(index + 1U), -EBADMSG);
	}
	if (capsule_digest_seen(
		    journal, index, entry->capsule_digest_hex)) {
		result->capsules_unique = false;
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_DUPLICATE_CAPSULE,
			(uint32_t)(index + 1U), -EBADMSG);
	}
	if (strcmp(entry->previous_entry_digest_hex,
		   expected_previous) != 0) {
		result->entry_chain_valid = false;
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_PREVIOUS_DIGEST,
			(uint32_t)(index + 1U), -EBADMSG);
	}
	ret = digest_entry(entry, computed);
	if (ret != 0 || strcmp(computed, entry->entry_digest_hex) != 0) {
		result->entry_chain_valid = false;
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_ENTRY_DIGEST,
			(uint32_t)(index + 1U), -EBADMSG);
	}
	result->entries_checked++;
	count_status(result, entry->passport_status);
	if (entry->signature_present && entry->signature_verified) {
		result->signed_count++;
	}
	if (entry->production_allowed) {
		result->production_count++;
	}
	result->distinct_capsule_count++;
	if (index == 0U) {
		result->first_boot_counter = entry->boot_counter;
		result->first_capture_time_ms = entry->capture_time_ms;
		set_text(result->first_entry_digest_hex,
			 sizeof(result->first_entry_digest_hex),
			 entry->entry_digest_hex);
	}
	result->last_boot_counter = entry->boot_counter;
	result->last_capture_time_ms = entry->capture_time_ms;
	result->latest_passport_status = entry->passport_status;
	result->latest_profile = entry->profile;
	result->latest_passport_score = entry->passport_score;
	result->latest_signature_verified =
		entry->signature_present && entry->signature_verified;
	result->latest_production_allowed = entry->production_allowed;
	set_text(result->latest_top_candidate_id,
		 sizeof(result->latest_top_candidate_id),
		 entry->top_candidate_id);
	set_text(result->latest_capsule_digest_hex,
		 sizeof(result->latest_capsule_digest_hex),
		 entry->capsule_digest_hex);
	set_text(result->last_entry_digest_hex,
		 sizeof(result->last_entry_digest_hex),
		 entry->entry_digest_hex);
	return 0;
}

static bool summary_matches(
	const struct pqcp_deployment_evidence_journal *journal,
	const struct pqcp_deployment_evidence_journal_replay_result *result)
{
	return journal->entry_count == result->entries_checked &&
	       journal->pass_count == result->pass_count &&
	       journal->warn_count == result->warn_count &&
	       journal->fail_count == result->fail_count &&
	       journal->signed_count == result->signed_count &&
	       journal->production_count == result->production_count &&
	       journal->distinct_capsule_count ==
		       result->distinct_capsule_count &&
	       journal->first_boot_counter ==
		       result->first_boot_counter &&
	       journal->last_boot_counter ==
		       result->last_boot_counter &&
	       journal->first_capture_time_ms ==
		       result->first_capture_time_ms &&
	       journal->last_capture_time_ms ==
		       result->last_capture_time_ms &&
	       journal->monotonic_boot_counters &&
	       journal->monotonic_capture_times &&
	       journal->unique_capsules &&
	       journal->stable_device_id &&
	       journal->stable_board &&
	       strcmp(journal->first_entry_digest_hex,
		      result->first_entry_digest_hex) == 0 &&
	       strcmp(journal->last_entry_digest_hex,
		      result->last_entry_digest_hex) == 0;
}

const char *pqcp_deployment_evidence_journal_replay_error_str(
	enum pqcp_deployment_evidence_journal_replay_error error)
{
	switch (error) {
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_NONE:
		return "none";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_INVALID_ARGUMENT:
		return "invalid_argument";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_BAD_SCHEMA:
		return "bad_schema";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_NOT_FINALIZED:
		return "not_finalized";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_EMPTY:
		return "empty";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_ENTRY_SCHEMA:
		return "entry_schema";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_SEQUENCE:
		return "sequence";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_BOOT_COUNTER:
		return "boot_counter";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_TIME_ORDER:
		return "time_order";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_DEVICE_DRIFT:
		return "device_drift";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_BOARD_DRIFT:
		return "board_drift";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_DUPLICATE_CAPSULE:
		return "duplicate_capsule";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_PREVIOUS_DIGEST:
		return "previous_digest";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_ENTRY_DIGEST:
		return "entry_digest";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_SUMMARY:
		return "summary";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_ROOT_DIGEST:
		return "root_digest";
	default:
		return "unknown";
	}
}

int pqcp_deployment_evidence_journal_replay_verify(
	const struct pqcp_deployment_evidence_journal *journal,
	struct pqcp_deployment_evidence_journal_replay_result *result)
{
	char computed[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS + 1U];
	int ret;

	if (result == NULL) {
		return -EINVAL;
	}
	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_SCHEMA_VERSION;
	result->first_error =
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_NONE;
	result->sequence_valid = true;
	result->boot_counters_valid = true;
	result->capture_times_valid = true;
	result->device_stable = true;
	result->board_stable = true;
	result->capsules_unique = true;
	result->entry_chain_valid = true;
	set_text(result->first_entry_digest_hex,
		 sizeof(result->first_entry_digest_hex), zero_digest);
	set_text(result->last_entry_digest_hex,
		 sizeof(result->last_entry_digest_hex), zero_digest);
	set_text(result->computed_journal_digest_hex,
		 sizeof(result->computed_journal_digest_hex), zero_digest);
	if (journal == NULL) {
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_INVALID_ARGUMENT,
			0U, -EINVAL);
	}
	if (journal->schema_version !=
	    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_SCHEMA_VERSION) {
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_BAD_SCHEMA,
			0U, -EPROTONOSUPPORT);
	}
	if (journal->status !=
	    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_FINALIZED) {
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_NOT_FINALIZED,
			0U, -EPERM);
	}
	if (journal->entry_count == 0U ||
	    journal->entry_count >
		    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_MAX_ENTRIES) {
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_EMPTY,
			0U, -ENODATA);
	}
	if (!text_valid(journal->device_id,
			sizeof(journal->device_id)) ||
	    !text_valid(journal->board, sizeof(journal->board)) ||
	    !digest_valid(journal->journal_digest_hex)) {
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_SUMMARY,
			0U, -EBADMSG);
	}
	set_text(result->device_id, sizeof(result->device_id),
		 journal->device_id);
	set_text(result->board, sizeof(result->board),
		 journal->board);
	for (size_t index = 0U; index < journal->entry_count; ++index) {
		ret = verify_entry(journal, index, result);
		if (ret != 0) {
			return ret;
		}
	}
	result->summary_valid = summary_matches(journal, result);
	if (!result->summary_valid) {
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_SUMMARY,
			0U, -EBADMSG);
	}
	ret = digest_journal(journal, computed);
	if (ret != 0 ||
	    strcmp(computed, journal->journal_digest_hex) != 0) {
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_ROOT_DIGEST,
			0U, -EBADMSG);
	}
	set_text(result->computed_journal_digest_hex,
		 sizeof(result->computed_journal_digest_hex), computed);
	result->root_digest_valid = true;
	result->passed = true;
	return 0;
}

int pqcp_deployment_evidence_journal_replay_emit(
	const struct pqcp_deployment_evidence_journal_replay_result *result)
{
	if (result == NULL ||
	    result->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_SCHEMA_VERSION ||
	    result->entries_checked >
		    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_MAX_ENTRIES) {
		return -EINVAL;
	}
	printk("PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY schema=%u "
	       "status=%s error=%s error_entry=%u entries=%u pass=%u "
	       "warn=%u fail=%u signed=%u production=%u distinct=%u "
	       "first_boot=%llu last_boot=%llu first_time_ms=%llu "
	       "last_time_ms=%llu latest_status=%u latest_profile=%u "
	       "latest_score=%u latest_signed=%u latest_production=%u "
	       "sequence=%u boot_order=%u time_order=%u "
	       "device_stable=%u board_stable=%u unique=%u chain=%u "
	       "summary=%u root_digest=%u device=%s board=%s "
	       "latest_top=%s latest_capsule=%s first_digest=%s "
	       "last_digest=%s journal_digest=%s\n",
	       result->schema_version, result->passed ? "PASS" : "FAIL",
	       pqcp_deployment_evidence_journal_replay_error_str(
		       result->first_error),
	       result->first_error_entry, result->entries_checked,
	       result->pass_count, result->warn_count,
	       result->fail_count, result->signed_count,
	       result->production_count, result->distinct_capsule_count,
	       (unsigned long long)result->first_boot_counter,
	       (unsigned long long)result->last_boot_counter,
	       (unsigned long long)result->first_capture_time_ms,
	       (unsigned long long)result->last_capture_time_ms,
	       (uint32_t)result->latest_passport_status,
	       (uint32_t)result->latest_profile,
	       result->latest_passport_score,
	       result->latest_signature_verified ? 1U : 0U,
	       result->latest_production_allowed ? 1U : 0U,
	       result->sequence_valid ? 1U : 0U,
	       result->boot_counters_valid ? 1U : 0U,
	       result->capture_times_valid ? 1U : 0U,
	       result->device_stable ? 1U : 0U,
	       result->board_stable ? 1U : 0U,
	       result->capsules_unique ? 1U : 0U,
	       result->entry_chain_valid ? 1U : 0U,
	       result->summary_valid ? 1U : 0U,
	       result->root_digest_valid ? 1U : 0U,
	       result->device_id, result->board,
	       result->latest_top_candidate_id,
	       result->latest_capsule_digest_hex,
	       result->first_entry_digest_hex,
	       result->last_entry_digest_hex,
	       result->computed_journal_digest_hex);
	return 0;
}
