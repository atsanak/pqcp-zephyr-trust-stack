/*
 * SPDX-License-Identifier: MIT
 *
 * Append-only firmware deployment evidence journal.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_evidence_journal.h>

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

static bool capsule_valid(
	const struct pqcp_deployment_evidence_capsule_replay_result *capsule)
{
	return capsule != NULL &&
	       capsule->schema_version ==
		       PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_SCHEMA_VERSION &&
	       capsule->passed && capsule->digest_verified &&
	       capsule->passport_replayed &&
	       capsule->first_error ==
		       PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_NONE &&
	       capsule->records_seen == capsule->records_expected &&
	       capsule->records_seen != 0U &&
	       capsule->records_seen <=
		       PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_RECORDS &&
	       capsule->bytes_consumed >=
		       PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_HEADER_BYTES &&
	       capsule->bytes_consumed <=
		       PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_BYTES &&
	       text_valid(capsule->board, sizeof(capsule->board)) &&
	       text_valid(capsule->top_candidate_id,
			  sizeof(capsule->top_candidate_id)) &&
	       pqcp_deployment_evidence_codec_is_lower_hex(
		       capsule->nonce_hex,
		       PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS) &&
	       digest_valid(capsule->passport_digest_hex) &&
	       digest_valid(capsule->capsule_digest_hex);
}

static void journal_fail(
	struct pqcp_deployment_evidence_journal *journal,
	enum pqcp_deployment_evidence_journal_error error)
{
	if (journal == NULL) {
		return;
	}
	journal->status = PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_FAILED;
	if (journal->first_error ==
	    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_NONE) {
		journal->first_error = error;
	}
}

static enum pqcp_deployment_evidence_journal_error
validate_append_order(
	const struct pqcp_deployment_evidence_journal *journal,
	const struct pqcp_deployment_evidence_capsule_replay_result *capsule,
	uint64_t boot_counter,
	uint64_t capture_time_ms)
{
	if (journal->entry_count == 0U) {
		return PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_NONE;
	}
	const struct pqcp_deployment_evidence_journal_entry *last =
		&journal->entries[journal->entry_count - 1U];

	if (boot_counter <= last->boot_counter) {
		return PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_BOOT_COUNTER;
	}
	if (capture_time_ms < last->capture_time_ms) {
		return PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_TIME_ORDER;
	}
	for (size_t index = 0U; index < journal->entry_count; ++index) {
		if (strcmp(journal->entries[index].capsule_digest_hex,
			   capsule->capsule_digest_hex) == 0) {
			return PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_DUPLICATE;
		}
	}
	return PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_NONE;
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

static void update_status_counts(
	struct pqcp_deployment_evidence_journal *journal,
	enum pqcp_deployment_assurance_passport_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS:
		journal->pass_count++;
		break;
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARN:
		journal->warn_count++;
		break;
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL:
	default:
		journal->fail_count++;
		break;
	}
}

static void fill_entry(
	struct pqcp_deployment_evidence_journal_entry *entry,
	const struct pqcp_deployment_evidence_journal *journal,
	const struct pqcp_deployment_evidence_capsule_replay_result *capsule,
	uint64_t boot_counter,
	uint64_t capture_time_ms)
{
	memset(entry, 0, sizeof(*entry));
	entry->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_SCHEMA_VERSION;
	entry->sequence = journal->entry_count + 1U;
	entry->boot_counter = boot_counter;
	entry->capture_time_ms = capture_time_ms;
	entry->passport_status = capsule->passport_status;
	entry->profile = capsule->profile;
	entry->passport_score = capsule->passport_score;
	entry->capsule_bytes = capsule->bytes_consumed;
	entry->capsule_records = capsule->records_seen;
	entry->capsule_replayed = capsule->passed;
	entry->signature_present = capsule->signature_present;
	entry->signature_verified = capsule->signature_verified;
	entry->production_allowed = capsule->production_allowed;
	set_text(entry->device_id, sizeof(entry->device_id),
		  journal->device_id);
	set_text(entry->board, sizeof(entry->board), capsule->board);
	set_text(entry->top_candidate_id,
		  sizeof(entry->top_candidate_id),
		  capsule->top_candidate_id);
	set_text(entry->nonce_hex, sizeof(entry->nonce_hex),
		  capsule->nonce_hex);
	set_text(entry->passport_digest_hex,
		  sizeof(entry->passport_digest_hex),
		  capsule->passport_digest_hex);
	set_text(entry->capsule_digest_hex,
		  sizeof(entry->capsule_digest_hex),
		  capsule->capsule_digest_hex);
	set_text(entry->previous_entry_digest_hex,
		  sizeof(entry->previous_entry_digest_hex),
		  journal->entry_count == 0U ?
			  zero_digest :
			  journal->entries[
				  journal->entry_count - 1U].entry_digest_hex);
}

const char *pqcp_deployment_evidence_journal_status_str(
	enum pqcp_deployment_evidence_journal_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_EMPTY:
		return "EMPTY";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_OPEN:
		return "OPEN";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_FINALIZED:
		return "FINALIZED";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_FAILED:
	default:
		return "FAILED";
	}
}

const char *pqcp_deployment_evidence_journal_error_str(
	enum pqcp_deployment_evidence_journal_error error)
{
	switch (error) {
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_NONE:
		return "none";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_INVALID_ARGUMENT:
		return "invalid_argument";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_BAD_DEVICE_ID:
		return "bad_device_id";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_BAD_CAPSULE:
		return "bad_capsule";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_FULL:
		return "full";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_FINALIZED:
		return "finalized";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_SEQUENCE:
		return "sequence";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_BOOT_COUNTER:
		return "boot_counter";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_TIME_ORDER:
		return "time_order";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_DUPLICATE:
		return "duplicate";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_DIGEST:
		return "digest";
	default:
		return "unknown";
	}
}

int pqcp_deployment_evidence_journal_init(
	struct pqcp_deployment_evidence_journal *journal,
	const char *device_id)
{
	if (journal == NULL) {
		return -EINVAL;
	}
	memset(journal, 0, sizeof(*journal));
	journal->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_SCHEMA_VERSION;
	journal->status = PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_EMPTY;
	journal->first_error =
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_NONE;
	journal->monotonic_boot_counters = true;
	journal->monotonic_capture_times = true;
	journal->unique_capsules = true;
	journal->stable_device_id = true;
	journal->stable_board = true;
	set_text(journal->first_entry_digest_hex,
		  sizeof(journal->first_entry_digest_hex), zero_digest);
	set_text(journal->last_entry_digest_hex,
		  sizeof(journal->last_entry_digest_hex), zero_digest);
	set_text(journal->journal_digest_hex,
		  sizeof(journal->journal_digest_hex), zero_digest);
	if (!text_valid(
		    device_id,
		    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DEVICE_ID_MAX_CHARS)) {
		journal_fail(
			journal,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_BAD_DEVICE_ID);
		return -EINVAL;
	}
	set_text(journal->device_id, sizeof(journal->device_id),
		  device_id);
	return 0;
}

int pqcp_deployment_evidence_journal_append(
	struct pqcp_deployment_evidence_journal *journal,
	const struct pqcp_deployment_evidence_capsule_replay_result *capsule,
	uint64_t boot_counter,
	uint64_t capture_time_ms)
{
	enum pqcp_deployment_evidence_journal_error order_error;
	struct pqcp_deployment_evidence_journal_entry *entry;
	int ret;

	if (journal == NULL || capsule == NULL ||
	    journal->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_SCHEMA_VERSION) {
		journal_fail(
			journal,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_INVALID_ARGUMENT);
		return -EINVAL;
	}
	if (journal->status ==
	    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_FINALIZED) {
		journal_fail(
			journal,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_FINALIZED);
		return -EPERM;
	}
	if (journal->status ==
	    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_FAILED) {
		return -EBADMSG;
	}
	if (journal->entry_count >=
	    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_MAX_ENTRIES) {
		journal_fail(journal,
			     PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_FULL);
		return -ENOSPC;
	}
	if (!capsule_valid(capsule)) {
		journal_fail(
			journal,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_BAD_CAPSULE);
		return -EBADMSG;
	}
	order_error = validate_append_order(
		journal, capsule, boot_counter, capture_time_ms);
	if (order_error != PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_NONE) {
		journal_fail(journal, order_error);
		return order_error ==
				       PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_DUPLICATE ?
			       -EEXIST : -ERANGE;
	}
	entry = &journal->entries[journal->entry_count];
	fill_entry(entry, journal, capsule, boot_counter,
		   capture_time_ms);
	ret = digest_entry(entry, entry->entry_digest_hex);
	if (ret != 0 || !digest_valid(entry->entry_digest_hex)) {
		memset(entry, 0, sizeof(*entry));
		journal_fail(
			journal,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_DIGEST);
		return ret != 0 ? ret : -EBADMSG;
	}
	if (journal->entry_count == 0U) {
		journal->first_boot_counter = boot_counter;
		journal->first_capture_time_ms = capture_time_ms;
		set_text(journal->board, sizeof(journal->board),
			  capsule->board);
		set_text(journal->first_entry_digest_hex,
			  sizeof(journal->first_entry_digest_hex),
			  entry->entry_digest_hex);
	}
	journal->last_boot_counter = boot_counter;
	journal->last_capture_time_ms = capture_time_ms;
	set_text(journal->last_entry_digest_hex,
		  sizeof(journal->last_entry_digest_hex),
		  entry->entry_digest_hex);
	journal->entry_count++;
	journal->distinct_capsule_count++;
	update_status_counts(journal, capsule->passport_status);
	if (capsule->signature_present &&
	    capsule->signature_verified) {
		journal->signed_count++;
	}
	if (capsule->production_allowed) {
		journal->production_count++;
	}
	journal->status = PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_OPEN;
	return 0;
}

int pqcp_deployment_evidence_journal_finalize(
	struct pqcp_deployment_evidence_journal *journal)
{
	int ret;

	if (journal == NULL ||
	    journal->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_SCHEMA_VERSION) {
		return -EINVAL;
	}
	if (journal->status ==
	    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_FAILED) {
		return -EBADMSG;
	}
	if (journal->status ==
	    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_FINALIZED) {
		return 0;
	}
	if (journal->entry_count == 0U) {
		journal_fail(
			journal,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_SEQUENCE);
		return -ENODATA;
	}
	ret = digest_journal(journal, journal->journal_digest_hex);
	if (ret != 0 || !digest_valid(journal->journal_digest_hex)) {
		journal_fail(
			journal,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_DIGEST);
		return ret != 0 ? ret : -EBADMSG;
	}
	journal->status =
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_FINALIZED;
	return 0;
}

const struct pqcp_deployment_evidence_journal_entry *
pqcp_deployment_evidence_journal_entry_at(
	const struct pqcp_deployment_evidence_journal *journal,
	size_t index)
{
	if (journal == NULL || index >= journal->entry_count ||
	    index >= PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_MAX_ENTRIES) {
		return NULL;
	}
	return &journal->entries[index];
}

int pqcp_deployment_evidence_journal_emit(
	const struct pqcp_deployment_evidence_journal *journal)
{
	if (journal == NULL ||
	    journal->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_SCHEMA_VERSION ||
	    journal->entry_count >
		    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_MAX_ENTRIES ||
	    !text_valid(journal->device_id,
			sizeof(journal->device_id))) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < journal->entry_count; ++index) {
		const struct pqcp_deployment_evidence_journal_entry *entry =
			&journal->entries[index];

		printk("PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ENTRY schema=%u "
		       "sequence=%u device=%s boot=%llu time_ms=%llu "
		       "passport_status=%u profile=%u score=%u "
		       "capsule_bytes=%u capsule_records=%u replay=%u "
		       "signed=%u signature_verified=%u production=%u "
		       "board=%s top=%s nonce=%s passport_digest=%s "
		       "capsule_digest=%s previous=%s entry_digest=%s\n",
		       entry->schema_version, entry->sequence,
		       entry->device_id,
		       (unsigned long long)entry->boot_counter,
		       (unsigned long long)entry->capture_time_ms,
		       (uint32_t)entry->passport_status,
		       (uint32_t)entry->profile, entry->passport_score,
		       entry->capsule_bytes, entry->capsule_records,
		       entry->capsule_replayed ? 1U : 0U,
		       entry->signature_present ? 1U : 0U,
		       entry->signature_verified ? 1U : 0U,
		       entry->production_allowed ? 1U : 0U,
		       entry->board, entry->top_candidate_id,
		       entry->nonce_hex, entry->passport_digest_hex,
		       entry->capsule_digest_hex,
		       entry->previous_entry_digest_hex,
		       entry->entry_digest_hex);
	}
	printk("PQCP_DEPLOYMENT_EVIDENCE_JOURNAL schema=%u status=%s "
	       "error=%s entries=%u pass=%u warn=%u fail=%u signed=%u "
	       "production=%u distinct=%u first_boot=%llu last_boot=%llu "
	       "first_time_ms=%llu last_time_ms=%llu monotonic_boot=%u "
	       "monotonic_time=%u unique=%u stable_device=%u stable_board=%u "
	       "device=%s board=%s first_digest=%s last_digest=%s "
	       "journal_digest=%s\n",
	       journal->schema_version,
	       pqcp_deployment_evidence_journal_status_str(journal->status),
	       pqcp_deployment_evidence_journal_error_str(
		       journal->first_error),
	       journal->entry_count, journal->pass_count,
	       journal->warn_count, journal->fail_count,
	       journal->signed_count, journal->production_count,
	       journal->distinct_capsule_count,
	       (unsigned long long)journal->first_boot_counter,
	       (unsigned long long)journal->last_boot_counter,
	       (unsigned long long)journal->first_capture_time_ms,
	       (unsigned long long)journal->last_capture_time_ms,
	       journal->monotonic_boot_counters ? 1U : 0U,
	       journal->monotonic_capture_times ? 1U : 0U,
	       journal->unique_capsules ? 1U : 0U,
	       journal->stable_device_id ? 1U : 0U,
	       journal->stable_board ? 1U : 0U,
	       journal->device_id, journal->board,
	       journal->first_entry_digest_hex,
	       journal->last_entry_digest_hex,
	       journal->journal_digest_hex);
	return 0;
}
