/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Cross-snapshot deployment evidence journal audit.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_evidence_journal_audit.h>

#define JOURNAL_AUDIT_DOMAIN UINT64_C(0x505143504a415544)

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

static bool replay_shape_valid(
	const struct pqcp_deployment_evidence_journal_replay_result *snapshot)
{
	return snapshot != NULL &&
	       snapshot->schema_version ==
		       PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_SCHEMA_VERSION &&
	       snapshot->entries_checked != 0U &&
	       snapshot->entries_checked <=
		       PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_MAX_ENTRIES &&
	       snapshot->device_id[0] != '\0' &&
	       snapshot->board[0] != '\0' &&
	       pqcp_deployment_evidence_codec_is_lower_hex(
		       snapshot->computed_journal_digest_hex,
		       PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS);
}

static bool policy_valid(
	const struct pqcp_deployment_evidence_journal_audit_policy *policy)
{
	return policy != NULL &&
	       policy->min_snapshots != 0U &&
	       policy->min_snapshots <=
		       PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_MAX_SNAPSHOTS &&
	       policy->min_entries != 0U &&
	       policy->min_entries <=
		       PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_MAX_ENTRIES &&
	       policy->min_signed_percent <= 100U &&
	       policy->min_production_percent <= 100U &&
	       policy->min_average_score <= 100U;
}

static uint32_t percent(uint32_t numerator, uint32_t denominator)
{
	if (denominator == 0U) {
		return 0U;
	}
	return (uint32_t)(((uint64_t)numerator * 100U) / denominator);
}

static bool root_seen(
	const struct pqcp_deployment_evidence_journal_replay_result *snapshots,
	size_t before,
	const char *root)
{
	for (size_t index = 0U; index < before; ++index) {
		if (strcmp(snapshots[index].computed_journal_digest_hex,
			   root) == 0) {
			return true;
		}
	}
	return false;
}

static uint32_t snapshot_average_score(
	const struct pqcp_deployment_evidence_journal_replay_result *snapshot)
{
	uint32_t weighted;

	if (snapshot == NULL || snapshot->entries_checked == 0U) {
		return 0U;
	}
	weighted = snapshot->pass_count * 100U +
		   snapshot->warn_count * 60U;
	return weighted / snapshot->entries_checked;
}

static void update_score_summary(
	struct pqcp_deployment_evidence_journal_audit_report *report,
	uint32_t score,
	uint64_t *score_sum)
{
	if (report->snapshot_count == 0U || score < report->min_score) {
		report->min_score = score;
	}
	if (report->snapshot_count == 0U || score > report->max_score) {
		report->max_score = score;
	}
	*score_sum += score;
}

static void update_identity(
	struct pqcp_deployment_evidence_journal_audit_report *report,
	const struct pqcp_deployment_evidence_journal_replay_result *snapshot,
	size_t index)
{
	if (index == 0U) {
		set_text(report->device_id, sizeof(report->device_id),
			  snapshot->device_id);
		set_text(report->board, sizeof(report->board),
			  snapshot->board);
		set_text(report->first_root_digest_hex,
			  sizeof(report->first_root_digest_hex),
			  snapshot->computed_journal_digest_hex);
		report->first_boot_counter =
			snapshot->first_boot_counter;
		report->first_capture_time_ms =
			snapshot->first_capture_time_ms;
		return;
	}
	if (strcmp(report->device_id, snapshot->device_id) != 0) {
		report->stable_device_id = false;
	}
	if (strcmp(report->board, snapshot->board) != 0) {
		report->stable_board = false;
	}
}

static void update_monotonicity(
	struct pqcp_deployment_evidence_journal_audit_report *report,
	const struct pqcp_deployment_evidence_journal_replay_result *previous,
	const struct pqcp_deployment_evidence_journal_replay_result *current)
{
	if (previous == NULL || current == NULL) {
		return;
	}
	if (current->entries_checked < previous->entries_checked) {
		report->monotonic_entry_growth = false;
	}
	if (current->last_boot_counter <
	    previous->last_boot_counter) {
		report->monotonic_boot_counter = false;
	}
	if (current->last_capture_time_ms <
	    previous->last_capture_time_ms) {
		report->monotonic_capture_time = false;
	}
	if (current->signed_count < previous->signed_count) {
		report->signature_non_regression = false;
	}
	if (current->production_count <
	    previous->production_count) {
		report->production_non_regression = false;
	}
}

static int compute_audit_digest(
	const struct pqcp_deployment_evidence_journal_audit_report *report,
	char output[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	if (report == NULL || output == NULL) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_init(
		&digest, JOURNAL_AUDIT_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)report->status);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->error_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->warning_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->snapshot_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->replay_pass_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->replay_fail_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->min_entries);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->max_entries);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->total_entries);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->min_score);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->max_score);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->average_score);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->signed_entries);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->production_entries);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->failed_passports);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->distinct_root_count);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, report->first_boot_counter);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, report->last_boot_counter);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, report->first_capture_time_ms);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, report->last_capture_time_ms);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, report->stable_device_id);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, report->stable_board);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, report->monotonic_entry_growth);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, report->monotonic_boot_counter);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, report->monotonic_capture_time);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, report->unique_roots);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, report->signature_non_regression);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, report->production_non_regression);
	pqcp_deployment_evidence_digest_update_text(
		&digest, report->device_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, report->board);
	pqcp_deployment_evidence_digest_update_text(
		&digest, report->first_root_digest_hex);
	pqcp_deployment_evidence_digest_update_text(
		&digest, report->last_root_digest_hex);
	return pqcp_deployment_evidence_digest_final_hex(&digest, output);
}

static void apply_policy(
	const struct pqcp_deployment_evidence_journal_audit_policy *policy,
	struct pqcp_deployment_evidence_journal_audit_report *report)
{
	uint32_t signed_percent =
		percent(report->signed_entries, report->total_entries);
	uint32_t production_percent =
		percent(report->production_entries, report->total_entries);

	if (report->snapshot_count < policy->min_snapshots) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_LOW_SAMPLES;
	}
	if (report->min_entries < policy->min_entries) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_LOW_SAMPLES;
	}
	if (policy->require_all_replays &&
	    report->replay_fail_count != 0U) {
		report->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_REPLAY_FAILURE;
	}
	if (policy->require_stable_identity &&
	    !report->stable_device_id) {
		report->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_DEVICE_DRIFT;
	}
	if (policy->require_stable_identity && !report->stable_board) {
		report->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_BOARD_DRIFT;
	}
	if (policy->require_monotonic_growth &&
	    !report->monotonic_entry_growth) {
		report->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_ENTRY_ROLLBACK;
	}
	if (policy->require_monotonic_growth &&
	    !report->monotonic_boot_counter) {
		report->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_BOOT_ROLLBACK;
	}
	if (policy->require_monotonic_growth &&
	    !report->monotonic_capture_time) {
		report->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_TIME_ROLLBACK;
	}
	if (policy->require_unique_roots && !report->unique_roots) {
		report->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_ROOT_REUSE;
	}
	if (policy->require_no_signature_regression &&
	    !report->signature_non_regression) {
		report->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_SIGNATURE_REGRESSION;
	}
	if (policy->require_no_production_regression &&
	    !report->production_non_regression) {
		report->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_PRODUCTION_REGRESSION;
	}
	if (signed_percent < policy->min_signed_percent) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_UNSIGNED;
	}
	if (production_percent < policy->min_production_percent) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_NON_PRODUCTION;
	}
	if (report->failed_passports != 0U) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_FAILURE_HISTORY;
	}
	if (report->average_score < policy->min_average_score) {
		if (policy->score_floor_blocks) {
			report->error_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_SCORE_FLOOR;
		} else {
			report->warning_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_SCORE_FLOOR;
		}
	}
	report->status = report->error_mask != 0U ?
				 PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_FAIL :
			 report->warning_mask != 0U ?
				 PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARN :
				 PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_PASS;
}

const char *pqcp_deployment_evidence_journal_audit_status_str(
	enum pqcp_deployment_evidence_journal_audit_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_FAIL:
	default:
		return "FAIL";
	}
}

int pqcp_deployment_evidence_journal_audit_default_policy(
	struct pqcp_deployment_evidence_journal_audit_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->min_snapshots = 2U;
	policy->min_entries = 1U;
	policy->min_signed_percent = 50U;
	policy->min_production_percent = 50U;
	policy->min_average_score = 70U;
	policy->require_all_replays = true;
	policy->require_stable_identity = true;
	policy->require_monotonic_growth = true;
	policy->require_unique_roots = true;
	policy->require_no_signature_regression = true;
	policy->require_no_production_regression = true;
	policy->score_floor_blocks = false;
	return 0;
}

int pqcp_deployment_evidence_journal_audit_run(
	const struct pqcp_deployment_evidence_journal_replay_result *snapshots,
	size_t snapshot_count,
	const struct pqcp_deployment_evidence_journal_audit_policy *policy,
	struct pqcp_deployment_evidence_journal_audit_report *report)
{
	uint64_t score_sum = 0U;
	int ret;

	if (report == NULL) {
		return -EINVAL;
	}
	memset(report, 0, sizeof(*report));
	report->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_SCHEMA_VERSION;
	report->status = PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_FAIL;
	report->stable_device_id = true;
	report->stable_board = true;
	report->monotonic_entry_growth = true;
	report->monotonic_boot_counter = true;
	report->monotonic_capture_time = true;
	report->unique_roots = true;
	report->signature_non_regression = true;
	report->production_non_regression = true;
	if (snapshots == NULL || snapshot_count == 0U ||
	    snapshot_count >
		    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_MAX_SNAPSHOTS ||
	    !policy_valid(policy)) {
		report->error_mask =
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_INVALID_INPUT;
		return -EINVAL;
	}
	for (size_t index = 0U; index < snapshot_count; ++index) {
		const struct pqcp_deployment_evidence_journal_replay_result
			*snapshot = &snapshots[index];
		uint32_t score;

		if (!replay_shape_valid(snapshot)) {
			report->replay_fail_count++;
			report->error_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_REPLAY_FAILURE;
			continue;
		}
		if (snapshot->passed) {
			report->replay_pass_count++;
		} else {
			report->replay_fail_count++;
		}
		update_identity(report, snapshot, index);
		if (index != 0U) {
			update_monotonicity(
				report, &snapshots[index - 1U],
				snapshot);
		}
		if (root_seen(snapshots, index,
			      snapshot->computed_journal_digest_hex)) {
			report->unique_roots = false;
		} else {
			report->distinct_root_count++;
		}
		if (index == 0U ||
		    snapshot->entries_checked < report->min_entries) {
			report->min_entries = snapshot->entries_checked;
		}
		if (snapshot->entries_checked > report->max_entries) {
			report->max_entries = snapshot->entries_checked;
		}
		report->total_entries += snapshot->entries_checked;
		report->signed_entries += snapshot->signed_count;
		report->production_entries +=
			snapshot->production_count;
		report->failed_passports += snapshot->fail_count;
		score = snapshot_average_score(snapshot);
		update_score_summary(report, score, &score_sum);
		report->last_boot_counter =
			snapshot->last_boot_counter;
		report->last_capture_time_ms =
			snapshot->last_capture_time_ms;
		set_text(report->last_root_digest_hex,
			 sizeof(report->last_root_digest_hex),
			 snapshot->computed_journal_digest_hex);
		report->snapshot_count++;
	}
	if (report->snapshot_count == 0U) {
		report->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_REPLAY_FAILURE;
		return -EBADMSG;
	}
	report->average_score =
		(uint32_t)(score_sum / report->snapshot_count);
	apply_policy(policy, report);
	ret = compute_audit_digest(report, report->audit_digest_hex);
	if (ret != 0) {
		report->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_INVALID_INPUT;
		report->status =
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_FAIL;
		return ret;
	}
	return report->status ==
		       PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_FAIL ?
		       -EBADMSG : 0;
}

int pqcp_deployment_evidence_journal_audit_emit(
	const struct pqcp_deployment_evidence_journal_audit_report *report)
{
	if (report == NULL ||
	    report->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_SCHEMA_VERSION ||
	    (report->error_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_KNOWN_MASK) != 0U ||
	    (report->warning_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_KNOWN_MASK) !=
		    0U) {
		return -EINVAL;
	}
	printk("PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT schema=%u "
	       "status=%s errors=0x%08x warnings=0x%08x snapshots=%u "
	       "replay_pass=%u replay_fail=%u min_entries=%u max_entries=%u "
	       "total_entries=%u min_score=%u max_score=%u avg_score=%u "
	       "signed=%u production=%u failed_passports=%u roots=%u "
	       "first_boot=%llu last_boot=%llu first_time_ms=%llu "
	       "last_time_ms=%llu stable_device=%u stable_board=%u "
	       "entry_growth=%u boot_growth=%u time_growth=%u unique_roots=%u "
	       "signature_non_regression=%u production_non_regression=%u "
	       "device=%s board=%s first_root=%s last_root=%s audit_digest=%s\n",
	       report->schema_version,
	       pqcp_deployment_evidence_journal_audit_status_str(
		       report->status),
	       report->error_mask, report->warning_mask,
	       report->snapshot_count, report->replay_pass_count,
	       report->replay_fail_count, report->min_entries,
	       report->max_entries, report->total_entries,
	       report->min_score, report->max_score,
	       report->average_score, report->signed_entries,
	       report->production_entries, report->failed_passports,
	       report->distinct_root_count,
	       (unsigned long long)report->first_boot_counter,
	       (unsigned long long)report->last_boot_counter,
	       (unsigned long long)report->first_capture_time_ms,
	       (unsigned long long)report->last_capture_time_ms,
	       report->stable_device_id ? 1U : 0U,
	       report->stable_board ? 1U : 0U,
	       report->monotonic_entry_growth ? 1U : 0U,
	       report->monotonic_boot_counter ? 1U : 0U,
	       report->monotonic_capture_time ? 1U : 0U,
	       report->unique_roots ? 1U : 0U,
	       report->signature_non_regression ? 1U : 0U,
	       report->production_non_regression ? 1U : 0U,
	       report->device_id, report->board,
	       report->first_root_digest_hex,
	       report->last_root_digest_hex,
	       report->audit_digest_hex);
	return 0;
}
