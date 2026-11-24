/*
 * SPDX-License-Identifier: MIT
 *
 * Fleet-level consensus over replayed deployment evidence journals.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_fleet_consensus.h>

#define FLEET_CONSENSUS_DOMAIN UINT64_C(0x50514350464c4545)

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
		digest, PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS);
}

static bool policy_valid(
	const struct pqcp_deployment_fleet_consensus_policy *policy)
{
	return policy != NULL &&
	       policy->min_devices != 0U &&
	       policy->min_devices <=
		       PQCP_DEPLOYMENT_FLEET_CONSENSUS_MAX_DEVICES &&
	       policy->min_quorum_percent <= 100U &&
	       policy->min_signature_percent <= 100U &&
	       policy->min_production_percent <= 100U &&
	       policy->min_average_score <= 100U;
}

static bool journal_valid(
	const struct pqcp_deployment_evidence_journal_replay_result *journal)
{
	return journal != NULL &&
	       journal->schema_version ==
		       PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_SCHEMA_VERSION &&
	       journal->entries_checked != 0U &&
	       journal->entries_checked <=
		       PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_MAX_ENTRIES &&
	       text_valid(journal->device_id, sizeof(journal->device_id)) &&
	       text_valid(journal->board, sizeof(journal->board)) &&
	       text_valid(journal->latest_top_candidate_id,
			  sizeof(journal->latest_top_candidate_id)) &&
	       digest_valid(journal->computed_journal_digest_hex) &&
	       digest_valid(journal->latest_capsule_digest_hex) &&
	       journal->latest_passport_score <= 100U;
}

static bool audit_valid(
	const struct pqcp_deployment_evidence_journal_audit_report *audit)
{
	return audit != NULL &&
	       audit->schema_version ==
		       PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_SCHEMA_VERSION &&
	       audit->snapshot_count != 0U &&
	       audit->snapshot_count <=
		       PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_MAX_SNAPSHOTS &&
	       text_valid(audit->device_id, sizeof(audit->device_id)) &&
	       text_valid(audit->board, sizeof(audit->board)) &&
	       digest_valid(audit->audit_digest_hex);
}

static uint32_t percent(uint32_t numerator, uint32_t denominator)
{
	if (denominator == 0U) {
		return 0U;
	}
	return (uint32_t)(((uint64_t)numerator * 100U) / denominator);
}

static bool duplicate_device(
	const struct pqcp_deployment_fleet_consensus_report *report,
	size_t before,
	const char *device_id)
{
	for (size_t index = 0U; index < before; ++index) {
		if (strcmp(report->members[index].device_id,
			   device_id) == 0) {
			return true;
		}
	}
	return false;
}

static int find_or_add_group(
	struct pqcp_deployment_fleet_group *groups,
	uint32_t *group_count,
	const char *value,
	uint32_t score)
{
	if (groups == NULL || group_count == NULL || value == NULL) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < *group_count; ++index) {
		if (strcmp(groups[index].value, value) == 0) {
			groups[index].member_count++;
			groups[index].score_sum += score;
			groups[index].average_score =
				groups[index].score_sum /
				groups[index].member_count;
			return (int)index;
		}
	}
	if (*group_count >=
	    PQCP_DEPLOYMENT_FLEET_CONSENSUS_MAX_GROUPS) {
		return -ENOSPC;
	}
	const uint32_t index = *group_count;

	memset(&groups[index], 0, sizeof(groups[index]));
	set_text(groups[index].value, sizeof(groups[index].value), value);
	groups[index].member_count = 1U;
	groups[index].score_sum = score;
	groups[index].average_score = score;
	(*group_count)++;
	return (int)index;
}

static size_t best_group(
	const struct pqcp_deployment_fleet_group *groups,
	uint32_t group_count)
{
	size_t best = 0U;

	for (size_t index = 1U; index < group_count; ++index) {
		if (groups[index].member_count >
		    groups[best].member_count) {
			best = index;
		} else if (groups[index].member_count ==
			   groups[best].member_count &&
			   groups[index].average_score >
				   groups[best].average_score) {
			best = index;
		} else if (groups[index].member_count ==
			   groups[best].member_count &&
			   groups[index].average_score ==
				   groups[best].average_score &&
			   strcmp(groups[index].value,
				  groups[best].value) < 0) {
			best = index;
		}
	}
	return best;
}

static uint32_t best_profile(const uint32_t counts[4])
{
	uint32_t best = 0U;

	for (uint32_t index = 1U; index < 4U; ++index) {
		if (counts[index] > counts[best]) {
			best = index;
		}
	}
	return best;
}

static void count_status(
	struct pqcp_deployment_fleet_consensus_report *report,
	enum pqcp_deployment_assurance_passport_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS:
		report->passport_pass_count++;
		break;
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARN:
		report->passport_warn_count++;
		break;
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL:
	default:
		report->passport_fail_count++;
		break;
	}
}

static void count_audit(
	struct pqcp_deployment_fleet_consensus_report *report,
	enum pqcp_deployment_evidence_journal_audit_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_PASS:
		report->audit_pass_count++;
		break;
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARN:
		report->audit_warn_count++;
		break;
	case PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_FAIL:
	default:
		report->audit_fail_count++;
		break;
	}
}

static void fill_member(
	struct pqcp_deployment_fleet_member *member,
	size_t index,
	const struct pqcp_deployment_evidence_journal_replay_result *journal,
	const struct pqcp_deployment_evidence_journal_audit_report *audit)
{
	memset(member, 0, sizeof(*member));
	member->index = (uint32_t)index;
	member->replay_passed = journal->passed;
	member->audit_status = audit->status;
	member->passport_status = journal->latest_passport_status;
	member->profile = journal->latest_profile;
	member->latest_score = journal->latest_passport_score;
	member->journal_entries = journal->entries_checked;
	member->audit_snapshots = audit->snapshot_count;
	member->signature_verified =
		journal->latest_signature_verified;
	member->production_allowed =
		journal->latest_production_allowed;
	set_text(member->device_id, sizeof(member->device_id),
		  journal->device_id);
	set_text(member->board, sizeof(member->board),
		  journal->board);
	set_text(member->top_candidate_id,
		  sizeof(member->top_candidate_id),
		  journal->latest_top_candidate_id);
	set_text(member->journal_digest_hex,
		  sizeof(member->journal_digest_hex),
		  journal->computed_journal_digest_hex);
	set_text(member->audit_digest_hex,
		  sizeof(member->audit_digest_hex),
		  audit->audit_digest_hex);
	member->accepted =
		journal->passed &&
		audit->status !=
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_FAIL &&
		strcmp(journal->device_id, audit->device_id) == 0 &&
		strcmp(journal->board, audit->board) == 0;
}

static int digest_report(
	const struct pqcp_deployment_fleet_consensus_report *report,
	char output[PQCP_DEPLOYMENT_FLEET_CONSENSUS_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	if (report == NULL || output == NULL) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_init(
		&digest, FLEET_CONSENSUS_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)report->status);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->error_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->warning_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->device_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->accepted_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->rejected_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->outlier_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->replay_pass_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->audit_pass_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->audit_warn_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->audit_fail_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->signature_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->production_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->passport_pass_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->passport_warn_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->passport_fail_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->min_score);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->max_score);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->average_score);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->candidate_quorum_percent);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->board_quorum_percent);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->profile_quorum_percent);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->distinct_candidates);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->distinct_boards);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, report->distinct_profiles);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)report->consensus_profile);
	pqcp_deployment_evidence_digest_update_text(
		&digest, report->consensus_candidate_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, report->consensus_board);
	for (size_t index = 0U; index < report->device_count; ++index) {
		const struct pqcp_deployment_fleet_member *member =
			&report->members[index];

		pqcp_deployment_evidence_digest_update_text(
			&digest, member->device_id);
		pqcp_deployment_evidence_digest_update_text(
			&digest, member->journal_digest_hex);
		pqcp_deployment_evidence_digest_update_text(
			&digest, member->audit_digest_hex);
		pqcp_deployment_evidence_digest_update_bool(
			&digest, member->accepted);
		pqcp_deployment_evidence_digest_update_bool(
			&digest, member->outlier);
	}
	return pqcp_deployment_evidence_digest_final_hex(&digest, output);
}

static void mark_outliers(
	struct pqcp_deployment_fleet_consensus_report *report)
{
	for (size_t index = 0U; index < report->device_count; ++index) {
		struct pqcp_deployment_fleet_member *member =
			&report->members[index];

		if (!member->accepted) {
			member->outlier = true;
		} else if (strcmp(member->top_candidate_id,
				  report->consensus_candidate_id) != 0 ||
			   strcmp(member->board,
				  report->consensus_board) != 0 ||
			   member->profile != report->consensus_profile) {
			member->outlier = true;
		}
		if (member->outlier) {
			report->outlier_count++;
		}
	}
}

static void apply_policy(
	const struct pqcp_deployment_fleet_consensus_policy *policy,
	struct pqcp_deployment_fleet_consensus_report *report)
{
	const uint32_t signature_percent =
		percent(report->signature_count, report->accepted_count);
	const uint32_t production_percent =
		percent(report->production_count, report->accepted_count);

	if (report->accepted_count < policy->min_devices) {
		report->error_mask |=
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_QUORUM;
	}
	if (policy->require_all_replays &&
	    report->replay_pass_count != report->device_count) {
		report->error_mask |=
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_REPLAY_FAILURE;
	}
	if (policy->require_all_audits &&
	    report->audit_fail_count != 0U) {
		report->error_mask |=
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_AUDIT_FAILURE;
	}
	if (report->audit_warn_count != 0U) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_AUDIT_WARN;
	}
	if (report->candidate_quorum_percent <
	    policy->min_quorum_percent) {
		if (policy->require_candidate_consensus) {
			report->error_mask |=
				PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_CANDIDATE_DRIFT;
		} else {
			report->warning_mask |=
				PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_CANDIDATE_DRIFT;
		}
	}
	if (report->board_quorum_percent < policy->min_quorum_percent) {
		if (policy->require_board_consensus) {
			report->error_mask |=
				PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_BOARD_DRIFT;
		} else {
			report->warning_mask |=
				PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_BOARD_DRIFT;
		}
	}
	if (report->profile_quorum_percent <
	    policy->min_quorum_percent) {
		if (policy->require_profile_consensus) {
			report->error_mask |=
				PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_PROFILE_DRIFT;
		} else {
			report->warning_mask |=
				PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_PROFILE_DRIFT;
		}
	}
	if (signature_percent < policy->min_signature_percent) {
		if (policy->signature_floor_blocks) {
			report->error_mask |=
				PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_SIGNATURE_COVERAGE;
		} else {
			report->warning_mask |=
				PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_UNSIGNED;
		}
	}
	if (production_percent < policy->min_production_percent) {
		if (policy->production_floor_blocks) {
			report->error_mask |=
				PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_PRODUCTION_COVERAGE;
		} else {
			report->warning_mask |=
				PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_NON_PRODUCTION;
		}
	}
	if (report->average_score < policy->min_average_score) {
		if (policy->score_floor_blocks) {
			report->error_mask |=
				PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_SCORE_FLOOR;
		} else {
			report->warning_mask |=
				PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_LOW_SCORE;
		}
	}
	if (report->outlier_count != 0U) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_OUTLIERS;
	}
	report->status = report->error_mask != 0U ?
				 PQCP_DEPLOYMENT_FLEET_CONSENSUS_FAIL :
			 report->warning_mask != 0U ?
				 PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARN :
				 PQCP_DEPLOYMENT_FLEET_CONSENSUS_PASS;
}

const char *pqcp_deployment_fleet_consensus_status_str(
	enum pqcp_deployment_fleet_consensus_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_FLEET_CONSENSUS_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_FLEET_CONSENSUS_FAIL:
	default:
		return "FAIL";
	}
}

int pqcp_deployment_fleet_consensus_default_policy(
	struct pqcp_deployment_fleet_consensus_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->min_devices = 3U;
	policy->min_quorum_percent = 67U;
	policy->min_signature_percent = 67U;
	policy->min_production_percent = 67U;
	policy->min_average_score = 70U;
	policy->require_all_replays = true;
	policy->require_all_audits = true;
	policy->require_profile_consensus = true;
	policy->require_board_consensus = false;
	policy->require_candidate_consensus = true;
	policy->signature_floor_blocks = false;
	policy->production_floor_blocks = false;
	policy->score_floor_blocks = false;
	return 0;
}

int pqcp_deployment_fleet_consensus_run(
	const struct pqcp_deployment_evidence_journal_replay_result *journals,
	const struct pqcp_deployment_evidence_journal_audit_report *audits,
	size_t device_count,
	const struct pqcp_deployment_fleet_consensus_policy *policy,
	struct pqcp_deployment_fleet_consensus_report *report)
{
	uint64_t score_sum = 0U;
	int ret;

	if (report == NULL) {
		return -EINVAL;
	}
	memset(report, 0, sizeof(*report));
	report->schema_version =
		PQCP_DEPLOYMENT_FLEET_CONSENSUS_SCHEMA_VERSION;
	report->status = PQCP_DEPLOYMENT_FLEET_CONSENSUS_FAIL;
	if (journals == NULL || audits == NULL ||
	    device_count == 0U ||
	    device_count >
		    PQCP_DEPLOYMENT_FLEET_CONSENSUS_MAX_DEVICES ||
	    !policy_valid(policy)) {
		report->error_mask =
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_INVALID_INPUT;
		return -EINVAL;
	}
	report->device_count = (uint32_t)device_count;
	for (size_t index = 0U; index < device_count; ++index) {
		const struct pqcp_deployment_evidence_journal_replay_result
			*journal = &journals[index];
		const struct pqcp_deployment_evidence_journal_audit_report
			*audit = &audits[index];
		struct pqcp_deployment_fleet_member *member =
			&report->members[index];

		if (!journal_valid(journal) || !audit_valid(audit)) {
			report->rejected_count++;
			report->error_mask |=
				PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_INVALID_INPUT;
			continue;
		}
		if (duplicate_device(report, index, journal->device_id)) {
			report->rejected_count++;
			report->error_mask |=
				PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_DUPLICATE_DEVICE;
			continue;
		}
		fill_member(member, index, journal, audit);
		if (journal->passed) {
			report->replay_pass_count++;
		}
		count_audit(report, audit->status);
		if (!member->accepted) {
			report->rejected_count++;
			if (!journal->passed) {
				report->error_mask |=
					PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_REPLAY_FAILURE;
			} else if (audit->status ==
				   PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_FAIL) {
				report->error_mask |=
					PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_AUDIT_FAILURE;
			} else {
				report->error_mask |=
					PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_IDENTITY_MISMATCH;
			}
			continue;
		}
		report->accepted_count++;
		if (member->signature_verified) {
			report->signature_count++;
		}
		if (member->production_allowed) {
			report->production_count++;
		}
		count_status(report, member->passport_status);
		if (report->accepted_count == 1U ||
		    member->latest_score < report->min_score) {
			report->min_score = member->latest_score;
		}
		if (report->accepted_count == 1U ||
		    member->latest_score > report->max_score) {
			report->max_score = member->latest_score;
		}
		score_sum += member->latest_score;
		ret = find_or_add_group(
			report->candidate_groups,
			&report->distinct_candidates,
			member->top_candidate_id,
			member->latest_score);
		if (ret < 0) {
			report->error_mask |=
				PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_INVALID_INPUT;
		}
		ret = find_or_add_group(
			report->board_groups,
			&report->distinct_boards,
			member->board,
			member->latest_score);
		if (ret < 0) {
			report->error_mask |=
				PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_INVALID_INPUT;
		}
		if ((uint32_t)member->profile < 4U) {
			if (report->profile_counts[member->profile] == 0U) {
				report->distinct_profiles++;
			}
			report->profile_counts[member->profile]++;
		} else {
			report->error_mask |=
				PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_INVALID_INPUT;
		}
	}
	if (report->accepted_count == 0U ||
	    report->distinct_candidates == 0U ||
	    report->distinct_boards == 0U) {
		report->error_mask |=
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_QUORUM;
		return -EBADMSG;
	}
	report->average_score =
		(uint32_t)(score_sum / report->accepted_count);
	const size_t candidate_index = best_group(
		report->candidate_groups,
		report->distinct_candidates);
	const size_t board_index = best_group(
		report->board_groups, report->distinct_boards);
	const uint32_t profile_index =
		best_profile(report->profile_counts);
	set_text(report->consensus_candidate_id,
		  sizeof(report->consensus_candidate_id),
		  report->candidate_groups[candidate_index].value);
	set_text(report->consensus_board,
		  sizeof(report->consensus_board),
		  report->board_groups[board_index].value);
	report->consensus_profile =
		(enum pqcp_deployment_release_gate_profile)profile_index;
	report->candidate_quorum_percent = percent(
		report->candidate_groups[candidate_index].member_count,
		report->accepted_count);
	report->board_quorum_percent = percent(
		report->board_groups[board_index].member_count,
		report->accepted_count);
	report->profile_quorum_percent = percent(
		report->profile_counts[profile_index],
		report->accepted_count);
	mark_outliers(report);
	apply_policy(policy, report);
	ret = digest_report(report, report->fleet_digest_hex);
	if (ret != 0) {
		report->error_mask |=
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_INVALID_INPUT;
		report->status = PQCP_DEPLOYMENT_FLEET_CONSENSUS_FAIL;
		return ret;
	}
	return report->status == PQCP_DEPLOYMENT_FLEET_CONSENSUS_FAIL ?
		       -EBADMSG : 0;
}

int pqcp_deployment_fleet_consensus_emit(
	const struct pqcp_deployment_fleet_consensus_report *report)
{
	if (report == NULL ||
	    report->schema_version !=
		    PQCP_DEPLOYMENT_FLEET_CONSENSUS_SCHEMA_VERSION ||
	    report->device_count >
		    PQCP_DEPLOYMENT_FLEET_CONSENSUS_MAX_DEVICES ||
	    (report->error_mask &
	     ~PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_KNOWN_MASK) != 0U ||
	    (report->warning_mask &
	     ~PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_KNOWN_MASK) != 0U) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < report->device_count; ++index) {
		const struct pqcp_deployment_fleet_member *member =
			&report->members[index];

		printk("PQCP_DEPLOYMENT_FLEET_MEMBER schema=%u index=%u "
		       "accepted=%u outlier=%u replay=%u audit_status=%u "
		       "passport_status=%u profile=%u score=%u entries=%u "
		       "snapshots=%u signed=%u production=%u device=%s "
		       "board=%s top=%s journal_digest=%s audit_digest=%s\n",
		       report->schema_version, member->index,
		       member->accepted ? 1U : 0U,
		       member->outlier ? 1U : 0U,
		       member->replay_passed ? 1U : 0U,
		       (uint32_t)member->audit_status,
		       (uint32_t)member->passport_status,
		       (uint32_t)member->profile,
		       member->latest_score, member->journal_entries,
		       member->audit_snapshots,
		       member->signature_verified ? 1U : 0U,
		       member->production_allowed ? 1U : 0U,
		       member->device_id, member->board,
		       member->top_candidate_id,
		       member->journal_digest_hex,
		       member->audit_digest_hex);
	}
	printk("PQCP_DEPLOYMENT_FLEET_CONSENSUS schema=%u status=%s "
	       "errors=0x%08x warnings=0x%08x devices=%u accepted=%u "
	       "rejected=%u outliers=%u replay_pass=%u audit_pass=%u "
	       "audit_warn=%u audit_fail=%u signed=%u production=%u "
	       "passport_pass=%u passport_warn=%u passport_fail=%u "
	       "min_score=%u max_score=%u avg_score=%u candidate_quorum=%u "
	       "board_quorum=%u profile_quorum=%u candidates=%u boards=%u "
	       "profiles=%u consensus_profile=%u consensus_candidate=%s "
	       "consensus_board=%s fleet_digest=%s\n",
	       report->schema_version,
	       pqcp_deployment_fleet_consensus_status_str(report->status),
	       report->error_mask, report->warning_mask,
	       report->device_count, report->accepted_count,
	       report->rejected_count, report->outlier_count,
	       report->replay_pass_count, report->audit_pass_count,
	       report->audit_warn_count, report->audit_fail_count,
	       report->signature_count, report->production_count,
	       report->passport_pass_count,
	       report->passport_warn_count,
	       report->passport_fail_count, report->min_score,
	       report->max_score, report->average_score,
	       report->candidate_quorum_percent,
	       report->board_quorum_percent,
	       report->profile_quorum_percent,
	       report->distinct_candidates, report->distinct_boards,
	       report->distinct_profiles,
	       (uint32_t)report->consensus_profile,
	       report->consensus_candidate_id,
	       report->consensus_board, report->fleet_digest_hex);
	return 0;
}
