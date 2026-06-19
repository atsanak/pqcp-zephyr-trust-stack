/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Canary-based migration of future sessions between measured PQC profiles.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/runtime_migration.h>

#include "runtime_internal.h"

#define MIGRATION_DOMAIN UINT64_C(0x505143504d494731)

static bool migration_policy_valid(
	const struct pqcp_runtime_migration_policy *policy)
{
	return policy != NULL &&
	       policy->schema_version == PQCP_RUNTIME_SCHEMA_VERSION &&
	       policy->minimum_security_level >= 1U &&
	       policy->minimum_security_level <= 5U &&
	       policy->minimum_evidence_score <= 100U &&
	       policy->required_canary_successes != 0U &&
	       policy->required_canary_successes <=
		       PQCP_RUNTIME_MIGRATION_MAX_CANARIES &&
	       policy->maximum_canary_failures <
		       PQCP_RUNTIME_MIGRATION_MAX_CANARIES &&
	       policy->maximum_latency_regression_permille <= 1000U &&
	       policy->maximum_memory_regression_permille <= 1000U &&
	       policy->drain_timeout_ms != 0U &&
	       policy->canary_timeout_ms != 0U;
}

int pqcp_runtime_migration_policy_default(
	struct pqcp_runtime_migration_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	*policy = (struct pqcp_runtime_migration_policy) {
		.schema_version = PQCP_RUNTIME_SCHEMA_VERSION,
		.minimum_security_level = 3U,
		.minimum_evidence_score = 70U,
		.required_canary_successes = 2U,
		.maximum_canary_failures = 0U,
		.maximum_latency_regression_permille = 100U,
		.maximum_memory_regression_permille = 100U,
		.drain_timeout_ms = 60000U,
		.canary_timeout_ms = 30000U,
		.require_measured_target = true,
		.forbid_security_downgrade = true,
		.drain_old_sessions = true,
		.rollback_on_canary_failure = true,
	};
	return 0;
}

static const struct pqcp_adaptive_profile *find_profile(
	const struct pqcp_runtime_migration *migration,
	const char *profile_id)
{
	if (migration == NULL ||
	    migration->controller == NULL ||
	    migration->controller->sessions == NULL ||
	    migration->controller->sessions->adaptive_control == NULL) {
		return NULL;
	}
	return pqcp_adaptive_profile_registry_find(
		&migration->controller->sessions->
			adaptive_control->registry,
		profile_id);
}

static struct pqcp_adaptive_profile *find_profile_mutable(
	struct pqcp_runtime_migration *migration,
	const char *profile_id)
{
	struct pqcp_adaptive_profile_registry *registry;

	if (migration == NULL ||
	    migration->controller == NULL ||
	    migration->controller->sessions == NULL ||
	    migration->controller->sessions->adaptive_control == NULL) {
		return NULL;
	}
	registry = &migration->controller->sessions->
		adaptive_control->registry;
	for (size_t index = 0U; index < registry->count; ++index) {
		if (strcmp(registry->profiles[index].profile_id,
			   profile_id) == 0) {
			return &registry->profiles[index];
		}
	}
	return NULL;
}

static uint32_t evidence_score(
	const struct pqcp_adaptive_profile *profile)
{
	const uint32_t relevant =
		PQCP_DEPLOYMENT_EVIDENCE_KAT |
		PQCP_DEPLOYMENT_EVIDENCE_ACVP |
		PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE |
		PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE |
		PQCP_DEPLOYMENT_EVIDENCE_BASELINE |
		PQCP_DEPLOYMENT_EVIDENCE_POLICY |
		PQCP_DEPLOYMENT_EVIDENCE_PROVIDER |
		PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT |
		PQCP_DEPLOYMENT_EVIDENCE_RESOURCE;
	uint32_t observed;
	uint32_t possible = 0U;
	uint32_t present = 0U;

	if (profile == NULL) {
		return 0U;
	}
	observed = profile->evidence_mask & relevant;
	for (uint32_t bit = 1U; bit != 0U; bit <<= 1U) {
		if ((relevant & bit) != 0U) {
			possible++;
			if ((observed & bit) != 0U) {
				present++;
			}
		}
	}
	return possible == 0U ? 0U :
		(present * 100U) / possible;
}

static uint64_t profile_memory(
	const struct pqcp_adaptive_profile *profile)
{
	return profile->ram_bytes + profile->stack_bytes +
	       profile->heap_bytes;
}

static bool exceeds_regression(
	uint64_t previous,
	uint64_t candidate,
	uint32_t allowed_permille)
{
	uint64_t limit;

	if (previous == 0U) {
		return false;
	}
	if (previous > UINT64_MAX /
		    (1000U + allowed_permille)) {
		return false;
	}
	limit = previous * (1000U + allowed_permille) / 1000U;
	return candidate > limit;
}

static uint32_t assess_profiles(
	const struct pqcp_runtime_migration *migration,
	const struct pqcp_adaptive_profile *source,
	const struct pqcp_adaptive_profile *target)
{
	uint32_t reasons = 0U;

	if (target == NULL) {
		return PQCP_RUNTIME_MIGRATION_REASON_TARGET_MISSING;
	}
	if (!target->enabled) {
		reasons |= PQCP_RUNTIME_MIGRATION_REASON_TARGET_DISABLED;
	}
	if (target->security_level <
	    migration->policy.minimum_security_level ||
	    (migration->policy.forbid_security_downgrade &&
	     source != NULL &&
	     target->security_level < source->security_level)) {
		reasons |= PQCP_RUNTIME_MIGRATION_REASON_SECURITY_DOWNGRADE;
	}
	if (evidence_score(target) <
	    migration->policy.minimum_evidence_score) {
		reasons |= PQCP_RUNTIME_MIGRATION_REASON_EVIDENCE_REGRESSION;
	}
	if (migration->policy.require_measured_target &&
	    (target->latency_source <
		     PQCP_ADAPTIVE_METRIC_MEASURED ||
	     target->cycles_source <
		     PQCP_ADAPTIVE_METRIC_MEASURED)) {
		reasons |= PQCP_RUNTIME_MIGRATION_REASON_EVIDENCE_REGRESSION;
	}
	if (source != NULL &&
	    exceeds_regression(
		    source->nominal_latency_us,
		    target->nominal_latency_us,
		    migration->policy
			    .maximum_latency_regression_permille)) {
		reasons |= PQCP_RUNTIME_MIGRATION_REASON_LATENCY_REGRESSION;
	}
	if (source != NULL &&
	    exceeds_regression(
		    profile_memory(source), profile_memory(target),
		    migration->policy
			    .maximum_memory_regression_permille)) {
		reasons |= PQCP_RUNTIME_MIGRATION_REASON_MEMORY_REGRESSION;
	}
	return reasons;
}

static uint32_t count_profile_sessions(
	const struct pqcp_runtime_session_manager *manager,
	const char *profile_id,
	bool include_draining)
{
	uint32_t count = 0U;

	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		const struct pqcp_runtime_session *session =
			&manager->sessions[index];

		if (!session->active ||
		    strcmp(session->profile_id, profile_id) != 0) {
			continue;
		}
		if (include_draining || !session->draining) {
			count++;
		}
	}
	return count;
}

static int migration_digest(
	const struct pqcp_runtime_migration_report *report,
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES])
{
	uint8_t buffer[256];
	size_t offset = 0U;
	size_t from_length;
	size_t to_length;

	memset(buffer, 0, sizeof(buffer));
	from_length = strnlen(
		report->from_profile, sizeof(report->from_profile));
	to_length = strnlen(
		report->to_profile, sizeof(report->to_profile));
	pqcp_runtime_internal_write_u64(
		buffer + offset, MIGRATION_DOMAIN);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, report->migration_id);
	offset += 8U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, (uint32_t)report->state);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->reason_mask);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->old_security_level);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->new_security_level);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->old_evidence_score);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->new_evidence_score);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->canaries_started);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->canaries_succeeded);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->canaries_failed);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->sessions_draining);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->sessions_remaining);
	offset += 4U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, report->started_at_ms);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, report->completed_at_ms);
	offset += 8U;
	memcpy(buffer + offset, report->from_profile, from_length);
	offset += from_length;
	buffer[offset++] = 0U;
	memcpy(buffer + offset, report->to_profile, to_length);
	offset += to_length;
	return pqcp_runtime_internal_sha256(buffer, offset, digest);
}

static int fill_report(
	const struct pqcp_runtime_migration *migration,
	uint64_t completed_at_ms,
	struct pqcp_runtime_migration_report *report)
{
	const struct pqcp_adaptive_profile *source =
		find_profile(migration, migration->from_profile);
	const struct pqcp_adaptive_profile *target =
		find_profile(migration, migration->to_profile);

	memset(report, 0, sizeof(*report));
	report->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	report->migration_id = migration->migration_id;
	report->state = migration->state;
	report->reason_mask = migration->reason_mask;
	report->old_security_level =
		source != NULL ? source->security_level : 0U;
	report->new_security_level =
		target != NULL ? target->security_level : 0U;
	report->old_evidence_score = evidence_score(source);
	report->new_evidence_score = evidence_score(target);
	report->canaries_started = (uint32_t)migration->canary_count;
	for (size_t index = 0U;
	     index < migration->canary_count; ++index) {
		if (migration->canaries[index].successful) {
			report->canaries_succeeded++;
		} else if (migration->canaries[index].completed) {
			report->canaries_failed++;
		}
	}
	report->sessions_draining = count_profile_sessions(
		migration->controller->sessions,
		migration->from_profile, true);
	report->sessions_remaining = report->sessions_draining;
	report->started_at_ms = migration->started_at_ms;
	report->completed_at_ms = completed_at_ms;
	(void)pqcp_runtime_internal_copy_text(
		report->from_profile, sizeof(report->from_profile),
		migration->from_profile);
	(void)pqcp_runtime_internal_copy_text(
		report->to_profile, sizeof(report->to_profile),
		migration->to_profile);
	return migration_digest(report, report->digest);
}

int pqcp_runtime_migration_begin(
	struct pqcp_runtime_migration *migration,
	uint64_t migration_id,
	const char *from_profile,
	const char *to_profile,
	struct pqcp_runtime_controller *controller,
	const struct pqcp_runtime_migration_policy *policy,
	uint64_t now_ms,
	struct pqcp_runtime_migration_report *report)
{
	struct pqcp_runtime_migration_policy effective;
	const struct pqcp_adaptive_profile *source;
	const struct pqcp_adaptive_profile *target;
	uint32_t reasons;

	if (migration == NULL || controller == NULL ||
	    report == NULL || migration_id == 0U ||
	    now_ms == 0U ||
	    !pqcp_runtime_internal_text_valid(
		    from_profile, PQCP_RUNTIME_PROFILE_MAX_CHARS) ||
	    !pqcp_runtime_internal_text_valid(
		    to_profile, PQCP_RUNTIME_PROFILE_MAX_CHARS) ||
	    strcmp(from_profile, to_profile) == 0) {
		return -EINVAL;
	}
	if (policy == NULL) {
		if (pqcp_runtime_migration_policy_default(
			    &effective) != 0) {
			return -EINVAL;
		}
		policy = &effective;
	}
	if (!migration_policy_valid(policy)) {
		return -EINVAL;
	}
	memset(migration, 0, sizeof(*migration));
	migration->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	migration->migration_id = migration_id;
	migration->state = PQCP_RUNTIME_MIGRATION_ASSESSING;
	migration->controller = controller;
	migration->policy = *policy;
	migration->started_at_ms = now_ms;
	migration->deadline_ms =
		now_ms + policy->drain_timeout_ms +
		policy->canary_timeout_ms;
	(void)pqcp_runtime_internal_copy_text(
		migration->from_profile,
		sizeof(migration->from_profile), from_profile);
	(void)pqcp_runtime_internal_copy_text(
		migration->to_profile,
		sizeof(migration->to_profile), to_profile);
	k_mutex_init(&migration->lock);
	source = find_profile(migration, from_profile);
	target = find_profile(migration, to_profile);
	migration->source_enabled_before =
		source != NULL && source->enabled;
	migration->target_enabled_before =
		target != NULL && target->enabled;
	reasons = assess_profiles(migration, source, target);
	migration->reason_mask = reasons;
	if (reasons != 0U) {
		migration->state = PQCP_RUNTIME_MIGRATION_BLOCKED;
		(void)fill_report(migration, now_ms, report);
		return -EACCES;
	}
	migration->state = PQCP_RUNTIME_MIGRATION_CANARY;
	return fill_report(migration, 0U, report);
}

static struct pqcp_runtime_migration_canary *find_canary(
	struct pqcp_runtime_migration *migration,
	uint64_t canary_id)
{
	for (size_t index = 0U;
	     index < migration->canary_count; ++index) {
		if (migration->canaries[index].canary_id == canary_id) {
			return &migration->canaries[index];
		}
	}
	return NULL;
}

int pqcp_runtime_migration_start_canary(
	struct pqcp_runtime_migration *migration,
	uint64_t canary_id,
	uint64_t session_id,
	uint64_t now_ms)
{
	struct pqcp_runtime_migration_canary *canary;

	if (migration == NULL || canary_id == 0U ||
	    session_id == 0U || now_ms == 0U ||
	    migration->state != PQCP_RUNTIME_MIGRATION_CANARY ||
	    migration->canary_count >=
		    PQCP_RUNTIME_MIGRATION_MAX_CANARIES ||
	    find_canary(migration, canary_id) != NULL ||
	    now_ms > migration->deadline_ms) {
		return -EINVAL;
	}
	canary = &migration->canaries[migration->canary_count++];
	memset(canary, 0, sizeof(*canary));
	canary->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	canary->canary_id = canary_id;
	canary->session_id = session_id;
	canary->started_at_ms = now_ms;
	return 0;
}

int pqcp_runtime_migration_complete_canary(
	struct pqcp_runtime_migration *migration,
	uint64_t canary_id,
	const struct pqcp_runtime_measurement *measurement,
	uint64_t now_ms)
{
	struct pqcp_runtime_migration_canary *canary;

	if (migration == NULL || measurement == NULL ||
	    now_ms == 0U ||
	    migration->state != PQCP_RUNTIME_MIGRATION_CANARY ||
	    measurement->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION) {
		return -EINVAL;
	}
	canary = find_canary(migration, canary_id);
	if (canary == NULL || canary->completed ||
	    now_ms < canary->started_at_ms ||
	    now_ms - canary->started_at_ms >
		    migration->policy.canary_timeout_ms) {
		return -EINVAL;
	}
	canary->completed_at_ms = now_ms;
	canary->latency_us = measurement->latency_us;
	canary->cycles = measurement->cycles;
	canary->stack_bytes = measurement->stack_used_bytes;
	canary->result = measurement->result;
	canary->successful = measurement->success;
	canary->completed = true;
	if (!canary->successful) {
		uint32_t failures = 0U;

		for (size_t index = 0U;
		     index < migration->canary_count; ++index) {
			if (migration->canaries[index].completed &&
			    !migration->canaries[index].successful) {
				failures++;
			}
		}
		if (failures >
		    migration->policy.maximum_canary_failures) {
			migration->reason_mask |=
				PQCP_RUNTIME_MIGRATION_REASON_CANARY_FAILURE;
			if (migration->policy.rollback_on_canary_failure) {
				migration->state =
					PQCP_RUNTIME_MIGRATION_ROLLING_BACK;
			}
		}
	}
	return 0;
}

static bool canaries_satisfy_policy(
	const struct pqcp_runtime_migration *migration)
{
	uint32_t successes = 0U;
	uint32_t failures = 0U;

	for (size_t index = 0U;
	     index < migration->canary_count; ++index) {
		if (!migration->canaries[index].completed) {
			continue;
		}
		if (migration->canaries[index].successful) {
			successes++;
		} else {
			failures++;
		}
	}
	return successes >=
		       migration->policy.required_canary_successes &&
	       failures <=
		       migration->policy.maximum_canary_failures;
}

int pqcp_runtime_migration_promote(
	struct pqcp_runtime_migration *migration,
	uint64_t now_ms,
	struct pqcp_runtime_migration_report *report)
{
	struct pqcp_adaptive_profile *target;
	int draining = 0;

	if (migration == NULL || report == NULL ||
	    now_ms == 0U ||
	    migration->state != PQCP_RUNTIME_MIGRATION_CANARY ||
	    !canaries_satisfy_policy(migration) ||
	    now_ms > migration->deadline_ms) {
		return -EINVAL;
	}
	target = find_profile_mutable(
		migration, migration->to_profile);
	if (target == NULL) {
		migration->reason_mask |=
			PQCP_RUNTIME_MIGRATION_REASON_TARGET_MISSING;
		migration->state = PQCP_RUNTIME_MIGRATION_BLOCKED;
		(void)fill_report(migration, now_ms, report);
		return -ENOENT;
	}
	target->enabled = true;
	if (migration->policy.drain_old_sessions) {
		draining = pqcp_runtime_controller_transition_profile(
			migration->controller,
			migration->from_profile,
			migration->to_profile, now_ms);
		if (draining < 0) {
			migration->reason_mask |=
				PQCP_RUNTIME_MIGRATION_REASON_AUDIT;
			migration->state =
				PQCP_RUNTIME_MIGRATION_ROLLING_BACK;
			(void)fill_report(migration, now_ms, report);
			return draining;
		}
	}
	migration->state = draining > 0 ?
		PQCP_RUNTIME_MIGRATION_DRAINING :
		PQCP_RUNTIME_MIGRATION_PROMOTED;
	return fill_report(
		migration,
		migration->state == PQCP_RUNTIME_MIGRATION_PROMOTED ?
			now_ms : 0U,
		report);
}

int pqcp_runtime_migration_rollback(
	struct pqcp_runtime_migration *migration,
	uint64_t now_ms,
	struct pqcp_runtime_migration_report *report)
{
	struct pqcp_adaptive_profile *source;
	struct pqcp_adaptive_profile *target;

	if (migration == NULL || report == NULL ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	migration->state = PQCP_RUNTIME_MIGRATION_ROLLING_BACK;
	source = find_profile_mutable(
		migration, migration->from_profile);
	target = find_profile_mutable(
		migration, migration->to_profile);
	if (source == NULL || target == NULL) {
		migration->reason_mask |=
			PQCP_RUNTIME_MIGRATION_REASON_TARGET_MISSING;
		migration->state = PQCP_RUNTIME_MIGRATION_BLOCKED;
		(void)fill_report(migration, now_ms, report);
		return -ENOENT;
	}
	source->enabled = migration->source_enabled_before;
	target->enabled = migration->target_enabled_before;
	for (size_t index = 0U;
	     index < migration->controller->sessions->capacity; ++index) {
		struct pqcp_runtime_session *session =
			&migration->controller->sessions->sessions[index];

		if (session->active &&
		    strcmp(session->profile_id,
			   migration->from_profile) == 0) {
			session->draining = false;
		}
	}
	migration->state = PQCP_RUNTIME_MIGRATION_ROLLED_BACK;
	return fill_report(migration, now_ms, report);
}

int pqcp_runtime_migration_tick(
	struct pqcp_runtime_migration *migration,
	uint64_t now_ms,
	struct pqcp_runtime_migration_report *report)
{
	uint32_t remaining;

	if (migration == NULL || report == NULL ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	if (now_ms > migration->deadline_ms &&
	    migration->state != PQCP_RUNTIME_MIGRATION_PROMOTED &&
	    migration->state != PQCP_RUNTIME_MIGRATION_ROLLED_BACK &&
	    migration->state != PQCP_RUNTIME_MIGRATION_BLOCKED) {
		migration->reason_mask |=
			PQCP_RUNTIME_MIGRATION_REASON_DEADLINE;
		return pqcp_runtime_migration_rollback(
			migration, now_ms, report);
	}
	if (migration->state ==
	    PQCP_RUNTIME_MIGRATION_ROLLING_BACK) {
		return pqcp_runtime_migration_rollback(
			migration, now_ms, report);
	}
	if (migration->state !=
	    PQCP_RUNTIME_MIGRATION_DRAINING) {
		return fill_report(migration, 0U, report);
	}
	remaining = count_profile_sessions(
		migration->controller->sessions,
		migration->from_profile, true);
	if (remaining == 0U) {
		migration->state =
			PQCP_RUNTIME_MIGRATION_PROMOTED;
		return fill_report(migration, now_ms, report);
	}
	migration->reason_mask |=
		PQCP_RUNTIME_MIGRATION_REASON_ACTIVE_SESSIONS;
	return fill_report(migration, 0U, report);
}

int pqcp_runtime_migration_audit(
	const struct pqcp_runtime_migration *migration)
{
	if (migration == NULL ||
	    migration->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    migration->migration_id == 0U ||
	    migration->controller == NULL ||
	    !migration_policy_valid(&migration->policy) ||
	    !pqcp_runtime_internal_text_valid(
		    migration->from_profile,
		    sizeof(migration->from_profile)) ||
	    !pqcp_runtime_internal_text_valid(
		    migration->to_profile,
		    sizeof(migration->to_profile)) ||
	    migration->canary_count >
		    PQCP_RUNTIME_MIGRATION_MAX_CANARIES) {
		return -EBADMSG;
	}
	for (size_t index = 0U;
	     index < migration->canary_count; ++index) {
		const struct pqcp_runtime_migration_canary *canary =
			&migration->canaries[index];

		if (canary->schema_version !=
			    PQCP_RUNTIME_SCHEMA_VERSION ||
		    canary->canary_id == 0U ||
		    canary->session_id == 0U ||
		    (canary->completed &&
		     canary->completed_at_ms < canary->started_at_ms)) {
			return -EBADMSG;
		}
	}
	return 0;
}

int pqcp_runtime_migration_report_verify(
	const struct pqcp_runtime_migration_report *report)
{
	uint8_t expected[PQCP_RUNTIME_DIGEST_BYTES];

	if (report == NULL ||
	    report->schema_version != PQCP_RUNTIME_SCHEMA_VERSION ||
	    report->migration_id == 0U ||
	    !pqcp_runtime_internal_text_valid(
		    report->from_profile,
		    sizeof(report->from_profile)) ||
	    !pqcp_runtime_internal_text_valid(
		    report->to_profile,
		    sizeof(report->to_profile)) ||
	    report->canaries_succeeded +
			    report->canaries_failed >
		    report->canaries_started ||
	    migration_digest(report, expected) != 0 ||
	    memcmp(expected, report->digest,
		   sizeof(expected)) != 0) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_runtime_migration_emit(
	const struct pqcp_runtime_migration_report *report)
{
	char digest_hex[PQCP_RUNTIME_DIGEST_HEX_CHARS + 1U];

	if (pqcp_runtime_migration_report_verify(report) != 0 ||
	    pqcp_runtime_internal_hex(
		    report->digest, sizeof(report->digest),
		    digest_hex, sizeof(digest_hex)) != 0) {
		return -EBADMSG;
	}
	printk("PQCP_RUNTIME_MIGRATION id=%llu state=%u from=%s to=%s reasons=0x%08x security=%u/%u evidence=%u/%u canaries=%u/%u/%u draining=%u remaining=%u digest=%s\n",
	       (unsigned long long)report->migration_id,
	       (unsigned int)report->state,
	       report->from_profile, report->to_profile,
	       report->reason_mask, report->old_security_level,
	       report->new_security_level,
	       report->old_evidence_score,
	       report->new_evidence_score,
	       report->canaries_started,
	       report->canaries_succeeded,
	       report->canaries_failed,
	       report->sessions_draining,
	       report->sessions_remaining, digest_hex);
	return 0;
}
