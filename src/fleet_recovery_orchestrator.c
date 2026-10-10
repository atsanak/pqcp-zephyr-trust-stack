/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Typed, dependency-aware fleet recovery playbook orchestration.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/errno.h>
#include <pqcp_zephyr/fleet_recovery_orchestrator.h>

#include "runtime_internal.h"

#define RECOVERY_PLAYBOOK_LABEL "PQCP-FLEET-RECOVERY-PLAYBOOK-V1"
#define RECOVERY_AUTHORIZATION_LABEL "PQCP-FLEET-RECOVERY-AUTH-V1"
#define RECOVERY_CHECKPOINT_LABEL "PQCP-FLEET-RECOVERY-CHECKPOINT-V1"
#define RECOVERY_AUDIT_LABEL "PQCP-FLEET-RECOVERY-AUDIT-V1"
#define RECOVERY_SNAPSHOT_LABEL "PQCP-FLEET-RECOVERY-SNAPSHOT-V1"
#define RECOVERY_STEP_BODY_BYTES 512U
#define RECOVERY_CHECKPOINT_BODY_BYTES 224U
#define RECOVERY_AUDIT_BODY_BYTES 160U
#define RECOVERY_SNAPSHOT_BODY_BYTES 384U
#define RECOVERY_STEP_RESULT_BYTES 128U

static bool step_type_valid(
	enum pqcp_fleet_recovery_step_type type)
{
	return type >
		       PQCP_FLEET_RECOVERY_STEP_NONE &&
	       type <
		       PQCP_FLEET_RECOVERY_STEP_TYPE_COUNT;
}

static bool step_state_valid(
	enum pqcp_fleet_recovery_step_state state)
{
	return state >= PQCP_FLEET_RECOVERY_STEP_PENDING &&
	       state <= PQCP_FLEET_RECOVERY_STEP_SKIPPED;
}

static bool orchestrator_state_valid(
	enum pqcp_fleet_recovery_orchestrator_state state)
{
	return state >=
		       PQCP_FLEET_RECOVERY_ORCHESTRATOR_EMPTY &&
	       state <=
		       PQCP_FLEET_RECOVERY_ORCHESTRATOR_LOCKED;
}

static bool compensation_valid(
	enum pqcp_fleet_recovery_compensation compensation)
{
	return compensation >=
		       PQCP_FLEET_RECOVERY_COMPENSATE_NONE &&
	       compensation <=
		       PQCP_FLEET_RECOVERY_COMPENSATE_CLOSE_REOPENED_SESSIONS;
}

static bool audit_event_valid(
	enum pqcp_fleet_recovery_audit_event event)
{
	return event > PQCP_FLEET_RECOVERY_AUDIT_NONE &&
	       event < PQCP_FLEET_RECOVERY_AUDIT_EVENT_COUNT;
}

static bool reason_valid(
	enum pqcp_fleet_recovery_reason reason)
{
	return reason >
		       PQCP_FLEET_RECOVERY_REASON_NONE &&
	       reason <=
		       PQCP_FLEET_RECOVERY_OPERATOR_REQUEST;
}

static bool time_source_valid(
	enum pqcp_fleet_time_source source)
{
	return source >
		       PQCP_FLEET_TIME_SOURCE_NONE &&
	       source <=
		       PQCP_FLEET_TIME_SOURCE_SECURE_ELEMENT;
}

static bool time_quality_valid(
	enum pqcp_fleet_time_quality quality)
{
	return quality >= PQCP_FLEET_TIME_HOLDOVER &&
	       quality <= PQCP_FLEET_TIME_ATTESTED;
}

static bool digest_zero(const uint8_t *digest, size_t length)
{
	uint8_t aggregate = 0U;

	if (digest == NULL) {
		return true;
	}
	for (size_t index = 0U; index < length; ++index) {
		aggregate |= digest[index];
	}
	return aggregate == 0U;
}

static bool digest_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length)
{
	uint8_t difference = 0U;

	if (left == NULL || right == NULL) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

static int size_multiply(size_t left, size_t right, size_t *result)
{
	if (result == NULL) {
		return -EINVAL;
	}
	if (left != 0U && right > SIZE_MAX / left) {
		return -EOVERFLOW;
	}
	*result = left * right;
	return 0;
}

static uint64_t saturating_add_u64(uint64_t left, uint64_t right)
{
	if (right > UINT64_MAX - left) {
		return UINT64_MAX;
	}
	return left + right;
}

static uint64_t saturating_increment_u64(uint64_t value)
{
	return value == UINT64_MAX ? UINT64_MAX : value + 1U;
}

static uint32_t saturating_increment_u32(uint32_t value)
{
	return value == UINT32_MAX ? UINT32_MAX : value + 1U;
}

static uint64_t retry_delay(
	const struct pqcp_fleet_recovery_step_definition *step,
	uint32_t attempt)
{
	uint32_t shift;
	uint64_t delay;
	uint64_t jitter;

	if (step->base_retry_ms == 0U) {
		return 0U;
	}
	shift = attempt > 1U ? attempt - 1U : 0U;
	if (shift > 31U ||
	    step->base_retry_ms > (UINT64_MAX >> shift)) {
		delay = UINT64_MAX;
	} else {
		delay = step->base_retry_ms << shift;
	}
	if (delay > step->maximum_retry_ms) {
		delay = step->maximum_retry_ms;
	}
	if (delay == 0U) {
		return 0U;
	}
	jitter = ((uint64_t)step->step_id << 32 |
		  attempt) % (delay / 8U + 1U);
	if (jitter >
	    step->maximum_retry_ms - delay) {
		return step->maximum_retry_ms;
	}
	return delay + jitter;
}

static size_t append_u32(
	uint8_t *output,
	size_t offset,
	uint32_t value)
{
	pqcp_runtime_internal_write_u32(output + offset, value);
	return offset + 4U;
}

static size_t append_i32(
	uint8_t *output,
	size_t offset,
	int32_t value)
{
	pqcp_runtime_internal_write_u32(
		output + offset, (uint32_t)value);
	return offset + 4U;
}

static size_t append_u64(
	uint8_t *output,
	size_t offset,
	uint64_t value)
{
	pqcp_runtime_internal_write_u64(output + offset, value);
	return offset + 8U;
}

static size_t append_bool(
	uint8_t *output,
	size_t offset,
	bool value)
{
	output[offset] = value ? 1U : 0U;
	return offset + 1U;
}

static size_t append_digest(
	uint8_t *output,
	size_t offset,
	const uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	memcpy(output + offset, digest, PQCP_FLEET_DIGEST_BYTES);
	return offset + PQCP_FLEET_DIGEST_BYTES;
}

static size_t append_text(
	uint8_t *output,
	size_t offset,
	const char *text,
	size_t capacity)
{
	size_t length = strnlen(text, capacity);

	output[offset++] = (uint8_t)length;
	memcpy(output + offset, text, length);
	return offset + length;
}

static int policy_validate(
	const struct pqcp_fleet_recovery_policy *policy)
{
	if (policy == NULL ||
	    policy->schema_version !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_SCHEMA_VERSION ||
	    policy->maximum_playbook_attempts == 0U ||
	    policy->lockout_after_failures == 0U ||
	    policy->maximum_authorization_failures == 0U ||
	    policy->default_step_timeout_ms == 0U ||
	    policy->default_base_retry_ms == 0U ||
	    policy->default_maximum_retry_ms <
		    policy->default_base_retry_ms ||
	    policy->lockout_ms == 0U ||
	    policy->completion_cooldown_ms == 0U) {
		return -EINVAL;
	}
	return 0;
}

int pqcp_fleet_recovery_policy_default(
	struct pqcp_fleet_recovery_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->schema_version =
		PQCP_FLEET_RECOVERY_ORCHESTRATOR_SCHEMA_VERSION;
	policy->maximum_playbook_attempts = 3U;
	policy->lockout_after_failures = 3U;
	policy->maximum_authorization_failures = 3U;
	policy->default_step_timeout_ms = 120000U;
	policy->default_base_retry_ms = 1000U;
	policy->default_maximum_retry_ms = 60000U;
	policy->lockout_ms = 300000U;
	policy->completion_cooldown_ms = 60000U;
	policy->auto_compensate = true;
	policy->compensate_optional_steps = true;
	policy->lock_on_compensation_failure = true;
	policy->require_checkpoint_persistence = true;
	policy->require_all_steps_authorized = true;
	return 0;
}

static int trust_anchor_validate(
	const struct pqcp_fleet_recovery_trust_anchor_step *step)
{
	if (step->current_epoch == 0U ||
	    step->replacement_epoch <= step->current_epoch ||
	    digest_zero(
		    step->current_anchor_digest,
		    sizeof(step->current_anchor_digest)) ||
	    digest_zero(
		    step->replacement_anchor_digest,
		    sizeof(step->replacement_anchor_digest)) ||
	    digest_zero(
		    step->authorization_key_digest,
		    sizeof(step->authorization_key_digest)) ||
	    digest_equal(
		    step->current_anchor_digest,
		    step->replacement_anchor_digest,
		    sizeof(step->current_anchor_digest))) {
		return -EINVAL;
	}
	return 0;
}

static int security_snapshot_validate(
	const struct pqcp_fleet_recovery_security_snapshot_step *step)
{
	if (step->current_policy_epoch == 0U ||
	    step->current_revocation_epoch == 0U ||
	    step->target_policy_epoch <
		    step->current_policy_epoch ||
	    (!step->allow_equal_policy_epoch &&
	     step->target_policy_epoch ==
		     step->current_policy_epoch) ||
	    step->target_revocation_epoch <
		    step->current_revocation_epoch ||
	    digest_zero(
		    step->policy_snapshot_digest,
		    sizeof(step->policy_snapshot_digest)) ||
	    digest_zero(
		    step->revocation_snapshot_digest,
		    sizeof(step->revocation_snapshot_digest))) {
		return -EINVAL;
	}
	return 0;
}

static int credential_validate(
	const struct pqcp_fleet_recovery_credential_step *step)
{
	if (!pqcp_runtime_internal_text_valid(
		    step->current_credential_id,
		    sizeof(step->current_credential_id)) ||
	    !pqcp_runtime_internal_text_valid(
		    step->replacement_credential_id,
		    sizeof(step->replacement_credential_id)) ||
	    strcmp(
		    step->current_credential_id,
		    step->replacement_credential_id) == 0 ||
	    step->current_credential_epoch == 0U ||
	    step->replacement_credential_epoch <=
		    step->current_credential_epoch ||
	    step->overlap_until_ms == 0U ||
	    digest_zero(
		    step->current_key_digest,
		    sizeof(step->current_key_digest)) ||
	    digest_zero(
		    step->replacement_key_digest,
		    sizeof(step->replacement_key_digest)) ||
	    digest_zero(
		    step->replacement_credential_digest,
		    sizeof(step->replacement_credential_digest)) ||
	    digest_equal(
		    step->current_key_digest,
		    step->replacement_key_digest,
		    sizeof(step->current_key_digest))) {
		return -EINVAL;
	}
	return 0;
}

static int update_rollback_validate(
	const struct pqcp_fleet_recovery_update_rollback_step *step)
{
	if (!pqcp_runtime_internal_text_valid(
		    step->component_id,
		    sizeof(step->component_id)) ||
	    step->failed_version == 0U ||
	    step->rollback_version == 0U ||
	    step->rollback_version >= step->failed_version ||
	    step->rollback_deadline_ms == 0U ||
	    digest_zero(
		    step->failed_image_digest,
		    sizeof(step->failed_image_digest)) ||
	    digest_zero(
		    step->rollback_image_digest,
		    sizeof(step->rollback_image_digest)) ||
	    digest_zero(
		    step->boot_measurement_digest,
		    sizeof(step->boot_measurement_digest)) ||
	    digest_equal(
		    step->failed_image_digest,
		    step->rollback_image_digest,
		    sizeof(step->failed_image_digest))) {
		return -EINVAL;
	}
	return 0;
}

static int secure_time_validate(
	const struct pqcp_fleet_recovery_secure_time_step *step)
{
	if (!time_source_valid(step->source) ||
	    !time_quality_valid(step->minimum_quality) ||
	    step->minimum_reference_time_ms == 0U ||
	    step->maximum_uncertainty_ms == 0U ||
	    step->valid_until_monotonic_ms == 0U ||
	    step->maximum_drift_ppm > 100000U ||
	    digest_zero(
		    step->source_digest,
		    sizeof(step->source_digest)) ||
	    (step->require_attested_source &&
	     step->minimum_quality !=
		     PQCP_FLEET_TIME_ATTESTED)) {
		return -EINVAL;
	}
	return 0;
}

static int session_validate(
	const struct pqcp_fleet_recovery_session_step *step)
{
	if (!pqcp_runtime_internal_text_valid(
		    step->session_label,
		    sizeof(step->session_label)) ||
	    step->required_capabilities == 0U ||
	    step->minimum_session_count == 0U ||
	    step->maximum_session_count <
		    step->minimum_session_count ||
	    digest_zero(
		    step->peer_identity_digest,
		    sizeof(step->peer_identity_digest)) ||
	    digest_zero(
		    step->expected_channel_binding,
		    sizeof(step->expected_channel_binding))) {
		return -EINVAL;
	}
	return 0;
}

static int compensation_matches_step(
	enum pqcp_fleet_recovery_step_type type,
	enum pqcp_fleet_recovery_compensation compensation)
{
	if (compensation ==
	    PQCP_FLEET_RECOVERY_COMPENSATE_NONE) {
		return 0;
	}
	switch (type) {
	case PQCP_FLEET_RECOVERY_STEP_TRUST_ANCHOR_RENEWAL:
		return compensation ==
			PQCP_FLEET_RECOVERY_COMPENSATE_RESTORE_TRUST_ANCHOR ?
			0 : -EINVAL;
	case PQCP_FLEET_RECOVERY_STEP_REVOCATION_POLICY_SNAPSHOT:
		return compensation ==
			PQCP_FLEET_RECOVERY_COMPENSATE_RESTORE_SECURITY_SNAPSHOT ?
			0 : -EINVAL;
	case PQCP_FLEET_RECOVERY_STEP_CREDENTIAL_REPLACEMENT:
		return compensation ==
			PQCP_FLEET_RECOVERY_COMPENSATE_REVOKE_REPLACEMENT ?
			0 : -EINVAL;
	case PQCP_FLEET_RECOVERY_STEP_UPDATE_ROLLBACK:
		return compensation ==
			PQCP_FLEET_RECOVERY_COMPENSATE_REACTIVATE_UPDATE ?
			0 : -EINVAL;
	case PQCP_FLEET_RECOVERY_STEP_SECURE_TIME_RESTORE:
		return compensation ==
			PQCP_FLEET_RECOVERY_COMPENSATE_INVALIDATE_TIME_ANCHOR ?
			0 : -EINVAL;
	case PQCP_FLEET_RECOVERY_STEP_SESSION_REOPEN:
		return compensation ==
			PQCP_FLEET_RECOVERY_COMPENSATE_CLOSE_REOPENED_SESSIONS ?
			0 : -EINVAL;
	default:
		return -EINVAL;
	}
}

static int step_parameters_validate(
	const struct pqcp_fleet_recovery_step_definition *step)
{
	switch (step->type) {
	case PQCP_FLEET_RECOVERY_STEP_TRUST_ANCHOR_RENEWAL:
		return trust_anchor_validate(
			&step->parameters.trust_anchor);
	case PQCP_FLEET_RECOVERY_STEP_REVOCATION_POLICY_SNAPSHOT:
		return security_snapshot_validate(
			&step->parameters.security_snapshot);
	case PQCP_FLEET_RECOVERY_STEP_CREDENTIAL_REPLACEMENT:
		return credential_validate(
			&step->parameters.credential);
	case PQCP_FLEET_RECOVERY_STEP_UPDATE_ROLLBACK:
		return update_rollback_validate(
			&step->parameters.update_rollback);
	case PQCP_FLEET_RECOVERY_STEP_SECURE_TIME_RESTORE:
		return secure_time_validate(
			&step->parameters.secure_time);
	case PQCP_FLEET_RECOVERY_STEP_SESSION_REOPEN:
		return session_validate(
			&step->parameters.session);
	default:
		return -EINVAL;
	}
}

static bool executor_supports(
	const struct pqcp_fleet_recovery_executor *executor,
	enum pqcp_fleet_recovery_step_type type)
{
	switch (type) {
	case PQCP_FLEET_RECOVERY_STEP_TRUST_ANCHOR_RENEWAL:
		return executor->renew_trust_anchor != NULL;
	case PQCP_FLEET_RECOVERY_STEP_REVOCATION_POLICY_SNAPSHOT:
		return executor->install_security_snapshot != NULL;
	case PQCP_FLEET_RECOVERY_STEP_CREDENTIAL_REPLACEMENT:
		return executor->replace_credential != NULL;
	case PQCP_FLEET_RECOVERY_STEP_UPDATE_ROLLBACK:
		return executor->rollback_update != NULL;
	case PQCP_FLEET_RECOVERY_STEP_SECURE_TIME_RESTORE:
		return executor->restore_secure_time != NULL;
	case PQCP_FLEET_RECOVERY_STEP_SESSION_REOPEN:
		return executor->reopen_sessions != NULL;
	default:
		return false;
	}
}

static int step_definition_validate(
	const struct pqcp_fleet_recovery_step_definition *step,
	size_t index,
	size_t step_count,
	const struct pqcp_fleet_recovery_executor *executor)
{
	uint32_t valid_dependency_mask;

	if (step == NULL ||
	    step->schema_version !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_SCHEMA_VERSION ||
	    step->step_id == 0U ||
	    !step_type_valid(step->type) ||
	    step->priority > 255U ||
	    step->maximum_attempts == 0U ||
	    step->timeout_ms == 0U ||
	    step->base_retry_ms == 0U ||
	    step->maximum_retry_ms < step->base_retry_ms ||
	    !compensation_valid(step->compensation) ||
	    compensation_matches_step(
		    step->type, step->compensation) != 0 ||
	    !executor_supports(executor, step->type) ||
	    step_parameters_validate(step) != 0) {
		return -EINVAL;
	}
	valid_dependency_mask =
		step_count == 32U ?
			UINT32_MAX :
			(UINT32_C(1) << step_count) - 1U;
	if ((step->dependency_mask &
	     ~valid_dependency_mask) != 0U ||
	    (step->dependency_mask &
	     (UINT32_C(1) << index)) != 0U) {
		return -EINVAL;
	}
	if (step->required) {
		if (step->manager_step_bit == 0U ||
		    (step->manager_step_bit &
		     (step->manager_step_bit - 1U)) != 0U) {
			return -EINVAL;
		}
	} else if (step->manager_step_bit != 0U &&
		   (step->manager_step_bit &
		    (step->manager_step_bit - 1U)) != 0U) {
		return -EINVAL;
	}
	return 0;
}

static size_t step_body(
	const struct pqcp_fleet_recovery_step_definition *step,
	uint8_t output[RECOVERY_STEP_BODY_BYTES])
{
	size_t offset = 0U;

	if (step == NULL || output == NULL ||
	    !step_type_valid(step->type)) {
		return 0U;
	}
	memset(output, 0, RECOVERY_STEP_BODY_BYTES);
	offset = append_u32(output, offset, step->schema_version);
	offset = append_u32(output, offset, step->step_id);
	offset = append_u32(
		output, offset, (uint32_t)step->type);
	offset = append_u32(
		output, offset, step->dependency_mask);
	offset = append_u32(
		output, offset, step->manager_step_bit);
	offset = append_u32(output, offset, step->priority);
	offset = append_u32(
		output, offset, step->maximum_attempts);
	offset = append_u64(output, offset, step->timeout_ms);
	offset = append_u64(output, offset, step->base_retry_ms);
	offset = append_u64(
		output, offset, step->maximum_retry_ms);
	offset = append_u32(
		output, offset, (uint32_t)step->compensation);
	offset = append_bool(output, offset, step->required);
	switch (step->type) {
	case PQCP_FLEET_RECOVERY_STEP_TRUST_ANCHOR_RENEWAL: {
		const struct pqcp_fleet_recovery_trust_anchor_step *item =
			&step->parameters.trust_anchor;

		offset = append_u64(
			output, offset, item->current_epoch);
		offset = append_u64(
			output, offset, item->replacement_epoch);
		offset = append_digest(
			output, offset, item->current_anchor_digest);
		offset = append_digest(
			output, offset,
			item->replacement_anchor_digest);
		offset = append_digest(
			output, offset,
			item->authorization_key_digest);
		offset = append_bool(
			output, offset,
			item->require_cross_signature);
		break;
	}
	case PQCP_FLEET_RECOVERY_STEP_REVOCATION_POLICY_SNAPSHOT: {
		const struct pqcp_fleet_recovery_security_snapshot_step
			*item = &step->parameters.security_snapshot;

		offset = append_u64(
			output, offset, item->current_policy_epoch);
		offset = append_u64(
			output, offset, item->target_policy_epoch);
		offset = append_u64(
			output, offset,
			item->current_revocation_epoch);
		offset = append_u64(
			output, offset,
			item->target_revocation_epoch);
		offset = append_digest(
			output, offset, item->policy_snapshot_digest);
		offset = append_digest(
			output, offset,
			item->revocation_snapshot_digest);
		offset = append_bool(
			output, offset,
			item->allow_equal_policy_epoch);
		offset = append_bool(
			output, offset,
			item->require_complete_revocation_set);
		break;
	}
	case PQCP_FLEET_RECOVERY_STEP_CREDENTIAL_REPLACEMENT: {
		const struct pqcp_fleet_recovery_credential_step *item =
			&step->parameters.credential;

		offset = append_text(
			output, offset, item->current_credential_id,
			sizeof(item->current_credential_id));
		offset = append_text(
			output, offset,
			item->replacement_credential_id,
			sizeof(item->replacement_credential_id));
		offset = append_u64(
			output, offset,
			item->current_credential_epoch);
		offset = append_u64(
			output, offset,
			item->replacement_credential_epoch);
		offset = append_u64(
			output, offset, item->overlap_until_ms);
		offset = append_digest(
			output, offset, item->current_key_digest);
		offset = append_digest(
			output, offset, item->replacement_key_digest);
		offset = append_digest(
			output, offset,
			item->replacement_credential_digest);
		offset = append_bool(
			output, offset,
			item->destroy_old_key_after_commit);
		break;
	}
	case PQCP_FLEET_RECOVERY_STEP_UPDATE_ROLLBACK: {
		const struct pqcp_fleet_recovery_update_rollback_step *item =
			&step->parameters.update_rollback;

		offset = append_text(
			output, offset, item->component_id,
			sizeof(item->component_id));
		offset = append_u64(
			output, offset, item->failed_version);
		offset = append_u64(
			output, offset, item->rollback_version);
		offset = append_u64(
			output, offset, item->rollback_deadline_ms);
		offset = append_digest(
			output, offset, item->failed_image_digest);
		offset = append_digest(
			output, offset, item->rollback_image_digest);
		offset = append_digest(
			output, offset,
			item->boot_measurement_digest);
		offset = append_bool(
			output, offset,
			item->require_health_validation);
		break;
	}
	case PQCP_FLEET_RECOVERY_STEP_SECURE_TIME_RESTORE: {
		const struct pqcp_fleet_recovery_secure_time_step *item =
			&step->parameters.secure_time;

		offset = append_u32(
			output, offset, (uint32_t)item->source);
		offset = append_u32(
			output, offset,
			(uint32_t)item->minimum_quality);
		offset = append_u64(
			output, offset,
			item->minimum_reference_time_ms);
		offset = append_u64(
			output, offset,
			item->maximum_uncertainty_ms);
		offset = append_u64(
			output, offset,
			item->valid_until_monotonic_ms);
		offset = append_u32(
			output, offset, item->maximum_drift_ppm);
		offset = append_digest(
			output, offset, item->source_digest);
		offset = append_bool(
			output, offset,
			item->require_attested_source);
		break;
	}
	case PQCP_FLEET_RECOVERY_STEP_SESSION_REOPEN: {
		const struct pqcp_fleet_recovery_session_step *item =
			&step->parameters.session;

		offset = append_text(
			output, offset, item->session_label,
			sizeof(item->session_label));
		offset = append_u64(
			output, offset, item->previous_session_id);
		offset = append_u32(
			output, offset, item->required_capabilities);
		offset = append_u32(
			output, offset, item->minimum_session_count);
		offset = append_u32(
			output, offset, item->maximum_session_count);
		offset = append_digest(
			output, offset, item->peer_identity_digest);
		offset = append_digest(
			output, offset,
			item->expected_channel_binding);
		offset = append_bool(
			output, offset,
			item->require_fresh_handshake);
		break;
	}
	default:
		return 0U;
	}
	return offset <= RECOVERY_STEP_BODY_BYTES ? offset : 0U;
}

static int step_definition_digest(
	const struct pqcp_fleet_recovery_step_definition *step,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t body[RECOVERY_STEP_BODY_BYTES];
	size_t length = step_body(step, body);
	int ret;

	if (length == 0U) {
		return -EINVAL;
	}
	ret = pqcp_runtime_internal_sha256(body, length, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

int pqcp_fleet_recovery_playbook_digest(
	const struct pqcp_fleet_recovery_step_definition *steps,
	size_t step_count,
	uint64_t playbook_id,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	const uint8_t *parts[PQCP_FLEET_RECOVERY_MAX_STEPS + 1U];
	size_t lengths[PQCP_FLEET_RECOVERY_MAX_STEPS + 1U];
	uint8_t header[
		sizeof(RECOVERY_PLAYBOOK_LABEL) - 1U + 12U];
	uint8_t step_digests[PQCP_FLEET_RECOVERY_MAX_STEPS]
		[PQCP_FLEET_DIGEST_BYTES];
	size_t offset = 0U;
	int ret;

	if (steps == NULL || step_count == 0U ||
	    step_count > PQCP_FLEET_RECOVERY_MAX_STEPS ||
	    playbook_id == 0U || digest == NULL) {
		return -EINVAL;
	}
	memcpy(header + offset, RECOVERY_PLAYBOOK_LABEL,
	       sizeof(RECOVERY_PLAYBOOK_LABEL) - 1U);
	offset += sizeof(RECOVERY_PLAYBOOK_LABEL) - 1U;
	pqcp_runtime_internal_write_u64(
		header + offset, playbook_id);
	offset += 8U;
	pqcp_runtime_internal_write_u32(
		header + offset, (uint32_t)step_count);
	offset += 4U;
	parts[0] = header;
	lengths[0] = offset;
	for (size_t index = 0U; index < step_count; ++index) {
		ret = step_definition_digest(
			&steps[index], step_digests[index]);
		if (ret != 0) {
			pqcp_runtime_secure_zero(
				step_digests,
				sizeof(step_digests));
			return ret;
		}
		parts[index + 1U] = step_digests[index];
		lengths[index + 1U] =
			PQCP_FLEET_DIGEST_BYTES;
	}
	ret = pqcp_runtime_internal_sha256_parts(
		parts, lengths, step_count + 1U, digest);
	pqcp_runtime_secure_zero(
		step_digests, sizeof(step_digests));
	pqcp_runtime_secure_zero(header, sizeof(header));
	return ret;
}

static int graph_validate(
	const struct pqcp_fleet_recovery_step_definition *steps,
	size_t step_count)
{
	uint32_t processed = 0U;
	uint32_t valid_mask =
		step_count == 32U ?
			UINT32_MAX :
			(UINT32_C(1) << step_count) - 1U;
	size_t processed_count = 0U;

	while (processed_count < step_count) {
		bool progress = false;

		for (size_t index = 0U;
		     index < step_count; ++index) {
			uint32_t bit = UINT32_C(1) << index;

			if ((processed & bit) != 0U) {
				continue;
			}
			if ((steps[index].dependency_mask &
			     ~processed) == 0U) {
				processed |= bit;
				processed_count++;
				progress = true;
			}
		}
		if (!progress) {
			return -ELOOP;
		}
	}
	return processed == valid_mask ? 0 : -EBADMSG;
}

static int definitions_validate(
	const struct pqcp_fleet_recovery_step_definition *steps,
	size_t step_count,
	const struct pqcp_fleet_recovery_executor *executor,
	const struct pqcp_fleet_recovery_manager *manager)
{
	uint32_t manager_mask = 0U;

	for (size_t left = 0U; left < step_count; ++left) {
		int ret = step_definition_validate(
			&steps[left], left, step_count, executor);

		if (ret != 0) {
			return ret;
		}
		for (size_t right = left + 1U;
		     right < step_count; ++right) {
			if (steps[right].step_id ==
			    steps[left].step_id) {
				return -EEXIST;
			}
			if (steps[left].manager_step_bit != 0U &&
			    steps[right].manager_step_bit ==
				    steps[left].manager_step_bit) {
				return -EEXIST;
			}
		}
		manager_mask |= steps[left].manager_step_bit;
	}
	if (manager_mask != manager->required_steps) {
		return -EINVAL;
	}
	return graph_validate(steps, step_count);
}

static size_t audit_body(
	const struct pqcp_fleet_recovery_audit_entry *entry,
	uint8_t output[RECOVERY_AUDIT_BODY_BYTES])
{
	size_t offset = 0U;

	if (entry == NULL || output == NULL ||
	    entry->schema_version !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_SCHEMA_VERSION ||
	    entry->sequence == 0U ||
	    entry->timestamp_ms == 0U ||
	    !audit_event_valid(entry->event) ||
	    !orchestrator_state_valid(
		    entry->orchestrator_state)) {
		return 0U;
	}
	memset(output, 0, RECOVERY_AUDIT_BODY_BYTES);
	memcpy(output + offset, RECOVERY_AUDIT_LABEL,
	       sizeof(RECOVERY_AUDIT_LABEL) - 1U);
	offset += sizeof(RECOVERY_AUDIT_LABEL) - 1U;
	offset = append_u32(
		output, offset, entry->schema_version);
	offset = append_u64(output, offset, entry->sequence);
	offset = append_u64(
		output, offset, entry->timestamp_ms);
	offset = append_u64(output, offset, entry->session_id);
	offset = append_u32(
		output, offset, (uint32_t)entry->event);
	offset = append_u32(
		output, offset,
		(uint32_t)entry->orchestrator_state);
	offset = append_u32(output, offset, entry->step_id);
	offset = append_u32(output, offset, entry->detail);
	offset = append_i32(output, offset, entry->result);
	memcpy(output + offset, entry->previous_digest,
	       sizeof(entry->previous_digest));
	offset += sizeof(entry->previous_digest);
	return offset <= RECOVERY_AUDIT_BODY_BYTES ?
		offset : 0U;
}

static int audit_digest(
	const struct pqcp_fleet_recovery_audit_entry *entry,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t body[RECOVERY_AUDIT_BODY_BYTES];
	size_t length = audit_body(entry, body);
	int ret;

	if (length == 0U) {
		return -EINVAL;
	}
	ret = pqcp_runtime_internal_sha256(body, length, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static int audit_append_locked(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	enum pqcp_fleet_recovery_audit_event event,
	uint32_t step_id,
	uint32_t detail,
	int result,
	uint64_t now_ms)
{
	struct pqcp_fleet_recovery_audit_entry entry;
	int ret;

	if (orchestrator->audit_entries == NULL ||
	    orchestrator->audit_capacity == 0U) {
		return 0;
	}
	if (!audit_event_valid(event) || now_ms == 0U) {
		return -EINVAL;
	}
	memset(&entry, 0, sizeof(entry));
	entry.schema_version =
		PQCP_FLEET_RECOVERY_ORCHESTRATOR_SCHEMA_VERSION;
	entry.sequence = orchestrator->next_audit_sequence;
	if (entry.sequence == 0U) {
		entry.sequence = 1U;
	}
	entry.timestamp_ms = now_ms;
	entry.session_id =
		orchestrator->authorization.session_id;
	entry.event = event;
	entry.orchestrator_state = orchestrator->state;
	entry.step_id = step_id;
	entry.detail = detail;
	entry.result = result;
	memcpy(entry.previous_digest,
	       orchestrator->audit_chain_head,
	       sizeof(entry.previous_digest));
	entry.occupied = true;
	ret = audit_digest(&entry, entry.entry_digest);
	if (ret != 0) {
		pqcp_runtime_secure_zero(&entry, sizeof(entry));
		return ret;
	}
	orchestrator->audit_entries[
		orchestrator->audit_next] = entry;
	orchestrator->audit_next =
		(orchestrator->audit_next + 1U) %
		orchestrator->audit_capacity;
	if (orchestrator->audit_count <
	    orchestrator->audit_capacity) {
		orchestrator->audit_count++;
	}
	memcpy(orchestrator->audit_chain_head,
	       entry.entry_digest,
	       sizeof(orchestrator->audit_chain_head));
	orchestrator->next_audit_sequence =
		saturating_increment_u64(entry.sequence);
	pqcp_runtime_secure_zero(&entry, sizeof(entry));
	return 0;
}

static size_t checkpoint_body(
	const struct pqcp_fleet_recovery_checkpoint *checkpoint,
	uint8_t output[RECOVERY_CHECKPOINT_BODY_BYTES])
{
	size_t offset = 0U;

	if (checkpoint == NULL || output == NULL ||
	    checkpoint->schema_version !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_SCHEMA_VERSION ||
	    checkpoint->checkpoint_sequence == 0U ||
	    checkpoint->session_id == 0U ||
	    checkpoint->timestamp_ms == 0U ||
	    checkpoint->step_id == 0U ||
	    !step_type_valid(checkpoint->step_type) ||
	    !step_state_valid(checkpoint->step_state) ||
	    digest_zero(
		    checkpoint->authorization_binding,
		    sizeof(checkpoint->authorization_binding)) ||
	    digest_zero(
		    checkpoint->evidence_digest,
		    sizeof(checkpoint->evidence_digest))) {
		return 0U;
	}
	memset(output, 0, RECOVERY_CHECKPOINT_BODY_BYTES);
	memcpy(output + offset, RECOVERY_CHECKPOINT_LABEL,
	       sizeof(RECOVERY_CHECKPOINT_LABEL) - 1U);
	offset += sizeof(RECOVERY_CHECKPOINT_LABEL) - 1U;
	offset = append_u32(
		output, offset, checkpoint->schema_version);
	offset = append_u64(
		output, offset,
		checkpoint->checkpoint_sequence);
	offset = append_u64(
		output, offset, checkpoint->session_id);
	offset = append_u64(
		output, offset, checkpoint->timestamp_ms);
	offset = append_u32(
		output, offset, checkpoint->step_id);
	offset = append_u32(
		output, offset, (uint32_t)checkpoint->step_type);
	offset = append_u32(
		output, offset, (uint32_t)checkpoint->step_state);
	offset = append_u32(
		output, offset, checkpoint->attempt_count);
	offset = append_i32(output, offset, checkpoint->result);
	offset = append_digest(
		output, offset,
		checkpoint->authorization_binding);
	offset = append_digest(
		output, offset, checkpoint->evidence_digest);
	offset = append_digest(
		output, offset, checkpoint->previous_digest);
	offset = append_bool(
		output, offset, checkpoint->compensation);
	return offset <= RECOVERY_CHECKPOINT_BODY_BYTES ?
		offset : 0U;
}

static int checkpoint_digest(
	const struct pqcp_fleet_recovery_checkpoint *checkpoint,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t body[RECOVERY_CHECKPOINT_BODY_BYTES];
	size_t length = checkpoint_body(checkpoint, body);
	int ret;

	if (length == 0U) {
		return -EINVAL;
	}
	ret = pqcp_runtime_internal_sha256(body, length, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static int checkpoint_stage_locked(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	const struct pqcp_fleet_recovery_step_runtime *step,
	enum pqcp_fleet_recovery_step_state state,
	const uint8_t evidence_digest[PQCP_FLEET_DIGEST_BYTES],
	bool compensation,
	int result,
	uint64_t now_ms,
	struct pqcp_fleet_recovery_checkpoint *checkpoint)
{
	if (orchestrator->checkpoint_count >=
	    orchestrator->checkpoint_capacity ||
	    orchestrator->next_checkpoint_sequence == 0U ||
	    orchestrator->next_checkpoint_sequence ==
		    UINT64_MAX) {
		return -ENOSPC;
	}
	memset(checkpoint, 0, sizeof(*checkpoint));
	checkpoint->schema_version =
		PQCP_FLEET_RECOVERY_ORCHESTRATOR_SCHEMA_VERSION;
	checkpoint->checkpoint_sequence =
		orchestrator->next_checkpoint_sequence;
	checkpoint->session_id =
		orchestrator->authorization.session_id;
	checkpoint->timestamp_ms = now_ms;
	checkpoint->step_id = step->definition.step_id;
	checkpoint->step_type = step->definition.type;
	checkpoint->step_state = state;
	checkpoint->attempt_count = step->attempt_count;
	checkpoint->result = result;
	memcpy(checkpoint->authorization_binding,
	       orchestrator->authorization.binding_digest,
	       sizeof(checkpoint->authorization_binding));
	memcpy(checkpoint->evidence_digest, evidence_digest,
	       sizeof(checkpoint->evidence_digest));
	memcpy(checkpoint->previous_digest,
	       orchestrator->evidence_chain_head,
	       sizeof(checkpoint->previous_digest));
	checkpoint->compensation = compensation;
	checkpoint->occupied = true;
	return checkpoint_digest(
		checkpoint, checkpoint->checkpoint_digest);
}

static int checkpoint_commit_locked(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	struct pqcp_fleet_recovery_step_runtime *step,
	const struct pqcp_fleet_recovery_checkpoint *checkpoint,
	uint64_t now_ms)
{
	if (orchestrator->checkpoint_count >=
	    orchestrator->checkpoint_capacity ||
	    checkpoint->checkpoint_sequence !=
		    orchestrator->next_checkpoint_sequence ||
	    !digest_equal(
		    checkpoint->previous_digest,
		    orchestrator->evidence_chain_head,
		    sizeof(checkpoint->previous_digest))) {
		return -ESTALE;
	}
	orchestrator->checkpoints[
		orchestrator->checkpoint_count++] = *checkpoint;
	orchestrator->next_checkpoint_sequence =
		saturating_increment_u64(
			checkpoint->checkpoint_sequence);
	memcpy(orchestrator->evidence_chain_head,
	       checkpoint->checkpoint_digest,
	       sizeof(orchestrator->evidence_chain_head));
	memcpy(step->checkpoint_digest,
	       checkpoint->checkpoint_digest,
	       sizeof(step->checkpoint_digest));
	return audit_append_locked(
		orchestrator,
		PQCP_FLEET_RECOVERY_AUDIT_CHECKPOINT,
		step->definition.step_id,
		(uint32_t)checkpoint->checkpoint_sequence,
		checkpoint->result, now_ms);
}

int pqcp_fleet_recovery_orchestrator_init(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	const struct pqcp_fleet_recovery_policy *policy,
	struct pqcp_fleet_recovery_manager *manager,
	const struct pqcp_fleet_recovery_executor *executor,
	struct pqcp_fleet_recovery_step_runtime *steps,
	size_t step_capacity,
	struct pqcp_fleet_recovery_checkpoint *checkpoints,
	size_t checkpoint_capacity,
	uint8_t *evidence_storage,
	size_t evidence_storage_bytes,
	size_t evidence_slot_bytes,
	struct pqcp_fleet_recovery_audit_entry *audit_entries,
	size_t audit_capacity)
{
	size_t required_evidence;
	int ret;

	if (orchestrator == NULL ||
	    policy_validate(policy) != 0 ||
	    manager == NULL || !manager->initialized ||
	    executor == NULL || steps == NULL ||
	    step_capacity == 0U ||
	    step_capacity > PQCP_FLEET_RECOVERY_MAX_STEPS ||
	    checkpoints == NULL ||
	    checkpoint_capacity < step_capacity ||
	    evidence_storage == NULL ||
	    evidence_slot_bytes == 0U ||
	    (audit_entries == NULL && audit_capacity != 0U) ||
	    (policy->require_checkpoint_persistence &&
	     executor->persist_checkpoint == NULL)) {
		return -EINVAL;
	}
	ret = size_multiply(
		step_capacity, evidence_slot_bytes,
		&required_evidence);
	if (ret != 0 ||
	    required_evidence > evidence_storage_bytes) {
		return ret != 0 ? ret : -ENOSPC;
	}
	memset(orchestrator, 0, sizeof(*orchestrator));
	memset(steps, 0, step_capacity * sizeof(*steps));
	memset(checkpoints, 0,
	       checkpoint_capacity * sizeof(*checkpoints));
	memset(evidence_storage, 0, required_evidence);
	if (audit_entries != NULL) {
		memset(audit_entries, 0,
		       audit_capacity * sizeof(*audit_entries));
	}
	for (size_t index = 0U; index < step_capacity; ++index) {
		steps[index].evidence =
			evidence_storage +
			index * evidence_slot_bytes;
		steps[index].evidence_capacity =
			evidence_slot_bytes;
	}
	orchestrator->schema_version =
		PQCP_FLEET_RECOVERY_ORCHESTRATOR_SCHEMA_VERSION;
	orchestrator->policy = *policy;
	orchestrator->manager = manager;
	orchestrator->executor = *executor;
	orchestrator->steps = steps;
	orchestrator->step_capacity = step_capacity;
	orchestrator->checkpoints = checkpoints;
	orchestrator->checkpoint_capacity =
		checkpoint_capacity;
	orchestrator->evidence_storage = evidence_storage;
	orchestrator->evidence_storage_bytes =
		evidence_storage_bytes;
	orchestrator->evidence_slot_bytes =
		evidence_slot_bytes;
	orchestrator->audit_entries = audit_entries;
	orchestrator->audit_capacity = audit_capacity;
	orchestrator->state =
		PQCP_FLEET_RECOVERY_ORCHESTRATOR_EMPTY;
	orchestrator->next_checkpoint_sequence = 1U;
	orchestrator->next_audit_sequence = 1U;
	orchestrator->active_step_index = UINT32_MAX;
	k_mutex_init(&orchestrator->lock);
	orchestrator->initialized = true;
	return 0;
}

static void normalize_definition(
	const struct pqcp_fleet_recovery_policy *policy,
	const struct pqcp_fleet_recovery_step_definition *input,
	struct pqcp_fleet_recovery_step_definition *output)
{
	*output = *input;
	if (output->maximum_attempts == 0U) {
		output->maximum_attempts =
			policy->maximum_playbook_attempts;
	}
	if (output->timeout_ms == 0U) {
		output->timeout_ms =
			policy->default_step_timeout_ms;
	}
	if (output->base_retry_ms == 0U) {
		output->base_retry_ms =
			policy->default_base_retry_ms;
	}
	if (output->maximum_retry_ms == 0U) {
		output->maximum_retry_ms =
			policy->default_maximum_retry_ms;
	}
}

int pqcp_fleet_recovery_playbook_load(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	uint64_t playbook_id,
	const struct pqcp_fleet_recovery_step_definition *steps,
	size_t step_count,
	uint64_t now_ms)
{
	struct pqcp_fleet_recovery_step_definition normalized[
		PQCP_FLEET_RECOVERY_MAX_STEPS];
	uint8_t playbook_digest[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    playbook_id == 0U || steps == NULL ||
	    step_count == 0U ||
	    step_count > orchestrator->step_capacity ||
	    step_count > PQCP_FLEET_RECOVERY_MAX_STEPS ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < step_count; ++index) {
		normalize_definition(
			&orchestrator->policy,
			&steps[index], &normalized[index]);
	}
	ret = definitions_validate(
		normalized, step_count,
		&orchestrator->executor,
		orchestrator->manager);
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			normalized, sizeof(normalized));
		return ret;
	}
	ret = pqcp_fleet_recovery_playbook_digest(
		normalized, step_count, playbook_id,
		playbook_digest);
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			normalized, sizeof(normalized));
		return ret;
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			normalized, sizeof(normalized));
		pqcp_runtime_secure_zero(
			playbook_digest, sizeof(playbook_digest));
		return ret;
	}
	if (orchestrator->executor_busy ||
	    orchestrator->state ==
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_RUNNING ||
	    orchestrator->state ==
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_PAUSED ||
	    orchestrator->state ==
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_COMPENSATING ||
	    orchestrator->state ==
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_VALIDATING ||
	    orchestrator->state ==
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_LOCKED) {
		(void)k_mutex_unlock(&orchestrator->lock);
		pqcp_runtime_secure_zero(
			normalized, sizeof(normalized));
		pqcp_runtime_secure_zero(
			playbook_digest, sizeof(playbook_digest));
		return -EBUSY;
	}
	for (size_t index = 0U;
	     index < orchestrator->step_capacity; ++index) {
		uint8_t *evidence =
			orchestrator->steps[index].evidence;
		size_t capacity =
			orchestrator->steps[index].evidence_capacity;

		if (evidence != NULL && capacity != 0U) {
			pqcp_runtime_secure_zero(evidence, capacity);
		}
		memset(&orchestrator->steps[index], 0,
		       sizeof(orchestrator->steps[index]));
		orchestrator->steps[index].evidence = evidence;
		orchestrator->steps[index].evidence_capacity =
			capacity;
	}
	memset(orchestrator->checkpoints, 0,
	       orchestrator->checkpoint_capacity *
		       sizeof(*orchestrator->checkpoints));
	for (size_t index = 0U; index < step_count; ++index) {
		orchestrator->steps[index].definition =
			normalized[index];
		orchestrator->steps[index].state =
			PQCP_FLEET_RECOVERY_STEP_PENDING;
		orchestrator->steps[index].occupied = true;
	}
	orchestrator->step_count = step_count;
	orchestrator->checkpoint_count = 0U;
	orchestrator->next_checkpoint_sequence = 1U;
	orchestrator->playbook_id = playbook_id;
	orchestrator->loaded_at_ms = now_ms;
	orchestrator->started_at_ms = 0U;
	orchestrator->completed_at_ms = 0U;
	orchestrator->completion_counter = 0U;
	orchestrator->authorized_step_mask = 0U;
	orchestrator->completed_step_mask = 0U;
	orchestrator->failed_step_mask = 0U;
	orchestrator->compensated_step_mask = 0U;
	orchestrator->playbook_attempts = 0U;
	orchestrator->terminal_result = 0;
	orchestrator->active_step_index = UINT32_MAX;
	orchestrator->pause_requested = false;
	orchestrator->abort_requested = false;
	memset(&orchestrator->authorization, 0,
	       sizeof(orchestrator->authorization));
	memset(orchestrator->evidence_chain_head, 0,
	       sizeof(orchestrator->evidence_chain_head));
	memcpy(orchestrator->playbook_digest, playbook_digest,
	       sizeof(orchestrator->playbook_digest));
	orchestrator->state =
		PQCP_FLEET_RECOVERY_ORCHESTRATOR_LOADED;
	ret = audit_append_locked(
		orchestrator,
		PQCP_FLEET_RECOVERY_AUDIT_PLAYBOOK_LOADED,
		0U, (uint32_t)step_count, 0, now_ms);
	(void)k_mutex_unlock(&orchestrator->lock);
	pqcp_runtime_secure_zero(
		normalized, sizeof(normalized));
	pqcp_runtime_secure_zero(
		playbook_digest, sizeof(playbook_digest));
	return ret;
}

static int authorization_binding_calculate(
	const struct pqcp_fleet_recovery_authorization *authorization,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	const uint8_t *parts[6];
	size_t lengths[6];
	uint8_t scalars[36];
	size_t offset = 0U;

	if (authorization == NULL || digest == NULL) {
		return -EINVAL;
	}
	pqcp_runtime_internal_write_u32(
		scalars + offset, authorization->schema_version);
	offset += 4U;
	pqcp_runtime_internal_write_u64(
		scalars + offset, authorization->session_id);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		scalars + offset, authorization->issued_at_ms);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		scalars + offset, authorization->expires_at_ms);
	offset += 8U;
	pqcp_runtime_internal_write_u32(
		scalars + offset, (uint32_t)authorization->reason);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		scalars + offset,
		authorization->authorized_step_mask);
	offset += 4U;
	parts[0] =
		(const uint8_t *)RECOVERY_AUTHORIZATION_LABEL;
	lengths[0] =
		sizeof(RECOVERY_AUTHORIZATION_LABEL) - 1U;
	parts[1] = scalars;
	lengths[1] = offset;
	parts[2] = authorization->challenge;
	lengths[2] = sizeof(authorization->challenge);
	parts[3] = authorization->authority_digest;
	lengths[3] = sizeof(authorization->authority_digest);
	parts[4] = authorization->scope_digest;
	lengths[4] = sizeof(authorization->scope_digest);
	parts[5] = authorization->playbook_digest;
	lengths[5] = sizeof(authorization->playbook_digest);
	int ret = pqcp_runtime_internal_sha256_parts(
		parts, lengths, 6U, digest);

	pqcp_runtime_secure_zero(scalars, sizeof(scalars));
	return ret;
}

static uint32_t all_step_mask(size_t step_count)
{
	return step_count == 32U ?
		UINT32_MAX :
		(UINT32_C(1) << step_count) - 1U;
}

static uint32_t required_step_index_mask(
	const struct pqcp_fleet_recovery_orchestrator *orchestrator)
{
	uint32_t mask = 0U;

	for (size_t index = 0U;
	     index < orchestrator->step_count; ++index) {
		if (orchestrator->steps[index].definition.required) {
			mask |= UINT32_C(1) << index;
		}
	}
	return mask;
}

static void enter_lockout_locked(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	int reason,
	uint64_t now_ms)
{
	orchestrator->state =
		PQCP_FLEET_RECOVERY_ORCHESTRATOR_LOCKED;
	orchestrator->lockout_until_ms =
		saturating_add_u64(
			now_ms, orchestrator->policy.lockout_ms);
	orchestrator->terminal_result =
		reason != 0 ? reason : -EACCES;
	(void)audit_append_locked(
		orchestrator,
		PQCP_FLEET_RECOVERY_AUDIT_LOCKED,
		0U, 0U, orchestrator->terminal_result, now_ms);
}

int pqcp_fleet_recovery_authorization_bind(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	const struct pqcp_fleet_recovery_authorization *authorization,
	uint64_t now_ms)
{
	uint8_t binding[PQCP_FLEET_DIGEST_BYTES];
	uint32_t required_mask;
	uint32_t valid_mask;
	int ret;
	int manager_ret;
	bool notify_lockout = false;
	uint64_t lockout_until = 0U;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    authorization == NULL ||
	    authorization->schema_version !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_SCHEMA_VERSION ||
	    authorization->session_id == 0U ||
	    authorization->issued_at_ms == 0U ||
	    authorization->issued_at_ms > now_ms ||
	    authorization->expires_at_ms <= now_ms ||
	    !reason_valid(authorization->reason) ||
	    digest_zero(
		    authorization->challenge,
		    sizeof(authorization->challenge)) ||
	    digest_zero(
		    authorization->authority_digest,
		    sizeof(authorization->authority_digest)) ||
	    digest_zero(
		    authorization->scope_digest,
		    sizeof(authorization->scope_digest)) ||
	    digest_zero(
		    authorization->playbook_digest,
		    sizeof(authorization->playbook_digest)) ||
	    digest_zero(
		    authorization->binding_digest,
		    sizeof(authorization->binding_digest)) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = authorization_binding_calculate(
		authorization, binding);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		pqcp_runtime_secure_zero(binding, sizeof(binding));
		return ret;
	}
	if (orchestrator->state ==
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_LOCKED &&
	    now_ms < orchestrator->lockout_until_ms) {
		(void)k_mutex_unlock(&orchestrator->lock);
		pqcp_runtime_secure_zero(binding, sizeof(binding));
		return -EACCES;
	}
	if (orchestrator->state !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_LOADED &&
	    orchestrator->state !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_AUTHORIZED) {
		(void)k_mutex_unlock(&orchestrator->lock);
		pqcp_runtime_secure_zero(binding, sizeof(binding));
		return -EBUSY;
	}
	valid_mask = all_step_mask(orchestrator->step_count);
	required_mask =
		required_step_index_mask(orchestrator);
	if (!digest_equal(
		    authorization->playbook_digest,
		    orchestrator->playbook_digest,
		    sizeof(orchestrator->playbook_digest)) ||
	    !digest_equal(
		    authorization->binding_digest, binding,
		    sizeof(binding)) ||
	    (authorization->authorized_step_mask &
	     ~valid_mask) != 0U ||
	    (authorization->authorized_step_mask &
	     required_mask) != required_mask ||
	    (orchestrator->policy.require_all_steps_authorized &&
	     authorization->authorized_step_mask != valid_mask)) {
		orchestrator->authorization_failures =
			saturating_increment_u32(
				orchestrator->authorization_failures);
		if (orchestrator->authorization_failures >=
		    orchestrator->policy.
			    maximum_authorization_failures) {
			enter_lockout_locked(
				orchestrator, -EKEYREJECTED, now_ms);
			notify_lockout = true;
			lockout_until =
				orchestrator->lockout_until_ms;
		}
		(void)k_mutex_unlock(&orchestrator->lock);
		if (notify_lockout &&
		    orchestrator->executor.notify_lockout != NULL) {
			(void)orchestrator->executor.notify_lockout(
				orchestrator->executor.context,
				authorization->session_id,
				lockout_until, -EKEYREJECTED);
		}
		pqcp_runtime_secure_zero(binding, sizeof(binding));
		return -EKEYREJECTED;
	}
	orchestrator->executor_busy = true;
	(void)k_mutex_unlock(&orchestrator->lock);
	manager_ret = pqcp_fleet_recovery_authorize(
		orchestrator->manager,
		authorization->session_id,
		authorization->reason,
		binding, now_ms,
		authorization->expires_at_ms);
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		pqcp_runtime_secure_zero(binding, sizeof(binding));
		return ret;
	}
	orchestrator->executor_busy = false;
	if (manager_ret != 0) {
		orchestrator->authorization_failures =
			saturating_increment_u32(
				orchestrator->authorization_failures);
		(void)k_mutex_unlock(&orchestrator->lock);
		pqcp_runtime_secure_zero(binding, sizeof(binding));
		return manager_ret;
	}
	orchestrator->authorization = *authorization;
	memcpy(orchestrator->authorization.binding_digest,
	       binding,
	       sizeof(orchestrator->authorization.binding_digest));
	orchestrator->authorized_step_mask =
		authorization->authorized_step_mask;
	orchestrator->state =
		PQCP_FLEET_RECOVERY_ORCHESTRATOR_AUTHORIZED;
	ret = audit_append_locked(
		orchestrator,
		PQCP_FLEET_RECOVERY_AUDIT_AUTHORIZED,
		0U, authorization->authorized_step_mask,
		0, now_ms);
	(void)k_mutex_unlock(&orchestrator->lock);
	pqcp_runtime_secure_zero(binding, sizeof(binding));
	return ret;
}

int pqcp_fleet_recovery_orchestrator_start(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	uint64_t now_ms)
{
	int ret;
	int manager_ret;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (orchestrator->state !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_AUTHORIZED ||
	    orchestrator->executor_busy) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return -EACCES;
	}
	if (now_ms >
	    orchestrator->authorization.expires_at_ms) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return -ETIMEDOUT;
	}
	if (orchestrator->playbook_attempts >=
	    orchestrator->policy.maximum_playbook_attempts) {
		enter_lockout_locked(
			orchestrator, -EDQUOT, now_ms);
		(void)k_mutex_unlock(&orchestrator->lock);
		return -EDQUOT;
	}
	orchestrator->executor_busy = true;
	(void)k_mutex_unlock(&orchestrator->lock);
	manager_ret = pqcp_fleet_recovery_enter(
		orchestrator->manager, now_ms);
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	orchestrator->executor_busy = false;
	if (manager_ret != 0) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return manager_ret;
	}
	orchestrator->playbook_attempts =
		saturating_increment_u32(
			orchestrator->playbook_attempts);
	orchestrator->started_at_ms = now_ms;
	orchestrator->state =
		PQCP_FLEET_RECOVERY_ORCHESTRATOR_RUNNING;
	ret = audit_append_locked(
		orchestrator,
		PQCP_FLEET_RECOVERY_AUDIT_STARTED,
		0U, orchestrator->playbook_attempts, 0, now_ms);
	(void)k_mutex_unlock(&orchestrator->lock);
	return ret;
}

static void progress_fill_locked(
	const struct pqcp_fleet_recovery_orchestrator *orchestrator,
	bool progressed,
	int result,
	struct pqcp_fleet_recovery_progress *progress)
{
	if (progress == NULL) {
		return;
	}
	memset(progress, 0, sizeof(*progress));
	progress->state = orchestrator->state;
	progress->total_steps = (uint32_t)orchestrator->step_count;
	progress->progressed = progressed;
	progress->result = result;
	progress->terminal =
		orchestrator->state ==
			PQCP_FLEET_RECOVERY_ORCHESTRATOR_COMPLETE ||
		orchestrator->state ==
			PQCP_FLEET_RECOVERY_ORCHESTRATOR_ABORTED ||
		orchestrator->state ==
			PQCP_FLEET_RECOVERY_ORCHESTRATOR_FAILED ||
		orchestrator->state ==
			PQCP_FLEET_RECOVERY_ORCHESTRATOR_LOCKED;
	if (orchestrator->active_step_index <
	    orchestrator->step_count) {
		progress->active_step_id =
			orchestrator->steps[
				orchestrator->active_step_index].
				definition.step_id;
	}
	for (size_t index = 0U;
	     index < orchestrator->step_count; ++index) {
		switch (orchestrator->steps[index].state) {
		case PQCP_FLEET_RECOVERY_STEP_SUCCEEDED:
			progress->succeeded_steps++;
			break;
		case PQCP_FLEET_RECOVERY_STEP_FAILED:
			progress->failed_steps++;
			break;
		case PQCP_FLEET_RECOVERY_STEP_COMPENSATED:
			progress->compensated_steps++;
			break;
		case PQCP_FLEET_RECOVERY_STEP_PENDING:
		case PQCP_FLEET_RECOVERY_STEP_READY:
		case PQCP_FLEET_RECOVERY_STEP_RUNNING:
		case PQCP_FLEET_RECOVERY_STEP_RETRY_WAIT:
		case PQCP_FLEET_RECOVERY_STEP_COMPENSATING:
			progress->pending_steps++;
			break;
		case PQCP_FLEET_RECOVERY_STEP_SKIPPED:
		default:
			break;
		}
	}
}

static int execute_step(
	const struct pqcp_fleet_recovery_executor *executor,
	const struct pqcp_fleet_recovery_step_definition *step,
	const uint8_t binding[PQCP_FLEET_RECOVERY_BINDING_BYTES],
	uint8_t *evidence,
	size_t evidence_capacity,
	size_t *evidence_length,
	uint64_t now_ms)
{
	switch (step->type) {
	case PQCP_FLEET_RECOVERY_STEP_TRUST_ANCHOR_RENEWAL:
		return executor->renew_trust_anchor(
			executor->context,
			&step->parameters.trust_anchor,
			binding, evidence, evidence_capacity,
			evidence_length, now_ms);
	case PQCP_FLEET_RECOVERY_STEP_REVOCATION_POLICY_SNAPSHOT:
		return executor->install_security_snapshot(
			executor->context,
			&step->parameters.security_snapshot,
			binding, evidence, evidence_capacity,
			evidence_length, now_ms);
	case PQCP_FLEET_RECOVERY_STEP_CREDENTIAL_REPLACEMENT:
		return executor->replace_credential(
			executor->context,
			&step->parameters.credential,
			binding, evidence, evidence_capacity,
			evidence_length, now_ms);
	case PQCP_FLEET_RECOVERY_STEP_UPDATE_ROLLBACK:
		return executor->rollback_update(
			executor->context,
			&step->parameters.update_rollback,
			binding, evidence, evidence_capacity,
			evidence_length, now_ms);
	case PQCP_FLEET_RECOVERY_STEP_SECURE_TIME_RESTORE:
		return executor->restore_secure_time(
			executor->context,
			&step->parameters.secure_time,
			binding, evidence, evidence_capacity,
			evidence_length, now_ms);
	case PQCP_FLEET_RECOVERY_STEP_SESSION_REOPEN:
		return executor->reopen_sessions(
			executor->context,
			&step->parameters.session,
			binding, evidence, evidence_capacity,
			evidence_length, now_ms);
	default:
		return -EINVAL;
	}
}

static bool dependencies_complete_locked(
	const struct pqcp_fleet_recovery_orchestrator *orchestrator,
	size_t index)
{
	return (orchestrator->steps[index].definition.dependency_mask &
		~orchestrator->completed_step_mask) == 0U;
}

static int ready_step_locked(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	uint64_t now_ms,
	size_t *selected)
{
	uint32_t best_priority = 0U;
	uint32_t best_step_id = UINT32_MAX;
	size_t best = SIZE_MAX;

	for (size_t index = 0U;
	     index < orchestrator->step_count; ++index) {
		struct pqcp_fleet_recovery_step_runtime *step =
			&orchestrator->steps[index];
		uint32_t bit = UINT32_C(1) << index;

		if ((orchestrator->authorized_step_mask & bit) == 0U) {
			if (step->state ==
			    PQCP_FLEET_RECOVERY_STEP_PENDING) {
				step->state =
					PQCP_FLEET_RECOVERY_STEP_SKIPPED;
			}
			continue;
		}
		if (step->state ==
			    PQCP_FLEET_RECOVERY_STEP_RETRY_WAIT &&
		    now_ms >= step->next_attempt_ms) {
			step->state =
				PQCP_FLEET_RECOVERY_STEP_PENDING;
		}
		if (step->state !=
			    PQCP_FLEET_RECOVERY_STEP_PENDING &&
		    step->state !=
			    PQCP_FLEET_RECOVERY_STEP_READY) {
			continue;
		}
		if (!dependencies_complete_locked(
			    orchestrator, index)) {
			continue;
		}
		if (step->state !=
		    PQCP_FLEET_RECOVERY_STEP_READY) {
			step->state =
				PQCP_FLEET_RECOVERY_STEP_READY;
			(void)audit_append_locked(
				orchestrator,
				PQCP_FLEET_RECOVERY_AUDIT_STEP_READY,
				step->definition.step_id,
				step->attempt_count, 0, now_ms);
		}
		if (best == SIZE_MAX ||
		    step->definition.priority > best_priority ||
		    (step->definition.priority == best_priority &&
		     step->definition.step_id < best_step_id)) {
			best = index;
			best_priority = step->definition.priority;
			best_step_id = step->definition.step_id;
		}
	}
	if (best == SIZE_MAX) {
		return -EAGAIN;
	}
	*selected = best;
	return 0;
}

static bool authorized_steps_complete_locked(
	const struct pqcp_fleet_recovery_orchestrator *orchestrator)
{
	for (size_t index = 0U;
	     index < orchestrator->step_count; ++index) {
		uint32_t bit = UINT32_C(1) << index;
		enum pqcp_fleet_recovery_step_state state =
			orchestrator->steps[index].state;

		if ((orchestrator->authorized_step_mask & bit) == 0U) {
			continue;
		}
		if (state != PQCP_FLEET_RECOVERY_STEP_SUCCEEDED &&
		    state != PQCP_FLEET_RECOVERY_STEP_SKIPPED) {
			return false;
		}
	}
	return true;
}

static int mark_step_failure_locked(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	size_t index,
	int result,
	uint64_t now_ms)
{
	struct pqcp_fleet_recovery_step_runtime *step =
		&orchestrator->steps[index];
	uint64_t delay;

	step->result = result != 0 ? result : -EIO;
	step->evidence_length = 0U;
	memset(step->evidence_digest, 0,
	       sizeof(step->evidence_digest));
	if (step->attempt_count <
	    step->definition.maximum_attempts) {
		delay = retry_delay(
			&step->definition, step->attempt_count);
		step->next_attempt_ms =
			saturating_add_u64(now_ms, delay);
		if (step->next_attempt_ms <=
		    orchestrator->authorization.expires_at_ms) {
			step->state =
				PQCP_FLEET_RECOVERY_STEP_RETRY_WAIT;
			orchestrator->active_step_index = UINT32_MAX;
			return audit_append_locked(
				orchestrator,
				PQCP_FLEET_RECOVERY_AUDIT_STEP_RETRY,
				step->definition.step_id,
				step->attempt_count,
				step->result, now_ms);
		}
	}
	step->state = PQCP_FLEET_RECOVERY_STEP_FAILED;
	step->completed_at_ms = now_ms;
	orchestrator->failed_step_mask |=
		UINT32_C(1) << index;
	orchestrator->terminal_failures =
		saturating_increment_u32(
			orchestrator->terminal_failures);
	orchestrator->terminal_result = step->result;
	orchestrator->active_step_index = UINT32_MAX;
	(void)audit_append_locked(
		orchestrator,
		PQCP_FLEET_RECOVERY_AUDIT_STEP_FAILED,
		step->definition.step_id,
		step->attempt_count, step->result, now_ms);
	if (orchestrator->terminal_failures >=
	    orchestrator->policy.lockout_after_failures) {
		enter_lockout_locked(
			orchestrator, step->result, now_ms);
		return step->result;
	}
	if (orchestrator->policy.auto_compensate) {
		orchestrator->state =
			PQCP_FLEET_RECOVERY_ORCHESTRATOR_COMPENSATING;
	} else {
		orchestrator->state =
			PQCP_FLEET_RECOVERY_ORCHESTRATOR_FAILED;
	}
	return step->result;
}

static int checkpoint_persist(
	const struct pqcp_fleet_recovery_orchestrator *orchestrator,
	const struct pqcp_fleet_recovery_checkpoint *checkpoint)
{
	if (orchestrator->executor.persist_checkpoint == NULL) {
		return orchestrator->policy.
				require_checkpoint_persistence ?
			-ENOSYS : 0;
	}
	return orchestrator->executor.persist_checkpoint(
		orchestrator->executor.context, checkpoint);
}

static int execute_forward_step(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	size_t index,
	uint64_t now_ms)
{
	struct pqcp_fleet_recovery_step_runtime *step;
	struct pqcp_fleet_recovery_step_definition definition;
	struct pqcp_fleet_recovery_checkpoint checkpoint;
	uint8_t binding[PQCP_FLEET_RECOVERY_BINDING_BYTES];
	uint8_t evidence_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t *evidence;
	size_t evidence_capacity;
	size_t evidence_length = 0U;
	int ret;
	int operation_ret;

	step = &orchestrator->steps[index];
	step->state = PQCP_FLEET_RECOVERY_STEP_RUNNING;
	step->started_at_ms = now_ms;
	step->completed_at_ms = 0U;
	step->next_attempt_ms = 0U;
	step->attempt_count =
		saturating_increment_u32(step->attempt_count);
	step->result = 0;
	step->evidence_length = 0U;
	memset(step->evidence_digest, 0,
	       sizeof(step->evidence_digest));
	definition = step->definition;
	evidence = step->evidence;
	evidence_capacity = step->evidence_capacity;
	memcpy(binding,
	       orchestrator->authorization.binding_digest,
	       sizeof(binding));
	orchestrator->active_step_index = (uint32_t)index;
	orchestrator->executor_busy = true;
	(void)audit_append_locked(
		orchestrator,
		PQCP_FLEET_RECOVERY_AUDIT_STEP_STARTED,
		step->definition.step_id,
		step->attempt_count, 0, now_ms);
	(void)k_mutex_unlock(&orchestrator->lock);

	operation_ret = execute_step(
		&orchestrator->executor, &definition, binding,
		evidence, evidence_capacity, &evidence_length,
		now_ms);
	if (operation_ret == 0 &&
	    (evidence_length == 0U ||
	     evidence_length > evidence_capacity)) {
		operation_ret = -EBADMSG;
	}
	if (operation_ret == 0 &&
	    orchestrator->executor.verify_evidence != NULL) {
		operation_ret =
			orchestrator->executor.verify_evidence(
				orchestrator->executor.context,
				&definition, evidence,
				evidence_length, now_ms);
	}
	if (operation_ret == 0) {
		operation_ret = pqcp_runtime_internal_sha256(
			evidence, evidence_length, evidence_digest);
	}

	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		pqcp_runtime_secure_zero(binding, sizeof(binding));
		pqcp_runtime_secure_zero(
			evidence_digest, sizeof(evidence_digest));
		return ret;
	}
	if (operation_ret != 0) {
		orchestrator->executor_busy = false;
		ret = mark_step_failure_locked(
			orchestrator, index, operation_ret, now_ms);
		(void)k_mutex_unlock(&orchestrator->lock);
		pqcp_runtime_secure_zero(binding, sizeof(binding));
		pqcp_runtime_secure_zero(
			evidence_digest, sizeof(evidence_digest));
		return ret;
	}
	step->evidence_length = evidence_length;
	memcpy(step->evidence_digest, evidence_digest,
	       sizeof(step->evidence_digest));
	ret = checkpoint_stage_locked(
		orchestrator, step,
		PQCP_FLEET_RECOVERY_STEP_SUCCEEDED,
		evidence_digest, false, 0, now_ms, &checkpoint);
	if (ret != 0) {
		orchestrator->executor_busy = false;
		ret = mark_step_failure_locked(
			orchestrator, index, ret, now_ms);
		(void)k_mutex_unlock(&orchestrator->lock);
		pqcp_runtime_secure_zero(binding, sizeof(binding));
		pqcp_runtime_secure_zero(
			evidence_digest, sizeof(evidence_digest));
		return ret;
	}
	(void)k_mutex_unlock(&orchestrator->lock);

	operation_ret = checkpoint_persist(
		orchestrator, &checkpoint);
	if (operation_ret == 0 &&
	    definition.manager_step_bit != 0U) {
		operation_ret = pqcp_fleet_recovery_step(
			orchestrator->manager,
			definition.manager_step_bit,
			evidence, evidence_length, now_ms);
	}

	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		pqcp_runtime_secure_zero(binding, sizeof(binding));
		pqcp_runtime_secure_zero(
			evidence_digest, sizeof(evidence_digest));
		pqcp_runtime_secure_zero(
			&checkpoint, sizeof(checkpoint));
		return ret;
	}
	orchestrator->executor_busy = false;
	if (operation_ret != 0) {
		ret = mark_step_failure_locked(
			orchestrator, index, operation_ret, now_ms);
		(void)k_mutex_unlock(&orchestrator->lock);
		pqcp_runtime_secure_zero(binding, sizeof(binding));
		pqcp_runtime_secure_zero(
			evidence_digest, sizeof(evidence_digest));
		pqcp_runtime_secure_zero(
			&checkpoint, sizeof(checkpoint));
		return ret;
	}
	ret = checkpoint_commit_locked(
		orchestrator, step, &checkpoint, now_ms);
	if (ret == 0) {
		step->state =
			PQCP_FLEET_RECOVERY_STEP_SUCCEEDED;
		step->completed_at_ms = now_ms;
		step->result = 0;
		step->completion_ordinal =
			saturating_increment_u64(
				orchestrator->completion_counter);
		orchestrator->completion_counter =
			step->completion_ordinal;
		orchestrator->completed_step_mask |=
			UINT32_C(1) << index;
		orchestrator->active_step_index = UINT32_MAX;
		ret = audit_append_locked(
			orchestrator,
			PQCP_FLEET_RECOVERY_AUDIT_STEP_SUCCEEDED,
			step->definition.step_id,
			step->attempt_count, 0, now_ms);
	} else {
		ret = mark_step_failure_locked(
			orchestrator, index, ret, now_ms);
	}
	(void)k_mutex_unlock(&orchestrator->lock);
	pqcp_runtime_secure_zero(binding, sizeof(binding));
	pqcp_runtime_secure_zero(
		evidence_digest, sizeof(evidence_digest));
	pqcp_runtime_secure_zero(&checkpoint, sizeof(checkpoint));
	return ret;
}

static const struct pqcp_fleet_recovery_checkpoint *
latest_forward_checkpoint_locked(
	const struct pqcp_fleet_recovery_orchestrator *orchestrator,
	uint32_t step_id)
{
	for (size_t cursor = orchestrator->checkpoint_count;
	     cursor > 0U; --cursor) {
		const struct pqcp_fleet_recovery_checkpoint *checkpoint =
			&orchestrator->checkpoints[cursor - 1U];

		if (checkpoint->occupied &&
		    !checkpoint->compensation &&
		    checkpoint->step_id == step_id) {
			return checkpoint;
		}
	}
	return NULL;
}

static int compensation_step_locked(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	size_t *selected)
{
	uint64_t best_ordinal = 0U;
	size_t best = SIZE_MAX;

	for (size_t index = 0U;
	     index < orchestrator->step_count; ++index) {
		const struct pqcp_fleet_recovery_step_runtime *step =
			&orchestrator->steps[index];
		uint32_t bit = UINT32_C(1) << index;

		if (step->state !=
			    PQCP_FLEET_RECOVERY_STEP_SUCCEEDED ||
		    (orchestrator->compensated_step_mask & bit) != 0U ||
		    step->definition.compensation ==
			    PQCP_FLEET_RECOVERY_COMPENSATE_NONE ||
		    (!step->definition.required &&
		     !orchestrator->policy.
			     compensate_optional_steps)) {
			continue;
		}
		if (step->completion_ordinal > best_ordinal) {
			best = index;
			best_ordinal = step->completion_ordinal;
		}
	}
	if (best == SIZE_MAX) {
		return -ENOENT;
	}
	*selected = best;
	return 0;
}

static int complete_abort(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	int reason,
	uint64_t now_ms)
{
	int manager_ret;
	int ret;

	orchestrator->executor_busy = true;
	(void)k_mutex_unlock(&orchestrator->lock);
	manager_ret = pqcp_fleet_recovery_abort(
		orchestrator->manager, now_ms,
		orchestrator->policy.completion_cooldown_ms);
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	orchestrator->executor_busy = false;
	if (manager_ret != 0 && manager_ret != -EALREADY) {
		orchestrator->state =
			PQCP_FLEET_RECOVERY_ORCHESTRATOR_FAILED;
		orchestrator->terminal_result = manager_ret;
		return manager_ret;
	}
	orchestrator->state =
		PQCP_FLEET_RECOVERY_ORCHESTRATOR_ABORTED;
	orchestrator->completed_at_ms = now_ms;
	orchestrator->terminal_result =
		reason != 0 ? reason : -ECANCELED;
	orchestrator->active_step_index = UINT32_MAX;
	return 0;
}

static int execute_compensation(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	size_t index,
	uint64_t now_ms)
{
	struct pqcp_fleet_recovery_step_runtime *step =
		&orchestrator->steps[index];
	const struct pqcp_fleet_recovery_checkpoint *source;
	struct pqcp_fleet_recovery_checkpoint source_copy;
	struct pqcp_fleet_recovery_checkpoint checkpoint;
	struct pqcp_fleet_recovery_step_definition definition;
	uint8_t binding[PQCP_FLEET_RECOVERY_BINDING_BYTES];
	uint8_t evidence_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t *evidence = step->evidence;
	size_t evidence_capacity = step->evidence_capacity;
	size_t evidence_length = 0U;
	int operation_ret;
	int ret;

	source = latest_forward_checkpoint_locked(
		orchestrator, step->definition.step_id);
	if (source == NULL ||
	    orchestrator->executor.compensate == NULL) {
		orchestrator->state =
			PQCP_FLEET_RECOVERY_ORCHESTRATOR_FAILED;
		orchestrator->terminal_result = -ENOSYS;
		return -ENOSYS;
	}
	source_copy = *source;
	definition = step->definition;
	memcpy(binding,
	       orchestrator->authorization.binding_digest,
	       sizeof(binding));
	step->state =
		PQCP_FLEET_RECOVERY_STEP_COMPENSATING;
	orchestrator->active_step_index = (uint32_t)index;
	orchestrator->executor_busy = true;
	(void)audit_append_locked(
		orchestrator,
		PQCP_FLEET_RECOVERY_AUDIT_COMPENSATION_STARTED,
		step->definition.step_id,
		(uint32_t)step->definition.compensation,
		0, now_ms);
	(void)k_mutex_unlock(&orchestrator->lock);

	operation_ret = orchestrator->executor.compensate(
		orchestrator->executor.context,
		definition.compensation, &definition,
		&source_copy, binding, evidence,
		evidence_capacity, &evidence_length, now_ms);
	if (operation_ret == 0 &&
	    (evidence_length == 0U ||
	     evidence_length > evidence_capacity)) {
		operation_ret = -EBADMSG;
	}
	if (operation_ret == 0 &&
	    orchestrator->executor.verify_evidence != NULL) {
		operation_ret =
			orchestrator->executor.verify_evidence(
				orchestrator->executor.context,
				&definition, evidence,
				evidence_length, now_ms);
	}
	if (operation_ret == 0) {
		operation_ret = pqcp_runtime_internal_sha256(
			evidence, evidence_length, evidence_digest);
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		goto out;
	}
	if (operation_ret != 0) {
		orchestrator->executor_busy = false;
		step->state = PQCP_FLEET_RECOVERY_STEP_FAILED;
		step->result = operation_ret;
		orchestrator->terminal_result = operation_ret;
		(void)audit_append_locked(
			orchestrator,
			PQCP_FLEET_RECOVERY_AUDIT_COMPENSATION_FAILED,
			step->definition.step_id,
			(uint32_t)step->definition.compensation,
			operation_ret, now_ms);
		if (orchestrator->policy.
		    lock_on_compensation_failure) {
			enter_lockout_locked(
				orchestrator, operation_ret, now_ms);
		} else {
			orchestrator->state =
				PQCP_FLEET_RECOVERY_ORCHESTRATOR_FAILED;
		}
		(void)k_mutex_unlock(&orchestrator->lock);
		ret = operation_ret;
		goto out;
	}
	ret = checkpoint_stage_locked(
		orchestrator, step,
		PQCP_FLEET_RECOVERY_STEP_COMPENSATED,
		evidence_digest, true, 0, now_ms, &checkpoint);
	if (ret != 0) {
		orchestrator->executor_busy = false;
		orchestrator->state =
			PQCP_FLEET_RECOVERY_ORCHESTRATOR_FAILED;
		orchestrator->terminal_result = ret;
		(void)k_mutex_unlock(&orchestrator->lock);
		goto out;
	}
	(void)k_mutex_unlock(&orchestrator->lock);
	operation_ret = checkpoint_persist(
		orchestrator, &checkpoint);
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		goto out;
	}
	orchestrator->executor_busy = false;
	if (operation_ret == 0) {
		operation_ret = checkpoint_commit_locked(
			orchestrator, step, &checkpoint, now_ms);
	}
	if (operation_ret != 0) {
		step->state = PQCP_FLEET_RECOVERY_STEP_FAILED;
		step->result = operation_ret;
		orchestrator->terminal_result = operation_ret;
		(void)audit_append_locked(
			orchestrator,
			PQCP_FLEET_RECOVERY_AUDIT_COMPENSATION_FAILED,
			step->definition.step_id,
			(uint32_t)step->definition.compensation,
			operation_ret, now_ms);
		if (orchestrator->policy.
		    lock_on_compensation_failure) {
			enter_lockout_locked(
				orchestrator, operation_ret, now_ms);
		} else {
			orchestrator->state =
				PQCP_FLEET_RECOVERY_ORCHESTRATOR_FAILED;
		}
		(void)k_mutex_unlock(&orchestrator->lock);
		ret = operation_ret;
		goto out;
	}
	step->state =
		PQCP_FLEET_RECOVERY_STEP_COMPENSATED;
	step->completed_at_ms = now_ms;
	step->evidence_length = evidence_length;
	step->result = 0;
	memcpy(step->evidence_digest, evidence_digest,
	       sizeof(step->evidence_digest));
	orchestrator->compensated_step_mask |=
		UINT32_C(1) << index;
	orchestrator->active_step_index = UINT32_MAX;
	ret = audit_append_locked(
		orchestrator,
		PQCP_FLEET_RECOVERY_AUDIT_COMPENSATION_SUCCEEDED,
		step->definition.step_id,
		(uint32_t)step->definition.compensation,
		0, now_ms);
	(void)k_mutex_unlock(&orchestrator->lock);
out:
	pqcp_runtime_secure_zero(binding, sizeof(binding));
	pqcp_runtime_secure_zero(
		evidence_digest, sizeof(evidence_digest));
	pqcp_runtime_secure_zero(&source_copy, sizeof(source_copy));
	pqcp_runtime_secure_zero(&checkpoint, sizeof(checkpoint));
	return ret;
}

int pqcp_fleet_recovery_orchestrator_advance(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	uint64_t now_ms,
	struct pqcp_fleet_recovery_progress *progress)
{
	size_t selected;
	int ret;
	int manager_ret;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    now_ms == 0U || progress == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (orchestrator->executor_busy) {
		progress_fill_locked(
			orchestrator, false, -EBUSY, progress);
		(void)k_mutex_unlock(&orchestrator->lock);
		return -EBUSY;
	}
	if (orchestrator->state ==
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_PAUSED) {
		progress_fill_locked(
			orchestrator, false, -EAGAIN, progress);
		(void)k_mutex_unlock(&orchestrator->lock);
		return -EAGAIN;
	}
	if (orchestrator->state !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_RUNNING &&
	    orchestrator->state !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_COMPENSATING) {
		progress_fill_locked(
			orchestrator, false,
			orchestrator->terminal_result, progress);
		(void)k_mutex_unlock(&orchestrator->lock);
		return progress->terminal ? 0 : -EACCES;
	}
	if (orchestrator->state ==
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_RUNNING &&
	    now_ms > orchestrator->authorization.expires_at_ms) {
		orchestrator->abort_requested = true;
		orchestrator->terminal_result = -ETIMEDOUT;
		orchestrator->state =
			orchestrator->policy.auto_compensate ?
				PQCP_FLEET_RECOVERY_ORCHESTRATOR_COMPENSATING :
				PQCP_FLEET_RECOVERY_ORCHESTRATOR_FAILED;
	}
	if (orchestrator->state ==
	    PQCP_FLEET_RECOVERY_ORCHESTRATOR_COMPENSATING) {
		ret = compensation_step_locked(
			orchestrator, &selected);
		if (ret == -ENOENT) {
			ret = complete_abort(
				orchestrator,
				orchestrator->terminal_result,
				now_ms);
			progress_fill_locked(
				orchestrator, true, ret, progress);
			(void)k_mutex_unlock(&orchestrator->lock);
			return ret;
		}
		if (ret != 0) {
			progress_fill_locked(
				orchestrator, false, ret, progress);
			(void)k_mutex_unlock(&orchestrator->lock);
			return ret;
		}
		ret = execute_compensation(
			orchestrator, selected, now_ms);
		if (k_mutex_lock(
			    &orchestrator->lock, K_FOREVER) != 0) {
			return ret;
		}
		progress_fill_locked(
			orchestrator, ret == 0, ret, progress);
		(void)k_mutex_unlock(&orchestrator->lock);
		return ret;
	}
	if (orchestrator->abort_requested) {
		orchestrator->state =
			orchestrator->policy.auto_compensate ?
				PQCP_FLEET_RECOVERY_ORCHESTRATOR_COMPENSATING :
				PQCP_FLEET_RECOVERY_ORCHESTRATOR_FAILED;
		progress_fill_locked(
			orchestrator, true,
			orchestrator->terminal_result, progress);
		(void)k_mutex_unlock(&orchestrator->lock);
		return 0;
	}
	if (authorized_steps_complete_locked(orchestrator)) {
		orchestrator->executor_busy = true;
		(void)k_mutex_unlock(&orchestrator->lock);
		manager_ret = pqcp_fleet_recovery_validate(
			orchestrator->manager, now_ms);
		ret = k_mutex_lock(
			&orchestrator->lock, K_FOREVER);
		if (ret != 0) {
			return ret;
		}
		orchestrator->executor_busy = false;
		if (manager_ret == 0) {
			orchestrator->state =
				PQCP_FLEET_RECOVERY_ORCHESTRATOR_VALIDATING;
			(void)audit_append_locked(
				orchestrator,
				PQCP_FLEET_RECOVERY_AUDIT_VALIDATED,
				0U, orchestrator->completed_step_mask,
				0, now_ms);
		} else {
			orchestrator->terminal_result = manager_ret;
		}
		progress_fill_locked(
			orchestrator, manager_ret == 0,
			manager_ret, progress);
		(void)k_mutex_unlock(&orchestrator->lock);
		return manager_ret;
	}
	ret = ready_step_locked(
		orchestrator, now_ms, &selected);
	if (ret != 0) {
		progress_fill_locked(
			orchestrator, false, ret, progress);
		(void)k_mutex_unlock(&orchestrator->lock);
		return ret;
	}
	ret = execute_forward_step(
		orchestrator, selected, now_ms);
	if (k_mutex_lock(
		    &orchestrator->lock, K_FOREVER) != 0) {
		return ret;
	}
	progress_fill_locked(
		orchestrator, ret == 0, ret, progress);
	(void)k_mutex_unlock(&orchestrator->lock);
	return ret;
}

int pqcp_fleet_recovery_orchestrator_pause(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	uint64_t now_ms)
{
	int ret;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (orchestrator->state !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_RUNNING ||
	    orchestrator->executor_busy) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return -EBUSY;
	}
	orchestrator->pause_requested = true;
	orchestrator->state =
		PQCP_FLEET_RECOVERY_ORCHESTRATOR_PAUSED;
	ret = audit_append_locked(
		orchestrator,
		PQCP_FLEET_RECOVERY_AUDIT_PAUSED,
		0U, 0U, 0, now_ms);
	(void)k_mutex_unlock(&orchestrator->lock);
	return ret;
}

int pqcp_fleet_recovery_orchestrator_resume(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	uint64_t now_ms)
{
	int ret;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (orchestrator->state !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_PAUSED ||
	    orchestrator->executor_busy) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return -EACCES;
	}
	if (now_ms > orchestrator->authorization.expires_at_ms) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return -ETIMEDOUT;
	}
	orchestrator->pause_requested = false;
	orchestrator->state =
		PQCP_FLEET_RECOVERY_ORCHESTRATOR_RUNNING;
	ret = audit_append_locked(
		orchestrator,
		PQCP_FLEET_RECOVERY_AUDIT_RESUMED,
		0U, 0U, 0, now_ms);
	(void)k_mutex_unlock(&orchestrator->lock);
	return ret;
}

int pqcp_fleet_recovery_orchestrator_abort(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	int reason,
	uint64_t now_ms)
{
	int ret;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    reason == 0 || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if ((orchestrator->state !=
		     PQCP_FLEET_RECOVERY_ORCHESTRATOR_RUNNING &&
	     orchestrator->state !=
		     PQCP_FLEET_RECOVERY_ORCHESTRATOR_PAUSED &&
	     orchestrator->state !=
		     PQCP_FLEET_RECOVERY_ORCHESTRATOR_VALIDATING) ||
	    orchestrator->executor_busy) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return -EACCES;
	}
	orchestrator->abort_requested = true;
	orchestrator->terminal_result = reason;
	(void)audit_append_locked(
		orchestrator,
		PQCP_FLEET_RECOVERY_AUDIT_ABORT_REQUESTED,
		0U, 0U, reason, now_ms);
	if (orchestrator->policy.auto_compensate &&
	    orchestrator->completed_step_mask != 0U) {
		orchestrator->state =
			PQCP_FLEET_RECOVERY_ORCHESTRATOR_COMPENSATING;
		ret = 0;
	} else {
		ret = complete_abort(
			orchestrator, reason, now_ms);
	}
	(void)k_mutex_unlock(&orchestrator->lock);
	return ret;
}

int pqcp_fleet_recovery_orchestrator_finish(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	uint64_t now_ms)
{
	int ret;
	int manager_ret;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (orchestrator->state !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_VALIDATING ||
	    orchestrator->executor_busy) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return -EACCES;
	}
	orchestrator->executor_busy = true;
	(void)k_mutex_unlock(&orchestrator->lock);
	manager_ret = pqcp_fleet_recovery_complete(
		orchestrator->manager, now_ms,
		orchestrator->policy.completion_cooldown_ms);
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	orchestrator->executor_busy = false;
	if (manager_ret == 0) {
		orchestrator->state =
			PQCP_FLEET_RECOVERY_ORCHESTRATOR_COMPLETE;
		orchestrator->completed_at_ms = now_ms;
		orchestrator->terminal_result = 0;
		ret = audit_append_locked(
			orchestrator,
			PQCP_FLEET_RECOVERY_AUDIT_COMPLETED,
			0U, orchestrator->completed_step_mask,
			0, now_ms);
	} else {
		ret = manager_ret;
	}
	(void)k_mutex_unlock(&orchestrator->lock);
	return ret;
}

int pqcp_fleet_recovery_orchestrator_unlock(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	const uint8_t authority_digest[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms)
{
	int ret;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    authority_digest == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (orchestrator->state !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_LOCKED ||
	    now_ms < orchestrator->lockout_until_ms ||
	    !digest_equal(
		    authority_digest,
		    orchestrator->authorization.authority_digest,
		    PQCP_FLEET_DIGEST_BYTES)) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return -EACCES;
	}
	orchestrator->state =
		orchestrator->step_count != 0U ?
			PQCP_FLEET_RECOVERY_ORCHESTRATOR_LOADED :
			PQCP_FLEET_RECOVERY_ORCHESTRATOR_EMPTY;
	orchestrator->lockout_until_ms = 0U;
	orchestrator->authorization_failures = 0U;
	orchestrator->terminal_failures = 0U;
	orchestrator->terminal_result = 0;
	ret = audit_append_locked(
		orchestrator,
		PQCP_FLEET_RECOVERY_AUDIT_RESTORED,
		0U, 0U, 0, now_ms);
	(void)k_mutex_unlock(&orchestrator->lock);
	return ret;
}

static int step_index_by_id_locked(
	const struct pqcp_fleet_recovery_orchestrator *orchestrator,
	uint32_t step_id,
	size_t *index)
{
	for (size_t cursor = 0U;
	     cursor < orchestrator->step_count; ++cursor) {
		if (orchestrator->steps[cursor].
		    definition.step_id == step_id) {
			*index = cursor;
			return 0;
		}
	}
	return -ENOENT;
}

static int checkpoint_series_validate_locked(
	const struct pqcp_fleet_recovery_orchestrator *orchestrator,
	const struct pqcp_fleet_recovery_checkpoint *checkpoints,
	size_t checkpoint_count)
{
	uint8_t previous[PQCP_FLEET_DIGEST_BYTES] = { 0 };
	uint32_t succeeded_mask = 0U;
	uint32_t compensated_mask = 0U;

	for (size_t cursor = 0U;
	     cursor < checkpoint_count; ++cursor) {
		const struct pqcp_fleet_recovery_checkpoint *checkpoint =
			&checkpoints[cursor];
		uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
		size_t index;
		uint32_t bit;
		int ret;

		if (!checkpoint->occupied ||
		    checkpoint->checkpoint_sequence != cursor + 1U ||
		    checkpoint->session_id !=
			    orchestrator->authorization.session_id ||
		    !digest_equal(
			    checkpoint->authorization_binding,
			    orchestrator->authorization.binding_digest,
			    sizeof(checkpoint->authorization_binding)) ||
		    !digest_equal(
			    checkpoint->previous_digest, previous,
			    sizeof(previous))) {
			return -EBADMSG;
		}
		ret = step_index_by_id_locked(
			orchestrator, checkpoint->step_id, &index);
		if (ret != 0 ||
		    checkpoint->step_type !=
			    orchestrator->steps[index].definition.type) {
			return -EBADMSG;
		}
		bit = UINT32_C(1) << index;
		if (!checkpoint->compensation) {
			if (checkpoint->step_state !=
				    PQCP_FLEET_RECOVERY_STEP_SUCCEEDED ||
			    (succeeded_mask & bit) != 0U ||
			    (orchestrator->steps[index].
			     definition.dependency_mask &
			     ~succeeded_mask) != 0U) {
				return -EBADMSG;
			}
			succeeded_mask |= bit;
		} else {
			if (checkpoint->step_state !=
				    PQCP_FLEET_RECOVERY_STEP_COMPENSATED ||
			    (succeeded_mask & bit) == 0U ||
			    (compensated_mask & bit) != 0U ||
			    orchestrator->steps[index].
				    definition.compensation ==
				    PQCP_FLEET_RECOVERY_COMPENSATE_NONE) {
				return -EBADMSG;
			}
			compensated_mask |= bit;
		}
		ret = checkpoint_digest(checkpoint, digest);
		if (ret != 0 ||
		    !digest_equal(
			    digest, checkpoint->checkpoint_digest,
			    sizeof(digest))) {
			pqcp_runtime_secure_zero(
				digest, sizeof(digest));
			return ret != 0 ? ret : -EBADMSG;
		}
		memcpy(previous, checkpoint->checkpoint_digest,
		       sizeof(previous));
		pqcp_runtime_secure_zero(digest, sizeof(digest));
	}
	pqcp_runtime_secure_zero(previous, sizeof(previous));
	return 0;
}

int pqcp_fleet_recovery_checkpoint_import(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	const struct pqcp_fleet_recovery_checkpoint *checkpoints,
	size_t checkpoint_count,
	uint64_t now_ms)
{
	int ret;
	int manager_ret = 0;
	uint32_t manager_replayed = 0U;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    checkpoints == NULL || checkpoint_count == 0U ||
	    checkpoint_count > orchestrator->checkpoint_capacity ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (orchestrator->state !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_AUTHORIZED ||
	    orchestrator->executor_busy ||
	    orchestrator->checkpoint_count != 0U ||
	    now_ms > orchestrator->authorization.expires_at_ms) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return -EBUSY;
	}
	ret = checkpoint_series_validate_locked(
		orchestrator, checkpoints, checkpoint_count);
	if (ret != 0) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return ret;
	}
	orchestrator->executor_busy = true;
	(void)k_mutex_unlock(&orchestrator->lock);

	manager_ret = pqcp_fleet_recovery_enter(
		orchestrator->manager, now_ms);
	for (size_t cursor = 0U;
	     manager_ret == 0 && cursor < checkpoint_count;
	     ++cursor) {
		const struct pqcp_fleet_recovery_checkpoint *checkpoint =
			&checkpoints[cursor];
		size_t index;
		uint32_t manager_bit;

		if (checkpoint->compensation) {
			continue;
		}
		ret = k_mutex_lock(
			&orchestrator->lock, K_FOREVER);
		if (ret != 0) {
			return ret;
		}
		ret = step_index_by_id_locked(
			orchestrator, checkpoint->step_id, &index);
		manager_bit = ret == 0 ?
			orchestrator->steps[index].
				definition.manager_step_bit : 0U;
		(void)k_mutex_unlock(&orchestrator->lock);
		if (ret != 0) {
			manager_ret = ret;
			break;
		}
		if (manager_bit != 0U &&
		    (manager_replayed & manager_bit) == 0U) {
			manager_ret = pqcp_fleet_recovery_step(
				orchestrator->manager, manager_bit,
				checkpoint->evidence_digest,
				sizeof(checkpoint->evidence_digest),
				now_ms);
			if (manager_ret == 0) {
				manager_replayed |= manager_bit;
			}
		}
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	orchestrator->executor_busy = false;
	if (manager_ret != 0) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return manager_ret;
	}
	memcpy(orchestrator->checkpoints, checkpoints,
	       checkpoint_count * sizeof(*checkpoints));
	orchestrator->checkpoint_count = checkpoint_count;
	orchestrator->next_checkpoint_sequence =
		saturating_increment_u64(
			checkpoints[checkpoint_count - 1U].
				checkpoint_sequence);
	memcpy(orchestrator->evidence_chain_head,
	       checkpoints[checkpoint_count - 1U].
		       checkpoint_digest,
	       sizeof(orchestrator->evidence_chain_head));
	orchestrator->completion_counter = 0U;
	orchestrator->completed_step_mask = 0U;
	orchestrator->compensated_step_mask = 0U;
	for (size_t index = 0U;
	     index < orchestrator->step_count; ++index) {
		struct pqcp_fleet_recovery_step_runtime *step =
			&orchestrator->steps[index];

		step->state =
			PQCP_FLEET_RECOVERY_STEP_PENDING;
		step->attempt_count = 0U;
		step->result = 0;
		step->started_at_ms = 0U;
		step->completed_at_ms = 0U;
		step->next_attempt_ms = 0U;
		step->completion_ordinal = 0U;
		step->evidence_length = 0U;
		step->restored = false;
		memset(step->evidence_digest, 0,
		       sizeof(step->evidence_digest));
		memset(step->checkpoint_digest, 0,
		       sizeof(step->checkpoint_digest));
	}
	for (size_t cursor = 0U;
	     cursor < checkpoint_count; ++cursor) {
		const struct pqcp_fleet_recovery_checkpoint *checkpoint =
			&checkpoints[cursor];
		struct pqcp_fleet_recovery_step_runtime *step;
		size_t index;
		uint32_t bit;

		ret = step_index_by_id_locked(
			orchestrator, checkpoint->step_id, &index);
		if (ret != 0) {
			(void)k_mutex_unlock(&orchestrator->lock);
			return -EBADMSG;
		}
		step = &orchestrator->steps[index];
		bit = UINT32_C(1) << index;
		step->state = checkpoint->step_state;
		step->attempt_count = checkpoint->attempt_count;
		step->result = checkpoint->result;
		step->completed_at_ms = checkpoint->timestamp_ms;
		step->restored = true;
		memcpy(step->evidence_digest,
		       checkpoint->evidence_digest,
		       sizeof(step->evidence_digest));
		memcpy(step->checkpoint_digest,
		       checkpoint->checkpoint_digest,
		       sizeof(step->checkpoint_digest));
		if (!checkpoint->compensation) {
			step->completion_ordinal =
				saturating_increment_u64(
					orchestrator->
						completion_counter);
			orchestrator->completion_counter =
				step->completion_ordinal;
			orchestrator->completed_step_mask |= bit;
		} else {
			orchestrator->compensated_step_mask |= bit;
		}
	}
	orchestrator->playbook_attempts =
		saturating_increment_u32(
			orchestrator->playbook_attempts);
	orchestrator->started_at_ms = now_ms;
	orchestrator->state =
		orchestrator->compensated_step_mask != 0U ?
			PQCP_FLEET_RECOVERY_ORCHESTRATOR_COMPENSATING :
			PQCP_FLEET_RECOVERY_ORCHESTRATOR_RUNNING;
	ret = audit_append_locked(
		orchestrator,
		PQCP_FLEET_RECOVERY_AUDIT_RESTORED,
		0U, (uint32_t)checkpoint_count, 0, now_ms);
	(void)k_mutex_unlock(&orchestrator->lock);
	return ret;
}

static size_t step_result_body(
	const struct pqcp_fleet_recovery_step_result *result,
	uint8_t output[RECOVERY_STEP_RESULT_BYTES])
{
	size_t offset = 0U;

	memset(output, 0, RECOVERY_STEP_RESULT_BYTES);
	offset = append_u32(output, offset, result->step_id);
	offset = append_u32(
		output, offset, (uint32_t)result->type);
	offset = append_u32(
		output, offset, (uint32_t)result->state);
	offset = append_u32(
		output, offset, result->attempt_count);
	offset = append_i32(output, offset, result->result);
	offset = append_digest(
		output, offset, result->evidence_digest);
	offset = append_digest(
		output, offset, result->checkpoint_digest);
	return offset;
}

static size_t recovery_snapshot_body(
	const struct pqcp_fleet_recovery_snapshot *snapshot,
	uint8_t output[RECOVERY_SNAPSHOT_BODY_BYTES])
{
	size_t offset = 0U;

	if (snapshot == NULL || output == NULL ||
	    snapshot->schema_version !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_SCHEMA_VERSION ||
	    snapshot->captured_at_ms == 0U ||
	    !orchestrator_state_valid(snapshot->state) ||
	    snapshot->step_count >
		    PQCP_FLEET_RECOVERY_MAX_STEPS) {
		return 0U;
	}
	memset(output, 0, RECOVERY_SNAPSHOT_BODY_BYTES);
	memcpy(output + offset, RECOVERY_SNAPSHOT_LABEL,
	       sizeof(RECOVERY_SNAPSHOT_LABEL) - 1U);
	offset += sizeof(RECOVERY_SNAPSHOT_LABEL) - 1U;
	offset = append_u32(
		output, offset, snapshot->schema_version);
	offset = append_u64(
		output, offset, snapshot->captured_at_ms);
	offset = append_u64(
		output, offset, snapshot->session_id);
	offset = append_u32(
		output, offset, (uint32_t)snapshot->state);
	offset = append_u32(
		output, offset, (uint32_t)snapshot->reason);
	offset = append_u32(
		output, offset, snapshot->authorized_step_mask);
	offset = append_u32(
		output, offset, snapshot->completed_step_mask);
	offset = append_u32(
		output, offset, snapshot->failed_step_mask);
	offset = append_u32(
		output, offset, snapshot->compensated_step_mask);
	offset = append_u32(
		output, offset, snapshot->playbook_attempts);
	offset = append_u32(
		output, offset, snapshot->authorization_failures);
	offset = append_u32(
		output, offset, snapshot->terminal_failures);
	offset = append_u64(
		output, offset, snapshot->lockout_until_ms);
	offset = append_u64(
		output, offset, snapshot->checkpoint_count);
	offset = append_u64(
		output, offset, snapshot->audit_count);
	offset = append_u64(
		output, offset, snapshot->step_count);
	offset = append_digest(
		output, offset, snapshot->playbook_digest);
	offset = append_digest(
		output, offset, snapshot->authorization_binding);
	offset = append_digest(
		output, offset, snapshot->evidence_chain_head);
	offset = append_digest(
		output, offset, snapshot->audit_chain_head);
	return offset <= RECOVERY_SNAPSHOT_BODY_BYTES ?
		offset : 0U;
}

static int recovery_snapshot_digest(
	const struct pqcp_fleet_recovery_snapshot *snapshot,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	const uint8_t *parts[
		PQCP_FLEET_RECOVERY_MAX_STEPS + 1U];
	size_t lengths[
		PQCP_FLEET_RECOVERY_MAX_STEPS + 1U];
	uint8_t body[RECOVERY_SNAPSHOT_BODY_BYTES];
	uint8_t step_bodies[PQCP_FLEET_RECOVERY_MAX_STEPS]
		[RECOVERY_STEP_RESULT_BYTES];
	size_t length;
	int ret;

	if (snapshot == NULL || digest == NULL ||
	    snapshot->step_count >
		    PQCP_FLEET_RECOVERY_MAX_STEPS ||
	    (snapshot->step_count != 0U &&
	     snapshot->steps == NULL)) {
		return -EINVAL;
	}
	length = recovery_snapshot_body(snapshot, body);
	if (length == 0U) {
		return -EINVAL;
	}
	parts[0] = body;
	lengths[0] = length;
	for (size_t index = 0U;
	     index < snapshot->step_count; ++index) {
		length = step_result_body(
			&snapshot->steps[index],
			step_bodies[index]);
		parts[index + 1U] = step_bodies[index];
		lengths[index + 1U] = length;
	}
	ret = pqcp_runtime_internal_sha256_parts(
		parts, lengths, snapshot->step_count + 1U,
		digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	pqcp_runtime_secure_zero(
		step_bodies, sizeof(step_bodies));
	return ret;
}

int pqcp_fleet_recovery_snapshot(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	uint64_t now_ms,
	struct pqcp_fleet_recovery_snapshot *snapshot)
{
	struct pqcp_fleet_recovery_step_result *steps;
	size_t step_capacity;
	int ret;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    now_ms == 0U || snapshot == NULL ||
	    snapshot->steps == NULL) {
		return -EINVAL;
	}
	steps = snapshot->steps;
	step_capacity = snapshot->step_capacity;
	if (step_capacity < orchestrator->step_count ||
	    step_capacity >
		    PQCP_FLEET_RECOVERY_MAX_STEPS) {
		return -ENOSPC;
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->steps = steps;
	snapshot->step_capacity = step_capacity;
	snapshot->schema_version =
		PQCP_FLEET_RECOVERY_ORCHESTRATOR_SCHEMA_VERSION;
	snapshot->captured_at_ms = now_ms;
	snapshot->session_id =
		orchestrator->authorization.session_id;
	snapshot->state = orchestrator->state;
	snapshot->reason = orchestrator->authorization.reason;
	snapshot->authorized_step_mask =
		orchestrator->authorized_step_mask;
	snapshot->completed_step_mask =
		orchestrator->completed_step_mask;
	snapshot->failed_step_mask =
		orchestrator->failed_step_mask;
	snapshot->compensated_step_mask =
		orchestrator->compensated_step_mask;
	snapshot->playbook_attempts =
		orchestrator->playbook_attempts;
	snapshot->authorization_failures =
		orchestrator->authorization_failures;
	snapshot->terminal_failures =
		orchestrator->terminal_failures;
	snapshot->lockout_until_ms =
		orchestrator->lockout_until_ms;
	snapshot->checkpoint_count =
		orchestrator->checkpoint_count;
	snapshot->audit_count = orchestrator->audit_count;
	snapshot->step_count = orchestrator->step_count;
	memcpy(snapshot->playbook_digest,
	       orchestrator->playbook_digest,
	       sizeof(snapshot->playbook_digest));
	memcpy(snapshot->authorization_binding,
	       orchestrator->authorization.binding_digest,
	       sizeof(snapshot->authorization_binding));
	memcpy(snapshot->evidence_chain_head,
	       orchestrator->evidence_chain_head,
	       sizeof(snapshot->evidence_chain_head));
	memcpy(snapshot->audit_chain_head,
	       orchestrator->audit_chain_head,
	       sizeof(snapshot->audit_chain_head));
	for (size_t index = 0U;
	     index < orchestrator->step_count; ++index) {
		const struct pqcp_fleet_recovery_step_runtime *step =
			&orchestrator->steps[index];
		struct pqcp_fleet_recovery_step_result *result =
			&snapshot->steps[index];

		memset(result, 0, sizeof(*result));
		result->step_id = step->definition.step_id;
		result->type = step->definition.type;
		result->state = step->state;
		result->attempt_count = step->attempt_count;
		result->result = step->result;
		memcpy(result->evidence_digest,
		       step->evidence_digest,
		       sizeof(result->evidence_digest));
		memcpy(result->checkpoint_digest,
		       step->checkpoint_digest,
		       sizeof(result->checkpoint_digest));
	}
	(void)k_mutex_unlock(&orchestrator->lock);
	return recovery_snapshot_digest(
		snapshot, snapshot->snapshot_digest);
}

int pqcp_fleet_recovery_snapshot_verify(
	const struct pqcp_fleet_recovery_snapshot *snapshot)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	uint32_t valid_mask;
	int ret;

	if (snapshot == NULL ||
	    snapshot->schema_version !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_SCHEMA_VERSION ||
	    snapshot->captured_at_ms == 0U ||
	    !orchestrator_state_valid(snapshot->state) ||
	    snapshot->step_count == 0U ||
	    snapshot->step_count > snapshot->step_capacity ||
	    snapshot->step_count >
		    PQCP_FLEET_RECOVERY_MAX_STEPS ||
	    snapshot->steps == NULL ||
	    digest_zero(
		    snapshot->playbook_digest,
		    sizeof(snapshot->playbook_digest)) ||
	    digest_zero(
		    snapshot->snapshot_digest,
		    sizeof(snapshot->snapshot_digest))) {
		return -EINVAL;
	}
	valid_mask = all_step_mask(snapshot->step_count);
	if ((snapshot->authorized_step_mask & ~valid_mask) != 0U ||
	    (snapshot->completed_step_mask & ~valid_mask) != 0U ||
	    (snapshot->failed_step_mask & ~valid_mask) != 0U ||
	    (snapshot->compensated_step_mask & ~valid_mask) != 0U ||
	    (snapshot->failed_step_mask &
	     snapshot->completed_step_mask) != 0U ||
	    (snapshot->compensated_step_mask &
	     ~snapshot->completed_step_mask) != 0U) {
		return -EBADMSG;
	}
	for (size_t left = 0U;
	     left < snapshot->step_count; ++left) {
		const struct pqcp_fleet_recovery_step_result *step =
			&snapshot->steps[left];

		if (step->step_id == 0U ||
		    !step_type_valid(step->type) ||
		    !step_state_valid(step->state)) {
			return -EBADMSG;
		}
		for (size_t right = left + 1U;
		     right < snapshot->step_count; ++right) {
			if (snapshot->steps[right].step_id ==
			    step->step_id) {
				return -EEXIST;
			}
		}
	}
	ret = recovery_snapshot_digest(snapshot, digest);
	if (ret == 0 &&
	    !digest_equal(
		    digest, snapshot->snapshot_digest,
		    sizeof(digest))) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

static int audit_entries_validate_locked(
	const struct pqcp_fleet_recovery_orchestrator *orchestrator)
{
	uint64_t highest_sequence = 0U;
	const struct pqcp_fleet_recovery_audit_entry *latest = NULL;

	for (size_t index = 0U;
	     index < orchestrator->audit_capacity; ++index) {
		const struct pqcp_fleet_recovery_audit_entry *entry =
			&orchestrator->audit_entries[index];
		uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
		int ret;

		if (!entry->occupied) {
			continue;
		}
		ret = audit_digest(entry, digest);
		if (ret != 0 ||
		    !digest_equal(
			    digest, entry->entry_digest,
			    sizeof(digest))) {
			pqcp_runtime_secure_zero(
				digest, sizeof(digest));
			return ret != 0 ? ret : -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < orchestrator->audit_capacity; ++other) {
			if (orchestrator->audit_entries[other].occupied &&
			    orchestrator->audit_entries[other].sequence ==
				    entry->sequence) {
				pqcp_runtime_secure_zero(
					digest, sizeof(digest));
				return -EEXIST;
			}
		}
		if (entry->sequence > highest_sequence) {
			highest_sequence = entry->sequence;
			latest = entry;
		}
		pqcp_runtime_secure_zero(digest, sizeof(digest));
	}
	if (orchestrator->audit_count != 0U &&
	    (latest == NULL ||
	     !digest_equal(
		     latest->entry_digest,
		     orchestrator->audit_chain_head,
		     sizeof(latest->entry_digest)))) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_fleet_recovery_orchestrator_audit(
	struct pqcp_fleet_recovery_orchestrator *orchestrator)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	uint32_t valid_mask;
	int ret;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    orchestrator->schema_version !=
		    PQCP_FLEET_RECOVERY_ORCHESTRATOR_SCHEMA_VERSION ||
	    policy_validate(&orchestrator->policy) != 0 ||
	    orchestrator->manager == NULL ||
	    orchestrator->steps == NULL ||
	    orchestrator->step_capacity == 0U ||
	    orchestrator->step_count >
		    orchestrator->step_capacity ||
	    orchestrator->checkpoints == NULL ||
	    orchestrator->checkpoint_count >
		    orchestrator->checkpoint_capacity ||
	    !orchestrator_state_valid(orchestrator->state)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	valid_mask = all_step_mask(orchestrator->step_count);
	if ((orchestrator->authorized_step_mask & ~valid_mask) != 0U ||
	    (orchestrator->completed_step_mask & ~valid_mask) != 0U ||
	    (orchestrator->failed_step_mask & ~valid_mask) != 0U ||
	    (orchestrator->compensated_step_mask & ~valid_mask) != 0U ||
	    (orchestrator->failed_step_mask &
	     orchestrator->completed_step_mask) != 0U ||
	    (orchestrator->compensated_step_mask &
	     ~orchestrator->completed_step_mask) != 0U ||
	    (orchestrator->active_step_index != UINT32_MAX &&
	     orchestrator->active_step_index >=
		     orchestrator->step_count)) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return -EBADMSG;
	}
	if (orchestrator->step_count != 0U) {
		struct pqcp_fleet_recovery_step_definition
			definitions[PQCP_FLEET_RECOVERY_MAX_STEPS];

		ret = 0;
		for (size_t index = 0U;
		     index < orchestrator->step_count; ++index) {
			if (!orchestrator->steps[index].occupied) {
				ret = -EBADMSG;
				break;
			}
			definitions[index] =
				orchestrator->steps[index].definition;
		}
		if (ret == 0) {
			ret = definitions_validate(
				definitions, orchestrator->step_count,
				&orchestrator->executor,
				orchestrator->manager);
		}
		if (ret == 0) {
			ret = pqcp_fleet_recovery_playbook_digest(
				definitions,
				orchestrator->step_count,
				orchestrator->playbook_id, digest);
		}
		pqcp_runtime_secure_zero(
			definitions, sizeof(definitions));
		if (ret != 0 ||
		    !digest_equal(
			    digest, orchestrator->playbook_digest,
			    sizeof(digest))) {
			pqcp_runtime_secure_zero(
				digest, sizeof(digest));
			(void)k_mutex_unlock(&orchestrator->lock);
			return ret != 0 ? ret : -EBADMSG;
		}
	}
	ret = checkpoint_series_validate_locked(
		orchestrator, orchestrator->checkpoints,
		orchestrator->checkpoint_count);
	if (ret == 0 && orchestrator->checkpoint_count != 0U &&
	    !digest_equal(
		    orchestrator->checkpoints[
			    orchestrator->checkpoint_count - 1U].
			    checkpoint_digest,
		    orchestrator->evidence_chain_head,
		    sizeof(orchestrator->evidence_chain_head))) {
		ret = -EBADMSG;
	}
	if (ret == 0 && orchestrator->audit_entries != NULL) {
		ret = audit_entries_validate_locked(orchestrator);
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	(void)k_mutex_unlock(&orchestrator->lock);
	if (ret != 0) {
		return ret;
	}
	return pqcp_fleet_recovery_audit(orchestrator->manager);
}

int pqcp_fleet_recovery_orchestrator_reset(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	bool retain_playbook,
	uint64_t now_ms)
{
	int ret;
	int manager_ret = 0;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (orchestrator->executor_busy) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return -EBUSY;
	}
	orchestrator->executor_busy = true;
	(void)k_mutex_unlock(&orchestrator->lock);
	manager_ret = pqcp_fleet_recovery_abort(
		orchestrator->manager, now_ms,
		orchestrator->policy.completion_cooldown_ms);
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	orchestrator->executor_busy = false;
	if (manager_ret != 0 && manager_ret != -EALREADY) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return manager_ret;
	}
	for (size_t index = 0U;
	     index < orchestrator->step_capacity; ++index) {
		struct pqcp_fleet_recovery_step_runtime *step =
			&orchestrator->steps[index];
		struct pqcp_fleet_recovery_step_definition definition =
			step->definition;
		uint8_t *evidence = step->evidence;
		size_t evidence_capacity = step->evidence_capacity;
		bool occupied =
			retain_playbook && index <
				orchestrator->step_count;

		if (evidence != NULL && evidence_capacity != 0U) {
			pqcp_runtime_secure_zero(
				evidence, evidence_capacity);
		}
		memset(step, 0, sizeof(*step));
		step->evidence = evidence;
		step->evidence_capacity = evidence_capacity;
		if (occupied) {
			step->definition = definition;
			step->state =
				PQCP_FLEET_RECOVERY_STEP_PENDING;
			step->occupied = true;
		}
		pqcp_runtime_secure_zero(
			&definition, sizeof(definition));
	}
	memset(orchestrator->checkpoints, 0,
	       orchestrator->checkpoint_capacity *
		       sizeof(*orchestrator->checkpoints));
	if (orchestrator->audit_entries != NULL) {
		memset(orchestrator->audit_entries, 0,
		       orchestrator->audit_capacity *
			       sizeof(*orchestrator->audit_entries));
	}
	memset(&orchestrator->authorization, 0,
	       sizeof(orchestrator->authorization));
	memset(orchestrator->evidence_chain_head, 0,
	       sizeof(orchestrator->evidence_chain_head));
	memset(orchestrator->audit_chain_head, 0,
	       sizeof(orchestrator->audit_chain_head));
	orchestrator->checkpoint_count = 0U;
	orchestrator->audit_count = 0U;
	orchestrator->audit_next = 0U;
	orchestrator->next_checkpoint_sequence = 1U;
	orchestrator->next_audit_sequence = 1U;
	orchestrator->started_at_ms = 0U;
	orchestrator->completed_at_ms = 0U;
	orchestrator->completion_counter = 0U;
	orchestrator->lockout_until_ms = 0U;
	orchestrator->authorized_step_mask = 0U;
	orchestrator->completed_step_mask = 0U;
	orchestrator->failed_step_mask = 0U;
	orchestrator->compensated_step_mask = 0U;
	orchestrator->playbook_attempts = 0U;
	orchestrator->authorization_failures = 0U;
	orchestrator->terminal_failures = 0U;
	orchestrator->active_step_index = UINT32_MAX;
	orchestrator->terminal_result = 0;
	orchestrator->pause_requested = false;
	orchestrator->abort_requested = false;
	if (retain_playbook && orchestrator->step_count != 0U) {
		orchestrator->state =
			PQCP_FLEET_RECOVERY_ORCHESTRATOR_LOADED;
		orchestrator->loaded_at_ms = now_ms;
		ret = audit_append_locked(
			orchestrator,
			PQCP_FLEET_RECOVERY_AUDIT_PLAYBOOK_LOADED,
			0U, (uint32_t)orchestrator->step_count,
			0, now_ms);
	} else {
		orchestrator->state =
			PQCP_FLEET_RECOVERY_ORCHESTRATOR_EMPTY;
		orchestrator->step_count = 0U;
		orchestrator->playbook_id = 0U;
		orchestrator->loaded_at_ms = 0U;
		memset(orchestrator->playbook_digest, 0,
		       sizeof(orchestrator->playbook_digest));
		ret = 0;
	}
	(void)k_mutex_unlock(&orchestrator->lock);
	return ret;
}
