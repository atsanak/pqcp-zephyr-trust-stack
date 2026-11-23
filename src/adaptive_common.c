/*
 * SPDX-License-Identifier: MIT
 *
 * Shared primitives for the firmware-native adaptive PQC control plane.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/adaptive_control.h>

#include "adaptive_internal.h"

#define PQCP_ADAPTIVE_DOMAIN_EVENT UINT64_C(0x4144504556454e54)
#define PQCP_ADAPTIVE_DOMAIN_REGISTRY UINT64_C(0x4144505245474953)
#define PQCP_ADAPTIVE_DOMAIN_CONTROL UINT64_C(0x414450434f4e5452)

static bool ascii_alpha(char value)
{
	return (value >= 'a' && value <= 'z') ||
	       (value >= 'A' && value <= 'Z');
}

static bool ascii_digit(char value)
{
	return value >= '0' && value <= '9';
}

static bool id_character(char value)
{
	return ascii_alpha(value) || ascii_digit(value) ||
	       value == '-' || value == '_' || value == '.';
}

bool pqcp_adaptive_internal_id_valid(const char *value)
{
	size_t length;

	if (value == NULL || value[0] == '\0') {
		return false;
	}
	length = strnlen(value, PQCP_ADAPTIVE_ID_MAX_CHARS);
	if (length == 0U || length >= PQCP_ADAPTIVE_ID_MAX_CHARS) {
		return false;
	}
	if (!ascii_alpha(value[0]) && !ascii_digit(value[0])) {
		return false;
	}
	if (!ascii_alpha(value[length - 1U]) &&
	    !ascii_digit(value[length - 1U])) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		if (!id_character(value[index])) {
			return false;
		}
		if (index != 0U && value[index] == '.' &&
		    value[index - 1U] == '.') {
			return false;
		}
	}
	return true;
}

void pqcp_adaptive_internal_set_text(
	char *destination, size_t capacity, const char *source)
{
	size_t length;

	if (destination == NULL || capacity == 0U) {
		return;
	}
	destination[0] = '\0';
	if (source == NULL) {
		return;
	}
	length = strnlen(source, capacity);
	if (length >= capacity) {
		length = capacity - 1U;
	}
	if (length != 0U) {
		memcpy(destination, source, length);
	}
	destination[length] = '\0';
}

uint32_t pqcp_adaptive_internal_clamp_u32(
	uint32_t value, uint32_t minimum, uint32_t maximum)
{
	if (minimum > maximum) {
		const uint32_t temporary = minimum;

		minimum = maximum;
		maximum = temporary;
	}
	if (value < minimum) {
		return minimum;
	}
	if (value > maximum) {
		return maximum;
	}
	return value;
}

uint64_t pqcp_adaptive_internal_clamp_u64(
	uint64_t value, uint64_t minimum, uint64_t maximum)
{
	if (minimum > maximum) {
		const uint64_t temporary = minimum;

		minimum = maximum;
		maximum = temporary;
	}
	if (value < minimum) {
		return minimum;
	}
	if (value > maximum) {
		return maximum;
	}
	return value;
}

uint32_t pqcp_adaptive_internal_percent(
	uint64_t numerator, uint64_t denominator)
{
	uint64_t quotient;
	uint64_t remainder;
	uint64_t scaled;

	if (denominator == 0U) {
		return numerator == 0U ? 0U : 100U;
	}
	quotient = numerator / denominator;
	remainder = numerator % denominator;
	if (quotient >= 1U) {
		return 100U;
	}
	scaled = remainder > UINT64_MAX / 100U ?
			 UINT64_MAX : remainder * 100U;
	return (uint32_t)pqcp_adaptive_internal_clamp_u64(
		scaled / denominator, 0U, 100U);
}

uint32_t pqcp_adaptive_internal_permille(
	uint64_t numerator, uint64_t denominator)
{
	uint64_t quotient;
	uint64_t remainder;
	uint64_t scaled;

	if (denominator == 0U) {
		return numerator == 0U ? 0U : 1000U;
	}
	quotient = numerator / denominator;
	remainder = numerator % denominator;
	if (quotient >= 1U) {
		return 1000U;
	}
	scaled = remainder > UINT64_MAX / 1000U ?
			 UINT64_MAX : remainder * 1000U;
	return (uint32_t)pqcp_adaptive_internal_clamp_u64(
		scaled / denominator, 0U, 1000U);
}

uint32_t pqcp_adaptive_internal_bit_count(uint32_t value)
{
	uint32_t count = 0U;

	while (value != 0U) {
		value &= value - 1U;
		count++;
	}
	return count;
}

uint64_t pqcp_adaptive_internal_saturating_add_u64(
	uint64_t left, uint64_t right)
{
	if (left > UINT64_MAX - right) {
		return UINT64_MAX;
	}
	return left + right;
}

uint64_t pqcp_adaptive_internal_saturating_mul_u64(
	uint64_t left, uint64_t right)
{
	if (left == 0U || right == 0U) {
		return 0U;
	}
	if (left > UINT64_MAX / right) {
		return UINT64_MAX;
	}
	return left * right;
}

uint64_t pqcp_adaptive_internal_abs_i64(int64_t value)
{
	if (value >= 0) {
		return (uint64_t)value;
	}
	if (value == INT64_MIN) {
		return (uint64_t)INT64_MAX + 1U;
	}
	return (uint64_t)-value;
}

bool pqcp_adaptive_internal_status_valid(enum pqcp_adaptive_status status)
{
	return status >= PQCP_ADAPTIVE_STATUS_FAIL &&
	       status <= PQCP_ADAPTIVE_STATUS_PASS;
}

bool pqcp_adaptive_internal_pressure_valid(
	enum pqcp_adaptive_pressure pressure)
{
	return pressure >= PQCP_ADAPTIVE_PRESSURE_NONE &&
	       pressure <= PQCP_ADAPTIVE_PRESSURE_CRITICAL;
}

bool pqcp_adaptive_internal_threat_valid(
	enum pqcp_adaptive_threat_level level)
{
	return level >= PQCP_ADAPTIVE_THREAT_NOMINAL &&
	       level <= PQCP_ADAPTIVE_THREAT_CRITICAL;
}

static bool profile_kind_valid(enum pqcp_deployment_candidate_kind kind)
{
	return kind >= PQCP_DEPLOYMENT_CANDIDATE_MLKEM &&
	       kind <= PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE;
}

static bool mlkem_level_valid(uint32_t level)
{
	return level == 0U || level == 512U ||
	       level == 768U || level == 1024U;
}

static bool mldsa_level_valid(uint32_t level)
{
	return level == 0U || level == 44U ||
	       level == 65U || level == 87U;
}

static bool kind_levels_valid(const struct pqcp_adaptive_profile *profile)
{
	switch (profile->kind) {
	case PQCP_DEPLOYMENT_CANDIDATE_MLKEM:
		return profile->mlkem_level != 0U &&
		       profile->mldsa_level == 0U;
	case PQCP_DEPLOYMENT_CANDIDATE_MLDSA:
		return profile->mlkem_level == 0U &&
		       profile->mldsa_level != 0U;
	case PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE:
		return profile->mlkem_level != 0U &&
		       profile->mldsa_level != 0U;
	default:
		return false;
	}
}

static bool kind_operations_valid(
	const struct pqcp_adaptive_profile *profile)
{
	const uint32_t kem_operations =
		PQCP_DEPLOYMENT_OPERATION_MASK_KEM |
		PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS |
		PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING |
		PQCP_DEPLOYMENT_OPERATION_MASK_RECONNECT |
		PQCP_DEPLOYMENT_OPERATION_MASK_TELEMETRY;
	const uint32_t signature_operations =
		PQCP_DEPLOYMENT_OPERATION_MASK_SIGNATURE |
		PQCP_DEPLOYMENT_OPERATION_MASK_FIRMWARE_UPDATE |
		PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING;

	switch (profile->kind) {
	case PQCP_DEPLOYMENT_CANDIDATE_MLKEM:
		return (profile->operation_mask & kem_operations) != 0U &&
		       (profile->operation_mask &
			PQCP_DEPLOYMENT_OPERATION_MASK_SIGNATURE) == 0U;
	case PQCP_DEPLOYMENT_CANDIDATE_MLDSA:
		return (profile->operation_mask & signature_operations) != 0U &&
		       (profile->operation_mask &
			PQCP_DEPLOYMENT_OPERATION_MASK_KEM) == 0U;
	case PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE:
		return (profile->operation_mask &
			PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS) != 0U ||
		       (profile->operation_mask &
			PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING) != 0U;
	default:
		return false;
	}
}

bool pqcp_adaptive_internal_profile_valid(
	const struct pqcp_adaptive_profile *profile)
{
	if (profile == NULL ||
	    profile->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    !pqcp_adaptive_internal_id_valid(profile->profile_id) ||
	    !profile_kind_valid(profile->kind) ||
	    profile->operation_mask == 0U ||
	    (profile->operation_mask &
	     ~PQCP_DEPLOYMENT_OPERATION_MASK_KNOWN) != 0U ||
	    profile->security_level == 0U ||
	    profile->security_level > 5U ||
	    !mlkem_level_valid(profile->mlkem_level) ||
	    !mldsa_level_valid(profile->mldsa_level) ||
	    !kind_levels_valid(profile) ||
	    !kind_operations_valid(profile) ||
	    profile->nominal_latency_us == 0U ||
	    profile->ram_bytes == 0U ||
	    profile->stack_bytes == 0U ||
	    profile->flash_bytes == 0U ||
	    profile->latency_source < PQCP_ADAPTIVE_METRIC_UNKNOWN ||
	    profile->latency_source > PQCP_ADAPTIVE_METRIC_CALIBRATED ||
	    profile->cycles_source < PQCP_ADAPTIVE_METRIC_UNKNOWN ||
	    profile->cycles_source > PQCP_ADAPTIVE_METRIC_CALIBRATED ||
	    profile->memory_source < PQCP_ADAPTIVE_METRIC_UNKNOWN ||
	    profile->memory_source > PQCP_ADAPTIVE_METRIC_CALIBRATED ||
	    profile->energy_source < PQCP_ADAPTIVE_METRIC_UNKNOWN ||
	    profile->energy_source > PQCP_ADAPTIVE_METRIC_CALIBRATED ||
	    (profile->evidence_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_KNOWN_MASK) != 0U ||
	    profile->priority > PQCP_ADAPTIVE_SCORE_MAX) {
		return false;
	}
	if (profile->production_allowed &&
	    (!profile->native_provider || !profile->enabled)) {
		return false;
	}
	if (profile->hardware_validated &&
	    (profile->evidence_mask &
	     PQCP_DEPLOYMENT_EVIDENCE_HARDWARE) == 0U) {
		return false;
	}
	if (profile->native_provider &&
	    (profile->evidence_mask &
	     PQCP_DEPLOYMENT_EVIDENCE_PROVIDER) == 0U) {
		return false;
	}
	return true;
}

bool pqcp_adaptive_internal_policy_valid(
	const struct pqcp_adaptive_policy *policy)
{
	uint64_t total_weight;

	if (policy == NULL ||
	    policy->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    policy->profile < PQCP_ADAPTIVE_POLICY_SENSOR ||
	    policy->profile > PQCP_ADAPTIVE_POLICY_RESEARCH ||
	    policy->default_mode < PQCP_ADAPTIVE_MODE_SAFE ||
	    policy->default_mode > PQCP_ADAPTIVE_MODE_LOCKDOWN ||
	    policy->minimum_security_level == 0U ||
	    policy->minimum_security_level > 5U ||
	    (policy->required_evidence_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_KNOWN_MASK) != 0U ||
	    policy->minimum_confidence > PQCP_ADAPTIVE_SCORE_MAX ||
	    policy->minimum_improvement_score > PQCP_ADAPTIVE_SCORE_MAX ||
	    policy->transition_confirmations == 0U ||
	    policy->transition_confirmations > 32U ||
	    policy->fleet_quorum_percent > 100U ||
	    policy->risk_penalty > PQCP_ADAPTIVE_SCORE_MAX ||
	    policy->missing_evidence_penalty > PQCP_ADAPTIVE_SCORE_MAX) {
		return false;
	}
	total_weight = (uint64_t)policy->weight_security +
		       policy->weight_latency +
		       policy->weight_memory +
		       policy->weight_energy +
		       policy->weight_evidence +
		       policy->weight_stability;
	if (total_weight == 0U || total_weight > 100000U) {
		return false;
	}
	if (policy->require_hardware_evidence &&
	    (policy->required_evidence_mask &
	     PQCP_DEPLOYMENT_EVIDENCE_HARDWARE) == 0U) {
		return false;
	}
	return true;
}

uint32_t pqcp_adaptive_internal_operation_for_session(
	enum pqcp_adaptive_session_kind kind)
{
	switch (kind) {
	case PQCP_ADAPTIVE_SESSION_KEM:
		return PQCP_DEPLOYMENT_OPERATION_MASK_KEM;
	case PQCP_ADAPTIVE_SESSION_SIGNATURE:
		return PQCP_DEPLOYMENT_OPERATION_MASK_SIGNATURE;
	case PQCP_ADAPTIVE_SESSION_HYBRID_TLS:
		return PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS;
	case PQCP_ADAPTIVE_SESSION_ONBOARDING:
		return PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING;
	case PQCP_ADAPTIVE_SESSION_RECONNECT:
		return PQCP_DEPLOYMENT_OPERATION_MASK_RECONNECT;
	case PQCP_ADAPTIVE_SESSION_FIRMWARE_UPDATE:
		return PQCP_DEPLOYMENT_OPERATION_MASK_FIRMWARE_UPDATE;
	case PQCP_ADAPTIVE_SESSION_TELEMETRY:
		return PQCP_DEPLOYMENT_OPERATION_MASK_TELEMETRY;
	default:
		return 0U;
	}
}

uint32_t pqcp_adaptive_internal_profile_security_strength(
	const struct pqcp_adaptive_profile *profile)
{
	uint32_t level;

	if (!pqcp_adaptive_internal_profile_valid(profile)) {
		return 0U;
	}
	level = profile->security_level * 100U;
	if (profile->kind == PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE) {
		level += 40U;
	}
	if (profile->hybrid_required) {
		level += 20U;
	}
	if (profile->hardware_validated) {
		level += 10U;
	}
	if (profile->production_allowed) {
		level += 5U;
	}
	return level;
}

int pqcp_adaptive_internal_compare_profile_ids(
	const struct pqcp_adaptive_profile *left,
	const struct pqcp_adaptive_profile *right)
{
	if (left == NULL && right == NULL) {
		return 0;
	}
	if (left == NULL) {
		return 1;
	}
	if (right == NULL) {
		return -1;
	}
	return strcmp(left->profile_id, right->profile_id);
}

int pqcp_adaptive_internal_digest_profile(
	const struct pqcp_adaptive_profile *profile,
	struct pqcp_deployment_evidence_digest *digest)
{
	if (!pqcp_adaptive_internal_profile_valid(profile) || digest == NULL) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_update_u32(
		digest, profile->schema_version);
	pqcp_deployment_evidence_digest_update_text(
		digest, profile->profile_id);
	pqcp_deployment_evidence_digest_update_u32(
		digest, (uint32_t)profile->kind);
	pqcp_deployment_evidence_digest_update_u32(
		digest, profile->operation_mask);
	pqcp_deployment_evidence_digest_update_u32(
		digest, profile->security_level);
	pqcp_deployment_evidence_digest_update_u32(
		digest, profile->mlkem_level);
	pqcp_deployment_evidence_digest_update_u32(
		digest, profile->mldsa_level);
	pqcp_deployment_evidence_digest_update_u64(
		digest, profile->nominal_latency_us);
	pqcp_deployment_evidence_digest_update_u64(
		digest, profile->nominal_cycles);
	pqcp_deployment_evidence_digest_update_u64(
		digest, profile->ram_bytes);
	pqcp_deployment_evidence_digest_update_u64(
		digest, profile->stack_bytes);
	pqcp_deployment_evidence_digest_update_u64(
		digest, profile->heap_bytes);
	pqcp_deployment_evidence_digest_update_u64(
		digest, profile->flash_bytes);
	pqcp_deployment_evidence_digest_update_u64(
		digest, profile->energy_uj);
	pqcp_deployment_evidence_digest_update_u32(
		digest, (uint32_t)profile->latency_source);
	pqcp_deployment_evidence_digest_update_u32(
		digest, (uint32_t)profile->cycles_source);
	pqcp_deployment_evidence_digest_update_u32(
		digest, (uint32_t)profile->memory_source);
	pqcp_deployment_evidence_digest_update_u32(
		digest, (uint32_t)profile->energy_source);
	pqcp_deployment_evidence_digest_update_u32(
		digest, profile->observation_count);
	pqcp_deployment_evidence_digest_update_u32(
		digest, profile->evidence_mask);
	pqcp_deployment_evidence_digest_update_u32(
		digest, profile->priority);
	pqcp_deployment_evidence_digest_update_bool(
		digest, profile->enabled);
	pqcp_deployment_evidence_digest_update_bool(
		digest, profile->native_provider);
	pqcp_deployment_evidence_digest_update_bool(
		digest, profile->production_allowed);
	pqcp_deployment_evidence_digest_update_bool(
		digest, profile->hardware_validated);
	pqcp_deployment_evidence_digest_update_bool(
		digest, profile->hybrid_required);
	return 0;
}

int pqcp_adaptive_internal_digest_registry(
	const struct pqcp_adaptive_profile_registry *registry,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	if (registry == NULL || output == NULL ||
	    registry->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    registry->count > PQCP_ADAPTIVE_MAX_PROFILES) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_DOMAIN_REGISTRY);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, registry->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, registry->count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, registry->enabled_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, registry->native_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, registry->production_count);
	for (uint32_t index = 0U; index < registry->count; ++index) {
		if (pqcp_adaptive_internal_digest_profile(
			    &registry->profiles[index], &digest) != 0) {
			return -EINVAL;
		}
	}
	return pqcp_deployment_evidence_digest_final_hex(&digest, output);
}

int pqcp_adaptive_internal_digest_event(
	const struct pqcp_adaptive_event *event,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	if (event == NULL || output == NULL ||
	    event->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    !pqcp_adaptive_internal_status_valid(event->status) ||
	    !pqcp_adaptive_internal_id_valid(event->profile_id) ||
	    !pqcp_adaptive_internal_id_valid(event->related_id)) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_DOMAIN_EVENT);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, event->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, event->sequence);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)event->type);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)event->status);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, event->timestamp_ms);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, event->reason_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, event->blocker_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, event->warning_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, event->score);
	pqcp_deployment_evidence_digest_update_text(
		&digest, event->profile_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, event->related_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, event->previous_digest_hex);
	return pqcp_deployment_evidence_digest_final_hex(&digest, output);
}

static int digest_control_profile(
	const struct pqcp_adaptive_control_plane *control,
	struct pqcp_deployment_evidence_digest *digest)
{
	const char *active;

	active = control->transition.current_profile_id;
	if (!pqcp_adaptive_internal_id_valid(active)) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_update_text(digest, active);
	pqcp_deployment_evidence_digest_update_u32(
		digest, (uint32_t)control->transition.state);
	pqcp_deployment_evidence_digest_update_u32(
		digest, control->transition.transition_count);
	pqcp_deployment_evidence_digest_update_u32(
		digest, control->transition.rejected_count);
	return 0;
}

int pqcp_adaptive_internal_digest_control(
	const struct pqcp_adaptive_control_plane *control,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	if (control == NULL || output == NULL ||
	    control->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    !pqcp_adaptive_internal_id_valid(control->device_id) ||
	    !pqcp_adaptive_internal_policy_valid(&control->policy) ||
	    !pqcp_adaptive_internal_id_valid(
		    control->transition.current_profile_id)) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_DOMAIN_CONTROL);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, control->schema_version);
	pqcp_deployment_evidence_digest_update_text(
		&digest, control->device_id);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)control->mode);
	pqcp_deployment_evidence_digest_update_text(
		&digest, control->registry.registry_digest_hex);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)control->policy.profile);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, control->telemetry.count);
	pqcp_deployment_evidence_digest_update_text(
		&digest, control->telemetry_summary.telemetry_digest_hex);
	pqcp_deployment_evidence_digest_update_text(
		&digest, control->forecast.forecast_digest_hex);
	pqcp_deployment_evidence_digest_update_text(
		&digest, control->threat.threat_digest_hex);
	pqcp_deployment_evidence_digest_update_text(
		&digest, control->resources.resource_digest_hex);
	pqcp_deployment_evidence_digest_update_text(
		&digest, control->recommendation.recommendation_digest_hex);
	if (digest_control_profile(control, &digest) != 0) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_update_u32(
		&digest, control->sessions.active_count);
	pqcp_deployment_evidence_digest_update_text(
		&digest, control->sessions.table_digest_hex);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, control->events.count);
	pqcp_deployment_evidence_digest_update_text(
		&digest, control->events.root_digest_hex);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, control->cycle_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, control->failure_count);
	return pqcp_deployment_evidence_digest_final_hex(&digest, output);
}

const char *pqcp_adaptive_status_str(enum pqcp_adaptive_status status)
{
	switch (status) {
	case PQCP_ADAPTIVE_STATUS_FAIL:
		return "FAIL";
	case PQCP_ADAPTIVE_STATUS_WARN:
		return "WARN";
	case PQCP_ADAPTIVE_STATUS_PASS:
		return "PASS";
	default:
		return "INVALID";
	}
}

const char *pqcp_adaptive_mode_str(enum pqcp_adaptive_mode mode)
{
	switch (mode) {
	case PQCP_ADAPTIVE_MODE_SAFE:
		return "safe";
	case PQCP_ADAPTIVE_MODE_CONSERVATIVE:
		return "conservative";
	case PQCP_ADAPTIVE_MODE_BALANCED:
		return "balanced";
	case PQCP_ADAPTIVE_MODE_PERFORMANCE:
		return "performance";
	case PQCP_ADAPTIVE_MODE_RECOVERY:
		return "recovery";
	case PQCP_ADAPTIVE_MODE_LOCKDOWN:
		return "lockdown";
	default:
		return "invalid";
	}
}

const char *pqcp_adaptive_pressure_str(enum pqcp_adaptive_pressure pressure)
{
	switch (pressure) {
	case PQCP_ADAPTIVE_PRESSURE_NONE:
		return "none";
	case PQCP_ADAPTIVE_PRESSURE_LOW:
		return "low";
	case PQCP_ADAPTIVE_PRESSURE_MODERATE:
		return "moderate";
	case PQCP_ADAPTIVE_PRESSURE_HIGH:
		return "high";
	case PQCP_ADAPTIVE_PRESSURE_CRITICAL:
		return "critical";
	default:
		return "invalid";
	}
}

const char *pqcp_adaptive_threat_level_str(
	enum pqcp_adaptive_threat_level level)
{
	switch (level) {
	case PQCP_ADAPTIVE_THREAT_NOMINAL:
		return "nominal";
	case PQCP_ADAPTIVE_THREAT_ELEVATED:
		return "elevated";
	case PQCP_ADAPTIVE_THREAT_HIGH:
		return "high";
	case PQCP_ADAPTIVE_THREAT_SEVERE:
		return "severe";
	case PQCP_ADAPTIVE_THREAT_CRITICAL:
		return "critical";
	default:
		return "invalid";
	}
}

const char *pqcp_adaptive_transition_state_str(
	enum pqcp_adaptive_transition_state state)
{
	switch (state) {
	case PQCP_ADAPTIVE_TRANSITION_STABLE:
		return "stable";
	case PQCP_ADAPTIVE_TRANSITION_PENDING:
		return "pending";
	case PQCP_ADAPTIVE_TRANSITION_PREPARING:
		return "preparing";
	case PQCP_ADAPTIVE_TRANSITION_COMMITTING:
		return "committing";
	case PQCP_ADAPTIVE_TRANSITION_COOLDOWN:
		return "cooldown";
	case PQCP_ADAPTIVE_TRANSITION_ROLLBACK:
		return "rollback";
	case PQCP_ADAPTIVE_TRANSITION_BLOCKED:
		return "blocked";
	default:
		return "invalid";
	}
}

const char *pqcp_adaptive_transition_reason_str(
	enum pqcp_adaptive_transition_reason reason)
{
	switch (reason) {
	case PQCP_ADAPTIVE_REASON_NONE:
		return "none";
	case PQCP_ADAPTIVE_REASON_INITIAL_SELECTION:
		return "initial_selection";
	case PQCP_ADAPTIVE_REASON_THREAT_ESCALATION:
		return "threat_escalation";
	case PQCP_ADAPTIVE_REASON_RESOURCE_PRESSURE:
		return "resource_pressure";
	case PQCP_ADAPTIVE_REASON_LATENCY_PRESSURE:
		return "latency_pressure";
	case PQCP_ADAPTIVE_REASON_ENERGY_PRESSURE:
		return "energy_pressure";
	case PQCP_ADAPTIVE_REASON_POLICY_CHANGE:
		return "policy_change";
	case PQCP_ADAPTIVE_REASON_HARDWARE_RECOVERY:
		return "hardware_recovery";
	case PQCP_ADAPTIVE_REASON_FLEET_CONSENSUS:
		return "fleet_consensus";
	case PQCP_ADAPTIVE_REASON_MANUAL_OVERRIDE:
		return "manual_override";
	case PQCP_ADAPTIVE_REASON_ROLLBACK:
		return "rollback";
	default:
		return "invalid";
	}
}

const char *pqcp_adaptive_session_kind_str(
	enum pqcp_adaptive_session_kind kind)
{
	switch (kind) {
	case PQCP_ADAPTIVE_SESSION_KEM:
		return "kem";
	case PQCP_ADAPTIVE_SESSION_SIGNATURE:
		return "signature";
	case PQCP_ADAPTIVE_SESSION_HYBRID_TLS:
		return "hybrid_tls";
	case PQCP_ADAPTIVE_SESSION_ONBOARDING:
		return "onboarding";
	case PQCP_ADAPTIVE_SESSION_RECONNECT:
		return "reconnect";
	case PQCP_ADAPTIVE_SESSION_FIRMWARE_UPDATE:
		return "firmware_update";
	case PQCP_ADAPTIVE_SESSION_TELEMETRY:
		return "telemetry";
	default:
		return "invalid";
	}
}

const char *pqcp_adaptive_event_type_str(enum pqcp_adaptive_event_type type)
{
	switch (type) {
	case PQCP_ADAPTIVE_EVENT_BOOT:
		return "boot";
	case PQCP_ADAPTIVE_EVENT_TELEMETRY:
		return "telemetry";
	case PQCP_ADAPTIVE_EVENT_THREAT_CHANGE:
		return "threat_change";
	case PQCP_ADAPTIVE_EVENT_RECOMMENDATION:
		return "recommendation";
	case PQCP_ADAPTIVE_EVENT_TRANSITION_REQUEST:
		return "transition_request";
	case PQCP_ADAPTIVE_EVENT_TRANSITION_COMMIT:
		return "transition_commit";
	case PQCP_ADAPTIVE_EVENT_TRANSITION_REJECT:
		return "transition_reject";
	case PQCP_ADAPTIVE_EVENT_DOWNGRADE_REQUEST:
		return "downgrade_request";
	case PQCP_ADAPTIVE_EVENT_DOWNGRADE_APPROVED:
		return "downgrade_approved";
	case PQCP_ADAPTIVE_EVENT_DOWNGRADE_REJECTED:
		return "downgrade_rejected";
	case PQCP_ADAPTIVE_EVENT_SESSION_OPEN:
		return "session_open";
	case PQCP_ADAPTIVE_EVENT_SESSION_CLOSE:
		return "session_close";
	case PQCP_ADAPTIVE_EVENT_SNAPSHOT:
		return "snapshot";
	case PQCP_ADAPTIVE_EVENT_FLEET_UPDATE:
		return "fleet_update";
	case PQCP_ADAPTIVE_EVENT_FAULT:
		return "fault";
	default:
		return "invalid";
	}
}
