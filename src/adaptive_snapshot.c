/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Canonical binary snapshot codec for adaptive PQC runtime state.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/adaptive_control.h>

#include "adaptive_internal.h"

#define PQCP_ADAPTIVE_SNAPSHOT_MAGIC UINT32_C(0x41505143)
#define PQCP_ADAPTIVE_SNAPSHOT_DOMAIN UINT64_C(0x414450534e415053)
#define PQCP_ADAPTIVE_SNAPSHOT_FLAG_TELEMETRY (1U << 0)
#define PQCP_ADAPTIVE_SNAPSHOT_FLAG_EVENTS    (1U << 1)
#define PQCP_ADAPTIVE_SNAPSHOT_FLAG_SESSIONS  (1U << 2)

static int write_profile(
	struct pqcp_deployment_evidence_codec_writer *writer,
	const struct pqcp_adaptive_profile *profile)
{
	int ret;

#define WRITE_PROFILE(call) do { ret = (call); if (ret != 0) return ret; } while (0)
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_u32(
		writer, profile->schema_version));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_text(
		writer, profile->profile_id,
		PQCP_ADAPTIVE_ID_MAX_CHARS - 1U));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_u32(
		writer, (uint32_t)profile->kind));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_u32(
		writer, profile->operation_mask));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_u32(
		writer, profile->security_level));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_u32(
		writer, profile->mlkem_level));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_u32(
		writer, profile->mldsa_level));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_u64(
		writer, profile->nominal_latency_us));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_u64(
		writer, profile->nominal_cycles));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_u64(
		writer, profile->ram_bytes));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_u64(
		writer, profile->stack_bytes));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_u64(
		writer, profile->heap_bytes));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_u64(
		writer, profile->flash_bytes));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_u64(
		writer, profile->energy_uj));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_u32(
		writer, profile->evidence_mask));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_u32(
		writer, profile->priority));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_bool(
		writer, profile->enabled));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_bool(
		writer, profile->native_provider));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_bool(
		writer, profile->production_allowed));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_bool(
		writer, profile->hardware_validated));
	WRITE_PROFILE(pqcp_deployment_evidence_codec_write_bool(
		writer, profile->hybrid_required));
#undef WRITE_PROFILE
	return 0;
}

static int read_profile(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_adaptive_profile *profile)
{
	uint32_t value;
	int ret;

#define READ_PROFILE(call) do { ret = (call); if (ret != 0) return ret; } while (0)
	memset(profile, 0, sizeof(*profile));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_u32(
		reader, &profile->schema_version));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_text(
		reader, profile->profile_id,
		sizeof(profile->profile_id),
		PQCP_ADAPTIVE_ID_MAX_CHARS - 1U));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_u32(
		reader, &value));
	profile->kind = (enum pqcp_deployment_candidate_kind)value;
	READ_PROFILE(pqcp_deployment_evidence_codec_read_u32(
		reader, &profile->operation_mask));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_u32(
		reader, &profile->security_level));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_u32(
		reader, &profile->mlkem_level));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_u32(
		reader, &profile->mldsa_level));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_u64(
		reader, &profile->nominal_latency_us));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_u64(
		reader, &profile->nominal_cycles));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_u64(
		reader, &profile->ram_bytes));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_u64(
		reader, &profile->stack_bytes));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_u64(
		reader, &profile->heap_bytes));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_u64(
		reader, &profile->flash_bytes));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_u64(
		reader, &profile->energy_uj));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_u32(
		reader, &profile->evidence_mask));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_u32(
		reader, &profile->priority));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_bool(
		reader, &profile->enabled));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_bool(
		reader, &profile->native_provider));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_bool(
		reader, &profile->production_allowed));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_bool(
		reader, &profile->hardware_validated));
	READ_PROFILE(pqcp_deployment_evidence_codec_read_bool(
		reader, &profile->hybrid_required));
#undef READ_PROFILE
	return pqcp_adaptive_internal_profile_valid(profile) ?
		0 : -EBADMSG;
}

static int write_policy(
	struct pqcp_deployment_evidence_codec_writer *writer,
	const struct pqcp_adaptive_policy *policy)
{
	const uint32_t values[] = {
		policy->schema_version,
		(uint32_t)policy->profile,
		(uint32_t)policy->default_mode,
		policy->minimum_security_level,
		policy->required_evidence_mask,
		policy->minimum_confidence,
		policy->minimum_improvement_score,
		policy->transition_confirmations,
		policy->cooldown_cycles,
		policy->maximum_transitions_per_hour,
		policy->fleet_quorum_percent,
		policy->weight_security,
		policy->weight_latency,
		policy->weight_memory,
		policy->weight_energy,
		policy->weight_evidence,
		policy->weight_stability,
		policy->risk_penalty,
		policy->missing_evidence_penalty,
	};
	const bool booleans[] = {
		policy->require_native_provider,
		policy->require_production_allowed,
		policy->require_hardware_evidence,
		policy->allow_security_downgrade,
		policy->allow_manual_override,
		policy->require_fleet_consensus,
		policy->fail_closed,
	};

	for (size_t index = 0U;
	     index < sizeof(values) / sizeof(values[0]); ++index) {
		const int ret =
			pqcp_deployment_evidence_codec_write_u32(
				writer, values[index]);

		if (ret != 0) {
			return ret;
		}
	}
	for (size_t index = 0U;
	     index < sizeof(booleans) / sizeof(booleans[0]); ++index) {
		const int ret =
			pqcp_deployment_evidence_codec_write_bool(
				writer, booleans[index]);

		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

static int read_policy(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_adaptive_policy *policy)
{
	uint32_t values[19];
	bool booleans[7];

	for (size_t index = 0U;
	     index < sizeof(values) / sizeof(values[0]); ++index) {
		const int ret =
			pqcp_deployment_evidence_codec_read_u32(
				reader, &values[index]);

		if (ret != 0) {
			return ret;
		}
	}
	for (size_t index = 0U;
	     index < sizeof(booleans) / sizeof(booleans[0]); ++index) {
		const int ret =
			pqcp_deployment_evidence_codec_read_bool(
				reader, &booleans[index]);

		if (ret != 0) {
			return ret;
		}
	}
	memset(policy, 0, sizeof(*policy));
	policy->schema_version = values[0];
	policy->profile =
		(enum pqcp_adaptive_policy_profile)values[1];
	policy->default_mode =
		(enum pqcp_adaptive_mode)values[2];
	policy->minimum_security_level = values[3];
	policy->required_evidence_mask = values[4];
	policy->minimum_confidence = values[5];
	policy->minimum_improvement_score = values[6];
	policy->transition_confirmations = values[7];
	policy->cooldown_cycles = values[8];
	policy->maximum_transitions_per_hour = values[9];
	policy->fleet_quorum_percent = values[10];
	policy->weight_security = values[11];
	policy->weight_latency = values[12];
	policy->weight_memory = values[13];
	policy->weight_energy = values[14];
	policy->weight_evidence = values[15];
	policy->weight_stability = values[16];
	policy->risk_penalty = values[17];
	policy->missing_evidence_penalty = values[18];
	policy->require_native_provider = booleans[0];
	policy->require_production_allowed = booleans[1];
	policy->require_hardware_evidence = booleans[2];
	policy->allow_security_downgrade = booleans[3];
	policy->allow_manual_override = booleans[4];
	policy->require_fleet_consensus = booleans[5];
	policy->fail_closed = booleans[6];
	return pqcp_adaptive_policy_validate(policy);
}

static int write_telemetry_sample(
	struct pqcp_deployment_evidence_codec_writer *writer,
	const struct pqcp_adaptive_telemetry_sample *sample)
{
	int ret;

#define WRITE_SAMPLE(call) do { ret = (call); if (ret != 0) return ret; } while (0)
	WRITE_SAMPLE(pqcp_deployment_evidence_codec_write_u64(
		writer, sample->timestamp_ms));
	WRITE_SAMPLE(pqcp_deployment_evidence_codec_write_u64(
		writer, sample->latency_us));
	WRITE_SAMPLE(pqcp_deployment_evidence_codec_write_u64(
		writer, sample->cycles));
	WRITE_SAMPLE(pqcp_deployment_evidence_codec_write_u64(
		writer, sample->free_ram_bytes));
	WRITE_SAMPLE(pqcp_deployment_evidence_codec_write_u64(
		writer, sample->stack_used_bytes));
	WRITE_SAMPLE(pqcp_deployment_evidence_codec_write_u64(
		writer, sample->heap_free_bytes));
	WRITE_SAMPLE(pqcp_deployment_evidence_codec_write_u64(
		writer, sample->energy_uj));
	WRITE_SAMPLE(pqcp_deployment_evidence_codec_write_u32(
		writer, sample->queue_depth));
	WRITE_SAMPLE(pqcp_deployment_evidence_codec_write_i32(
		writer, sample->temperature_millic));
	WRITE_SAMPLE(pqcp_deployment_evidence_codec_write_u32(
		writer, sample->battery_permille));
	WRITE_SAMPLE(pqcp_deployment_evidence_codec_write_u32(
		writer, sample->network_loss_permille));
	WRITE_SAMPLE(pqcp_deployment_evidence_codec_write_u32(
		writer, sample->handshake_failures));
	WRITE_SAMPLE(pqcp_deployment_evidence_codec_write_u32(
		writer, sample->auth_failures));
	WRITE_SAMPLE(pqcp_deployment_evidence_codec_write_bool(
		writer, sample->operation_succeeded));
#undef WRITE_SAMPLE
	return 0;
}

static int read_telemetry_sample(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_adaptive_telemetry_sample *sample)
{
	int ret;

#define READ_SAMPLE(call) do { ret = (call); if (ret != 0) return ret; } while (0)
	memset(sample, 0, sizeof(*sample));
	READ_SAMPLE(pqcp_deployment_evidence_codec_read_u64(
		reader, &sample->timestamp_ms));
	READ_SAMPLE(pqcp_deployment_evidence_codec_read_u64(
		reader, &sample->latency_us));
	READ_SAMPLE(pqcp_deployment_evidence_codec_read_u64(
		reader, &sample->cycles));
	READ_SAMPLE(pqcp_deployment_evidence_codec_read_u64(
		reader, &sample->free_ram_bytes));
	READ_SAMPLE(pqcp_deployment_evidence_codec_read_u64(
		reader, &sample->stack_used_bytes));
	READ_SAMPLE(pqcp_deployment_evidence_codec_read_u64(
		reader, &sample->heap_free_bytes));
	READ_SAMPLE(pqcp_deployment_evidence_codec_read_u64(
		reader, &sample->energy_uj));
	READ_SAMPLE(pqcp_deployment_evidence_codec_read_u32(
		reader, &sample->queue_depth));
	READ_SAMPLE(pqcp_deployment_evidence_codec_read_i32(
		reader, &sample->temperature_millic));
	READ_SAMPLE(pqcp_deployment_evidence_codec_read_u32(
		reader, &sample->battery_permille));
	READ_SAMPLE(pqcp_deployment_evidence_codec_read_u32(
		reader, &sample->network_loss_permille));
	READ_SAMPLE(pqcp_deployment_evidence_codec_read_u32(
		reader, &sample->handshake_failures));
	READ_SAMPLE(pqcp_deployment_evidence_codec_read_u32(
		reader, &sample->auth_failures));
	READ_SAMPLE(pqcp_deployment_evidence_codec_read_bool(
		reader, &sample->operation_succeeded));
#undef READ_SAMPLE
	return 0;
}

static int write_transition(
	struct pqcp_deployment_evidence_codec_writer *writer,
	const struct pqcp_adaptive_transition_controller *transition)
{
	int ret;

#define WRITE_TRANSITION(call) do { ret = (call); if (ret != 0) return ret; } while (0)
	WRITE_TRANSITION(pqcp_deployment_evidence_codec_write_u32(
		writer, transition->schema_version));
	WRITE_TRANSITION(pqcp_deployment_evidence_codec_write_u32(
		writer, (uint32_t)transition->state));
	WRITE_TRANSITION(pqcp_deployment_evidence_codec_write_u32(
		writer, (uint32_t)transition->pending_reason));
	WRITE_TRANSITION(pqcp_deployment_evidence_codec_write_u32(
		writer, transition->confirmation_count));
	WRITE_TRANSITION(pqcp_deployment_evidence_codec_write_u32(
		writer, transition->cooldown_remaining));
	WRITE_TRANSITION(pqcp_deployment_evidence_codec_write_u32(
		writer, transition->transition_count));
	WRITE_TRANSITION(pqcp_deployment_evidence_codec_write_u32(
		writer, transition->rejected_count));
	WRITE_TRANSITION(pqcp_deployment_evidence_codec_write_u64(
		writer, transition->hour_window_start_ms));
	WRITE_TRANSITION(pqcp_deployment_evidence_codec_write_u64(
		writer, transition->last_transition_ms));
	WRITE_TRANSITION(pqcp_deployment_evidence_codec_write_u64(
		writer, transition->pending_since_ms));
	WRITE_TRANSITION(pqcp_deployment_evidence_codec_write_text(
		writer, transition->current_profile_id,
		PQCP_ADAPTIVE_ID_MAX_CHARS - 1U));
	WRITE_TRANSITION(pqcp_deployment_evidence_codec_write_text(
		writer, transition->previous_profile_id,
		PQCP_ADAPTIVE_ID_MAX_CHARS - 1U));
	WRITE_TRANSITION(pqcp_deployment_evidence_codec_write_text(
		writer, transition->pending_profile_id,
		PQCP_ADAPTIVE_ID_MAX_CHARS - 1U));
	WRITE_TRANSITION(pqcp_deployment_evidence_codec_write_text(
		writer, transition->controller_digest_hex,
		PQCP_ADAPTIVE_DIGEST_HEX_CHARS));
#undef WRITE_TRANSITION
	return 0;
}

static int read_transition(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_adaptive_transition_controller *transition)
{
	uint32_t value;
	int ret;

#define READ_TRANSITION(call) do { ret = (call); if (ret != 0) return ret; } while (0)
	memset(transition, 0, sizeof(*transition));
	READ_TRANSITION(pqcp_deployment_evidence_codec_read_u32(
		reader, &transition->schema_version));
	READ_TRANSITION(pqcp_deployment_evidence_codec_read_u32(
		reader, &value));
	transition->state =
		(enum pqcp_adaptive_transition_state)value;
	READ_TRANSITION(pqcp_deployment_evidence_codec_read_u32(
		reader, &value));
	transition->pending_reason =
		(enum pqcp_adaptive_transition_reason)value;
	READ_TRANSITION(pqcp_deployment_evidence_codec_read_u32(
		reader, &transition->confirmation_count));
	READ_TRANSITION(pqcp_deployment_evidence_codec_read_u32(
		reader, &transition->cooldown_remaining));
	READ_TRANSITION(pqcp_deployment_evidence_codec_read_u32(
		reader, &transition->transition_count));
	READ_TRANSITION(pqcp_deployment_evidence_codec_read_u32(
		reader, &transition->rejected_count));
	READ_TRANSITION(pqcp_deployment_evidence_codec_read_u64(
		reader, &transition->hour_window_start_ms));
	READ_TRANSITION(pqcp_deployment_evidence_codec_read_u64(
		reader, &transition->last_transition_ms));
	READ_TRANSITION(pqcp_deployment_evidence_codec_read_u64(
		reader, &transition->pending_since_ms));
	READ_TRANSITION(pqcp_deployment_evidence_codec_read_text(
		reader, transition->current_profile_id,
		sizeof(transition->current_profile_id),
		PQCP_ADAPTIVE_ID_MAX_CHARS - 1U));
	READ_TRANSITION(pqcp_deployment_evidence_codec_read_text(
		reader, transition->previous_profile_id,
		sizeof(transition->previous_profile_id),
		PQCP_ADAPTIVE_ID_MAX_CHARS - 1U));
	READ_TRANSITION(pqcp_deployment_evidence_codec_read_text(
		reader, transition->pending_profile_id,
		sizeof(transition->pending_profile_id),
		PQCP_ADAPTIVE_ID_MAX_CHARS - 1U));
	READ_TRANSITION(pqcp_deployment_evidence_codec_read_text(
		reader, transition->controller_digest_hex,
		sizeof(transition->controller_digest_hex),
		PQCP_ADAPTIVE_DIGEST_HEX_CHARS));
#undef READ_TRANSITION
	return pqcp_adaptive_internal_id_valid(
		transition->current_profile_id) ? 0 : -EBADMSG;
}

static int write_session(
	struct pqcp_deployment_evidence_codec_writer *writer,
	const struct pqcp_adaptive_session_entry *entry)
{
	int ret;

	ret = pqcp_deployment_evidence_codec_write_bool(
		writer, entry->active);
	if (ret != 0 || !entry->active) {
		return ret;
	}
	if ((ret = pqcp_deployment_evidence_codec_write_u64(
		     writer, entry->session_id)) != 0 ||
	    (ret = pqcp_deployment_evidence_codec_write_u32(
		     writer, (uint32_t)entry->kind)) != 0 ||
	    (ret = pqcp_deployment_evidence_codec_write_u64(
		     writer, entry->opened_at_ms)) != 0 ||
	    (ret = pqcp_deployment_evidence_codec_write_u64(
		     writer, entry->expires_at_ms)) != 0 ||
	    (ret = pqcp_deployment_evidence_codec_write_text(
		     writer, entry->profile_id,
		     PQCP_ADAPTIVE_ID_MAX_CHARS - 1U)) != 0) {
		return ret;
	}
	return 0;
}

static int read_session(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_adaptive_session_entry *entry)
{
	uint32_t kind;
	int ret;

	memset(entry, 0, sizeof(*entry));
	ret = pqcp_deployment_evidence_codec_read_bool(
		reader, &entry->active);
	if (ret != 0 || !entry->active) {
		return ret;
	}
	if ((ret = pqcp_deployment_evidence_codec_read_u64(
		     reader, &entry->session_id)) != 0 ||
	    (ret = pqcp_deployment_evidence_codec_read_u32(
		     reader, &kind)) != 0 ||
	    (ret = pqcp_deployment_evidence_codec_read_u64(
		     reader, &entry->opened_at_ms)) != 0 ||
	    (ret = pqcp_deployment_evidence_codec_read_u64(
		     reader, &entry->expires_at_ms)) != 0 ||
	    (ret = pqcp_deployment_evidence_codec_read_text(
		     reader, entry->profile_id,
		     sizeof(entry->profile_id),
		     PQCP_ADAPTIVE_ID_MAX_CHARS - 1U)) != 0) {
		return ret;
	}
	entry->kind = (enum pqcp_adaptive_session_kind)kind;
	return pqcp_adaptive_internal_id_valid(entry->profile_id) ?
		0 : -EBADMSG;
}

static int write_event(
	struct pqcp_deployment_evidence_codec_writer *writer,
	const struct pqcp_adaptive_event *event)
{
	int ret;

#define WRITE_EVENT(call) do { ret = (call); if (ret != 0) return ret; } while (0)
	WRITE_EVENT(pqcp_deployment_evidence_codec_write_u32(
		writer, event->schema_version));
	WRITE_EVENT(pqcp_deployment_evidence_codec_write_u32(
		writer, event->sequence));
	WRITE_EVENT(pqcp_deployment_evidence_codec_write_u32(
		writer, (uint32_t)event->type));
	WRITE_EVENT(pqcp_deployment_evidence_codec_write_u32(
		writer, (uint32_t)event->status));
	WRITE_EVENT(pqcp_deployment_evidence_codec_write_u64(
		writer, event->timestamp_ms));
	WRITE_EVENT(pqcp_deployment_evidence_codec_write_u32(
		writer, event->reason_mask));
	WRITE_EVENT(pqcp_deployment_evidence_codec_write_u32(
		writer, event->blocker_mask));
	WRITE_EVENT(pqcp_deployment_evidence_codec_write_u32(
		writer, event->warning_mask));
	WRITE_EVENT(pqcp_deployment_evidence_codec_write_u32(
		writer, event->score));
	WRITE_EVENT(pqcp_deployment_evidence_codec_write_text(
		writer, event->profile_id,
		PQCP_ADAPTIVE_ID_MAX_CHARS - 1U));
	WRITE_EVENT(pqcp_deployment_evidence_codec_write_text(
		writer, event->related_id,
		PQCP_ADAPTIVE_ID_MAX_CHARS - 1U));
	WRITE_EVENT(pqcp_deployment_evidence_codec_write_text(
		writer, event->previous_digest_hex,
		PQCP_ADAPTIVE_DIGEST_HEX_CHARS));
	WRITE_EVENT(pqcp_deployment_evidence_codec_write_text(
		writer, event->event_digest_hex,
		PQCP_ADAPTIVE_DIGEST_HEX_CHARS));
#undef WRITE_EVENT
	return 0;
}

static int read_event(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_adaptive_event *event)
{
	uint32_t value;
	int ret;

#define READ_EVENT(call) do { ret = (call); if (ret != 0) return ret; } while (0)
	memset(event, 0, sizeof(*event));
	READ_EVENT(pqcp_deployment_evidence_codec_read_u32(
		reader, &event->schema_version));
	READ_EVENT(pqcp_deployment_evidence_codec_read_u32(
		reader, &event->sequence));
	READ_EVENT(pqcp_deployment_evidence_codec_read_u32(
		reader, &value));
	event->type = (enum pqcp_adaptive_event_type)value;
	READ_EVENT(pqcp_deployment_evidence_codec_read_u32(
		reader, &value));
	event->status = (enum pqcp_adaptive_status)value;
	READ_EVENT(pqcp_deployment_evidence_codec_read_u64(
		reader, &event->timestamp_ms));
	READ_EVENT(pqcp_deployment_evidence_codec_read_u32(
		reader, &event->reason_mask));
	READ_EVENT(pqcp_deployment_evidence_codec_read_u32(
		reader, &event->blocker_mask));
	READ_EVENT(pqcp_deployment_evidence_codec_read_u32(
		reader, &event->warning_mask));
	READ_EVENT(pqcp_deployment_evidence_codec_read_u32(
		reader, &event->score));
	READ_EVENT(pqcp_deployment_evidence_codec_read_text(
		reader, event->profile_id,
		sizeof(event->profile_id),
		PQCP_ADAPTIVE_ID_MAX_CHARS - 1U));
	READ_EVENT(pqcp_deployment_evidence_codec_read_text(
		reader, event->related_id,
		sizeof(event->related_id),
		PQCP_ADAPTIVE_ID_MAX_CHARS - 1U));
	READ_EVENT(pqcp_deployment_evidence_codec_read_text(
		reader, event->previous_digest_hex,
		sizeof(event->previous_digest_hex),
		PQCP_ADAPTIVE_DIGEST_HEX_CHARS));
	READ_EVENT(pqcp_deployment_evidence_codec_read_text(
		reader, event->event_digest_hex,
		sizeof(event->event_digest_hex),
		PQCP_ADAPTIVE_DIGEST_HEX_CHARS));
#undef READ_EVENT
	return 0;
}

static int write_control(
	struct pqcp_deployment_evidence_codec_writer *writer,
	const struct pqcp_adaptive_control_plane *control,
	uint32_t flags,
	uint32_t *record_count)
{
	int ret;

#define WRITE_CONTROL(call) do { ret = (call); if (ret != 0) return ret; } while (0)
	WRITE_CONTROL(pqcp_deployment_evidence_codec_write_u32(
		writer, PQCP_ADAPTIVE_SNAPSHOT_MAGIC));
	WRITE_CONTROL(pqcp_deployment_evidence_codec_write_u32(
		writer, PQCP_ADAPTIVE_SCHEMA_VERSION));
	WRITE_CONTROL(pqcp_deployment_evidence_codec_write_u32(
		writer, flags));
	WRITE_CONTROL(pqcp_deployment_evidence_codec_write_text(
		writer, control->device_id,
		PQCP_ADAPTIVE_ID_MAX_CHARS - 1U));
	WRITE_CONTROL(pqcp_deployment_evidence_codec_write_u32(
		writer, (uint32_t)control->mode));
	WRITE_CONTROL(pqcp_deployment_evidence_codec_write_u32(
		writer, control->cycle_count));
	WRITE_CONTROL(pqcp_deployment_evidence_codec_write_u32(
		writer, control->failure_count));
	WRITE_CONTROL(pqcp_deployment_evidence_codec_write_u32(
		writer, control->registry.count));
	for (uint32_t index = 0U;
	     index < control->registry.count; ++index) {
		WRITE_CONTROL(write_profile(
			writer, &control->registry.profiles[index]));
		(*record_count)++;
	}
	WRITE_CONTROL(write_policy(writer, &control->policy));
	(*record_count)++;
	WRITE_CONTROL(write_transition(writer, &control->transition));
	(*record_count)++;
	if ((flags & PQCP_ADAPTIVE_SNAPSHOT_FLAG_TELEMETRY) != 0U) {
		WRITE_CONTROL(pqcp_deployment_evidence_codec_write_u32(
			writer, control->telemetry.count));
		for (uint32_t index = 0U;
		     index < control->telemetry.count; ++index) {
			uint32_t physical =
				control->telemetry.count <
					control->telemetry.capacity ?
				index :
				(control->telemetry.head + index) %
				control->telemetry.capacity;

			WRITE_CONTROL(write_telemetry_sample(
				writer,
				&control->telemetry.samples[physical]));
			(*record_count)++;
		}
		WRITE_CONTROL(pqcp_deployment_evidence_codec_write_u32(
			writer, control->telemetry.rejected_samples));
	}
	if ((flags & PQCP_ADAPTIVE_SNAPSHOT_FLAG_SESSIONS) != 0U) {
		WRITE_CONTROL(pqcp_deployment_evidence_codec_write_u32(
			writer, PQCP_ADAPTIVE_MAX_SESSIONS));
		for (uint32_t index = 0U;
		     index < PQCP_ADAPTIVE_MAX_SESSIONS; ++index) {
			WRITE_CONTROL(write_session(
				writer, &control->sessions.sessions[index]));
			if (control->sessions.sessions[index].active) {
				(*record_count)++;
			}
		}
	}
	if ((flags & PQCP_ADAPTIVE_SNAPSHOT_FLAG_EVENTS) != 0U) {
		WRITE_CONTROL(pqcp_deployment_evidence_codec_write_u32(
			writer, control->events.count));
		for (uint32_t index = 0U;
		     index < control->events.count; ++index) {
			const struct pqcp_adaptive_event *event =
				pqcp_adaptive_event_log_get(
					&control->events, index);

			WRITE_CONTROL(write_event(writer, event));
			(*record_count)++;
		}
		WRITE_CONTROL(pqcp_deployment_evidence_codec_write_u32(
			writer, control->events.next_sequence));
		WRITE_CONTROL(pqcp_deployment_evidence_codec_write_u32(
			writer, control->events.dropped_events));
	}
	WRITE_CONTROL(pqcp_deployment_evidence_codec_write_text(
		writer, control->state_digest_hex,
		PQCP_ADAPTIVE_DIGEST_HEX_CHARS));
#undef WRITE_CONTROL
	return 0;
}

static int snapshot_digest(
	const uint8_t *buffer,
	size_t length,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U])
{
	return pqcp_deployment_evidence_digest_buffer_hex(
		PQCP_ADAPTIVE_SNAPSHOT_DOMAIN,
		buffer, length, output);
}

int pqcp_adaptive_snapshot_encode(
	const struct pqcp_adaptive_control_plane *control,
	uint8_t *buffer,
	size_t capacity,
	struct pqcp_adaptive_snapshot *snapshot)
{
	struct pqcp_deployment_evidence_codec_writer writer;
	uint32_t flags =
		PQCP_ADAPTIVE_SNAPSHOT_FLAG_TELEMETRY |
		PQCP_ADAPTIVE_SNAPSHOT_FLAG_EVENTS |
		PQCP_ADAPTIVE_SNAPSHOT_FLAG_SESSIONS;
	uint32_t records = 0U;
	int ret;

	if (control == NULL || buffer == NULL || snapshot == NULL ||
	    capacity == 0U ||
	    capacity > PQCP_ADAPTIVE_SNAPSHOT_MAX_BYTES ||
	    pqcp_adaptive_profile_registry_validate(
		    &control->registry) != 0 ||
	    pqcp_adaptive_policy_validate(&control->policy) != 0 ||
	    pqcp_adaptive_event_log_verify(&control->events) != 0) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_codec_writer_init(
		&writer, buffer, capacity);
	ret = write_control(
		&writer, control, flags, &records);
	if (ret != 0) {
		return ret;
	}
	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	snapshot->byte_count =
		(uint32_t)pqcp_deployment_evidence_codec_writer_used(
			&writer);
	snapshot->record_count = records;
	snapshot->flags = flags;
	return snapshot_digest(
		buffer, snapshot->byte_count,
		snapshot->snapshot_digest_hex);
}

static int read_control_header(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_adaptive_control_plane *control,
	uint32_t *flags)
{
	uint32_t magic;
	uint32_t schema;
	uint32_t mode;
	int ret;

	if ((ret = pqcp_deployment_evidence_codec_read_u32(
		     reader, &magic)) != 0 ||
	    (ret = pqcp_deployment_evidence_codec_read_u32(
		     reader, &schema)) != 0 ||
	    (ret = pqcp_deployment_evidence_codec_read_u32(
		     reader, flags)) != 0 ||
	    (ret = pqcp_deployment_evidence_codec_read_text(
		     reader, control->device_id,
		     sizeof(control->device_id),
		     PQCP_ADAPTIVE_ID_MAX_CHARS - 1U)) != 0 ||
	    (ret = pqcp_deployment_evidence_codec_read_u32(
		     reader, &mode)) != 0 ||
	    (ret = pqcp_deployment_evidence_codec_read_u32(
		     reader, &control->cycle_count)) != 0 ||
	    (ret = pqcp_deployment_evidence_codec_read_u32(
		     reader, &control->failure_count)) != 0) {
		return ret;
	}
	if (magic != PQCP_ADAPTIVE_SNAPSHOT_MAGIC ||
	    schema != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    (*flags & ~(PQCP_ADAPTIVE_SNAPSHOT_FLAG_TELEMETRY |
			PQCP_ADAPTIVE_SNAPSHOT_FLAG_EVENTS |
			PQCP_ADAPTIVE_SNAPSHOT_FLAG_SESSIONS)) != 0U ||
	    mode > PQCP_ADAPTIVE_MODE_LOCKDOWN ||
	    !pqcp_adaptive_internal_id_valid(control->device_id)) {
		return -EBADMSG;
	}
	control->schema_version = schema;
	control->mode = (enum pqcp_adaptive_mode)mode;
	return 0;
}

static int read_registry(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_adaptive_profile_registry *registry,
	uint32_t *records)
{
	uint32_t count;
	int ret;

	if ((ret = pqcp_deployment_evidence_codec_read_u32(
		     reader, &count)) != 0 ||
	    count > PQCP_ADAPTIVE_MAX_PROFILES ||
	    pqcp_adaptive_profile_registry_init(registry) != 0) {
		return ret != 0 ? ret : -EBADMSG;
	}
	for (uint32_t index = 0U; index < count; ++index) {
		struct pqcp_adaptive_profile profile;

		ret = read_profile(reader, &profile);
		if (ret != 0 ||
		    pqcp_adaptive_profile_registry_add(
			    registry, &profile) != 0) {
			return ret != 0 ? ret : -EBADMSG;
		}
		(*records)++;
	}
	return 0;
}

static int read_telemetry(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_adaptive_telemetry_window *window,
	uint32_t *records)
{
	uint32_t count;
	uint32_t rejected;
	int ret;

	if ((ret = pqcp_deployment_evidence_codec_read_u32(
		     reader, &count)) != 0 ||
	    count > PQCP_ADAPTIVE_TELEMETRY_CAPACITY ||
	    pqcp_adaptive_telemetry_init(window) != 0) {
		return ret != 0 ? ret : -EBADMSG;
	}
	for (uint32_t index = 0U; index < count; ++index) {
		struct pqcp_adaptive_telemetry_sample sample;

		ret = read_telemetry_sample(reader, &sample);
		if (ret != 0 ||
		    pqcp_adaptive_telemetry_push(
			    window, &sample) != 0) {
			return ret != 0 ? ret : -EBADMSG;
		}
		(*records)++;
	}
	ret = pqcp_deployment_evidence_codec_read_u32(
		reader, &rejected);
	if (ret != 0) {
		return ret;
	}
	window->rejected_samples = rejected;
	return 0;
}

static int read_sessions(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_adaptive_session_table *table,
	uint32_t *records)
{
	uint32_t slots;
	int ret;

	if ((ret = pqcp_deployment_evidence_codec_read_u32(
		     reader, &slots)) != 0 ||
	    slots != PQCP_ADAPTIVE_MAX_SESSIONS ||
	    pqcp_adaptive_session_table_init(table) != 0) {
		return ret != 0 ? ret : -EBADMSG;
	}
	for (uint32_t index = 0U; index < slots; ++index) {
		ret = read_session(reader, &table->sessions[index]);
		if (ret != 0) {
			return ret;
		}
		if (table->sessions[index].active) {
			table->active_count++;
			(*records)++;
		}
	}
	return 0;
}

static int read_events(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_adaptive_event_log *log,
	uint32_t *records)
{
	uint32_t count;
	uint32_t next_sequence;
	uint32_t dropped;
	int ret;

	if ((ret = pqcp_deployment_evidence_codec_read_u32(
		     reader, &count)) != 0 ||
	    count > PQCP_ADAPTIVE_MAX_EVENTS ||
	    pqcp_adaptive_event_log_init(log) != 0) {
		return ret != 0 ? ret : -EBADMSG;
	}
	log->count = count;
	log->head = count % PQCP_ADAPTIVE_MAX_EVENTS;
	for (uint32_t index = 0U; index < count; ++index) {
		ret = read_event(reader, &log->events[index]);
		if (ret != 0) {
			return ret;
		}
		(*records)++;
	}
	if ((ret = pqcp_deployment_evidence_codec_read_u32(
		     reader, &next_sequence)) != 0 ||
	    (ret = pqcp_deployment_evidence_codec_read_u32(
		     reader, &dropped)) != 0) {
		return ret;
	}
	log->next_sequence = next_sequence;
	log->dropped_events = dropped;
	return pqcp_adaptive_event_log_reseal(log);
}

int pqcp_adaptive_snapshot_decode(
	const uint8_t *buffer,
	size_t length,
	struct pqcp_adaptive_control_plane *control,
	struct pqcp_adaptive_snapshot *snapshot)
{
	struct pqcp_deployment_evidence_codec_reader reader;
	char encoded_state_digest[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
	uint32_t flags;
	uint32_t records = 0U;
	int ret;

	if (buffer == NULL || length == 0U ||
	    length > PQCP_ADAPTIVE_SNAPSHOT_MAX_BYTES ||
	    control == NULL || snapshot == NULL) {
		return -EINVAL;
	}
	memset(control, 0, sizeof(*control));
	pqcp_deployment_evidence_codec_reader_init(
		&reader, buffer, length);
	if ((ret = read_control_header(
		     &reader, control, &flags)) != 0 ||
	    (ret = read_registry(
		     &reader, &control->registry, &records)) != 0 ||
	    (ret = read_policy(
		     &reader, &control->policy)) != 0 ||
	    (records++, ret = read_transition(
		     &reader, &control->transition)) != 0) {
		return ret;
	}
	records++;
	if ((flags & PQCP_ADAPTIVE_SNAPSHOT_FLAG_TELEMETRY) != 0U) {
		ret = read_telemetry(
			&reader, &control->telemetry, &records);
	} else {
		ret = pqcp_adaptive_telemetry_init(
			&control->telemetry);
	}
	if (ret != 0) {
		return ret;
	}
	if ((flags & PQCP_ADAPTIVE_SNAPSHOT_FLAG_SESSIONS) != 0U) {
		ret = read_sessions(
			&reader, &control->sessions, &records);
	} else {
		ret = pqcp_adaptive_session_table_init(
			&control->sessions);
	}
	if (ret != 0) {
		return ret;
	}
	if ((flags & PQCP_ADAPTIVE_SNAPSHOT_FLAG_EVENTS) != 0U) {
		ret = read_events(
			&reader, &control->events, &records);
	} else {
		ret = pqcp_adaptive_event_log_init(
			&control->events);
	}
	if (ret != 0 ||
	    (ret = pqcp_deployment_evidence_codec_read_text(
		     &reader, encoded_state_digest,
		     sizeof(encoded_state_digest),
		     PQCP_ADAPTIVE_DIGEST_HEX_CHARS)) != 0 ||
	    (ret = pqcp_deployment_evidence_codec_require_eof(
		     &reader)) != 0) {
		return ret;
	}
	pqcp_adaptive_internal_set_text(
		control->state_digest_hex,
		sizeof(control->state_digest_hex),
		encoded_state_digest);
	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	snapshot->byte_count = (uint32_t)length;
	snapshot->record_count = records;
	snapshot->flags = flags;
	ret = snapshot_digest(
		buffer, length, snapshot->snapshot_digest_hex);
	if (ret != 0 ||
	    pqcp_adaptive_profile_registry_validate(
		    &control->registry) != 0 ||
	    pqcp_adaptive_policy_validate(&control->policy) != 0 ||
	    pqcp_adaptive_event_log_verify(&control->events) != 0) {
		return ret != 0 ? ret : -EBADMSG;
	}
	return 0;
}

int pqcp_adaptive_snapshot_emit(
	const struct pqcp_adaptive_snapshot *snapshot)
{
	if (snapshot == NULL ||
	    snapshot->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    snapshot->byte_count == 0U ||
	    snapshot->byte_count >
		    PQCP_ADAPTIVE_SNAPSHOT_MAX_BYTES) {
		return -EINVAL;
	}
	printk("PQCP_ADAPTIVE_SNAPSHOT schema=%u bytes=%u records=%u flags=0x%08x digest=%s\n",
	       snapshot->schema_version,
	       snapshot->byte_count,
	       snapshot->record_count,
	       snapshot->flags,
	       snapshot->snapshot_digest_hex);
	return 0;
}
