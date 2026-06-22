/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free, host-portable fleet policy explanation and audit traces.
 */

#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_policy_explain.h>

#define TRACE_MAGIC_0 ((uint8_t)'F')
#define TRACE_MAGIC_1 ((uint8_t)'P')
#define TRACE_MAGIC_2 ((uint8_t)'X')
#define TRACE_MAGIC_3 ((uint8_t)'T')

#define TRACE_EVENT_FLAG_MASK \
	(PQCP_FLEET_POLICY_TRACE_EVENT_REDACTED | \
	 PQCP_FLEET_POLICY_TRACE_EVENT_TERMINAL | \
	 PQCP_FLEET_POLICY_TRACE_EVENT_ERROR)

struct text_writer {
	char *output;
	size_t capacity;
	size_t length;
};

static bool event_type_valid(
	enum pqcp_fleet_policy_trace_event_type type)
{
	return type >= PQCP_FLEET_POLICY_TRACE_EVENT_INSTRUCTION &&
	       type <= PQCP_FLEET_POLICY_TRACE_EVENT_DECISION;
}

static bool redaction_valid(
	enum pqcp_fleet_policy_redaction_class redaction)
{
	return redaction >= PQCP_FLEET_POLICY_REDACTION_PUBLIC &&
	       redaction <= PQCP_FLEET_POLICY_REDACTION_SECRET;
}

static bool decision_valid(
	enum pqcp_fleet_policy_trace_decision decision)
{
	return decision >= PQCP_FLEET_POLICY_TRACE_DECISION_NONE &&
	       decision <= PQCP_FLEET_POLICY_TRACE_DECISION_QUARANTINE;
}

static bool trace_valid(const struct pqcp_fleet_policy_trace *trace)
{
	return trace != NULL &&
	       trace->schema_version ==
		       PQCP_FLEET_POLICY_EXPLAIN_SCHEMA_VERSION &&
	       trace->events != NULL && trace->capacity != 0U &&
	       trace->start < trace->capacity &&
	       trace->count <= trace->capacity &&
	       trace->next_event_id != 0U &&
	       trace->audit_next_event_id != 0U &&
	       trace->audit_next_event_id <= trace->next_event_id &&
	       decision_valid(trace->final_decision) &&
	       ((trace->terminal &&
		 trace->final_decision !=
			 PQCP_FLEET_POLICY_TRACE_DECISION_NONE) ||
		(!trace->terminal &&
		 trace->final_decision ==
			 PQCP_FLEET_POLICY_TRACE_DECISION_NONE &&
		 trace->final_reason ==
			 PQCP_FLEET_POLICY_TRACE_REASON_NONE));
}

static struct pqcp_fleet_policy_redaction default_redaction(void)
{
	struct pqcp_fleet_policy_redaction redaction;

	redaction.maximum_visible = PQCP_FLEET_POLICY_REDACTION_PUBLIC;
	redaction.retain_causal_parents = true;
	return redaction;
}

static bool payload_visible(
	const struct pqcp_fleet_policy_trace_event *event,
	const struct pqcp_fleet_policy_redaction *redaction)
{
	return event->redaction <= redaction->maximum_visible;
}

static uint64_t saturating_add_u64(uint64_t left, uint64_t right)
{
	return UINT64_MAX - left < right ?
		UINT64_MAX : left + right;
}

static uint64_t mix64(uint64_t value)
{
	value ^= value >> 30U;
	value *= UINT64_C(0xbf58476d1ce4e5b9);
	value ^= value >> 27U;
	value *= UINT64_C(0x94d049bb133111eb);
	value ^= value >> 31U;
	return value;
}

static void write_u16(uint8_t *output, uint16_t value)
{
	output[0] = (uint8_t)value;
	output[1] = (uint8_t)(value >> 8U);
}

static void write_u32(uint8_t *output, uint32_t value)
{
	output[0] = (uint8_t)value;
	output[1] = (uint8_t)(value >> 8U);
	output[2] = (uint8_t)(value >> 16U);
	output[3] = (uint8_t)(value >> 24U);
}

static void write_u64(uint8_t *output, uint64_t value)
{
	for (size_t index = 0U; index < 8U; ++index) {
		output[index] = (uint8_t)(value >> (index * 8U));
	}
}

static uint16_t read_u16(const uint8_t *input)
{
	return (uint16_t)input[0] |
	       ((uint16_t)input[1] << 8U);
}

static uint32_t read_u32(const uint8_t *input)
{
	return (uint32_t)input[0] |
	       ((uint32_t)input[1] << 8U) |
	       ((uint32_t)input[2] << 16U) |
	       ((uint32_t)input[3] << 24U);
}

static uint64_t read_u64(const uint8_t *input)
{
	uint64_t value = 0U;

	for (size_t index = 0U; index < 8U; ++index) {
		value |= (uint64_t)input[index] << (index * 8U);
	}
	return value;
}

static const struct pqcp_fleet_policy_trace_event *event_at(
	const struct pqcp_fleet_policy_trace *trace,
	size_t index)
{
	if (!trace_valid(trace) || index >= trace->count) {
		return NULL;
	}
	return &trace->events[
		(trace->start + index) % trace->capacity];
}

static struct pqcp_fleet_policy_trace_event redact_event(
	const struct pqcp_fleet_policy_trace_event *event,
	const struct pqcp_fleet_policy_redaction *redaction)
{
	struct pqcp_fleet_policy_trace_event result = *event;

	if (!redaction->retain_causal_parents) {
		result.parent_id = 0U;
	}
	if (!payload_visible(event, redaction)) {
		result.key = 0U;
		result.detail = 0U;
		result.value = 0U;
		result.flags |= PQCP_FLEET_POLICY_TRACE_EVENT_REDACTED;
	}
	return result;
}

static void encode_event(
	const struct pqcp_fleet_policy_trace_event *event,
	uint8_t output[PQCP_FLEET_POLICY_EXPLAIN_BINARY_EVENT_BYTES])
{
	write_u64(output, event->event_id);
	write_u64(output + 8U, event->parent_id);
	output[16] = (uint8_t)event->type;
	output[17] = (uint8_t)event->redaction;
	output[18] = (uint8_t)event->decision;
	output[19] = 0U;
	write_u32(output + 20U, event->flags);
	write_u32(output + 24U, event->reason);
	write_u32(output + 28U, event->key);
	write_u32(output + 32U, event->detail);
	write_u64(output + 36U, event->value);
}

static int decode_event(
	const uint8_t input[PQCP_FLEET_POLICY_EXPLAIN_BINARY_EVENT_BYTES],
	struct pqcp_fleet_policy_trace_event *event)
{
	memset(event, 0, sizeof(*event));
	event->event_id = read_u64(input);
	event->parent_id = read_u64(input + 8U);
	event->type =
		(enum pqcp_fleet_policy_trace_event_type)input[16];
	event->redaction =
		(enum pqcp_fleet_policy_redaction_class)input[17];
	event->decision =
		(enum pqcp_fleet_policy_trace_decision)input[18];
	event->flags = read_u32(input + 20U);
	event->reason = read_u32(input + 24U);
	event->key = read_u32(input + 28U);
	event->detail = read_u32(input + 32U);
	event->value = read_u64(input + 36U);
	if (event->event_id == 0U ||
	    event->parent_id >= event->event_id ||
	    !event_type_valid(event->type) ||
	    !redaction_valid(event->redaction) ||
	    !decision_valid(event->decision) ||
	    (event->flags & ~TRACE_EVENT_FLAG_MASK) != 0U ||
	    input[19] != 0U) {
		return PQCP_FLEET_POLICY_EXPLAIN_MALFORMED;
	}
	if (event->type == PQCP_FLEET_POLICY_TRACE_EVENT_DECISION) {
		if (event->decision ==
			    PQCP_FLEET_POLICY_TRACE_DECISION_NONE ||
		    (event->flags &
		     PQCP_FLEET_POLICY_TRACE_EVENT_TERMINAL) == 0U) {
			return PQCP_FLEET_POLICY_EXPLAIN_MALFORMED;
		}
	} else if (event->decision !=
			   PQCP_FLEET_POLICY_TRACE_DECISION_NONE ||
		   (event->flags &
		    PQCP_FLEET_POLICY_TRACE_EVENT_TERMINAL) != 0U) {
		return PQCP_FLEET_POLICY_EXPLAIN_MALFORMED;
	}
	return PQCP_FLEET_POLICY_EXPLAIN_OK;
}

static int size_for_events(size_t count, size_t *size)
{
	if (size == NULL ||
	    count > (SIZE_MAX -
		     PQCP_FLEET_POLICY_EXPLAIN_BINARY_HEADER_BYTES) /
			    PQCP_FLEET_POLICY_EXPLAIN_BINARY_EVENT_BYTES) {
		return PQCP_FLEET_POLICY_EXPLAIN_NO_SPACE;
	}
	*size = PQCP_FLEET_POLICY_EXPLAIN_BINARY_HEADER_BYTES +
		count * PQCP_FLEET_POLICY_EXPLAIN_BINARY_EVENT_BYTES;
	return PQCP_FLEET_POLICY_EXPLAIN_OK;
}

static void encode_header(
	const struct pqcp_fleet_policy_trace *trace,
	uint32_t count,
	uint64_t first_event_id,
	uint8_t output[PQCP_FLEET_POLICY_EXPLAIN_BINARY_HEADER_BYTES])
{
	memset(output, 0, PQCP_FLEET_POLICY_EXPLAIN_BINARY_HEADER_BYTES);
	output[0] = TRACE_MAGIC_0;
	output[1] = TRACE_MAGIC_1;
	output[2] = TRACE_MAGIC_2;
	output[3] = TRACE_MAGIC_3;
	write_u16(output + 4U,
		  PQCP_FLEET_POLICY_EXPLAIN_BINARY_VERSION);
	write_u16(output + 6U,
		  PQCP_FLEET_POLICY_EXPLAIN_BINARY_HEADER_BYTES);
	write_u16(output + 8U,
		  PQCP_FLEET_POLICY_EXPLAIN_BINARY_EVENT_BYTES);
	write_u32(output + 12U, count);
	write_u64(output + 16U, trace->dropped_count);
	write_u64(output + 24U, trace->correlation_id.high);
	write_u64(output + 32U, trace->correlation_id.low);
	write_u64(output + 40U, trace->next_event_id);
	write_u64(output + 48U, trace->audit_dropped_count);
	output[56] = (uint8_t)trace->final_decision;
	output[57] = trace->sampled ? 1U : 0U;
	output[58] = trace->terminal ? 1U : 0U;
	write_u32(output + 60U, trace->final_reason);
	write_u64(output + 64U, first_event_id);
}

static int header_validate(const uint8_t *input, size_t length)
{
	if (input == NULL ||
	    length < PQCP_FLEET_POLICY_EXPLAIN_BINARY_HEADER_BYTES ||
	    input[0] != TRACE_MAGIC_0 ||
	    input[1] != TRACE_MAGIC_1 ||
	    input[2] != TRACE_MAGIC_2 ||
	    input[3] != TRACE_MAGIC_3) {
		return PQCP_FLEET_POLICY_EXPLAIN_MALFORMED;
	}
	if (read_u16(input + 4U) !=
	    PQCP_FLEET_POLICY_EXPLAIN_BINARY_VERSION) {
		return PQCP_FLEET_POLICY_EXPLAIN_UNSUPPORTED;
	}
	if (read_u16(input + 6U) !=
		    PQCP_FLEET_POLICY_EXPLAIN_BINARY_HEADER_BYTES ||
	    read_u16(input + 8U) !=
		    PQCP_FLEET_POLICY_EXPLAIN_BINARY_EVENT_BYTES ||
	    read_u16(input + 10U) != 0U || input[59] != 0U ||
	    (input[57] != 0U && input[57] != 1U) ||
	    (input[58] != 0U && input[58] != 1U)) {
		return PQCP_FLEET_POLICY_EXPLAIN_MALFORMED;
	}
	return PQCP_FLEET_POLICY_EXPLAIN_OK;
}

int pqcp_fleet_policy_trace_init(
	struct pqcp_fleet_policy_trace *trace,
	struct pqcp_fleet_policy_trace_event *events,
	size_t capacity,
	struct pqcp_fleet_policy_correlation_id correlation_id)
{
	if (trace == NULL || events == NULL || capacity == 0U ||
	    capacity > SIZE_MAX / sizeof(*events)) {
		return PQCP_FLEET_POLICY_EXPLAIN_INVALID;
	}
	memset(trace, 0, sizeof(*trace));
	memset(events, 0, sizeof(*events) * capacity);
	trace->schema_version =
		PQCP_FLEET_POLICY_EXPLAIN_SCHEMA_VERSION;
	trace->correlation_id = correlation_id;
	trace->events = events;
	trace->capacity = capacity;
	trace->next_event_id = 1U;
	trace->audit_next_event_id = 1U;
	trace->sampled = true;
	return PQCP_FLEET_POLICY_EXPLAIN_OK;
}

int pqcp_fleet_policy_trace_reset(
	struct pqcp_fleet_policy_trace *trace,
	struct pqcp_fleet_policy_correlation_id correlation_id)
{
	struct pqcp_fleet_policy_trace_event *events;
	size_t capacity;

	if (!trace_valid(trace)) {
		return PQCP_FLEET_POLICY_EXPLAIN_INVALID;
	}
	events = trace->events;
	capacity = trace->capacity;
	return pqcp_fleet_policy_trace_init(
		trace, events, capacity, correlation_id);
}

int pqcp_fleet_policy_trace_set_sampling(
	struct pqcp_fleet_policy_trace *trace,
	const struct pqcp_fleet_policy_sampling *sampling)
{
	uint64_t hash;

	if (!trace_valid(trace) || sampling == NULL ||
	    sampling->denominator == 0U ||
	    sampling->numerator > sampling->denominator) {
		return PQCP_FLEET_POLICY_EXPLAIN_INVALID;
	}
	hash = mix64(trace->correlation_id.high ^ sampling->salt);
	hash ^= mix64(trace->correlation_id.low +
		      UINT64_C(0x9e3779b97f4a7c15));
	trace->sample_hash = mix64(hash);
	trace->sampled =
		sampling->numerator == sampling->denominator ||
		(sampling->numerator != 0U &&
		 trace->sample_hash % sampling->denominator <
			 sampling->numerator);
	return PQCP_FLEET_POLICY_EXPLAIN_OK;
}

bool pqcp_fleet_policy_trace_should_retain(
	const struct pqcp_fleet_policy_trace *trace)
{
	if (!trace_valid(trace)) {
		return false;
	}
	return trace->sampled ||
	       trace->final_decision ==
		       PQCP_FLEET_POLICY_TRACE_DECISION_DENY ||
	       trace->final_decision ==
		       PQCP_FLEET_POLICY_TRACE_DECISION_QUARANTINE;
}

int pqcp_fleet_policy_trace_record(
	struct pqcp_fleet_policy_trace *trace,
	const struct pqcp_fleet_policy_trace_event_input *input,
	uint64_t *event_id)
{
	struct pqcp_fleet_policy_trace_event event;
	size_t index;

	if (!trace_valid(trace) || input == NULL ||
	    !event_type_valid(input->type) ||
	    !redaction_valid(input->redaction) ||
	    !decision_valid(input->decision) ||
	    (input->flags & ~TRACE_EVENT_FLAG_MASK) != 0U ||
	    input->parent_id >= trace->next_event_id ||
	    trace->terminal ||
	    trace->next_event_id == UINT64_MAX) {
		return PQCP_FLEET_POLICY_EXPLAIN_INVALID;
	}
	if (input->type == PQCP_FLEET_POLICY_TRACE_EVENT_DECISION) {
		if (input->decision ==
		    PQCP_FLEET_POLICY_TRACE_DECISION_NONE) {
			return PQCP_FLEET_POLICY_EXPLAIN_INVALID;
		}
	} else if (input->decision !=
			   PQCP_FLEET_POLICY_TRACE_DECISION_NONE ||
		   (input->flags &
		    PQCP_FLEET_POLICY_TRACE_EVENT_TERMINAL) != 0U) {
		return PQCP_FLEET_POLICY_EXPLAIN_INVALID;
	}
	memset(&event, 0, sizeof(event));
	event.event_id = trace->next_event_id++;
	event.parent_id = input->parent_id;
	event.type = input->type;
	event.redaction = input->redaction;
	event.decision = input->decision;
	event.flags = input->flags;
	event.reason = input->reason;
	event.key = input->key;
	event.detail = input->detail;
	event.value = input->value;
	if (input->type == PQCP_FLEET_POLICY_TRACE_EVENT_DECISION) {
		event.flags |= PQCP_FLEET_POLICY_TRACE_EVENT_TERMINAL;
		trace->final_decision = input->decision;
		trace->final_reason = input->reason;
		trace->terminal = true;
	}
	if (trace->count == trace->capacity) {
		const uint64_t evicted_id =
			trace->events[trace->start].event_id;

		if (trace->audit_next_event_id <= evicted_id) {
			const uint64_t lost =
				evicted_id -
				trace->audit_next_event_id + 1U;

			trace->audit_dropped_count =
				saturating_add_u64(
					trace->audit_dropped_count,
					lost);
			trace->audit_next_event_id =
				evicted_id + 1U;
		}
		trace->start =
			(trace->start + 1U) % trace->capacity;
		trace->dropped_count =
			saturating_add_u64(
				trace->dropped_count, 1U);
	} else {
		trace->count++;
	}
	index = (trace->start + trace->count - 1U) %
		trace->capacity;
	trace->events[index] = event;
	if (event_id != NULL) {
		*event_id = event.event_id;
	}
	return PQCP_FLEET_POLICY_EXPLAIN_OK;
}

static int record_typed(
	struct pqcp_fleet_policy_trace *trace,
	uint64_t parent_id,
	enum pqcp_fleet_policy_trace_event_type type,
	uint32_t key,
	uint32_t detail,
	uint64_t value,
	uint32_t reason,
	enum pqcp_fleet_policy_redaction_class redaction,
	uint64_t *event_id)
{
	struct pqcp_fleet_policy_trace_event_input input;

	memset(&input, 0, sizeof(input));
	input.parent_id = parent_id;
	input.type = type;
	input.redaction = redaction;
	input.reason = reason;
	input.key = key;
	input.detail = detail;
	input.value = value;
	return pqcp_fleet_policy_trace_record(
		trace, &input, event_id);
}

int pqcp_fleet_policy_trace_instruction(
	struct pqcp_fleet_policy_trace *trace,
	uint64_t parent_id,
	uint32_t opcode,
	uint32_t program_counter,
	uint64_t result,
	uint32_t reason,
	enum pqcp_fleet_policy_redaction_class redaction,
	uint64_t *event_id)
{
	return record_typed(
		trace, parent_id,
		PQCP_FLEET_POLICY_TRACE_EVENT_INSTRUCTION,
		opcode, program_counter, result, reason,
		redaction, event_id);
}

int pqcp_fleet_policy_trace_rule(
	struct pqcp_fleet_policy_trace *trace,
	uint64_t parent_id,
	uint32_t rule_id,
	uint32_t priority,
	uint64_t result,
	uint32_t reason,
	enum pqcp_fleet_policy_redaction_class redaction,
	uint64_t *event_id)
{
	return record_typed(
		trace, parent_id, PQCP_FLEET_POLICY_TRACE_EVENT_RULE,
		rule_id, priority, result, reason,
		redaction, event_id);
}

int pqcp_fleet_policy_trace_claim(
	struct pqcp_fleet_policy_trace *trace,
	uint64_t parent_id,
	uint32_t claim_id,
	uint32_t operation,
	uint64_t value,
	uint32_t reason,
	enum pqcp_fleet_policy_redaction_class redaction,
	uint64_t *event_id)
{
	return record_typed(
		trace, parent_id, PQCP_FLEET_POLICY_TRACE_EVENT_CLAIM,
		claim_id, operation, value, reason,
		redaction, event_id);
}

int pqcp_fleet_policy_trace_builtin(
	struct pqcp_fleet_policy_trace *trace,
	uint64_t parent_id,
	uint32_t builtin_id,
	uint32_t result,
	uint64_t value,
	uint32_t reason,
	enum pqcp_fleet_policy_redaction_class redaction,
	uint64_t *event_id)
{
	return record_typed(
		trace, parent_id,
		PQCP_FLEET_POLICY_TRACE_EVENT_BUILTIN,
		builtin_id, result, value, reason,
		redaction, event_id);
}

int pqcp_fleet_policy_trace_decide(
	struct pqcp_fleet_policy_trace *trace,
	uint64_t parent_id,
	enum pqcp_fleet_policy_trace_decision decision,
	uint32_t reason,
	uint32_t rule_id,
	uint32_t priority,
	uint64_t metadata,
	enum pqcp_fleet_policy_redaction_class redaction,
	uint64_t *event_id)
{
	struct pqcp_fleet_policy_trace_event_input input;

	memset(&input, 0, sizeof(input));
	input.parent_id = parent_id;
	input.type = PQCP_FLEET_POLICY_TRACE_EVENT_DECISION;
	input.redaction = redaction;
	input.decision = decision;
	input.reason = reason;
	input.key = rule_id;
	input.detail = priority;
	input.value = metadata;
	return pqcp_fleet_policy_trace_record(
		trace, &input, event_id);
}

const struct pqcp_fleet_policy_trace_event *
pqcp_fleet_policy_trace_event_at(
	const struct pqcp_fleet_policy_trace *trace,
	size_t index)
{
	return event_at(trace, index);
}

const char *pqcp_fleet_policy_trace_event_type_name(
	enum pqcp_fleet_policy_trace_event_type type)
{
	switch (type) {
	case PQCP_FLEET_POLICY_TRACE_EVENT_INSTRUCTION:
		return "instruction";
	case PQCP_FLEET_POLICY_TRACE_EVENT_RULE:
		return "rule";
	case PQCP_FLEET_POLICY_TRACE_EVENT_CLAIM:
		return "claim";
	case PQCP_FLEET_POLICY_TRACE_EVENT_BUILTIN:
		return "builtin";
	case PQCP_FLEET_POLICY_TRACE_EVENT_DECISION:
		return "decision";
	default:
		return "unknown";
	}
}

const char *pqcp_fleet_policy_trace_decision_name(
	enum pqcp_fleet_policy_trace_decision decision)
{
	switch (decision) {
	case PQCP_FLEET_POLICY_TRACE_DECISION_NONE:
		return "none";
	case PQCP_FLEET_POLICY_TRACE_DECISION_ALLOW:
		return "allow";
	case PQCP_FLEET_POLICY_TRACE_DECISION_DENY:
		return "deny";
	case PQCP_FLEET_POLICY_TRACE_DECISION_REQUIRE_RECOVERY:
		return "require-recovery";
	case PQCP_FLEET_POLICY_TRACE_DECISION_QUARANTINE:
		return "quarantine";
	default:
		return "unknown";
	}
}

const char *pqcp_fleet_policy_trace_reason_name(uint32_t reason)
{
	switch (reason) {
	case PQCP_FLEET_POLICY_TRACE_REASON_NONE:
		return "none";
	case PQCP_FLEET_POLICY_TRACE_REASON_INSTRUCTION_EXECUTED:
		return "instruction-executed";
	case PQCP_FLEET_POLICY_TRACE_REASON_INSTRUCTION_FAILED:
		return "instruction-failed";
	case PQCP_FLEET_POLICY_TRACE_REASON_RULE_EVALUATED:
		return "rule-evaluated";
	case PQCP_FLEET_POLICY_TRACE_REASON_RULE_MATCHED:
		return "rule-matched";
	case PQCP_FLEET_POLICY_TRACE_REASON_RULE_REJECTED:
		return "rule-rejected";
	case PQCP_FLEET_POLICY_TRACE_REASON_RULE_PREEMPTED:
		return "rule-preempted";
	case PQCP_FLEET_POLICY_TRACE_REASON_CLAIM_PRESENT:
		return "claim-present";
	case PQCP_FLEET_POLICY_TRACE_REASON_CLAIM_MISSING:
		return "claim-missing";
	case PQCP_FLEET_POLICY_TRACE_REASON_CLAIM_MISMATCH:
		return "claim-mismatch";
	case PQCP_FLEET_POLICY_TRACE_REASON_BUILTIN_TRUE:
		return "builtin-true";
	case PQCP_FLEET_POLICY_TRACE_REASON_BUILTIN_FALSE:
		return "builtin-false";
	case PQCP_FLEET_POLICY_TRACE_REASON_BUILTIN_ERROR:
		return "builtin-error";
	case PQCP_FLEET_POLICY_TRACE_REASON_DECISION_RULE:
		return "decision-rule";
	case PQCP_FLEET_POLICY_TRACE_REASON_DECISION_DEFAULT:
		return "decision-default";
	case PQCP_FLEET_POLICY_TRACE_REASON_DECISION_HARD_GUARD:
		return "decision-hard-guard";
	case PQCP_FLEET_POLICY_TRACE_REASON_REVOKED:
		return "revoked";
	case PQCP_FLEET_POLICY_TRACE_REASON_CREDENTIAL_EXPIRED:
		return "credential-expired";
	case PQCP_FLEET_POLICY_TRACE_REASON_CAPABILITY:
		return "capability";
	case PQCP_FLEET_POLICY_TRACE_REASON_SECURITY_LEVEL:
		return "security-level";
	case PQCP_FLEET_POLICY_TRACE_REASON_CHANNEL_IDENTITY:
		return "channel-identity";
	case PQCP_FLEET_POLICY_TRACE_REASON_POLICY_EPOCH:
		return "policy-epoch";
	case PQCP_FLEET_POLICY_TRACE_REASON_REVOCATION_EPOCH:
		return "revocation-epoch";
	case PQCP_FLEET_POLICY_TRACE_REASON_RISK:
		return "risk";
	case PQCP_FLEET_POLICY_TRACE_REASON_TIME_WINDOW:
		return "time-window";
	case PQCP_FLEET_POLICY_TRACE_REASON_DEVICE_STATE:
		return "device-state";
	case PQCP_FLEET_POLICY_TRACE_REASON_OFFLINE:
		return "offline";
	case PQCP_FLEET_POLICY_TRACE_REASON_RESOURCE_LIMIT:
		return "resource-limit";
	case PQCP_FLEET_POLICY_TRACE_REASON_MALFORMED_INPUT:
		return "malformed-input";
	case PQCP_FLEET_POLICY_TRACE_REASON_INTERNAL_ERROR:
		return "internal-error";
	default:
		return "unknown";
	}
}

const char *pqcp_fleet_policy_redaction_name(
	enum pqcp_fleet_policy_redaction_class redaction)
{
	switch (redaction) {
	case PQCP_FLEET_POLICY_REDACTION_PUBLIC:
		return "public";
	case PQCP_FLEET_POLICY_REDACTION_INTERNAL:
		return "internal";
	case PQCP_FLEET_POLICY_REDACTION_SENSITIVE:
		return "sensitive";
	case PQCP_FLEET_POLICY_REDACTION_SECRET:
		return "secret";
	default:
		return "unknown";
	}
}

static void text_append_char(
	struct text_writer *writer,
	char value)
{
	if (writer->capacity != 0U &&
	    writer->length < writer->capacity - 1U) {
		writer->output[writer->length] = value;
	}
	if (writer->length != SIZE_MAX) {
		writer->length++;
	}
}

static void text_append(
	struct text_writer *writer,
	const char *value)
{
	while (*value != '\0') {
		text_append_char(writer, *value++);
	}
}

static void text_append_u64(
	struct text_writer *writer,
	uint64_t value)
{
	char digits[20];
	size_t count = 0U;

	do {
		digits[count++] = (char)('0' + value % 10U);
		value /= 10U;
	} while (value != 0U);
	while (count != 0U) {
		text_append_char(writer, digits[--count]);
	}
}

static void text_append_hex64(
	struct text_writer *writer,
	uint64_t value)
{
	static const char hex[] = "0123456789abcdef";

	for (size_t index = 16U; index != 0U; --index) {
		const unsigned int shift =
			(unsigned int)((index - 1U) * 4U);

		text_append_char(
			writer, hex[(value >> shift) & 0xfU]);
	}
}

static void text_finish(struct text_writer *writer)
{
	if (writer->capacity != 0U) {
		const size_t index =
			writer->length < writer->capacity ?
				writer->length :
				writer->capacity - 1U;

		writer->output[index] = '\0';
	}
}

int pqcp_fleet_policy_trace_format(
	const struct pqcp_fleet_policy_trace *trace,
	const struct pqcp_fleet_policy_redaction *redaction,
	char *output,
	size_t capacity,
	size_t *length)
{
	struct pqcp_fleet_policy_redaction selected;
	struct text_writer writer;

	if (!trace_valid(trace) || length == NULL ||
	    (output == NULL && capacity != 0U)) {
		return PQCP_FLEET_POLICY_EXPLAIN_INVALID;
	}
	selected = redaction != NULL ? *redaction :
		default_redaction();
	if (!redaction_valid(selected.maximum_visible)) {
		return PQCP_FLEET_POLICY_EXPLAIN_INVALID;
	}
	writer.output = output;
	writer.capacity = capacity;
	writer.length = 0U;
	text_append(&writer, "trace correlation=");
	text_append_hex64(&writer, trace->correlation_id.high);
	text_append_hex64(&writer, trace->correlation_id.low);
	text_append(&writer, " decision=");
	text_append(
		&writer,
		pqcp_fleet_policy_trace_decision_name(
			trace->final_decision));
	text_append(&writer, " reason=");
	text_append(
		&writer,
		pqcp_fleet_policy_trace_reason_name(
			trace->final_reason));
	text_append(&writer, " events=");
	text_append_u64(&writer, trace->count);
	text_append(&writer, " dropped=");
	text_append_u64(&writer, trace->dropped_count);
	text_append(&writer, " sampled=");
	text_append(&writer, trace->sampled ? "yes" : "no");
	text_append_char(&writer, '\n');
	for (size_t index = 0U; index < trace->count; ++index) {
		const struct pqcp_fleet_policy_trace_event *event =
			event_at(trace, index);

		text_append_char(&writer, '#');
		text_append_u64(&writer, event->event_id);
		text_append(&writer, " parent=");
		if (selected.retain_causal_parents &&
		    event->parent_id != 0U) {
			text_append_char(&writer, '#');
			text_append_u64(&writer, event->parent_id);
		} else {
			text_append_char(&writer, '-');
		}
		text_append(&writer, " type=");
		text_append(
			&writer,
			pqcp_fleet_policy_trace_event_type_name(
				event->type));
		text_append(&writer, " reason=");
		text_append(
			&writer,
			pqcp_fleet_policy_trace_reason_name(
				event->reason));
		text_append(&writer, " class=");
		text_append(
			&writer,
			pqcp_fleet_policy_redaction_name(
				event->redaction));
		if (!payload_visible(event, &selected)) {
			text_append(&writer, " payload=<redacted>");
		} else {
			text_append(&writer, " key=");
			text_append_u64(&writer, event->key);
			text_append(&writer, " detail=");
			text_append_u64(&writer, event->detail);
			text_append(&writer, " value=");
			text_append_u64(&writer, event->value);
		}
		if (event->type ==
		    PQCP_FLEET_POLICY_TRACE_EVENT_DECISION) {
			text_append(&writer, " decision=");
			text_append(
				&writer,
				pqcp_fleet_policy_trace_decision_name(
					event->decision));
		}
		text_append_char(&writer, '\n');
	}
	text_finish(&writer);
	*length = writer.length;
	return writer.length >= capacity ?
		PQCP_FLEET_POLICY_EXPLAIN_TRUNCATED :
		PQCP_FLEET_POLICY_EXPLAIN_OK;
}

int pqcp_fleet_policy_trace_export(
	const struct pqcp_fleet_policy_trace *trace,
	const struct pqcp_fleet_policy_redaction *redaction,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	struct pqcp_fleet_policy_redaction selected;
	const struct pqcp_fleet_policy_trace_event *first;
	size_t required;

	if (!trace_valid(trace) || length == NULL ||
	    (output == NULL && capacity != 0U)) {
		return PQCP_FLEET_POLICY_EXPLAIN_INVALID;
	}
	selected = redaction != NULL ? *redaction :
		default_redaction();
	if (!redaction_valid(selected.maximum_visible)) {
		return PQCP_FLEET_POLICY_EXPLAIN_INVALID;
	}
	if (trace->count > UINT32_MAX ||
	    size_for_events(trace->count, &required) !=
		    PQCP_FLEET_POLICY_EXPLAIN_OK) {
		return PQCP_FLEET_POLICY_EXPLAIN_NO_SPACE;
	}
	*length = required;
	if (output == NULL || capacity < required) {
		return PQCP_FLEET_POLICY_EXPLAIN_NO_SPACE;
	}
	first = event_at(trace, 0U);
	encode_header(
		trace, (uint32_t)trace->count,
		first != NULL ? first->event_id : 0U, output);
	for (size_t index = 0U; index < trace->count; ++index) {
		const struct pqcp_fleet_policy_trace_event *event =
			event_at(trace, index);
		const struct pqcp_fleet_policy_trace_event redacted =
			redact_event(event, &selected);

		encode_event(
			&redacted,
			output +
			PQCP_FLEET_POLICY_EXPLAIN_BINARY_HEADER_BYTES +
			index *
			PQCP_FLEET_POLICY_EXPLAIN_BINARY_EVENT_BYTES);
	}
	return PQCP_FLEET_POLICY_EXPLAIN_OK;
}

int pqcp_fleet_policy_trace_import(
	struct pqcp_fleet_policy_trace *trace,
	const uint8_t *input,
	size_t length)
{
	struct pqcp_fleet_policy_correlation_id correlation;
	enum pqcp_fleet_policy_trace_decision final_decision;
	struct pqcp_fleet_policy_trace_event last_event;
	uint64_t previous_id = 0U;
	uint64_t first_id;
	uint64_t next_id;
	uint64_t dropped;
	uint32_t final_reason;
	uint32_t count;
	size_t required;
	int ret;

	if (!trace_valid(trace) || input == NULL) {
		return PQCP_FLEET_POLICY_EXPLAIN_INVALID;
	}
	ret = header_validate(input, length);
	if (ret != PQCP_FLEET_POLICY_EXPLAIN_OK) {
		return ret;
	}
	count = read_u32(input + 12U);
	if (count > trace->capacity ||
	    size_for_events(count, &required) !=
		    PQCP_FLEET_POLICY_EXPLAIN_OK ||
	    length != required) {
		return count > trace->capacity ?
			PQCP_FLEET_POLICY_EXPLAIN_NO_SPACE :
			PQCP_FLEET_POLICY_EXPLAIN_MALFORMED;
	}
	final_decision =
		(enum pqcp_fleet_policy_trace_decision)input[56];
	if (!decision_valid(final_decision)) {
		return PQCP_FLEET_POLICY_EXPLAIN_MALFORMED;
	}
	first_id = read_u64(input + 64U);
	next_id = read_u64(input + 40U);
	dropped = read_u64(input + 16U);
	if (next_id == 0U ||
	    (count == 0U &&
	     (first_id != 0U || next_id != 1U || dropped != 0U)) ||
	    (count != 0U &&
	     (first_id == 0U ||
	      dropped != first_id - 1U ||
	      UINT64_MAX - first_id < count ||
	      first_id + count != next_id))) {
		return PQCP_FLEET_POLICY_EXPLAIN_MALFORMED;
	}
	memset(&last_event, 0, sizeof(last_event));
	for (size_t index = 0U; index < count; ++index) {
		struct pqcp_fleet_policy_trace_event event;

		ret = decode_event(
			input +
			PQCP_FLEET_POLICY_EXPLAIN_BINARY_HEADER_BYTES +
			index *
			PQCP_FLEET_POLICY_EXPLAIN_BINARY_EVENT_BYTES,
			&event);
		if (ret != PQCP_FLEET_POLICY_EXPLAIN_OK ||
		    (index == 0U && event.event_id != first_id) ||
		    (index != 0U &&
		     event.event_id != previous_id + 1U) ||
		    (event.type ==
			     PQCP_FLEET_POLICY_TRACE_EVENT_DECISION &&
		     index + 1U != count)) {
			return PQCP_FLEET_POLICY_EXPLAIN_MALFORMED;
		}
		previous_id = event.event_id;
		last_event = event;
	}
	final_reason = read_u32(input + 60U);
	if (input[58] != 0U) {
		if (count == 0U ||
		    final_decision ==
			    PQCP_FLEET_POLICY_TRACE_DECISION_NONE ||
		    last_event.type !=
			    PQCP_FLEET_POLICY_TRACE_EVENT_DECISION ||
		    last_event.decision != final_decision ||
		    last_event.reason != final_reason) {
			return PQCP_FLEET_POLICY_EXPLAIN_MALFORMED;
		}
	} else if (final_decision !=
			   PQCP_FLEET_POLICY_TRACE_DECISION_NONE ||
		   final_reason !=
			   PQCP_FLEET_POLICY_TRACE_REASON_NONE ||
		   (count != 0U &&
		    last_event.type ==
			    PQCP_FLEET_POLICY_TRACE_EVENT_DECISION)) {
		return PQCP_FLEET_POLICY_EXPLAIN_MALFORMED;
	}
	correlation.high = read_u64(input + 24U);
	correlation.low = read_u64(input + 32U);
	memset(trace->events, 0,
	       sizeof(*trace->events) * trace->capacity);
	trace->correlation_id = correlation;
	trace->start = 0U;
	trace->count = count;
	trace->next_event_id = next_id;
	trace->dropped_count = dropped;
	trace->audit_dropped_count = read_u64(input + 48U);
	trace->final_decision = final_decision;
	trace->final_reason = final_reason;
	trace->sampled = input[57] != 0U;
	trace->terminal = input[58] != 0U;
	trace->sample_hash = 0U;
	for (size_t index = 0U; index < count; ++index) {
		(void)decode_event(
			input +
			PQCP_FLEET_POLICY_EXPLAIN_BINARY_HEADER_BYTES +
			index *
			PQCP_FLEET_POLICY_EXPLAIN_BINARY_EVENT_BYTES,
			&trace->events[index]);
	}
	trace->audit_next_event_id =
		count != 0U ? first_id : next_id;
	return PQCP_FLEET_POLICY_EXPLAIN_OK;
}

static int digest_update(
	const struct pqcp_fleet_policy_digest_callbacks *callbacks,
	const uint8_t *data,
	size_t length)
{
	return callbacks->update(
		callbacks->context, data, length) == 0 ?
		PQCP_FLEET_POLICY_EXPLAIN_OK :
		PQCP_FLEET_POLICY_EXPLAIN_CALLBACK_ERROR;
}

int pqcp_fleet_policy_trace_proof(
	const struct pqcp_fleet_policy_trace *trace,
	const struct pqcp_fleet_policy_redaction *redaction,
	const struct pqcp_fleet_policy_digest_callbacks *callbacks,
	struct pqcp_fleet_policy_proof_summary *summary)
{
	struct pqcp_fleet_policy_redaction selected;
	struct pqcp_fleet_policy_trace canonical;
	const struct pqcp_fleet_policy_trace_event *first;
	const struct pqcp_fleet_policy_trace_event *last;
	uint8_t buffer[PQCP_FLEET_POLICY_EXPLAIN_BINARY_HEADER_BYTES];
	bool redacted_output = false;
	int ret;

	if (!trace_valid(trace) || callbacks == NULL ||
	    callbacks->begin == NULL || callbacks->update == NULL ||
	    callbacks->final == NULL || summary == NULL) {
		return PQCP_FLEET_POLICY_EXPLAIN_INVALID;
	}
	selected = redaction != NULL ? *redaction :
		default_redaction();
	if (!redaction_valid(selected.maximum_visible)) {
		return PQCP_FLEET_POLICY_EXPLAIN_INVALID;
	}
	if (trace->count > UINT32_MAX) {
		return PQCP_FLEET_POLICY_EXPLAIN_NO_SPACE;
	}
	memset(summary, 0, sizeof(*summary));
	if (callbacks->begin(callbacks->context) != 0) {
		return PQCP_FLEET_POLICY_EXPLAIN_CALLBACK_ERROR;
	}
	first = event_at(trace, 0U);
	last = trace->count != 0U ?
		event_at(trace, trace->count - 1U) : NULL;
	canonical = *trace;
	canonical.audit_dropped_count = 0U;
	encode_header(
		&canonical, (uint32_t)trace->count,
		first != NULL ? first->event_id : 0U, buffer);
	ret = digest_update(callbacks, buffer, sizeof(buffer));
	for (size_t index = 0U;
	     ret == PQCP_FLEET_POLICY_EXPLAIN_OK &&
	     index < trace->count; ++index) {
		const struct pqcp_fleet_policy_trace_event *event =
			event_at(trace, index);
		const struct pqcp_fleet_policy_trace_event redacted =
			redact_event(event, &selected);

		encode_event(&redacted, buffer);
		if (!payload_visible(event, &selected)) {
			redacted_output = true;
		}
		ret = digest_update(
			callbacks, buffer,
			PQCP_FLEET_POLICY_EXPLAIN_BINARY_EVENT_BYTES);
	}
	if (ret != PQCP_FLEET_POLICY_EXPLAIN_OK ||
	    callbacks->final(
		    callbacks->context, summary->digest,
		    sizeof(summary->digest),
		    &summary->digest_length) != 0 ||
	    summary->digest_length == 0U ||
	    summary->digest_length > sizeof(summary->digest)) {
		memset(summary, 0, sizeof(*summary));
		return PQCP_FLEET_POLICY_EXPLAIN_CALLBACK_ERROR;
	}
	summary->schema_version =
		PQCP_FLEET_POLICY_EXPLAIN_SCHEMA_VERSION;
	summary->correlation_id = trace->correlation_id;
	summary->first_event_id =
		first != NULL ? first->event_id : 0U;
	summary->last_event_id =
		last != NULL ? last->event_id : 0U;
	summary->recorded_count = trace->count;
	summary->dropped_count = trace->dropped_count;
	summary->decision = trace->final_decision;
	summary->reason = trace->final_reason;
	summary->redacted =
		redacted_output || !selected.retain_causal_parents;
	return PQCP_FLEET_POLICY_EXPLAIN_OK;
}

static size_t pending_audit_events(
	const struct pqcp_fleet_policy_trace *trace)
{
	size_t pending = 0U;

	for (size_t index = 0U; index < trace->count; ++index) {
		if (event_at(trace, index)->event_id >=
		    trace->audit_next_event_id) {
			pending++;
		}
	}
	return pending;
}

int pqcp_fleet_policy_trace_audit_flush(
	struct pqcp_fleet_policy_trace *trace,
	const struct pqcp_fleet_policy_redaction *redaction,
	const struct pqcp_fleet_policy_audit_sink *sink,
	size_t maximum_events,
	struct pqcp_fleet_policy_audit_result *result)
{
	struct pqcp_fleet_policy_redaction selected;
	uint8_t frame[PQCP_FLEET_POLICY_EXPLAIN_AUDIT_FRAME_BYTES];

	if (!trace_valid(trace) || sink == NULL ||
	    sink->write == NULL || result == NULL) {
		return PQCP_FLEET_POLICY_EXPLAIN_INVALID;
	}
	selected = redaction != NULL ? *redaction :
		default_redaction();
	if (!redaction_valid(selected.maximum_visible)) {
		return PQCP_FLEET_POLICY_EXPLAIN_INVALID;
	}
	memset(result, 0, sizeof(*result));
	result->dropped = trace->audit_dropped_count;
	if (!pqcp_fleet_policy_trace_should_retain(trace)) {
		result->sampled_out = true;
		result->pending = pending_audit_events(trace);
		return PQCP_FLEET_POLICY_EXPLAIN_OK;
	}
	for (size_t index = 0U;
	     index < trace->count &&
	     (maximum_events == 0U ||
	      result->emitted < maximum_events); ++index) {
		const struct pqcp_fleet_policy_trace_event *event =
			event_at(trace, index);
		struct pqcp_fleet_policy_trace_event redacted;
		enum pqcp_fleet_policy_audit_sink_result sink_result;

		if (event->event_id < trace->audit_next_event_id) {
			continue;
		}
		encode_header(
			trace, 1U, event->event_id, frame);
		redacted = redact_event(event, &selected);
		encode_event(
			&redacted,
			frame +
			PQCP_FLEET_POLICY_EXPLAIN_BINARY_HEADER_BYTES);
		sink_result = sink->write(
			sink->context, frame, sizeof(frame),
			&trace->correlation_id, event->event_id);
		if (sink_result ==
		    PQCP_FLEET_POLICY_AUDIT_SINK_BACKPRESSURE) {
			result->backpressured = true;
			break;
		}
		if (sink_result !=
		    PQCP_FLEET_POLICY_AUDIT_SINK_ACCEPTED) {
			result->pending =
				pending_audit_events(trace);
			return PQCP_FLEET_POLICY_EXPLAIN_CALLBACK_ERROR;
		}
		trace->audit_next_event_id = event->event_id + 1U;
		result->emitted++;
	}
	result->pending = pending_audit_events(trace);
	return PQCP_FLEET_POLICY_EXPLAIN_OK;
}

static uint64_t causal_distance(
	const struct pqcp_fleet_policy_trace_event *event)
{
	return event->parent_id == 0U ?
		0U : event->event_id - event->parent_id;
}

static int divergence_set(
	struct pqcp_fleet_policy_trace_divergence *divergence,
	enum pqcp_fleet_policy_trace_divergence_kind kind,
	size_t index,
	const struct pqcp_fleet_policy_trace_event *left,
	const struct pqcp_fleet_policy_trace_event *right,
	uint64_t left_value,
	uint64_t right_value)
{
	divergence->kind = kind;
	divergence->event_index = index;
	divergence->left_event_id =
		left != NULL ? left->event_id : 0U;
	divergence->right_event_id =
		right != NULL ? right->event_id : 0U;
	divergence->left_value = left_value;
	divergence->right_value = right_value;
	return PQCP_FLEET_POLICY_EXPLAIN_OK;
}

int pqcp_fleet_policy_trace_compare(
	const struct pqcp_fleet_policy_trace *left,
	const struct pqcp_fleet_policy_trace *right,
	struct pqcp_fleet_policy_trace_divergence *divergence)
{
	size_t common;

	if (!trace_valid(left) || !trace_valid(right) ||
	    divergence == NULL) {
		return PQCP_FLEET_POLICY_EXPLAIN_INVALID;
	}
	memset(divergence, 0, sizeof(*divergence));
	if (left->dropped_count != right->dropped_count) {
		return divergence_set(
			divergence,
			PQCP_FLEET_POLICY_TRACE_DIVERGENCE_DROPS,
			0U, event_at(left, 0U), event_at(right, 0U),
			left->dropped_count, right->dropped_count);
	}
	common = left->count < right->count ?
		left->count : right->count;
	for (size_t index = 0U; index < common; ++index) {
		const struct pqcp_fleet_policy_trace_event *a =
			event_at(left, index);
		const struct pqcp_fleet_policy_trace_event *b =
			event_at(right, index);

#define COMPARE_FIELD(field, kind) \
		if (a->field != b->field) { \
			return divergence_set( \
				divergence, kind, index, a, b, \
				(uint64_t)a->field, \
				(uint64_t)b->field); \
		}

		COMPARE_FIELD(
			type,
			PQCP_FLEET_POLICY_TRACE_DIVERGENCE_TYPE);
		COMPARE_FIELD(
			reason,
			PQCP_FLEET_POLICY_TRACE_DIVERGENCE_REASON);
		COMPARE_FIELD(
			key,
			PQCP_FLEET_POLICY_TRACE_DIVERGENCE_KEY);
		COMPARE_FIELD(
			detail,
			PQCP_FLEET_POLICY_TRACE_DIVERGENCE_DETAIL);
		COMPARE_FIELD(
			value,
			PQCP_FLEET_POLICY_TRACE_DIVERGENCE_VALUE);
		COMPARE_FIELD(
			decision,
			PQCP_FLEET_POLICY_TRACE_DIVERGENCE_DECISION);
		COMPARE_FIELD(
			redaction,
			PQCP_FLEET_POLICY_TRACE_DIVERGENCE_REDACTION);
		COMPARE_FIELD(
			flags,
			PQCP_FLEET_POLICY_TRACE_DIVERGENCE_FLAGS);
#undef COMPARE_FIELD
		if (causal_distance(a) != causal_distance(b)) {
			return divergence_set(
				divergence,
				PQCP_FLEET_POLICY_TRACE_DIVERGENCE_CAUSAL_PARENT,
				index, a, b, causal_distance(a),
				causal_distance(b));
		}
	}
	if (left->count != right->count) {
		return divergence_set(
			divergence,
			PQCP_FLEET_POLICY_TRACE_DIVERGENCE_EVENT_MISSING,
			common, event_at(left, common),
			event_at(right, common),
			left->count, right->count);
	}
	if (left->final_decision != right->final_decision) {
		return divergence_set(
			divergence,
			PQCP_FLEET_POLICY_TRACE_DIVERGENCE_FINAL_DECISION,
			common, NULL, NULL, left->final_decision,
			right->final_decision);
	}
	if (left->final_reason != right->final_reason) {
		return divergence_set(
			divergence,
			PQCP_FLEET_POLICY_TRACE_DIVERGENCE_FINAL_REASON,
			common, NULL, NULL, left->final_reason,
			right->final_reason);
	}
	return PQCP_FLEET_POLICY_EXPLAIN_OK;
}
