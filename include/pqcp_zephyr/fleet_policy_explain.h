/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free, host-portable fleet policy explanation and audit traces.
 *
 * The caller owns all storage and is responsible for synchronization.
 */

#ifndef PQCP_ZEPHYR_FLEET_POLICY_EXPLAIN_H_
#define PQCP_ZEPHYR_FLEET_POLICY_EXPLAIN_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_POLICY_EXPLAIN_SCHEMA_VERSION 1U
#define PQCP_FLEET_POLICY_EXPLAIN_BINARY_VERSION 1U
#define PQCP_FLEET_POLICY_EXPLAIN_DIGEST_MAX_BYTES 64U
#define PQCP_FLEET_POLICY_EXPLAIN_BINARY_HEADER_BYTES 72U
#define PQCP_FLEET_POLICY_EXPLAIN_BINARY_EVENT_BYTES 44U
#define PQCP_FLEET_POLICY_EXPLAIN_AUDIT_FRAME_BYTES 116U

enum pqcp_fleet_policy_explain_status {
	PQCP_FLEET_POLICY_EXPLAIN_OK = 0,
	PQCP_FLEET_POLICY_EXPLAIN_INVALID = -1,
	PQCP_FLEET_POLICY_EXPLAIN_NO_SPACE = -2,
	PQCP_FLEET_POLICY_EXPLAIN_TRUNCATED = -3,
	PQCP_FLEET_POLICY_EXPLAIN_MALFORMED = -4,
	PQCP_FLEET_POLICY_EXPLAIN_UNSUPPORTED = -5,
	PQCP_FLEET_POLICY_EXPLAIN_CALLBACK_ERROR = -6,
};

enum pqcp_fleet_policy_trace_event_type {
	PQCP_FLEET_POLICY_TRACE_EVENT_NONE = 0,
	PQCP_FLEET_POLICY_TRACE_EVENT_INSTRUCTION = 1,
	PQCP_FLEET_POLICY_TRACE_EVENT_RULE = 2,
	PQCP_FLEET_POLICY_TRACE_EVENT_CLAIM = 3,
	PQCP_FLEET_POLICY_TRACE_EVENT_BUILTIN = 4,
	PQCP_FLEET_POLICY_TRACE_EVENT_DECISION = 5,
};

enum pqcp_fleet_policy_redaction_class {
	PQCP_FLEET_POLICY_REDACTION_PUBLIC = 0,
	PQCP_FLEET_POLICY_REDACTION_INTERNAL = 1,
	PQCP_FLEET_POLICY_REDACTION_SENSITIVE = 2,
	PQCP_FLEET_POLICY_REDACTION_SECRET = 3,
};

enum pqcp_fleet_policy_trace_decision {
	PQCP_FLEET_POLICY_TRACE_DECISION_NONE = 0,
	PQCP_FLEET_POLICY_TRACE_DECISION_ALLOW = 1,
	PQCP_FLEET_POLICY_TRACE_DECISION_DENY = 2,
	PQCP_FLEET_POLICY_TRACE_DECISION_REQUIRE_RECOVERY = 3,
	PQCP_FLEET_POLICY_TRACE_DECISION_QUARANTINE = 4,
};

/*
 * Stable reason values are serialized and may be persisted. Existing values
 * must not be renumbered.
 */
enum pqcp_fleet_policy_trace_reason {
	PQCP_FLEET_POLICY_TRACE_REASON_NONE = 0x0000,
	PQCP_FLEET_POLICY_TRACE_REASON_INSTRUCTION_EXECUTED = 0x0101,
	PQCP_FLEET_POLICY_TRACE_REASON_INSTRUCTION_FAILED = 0x0102,
	PQCP_FLEET_POLICY_TRACE_REASON_RULE_EVALUATED = 0x0201,
	PQCP_FLEET_POLICY_TRACE_REASON_RULE_MATCHED = 0x0202,
	PQCP_FLEET_POLICY_TRACE_REASON_RULE_REJECTED = 0x0203,
	PQCP_FLEET_POLICY_TRACE_REASON_RULE_PREEMPTED = 0x0204,
	PQCP_FLEET_POLICY_TRACE_REASON_CLAIM_PRESENT = 0x0301,
	PQCP_FLEET_POLICY_TRACE_REASON_CLAIM_MISSING = 0x0302,
	PQCP_FLEET_POLICY_TRACE_REASON_CLAIM_MISMATCH = 0x0303,
	PQCP_FLEET_POLICY_TRACE_REASON_BUILTIN_TRUE = 0x0401,
	PQCP_FLEET_POLICY_TRACE_REASON_BUILTIN_FALSE = 0x0402,
	PQCP_FLEET_POLICY_TRACE_REASON_BUILTIN_ERROR = 0x0403,
	PQCP_FLEET_POLICY_TRACE_REASON_DECISION_RULE = 0x0501,
	PQCP_FLEET_POLICY_TRACE_REASON_DECISION_DEFAULT = 0x0502,
	PQCP_FLEET_POLICY_TRACE_REASON_DECISION_HARD_GUARD = 0x0503,
	PQCP_FLEET_POLICY_TRACE_REASON_REVOKED = 0x0601,
	PQCP_FLEET_POLICY_TRACE_REASON_CREDENTIAL_EXPIRED = 0x0602,
	PQCP_FLEET_POLICY_TRACE_REASON_CAPABILITY = 0x0603,
	PQCP_FLEET_POLICY_TRACE_REASON_SECURITY_LEVEL = 0x0604,
	PQCP_FLEET_POLICY_TRACE_REASON_CHANNEL_IDENTITY = 0x0605,
	PQCP_FLEET_POLICY_TRACE_REASON_POLICY_EPOCH = 0x0606,
	PQCP_FLEET_POLICY_TRACE_REASON_REVOCATION_EPOCH = 0x0607,
	PQCP_FLEET_POLICY_TRACE_REASON_RISK = 0x0608,
	PQCP_FLEET_POLICY_TRACE_REASON_TIME_WINDOW = 0x0609,
	PQCP_FLEET_POLICY_TRACE_REASON_DEVICE_STATE = 0x060a,
	PQCP_FLEET_POLICY_TRACE_REASON_OFFLINE = 0x060b,
	PQCP_FLEET_POLICY_TRACE_REASON_RESOURCE_LIMIT = 0x0701,
	PQCP_FLEET_POLICY_TRACE_REASON_MALFORMED_INPUT = 0x0702,
	PQCP_FLEET_POLICY_TRACE_REASON_INTERNAL_ERROR = 0x0703,
};

enum pqcp_fleet_policy_trace_event_flag {
	PQCP_FLEET_POLICY_TRACE_EVENT_REDACTED = (1U << 0),
	PQCP_FLEET_POLICY_TRACE_EVENT_TERMINAL = (1U << 1),
	PQCP_FLEET_POLICY_TRACE_EVENT_ERROR = (1U << 2),
};

struct pqcp_fleet_policy_correlation_id {
	uint64_t high;
	uint64_t low;
};

/*
 * key/detail/value are event-specific, stable numeric fields:
 * instruction: key=opcode, detail=program counter, value=result
 * rule:        key=rule id, detail=priority, value=match/result data
 * claim:       key=claim id, detail=operator/result, value=claim value
 * builtin:     key=builtin id, detail=result, value=builtin value
 * decision:    key=rule id, detail=priority, value=decision metadata
 */
struct pqcp_fleet_policy_trace_event {
	uint64_t event_id;
	uint64_t parent_id;
	enum pqcp_fleet_policy_trace_event_type type;
	enum pqcp_fleet_policy_redaction_class redaction;
	enum pqcp_fleet_policy_trace_decision decision;
	uint32_t flags;
	uint32_t reason;
	uint32_t key;
	uint32_t detail;
	uint64_t value;
};

struct pqcp_fleet_policy_trace_event_input {
	uint64_t parent_id;
	enum pqcp_fleet_policy_trace_event_type type;
	enum pqcp_fleet_policy_redaction_class redaction;
	enum pqcp_fleet_policy_trace_decision decision;
	uint32_t flags;
	uint32_t reason;
	uint32_t key;
	uint32_t detail;
	uint64_t value;
};

struct pqcp_fleet_policy_sampling {
	uint32_t numerator;
	uint32_t denominator;
	uint64_t salt;
};

struct pqcp_fleet_policy_redaction {
	enum pqcp_fleet_policy_redaction_class maximum_visible;
	bool retain_causal_parents;
};

struct pqcp_fleet_policy_trace {
	uint32_t schema_version;
	struct pqcp_fleet_policy_correlation_id correlation_id;
	struct pqcp_fleet_policy_trace_event *events;
	size_t capacity;
	size_t start;
	size_t count;
	uint64_t next_event_id;
	uint64_t dropped_count;
	uint64_t audit_next_event_id;
	uint64_t audit_dropped_count;
	uint64_t sample_hash;
	enum pqcp_fleet_policy_trace_decision final_decision;
	uint32_t final_reason;
	bool sampled;
	bool terminal;
};

struct pqcp_fleet_policy_digest_callbacks {
	int (*begin)(void *context);
	int (*update)(
		void *context,
		const uint8_t *data,
		size_t length);
	int (*final)(
		void *context,
		uint8_t *digest,
		size_t capacity,
		size_t *length);
	void *context;
};

struct pqcp_fleet_policy_proof_summary {
	uint32_t schema_version;
	struct pqcp_fleet_policy_correlation_id correlation_id;
	uint64_t first_event_id;
	uint64_t last_event_id;
	uint64_t recorded_count;
	uint64_t dropped_count;
	enum pqcp_fleet_policy_trace_decision decision;
	uint32_t reason;
	uint8_t digest[PQCP_FLEET_POLICY_EXPLAIN_DIGEST_MAX_BYTES];
	size_t digest_length;
	bool redacted;
};

enum pqcp_fleet_policy_audit_sink_result {
	PQCP_FLEET_POLICY_AUDIT_SINK_ACCEPTED = 0,
	PQCP_FLEET_POLICY_AUDIT_SINK_BACKPRESSURE = 1,
	PQCP_FLEET_POLICY_AUDIT_SINK_ERROR = 2,
};

typedef enum pqcp_fleet_policy_audit_sink_result
	(*pqcp_fleet_policy_audit_write_fn)(
		void *context,
		const uint8_t *record,
		size_t length,
		const struct pqcp_fleet_policy_correlation_id *correlation_id,
		uint64_t event_id);

struct pqcp_fleet_policy_audit_sink {
	pqcp_fleet_policy_audit_write_fn write;
	void *context;
};

struct pqcp_fleet_policy_audit_result {
	size_t emitted;
	size_t pending;
	uint64_t dropped;
	bool sampled_out;
	bool backpressured;
};

enum pqcp_fleet_policy_trace_divergence_kind {
	PQCP_FLEET_POLICY_TRACE_DIVERGENCE_NONE = 0,
	PQCP_FLEET_POLICY_TRACE_DIVERGENCE_DROPS,
	PQCP_FLEET_POLICY_TRACE_DIVERGENCE_EVENT_MISSING,
	PQCP_FLEET_POLICY_TRACE_DIVERGENCE_TYPE,
	PQCP_FLEET_POLICY_TRACE_DIVERGENCE_REASON,
	PQCP_FLEET_POLICY_TRACE_DIVERGENCE_KEY,
	PQCP_FLEET_POLICY_TRACE_DIVERGENCE_DETAIL,
	PQCP_FLEET_POLICY_TRACE_DIVERGENCE_VALUE,
	PQCP_FLEET_POLICY_TRACE_DIVERGENCE_DECISION,
	PQCP_FLEET_POLICY_TRACE_DIVERGENCE_REDACTION,
	PQCP_FLEET_POLICY_TRACE_DIVERGENCE_FLAGS,
	PQCP_FLEET_POLICY_TRACE_DIVERGENCE_CAUSAL_PARENT,
	PQCP_FLEET_POLICY_TRACE_DIVERGENCE_FINAL_DECISION,
	PQCP_FLEET_POLICY_TRACE_DIVERGENCE_FINAL_REASON,
};

struct pqcp_fleet_policy_trace_divergence {
	enum pqcp_fleet_policy_trace_divergence_kind kind;
	size_t event_index;
	uint64_t left_event_id;
	uint64_t right_event_id;
	uint64_t left_value;
	uint64_t right_value;
};

int pqcp_fleet_policy_trace_init(
	struct pqcp_fleet_policy_trace *trace,
	struct pqcp_fleet_policy_trace_event *events,
	size_t capacity,
	struct pqcp_fleet_policy_correlation_id correlation_id);

int pqcp_fleet_policy_trace_reset(
	struct pqcp_fleet_policy_trace *trace,
	struct pqcp_fleet_policy_correlation_id correlation_id);

int pqcp_fleet_policy_trace_set_sampling(
	struct pqcp_fleet_policy_trace *trace,
	const struct pqcp_fleet_policy_sampling *sampling);

bool pqcp_fleet_policy_trace_should_retain(
	const struct pqcp_fleet_policy_trace *trace);

int pqcp_fleet_policy_trace_record(
	struct pqcp_fleet_policy_trace *trace,
	const struct pqcp_fleet_policy_trace_event_input *input,
	uint64_t *event_id);

int pqcp_fleet_policy_trace_instruction(
	struct pqcp_fleet_policy_trace *trace,
	uint64_t parent_id,
	uint32_t opcode,
	uint32_t program_counter,
	uint64_t result,
	uint32_t reason,
	enum pqcp_fleet_policy_redaction_class redaction,
	uint64_t *event_id);

int pqcp_fleet_policy_trace_rule(
	struct pqcp_fleet_policy_trace *trace,
	uint64_t parent_id,
	uint32_t rule_id,
	uint32_t priority,
	uint64_t result,
	uint32_t reason,
	enum pqcp_fleet_policy_redaction_class redaction,
	uint64_t *event_id);

int pqcp_fleet_policy_trace_claim(
	struct pqcp_fleet_policy_trace *trace,
	uint64_t parent_id,
	uint32_t claim_id,
	uint32_t operation,
	uint64_t value,
	uint32_t reason,
	enum pqcp_fleet_policy_redaction_class redaction,
	uint64_t *event_id);

int pqcp_fleet_policy_trace_builtin(
	struct pqcp_fleet_policy_trace *trace,
	uint64_t parent_id,
	uint32_t builtin_id,
	uint32_t result,
	uint64_t value,
	uint32_t reason,
	enum pqcp_fleet_policy_redaction_class redaction,
	uint64_t *event_id);

int pqcp_fleet_policy_trace_decide(
	struct pqcp_fleet_policy_trace *trace,
	uint64_t parent_id,
	enum pqcp_fleet_policy_trace_decision decision,
	uint32_t reason,
	uint32_t rule_id,
	uint32_t priority,
	uint64_t metadata,
	enum pqcp_fleet_policy_redaction_class redaction,
	uint64_t *event_id);

const struct pqcp_fleet_policy_trace_event *
pqcp_fleet_policy_trace_event_at(
	const struct pqcp_fleet_policy_trace *trace,
	size_t index);

const char *pqcp_fleet_policy_trace_event_type_name(
	enum pqcp_fleet_policy_trace_event_type type);

const char *pqcp_fleet_policy_trace_decision_name(
	enum pqcp_fleet_policy_trace_decision decision);

const char *pqcp_fleet_policy_trace_reason_name(uint32_t reason);

const char *pqcp_fleet_policy_redaction_name(
	enum pqcp_fleet_policy_redaction_class redaction);

int pqcp_fleet_policy_trace_format(
	const struct pqcp_fleet_policy_trace *trace,
	const struct pqcp_fleet_policy_redaction *redaction,
	char *output,
	size_t capacity,
	size_t *length);

int pqcp_fleet_policy_trace_export(
	const struct pqcp_fleet_policy_trace *trace,
	const struct pqcp_fleet_policy_redaction *redaction,
	uint8_t *output,
	size_t capacity,
	size_t *length);

int pqcp_fleet_policy_trace_import(
	struct pqcp_fleet_policy_trace *trace,
	const uint8_t *input,
	size_t length);

int pqcp_fleet_policy_trace_proof(
	const struct pqcp_fleet_policy_trace *trace,
	const struct pqcp_fleet_policy_redaction *redaction,
	const struct pqcp_fleet_policy_digest_callbacks *callbacks,
	struct pqcp_fleet_policy_proof_summary *summary);

int pqcp_fleet_policy_trace_audit_flush(
	struct pqcp_fleet_policy_trace *trace,
	const struct pqcp_fleet_policy_redaction *redaction,
	const struct pqcp_fleet_policy_audit_sink *sink,
	size_t maximum_events,
	struct pqcp_fleet_policy_audit_result *result);

int pqcp_fleet_policy_trace_compare(
	const struct pqcp_fleet_policy_trace *left,
	const struct pqcp_fleet_policy_trace *right,
	struct pqcp_fleet_policy_trace_divergence *divergence);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_POLICY_EXPLAIN_H_ */
