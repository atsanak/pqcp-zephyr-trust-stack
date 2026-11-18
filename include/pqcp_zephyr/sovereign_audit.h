/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free sovereign audit interoperability.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_SOVEREIGN_AUDIT_H_
#define PQCP_ZEPHYR_SOVEREIGN_AUDIT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION 1U
#define PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES 32U
#define PQCP_SOVEREIGN_AUDIT_EVENT_ID_BYTES 16U
#define PQCP_SOVEREIGN_AUDIT_TENANT_MAX_CHARS 48U
#define PQCP_SOVEREIGN_AUDIT_REALM_MAX_CHARS 48U
#define PQCP_SOVEREIGN_AUDIT_SOURCE_MAX_CHARS 48U
#define PQCP_SOVEREIGN_AUDIT_ACTOR_MAX_CHARS 64U
#define PQCP_SOVEREIGN_AUDIT_OBJECT_MAX_CHARS 96U
#define PQCP_SOVEREIGN_AUDIT_ACTION_MAX_CHARS 48U
#define PQCP_SOVEREIGN_AUDIT_REASON_MAX_CHARS 128U
#define PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_KEY_MAX_CHARS 40U
#define PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_TEXT_MAX_CHARS 96U
#define PQCP_SOVEREIGN_AUDIT_MAX_ATTRIBUTES 12U
#define PQCP_SOVEREIGN_AUDIT_SIGNATURE_CONTEXT \
	"pqcp-sovereign-audit-batch-v1"
#define PQCP_SOVEREIGN_AUDIT_CEF_VENDOR "PQCP"
#define PQCP_SOVEREIGN_AUDIT_CEF_PRODUCT "ZephyrTrustStack"
#define PQCP_SOVEREIGN_AUDIT_CEF_VERSION "1"
#define PQCP_SOVEREIGN_AUDIT_SYSLOG_APP "pqcp-sovereign"

struct pqcp_runtime_key_store;
struct pqcp_crypto_broker_receipt;
struct pqcp_fleet_journal_entry;
struct pqcp_edge_incident;
struct pqcp_sovereign_rollout;
struct pqcp_sovereign_key_ceremony;
struct pqcp_sovereign_privacy_budget;
struct pqcp_sovereign_retention_record;
struct pqcp_sovereign_recovery_request;
struct pqcp_sovereign_continuity_exercise;

enum pqcp_sovereign_audit_event_class {
	PQCP_SOVEREIGN_AUDIT_CLASS_NONE = 0,
	PQCP_SOVEREIGN_AUDIT_CLASS_CRYPTO_OPERATION,
	PQCP_SOVEREIGN_AUDIT_CLASS_FLEET_OPERATION,
	PQCP_SOVEREIGN_AUDIT_CLASS_SECURITY_INCIDENT,
	PQCP_SOVEREIGN_AUDIT_CLASS_DEPLOYMENT,
	PQCP_SOVEREIGN_AUDIT_CLASS_KEY_CEREMONY,
	PQCP_SOVEREIGN_AUDIT_CLASS_PRIVACY,
	PQCP_SOVEREIGN_AUDIT_CLASS_RECOVERY,
	PQCP_SOVEREIGN_AUDIT_CLASS_CONTINUITY,
	PQCP_SOVEREIGN_AUDIT_CLASS_AUDIT_CONTROL,
	PQCP_SOVEREIGN_AUDIT_CLASS_COUNT,
};

enum pqcp_sovereign_audit_activity {
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_NONE = 0,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_CREATE,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_START,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_UPDATE,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_AUTHORIZE,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_APPROVE,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_REJECT,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_EXECUTE,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_COMPLETE,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_CANCEL,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_EXPIRE,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_REVOKE,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_ROTATE,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_DESTROY,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_DEPLOY,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_ROLLBACK,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_QUARANTINE,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_CONTAIN,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_REMEDIATE,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_RECOVER,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_FAILOVER,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_REJOIN,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_READ,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_WRITE,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_EXPORT,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_ERASE,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_ACKNOWLEDGE,
	PQCP_SOVEREIGN_AUDIT_ACTIVITY_COUNT,
};

enum pqcp_sovereign_audit_severity {
	PQCP_SOVEREIGN_AUDIT_SEVERITY_UNKNOWN = 0,
	PQCP_SOVEREIGN_AUDIT_SEVERITY_INFORMATIONAL,
	PQCP_SOVEREIGN_AUDIT_SEVERITY_LOW,
	PQCP_SOVEREIGN_AUDIT_SEVERITY_MEDIUM,
	PQCP_SOVEREIGN_AUDIT_SEVERITY_HIGH,
	PQCP_SOVEREIGN_AUDIT_SEVERITY_CRITICAL,
};

enum pqcp_sovereign_audit_outcome {
	PQCP_SOVEREIGN_AUDIT_OUTCOME_UNKNOWN = 0,
	PQCP_SOVEREIGN_AUDIT_OUTCOME_SUCCESS,
	PQCP_SOVEREIGN_AUDIT_OUTCOME_FAILURE,
	PQCP_SOVEREIGN_AUDIT_OUTCOME_DENIED,
	PQCP_SOVEREIGN_AUDIT_OUTCOME_PENDING,
	PQCP_SOVEREIGN_AUDIT_OUTCOME_CANCELLED,
	PQCP_SOVEREIGN_AUDIT_OUTCOME_EXPIRED,
};

enum pqcp_sovereign_audit_data_class {
	PQCP_SOVEREIGN_AUDIT_DATA_PUBLIC = 0,
	PQCP_SOVEREIGN_AUDIT_DATA_INTERNAL,
	PQCP_SOVEREIGN_AUDIT_DATA_CONFIDENTIAL,
	PQCP_SOVEREIGN_AUDIT_DATA_RESTRICTED,
	PQCP_SOVEREIGN_AUDIT_DATA_PERSONAL,
	PQCP_SOVEREIGN_AUDIT_DATA_SENSITIVE_PERSONAL,
	PQCP_SOVEREIGN_AUDIT_DATA_SECRET,
	PQCP_SOVEREIGN_AUDIT_DATA_CLASS_COUNT,
};

enum pqcp_sovereign_audit_redaction {
	PQCP_SOVEREIGN_AUDIT_REDACTION_NONE = 0,
	PQCP_SOVEREIGN_AUDIT_REDACTION_PSEUDONYMIZE,
	PQCP_SOVEREIGN_AUDIT_REDACTION_MINIMIZE,
	PQCP_SOVEREIGN_AUDIT_REDACTION_STRICT,
};

enum pqcp_sovereign_audit_format {
	PQCP_SOVEREIGN_AUDIT_FORMAT_CBOR = 0,
	PQCP_SOVEREIGN_AUDIT_FORMAT_CEF_SYSLOG,
	PQCP_SOVEREIGN_AUDIT_FORMAT_OCSF_JSON,
};

enum pqcp_sovereign_audit_attribute_type {
	PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_U64 = 0,
	PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_I64,
	PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_BOOL,
	PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_TEXT,
	PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_DIGEST,
};

enum pqcp_sovereign_audit_event_flag {
	PQCP_SOVEREIGN_AUDIT_EVENT_SECURITY_RELEVANT = (1U << 0),
	PQCP_SOVEREIGN_AUDIT_EVENT_OPERATOR_VISIBLE = (1U << 1),
	PQCP_SOVEREIGN_AUDIT_EVENT_REGULATORY = (1U << 2),
	PQCP_SOVEREIGN_AUDIT_EVENT_PRIVACY_RELEVANT = (1U << 3),
	PQCP_SOVEREIGN_AUDIT_EVENT_RECOVERY_RELEVANT = (1U << 4),
	PQCP_SOVEREIGN_AUDIT_EVENT_REDACTED = (1U << 5),
	PQCP_SOVEREIGN_AUDIT_EVENT_CHECKPOINT = (1U << 6),
	PQCP_SOVEREIGN_AUDIT_EVENT_SIGNED_SOURCE = (1U << 7),
};

enum pqcp_sovereign_audit_attribute_flag {
	PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_PERSONAL = (1U << 0),
	PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_SENSITIVE = (1U << 1),
	PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_REGULATORY = (1U << 2),
};

enum pqcp_sovereign_audit_cursor_state {
	PQCP_SOVEREIGN_AUDIT_CURSOR_EMPTY = 0,
	PQCP_SOVEREIGN_AUDIT_CURSOR_ACTIVE,
	PQCP_SOVEREIGN_AUDIT_CURSOR_OUTSTANDING,
	PQCP_SOVEREIGN_AUDIT_CURSOR_EXPIRED,
	PQCP_SOVEREIGN_AUDIT_CURSOR_CLOSED,
};

enum pqcp_sovereign_audit_signature_algorithm {
	PQCP_SOVEREIGN_AUDIT_SIGNATURE_NONE = 0,
	PQCP_SOVEREIGN_AUDIT_SIGNATURE_MLDSA,
};

struct pqcp_sovereign_audit_tenant_scope {
	char tenant_id[PQCP_SOVEREIGN_AUDIT_TENANT_MAX_CHARS];
	char realm[PQCP_SOVEREIGN_AUDIT_REALM_MAX_CHARS];
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint8_t scope_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
};

struct pqcp_sovereign_audit_attribute {
	char key[PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_KEY_MAX_CHARS];
	enum pqcp_sovereign_audit_attribute_type type;
	uint32_t flags;
	union {
		uint64_t u64;
		int64_t i64;
		bool boolean;
		char text[PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_TEXT_MAX_CHARS];
		uint8_t digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	} value;
};

struct pqcp_sovereign_event {
	uint32_t schema_version;
	uint32_t generation;
	uint64_t sequence;
	uint64_t observed_at_ms;
	uint64_t ingested_at_ms;
	uint64_t expires_at_ms;
	uint64_t correlation_id;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint8_t event_id[PQCP_SOVEREIGN_AUDIT_EVENT_ID_BYTES];
	struct pqcp_sovereign_audit_tenant_scope tenant;
	enum pqcp_sovereign_audit_event_class event_class;
	enum pqcp_sovereign_audit_activity activity;
	enum pqcp_sovereign_audit_severity severity;
	enum pqcp_sovereign_audit_outcome outcome;
	enum pqcp_sovereign_audit_data_class data_class;
	uint32_t flags;
	int32_t result;
	char source[PQCP_SOVEREIGN_AUDIT_SOURCE_MAX_CHARS];
	char actor[PQCP_SOVEREIGN_AUDIT_ACTOR_MAX_CHARS];
	char object[PQCP_SOVEREIGN_AUDIT_OBJECT_MAX_CHARS];
	char action[PQCP_SOVEREIGN_AUDIT_ACTION_MAX_CHARS];
	char reason[PQCP_SOVEREIGN_AUDIT_REASON_MAX_CHARS];
	uint8_t actor_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	uint8_t subject_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	uint8_t resource_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	uint8_t evidence_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	uint8_t receipt_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	uint8_t previous_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	uint8_t event_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	struct pqcp_sovereign_audit_attribute
		attributes[PQCP_SOVEREIGN_AUDIT_MAX_ATTRIBUTES];
	uint32_t attribute_count;
	bool occupied;
};

struct pqcp_sovereign_event_draft {
	const char *tenant_id;
	const char *realm;
	const char *source;
	const char *actor;
	const char *object;
	const char *action;
	const char *reason;
	enum pqcp_sovereign_audit_event_class event_class;
	enum pqcp_sovereign_audit_activity activity;
	enum pqcp_sovereign_audit_severity severity;
	enum pqcp_sovereign_audit_outcome outcome;
	enum pqcp_sovereign_audit_data_class data_class;
	uint64_t observed_at_ms;
	uint64_t ingested_at_ms;
	uint64_t expires_at_ms;
	uint64_t correlation_id;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint32_t flags;
	int32_t result;
	const uint8_t *actor_digest;
	const uint8_t *subject_digest;
	const uint8_t *resource_digest;
	const uint8_t *evidence_digest;
	const uint8_t *receipt_digest;
};

struct pqcp_sovereign_event_ledger_snapshot {
	uint32_t schema_version;
	uint64_t generation;
	uint64_t first_sequence;
	uint64_t last_sequence;
	uint64_t next_sequence;
	uint64_t appended_count;
	uint64_t evicted_count;
	uint64_t rejected_count;
	size_t count;
	size_t capacity;
	uint8_t anchor_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	uint8_t chain_head[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	uint8_t snapshot_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
};

struct pqcp_sovereign_event_ledger {
	uint32_t schema_version;
	struct pqcp_sovereign_event *events;
	size_t capacity;
	size_t head;
	size_t count;
	uint64_t generation;
	uint64_t next_sequence;
	uint64_t appended_count;
	uint64_t evicted_count;
	uint64_t rejected_count;
	uint8_t anchor_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	uint8_t chain_head[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_audit_export_policy {
	char tenant_id[PQCP_SOVEREIGN_AUDIT_TENANT_MAX_CHARS];
	char realm[PQCP_SOVEREIGN_AUDIT_REALM_MAX_CHARS];
	uint64_t class_mask;
	uint64_t activity_mask;
	uint32_t required_flags;
	uint32_t forbidden_flags;
	enum pqcp_sovereign_audit_severity minimum_severity;
	enum pqcp_sovereign_audit_data_class maximum_data_class;
	enum pqcp_sovereign_audit_redaction redaction;
	enum pqcp_sovereign_audit_format format;
	uint32_t maximum_events;
	uint64_t policy_epoch;
	bool require_signature;
	bool include_attributes;
	bool include_reasons;
};

struct pqcp_sovereign_audit_cursor {
	uint32_t schema_version;
	uint32_t generation;
	uint64_t cursor_id;
	char consumer_id[PQCP_SOVEREIGN_AUDIT_ACTOR_MAX_CHARS];
	char tenant_id[PQCP_SOVEREIGN_AUDIT_TENANT_MAX_CHARS];
	uint64_t next_sequence;
	uint64_t acknowledged_sequence;
	uint64_t opened_at_ms;
	uint64_t expires_at_ms;
	uint64_t policy_epoch;
	uint64_t outstanding_first_sequence;
	uint64_t outstanding_last_sequence;
	uint64_t outstanding_scanned_sequence;
	uint32_t outstanding_event_count;
	uint8_t previous_batch_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	uint8_t outstanding_batch_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	enum pqcp_sovereign_audit_cursor_state state;
	bool occupied;
};

struct pqcp_sovereign_export_batch {
	uint32_t schema_version;
	uint64_t cursor_id;
	uint64_t created_at_ms;
	uint64_t policy_epoch;
	uint64_t first_sequence;
	uint64_t last_sequence;
	uint64_t scanned_through_sequence;
	uint32_t event_count;
	enum pqcp_sovereign_audit_format format;
	enum pqcp_sovereign_audit_redaction redaction;
	char tenant_id[PQCP_SOVEREIGN_AUDIT_TENANT_MAX_CHARS];
	uint8_t source_anchor_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	uint8_t source_chain_head[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	uint8_t previous_batch_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	uint8_t receipt_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	uint8_t batch_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	enum pqcp_sovereign_audit_signature_algorithm signature_algorithm;
	uint8_t signature[PQCP_MLDSA_SIG_SIZE_MAX];
	size_t signature_length;
	const struct pqcp_sovereign_event *events;
	size_t encoded_length;
	bool complete;
	bool resumed;
};

struct pqcp_sovereign_audit_export_storage {
	struct pqcp_sovereign_audit_cursor *cursors;
	size_t cursor_capacity;
	struct pqcp_sovereign_event *workspace_events;
	size_t workspace_event_capacity;
};

struct pqcp_sovereign_audit_export_config {
	struct pqcp_runtime_key_store *key_store;
	struct pqcp_runtime_key_handle signing_key;
	uint64_t maximum_cursor_lifetime_ms;
	uint32_t maximum_batch_events;
	bool signing_enabled;
	bool signature_required;
};

/* Independent durable slots. A write replaces only the requested slot. A
 * successful write must have reached durable storage. Read returns -ENOENT
 * for an empty slot and -ENOSPC if the supplied buffer is too small.
 * Set binding to a stable digest of the firmware image and stream/key identity.
 */
struct pqcp_sovereign_audit_checkpoint_store {
	void *context;
	int (*read)(void *context, unsigned int slot, uint8_t *buffer,
		    size_t capacity, size_t *length);
	int (*write)(void *context, unsigned int slot, const uint8_t *buffer,
		     size_t length);
	uint8_t binding[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
};

struct pqcp_sovereign_audit_exporter {
	uint32_t schema_version;
	struct pqcp_sovereign_event_ledger *ledger;
	struct pqcp_sovereign_audit_export_storage storage;
	struct pqcp_sovereign_audit_export_config config;
	uint64_t next_cursor_id;
	uint32_t next_generation;
	uint64_t prepared_batches;
	uint64_t resumed_batches;
	uint64_t acknowledged_batches;
	uint64_t rejected_batches;
	/* One frozen batch owns the shared workspace until ack/close/expiry. */
	struct pqcp_sovereign_export_batch pending_batch;
	struct pqcp_sovereign_audit_export_policy pending_policy;
	uint8_t pending_snapshot_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	struct pqcp_sovereign_audit_checkpoint_store checkpoint_store;
	uint64_t checkpoint_generation;
	struct k_mutex lock;
	bool initialized;
};

const char *pqcp_sovereign_audit_event_class_str(
	enum pqcp_sovereign_audit_event_class event_class);
const char *pqcp_sovereign_audit_activity_str(
	enum pqcp_sovereign_audit_activity activity);
const char *pqcp_sovereign_audit_severity_str(
	enum pqcp_sovereign_audit_severity severity);
const char *pqcp_sovereign_audit_outcome_str(
	enum pqcp_sovereign_audit_outcome outcome);

int pqcp_sovereign_event_init(
	struct pqcp_sovereign_event *event,
	const struct pqcp_sovereign_event_draft *draft);
int pqcp_sovereign_event_set_id(
	struct pqcp_sovereign_event *event,
	const uint8_t event_id[PQCP_SOVEREIGN_AUDIT_EVENT_ID_BYTES]);
int pqcp_sovereign_event_derive_id(
	struct pqcp_sovereign_event *event);
int pqcp_sovereign_event_add_u64(
	struct pqcp_sovereign_event *event,
	const char *key,
	uint64_t value,
	uint32_t flags);
int pqcp_sovereign_event_add_i64(
	struct pqcp_sovereign_event *event,
	const char *key,
	int64_t value,
	uint32_t flags);
int pqcp_sovereign_event_add_bool(
	struct pqcp_sovereign_event *event,
	const char *key,
	bool value,
	uint32_t flags);
int pqcp_sovereign_event_add_text(
	struct pqcp_sovereign_event *event,
	const char *key,
	const char *value,
	uint32_t flags);
int pqcp_sovereign_event_add_digest(
	struct pqcp_sovereign_event *event,
	const char *key,
	const uint8_t value[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES],
	uint32_t flags);
int pqcp_sovereign_event_digest(
	const struct pqcp_sovereign_event *event,
	uint8_t digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES]);
int pqcp_sovereign_event_verify(
	const struct pqcp_sovereign_event *event);
int pqcp_sovereign_event_redact(
	const struct pqcp_sovereign_event *source,
	enum pqcp_sovereign_audit_redaction mode,
	bool include_attributes,
	bool include_reasons,
	struct pqcp_sovereign_event *projected);

int pqcp_sovereign_event_ledger_init(
	struct pqcp_sovereign_event_ledger *ledger,
	struct pqcp_sovereign_event *events,
	size_t capacity,
	uint64_t first_sequence,
	const uint8_t anchor_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES]);
int pqcp_sovereign_event_ledger_append(
	struct pqcp_sovereign_event_ledger *ledger,
	const struct pqcp_sovereign_event *event,
	struct pqcp_sovereign_event *committed);
int pqcp_sovereign_event_ledger_get(
	struct pqcp_sovereign_event_ledger *ledger,
	uint64_t sequence,
	struct pqcp_sovereign_event *event);
int pqcp_sovereign_event_ledger_bounds(
	struct pqcp_sovereign_event_ledger *ledger,
	uint64_t *first_sequence,
	uint64_t *last_sequence);
int pqcp_sovereign_event_ledger_snapshot(
	struct pqcp_sovereign_event_ledger *ledger,
	struct pqcp_sovereign_event_ledger_snapshot *snapshot);
int pqcp_sovereign_event_ledger_verify(
	struct pqcp_sovereign_event_ledger *ledger);

int pqcp_sovereign_audit_cbor_encode_event(
	const struct pqcp_sovereign_event *event,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_sovereign_audit_cbor_encode_batch(
	const struct pqcp_sovereign_export_batch *batch,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_sovereign_audit_cef_encode_event(
	const struct pqcp_sovereign_event *event,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_sovereign_audit_cef_encode_batch(
	const struct pqcp_sovereign_export_batch *batch,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_sovereign_audit_ocsf_encode_event(
	const struct pqcp_sovereign_event *event,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_sovereign_audit_ocsf_encode_batch(
	const struct pqcp_sovereign_export_batch *batch,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);

/* Allocation-free, in-memory retry protocol. The caller authorizes the tenant,
 * consumer and policy before calling; cursor IDs are not bearer credentials.
 * Caller-owned storage must remain live and must not alias arguments/output.
 * Multiple cursors may be open, but only one batch may be outstanding globally
 * (-EBUSY otherwise). A successful prepare freezes bytes, signature and policy:
 * repeat it to retransmit, then acknowledge the exact range and digest.
 * batch.events is read-only and valid until acknowledge/close/expiry or reinit.
 * Projections retain source event_digest values; authenticate their changed
 * fields with the batch commitment/signature, not event_verify(projected).
 * batch_digest = SHA256("PQCP-SOVEREIGN-AUDIT-BATCH-V1" || canonical CBOR body).
 * first_sequence=0 selects the oldest retained event. Evicted history yields
 * -ESTALE; no matching events yields -ENOENT without advancing the cursor.
 * For reboot recovery, persist the exporter state with the checkpoint API
 * before transmitting a batch.
 */
int pqcp_sovereign_audit_exporter_init(
	struct pqcp_sovereign_audit_exporter *exporter,
	struct pqcp_sovereign_event_ledger *ledger,
	const struct pqcp_sovereign_audit_export_config *config,
	const struct pqcp_sovereign_audit_export_storage *storage);
int pqcp_sovereign_audit_export_open(
	struct pqcp_sovereign_audit_exporter *exporter,
	const char *consumer_id,
	const char *tenant_id,
	uint64_t first_sequence,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint64_t policy_epoch,
	uint64_t *cursor_id);
int pqcp_sovereign_audit_export_prepare(
	struct pqcp_sovereign_audit_exporter *exporter,
	uint64_t cursor_id,
	const struct pqcp_sovereign_audit_export_policy *policy,
	uint64_t now_ms,
	uint8_t *output,
	size_t output_capacity,
	struct pqcp_sovereign_export_batch *batch);
int pqcp_sovereign_audit_export_acknowledge(
	struct pqcp_sovereign_audit_exporter *exporter,
	uint64_t cursor_id,
	uint64_t first_sequence,
	uint64_t last_sequence,
	const uint8_t batch_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_sovereign_audit_export_close(
	struct pqcp_sovereign_audit_exporter *exporter,
	uint64_t cursor_id);
int pqcp_sovereign_audit_export_expire(
	struct pqcp_sovereign_audit_exporter *exporter,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_audit_exporter_audit(
	struct pqcp_sovereign_audit_exporter *exporter);

/* Call recover on a fresh exporter with a restored ledger before opening any
 * cursor. On two empty slots it binds the store and returns -ENOENT when
 * minimum_generation is zero. An optional
 * trusted generation floor rejects older snapshots. Call checkpoint after
 * prepare and before releasing the bytes, and after acknowledge/close/expire
 * before acting on the new state. Retry a failed save before proceeding.
 * Both calls need scratch disjoint from exporter, ledger and their storage.
 * Slots are trusted local storage, with corruption detection. Their native
 * layout is private to a firmware image. Serialize application transactions
 * and storage access, and retain the signing key and time basis across reboot.
 */
int pqcp_sovereign_audit_exporter_recover(
	struct pqcp_sovereign_audit_exporter *exporter,
	const struct pqcp_sovereign_audit_checkpoint_store *store,
	uint64_t minimum_generation, uint8_t *scratch, size_t capacity);
int pqcp_sovereign_audit_exporter_checkpoint(
	struct pqcp_sovereign_audit_exporter *exporter,
	uint8_t *scratch, size_t capacity);
/* Worst-case scratch and slot size for this initialized exporter; zero on error. */
size_t pqcp_sovereign_audit_exporter_checkpoint_capacity(
	const struct pqcp_sovereign_audit_exporter *exporter);

/* Snapshot adapters: the caller authenticates source provenance and tenant
 * ownership (several source types carry no tenant). Fleet entries additionally
 * undergo entry-digest verification; broker signatures need a broker context
 * and are NOT verified by these adapters. SIGNED_SOURCE is never inferred.
 * The caller supplies a stable snapshot. No source state is modified; output
 * is unchanged on error. Event IDs bind the normalized projection including
 * attributes, excluding ingestion time.
 * They identify observations, not an authorization token or deduplication DB.
 */
int pqcp_sovereign_audit_bridge_broker_receipt(
	const char *tenant_id,
	const char *realm,
	const char *source,
	const struct pqcp_crypto_broker_receipt *receipt,
	uint64_t ingested_at_ms,
	struct pqcp_sovereign_event *event);
int pqcp_sovereign_audit_bridge_fleet_journal(
	const char *tenant_id,
	const char *realm,
	const struct pqcp_fleet_journal_entry *entry,
	uint64_t ingested_at_ms,
	struct pqcp_sovereign_event *event);
int pqcp_sovereign_audit_bridge_edge_incident(
	const char *tenant_id,
	const char *realm,
	const struct pqcp_edge_incident *incident,
	uint64_t ingested_at_ms,
	struct pqcp_sovereign_event *event);
int pqcp_sovereign_audit_bridge_deployment(
	const char *tenant_id,
	const char *realm,
	const struct pqcp_sovereign_rollout *rollout,
	uint64_t ingested_at_ms,
	struct pqcp_sovereign_event *event);
int pqcp_sovereign_audit_bridge_ceremony(
	const char *tenant_id,
	const char *realm,
	const struct pqcp_sovereign_key_ceremony *ceremony,
	uint64_t ingested_at_ms,
	struct pqcp_sovereign_event *event);
int pqcp_sovereign_audit_bridge_privacy_budget(
	const char *realm,
	const struct pqcp_sovereign_privacy_budget *budget,
	bool authorized,
	uint64_t observed_at_ms,
	struct pqcp_sovereign_event *event);
int pqcp_sovereign_audit_bridge_erasure(
	const char *realm,
	const struct pqcp_sovereign_retention_record *record,
	uint64_t observed_at_ms,
	struct pqcp_sovereign_event *event);
int pqcp_sovereign_audit_bridge_recovery(
	const char *tenant_id,
	const char *realm,
	const struct pqcp_sovereign_recovery_request *request,
	uint64_t observed_at_ms,
	struct pqcp_sovereign_event *event);
int pqcp_sovereign_audit_bridge_continuity(
	const char *tenant_id,
	const char *realm,
	const struct pqcp_sovereign_continuity_exercise *exercise,
	uint64_t observed_at_ms,
	struct pqcp_sovereign_event *event);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_SOVEREIGN_AUDIT_H_ */
