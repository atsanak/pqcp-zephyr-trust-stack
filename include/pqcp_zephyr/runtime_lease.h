/*
 * SPDX-License-Identifier: MIT
 *
 * Renewable bounded leases for runtime key handles.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_RUNTIME_LEASE_H_
#define PQCP_ZEPHYR_RUNTIME_LEASE_H_

#include <pqcp_zephyr/runtime_key_store.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_RUNTIME_LEASE_OWNER_MAX_CHARS PQCP_RUNTIME_OWNER_MAX_CHARS

enum pqcp_runtime_lease_state {
	PQCP_RUNTIME_LEASE_EMPTY = 0,
	PQCP_RUNTIME_LEASE_ACTIVE,
	PQCP_RUNTIME_LEASE_EXPIRING,
	PQCP_RUNTIME_LEASE_EXPIRED,
	PQCP_RUNTIME_LEASE_REVOKED,
	PQCP_RUNTIME_LEASE_STALE,
};

struct pqcp_runtime_lease_policy {
	uint32_t schema_version;
	uint64_t default_duration_ms;
	uint64_t maximum_duration_ms;
	uint64_t renewal_window_ms;
	uint32_t maximum_renewals;
	uint32_t maximum_uses;
	bool destroy_key_on_expiry;
	bool destroy_key_on_revoke;
	bool require_same_owner;
};

struct pqcp_runtime_key_lease {
	uint32_t schema_version;
	uint64_t lease_id;
	struct pqcp_runtime_key_handle key;
	enum pqcp_runtime_lease_state state;
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
	uint64_t last_used_at_ms;
	uint32_t renewal_count;
	uint32_t use_count;
	uint32_t allowed_usage;
	char owner[PQCP_RUNTIME_LEASE_OWNER_MAX_CHARS];
	bool occupied;
};

struct pqcp_runtime_lease_report {
	uint32_t schema_version;
	uint32_t capacity;
	uint32_t active;
	uint32_t expiring;
	uint32_t expired;
	uint32_t revoked;
	uint32_t stale;
	uint32_t destroyed_keys;
	uint32_t failures;
	uint64_t evaluated_at_ms;
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES];
};

struct pqcp_runtime_lease_manager {
	uint32_t schema_version;
	struct pqcp_runtime_key_store *key_store;
	struct pqcp_runtime_key_lease *leases;
	size_t capacity;
	struct pqcp_runtime_lease_policy policy;
	uint64_t next_lease_id;
	uint64_t issued_count;
	uint64_t renewal_count;
	uint64_t revoked_count;
	struct k_mutex lock;
};

int pqcp_runtime_lease_policy_default(
	struct pqcp_runtime_lease_policy *policy);
int pqcp_runtime_lease_manager_init(
	struct pqcp_runtime_lease_manager *manager,
	struct pqcp_runtime_key_store *key_store,
	struct pqcp_runtime_key_lease *leases,
	size_t capacity,
	const struct pqcp_runtime_lease_policy *policy);
int pqcp_runtime_lease_issue(
	struct pqcp_runtime_lease_manager *manager,
	const struct pqcp_runtime_key_handle *key,
	const char *owner,
	uint32_t allowed_usage,
	uint64_t now_ms,
	uint64_t requested_duration_ms,
	struct pqcp_runtime_key_lease **lease);
int pqcp_runtime_lease_authorize(
	struct pqcp_runtime_lease_manager *manager,
	uint64_t lease_id,
	const char *owner,
	uint32_t required_usage,
	uint64_t now_ms,
	struct pqcp_runtime_key_handle *key);
int pqcp_runtime_lease_renew(
	struct pqcp_runtime_lease_manager *manager,
	uint64_t lease_id,
	const char *owner,
	uint64_t now_ms,
	uint64_t requested_duration_ms);
int pqcp_runtime_lease_revoke(
	struct pqcp_runtime_lease_manager *manager,
	uint64_t lease_id,
	const char *owner,
	uint64_t now_ms);
int pqcp_runtime_lease_reconcile(
	struct pqcp_runtime_lease_manager *manager,
	uint64_t now_ms,
	struct pqcp_runtime_lease_report *report);
int pqcp_runtime_lease_manager_audit(
	struct pqcp_runtime_lease_manager *manager);
int pqcp_runtime_lease_report_verify(
	const struct pqcp_runtime_lease_report *report);
int pqcp_runtime_lease_emit(
	const struct pqcp_runtime_lease_report *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_RUNTIME_LEASE_H_ */
