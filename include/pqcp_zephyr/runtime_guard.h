/*
 * SPDX-License-Identifier: MIT
 *
 * Exhaustive authorization and continuity guards for runtime commands.
 */

#ifndef PQCP_ZEPHYR_RUNTIME_GUARD_H_
#define PQCP_ZEPHYR_RUNTIME_GUARD_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/runtime_operations.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_RUNTIME_AUTHORIZATION_CONDITION_COUNT 16U
#define PQCP_RUNTIME_CONTINUITY_CONDITION_COUNT 16U

enum pqcp_runtime_authorization_condition {
	PQCP_RUNTIME_AUTHORIZATION_ANONYMOUS = 0,
	PQCP_RUNTIME_AUTHORIZATION_AUTHENTICATED,
	PQCP_RUNTIME_AUTHORIZATION_OPERATOR,
	PQCP_RUNTIME_AUTHORIZATION_SECURITY_OFFICER,
	PQCP_RUNTIME_AUTHORIZATION_AUDITOR,
	PQCP_RUNTIME_AUTHORIZATION_AUTOMATION,
	PQCP_RUNTIME_AUTHORIZATION_BREAK_GLASS,
	PQCP_RUNTIME_AUTHORIZATION_TOKEN_EXPIRED,
	PQCP_RUNTIME_AUTHORIZATION_TOKEN_REVOKED,
	PQCP_RUNTIME_AUTHORIZATION_TENANT_MISMATCH,
	PQCP_RUNTIME_AUTHORIZATION_OWNER_MISMATCH,
	PQCP_RUNTIME_AUTHORIZATION_REPLAY_SUSPECTED,
	PQCP_RUNTIME_AUTHORIZATION_CLOCK_UNTRUSTED,
	PQCP_RUNTIME_AUTHORIZATION_POLICY_STALE,
	PQCP_RUNTIME_AUTHORIZATION_QUARANTINED,
	PQCP_RUNTIME_AUTHORIZATION_TERMINATED,
};

enum pqcp_runtime_authorization_disposition {
	PQCP_RUNTIME_AUTHORIZATION_DENY = 0,
	PQCP_RUNTIME_AUTHORIZATION_ALLOW,
	PQCP_RUNTIME_AUTHORIZATION_ALLOW_READ_ONLY,
	PQCP_RUNTIME_AUTHORIZATION_REQUIRE_OPERATOR,
	PQCP_RUNTIME_AUTHORIZATION_REQUIRE_SECURITY_OFFICER,
	PQCP_RUNTIME_AUTHORIZATION_REQUIRE_FRESH_TOKEN,
	PQCP_RUNTIME_AUTHORIZATION_REQUIRE_BREAK_GLASS,
	PQCP_RUNTIME_AUTHORIZATION_QUARANTINE,
};

enum pqcp_runtime_continuity_condition {
	PQCP_RUNTIME_CONTINUITY_HEALTHY = 0,
	PQCP_RUNTIME_CONTINUITY_REPLICA_LAGGING,
	PQCP_RUNTIME_CONTINUITY_CHECKPOINT_STALE,
	PQCP_RUNTIME_CONTINUITY_CHECKPOINT_MISSING,
	PQCP_RUNTIME_CONTINUITY_EVENT_CHAIN_STALE,
	PQCP_RUNTIME_CONTINUITY_EVENT_CHAIN_INVALID,
	PQCP_RUNTIME_CONTINUITY_KEY_STORE_DEGRADED,
	PQCP_RUNTIME_CONTINUITY_IDENTITY_DEGRADED,
	PQCP_RUNTIME_CONTINUITY_WORKSPACE_PRESSURE,
	PQCP_RUNTIME_CONTINUITY_QUEUE_SATURATED,
	PQCP_RUNTIME_CONTINUITY_CLOCK_ROLLBACK,
	PQCP_RUNTIME_CONTINUITY_EPOCH_DIVERGED,
	PQCP_RUNTIME_CONTINUITY_PARTITIONED,
	PQCP_RUNTIME_CONTINUITY_FAILOVER_ACTIVE,
	PQCP_RUNTIME_CONTINUITY_READ_ONLY,
	PQCP_RUNTIME_CONTINUITY_TERMINATED,
};

enum pqcp_runtime_continuity_directive {
	PQCP_RUNTIME_CONTINUITY_DENY = 0,
	PQCP_RUNTIME_CONTINUITY_ALLOW,
	PQCP_RUNTIME_CONTINUITY_ALLOW_READ_ONLY,
	PQCP_RUNTIME_CONTINUITY_DEFER,
	PQCP_RUNTIME_CONTINUITY_CHECKPOINT,
	PQCP_RUNTIME_CONTINUITY_RECONCILE,
	PQCP_RUNTIME_CONTINUITY_FAILOVER,
	PQCP_RUNTIME_CONTINUITY_LOCK_DOWN,
	PQCP_RUNTIME_CONTINUITY_TERMINATE,
};

enum pqcp_runtime_guard_verdict {
	PQCP_RUNTIME_GUARD_DENY = 0,
	PQCP_RUNTIME_GUARD_ALLOW,
	PQCP_RUNTIME_GUARD_ALLOW_READ_ONLY,
	PQCP_RUNTIME_GUARD_DEFER,
	PQCP_RUNTIME_GUARD_LOCK_DOWN,
	PQCP_RUNTIME_GUARD_TERMINATE,
};

struct pqcp_runtime_authorization_policy_decision {
	enum pqcp_runtime_authorization_condition condition;
	enum pqcp_runtime_command_kind command;
	enum pqcp_runtime_authorization_disposition disposition;
	uint32_t required_assurance;
	uint32_t audit_level;
	uint32_t reason_mask;
	int error;
};

struct pqcp_runtime_continuity_policy_decision {
	enum pqcp_runtime_continuity_condition condition;
	enum pqcp_runtime_command_kind command;
	enum pqcp_runtime_continuity_directive directive;
	enum pqcp_runtime_policy_state next_state;
	uint32_t delay_ms;
	uint32_t reason_mask;
	int error;
};

struct pqcp_runtime_guard_decision {
	struct pqcp_runtime_policy_decision lifecycle;
	struct pqcp_runtime_authorization_policy_decision authorization;
	struct pqcp_runtime_continuity_policy_decision continuity;
	enum pqcp_runtime_guard_verdict verdict;
	enum pqcp_runtime_policy_state next_state;
	uint32_t delay_ms;
	uint32_t reason_mask;
	int error;
	bool allowed;
};

int pqcp_runtime_authorization_policy_lookup(
	enum pqcp_runtime_authorization_condition condition,
	enum pqcp_runtime_command_kind command,
	struct pqcp_runtime_authorization_policy_decision *decision);
int pqcp_runtime_authorization_policy_catalog_audit(void);

int pqcp_runtime_continuity_policy_lookup(
	enum pqcp_runtime_continuity_condition condition,
	enum pqcp_runtime_command_kind command,
	struct pqcp_runtime_continuity_policy_decision *decision);
int pqcp_runtime_continuity_policy_catalog_audit(void);

int pqcp_runtime_guard_evaluate(
	enum pqcp_runtime_policy_state state,
	enum pqcp_runtime_authorization_condition authorization,
	enum pqcp_runtime_continuity_condition continuity,
	enum pqcp_runtime_command_kind command,
	struct pqcp_runtime_guard_decision *decision);
int pqcp_runtime_guard_audit(void);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_RUNTIME_GUARD_H_ */
