/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Sovereign placement, network-intent, rollout, and rollback policy.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_SOVEREIGN_POLICY_H_
#define PQCP_ZEPHYR_SOVEREIGN_POLICY_H_

#include <pqcp_zephyr/sovereign_runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

int pqcp_sovereign_network_intent_manager_init(
	struct pqcp_sovereign_network_intent_manager *manager,
	struct pqcp_sovereign_network_intent *intents,
	size_t capacity);
int pqcp_sovereign_network_intent_put(
	struct pqcp_sovereign_network_intent_manager *manager,
	const struct pqcp_sovereign_network_intent *intent,
	uint64_t now_ms,
	struct pqcp_sovereign_network_intent **stored);
int pqcp_sovereign_network_intent_authorize(
	struct pqcp_sovereign_network_intent_manager *manager,
	const char *tenant_id,
	const char *source_namespace,
	const char *destination_namespace,
	const char *protocol,
	uint16_t port,
	enum pqcp_sovereign_operation operation,
	uint64_t policy_epoch,
	uint32_t risk_score,
	bool mutually_authenticated,
	bool encrypted,
	uint64_t now_ms,
	uint64_t *intent_id);
int pqcp_sovereign_network_intent_release(
	struct pqcp_sovereign_network_intent_manager *manager,
	uint64_t intent_id);
int pqcp_sovereign_network_intent_revoke(
	struct pqcp_sovereign_network_intent_manager *manager,
	uint64_t intent_id,
	uint64_t now_ms);
int pqcp_sovereign_network_intent_expire(
	struct pqcp_sovereign_network_intent_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_network_intent_manager_audit(
	struct pqcp_sovereign_network_intent_manager *manager);

int pqcp_sovereign_placement_engine_init(
	struct pqcp_sovereign_placement_engine *engine,
	struct pqcp_sovereign_placement_node *nodes,
	size_t node_capacity,
	struct pqcp_sovereign_placement_reservation *reservations,
	size_t reservation_capacity);
int pqcp_sovereign_placement_node_put(
	struct pqcp_sovereign_placement_engine *engine,
	const struct pqcp_sovereign_placement_node *node,
	uint64_t now_ms,
	struct pqcp_sovereign_placement_node **stored);
int pqcp_sovereign_placement_node_revoke(
	struct pqcp_sovereign_placement_engine *engine,
	const char *tenant_id,
	const char *node_id);
int pqcp_sovereign_placement_select(
	struct pqcp_sovereign_placement_engine *engine,
	const struct pqcp_sovereign_placement_request *request,
	uint64_t reservation_lifetime_ms,
	struct pqcp_sovereign_placement_reservation **reservation);
int pqcp_sovereign_placement_commit(
	struct pqcp_sovereign_placement_engine *engine,
	uint64_t reservation_id,
	uint64_t now_ms);
int pqcp_sovereign_placement_release(
	struct pqcp_sovereign_placement_engine *engine,
	uint64_t reservation_id);
int pqcp_sovereign_placement_expire(
	struct pqcp_sovereign_placement_engine *engine,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_placement_engine_audit(
	struct pqcp_sovereign_placement_engine *engine);

int pqcp_sovereign_ring_registry_init(
	struct pqcp_sovereign_ring_registry *registry,
	struct pqcp_sovereign_deployment_ring *rings,
	size_t capacity);
int pqcp_sovereign_ring_put(
	struct pqcp_sovereign_ring_registry *registry,
	const struct pqcp_sovereign_deployment_ring *ring,
	uint64_t now_ms,
	struct pqcp_sovereign_deployment_ring **stored);
int pqcp_sovereign_ring_set_state(
	struct pqcp_sovereign_ring_registry *registry,
	const char *tenant_id,
	const char *ring_id,
	enum pqcp_sovereign_lifecycle_state state,
	uint64_t now_ms);
int pqcp_sovereign_ring_find(
	struct pqcp_sovereign_ring_registry *registry,
	const char *tenant_id,
	const char *ring_id,
	struct pqcp_sovereign_deployment_ring *ring);
int pqcp_sovereign_ring_registry_audit(
	struct pqcp_sovereign_ring_registry *registry);

int pqcp_sovereign_rollout_controller_init(
	struct pqcp_sovereign_rollout_controller *controller,
	struct pqcp_sovereign_rollout *rollouts,
	size_t capacity);
int pqcp_sovereign_rollout_plan(
	struct pqcp_sovereign_rollout_controller *controller,
	const struct pqcp_sovereign_deployment_ring *ring,
	const char *artifact_id,
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t start_at_ms,
	uint64_t deadline_ms,
	struct pqcp_sovereign_rollout **rollout);
int pqcp_sovereign_rollout_start(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t rollout_id,
	uint64_t now_ms);
int pqcp_sovereign_rollout_record_batch(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t rollout_id,
	uint32_t attempted,
	uint32_t succeeded,
	uint32_t failed,
	uint32_t unavailable,
	uint64_t now_ms);
int pqcp_sovereign_rollout_pause(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t rollout_id,
	uint64_t now_ms);
int pqcp_sovereign_rollout_resume(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t rollout_id,
	uint64_t now_ms);
int pqcp_sovereign_rollout_request_rollback(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t rollout_id,
	int reason,
	uint64_t now_ms);
int pqcp_sovereign_rollout_tick(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_sovereign_rollout_controller_audit(
	struct pqcp_sovereign_rollout_controller *controller);

int pqcp_sovereign_rollback_coordinator_init(
	struct pqcp_sovereign_rollback_coordinator *coordinator,
	struct pqcp_sovereign_rollback_plan *plans,
	size_t capacity);
int pqcp_sovereign_rollback_authorize(
	struct pqcp_sovereign_rollback_coordinator *coordinator,
	uint64_t rollout_id,
	const char *current_artifact_id,
	const char *target_artifact_id,
	uint64_t policy_epoch,
	const uint8_t authorization_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	const uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint32_t required_steps,
	uint32_t maximum_failures,
	uint64_t now_ms,
	uint64_t deadline_ms,
	struct pqcp_sovereign_rollback_plan **plan);
int pqcp_sovereign_rollback_start(
	struct pqcp_sovereign_rollback_coordinator *coordinator,
	uint64_t rollback_id,
	uint64_t now_ms);
int pqcp_sovereign_rollback_record_step(
	struct pqcp_sovereign_rollback_coordinator *coordinator,
	uint64_t rollback_id,
	bool success,
	const uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_sovereign_rollback_abort(
	struct pqcp_sovereign_rollback_coordinator *coordinator,
	uint64_t rollback_id,
	int result,
	uint64_t now_ms);
int pqcp_sovereign_rollback_tick(
	struct pqcp_sovereign_rollback_coordinator *coordinator,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_sovereign_rollback_coordinator_audit(
	struct pqcp_sovereign_rollback_coordinator *coordinator);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_SOVEREIGN_POLICY_H_ */
