/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Composition root for fleet policy, commands, updates, telemetry, and audit.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/fleet_operations.h>

#include "runtime_internal.h"

static void retain_first_error(int candidate, int *first_error)
{
	if (candidate != 0 && *first_error == 0) {
		*first_error = candidate;
	}
}

struct policy_audit_payload {
	uint32_t operation;
	uint32_t effect;
	uint32_t reason;
	uint32_t rule_id;
	uint32_t risk_score;
	uint32_t security_level;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
};

static bool storage_valid(
	const struct pqcp_fleet_operations_storage *storage)
{
	return storage != NULL &&
	       storage->policy_rules != NULL &&
	       storage->policy_rule_capacity != 0U &&
	       storage->commands != NULL &&
	       storage->command_capacity != 0U &&
	       storage->components != NULL &&
	       storage->component_capacity != 0U &&
	       storage->audit_entries != NULL &&
	       storage->audit_capacity != 0U &&
	       storage->metric_samples != NULL &&
	       storage->samples_per_metric != 0U;
}

static uint64_t device_policy_epoch(
	const struct pqcp_fleet_device *device)
{
	return device->record.policy.envelope.policy_epoch;
}

static uint64_t credential_valid_until(
	const struct pqcp_fleet_device *device)
{
	return device->record.credential.valid_until_ms;
}

static bool device_revoked(
	const struct pqcp_fleet_device *device)
{
	return device->record.state ==
		       PQCP_FLEET_DEVICE_REVOKED ||
	       device->record.state ==
		       PQCP_FLEET_DEVICE_DECOMMISSIONED;
}

static void build_policy_context(
	const struct pqcp_fleet_operations *operations,
	enum pqcp_fleet_operation_type operation,
	uint64_t now_ms,
	struct pqcp_fleet_policy_context *context)
{
	memset(context, 0, sizeof(*context));
	context->operation = operation;
	context->device_state =
		operations->device->record.state;
	context->capabilities =
		operations->device->record.granted_capabilities;
	context->security_level = operations->security_level;
	context->risk_score = operations->risk_score;
	context->policy_epoch =
		device_policy_epoch(operations->device);
	context->revocation_epoch =
		operations->device->record.revocation_epoch;
	context->credential_valid_until_ms =
		credential_valid_until(operations->device);
	context->now_ms = now_ms;
	context->channel_identity_verified =
		operations->channel_identity_verified;
	context->online = operations->online;
	context->revoked = device_revoked(operations->device);
}

static int append_policy_audit(
	struct pqcp_fleet_operations *operations,
	const struct pqcp_fleet_command *command,
	const struct pqcp_fleet_policy_decision *decision,
	uint64_t now_ms)
{
	struct policy_audit_payload payload = {
		.operation = command->operation,
		.effect = decision->effect,
		.reason = decision->reason,
		.rule_id = decision->matched_rule_id,
		.risk_score = operations->risk_score,
		.security_level = operations->security_level,
		.policy_epoch =
			device_policy_epoch(operations->device),
		.revocation_epoch =
			operations->device->record.revocation_epoch,
	};

	return pqcp_fleet_audit_append(
		&operations->audit,
		PQCP_FLEET_AUDIT_POLICY_DECISION,
		decision->severity, "policy-engine",
		command->command_id,
		decision->effect ==
			PQCP_FLEET_POLICY_EFFECT_ALLOW ?
			0 : -EACCES,
		(const uint8_t *)&payload, sizeof(payload),
		now_ms, NULL);
}

int pqcp_fleet_operations_init(
	struct pqcp_fleet_operations *operations,
	struct pqcp_fleet_device *device,
	const struct pqcp_fleet_operations_storage *storage,
	enum pqcp_fleet_policy_effect default_effect,
	uint32_t security_level)
{
	int ret;

	if (operations == NULL || device == NULL ||
	    !device->initialized || !storage_valid(storage) ||
	    security_level == 0U || security_level > 5U) {
		return -EINVAL;
	}
	memset(operations, 0, sizeof(*operations));
	operations->schema_version =
		PQCP_FLEET_OPERATIONS_SCHEMA_VERSION;
	operations->device = device;
	operations->security_level = security_level;
	ret = pqcp_fleet_policy_engine_init(
		&operations->policy, storage->policy_rules,
		storage->policy_rule_capacity, default_effect);
	if (ret == 0) {
		ret = pqcp_fleet_command_queue_init(
			&operations->commands, storage->commands,
			storage->command_capacity);
	}
	if (ret == 0) {
		ret = pqcp_fleet_update_manager_init(
			&operations->updates, storage->components,
			storage->component_capacity);
	}
	if (ret == 0) {
		ret = pqcp_fleet_audit_ledger_init(
			&operations->audit,
			storage->audit_entries,
			storage->audit_capacity);
	}
	if (ret == 0) {
		ret = pqcp_fleet_telemetry_init(
			&operations->telemetry,
			storage->metric_samples,
			storage->samples_per_metric);
	}
	if (ret == 0) {
		operations->initialized = true;
		ret = pqcp_fleet_operations_audit(
			operations,
			pqcp_runtime_internal_now_ms() == 0U ?
				1U :
				pqcp_runtime_internal_now_ms());
	}
	if (ret != 0) {
		operations->initialized = false;
	}
	return ret;
}

int pqcp_fleet_operations_submit(
	struct pqcp_fleet_operations *operations,
	const struct pqcp_fleet_command *command,
	uint64_t now_ms,
	struct pqcp_fleet_policy_decision *decision,
	bool *replayed)
{
	struct pqcp_fleet_policy_context context;
	struct pqcp_fleet_command *accepted = NULL;
	int ret;

	if (operations == NULL || !operations->initialized ||
	    command == NULL || decision == NULL ||
	    replayed == NULL || now_ms == 0U ||
	    command->submitted_at_ms > now_ms ||
	    command->deadline_ms <= now_ms) {
		return -EINVAL;
	}
	build_policy_context(
		operations, command->operation, now_ms, &context);
	ret = pqcp_fleet_policy_evaluate(
		&operations->policy, &context, decision);
	if (ret != 0) {
		return ret;
	}
	ret = append_policy_audit(
		operations, command, decision, now_ms);
	if (ret != 0) {
		return ret;
	}
	if (decision->effect !=
	    PQCP_FLEET_POLICY_EFFECT_ALLOW) {
		if (decision->effect ==
		    PQCP_FLEET_POLICY_EFFECT_QUARANTINE) {
			operations->quarantined = true;
		}
		(void)pqcp_fleet_audit_append(
			&operations->audit,
			PQCP_FLEET_AUDIT_COMMAND_REJECTED,
			decision->severity, "operations",
			command->command_id, -EACCES,
			command->payload_digest,
			sizeof(command->payload_digest),
			now_ms, NULL);
		return -EACCES;
	}
	if ((command->required_capabilities &
	     ~operations->device->record.granted_capabilities) != 0U) {
		decision->effect = PQCP_FLEET_POLICY_EFFECT_DENY;
		decision->reason =
			PQCP_FLEET_POLICY_REASON_CAPABILITY;
		decision->missing_capabilities =
			command->required_capabilities &
			~operations->device->record.granted_capabilities;
		decision->severity = PQCP_FLEET_AUDIT_WARNING;
		(void)pqcp_runtime_internal_copy_text(
			decision->explanation,
			sizeof(decision->explanation),
			"command capability not granted");
		return -EACCES;
	}
	if ((command->flags &
	     PQCP_FLEET_COMMAND_REQUIRE_ONLINE) != 0U &&
	    !operations->online) {
		return -ENETDOWN;
	}
	if ((command->flags &
	     PQCP_FLEET_COMMAND_REQUIRE_CHANNEL_IDENTITY) != 0U &&
	    !operations->channel_identity_verified) {
		return -EACCES;
	}
	ret = pqcp_fleet_command_submit(
		&operations->commands, command, &accepted,
		replayed);
	if (ret == 0 && !*replayed) {
		ret = pqcp_fleet_audit_append(
			&operations->audit,
			PQCP_FLEET_AUDIT_COMMAND_ACCEPTED,
			PQCP_FLEET_AUDIT_INFO, "operations",
			command->command_id, 0,
			command->payload_digest,
			sizeof(command->payload_digest),
			now_ms, NULL);
	}
	return ret;
}

int pqcp_fleet_operations_set_connectivity(
	struct pqcp_fleet_operations *operations,
	bool online,
	bool channel_identity_verified)
{
	if (operations == NULL || !operations->initialized ||
	    (!online && channel_identity_verified)) {
		return -EINVAL;
	}
	operations->online = online;
	operations->channel_identity_verified =
		channel_identity_verified;
	return 0;
}

int pqcp_fleet_operations_set_risk(
	struct pqcp_fleet_operations *operations,
	uint32_t risk_score,
	uint64_t now_ms)
{
	int ret;

	if (operations == NULL || !operations->initialized ||
	    risk_score > 1000U || now_ms == 0U) {
		return -EINVAL;
	}
	operations->risk_score = risk_score;
	ret = pqcp_fleet_telemetry_record(
		&operations->telemetry,
		PQCP_FLEET_METRIC_RISK_SCORE,
		risk_score, now_ms);
	if (ret == 0 && risk_score >= 900U &&
	    !operations->quarantined) {
		operations->quarantined = true;
		ret = pqcp_fleet_audit_append(
			&operations->audit,
			PQCP_FLEET_AUDIT_QUARANTINE,
			PQCP_FLEET_AUDIT_CRITICAL,
			"risk-engine",
			operations->device->record.boot_counter,
			-EACCES,
			(const uint8_t *)&risk_score,
			sizeof(risk_score), now_ms, NULL);
	}
	return ret;
}

int pqcp_fleet_operations_tick(
	struct pqcp_fleet_operations *operations,
	uint64_t now_ms)
{
	uint32_t expired = 0U;
	uint32_t updates_changed = 0U;
	int first_error = 0;
	int ret;

	if (operations == NULL || !operations->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = pqcp_fleet_device_tick(
		operations->device, now_ms);
	retain_first_error(ret, &first_error);
	ret = pqcp_fleet_command_expire(
		&operations->commands, now_ms, &expired);
	retain_first_error(ret, &first_error);
	ret = pqcp_fleet_update_tick(
		&operations->updates, now_ms,
		&updates_changed);
	retain_first_error(ret, &first_error);
	if (expired != 0U) {
		(void)pqcp_fleet_telemetry_record(
			&operations->telemetry,
			PQCP_FLEET_METRIC_FAILURES,
			expired, now_ms);
	}
	if (updates_changed != 0U) {
		(void)pqcp_fleet_audit_append(
			&operations->audit,
			PQCP_FLEET_AUDIT_UPDATE_ACTIVATED,
			PQCP_FLEET_AUDIT_NOTICE,
			"update-manager",
			operations->tick_count + 1U, 0,
			(const uint8_t *)&updates_changed,
			sizeof(updates_changed), now_ms, NULL);
	}
	operations->tick_count++;
	return first_error;
}

int pqcp_fleet_operations_audit(
	struct pqcp_fleet_operations *operations,
	uint64_t now_ms)
{
	int ret;

	if (operations == NULL || !operations->initialized ||
	    operations->schema_version !=
		    PQCP_FLEET_OPERATIONS_SCHEMA_VERSION ||
	    operations->device == NULL ||
	    !operations->device->initialized ||
	    operations->security_level == 0U ||
	    operations->security_level > 5U ||
	    operations->risk_score > 1000U ||
	    now_ms == 0U ||
	    (!operations->online &&
	     operations->channel_identity_verified)) {
		return -EINVAL;
	}
	ret = pqcp_fleet_device_audit(
		operations->device, now_ms);
	if (ret == 0) {
		ret = pqcp_fleet_policy_engine_audit(
			&operations->policy);
	}
	if (ret == 0) {
		ret = pqcp_fleet_command_queue_audit(
			&operations->commands);
	}
	if (ret == 0) {
		ret = pqcp_fleet_update_manager_audit(
			&operations->updates);
	}
	if (ret == 0) {
		ret = pqcp_fleet_audit_verify(
			&operations->audit);
	}
	if (ret == 0) {
		ret = pqcp_fleet_telemetry_audit(
			&operations->telemetry);
	}
	return ret;
}
