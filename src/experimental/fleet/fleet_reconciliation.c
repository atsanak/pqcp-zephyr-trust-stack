/*
 * SPDX-License-Identifier: MIT
 *
 * Security-monotonic offline fleet state reconciliation.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/fleet_operations.h>

static bool state_valid(enum pqcp_fleet_device_state state)
{
	return state >= PQCP_FLEET_DEVICE_FACTORY &&
	       state <= PQCP_FLEET_DEVICE_DECOMMISSIONED;
}

static bool digest_zero(
	const uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t aggregate = 0U;

	for (size_t index = 0U;
	     index < PQCP_FLEET_DIGEST_BYTES; ++index) {
		aggregate |= digest[index];
	}
	return aggregate == 0U;
}

static int state_validate(
	const struct pqcp_fleet_reconcile_state *state)
{
	if (state == NULL || !state_valid(state->device_state) ||
	    state->firmware_version == 0U) {
		return -EINVAL;
	}
	if (state->credential_epoch != 0U &&
	    digest_zero(state->credential_digest)) {
		return -EINVAL;
	}
	if (state->policy_epoch != 0U &&
	    digest_zero(state->policy_digest)) {
		return -EINVAL;
	}
	if (state->audit_sequence != 0U &&
	    digest_zero(state->audit_chain_head)) {
		return -EINVAL;
	}
	return 0;
}

static int state_security_rank(
	enum pqcp_fleet_device_state state)
{
	switch (state) {
	case PQCP_FLEET_DEVICE_DECOMMISSIONED:
		return 100;
	case PQCP_FLEET_DEVICE_REVOKED:
		return 90;
	case PQCP_FLEET_DEVICE_RECOVERY:
		return 80;
	case PQCP_FLEET_DEVICE_ROTATING:
		return 60;
	case PQCP_FLEET_DEVICE_OPERATIONAL:
		return 50;
	case PQCP_FLEET_DEVICE_OWNED:
		return 40;
	case PQCP_FLEET_DEVICE_ENROLLING:
		return 30;
	case PQCP_FLEET_DEVICE_FACTORY:
		return 20;
	default:
		return 0;
	}
}

static void select_epochs(
	const struct pqcp_fleet_reconcile_state *local,
	const struct pqcp_fleet_reconcile_state *remote,
	struct pqcp_fleet_reconcile_result *result)
{
	result->selected_policy_epoch =
		local->policy_epoch > remote->policy_epoch ?
			local->policy_epoch : remote->policy_epoch;
	result->selected_revocation_epoch =
		local->revocation_epoch >
				remote->revocation_epoch ?
			local->revocation_epoch :
			remote->revocation_epoch;
	result->selected_credential_epoch =
		local->credential_epoch >
				remote->credential_epoch ?
			local->credential_epoch :
			remote->credential_epoch;
	result->selected_firmware_version =
		local->firmware_version >
				remote->firmware_version ?
			local->firmware_version :
			remote->firmware_version;
}

static bool same_epoch_digest_conflict(
	uint64_t local_epoch,
	uint64_t remote_epoch,
	const uint8_t local_digest[PQCP_FLEET_DIGEST_BYTES],
	const uint8_t remote_digest[PQCP_FLEET_DIGEST_BYTES])
{
	return local_epoch != 0U &&
	       local_epoch == remote_epoch &&
	       memcmp(local_digest, remote_digest,
		      PQCP_FLEET_DIGEST_BYTES) != 0;
}

int pqcp_fleet_reconcile(
	const struct pqcp_fleet_reconcile_state *local,
	const struct pqcp_fleet_reconcile_state *remote,
	struct pqcp_fleet_reconcile_result *result)
{
	if (state_validate(local) != 0 ||
	    state_validate(remote) != 0 || result == NULL) {
		return -EINVAL;
	}
	memset(result, 0, sizeof(*result));
	select_epochs(local, remote, result);
	if (local->policy_epoch != remote->policy_epoch) {
		result->reason_mask |=
			PQCP_FLEET_RECONCILE_REASON_POLICY_EPOCH;
	}
	if (local->revocation_epoch !=
	    remote->revocation_epoch) {
		result->reason_mask |=
			PQCP_FLEET_RECONCILE_REASON_REVOCATION_EPOCH;
	}
	if (local->credential_epoch !=
	    remote->credential_epoch) {
		result->reason_mask |=
			PQCP_FLEET_RECONCILE_REASON_CREDENTIAL_EPOCH;
	}
	if (local->firmware_version !=
	    remote->firmware_version) {
		result->reason_mask |=
			PQCP_FLEET_RECONCILE_REASON_FIRMWARE_VERSION;
	}
	if (local->command_sequence !=
	    remote->command_sequence) {
		result->reason_mask |=
			PQCP_FLEET_RECONCILE_REASON_COMMAND_SEQUENCE;
	}
	if (local->device_state != remote->device_state) {
		result->reason_mask |=
			PQCP_FLEET_RECONCILE_REASON_DEVICE_STATE;
	}
	if (local->capabilities != remote->capabilities) {
		result->reason_mask |=
			PQCP_FLEET_RECONCILE_REASON_CAPABILITIES;
	}
	if (same_epoch_digest_conflict(
		    local->policy_epoch, remote->policy_epoch,
		    local->policy_digest, remote->policy_digest) ||
	    same_epoch_digest_conflict(
		    local->credential_epoch,
		    remote->credential_epoch,
		    local->credential_digest,
		    remote->credential_digest)) {
		result->reason_mask |=
			PQCP_FLEET_RECONCILE_REASON_DIGEST_CONFLICT;
		result->action =
			PQCP_FLEET_RECONCILE_QUARANTINE;
		result->conflict = true;
		result->security_critical = true;
		return 0;
	}
	if (local->audit_sequence == remote->audit_sequence &&
	    local->audit_sequence != 0U &&
	    memcmp(local->audit_chain_head,
		   remote->audit_chain_head,
		   PQCP_FLEET_DIGEST_BYTES) != 0) {
		result->reason_mask |=
			PQCP_FLEET_RECONCILE_REASON_AUDIT_CHAIN |
			PQCP_FLEET_RECONCILE_REASON_DIGEST_CONFLICT;
		result->action =
			PQCP_FLEET_RECONCILE_QUARANTINE;
		result->conflict = true;
		result->security_critical = true;
		return 0;
	}
	if (remote->device_state ==
		    PQCP_FLEET_DEVICE_DECOMMISSIONED ||
	    local->device_state ==
		    PQCP_FLEET_DEVICE_DECOMMISSIONED) {
		result->action =
			PQCP_FLEET_RECONCILE_DECOMMISSION;
		result->security_critical = true;
		return 0;
	}
	if (remote->device_state ==
		    PQCP_FLEET_DEVICE_REVOKED ||
	    local->device_state ==
		    PQCP_FLEET_DEVICE_REVOKED) {
		result->action =
			PQCP_FLEET_RECONCILE_QUARANTINE;
		result->security_critical = true;
		return 0;
	}
	if (remote->revocation_epoch >
	    local->revocation_epoch) {
		result->action =
			PQCP_FLEET_RECONCILE_REQUEST_REVOCATION;
		result->security_critical = true;
		return 0;
	}
	if (local->revocation_epoch >
	    remote->revocation_epoch) {
		result->action =
			PQCP_FLEET_RECONCILE_KEEP_LOCAL;
		result->security_critical = true;
		return 0;
	}
	if (remote->policy_epoch > local->policy_epoch) {
		result->action =
			PQCP_FLEET_RECONCILE_REQUEST_POLICY;
		return 0;
	}
	if (local->policy_epoch > remote->policy_epoch) {
		result->action =
			PQCP_FLEET_RECONCILE_KEEP_LOCAL;
		return 0;
	}
	if (remote->credential_epoch >
	    local->credential_epoch) {
		result->action =
			PQCP_FLEET_RECONCILE_REQUEST_CREDENTIAL;
		return 0;
	}
	if (local->credential_epoch >
	    remote->credential_epoch) {
		result->action =
			PQCP_FLEET_RECONCILE_KEEP_LOCAL;
		return 0;
	}
	if (remote->firmware_version <
	    local->firmware_version) {
		result->action =
			PQCP_FLEET_RECONCILE_KEEP_LOCAL;
		result->security_critical = true;
		return 0;
	}
	if (remote->firmware_version >
	    local->firmware_version) {
		result->action =
			PQCP_FLEET_RECONCILE_ACCEPT_REMOTE;
		return 0;
	}
	if (state_security_rank(remote->device_state) >
	    state_security_rank(local->device_state)) {
		result->action =
			remote->device_state ==
				PQCP_FLEET_DEVICE_RECOVERY ?
				PQCP_FLEET_RECONCILE_ENTER_RECOVERY :
				PQCP_FLEET_RECONCILE_ACCEPT_REMOTE;
		return 0;
	}
	if (state_security_rank(local->device_state) >
	    state_security_rank(remote->device_state)) {
		result->action =
			PQCP_FLEET_RECONCILE_KEEP_LOCAL;
		return 0;
	}
	if ((remote->capabilities & ~local->capabilities) != 0U) {
		/*
		 * Capability expansion is never accepted from reconciliation
		 * alone. It must arrive in a signed credential or policy.
		 */
		result->action =
			PQCP_FLEET_RECONCILE_REQUEST_CREDENTIAL;
		result->security_critical = true;
		return 0;
	}
	if (remote->command_sequence >
	    local->command_sequence) {
		result->action =
			PQCP_FLEET_RECONCILE_ACCEPT_REMOTE;
		return 0;
	}
	result->action = PQCP_FLEET_RECONCILE_NONE;
	return 0;
}
