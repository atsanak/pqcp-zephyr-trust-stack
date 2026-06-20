/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Keepalive and peer-liveness estimator for protected channels.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/protected_channel_operations.h>

static int peer_policy_validate(
	const struct pqcp_channel_peer_policy *policy)
{
	if (policy == NULL ||
	    policy->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    policy->keepalive_interval_ms == 0U ||
	    policy->keepalive_timeout_ms <
		    policy->keepalive_interval_ms ||
	    policy->maximum_missed_keepalives == 0U ||
	    policy->suspect_rtt_ms == 0U ||
	    policy->unreachable_rtt_ms <
		    policy->suspect_rtt_ms ||
	    policy->idle_timeout_ms <
		    policy->keepalive_timeout_ms) {
		return -EINVAL;
	}
	return 0;
}

int pqcp_channel_peer_policy_default(
	struct pqcp_channel_peer_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->schema_version =
		PQCP_CHANNEL_OPERATION_SCHEMA_VERSION;
	policy->keepalive_interval_ms = 5000U;
	policy->keepalive_timeout_ms = 15000U;
	policy->maximum_missed_keepalives = 3U;
	policy->suspect_rtt_ms = 1000U;
	policy->unreachable_rtt_ms = 5000U;
	policy->idle_timeout_ms = 60000U;
	return 0;
}

int pqcp_channel_peer_health_init(
	struct pqcp_channel_peer_health *health,
	const struct pqcp_channel_peer_policy *policy,
	uint64_t now_ms)
{
	if (health == NULL ||
	    peer_policy_validate(policy) != 0 ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	memset(health, 0, sizeof(*health));
	health->schema_version =
		PQCP_CHANNEL_OPERATION_SCHEMA_VERSION;
	health->status = PQCP_CHANNEL_PEER_HEALTHY;
	health->last_send_ms = now_ms;
	health->last_receive_ms = now_ms;
	health->last_ack_ms = now_ms;
	return 0;
}

bool pqcp_channel_peer_probe_due(
	const struct pqcp_channel_peer_health *health,
	const struct pqcp_channel_peer_policy *policy,
	uint64_t now_ms)
{
	uint64_t last_activity;

	if (health == NULL ||
	    health->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    peer_policy_validate(policy) != 0 ||
	    now_ms == 0U ||
	    health->status == PQCP_CHANNEL_PEER_CLOSED ||
	    health->status == PQCP_CHANNEL_PEER_UNREACHABLE) {
		return false;
	}
	if (health->probe_outstanding) {
		return now_ms >= health->last_probe_ms &&
		       now_ms - health->last_probe_ms >=
			       policy->keepalive_timeout_ms;
	}
	last_activity = health->last_send_ms >
				health->last_receive_ms ?
		health->last_send_ms :
		health->last_receive_ms;
	return now_ms >= last_activity &&
	       now_ms - last_activity >=
		       policy->keepalive_interval_ms;
}

int pqcp_channel_peer_probe_sent(
	struct pqcp_channel_peer_health *health,
	uint64_t now_ms)
{
	if (health == NULL ||
	    health->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    now_ms == 0U ||
	    health->status == PQCP_CHANNEL_PEER_CLOSED) {
		return -EINVAL;
	}
	if (health->probe_outstanding) {
		return -EALREADY;
	}
	health->probe_outstanding = true;
	health->last_probe_ms = now_ms;
	health->last_send_ms = now_ms;
	health->probes_sent++;
	return 0;
}

static void update_rtt(
	struct pqcp_channel_peer_health *health,
	uint64_t sample_us)
{
	if (health->smoothed_rtt_us == 0U) {
		health->smoothed_rtt_us = sample_us;
		health->rtt_variance_us = sample_us / 2U;
		return;
	}
	{
		const uint64_t difference =
			health->smoothed_rtt_us > sample_us ?
				health->smoothed_rtt_us - sample_us :
				sample_us -
					health->smoothed_rtt_us;

		health->rtt_variance_us =
			(health->rtt_variance_us * 3U +
			 difference) /
			4U;
		health->smoothed_rtt_us =
			(health->smoothed_rtt_us * 7U +
			 sample_us) /
			8U;
	}
}

int pqcp_channel_peer_probe_ack(
	struct pqcp_channel_peer_health *health,
	const struct pqcp_channel_peer_policy *policy,
	uint64_t now_ms)
{
	uint64_t sample_us;

	if (health == NULL ||
	    health->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    peer_policy_validate(policy) != 0 ||
	    now_ms == 0U || !health->probe_outstanding ||
	    now_ms < health->last_probe_ms) {
		return -EINVAL;
	}
	sample_us =
		(now_ms - health->last_probe_ms) * 1000U;
	update_rtt(health, sample_us);
	health->probe_outstanding = false;
	health->last_ack_ms = now_ms;
	health->last_receive_ms = now_ms;
	health->probes_acked++;
	health->consecutive_misses = 0U;
	if (health->smoothed_rtt_us >
	    (uint64_t)policy->unreachable_rtt_ms * 1000U) {
		health->status =
			PQCP_CHANNEL_PEER_UNREACHABLE;
	} else if (health->smoothed_rtt_us >
		   (uint64_t)policy->suspect_rtt_ms * 1000U) {
		health->status = PQCP_CHANNEL_PEER_SUSPECT;
	} else {
		health->status = PQCP_CHANNEL_PEER_HEALTHY;
	}
	return 0;
}

int pqcp_channel_peer_record_io(
	struct pqcp_channel_peer_health *health,
	uint64_t now_ms,
	size_t sent_bytes,
	size_t received_bytes)
{
	if (health == NULL ||
	    health->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    now_ms == 0U ||
	    sent_bytes > UINT64_MAX - health->bytes_sent ||
	    received_bytes >
		    UINT64_MAX - health->bytes_received) {
		return -EINVAL;
	}
	if (sent_bytes != 0U) {
		health->last_send_ms = now_ms;
		health->bytes_sent += sent_bytes;
	}
	if (received_bytes != 0U) {
		health->last_receive_ms = now_ms;
		health->bytes_received += received_bytes;
		if (health->status ==
		    PQCP_CHANNEL_PEER_SUSPECT) {
			health->status =
				PQCP_CHANNEL_PEER_HEALTHY;
		}
	}
	return 0;
}

int pqcp_channel_peer_tick(
	struct pqcp_channel_peer_health *health,
	const struct pqcp_channel_peer_policy *policy,
	uint64_t now_ms)
{
	uint64_t last_activity;

	if (health == NULL ||
	    health->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    peer_policy_validate(policy) != 0 ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	if (health->status == PQCP_CHANNEL_PEER_CLOSED) {
		return 0;
	}
	if (health->probe_outstanding &&
	    now_ms >= health->last_probe_ms &&
	    now_ms - health->last_probe_ms >=
		    policy->keepalive_timeout_ms) {
		health->probe_outstanding = false;
		health->probes_missed++;
		health->consecutive_misses++;
		if (health->consecutive_misses >=
		    policy->maximum_missed_keepalives) {
			health->status =
				PQCP_CHANNEL_PEER_UNREACHABLE;
		} else {
			health->status =
				PQCP_CHANNEL_PEER_SUSPECT;
		}
	}
	last_activity = health->last_send_ms >
				health->last_receive_ms ?
		health->last_send_ms :
		health->last_receive_ms;
	if (now_ms >= last_activity &&
	    now_ms - last_activity >=
		    policy->idle_timeout_ms) {
		health->status =
			PQCP_CHANNEL_PEER_UNREACHABLE;
	}
	return 0;
}

int pqcp_channel_peer_health_audit(
	const struct pqcp_channel_peer_health *health,
	const struct pqcp_channel_peer_policy *policy)
{
	if (health == NULL ||
	    health->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    peer_policy_validate(policy) != 0 ||
	    health->status < PQCP_CHANNEL_PEER_UNKNOWN ||
	    health->status > PQCP_CHANNEL_PEER_CLOSED ||
	    health->probes_acked > health->probes_sent ||
	    health->probes_missed > health->probes_sent ||
	    health->last_ack_ms > health->last_receive_ms ||
	    (health->probe_outstanding &&
	     health->last_probe_ms == 0U)) {
		return -EBADMSG;
	}
	return 0;
}
