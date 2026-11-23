/*
 * SPDX-License-Identifier: MIT
 *
 * Fleet-level adaptive PQC profile convergence.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/adaptive_control.h>

#include "adaptive_internal.h"

#define PQCP_ADAPTIVE_FLEET_DOMAIN UINT64_C(0x414450464c454554)

struct fleet_group {
	char profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	uint32_t count;
	uint32_t confidence_sum;
	uint32_t security_sum;
};

static bool peer_valid(const struct pqcp_adaptive_peer_report *peer)
{
	return peer != NULL &&
	       peer->schema_version == PQCP_ADAPTIVE_SCHEMA_VERSION &&
	       peer->observed_at_ms != 0U &&
	       peer->confidence <= PQCP_ADAPTIVE_SCORE_MAX &&
	       peer->security_level > 0U &&
	       peer->security_level <= 5U &&
	       peer->resource_pressure <=
		       PQCP_ADAPTIVE_PRESSURE_CRITICAL &&
	       peer->threat_level <= PQCP_ADAPTIVE_THREAT_CRITICAL &&
	       pqcp_adaptive_internal_id_valid(peer->device_id) &&
	       pqcp_adaptive_internal_id_valid(peer->profile_id);
}

static bool peer_fresh(
	const struct pqcp_adaptive_peer_report *peer,
	uint64_t now_ms,
	uint64_t maximum_age_ms)
{
	return peer->observed_at_ms <= now_ms &&
	       (maximum_age_ms == 0U ||
		now_ms - peer->observed_at_ms <= maximum_age_ms);
}

static int peer_index(
	const struct pqcp_adaptive_fleet_state *fleet,
	const char *device_id)
{
	for (uint32_t index = 0U; index < fleet->peer_count; ++index) {
		if (strcmp(fleet->peers[index].device_id,
			   device_id) == 0) {
			return (int)index;
		}
	}
	return -1;
}

static int group_index(
	const struct fleet_group *groups,
	uint32_t group_count,
	const char *profile_id)
{
	for (uint32_t index = 0U; index < group_count; ++index) {
		if (strcmp(groups[index].profile_id, profile_id) == 0) {
			return (int)index;
		}
	}
	return -1;
}

static bool group_better(
	const struct fleet_group *left,
	const struct fleet_group *right)
{
	uint32_t left_confidence;
	uint32_t right_confidence;

	if (left->count != right->count) {
		return left->count > right->count;
	}
	left_confidence = left->count == 0U ?
		0U : left->confidence_sum / left->count;
	right_confidence = right->count == 0U ?
		0U : right->confidence_sum / right->count;
	if (left_confidence != right_confidence) {
		return left_confidence > right_confidence;
	}
	if (left->security_sum != right->security_sum) {
		return left->security_sum > right->security_sum;
	}
	return strcmp(left->profile_id, right->profile_id) < 0;
}

static int fleet_digest(struct pqcp_adaptive_fleet_state *fleet)
{
	struct pqcp_deployment_evidence_digest digest;

	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_FLEET_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, fleet->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, fleet->peer_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, fleet->accepted_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, fleet->rejected_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, fleet->quorum_percent);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, fleet->distinct_profiles);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, fleet->average_confidence);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, fleet->quorum_reached);
	pqcp_deployment_evidence_digest_update_text(
		&digest, fleet->consensus_profile_id);
	for (uint32_t index = 0U; index < fleet->peer_count; ++index) {
		const struct pqcp_adaptive_peer_report *peer =
			&fleet->peers[index];

		pqcp_deployment_evidence_digest_update_text(
			&digest, peer->device_id);
		pqcp_deployment_evidence_digest_update_text(
			&digest, peer->profile_id);
		pqcp_deployment_evidence_digest_update_u64(
			&digest, peer->observed_at_ms);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, peer->confidence);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, peer->security_level);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, peer->resource_pressure);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, peer->threat_level);
		pqcp_deployment_evidence_digest_update_bool(
			&digest, peer->production_allowed);
		pqcp_deployment_evidence_digest_update_text(
			&digest, peer->recommendation_digest_hex);
	}
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, fleet->fleet_digest_hex);
}

static int recompute_fleet(
	struct pqcp_adaptive_fleet_state *fleet,
	uint32_t required_quorum_percent)
{
	struct fleet_group groups[PQCP_ADAPTIVE_MAX_PEERS];
	uint32_t group_count = 0U;
	uint64_t confidence_sum = 0U;
	int best = -1;

	memset(groups, 0, sizeof(groups));
	fleet->accepted_count = 0U;
	fleet->distinct_profiles = 0U;
	fleet->average_confidence = 0U;
	fleet->quorum_percent = 0U;
	fleet->quorum_reached = false;
	fleet->consensus_profile_id[0] = '\0';
	for (uint32_t index = 0U; index < fleet->peer_count; ++index) {
		const struct pqcp_adaptive_peer_report *peer =
			&fleet->peers[index];
		int group;

		if (!peer_valid(peer) || !peer->production_allowed) {
			continue;
		}
		fleet->accepted_count++;
		confidence_sum += peer->confidence;
		group = group_index(
			groups, group_count, peer->profile_id);
		if (group < 0) {
			if (group_count >= PQCP_ADAPTIVE_MAX_PEERS) {
				continue;
			}
			group = (int)group_count++;
			pqcp_adaptive_internal_set_text(
				groups[group].profile_id,
				sizeof(groups[group].profile_id),
				peer->profile_id);
		}
		groups[group].count++;
		groups[group].confidence_sum += peer->confidence;
		groups[group].security_sum += peer->security_level;
	}
	fleet->distinct_profiles = group_count;
	if (fleet->accepted_count != 0U) {
		fleet->average_confidence =
			(uint32_t)(confidence_sum /
				   fleet->accepted_count);
	}
	for (uint32_t index = 0U; index < group_count; ++index) {
		if (best < 0 ||
		    group_better(&groups[index], &groups[best])) {
			best = (int)index;
		}
	}
	if (best >= 0 && fleet->accepted_count != 0U) {
		fleet->quorum_percent =
			(groups[best].count * 100U) /
			fleet->accepted_count;
		fleet->quorum_reached =
			fleet->quorum_percent >=
			required_quorum_percent;
		pqcp_adaptive_internal_set_text(
			fleet->consensus_profile_id,
			sizeof(fleet->consensus_profile_id),
			groups[best].profile_id);
	}
	return fleet_digest(fleet);
}

int pqcp_adaptive_fleet_init(struct pqcp_adaptive_fleet_state *fleet)
{
	if (fleet == NULL) {
		return -EINVAL;
	}
	memset(fleet, 0, sizeof(*fleet));
	fleet->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	return fleet_digest(fleet);
}

int pqcp_adaptive_fleet_update(
	struct pqcp_adaptive_fleet_state *fleet,
	const struct pqcp_adaptive_peer_report *peer,
	uint64_t now_ms,
	uint64_t maximum_age_ms,
	uint32_t required_quorum_percent)
{
	int index;

	if (fleet == NULL ||
	    fleet->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    !peer_valid(peer) ||
	    required_quorum_percent > 100U) {
		return -EINVAL;
	}
	if (!peer_fresh(peer, now_ms, maximum_age_ms)) {
		fleet->rejected_count++;
		return -ESTALE;
	}
	index = peer_index(fleet, peer->device_id);
	if (index < 0) {
		if (fleet->peer_count >= PQCP_ADAPTIVE_MAX_PEERS) {
			fleet->rejected_count++;
			return -ENOSPC;
		}
		index = (int)fleet->peer_count++;
	}
	fleet->peers[index] = *peer;
	return recompute_fleet(fleet, required_quorum_percent);
}

int pqcp_adaptive_fleet_remove_stale(
	struct pqcp_adaptive_fleet_state *fleet,
	uint64_t now_ms,
	uint64_t maximum_age_ms,
	uint32_t required_quorum_percent)
{
	uint32_t write = 0U;
	uint32_t removed = 0U;

	if (fleet == NULL ||
	    fleet->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    required_quorum_percent > 100U) {
		return -EINVAL;
	}
	for (uint32_t read = 0U; read < fleet->peer_count; ++read) {
		if (!peer_fresh(
			    &fleet->peers[read], now_ms,
			    maximum_age_ms)) {
			removed++;
			continue;
		}
		if (write != read) {
			fleet->peers[write] = fleet->peers[read];
		}
		write++;
	}
	for (uint32_t index = write;
	     index < fleet->peer_count; ++index) {
		memset(&fleet->peers[index], 0,
		       sizeof(fleet->peers[index]));
	}
	fleet->peer_count = write;
	if (recompute_fleet(
		    fleet, required_quorum_percent) != 0) {
		return -EBADMSG;
	}
	return (int)removed;
}

int pqcp_adaptive_fleet_emit(
	const struct pqcp_adaptive_fleet_state *fleet)
{
	if (fleet == NULL ||
	    fleet->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    fleet->peer_count > PQCP_ADAPTIVE_MAX_PEERS) {
		return -EINVAL;
	}
	for (uint32_t index = 0U; index < fleet->peer_count; ++index) {
		const struct pqcp_adaptive_peer_report *peer =
			&fleet->peers[index];

		printk("PQCP_ADAPTIVE_FLEET_PEER schema=%u index=%u device=%s profile=%s observed_ms=%llu confidence=%u security=%u pressure=%u threat=%u production=%u recommendation=%s\n",
		       peer->schema_version,
		       index,
		       peer->device_id,
		       peer->profile_id,
		       (unsigned long long)peer->observed_at_ms,
		       peer->confidence,
		       peer->security_level,
		       peer->resource_pressure,
		       peer->threat_level,
		       peer->production_allowed ? 1U : 0U,
		       peer->recommendation_digest_hex);
	}
	printk("PQCP_ADAPTIVE_FLEET schema=%u peers=%u accepted=%u rejected=%u profiles=%u quorum=%u quorum_reached=%u confidence=%u consensus=%s digest=%s\n",
	       fleet->schema_version,
	       fleet->peer_count,
	       fleet->accepted_count,
	       fleet->rejected_count,
	       fleet->distinct_profiles,
	       fleet->quorum_percent,
	       fleet->quorum_reached ? 1U : 0U,
	       fleet->average_confidence,
	       fleet->consensus_profile_id[0] != '\0' ?
		       fleet->consensus_profile_id : "none",
	       fleet->fleet_digest_hex);
	return 0;
}
