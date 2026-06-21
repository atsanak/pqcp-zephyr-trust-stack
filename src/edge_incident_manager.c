/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Security incident lifecycle and evidence-bound state transitions.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool severity_valid(
	enum pqcp_edge_incident_severity severity)
{
	return severity >=
		       PQCP_EDGE_INCIDENT_INFORMATIONAL &&
	       severity <= PQCP_EDGE_INCIDENT_CRITICAL;
}

static bool state_valid(
	enum pqcp_edge_incident_state state)
{
	return state >= PQCP_EDGE_INCIDENT_EMPTY &&
	       state <= PQCP_EDGE_INCIDENT_CLOSED;
}

static int incident_index(
	const struct pqcp_edge_incident_manager *manager,
	uint64_t incident_id)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (manager->incidents[index].occupied &&
		    manager->incidents[index].incident_id ==
			    incident_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_incident_index(
	const struct pqcp_edge_incident_manager *manager)
{
	int recyclable = -1;
	uint64_t oldest = UINT64_MAX;

	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		const struct pqcp_edge_incident *incident =
			&manager->incidents[index];

		if (!incident->occupied) {
			return (int)index;
		}
		if (incident->state ==
			    PQCP_EDGE_INCIDENT_CLOSED &&
		    incident->updated_at_ms < oldest) {
			oldest = incident->updated_at_ms;
			recyclable = (int)index;
		}
	}
	return recyclable >= 0 ? recyclable : -ENOSPC;
}

static bool signal_present(
	const struct pqcp_edge_incident *incident,
	uint64_t signal_id)
{
	for (uint32_t index = 0U;
	     index < incident->signal_count; ++index) {
		if (incident->signal_ids[index] == signal_id) {
			return true;
		}
	}
	return false;
}

static bool transition_allowed(
	enum pqcp_edge_incident_state current,
	enum pqcp_edge_incident_state next)
{
	switch (current) {
	case PQCP_EDGE_INCIDENT_OPEN:
		return next == PQCP_EDGE_INCIDENT_TRIAGED ||
		       next == PQCP_EDGE_INCIDENT_CONTAINING ||
		       next == PQCP_EDGE_INCIDENT_CLOSED;
	case PQCP_EDGE_INCIDENT_TRIAGED:
		return next ==
			       PQCP_EDGE_INCIDENT_CONTAINING ||
		       next ==
			       PQCP_EDGE_INCIDENT_REMEDIATING ||
		       next == PQCP_EDGE_INCIDENT_CLOSED;
	case PQCP_EDGE_INCIDENT_CONTAINING:
		return next ==
			       PQCP_EDGE_INCIDENT_REMEDIATING ||
		       next == PQCP_EDGE_INCIDENT_MONITORING;
	case PQCP_EDGE_INCIDENT_REMEDIATING:
		return next == PQCP_EDGE_INCIDENT_MONITORING ||
		       next == PQCP_EDGE_INCIDENT_CONTAINING;
	case PQCP_EDGE_INCIDENT_MONITORING:
		return next == PQCP_EDGE_INCIDENT_RESOLVED ||
		       next == PQCP_EDGE_INCIDENT_CONTAINING;
	case PQCP_EDGE_INCIDENT_RESOLVED:
		return next == PQCP_EDGE_INCIDENT_CLOSED ||
		       next == PQCP_EDGE_INCIDENT_OPEN;
	case PQCP_EDGE_INCIDENT_CLOSED:
	case PQCP_EDGE_INCIDENT_EMPTY:
	default:
		return false;
	}
}

static int refresh_digest(
	struct pqcp_edge_incident *incident)
{
	return pqcp_edge_internal_incident_digest(
		incident, incident->incident_digest);
}

int pqcp_edge_incident_manager_init(
	struct pqcp_edge_incident_manager *manager,
	struct pqcp_edge_incident *incidents,
	size_t capacity)
{
	if (manager == NULL || incidents == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(incidents, 0,
	       capacity * sizeof(*incidents));
	manager->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	manager->incidents = incidents;
	manager->capacity = capacity;
	manager->next_incident_id = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_edge_incident_open(
	struct pqcp_edge_incident_manager *manager,
	const char *title,
	const char *subject_id,
	const char *owner_id,
	enum pqcp_edge_incident_severity severity,
	uint32_t risk_score,
	const uint64_t *signal_ids,
	uint32_t signal_count,
	uint64_t now_ms,
	struct pqcp_edge_incident **incident)
{
	struct pqcp_edge_incident candidate;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_edge_internal_text_valid(
		    title, PQCP_EDGE_REASON_MAX_CHARS) ||
	    !pqcp_edge_internal_text_valid(
		    subject_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    !pqcp_edge_internal_text_valid(
		    owner_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    !severity_valid(severity) || risk_score > 1000U ||
	    signal_count > PQCP_EDGE_MAX_INCIDENT_SIGNALS ||
	    (signal_ids == NULL && signal_count != 0U) ||
	    incident == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = free_incident_index(manager);
	if (index < 0) {
		*incident = NULL;
		k_mutex_unlock(&manager->lock);
		return index;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.incident_id =
		pqcp_edge_internal_next_identifier(
			&manager->next_incident_id);
	ret = pqcp_edge_internal_copy_text(
		candidate.title, sizeof(candidate.title), title);
	if (ret == 0) {
		ret = pqcp_edge_internal_copy_text(
			candidate.subject_id,
			sizeof(candidate.subject_id), subject_id);
	}
	if (ret == 0) {
		ret = pqcp_edge_internal_copy_text(
			candidate.owner_id,
			sizeof(candidate.owner_id), owner_id);
	}
	candidate.severity = severity;
	candidate.state = PQCP_EDGE_INCIDENT_OPEN;
	candidate.opened_at_ms = now_ms;
	candidate.updated_at_ms = now_ms;
	candidate.risk_score = risk_score;
	candidate.signal_count = signal_count;
	for (uint32_t signal = 0U;
	     signal < signal_count; ++signal) {
		if (signal_ids[signal] == 0U ||
		    signal_present(&candidate,
				   signal_ids[signal])) {
			ret = -EINVAL;
			break;
		}
		candidate.signal_ids[signal] =
			signal_ids[signal];
	}
	candidate.occupied = true;
	if (ret == 0) {
		ret = refresh_digest(&candidate);
	}
	if (ret == 0) {
		manager->incidents[index] = candidate;
		*incident = &manager->incidents[index];
		++manager->opened_count;
	} else {
		*incident = NULL;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_incident_add_signal(
	struct pqcp_edge_incident_manager *manager,
	uint64_t incident_id,
	uint64_t signal_id,
	uint32_t risk_score,
	enum pqcp_edge_incident_severity severity,
	uint64_t now_ms)
{
	struct pqcp_edge_incident candidate;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    incident_id == 0U || signal_id == 0U ||
	    risk_score > 1000U || !severity_valid(severity)) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = incident_index(manager, incident_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	candidate = manager->incidents[index];
	if (candidate.state ==
		    PQCP_EDGE_INCIDENT_CLOSED ||
	    signal_present(&candidate, signal_id)) {
		ret = candidate.state ==
			    PQCP_EDGE_INCIDENT_CLOSED ?
			    -EPERM : -EALREADY;
		goto out;
	}
	if (candidate.signal_count >=
	    PQCP_EDGE_MAX_INCIDENT_SIGNALS) {
		ret = -ENOSPC;
		goto out;
	}
	candidate.signal_ids[candidate.signal_count++] =
		signal_id;
	if (severity > candidate.severity) {
		candidate.severity = severity;
	}
	if (risk_score > candidate.risk_score) {
		candidate.risk_score = risk_score;
	}
	candidate.updated_at_ms = now_ms;
	ret = refresh_digest(&candidate);
	if (ret == 0) {
		manager->incidents[index] = candidate;
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_incident_transition(
	struct pqcp_edge_incident_manager *manager,
	uint64_t incident_id,
	enum pqcp_edge_incident_state state,
	uint64_t now_ms)
{
	struct pqcp_edge_incident candidate;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    incident_id == 0U || !state_valid(state) ||
	    state == PQCP_EDGE_INCIDENT_EMPTY) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = incident_index(manager, incident_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	candidate = manager->incidents[index];
	if (candidate.state == state) {
		ret = -EALREADY;
		goto out;
	}
	if (!transition_allowed(candidate.state, state)) {
		ret = -EPERM;
		goto out;
	}
	if (state == PQCP_EDGE_INCIDENT_RESOLVED &&
	    candidate.remediation_mask == 0U) {
		ret = -EAGAIN;
		goto out;
	}
	if (state == PQCP_EDGE_INCIDENT_CLOSED &&
	    candidate.state !=
		    PQCP_EDGE_INCIDENT_RESOLVED &&
	    candidate.severity >= PQCP_EDGE_INCIDENT_HIGH) {
		ret = -EPERM;
		goto out;
	}
	candidate.state = state;
	candidate.updated_at_ms = now_ms;
	if (state == PQCP_EDGE_INCIDENT_RESOLVED ||
	    state == PQCP_EDGE_INCIDENT_CLOSED) {
		candidate.resolved_at_ms = now_ms;
	}
	ret = refresh_digest(&candidate);
	if (ret == 0) {
		manager->incidents[index] = candidate;
		if (state == PQCP_EDGE_INCIDENT_RESOLVED) {
			++manager->resolved_count;
		}
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_incident_assign(
	struct pqcp_edge_incident_manager *manager,
	uint64_t incident_id,
	const char *owner_id,
	uint64_t now_ms)
{
	struct pqcp_edge_incident candidate;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    incident_id == 0U ||
	    !pqcp_edge_internal_text_valid(
		    owner_id, PQCP_EDGE_ID_MAX_CHARS)) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = incident_index(manager, incident_id);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return index;
	}
	candidate = manager->incidents[index];
	if (candidate.state == PQCP_EDGE_INCIDENT_CLOSED) {
		k_mutex_unlock(&manager->lock);
		return -EPERM;
	}
	ret = pqcp_edge_internal_copy_text(
		candidate.owner_id,
		sizeof(candidate.owner_id), owner_id);
	if (ret == 0) {
		candidate.updated_at_ms = now_ms;
		ret = refresh_digest(&candidate);
	}
	if (ret == 0) {
		manager->incidents[index] = candidate;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_incident_find(
	struct pqcp_edge_incident_manager *manager,
	uint64_t incident_id,
	struct pqcp_edge_incident **incident)
{
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    incident_id == 0U || incident == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = incident_index(manager, incident_id);
	if (index < 0) {
		*incident = NULL;
		ret = index;
	} else {
		*incident = &manager->incidents[index];
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_incident_manager_audit(
	struct pqcp_edge_incident_manager *manager)
{
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    manager->incidents == NULL ||
	    manager->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_incident *incident =
			&manager->incidents[index];

		if (!incident->occupied) {
			continue;
		}
		if (incident->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    incident->incident_id == 0U ||
		    !severity_valid(incident->severity) ||
		    !state_valid(incident->state) ||
		    incident->state ==
			    PQCP_EDGE_INCIDENT_EMPTY ||
		    incident->signal_count >
			    PQCP_EDGE_MAX_INCIDENT_SIGNALS ||
		    incident->risk_score > 1000U ||
		    incident->updated_at_ms <
			    incident->opened_at_ms ||
		    pqcp_edge_internal_incident_digest(
			    incident, digest) != 0 ||
		    !pqcp_edge_internal_equal(
			    digest, incident->incident_digest,
			    sizeof(digest))) {
			ret = -EBADMSG;
			break;
		}
		for (uint32_t signal = 0U;
		     signal < incident->signal_count; ++signal) {
			if (incident->signal_ids[signal] == 0U) {
				ret = -EBADMSG;
				break;
			}
			for (uint32_t other = signal + 1U;
			     other < incident->signal_count;
			     ++other) {
				if (incident->signal_ids[signal] ==
				    incident->signal_ids[other]) {
					ret = -EEXIST;
					break;
				}
			}
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
