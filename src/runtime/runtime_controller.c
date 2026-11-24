/*
 * SPDX-License-Identifier: MIT
 *
 * High-level operational controller.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_control.h>

#include "runtime_internal.h"

static int append_audit(
	struct pqcp_runtime_controller *controller,
	enum pqcp_runtime_audit_event event,
	uint64_t timestamp_ms,
	uint64_t object_id,
	int result,
	uint32_t reason_mask,
	const char *profile,
	const char *detail)
{
	return pqcp_runtime_audit_append(
		controller->audit, event, timestamp_ms,
		object_id, result, reason_mask,
		profile != NULL ? profile : "none",
		detail != NULL ? detail : "none");
}

int pqcp_runtime_controller_init(
	struct pqcp_runtime_controller *controller,
	struct pqcp_runtime_key_store *key_store,
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_session_manager *sessions,
	struct pqcp_runtime_audit_log *audit,
	uint64_t now_ms)
{
	int ret;

	if (controller == NULL || key_store == NULL ||
	    executor == NULL || sessions == NULL ||
	    audit == NULL || now_ms == 0U ||
	    executor->key_store != key_store ||
	    sessions->executor != executor) {
		return -EINVAL;
	}
	memset(controller, 0, sizeof(*controller));
	controller->schema_version =
		PQCP_RUNTIME_SCHEMA_VERSION;
	controller->key_store = key_store;
	controller->executor = executor;
	controller->sessions = sessions;
	controller->audit = audit;
	ret = pqcp_runtime_key_policy_default(
		&controller->key_policy);
	if (ret == 0) {
		ret = pqcp_runtime_health_policy_default(
			&controller->health_policy);
	}
	if (ret != 0) {
		return ret;
	}
	controller->last_tick_ms = now_ms;
	controller->accepting_sessions = true;
	controller->initialized = true;
	ret = append_audit(
		controller, PQCP_RUNTIME_AUDIT_BOOT,
		now_ms, 0U, 0, 0U, "runtime", "boot");
	if (ret != 0) {
		controller->initialized = false;
		return ret;
	}
	return pqcp_runtime_health_evaluate(
		controller, &controller->health);
}

int pqcp_runtime_controller_open_session(
	struct pqcp_runtime_controller *controller,
	const struct pqcp_runtime_session_request *request,
	struct pqcp_runtime_session **session)
{
	int ret;

	if (controller == NULL || !controller->initialized ||
	    request == NULL || session == NULL) {
		return -EINVAL;
	}
	if (!controller->accepting_sessions ||
	    controller->lockdown) {
		return -ESHUTDOWN;
	}
	ret = pqcp_runtime_session_open(
		controller->sessions, request, session);
	(void)append_audit(
		controller,
		ret == 0 ?
			PQCP_RUNTIME_AUDIT_SESSION_OPEN :
			PQCP_RUNTIME_AUDIT_FAULT,
		request->now_ms, request->session_id,
		ret, 0U, request->profile_id,
		ret == 0 ? "session-open" :
			   "session-open-failed");
	if (ret != 0) {
		controller->consecutive_failures++;
	} else {
		controller->consecutive_failures = 0U;
	}
	return ret;
}

static bool job_key_request_present(
	const struct pqcp_runtime_job *job)
{
	return job->type ==
		       PQCP_RUNTIME_JOB_MLKEM_KEYGEN ||
	       job->type ==
		       PQCP_RUNTIME_JOB_MLDSA_KEYGEN;
}

int pqcp_runtime_controller_submit(
	struct pqcp_runtime_controller *controller,
	uint64_t session_id,
	struct pqcp_runtime_job *job)
{
	uint32_t reason_mask = 0U;
	uint64_t now_ms;
	int ret;

	if (controller == NULL || !controller->initialized ||
	    job == NULL || session_id == 0U) {
		return -EINVAL;
	}
	if (controller->lockdown) {
		return -ESHUTDOWN;
	}
	now_ms = pqcp_runtime_internal_now_ms();
	if (job_key_request_present(job)) {
		ret = pqcp_runtime_key_policy_check(
			&controller->key_policy,
			&job->key_request, &reason_mask);
		if (ret != 0) {
			(void)append_audit(
				controller,
				PQCP_RUNTIME_AUDIT_FAULT,
				now_ms, job->job_id, ret,
				reason_mask, job->profile_id,
				"key-policy-reject");
			controller->consecutive_failures++;
			return ret;
		}
	}
	(void)append_audit(
		controller, PQCP_RUNTIME_AUDIT_JOB_SUBMIT,
		now_ms, job->job_id, 0, 0U,
		job->profile_id, "job-submit");
	ret = pqcp_runtime_session_submit(
		controller->sessions, session_id, job);
	if ((job->flags &
	     PQCP_RUNTIME_JOB_FLAG_SYNCHRONOUS) != 0U ||
	    ret != 0) {
		(void)append_audit(
			controller,
			ret == 0 ?
				PQCP_RUNTIME_AUDIT_JOB_COMPLETE :
				PQCP_RUNTIME_AUDIT_FAULT,
			pqcp_runtime_internal_now_ms(),
			job->job_id, ret, 0U,
			job->profile_id,
			ret == 0 ? "job-complete" :
				   "job-failed");
	}
	if (ret == 0) {
		controller->consecutive_failures = 0U;
	} else {
		controller->consecutive_failures++;
	}
	return ret;
}

int pqcp_runtime_controller_close_session(
	struct pqcp_runtime_controller *controller,
	uint64_t session_id)
{
	const struct pqcp_runtime_session *session;
	char profile[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	int ret;

	if (controller == NULL || !controller->initialized ||
	    session_id == 0U) {
		return -EINVAL;
	}
	session = pqcp_runtime_session_find(
		controller->sessions, session_id);
	if (session != NULL) {
		(void)pqcp_runtime_internal_copy_text(
			profile, sizeof(profile),
			session->profile_id);
	} else {
		(void)pqcp_runtime_internal_copy_text(
			profile, sizeof(profile), "none");
	}
	ret = pqcp_runtime_session_close(
		controller->sessions, session_id);
	(void)append_audit(
		controller,
		ret == 0 ?
			PQCP_RUNTIME_AUDIT_SESSION_CLOSE :
			PQCP_RUNTIME_AUDIT_FAULT,
		pqcp_runtime_internal_now_ms(),
		session_id, ret, 0U, profile,
		ret == 0 ? "session-close" :
			   "session-close-failed");
	return ret;
}

int pqcp_runtime_controller_transition_profile(
	struct pqcp_runtime_controller *controller,
	const char *from_profile,
	const char *to_profile,
	uint64_t now_ms)
{
	const struct pqcp_adaptive_profile *target;
	int drained;

	if (controller == NULL || !controller->initialized ||
	    !pqcp_runtime_internal_text_valid(
		    from_profile, PQCP_RUNTIME_PROFILE_MAX_CHARS) ||
	    !pqcp_runtime_internal_text_valid(
		    to_profile, PQCP_RUNTIME_PROFILE_MAX_CHARS) ||
	    now_ms == 0U || controller->lockdown) {
		return -EINVAL;
	}
	if (controller->sessions->adaptive_control == NULL) {
		return -ENOTSUP;
	}
	target = pqcp_adaptive_profile_registry_find(
		&controller->sessions->adaptive_control->registry,
		to_profile);
	if (target == NULL || !target->enabled) {
		return -ENOENT;
	}
	drained = pqcp_runtime_session_mark_draining(
		controller->sessions, from_profile);
	if (drained == -ENOENT) {
		drained = 0;
	} else if (drained < 0) {
		return drained;
	}
	(void)append_audit(
		controller,
		PQCP_RUNTIME_AUDIT_PROFILE_TRANSITION,
		now_ms, (uint64_t)drained, 0, 0U,
		to_profile, "future-sessions-only");
	return drained;
}

int pqcp_runtime_controller_lockdown(
	struct pqcp_runtime_controller *controller,
	uint32_t reason_mask,
	uint64_t now_ms)
{
	if (controller == NULL || !controller->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	controller->lockdown = true;
	controller->accepting_sessions = false;
	(void)append_audit(
		controller, PQCP_RUNTIME_AUDIT_FAULT,
		now_ms, 0U, -EACCES, reason_mask,
		"runtime", "lockdown");
	return 0;
}

int pqcp_runtime_controller_recover(
	struct pqcp_runtime_controller *controller,
	uint64_t now_ms)
{
	struct pqcp_runtime_health_report report;
	int ret;

	if (controller == NULL || !controller->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = pqcp_runtime_health_evaluate(controller, &report);
	if (report.blocker_mask != 0U) {
		return ret != 0 ? ret : -EAGAIN;
	}
	controller->lockdown = false;
	controller->accepting_sessions = true;
	controller->consecutive_failures = 0U;
	(void)append_audit(
		controller, PQCP_RUNTIME_AUDIT_RESTORE,
		now_ms, 0U, 0, 0U, "runtime", "recover");
	return 0;
}

int pqcp_runtime_controller_tick(
	struct pqcp_runtime_controller *controller,
	uint64_t now_ms)
{
	struct pqcp_runtime_health_report report;
	uint32_t expired_sessions = 0U;
	uint32_t expired_keys = 0U;
	int ret;

	if (controller == NULL || !controller->initialized ||
	    now_ms <= controller->last_tick_ms) {
		return -EINVAL;
	}
	controller->last_tick_ms = now_ms;
	(void)pqcp_runtime_session_expire(
		controller->sessions, now_ms,
		&expired_sessions);
	(void)pqcp_runtime_key_store_expire(
		controller->key_store, now_ms,
		&expired_keys);
	ret = pqcp_runtime_health_evaluate(
		controller, &report);
	if (report.status ==
		    PQCP_RUNTIME_HEALTH_LOCKDOWN ||
	    (report.status ==
		     PQCP_RUNTIME_HEALTH_RECOVERY &&
	     controller->consecutive_failures >=
		     controller->health_policy
			     .maximum_consecutive_failures)) {
		(void)pqcp_runtime_controller_lockdown(
			controller, report.blocker_mask, now_ms);
		return -EACCES;
	}
	controller->accepting_sessions =
		report.status !=
			PQCP_RUNTIME_HEALTH_RECOVERY;
	return ret;
}

int pqcp_runtime_controller_audit(
	struct pqcp_runtime_controller *controller)
{
	if (controller == NULL || !controller->initialized ||
	    controller->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    pqcp_runtime_key_policy_validate(
		    &controller->key_policy) != 0 ||
	    pqcp_runtime_key_store_audit(
		    controller->key_store) != 0 ||
	    pqcp_runtime_executor_audit(
		    controller->executor) != 0 ||
	    pqcp_runtime_session_manager_audit(
		    controller->sessions) != 0 ||
	    pqcp_runtime_audit_verify(
		    controller->audit) != 0) {
		return -EBADMSG;
	}
	return 0;
}
