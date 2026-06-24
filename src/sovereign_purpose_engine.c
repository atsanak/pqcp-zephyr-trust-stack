/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Purpose limitation and composed sovereign privacy authorization.
 */

#include "sovereign_privacy_internal.h"
#include "runtime_internal.h"

#include <errno.h>
#include <limits.h>
#include <string.h>

static ssize_t binding_index_locked(
	const struct pqcp_sovereign_purpose_engine *engine,
	uint32_t binding_id)
{
	size_t index;

	for (index = 0U; index < engine->capacity; ++index) {
		if (engine->bindings[index].enabled &&
		    engine->bindings[index].binding_id == binding_id) {
			return (ssize_t)index;
		}
	}
	return -1;
}

static ssize_t free_binding_index_locked(
	const struct pqcp_sovereign_purpose_engine *engine)
{
	size_t index;

	for (index = 0U; index < engine->capacity; ++index) {
		if (!engine->bindings[index].enabled) {
			return (ssize_t)index;
		}
	}
	return -1;
}

static bool binding_valid(
	const struct pqcp_sovereign_purpose_binding *binding)
{
	uint32_t data_mask =
		(1U << PQCP_SOVEREIGN_DATA_CLASS_COUNT) - 1U;

	return binding != NULL &&
	       pqcp_sovereign_privacy_text_valid(
		       binding->tenant_id,
		       sizeof(binding->tenant_id)) &&
	       pqcp_sovereign_privacy_text_valid(
		       binding->workload_id,
		       sizeof(binding->workload_id)) &&
	       pqcp_sovereign_privacy_text_valid(
		       binding->purpose, sizeof(binding->purpose)) &&
	       binding->allowed_data_class_mask != 0U &&
	       (binding->allowed_data_class_mask & ~data_mask) == 0U &&
	       binding->allowed_operation_mask != 0U &&
	       binding->policy_epoch != 0U &&
	       binding->expires_at_ms != 0U &&
	       binding->maximum_risk <= 1000U &&
	       binding->enabled;
}

int pqcp_sovereign_purpose_engine_init(
	struct pqcp_sovereign_purpose_engine *engine,
	struct pqcp_sovereign_purpose_binding *bindings,
	size_t capacity)
{
	if (engine == NULL || bindings == NULL || capacity == 0U ||
	    capacity > UINT32_MAX) {
		return -EINVAL;
	}
	memset(engine, 0, sizeof(*engine));
	memset(bindings, 0, capacity * sizeof(*bindings));
	engine->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	engine->bindings = bindings;
	engine->capacity = capacity;
	engine->next_binding_id = 1U;
	k_mutex_init(&engine->lock);
	engine->initialized = true;
	return 0;
}

int pqcp_sovereign_purpose_binding_put(
	struct pqcp_sovereign_purpose_engine *engine,
	const struct pqcp_sovereign_purpose_binding *binding)
{
	struct pqcp_sovereign_purpose_binding candidate;
	ssize_t index;

	if (engine == NULL || !engine->initialized ||
	    !binding_valid(binding)) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	if (binding->binding_id != 0U) {
		index = binding_index_locked(
			engine, binding->binding_id);
	} else {
		index = -1;
	}
	if (index < 0) {
		index = free_binding_index_locked(engine);
		if (index < 0) {
			k_mutex_unlock(&engine->lock);
			return -ENOSPC;
		}
		if (engine->next_binding_id == 0U ||
		    engine->next_binding_id == UINT32_MAX) {
			k_mutex_unlock(&engine->lock);
			return -EOVERFLOW;
		}
	}
	candidate = *binding;
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	if (candidate.binding_id == 0U) {
		candidate.binding_id = engine->next_binding_id++;
	}
	candidate.enabled = true;
	engine->bindings[index] = candidate;
	k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_sovereign_purpose_binding_remove(
	struct pqcp_sovereign_purpose_engine *engine,
	uint32_t binding_id)
{
	ssize_t index;

	if (engine == NULL || !engine->initialized ||
	    binding_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	index = binding_index_locked(engine, binding_id);
	if (index < 0) {
		k_mutex_unlock(&engine->lock);
		return -ENOENT;
	}
	memset(&engine->bindings[index], 0,
	       sizeof(engine->bindings[index]));
	k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_sovereign_purpose_authorize(
	struct pqcp_sovereign_purpose_engine *engine,
	const char *tenant_id,
	const char *workload_id,
	const char *purpose,
	enum pqcp_sovereign_operation operation,
	enum pqcp_sovereign_data_class data_class,
	uint32_t risk_score,
	bool consent_valid,
	uint64_t policy_epoch,
	uint64_t now_ms)
{
	size_t index;
	int ret = -EACCES;

	if (engine == NULL || !engine->initialized ||
	    !pqcp_sovereign_privacy_text_valid(
		    tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    workload_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    purpose, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_operation_valid(operation) ||
	    !pqcp_sovereign_privacy_data_class_valid(data_class) ||
	    risk_score > 1000U || policy_epoch == 0U ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (index = 0U; index < engine->capacity; ++index) {
		const struct pqcp_sovereign_purpose_binding *binding =
			&engine->bindings[index];

		if (!binding->enabled ||
		    strcmp(binding->tenant_id, tenant_id) != 0 ||
		    strcmp(binding->workload_id, workload_id) != 0 ||
		    strcmp(binding->purpose, purpose) != 0 ||
		    (binding->allowed_operation_mask &
		     PQCP_SOVEREIGN_BIT(operation)) == 0U ||
		    (binding->allowed_data_class_mask &
		     (1U << (uint32_t)data_class)) == 0U) {
			continue;
		}
		if (binding->policy_epoch != policy_epoch) {
			ret = -ESTALE;
			continue;
		}
		if (binding->expires_at_ms <= now_ms) {
			ret = -ETIME;
			continue;
		}
		if (risk_score > binding->maximum_risk) {
			ret = -ERANGE;
			continue;
		}
		if (binding->require_consent && !consent_valid) {
			ret = -EACCES;
			continue;
		}
		ret = 0;
		break;
	}
	if (ret == 0) {
		engine->allow_count++;
	} else {
		engine->deny_count++;
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}

int pqcp_sovereign_purpose_engine_audit(
	struct pqcp_sovereign_purpose_engine *engine)
{
	size_t index;
	size_t other;
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    engine->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    engine->bindings == NULL || engine->capacity == 0U ||
	    engine->next_binding_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (index = 0U; index < engine->capacity && ret == 0;
	     ++index) {
		const struct pqcp_sovereign_purpose_binding *binding =
			&engine->bindings[index];

		if (!binding->enabled) {
			continue;
		}
		if (binding->schema_version !=
			    PQCP_SOVEREIGN_SCHEMA_VERSION ||
		    binding->binding_id == 0U ||
		    !binding_valid(binding)) {
			ret = -EBADMSG;
			break;
		}
		for (other = index + 1U;
		     other < engine->capacity; ++other) {
			if (engine->bindings[other].enabled &&
			    engine->bindings[other].binding_id ==
				    binding->binding_id) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}

static bool legal_basis_valid(const char *legal_basis)
{
	static const char *const values[] = {
		"consent",
		"contract",
		"legal-obligation",
		"vital-interest",
		"public-task",
		"legitimate-interest",
	};
	size_t index;

	if (!pqcp_sovereign_privacy_text_valid(
		    legal_basis, PQCP_SOVEREIGN_LABEL_MAX_CHARS)) {
		return false;
	}
	for (index = 0U; index < ARRAY_SIZE(values); ++index) {
		if (strcmp(legal_basis, values[index]) == 0) {
			return true;
		}
	}
	return false;
}

static bool privacy_request_valid(
	const struct pqcp_sovereign_privacy_authorization_request *request)
{
	if (request == NULL ||
	    !pqcp_sovereign_privacy_text_valid(
		    request->request_tenant_id,
		    PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    request->resource_tenant_id,
		    PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    request->namespace_id,
		    PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    request->workload_id,
		    PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    request->purpose,
		    PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    !legal_basis_valid(request->legal_basis) ||
	    !pqcp_sovereign_privacy_text_valid(
		    request->source_zone,
		    PQCP_SOVEREIGN_ZONE_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    request->destination_zone,
		    PQCP_SOVEREIGN_ZONE_MAX_CHARS) ||
	    request->resource_class <= PQCP_SOVEREIGN_RESOURCE_NONE ||
	    request->resource_class >= PQCP_SOVEREIGN_RESOURCE_COUNT ||
	    !pqcp_sovereign_privacy_operation_valid(
		    request->operation) ||
	    !pqcp_sovereign_privacy_data_class_valid(
		    request->data_class) ||
	    request->capabilities == 0U ||
	    request->policy_epoch == 0U ||
	    request->revocation_epoch == 0U ||
	    request->now_ms == 0U || request->risk_score > 1000U) {
		return false;
	}
	if (request->consent_required &&
	    (!pqcp_sovereign_privacy_text_valid(
		     request->subject_id,
		     PQCP_SOVEREIGN_SUBJECT_MAX_CHARS) ||
	     !pqcp_sovereign_privacy_text_valid(
		     request->controller_id,
		     PQCP_SOVEREIGN_ID_MAX_CHARS))) {
		return false;
	}
	if (request->budget_required &&
	    (!pqcp_sovereign_privacy_text_valid(
		     request->budget_id,
		     PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	     request->epsilon_micros == 0U ||
	     request->delta_nanos == 0U ||
	     request->query_count == 0U)) {
		return false;
	}
	if (request->contract_required &&
	    (request->contract_id == 0U ||
	     !pqcp_sovereign_privacy_text_valid(
		     request->dataset_id,
		     PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	     request->records == 0U || request->bytes == 0U)) {
		return false;
	}
	if (request->egress_required &&
	    (!pqcp_sovereign_privacy_text_valid(
		     request->destination_domain,
		     PQCP_SOVEREIGN_DOMAIN_MAX_CHARS) ||
	     request->bytes == 0U)) {
		return false;
	}
	return true;
}

static void set_failure(
	struct pqcp_sovereign_privacy_authorization_result *result,
	uint32_t failure,
	const char *reason)
{
	result->decision = PQCP_SOVEREIGN_DECISION_DENY;
	result->failure_mask |= failure;
	(void)pqcp_sovereign_privacy_copy_text(
		result->reason, sizeof(result->reason), reason);
}

static int privacy_decision_digest(
	const struct pqcp_sovereign_privacy_authorization_request *request,
	const struct pqcp_sovereign_privacy_authorization_result *result,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t numeric[112];
	const uint8_t *parts[9];
	size_t lengths[9];
	size_t offset = 0U;

	pqcp_runtime_internal_write_u32(
		&numeric[offset], (uint32_t)request->resource_class);
	offset += sizeof(uint32_t);
	pqcp_runtime_internal_write_u32(
		&numeric[offset], (uint32_t)request->operation);
	offset += sizeof(uint32_t);
	pqcp_runtime_internal_write_u32(
		&numeric[offset], (uint32_t)request->data_class);
	offset += sizeof(uint32_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], request->records);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], request->bytes);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], request->policy_epoch);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], request->revocation_epoch);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], request->now_ms);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u32(
		&numeric[offset], (uint32_t)result->decision);
	offset += sizeof(uint32_t);
	pqcp_runtime_internal_write_u32(
		&numeric[offset], result->failure_mask);
	offset += sizeof(uint32_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], result->federation_grant_id);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u32(
		&numeric[offset], result->residency_rule_id);
	offset += sizeof(uint32_t);
	pqcp_runtime_internal_write_u32(
		&numeric[offset], result->egress_rule_id);
	offset += sizeof(uint32_t);
	parts[0] = (const uint8_t *)request->request_tenant_id;
	lengths[0] = strlen(request->request_tenant_id);
	parts[1] = (const uint8_t *)request->resource_tenant_id;
	lengths[1] = strlen(request->resource_tenant_id);
	parts[2] = (const uint8_t *)request->namespace_id;
	lengths[2] = strlen(request->namespace_id);
	parts[3] = (const uint8_t *)request->workload_id;
	lengths[3] = strlen(request->workload_id);
	parts[4] = (const uint8_t *)request->purpose;
	lengths[4] = strlen(request->purpose);
	parts[5] = (const uint8_t *)request->legal_basis;
	lengths[5] = strlen(request->legal_basis);
	parts[6] = (const uint8_t *)request->source_zone;
	lengths[6] = strlen(request->source_zone);
	parts[7] = (const uint8_t *)request->destination_zone;
	lengths[7] = strlen(request->destination_zone);
	parts[8] = numeric;
	lengths[8] = offset;
	return pqcp_sovereign_privacy_digest_parts(
		parts, lengths, ARRAY_SIZE(parts), output);
}

static int identify_consent(
	struct pqcp_sovereign_consent_ledger *ledger,
	const struct pqcp_sovereign_privacy_authorization_request *request,
	uint64_t *consent_id)
{
	size_t index;

	k_mutex_lock(&ledger->lock, K_FOREVER);
	for (index = 0U; index < ledger->capacity; ++index) {
		const struct pqcp_sovereign_consent_record *record =
			&ledger->records[index];

		if (record->occupied &&
		    record->state == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE &&
		    strcmp(record->tenant_id,
			   request->resource_tenant_id) == 0 &&
		    strcmp(record->subject_id,
			   request->subject_id) == 0 &&
		    strcmp(record->controller_id,
			   request->controller_id) == 0 &&
		    strcmp(record->purpose, request->purpose) == 0 &&
		    (record->data_class_mask &
		     (1U << (uint32_t)request->data_class)) != 0U &&
		    record->policy_epoch == request->policy_epoch &&
		    record->granted_at_ms <= request->now_ms &&
		    record->expires_at_ms > request->now_ms &&
		    record->revoked_at_ms == 0U) {
			*consent_id = record->consent_id;
			k_mutex_unlock(&ledger->lock);
			return 0;
		}
	}
	k_mutex_unlock(&ledger->lock);
	return -EACCES;
}

int pqcp_sovereign_privacy_governor_init(
	struct pqcp_sovereign_privacy_governor *governor,
	struct pqcp_sovereign_tenant_registry *tenants,
	struct pqcp_sovereign_namespace_manager *namespaces,
	struct pqcp_sovereign_federation_manager *federation,
	struct pqcp_sovereign_privacy_budget_manager *budgets,
	struct pqcp_sovereign_residency_engine *residency,
	struct pqcp_sovereign_consent_ledger *consent,
	struct pqcp_sovereign_purpose_engine *purposes,
	struct pqcp_sovereign_retention_manager *retention,
	struct pqcp_sovereign_data_contract_manager *contracts,
	struct pqcp_sovereign_egress_engine *egress)
{
	if (governor == NULL ||
	    tenants == NULL || !tenants->initialized ||
	    namespaces == NULL || !namespaces->initialized ||
	    federation == NULL || !federation->initialized ||
	    budgets == NULL || !budgets->initialized ||
	    residency == NULL || !residency->initialized ||
	    consent == NULL || !consent->initialized ||
	    purposes == NULL || !purposes->initialized ||
	    retention == NULL || !retention->initialized ||
	    contracts == NULL || !contracts->initialized ||
	    egress == NULL || !egress->initialized) {
		return -EINVAL;
	}
	memset(governor, 0, sizeof(*governor));
	governor->tenants = tenants;
	governor->namespaces = namespaces;
	governor->federation = federation;
	governor->budgets = budgets;
	governor->residency = residency;
	governor->consent = consent;
	governor->purposes = purposes;
	governor->retention = retention;
	governor->contracts = contracts;
	governor->egress = egress;
	k_mutex_init(&governor->lock);
	governor->initialized = true;
	return 0;
}

static int evaluate_residency(
	struct pqcp_sovereign_privacy_governor *governor,
	const struct pqcp_sovereign_privacy_authorization_request *request,
	struct pqcp_sovereign_privacy_authorization_result *result)
{
	struct pqcp_sovereign_residency_context context;
	enum pqcp_sovereign_decision decision;
	uint32_t rule_id;
	size_t index;
	int ret;

	memset(&context, 0, sizeof(context));
	(void)pqcp_sovereign_privacy_copy_text(
		context.tenant_id, sizeof(context.tenant_id),
		request->resource_tenant_id);
	(void)pqcp_sovereign_privacy_copy_text(
		context.source_zone, sizeof(context.source_zone),
		request->source_zone);
	(void)pqcp_sovereign_privacy_copy_text(
		context.destination_zone,
		sizeof(context.destination_zone),
		request->destination_zone);
	context.data_class = request->data_class;
	context.now_ms = request->now_ms;
	context.encrypted = request->encrypted;
	context.approved = request->approved;
	ret = pqcp_sovereign_residency_evaluate(
		governor->residency, &context, &decision, &rule_id);
	result->residency_rule_id = rule_id;
	if (ret != 0) {
		return ret;
	}
	k_mutex_lock(&governor->residency->lock, K_FOREVER);
	for (index = 0U; index < governor->residency->capacity;
	     ++index) {
		const struct pqcp_sovereign_residency_rule *rule =
			&governor->residency->rules[index];

		if (rule->enabled && rule->rule_id == rule_id) {
			ret = strcmp(rule->legal_basis,
				     request->legal_basis) == 0 ?
				      0 :
				      -EACCES;
			k_mutex_unlock(&governor->residency->lock);
			return ret;
		}
	}
	k_mutex_unlock(&governor->residency->lock);
	return -EACCES;
}

int pqcp_sovereign_privacy_authorize(
	struct pqcp_sovereign_privacy_governor *governor,
	const struct pqcp_sovereign_privacy_authorization_request *request,
	struct pqcp_sovereign_privacy_authorization_result *result)
{
	bool cross_tenant;
	bool consent_valid = false;
	uint64_t remaining_epsilon;
	uint64_t remaining_delta;
	uint64_t remaining_queries;
	int ret;

	if (governor == NULL || !governor->initialized ||
	    result == NULL) {
		return -EINVAL;
	}
	memset(result, 0, sizeof(*result));
	result->decision = PQCP_SOVEREIGN_DECISION_DENY;
	if (!privacy_request_valid(request)) {
		set_failure(
			result, PQCP_SOVEREIGN_PRIVACY_FAILURE_ARGUMENT,
			"privacy request is incomplete or malformed");
		return -EINVAL;
	}
	k_mutex_lock(&governor->lock, K_FOREVER);
	ret = pqcp_sovereign_tenant_authorize(
		governor->tenants, request->request_tenant_id,
		request->operation, request->capabilities,
		request->policy_epoch, request->revocation_epoch,
		request->now_ms);
	if (ret != 0) {
		set_failure(
			result, PQCP_SOVEREIGN_PRIVACY_FAILURE_TENANT,
			"requesting tenant is not authorized");
		goto denied;
	}
	ret = pqcp_sovereign_namespace_authorize(
		governor->namespaces, request->namespace_id,
		request->operation, request->data_class,
		request->policy_epoch, request->now_ms);
	if (ret != 0) {
		set_failure(
			result, PQCP_SOVEREIGN_PRIVACY_FAILURE_NAMESPACE,
			"namespace policy rejected the operation");
		goto denied;
	}
	cross_tenant = strcmp(
		request->request_tenant_id,
		request->resource_tenant_id) != 0;
	if (cross_tenant) {
		ret = pqcp_sovereign_federation_authorize(
			governor->federation,
			request->request_tenant_id,
			request->resource_tenant_id,
			request->resource_class, request->operation,
			request->data_class, request->purpose,
			request->legal_basis, request->policy_epoch,
			request->revocation_epoch, request->now_ms,
			&result->federation_grant_id);
		if (ret != 0) {
			set_failure(
				result,
				PQCP_SOVEREIGN_PRIVACY_FAILURE_FEDERATION,
				"cross-tenant federation grant is absent or invalid");
			goto denied;
		}
	}
	if (request->consent_required ||
	    strcmp(request->legal_basis, "consent") == 0) {
		ret = pqcp_sovereign_consent_authorize(
			governor->consent,
			request->resource_tenant_id,
			request->subject_id, request->controller_id,
			request->purpose, request->data_class,
			request->policy_epoch, request->now_ms);
		if (ret != 0) {
			set_failure(
				result,
				PQCP_SOVEREIGN_PRIVACY_FAILURE_CONSENT,
				"active consent receipt is required");
			goto denied;
		}
		consent_valid = true;
		(void)identify_consent(
			governor->consent, request,
			&result->consent_id);
	}
	ret = pqcp_sovereign_purpose_authorize(
		governor->purposes, request->resource_tenant_id,
		request->workload_id, request->purpose,
		request->operation, request->data_class,
		request->risk_score, consent_valid,
		request->policy_epoch, request->now_ms);
	if (ret != 0) {
		set_failure(
			result, PQCP_SOVEREIGN_PRIVACY_FAILURE_PURPOSE,
			"purpose binding rejected the operation");
		goto denied;
	}
	ret = evaluate_residency(governor, request, result);
	if (ret != 0) {
		set_failure(
			result,
			PQCP_SOVEREIGN_PRIVACY_FAILURE_RESIDENCY |
				PQCP_SOVEREIGN_PRIVACY_FAILURE_LEGAL_BASIS,
			"residency rule or legal basis rejected movement");
		goto denied;
	}
	if (request->budget_required) {
		ret = pqcp_sovereign_privacy_budget_remaining(
			governor->budgets, request->budget_id,
			request->now_ms, &remaining_epsilon,
			&remaining_delta, &remaining_queries);
		if (ret != 0 ||
		    remaining_epsilon < request->epsilon_micros ||
		    remaining_delta < request->delta_nanos ||
		    remaining_queries < request->query_count) {
			set_failure(
				result,
				PQCP_SOVEREIGN_PRIVACY_FAILURE_BUDGET,
				"privacy composition budget is exhausted");
			goto denied;
		}
	}
	if (request->contract_required) {
		ret = pqcp_sovereign_data_contract_authorize(
			governor->contracts, request->contract_id,
			request->resource_tenant_id,
			request->request_tenant_id,
			request->dataset_id, request->purpose,
			request->operation, request->records,
			request->bytes, request->risk_score,
			consent_valid, request->encrypted,
			request->policy_epoch, request->now_ms);
		if (ret != 0) {
			set_failure(
				result,
				PQCP_SOVEREIGN_PRIVACY_FAILURE_CONTRACT,
				"data contract rejected the transfer");
			goto denied;
		}
	}
	if (request->egress_required) {
		ret = pqcp_sovereign_egress_authorize(
			governor->egress,
			request->resource_tenant_id,
			request->workload_id,
			request->destination_domain,
			request->operation, request->data_class,
			request->bytes, request->risk_score,
			request->encrypted, request->dlp_passed,
			request->now_ms, &result->egress_rule_id);
		if (ret != 0) {
			set_failure(
				result,
				PQCP_SOVEREIGN_PRIVACY_FAILURE_EGRESS,
				"egress policy rejected the transfer");
			goto denied;
		}
	}
	if (request->budget_required) {
		ret = pqcp_sovereign_privacy_budget_consume(
			governor->budgets, request->budget_id,
			request->epsilon_micros,
			request->delta_nanos, request->query_count,
			request->policy_epoch, request->now_ms);
		if (ret != 0) {
			set_failure(
				result,
				PQCP_SOVEREIGN_PRIVACY_FAILURE_BUDGET,
				"privacy budget changed before commit");
			goto denied;
		}
	}
	result->decision = PQCP_SOVEREIGN_DECISION_ALLOW;
	(void)pqcp_sovereign_privacy_copy_text(
		result->reason, sizeof(result->reason),
		"all sovereign privacy controls satisfied");
	governor->authorization_count++;
	(void)privacy_decision_digest(
		request, result, result->decision_digest);
	k_mutex_unlock(&governor->lock);
	return 0;
denied:
	governor->denial_count++;
	(void)privacy_decision_digest(
		request, result, result->decision_digest);
	k_mutex_unlock(&governor->lock);
	return ret != 0 ? ret : -EACCES;
}

int pqcp_sovereign_privacy_governor_audit(
	struct pqcp_sovereign_privacy_governor *governor)
{
	int ret;

	if (governor == NULL || !governor->initialized ||
	    governor->tenants == NULL ||
	    governor->namespaces == NULL ||
	    governor->federation == NULL ||
	    governor->budgets == NULL ||
	    governor->residency == NULL ||
	    governor->consent == NULL ||
	    governor->purposes == NULL ||
	    governor->retention == NULL ||
	    governor->contracts == NULL ||
	    governor->egress == NULL) {
		return -EINVAL;
	}
	ret = pqcp_sovereign_tenant_registry_audit(
		governor->tenants);
	if (ret == 0) {
		ret = pqcp_sovereign_namespace_manager_audit(
			governor->namespaces);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_federation_manager_audit(
			governor->federation);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_privacy_budget_manager_audit(
			governor->budgets);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_residency_engine_audit(
			governor->residency);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_consent_ledger_audit(
			governor->consent);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_purpose_engine_audit(
			governor->purposes);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_retention_manager_audit(
			governor->retention);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_data_contract_manager_audit(
			governor->contracts);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_egress_engine_audit(
			governor->egress);
	}
	return ret;
}
