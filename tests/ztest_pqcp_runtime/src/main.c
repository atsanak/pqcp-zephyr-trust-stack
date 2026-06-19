/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/build_manifest.h>
#include <pqcp_zephyr/runtime_lease.h>
#include <pqcp_zephyr/runtime_service.h>

#define TEST_KEYS 12U
#define TEST_WORKSPACES 2U
#define TEST_WORKSPACE_BYTES 49152U
#define TEST_JOBS 8U
#define TEST_SESSIONS 4U
#define TEST_PROFILES 8U
#define TEST_AUDIT_ENTRIES 32U
#define TEST_IDENTITIES 4U
#define TEST_QUOTAS 4U
#define TEST_LEASES 4U

static struct pqcp_adaptive_control_plane adaptive;
static struct pqcp_runtime_service service;
static struct pqcp_runtime_volatile_slot key_slots[TEST_KEYS];
static struct pqcp_runtime_workspace_slot
	workspace_slots[TEST_WORKSPACES];
static uint8_t workspace_bytes[
	TEST_WORKSPACES * TEST_WORKSPACE_BYTES];
static struct pqcp_runtime_queue_entry queue[TEST_JOBS];
static struct pqcp_runtime_session sessions[TEST_SESSIONS];
static struct pqcp_runtime_profile_state profiles[TEST_PROFILES];
static struct pqcp_runtime_audit_entry audit_entries[TEST_AUDIT_ENTRIES];
static struct pqcp_runtime_identity identities[TEST_IDENTITIES];
static struct pqcp_runtime_admission_quota quotas[TEST_QUOTAS];
static struct pqcp_runtime_key_lease leases[TEST_LEASES];
static struct pqcp_runtime_lease_manager lease_manager;

static const struct pqcp_runtime_service_storage storage = {
	.key_slots = key_slots,
	.key_slot_count = ARRAY_SIZE(key_slots),
	.workspace_slots = workspace_slots,
	.workspace_bytes = workspace_bytes,
	.workspace_slot_count = ARRAY_SIZE(workspace_slots),
	.workspace_bytes_per_slot = TEST_WORKSPACE_BYTES,
	.queue = queue,
	.queue_capacity = ARRAY_SIZE(queue),
	.sessions = sessions,
	.session_capacity = ARRAY_SIZE(sessions),
	.profile_states = profiles,
	.profile_state_capacity = ARRAY_SIZE(profiles),
	.audit_entries = audit_entries,
	.audit_capacity = ARRAY_SIZE(audit_entries),
	.identities = identities,
	.identity_capacity = ARRAY_SIZE(identities),
	.quotas = quotas,
	.quota_capacity = ARRAY_SIZE(quotas),
};

static void reset_runtime(void)
{
	memset(&adaptive, 0, sizeof(adaptive));
	memset(&service, 0, sizeof(service));
	zassert_ok(pqcp_adaptive_control_init(
		&adaptive, "runtime-test",
		PQCP_ADAPTIVE_POLICY_GATEWAY,
		"hybrid768-65-runtime", 1000U));
	zassert_ok(pqcp_runtime_service_init(
		&service, &storage, &adaptive, 1000U));
}

static bool contains_bytes(
	const uint8_t *haystack,
	size_t haystack_length,
	const uint8_t *needle,
	size_t needle_length)
{
	if (needle_length == 0U || haystack_length < needle_length) {
		return false;
	}
	for (size_t offset = 0U;
	     offset <= haystack_length - needle_length; ++offset) {
		if (memcmp(
			    haystack + offset, needle,
			    needle_length) == 0) {
			return true;
		}
	}
	return false;
}

ZTEST(pqcp_runtime, test_build_capability_is_executable)
{
	struct pqcp_runtime_capability capability;
	struct pqcp_adaptive_profile_registry registry;

	zassert_ok(pqcp_runtime_capability_current(&capability));
	zassert_true(capability.executable_runtime);
	zassert_true(capability.adaptive_integration);
	zassert_not_equal(capability.mlkem_level_mask, 0U);
	zassert_not_equal(capability.mldsa_level_mask, 0U);
	zassert_ok(pqcp_runtime_capability_validate(&capability));
	zassert_ok(pqcp_runtime_profile_registry_build(&registry));
	if (IS_ENABLED(CONFIG_PQCP_MLKEM_MULTI_LEVEL) &&
	    IS_ENABLED(CONFIG_PQCP_MLDSA_MULTI_LEVEL)) {
		zassert_equal(
			capability.mlkem_level_mask,
			PQCP_BUILD_MLKEM_LEVEL_512 |
			PQCP_BUILD_MLKEM_LEVEL_768 |
			PQCP_BUILD_MLKEM_LEVEL_1024);
		zassert_equal(
			capability.mldsa_level_mask,
			PQCP_BUILD_MLDSA_LEVEL_44 |
			PQCP_BUILD_MLDSA_LEVEL_65 |
			PQCP_BUILD_MLDSA_LEVEL_87);
		zassert_equal(registry.count, 12U);
	} else {
		zassert_equal(
			capability.mlkem_level_mask,
			PQCP_BUILD_MLKEM_LEVEL_768);
		zassert_equal(
			capability.mldsa_level_mask,
			PQCP_BUILD_MLDSA_LEVEL_65);
		zassert_equal(registry.count, 3U);
	}
}

ZTEST(pqcp_runtime, test_real_native_selftest_updates_measurements)
{
	int ret;

	reset_runtime();
	ret = pqcp_runtime_service_selftest(
		&service, 768U, 65U, 2000U);
	zassert_equal(ret, 0, "runtime selftest returned %d", ret);
	zassert_true(service.executor.completed_count >= 4U);
	zassert_equal(service.executor.failed_count, 0U);
	zassert_true(profiles[0].observation_count != 0U ||
		     profiles[1].observation_count != 0U);
	zassert_ok(pqcp_runtime_service_audit(&service));
}

ZTEST(pqcp_runtime, test_key_lease_rejects_stale_handle)
{
	static const uint8_t secret[PQCP_MLKEM_SS_SIZE] = {
		0x42, 0x11, 0x9a, 0x7c
	};
	struct pqcp_runtime_key_request request = {
		.family = PQCP_RUNTIME_KEY_SHARED_SECRET,
		.level = 256U,
		.usage = PQCP_RUNTIME_USAGE_DERIVE |
			 PQCP_RUNTIME_USAGE_DESTROY,
		.now_ms = 2000U,
		.expires_at_ms = 10000U,
		.owner = "lease-test",
		.label = "shared-secret",
	};
	struct pqcp_runtime_key_handle key;
	struct pqcp_runtime_key_handle authorized;
	struct pqcp_runtime_key_lease *lease;

	reset_runtime();
	zassert_ok(pqcp_runtime_key_store_create(
		&service.key_store, &request, NULL, 0U,
		secret, sizeof(secret), &key));
	zassert_ok(pqcp_runtime_lease_manager_init(
		&lease_manager, &service.key_store,
		leases, ARRAY_SIZE(leases), NULL));
	zassert_ok(pqcp_runtime_lease_issue(
		&lease_manager, &key, "lease-test",
		PQCP_RUNTIME_USAGE_DERIVE, 2000U, 3000U, &lease));
	zassert_ok(pqcp_runtime_lease_authorize(
		&lease_manager, lease->lease_id, "lease-test",
		PQCP_RUNTIME_USAGE_DERIVE, 2100U, &authorized));
	zassert_true(pqcp_runtime_key_handle_equal(&key, &authorized));
	zassert_ok(pqcp_runtime_key_store_destroy(
		&service.key_store, &key));
	zassert_not_equal(pqcp_runtime_lease_authorize(
		&lease_manager, lease->lease_id, "lease-test",
		PQCP_RUNTIME_USAGE_DERIVE, 2200U, &authorized), 0);
	zassert_equal(lease->state, PQCP_RUNTIME_LEASE_STALE);
}

ZTEST(pqcp_runtime, test_psa_persistence_fails_closed)
{
	struct pqcp_runtime_key_store store;
	struct pqcp_runtime_psa_context context;
	uint32_t bitmap[1];

	zassert_equal(pqcp_runtime_psa_store_init(
		&store, &context, 0x7fff0000U, 8U,
		bitmap, ARRAY_SIZE(bitmap)), -ENOTSUP);
	zassert_false(pqcp_runtime_psa_persistence_available(&store));
}

ZTEST(pqcp_runtime, test_snapshot_contains_references_not_secrets)
{
	static const uint8_t secret[PQCP_MLKEM_SS_SIZE] = {
		0x6a, 0xd4, 0x91, 0x2e, 0x7b, 0xc8, 0x53, 0xaf,
		0x15, 0xe1, 0x49, 0x8c, 0x32, 0x77, 0xb0, 0x5d,
		0xee, 0x18, 0x63, 0x9a, 0x41, 0xf5, 0x0c, 0xd7,
		0x84, 0x2b, 0xc1, 0x36, 0x99, 0x70, 0x4e, 0xbd,
	};
	struct pqcp_runtime_key_request request = {
		.family = PQCP_RUNTIME_KEY_SHARED_SECRET,
		.level = 256U,
		.usage = PQCP_RUNTIME_USAGE_DERIVE |
			 PQCP_RUNTIME_USAGE_DESTROY,
		.now_ms = 2000U,
		.expires_at_ms = 10000U,
		.owner = "snapshot-test",
		.label = "sentinel-secret",
	};
	struct pqcp_runtime_key_handle handle;
	struct pqcp_runtime_snapshot_info info;
	uint8_t snapshot[1024];

	reset_runtime();
	zassert_ok(pqcp_runtime_key_store_create(
		&service.key_store, &request, NULL, 0U,
		secret, sizeof(secret), &handle));
	memset(sessions, 0, sizeof(sessions));
	sessions[0].schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	sessions[0].session_id = UINT64_C(0x534e415053484f54);
	strcpy(sessions[0].profile_id, "hybrid768-65-runtime");
	sessions[0].mlkem_level = 768U;
	sessions[0].mldsa_level = 65U;
	sessions[0].opened_at_ms = 2000U;
	sessions[0].expires_at_ms = 10000U;
	sessions[0].kem_key = handle;
	sessions[0].active = true;
	memset(profiles, 0, sizeof(profiles));
	zassert_ok(pqcp_runtime_profile_state_init(
		&profiles[0], "hybrid768-65-runtime"));
	zassert_ok(pqcp_runtime_snapshot_write(
		sessions, ARRAY_SIZE(sessions),
		profiles, ARRAY_SIZE(profiles),
		snapshot, sizeof(snapshot), &info));
	zassert_equal(info.session_count, 1U);
	zassert_equal(info.profile_count, 1U);
	zassert_equal(info.key_reference_count, 1U);
	zassert_false(contains_bytes(
		snapshot, info.bytes_written,
		secret, sizeof(secret)));
	zassert_ok(pqcp_runtime_key_store_destroy(
		&service.key_store, &handle));
	for (size_t index = 0U;
	     index < sizeof(key_slots[handle.slot].secret_data); ++index) {
		zassert_equal(
			key_slots[handle.slot].secret_data[index], 0U);
	}
}

ZTEST_SUITE(pqcp_runtime, NULL, NULL, NULL, NULL, NULL);
