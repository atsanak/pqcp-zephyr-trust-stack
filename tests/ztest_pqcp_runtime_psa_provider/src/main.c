/*
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/runtime_key_store.h>

#define MOCK_KEY_BASE UINT32_C(0x7fff0000)
#define MOCK_KEY_COUNT 4U

struct mock_persistent_key {
	uint32_t key_id;
	uint8_t public_data[PQCP_RUNTIME_MAX_PUBLIC_KEY_BYTES];
	size_t public_length;
	bool active;
};

static struct mock_persistent_key mock_keys[MOCK_KEY_COUNT];

static struct mock_persistent_key *mock_find(uint32_t key_id)
{
	for (size_t index = 0U; index < ARRAY_SIZE(mock_keys); ++index) {
		if (mock_keys[index].active &&
		    mock_keys[index].key_id == key_id) {
			return &mock_keys[index];
		}
	}
	return NULL;
}

static struct mock_persistent_key *mock_free(void)
{
	for (size_t index = 0U; index < ARRAY_SIZE(mock_keys); ++index) {
		if (!mock_keys[index].active) {
			return &mock_keys[index];
		}
	}
	return NULL;
}

int pqcp_runtime_psa_provider_probe(void)
{
	return 0;
}

int pqcp_runtime_psa_provider_generate(
	uint32_t key_id,
	const struct pqcp_runtime_key_request *request)
{
	struct mock_persistent_key *key = mock_free();
	size_t public_length;

	if (key == NULL || request == NULL) {
		return -ENOSPC;
	}
	switch (request->family) {
	case PQCP_RUNTIME_KEY_MLKEM_KEYPAIR:
		public_length = pqcp_mlkem_pk_size(
			(pqcp_mlkem_level_t)request->level);
		break;
	case PQCP_RUNTIME_KEY_MLDSA_KEYPAIR:
		public_length = pqcp_mldsa_pk_size(
			(pqcp_mldsa_level_t)request->level);
		break;
	default:
		return -ENOTSUP;
	}
	memset(key, 0, sizeof(*key));
	key->key_id = key_id;
	key->public_length = public_length;
	for (size_t index = 0U; index < public_length; ++index) {
		key->public_data[index] =
			(uint8_t)(key_id + index);
	}
	key->active = true;
	return 0;
}

int pqcp_runtime_psa_provider_import(
	uint32_t key_id,
	const struct pqcp_runtime_key_request *request,
	const uint8_t *public_data,
	size_t public_length,
	const uint8_t *secret_data,
	size_t secret_length)
{
	struct mock_persistent_key *key = mock_free();

	ARG_UNUSED(request);
	ARG_UNUSED(secret_data);
	ARG_UNUSED(secret_length);
	if (key == NULL || public_data == NULL ||
	    public_length > sizeof(key->public_data)) {
		return -EINVAL;
	}
	memset(key, 0, sizeof(*key));
	key->key_id = key_id;
	memcpy(key->public_data, public_data, public_length);
	key->public_length = public_length;
	key->active = true;
	return 0;
}

int pqcp_runtime_psa_provider_open(
	uint32_t key_id,
	const struct pqcp_runtime_key_request *request)
{
	ARG_UNUSED(request);
	return mock_find(key_id) != NULL ? 0 : -ENOENT;
}

int pqcp_runtime_psa_provider_export_public(
	uint32_t key_id,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	struct mock_persistent_key *key = mock_find(key_id);

	if (key == NULL || output == NULL || output_length == NULL) {
		return -ENOENT;
	}
	if (output_capacity < key->public_length) {
		return -ENOSPC;
	}
	memcpy(output, key->public_data, key->public_length);
	*output_length = key->public_length;
	return 0;
}

int pqcp_runtime_psa_provider_destroy(uint32_t key_id)
{
	struct mock_persistent_key *key = mock_find(key_id);

	if (key == NULL) {
		return -ENOENT;
	}
	memset(key, 0, sizeof(*key));
	return 0;
}

ZTEST(pqcp_runtime_psa_provider, test_persistent_metadata_and_stale_handle)
{
	struct pqcp_runtime_key_store store;
	struct pqcp_runtime_psa_context context;
	struct pqcp_runtime_key_request request = {
		.family = PQCP_RUNTIME_KEY_MLDSA_KEYPAIR,
		.level = 65U,
		.usage = PQCP_RUNTIME_USAGE_SIGN |
			 PQCP_RUNTIME_USAGE_EXPORT_PUBLIC |
			 PQCP_RUNTIME_USAGE_DESTROY,
		.now_ms = 1000U,
		.expires_at_ms = 5000U,
		.owner = "persistent-owner",
		.label = "persistent-identity",
		.persistent = true,
		.exportable_public = true,
	};
	struct pqcp_runtime_key_handle handle;
	struct pqcp_runtime_key_handle stale;
	struct pqcp_runtime_key_metadata metadata;
	uint32_t bitmap[1];
	uint8_t public_key[PQCP_MLDSA_PK_SIZE_MAX];
	size_t public_length = 0U;

	memset(mock_keys, 0, sizeof(mock_keys));
	zassert_ok(pqcp_runtime_psa_store_init(
		&store, &context, MOCK_KEY_BASE,
		MOCK_KEY_COUNT, bitmap, ARRAY_SIZE(bitmap)));
	zassert_true(pqcp_runtime_psa_persistence_available(&store));
	zassert_ok(pqcp_runtime_key_store_generate(
		&store, &request, &handle));
	stale = handle;
	zassert_ok(pqcp_runtime_key_store_metadata(
		&store, &handle, &metadata));
	zassert_equal(metadata.usage, request.usage);
	zassert_equal(metadata.created_at_ms, request.now_ms);
	zassert_equal(metadata.expires_at_ms, request.expires_at_ms);
	zassert_true(metadata.persistent);
	zassert_equal(strcmp(metadata.owner, request.owner), 0);
	zassert_equal(strcmp(metadata.label, request.label), 0);
	zassert_ok(pqcp_runtime_key_store_export_public(
		&store, &handle, public_key, sizeof(public_key),
		&public_length));
	zassert_equal(
		public_length, pqcp_mldsa_pk_size(PQCP_MLDSA_65));
	zassert_ok(pqcp_runtime_key_store_destroy(
		&store, &handle));
	zassert_equal(pqcp_runtime_key_store_metadata(
		&store, &stale, &metadata), -ENOENT);
	zassert_ok(pqcp_runtime_key_store_audit(&store));
}

ZTEST(pqcp_runtime_psa_provider, test_persistent_expiry_destroys_provider_key)
{
	struct pqcp_runtime_key_store store;
	struct pqcp_runtime_psa_context context;
	struct pqcp_runtime_key_request request = {
		.family = PQCP_RUNTIME_KEY_MLKEM_KEYPAIR,
		.level = 768U,
		.usage = PQCP_RUNTIME_USAGE_DECAPSULATE |
			 PQCP_RUNTIME_USAGE_EXPORT_PUBLIC |
			 PQCP_RUNTIME_USAGE_DESTROY,
		.now_ms = 1000U,
		.expires_at_ms = 2000U,
		.owner = "expiry-owner",
		.label = "persistent-kem",
		.persistent = true,
		.exportable_public = true,
	};
	struct pqcp_runtime_key_handle handle;
	struct pqcp_runtime_key_metadata metadata;
	uint32_t bitmap[1];
	uint32_t expired = 0U;

	memset(mock_keys, 0, sizeof(mock_keys));
	zassert_ok(pqcp_runtime_psa_store_init(
		&store, &context, MOCK_KEY_BASE,
		MOCK_KEY_COUNT, bitmap, ARRAY_SIZE(bitmap)));
	zassert_ok(pqcp_runtime_key_store_generate(
		&store, &request, &handle));
	zassert_ok(pqcp_runtime_key_store_expire(
		&store, 2500U, &expired));
	zassert_equal(expired, 1U);
	zassert_equal(pqcp_runtime_key_store_metadata(
		&store, &handle, &metadata), -ENOENT);
	zassert_ok(pqcp_runtime_key_store_audit(&store));
}

ZTEST_SUITE(
	pqcp_runtime_psa_provider, NULL, NULL, NULL, NULL, NULL);
