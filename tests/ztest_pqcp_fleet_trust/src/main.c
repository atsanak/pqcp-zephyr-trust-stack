/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 */

#include <errno.h>
#include <string.h>

#include <psa/crypto.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/fleet_protocol.h>
#include <pqcp_zephyr/fleet_store.h>

struct test_signer_context {
	uint8_t secret_key[PQCP_MLDSA_65_SK_SIZE];
};

struct test_store_backend {
	struct pqcp_fleet_store_record slots[2];
	bool valid[2];
	bool fail_write;
};

static int test_sign(
	void *context, const uint8_t *message, size_t message_length,
	const uint8_t *signature_context,
	size_t signature_context_length,
	uint8_t *signature, size_t signature_capacity,
	size_t *signature_length)
{
	struct test_signer_context *signer = context;

	if (signer == NULL ||
	    signature_capacity < PQCP_FLEET_SIGNATURE_BYTES) {
		return -ENOSPC;
	}
	if (pqcp_mldsa_sign(
		    PQCP_MLDSA_65, signer->secret_key,
		    message, message_length, signature_context,
		    signature_context_length, signature) !=
	    PQCP_MLDSA_SUCCESS) {
		return -EIO;
	}
	*signature_length = PQCP_FLEET_SIGNATURE_BYTES;
	return 0;
}

static int backend_read(
	void *context, size_t slot,
	struct pqcp_fleet_store_record *record)
{
	struct test_store_backend *backend = context;

	if (backend == NULL || record == NULL ||
	    slot >= ARRAY_SIZE(backend->slots) ||
	    !backend->valid[slot]) {
		return -ENOENT;
	}
	*record = backend->slots[slot];
	return 0;
}

static int backend_write(
	void *context, size_t slot,
	const struct pqcp_fleet_store_record *record)
{
	struct test_store_backend *backend = context;

	if (backend == NULL || record == NULL ||
	    slot >= ARRAY_SIZE(backend->slots)) {
		return -EINVAL;
	}
	if (backend->fail_write) {
		return -EIO;
	}
	backend->slots[slot] = *record;
	backend->valid[slot] = true;
	return 0;
}

static int backend_erase(void *context, size_t slot)
{
	struct test_store_backend *backend = context;

	if (backend == NULL || slot >= ARRAY_SIZE(backend->slots)) {
		return -EINVAL;
	}
	memset(&backend->slots[slot], 0, sizeof(backend->slots[slot]));
	backend->valid[slot] = false;
	return 0;
}

static int test_store_init(
	struct pqcp_fleet_store *store,
	struct test_store_backend *backend)
{
	const struct pqcp_fleet_store_backend operations = {
		.context = backend,
		.read_slot = backend_read,
		.write_slot = backend_write,
		.erase_slot = backend_erase,
	};

	return pqcp_fleet_store_init(store, &operations);
}

static void fill_bytes(uint8_t *output, size_t length, uint8_t seed)
{
	for (size_t index = 0U; index < length; ++index) {
		output[index] = (uint8_t)(seed + index);
	}
}

static void fill_enrollment(
	struct pqcp_fleet_enrollment_request *request,
	const uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES])
{
	memset(request, 0, sizeof(*request));
	request->envelope.schema_version = PQCP_FLEET_SCHEMA_VERSION;
	request->envelope.protocol_version = PQCP_FLEET_PROTOCOL_VERSION;
	request->envelope.type = PQCP_FLEET_MESSAGE_ENROLLMENT_REQUEST;
	request->envelope.message_id = 7U;
	request->envelope.sequence = 11U;
	request->envelope.revocation_epoch = 1U;
	request->envelope.issued_at_ms = 1000U;
	request->envelope.expires_at_ms = 5000U;
	fill_bytes(
		request->envelope.nonce,
		sizeof(request->envelope.nonce), 0x10U);
	strcpy(request->envelope.device_id, "edge-001");
	strcpy(request->envelope.domain_id, "pqcp.local");
	request->stage = PQCP_FLEET_ENROLLMENT_FACTORY;
	request->boot_counter = 2U;
	request->enrollment_counter = 3U;
	request->supported_mlkem_mask = PQCP_FLEET_MLKEM_768;
	request->supported_mldsa_mask = PQCP_FLEET_MLDSA_65;
	request->requested_capabilities =
		PQCP_FLEET_CAP_APPLICATION |
		PQCP_FLEET_CAP_POLICY_UPDATE;
	strcpy(request->firmware_version, "1.0.0");
	strcpy(request->product_class, "gateway");
	memcpy(request->factory_public_key, public_key,
	       sizeof(request->factory_public_key));
	zassert_ok(pqcp_fleet_public_key_fingerprint(
		public_key, request->factory_fingerprint));
	fill_bytes(
		request->hardware_id_digest,
		sizeof(request->hardware_id_digest), 0x80U);
	memcpy(request->operational_public_key, public_key,
	       sizeof(request->operational_public_key));
	request->operational_key_present = true;
}

static struct pqcp_fleet_store_record factory_record(uint64_t counter)
{
	struct pqcp_fleet_store_record record;

	memset(&record, 0, sizeof(record));
	record.schema_version = PQCP_FLEET_STORE_SCHEMA_VERSION;
	record.state = PQCP_FLEET_DEVICE_FACTORY;
	record.factory_key.slot = 1U;
	record.factory_key.generation = 1U;
	record.factory_key.backend =
		PQCP_RUNTIME_KEY_BACKEND_VOLATILE;
	record.factory_key.family =
		PQCP_RUNTIME_KEY_MLDSA_KEYPAIR;
	record.factory_key.level = PQCP_MLDSA_65;
	record.factory_key_valid = true;
	record.boot_counter = 1U;
	record.enrollment_counter = counter;
	record.current_firmware_version = 1U;
	fill_bytes(
		record.registrar_public_key,
		sizeof(record.registrar_public_key), 0x20U);
	fill_bytes(
		record.factory_fingerprint,
		sizeof(record.factory_fingerprint), 0x40U);
	return record;
}

ZTEST(pqcp_fleet_trust, test_canonical_enrollment_roundtrip_and_rejection)
{
	struct test_signer_context signer_context;
	struct pqcp_fleet_signer signer = {
		.context = &signer_context,
		.sign = test_sign,
	};
	struct pqcp_fleet_enrollment_request request;
	struct pqcp_fleet_enrollment_request decoded;
	uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES];
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES + 1U];
	uint8_t malformed[PQCP_FLEET_MESSAGE_MAX_BYTES + 1U];
	size_t encoded_length = 0U;

	zassert_equal(pqcp_mldsa_keypair(
		PQCP_MLDSA_65, public_key,
		signer_context.secret_key), PQCP_MLDSA_SUCCESS);
	fill_enrollment(&request, public_key);
	zassert_ok(pqcp_fleet_enrollment_request_sign(
		&request, &signer, 2000U));
	zassert_ok(pqcp_fleet_enrollment_request_encode(
		&request, encoded, sizeof(encoded), &encoded_length));
	zassert_ok(pqcp_fleet_enrollment_request_decode(
		encoded, encoded_length, &decoded));
	zassert_ok(pqcp_fleet_enrollment_request_verify(
		&decoded, public_key, 2000U));

	encoded[encoded_length] = 0U;
	zassert_equal(pqcp_fleet_enrollment_request_decode(
		encoded, encoded_length + 1U, &decoded), -EBADMSG);

	memcpy(malformed, encoded, 2U);
	malformed[2] = 0x18U;
	malformed[3] = 0x01U;
	memcpy(malformed + 4U, encoded + 3U, encoded_length - 3U);
	zassert_equal(pqcp_fleet_enrollment_request_decode(
		malformed, encoded_length + 1U, &decoded), -EBADMSG);

	zassert_ok(pqcp_fleet_enrollment_request_decode(
		encoded, encoded_length, &decoded));
	decoded.signature[0] ^= 1U;
	zassert_equal(pqcp_fleet_enrollment_request_verify(
		&decoded, public_key, 2000U), -EKEYREJECTED);
}

ZTEST(pqcp_fleet_trust, test_store_commit_failure_preserves_caller_state)
{
	static struct test_store_backend backend;
	static struct pqcp_fleet_store store;
	static struct pqcp_fleet_store_record record;
	static struct pqcp_fleet_store_record before_failure;
	uint64_t generation;

	memset(&backend, 0, sizeof(backend));
	record = factory_record(1U);
	zassert_ok(test_store_init(&store, &backend));
	zassert_ok(pqcp_fleet_store_commit(&store, &record));
	generation = store.generation;
	record.enrollment_counter = 9U;
	before_failure = record;
	backend.fail_write = true;
	zassert_equal(
		pqcp_fleet_store_commit(&store, &record), -EIO);
	zassert_mem_equal(&record, &before_failure, sizeof(record));
	zassert_equal(store.generation, generation);
}

ZTEST(pqcp_fleet_trust, test_store_rejects_equal_generation_split_brain)
{
	static struct test_store_backend first_backend;
	static struct test_store_backend second_backend;
	static struct test_store_backend combined;
	static struct pqcp_fleet_store first_store;
	static struct pqcp_fleet_store second_store;
	static struct pqcp_fleet_store combined_store;
	static struct pqcp_fleet_store_record first;
	static struct pqcp_fleet_store_record second;
	static struct pqcp_fleet_store_record loaded;

	memset(&first_backend, 0, sizeof(first_backend));
	memset(&second_backend, 0, sizeof(second_backend));
	memset(&combined, 0, sizeof(combined));
	first = factory_record(1U);
	second = factory_record(2U);
	zassert_ok(test_store_init(&first_store, &first_backend));
	zassert_ok(test_store_init(&second_store, &second_backend));
	zassert_ok(pqcp_fleet_store_commit(&first_store, &first));
	zassert_ok(pqcp_fleet_store_commit(&second_store, &second));
	combined.slots[0] = first_backend.slots[first_store.active_slot];
	combined.slots[1] = second_backend.slots[second_store.active_slot];
	combined.valid[0] = true;
	combined.valid[1] = true;
	zassert_ok(test_store_init(&combined_store, &combined));
	zassert_equal(
		pqcp_fleet_store_load(&combined_store, &loaded), -EBADMSG);
}

static void *fleet_setup(void)
{
	zassert_equal(psa_crypto_init(), PSA_SUCCESS);
	return NULL;
}

ZTEST_SUITE(
	pqcp_fleet_trust, NULL, fleet_setup, NULL, NULL, NULL);
