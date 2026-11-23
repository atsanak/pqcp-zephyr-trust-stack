/*
 * SPDX-License-Identifier: MIT
 *
 * Suite entry point plus the shared bounded primitives of the edge
 * security plane (edge_security_common.c) and the public string helpers.
 */

#include <psa/crypto.h>

#include "edge_security_internal.h"
#include "test_common.h"

static void *suite_setup(void)
{
	zassert_equal(psa_crypto_init(), PSA_SUCCESS);
	return NULL;
}

ZTEST_SUITE(edge_security, NULL, suite_setup, NULL, NULL, NULL);

ZTEST(edge_security, test_string_helpers)
{
	zassert_str_equal(pqcp_edge_operation_str(
		PQCP_EDGE_OPERATION_NONE), "none");
	zassert_str_equal(pqcp_edge_operation_str(
		PQCP_EDGE_OPERATION_PUBLISH), "publish");
	zassert_str_equal(pqcp_edge_operation_str(
		PQCP_EDGE_OPERATION_REPLICATE), "replicate");
	zassert_str_equal(pqcp_edge_operation_str(
		PQCP_EDGE_OPERATION_COUNT), "invalid");
	zassert_str_equal(pqcp_edge_operation_str(
		(enum pqcp_edge_operation)99), "invalid");

	zassert_str_equal(pqcp_edge_incident_state_str(
		PQCP_EDGE_INCIDENT_EMPTY), "empty");
	zassert_str_equal(pqcp_edge_incident_state_str(
		PQCP_EDGE_INCIDENT_CONTAINING), "containing");
	zassert_str_equal(pqcp_edge_incident_state_str(
		PQCP_EDGE_INCIDENT_CLOSED), "closed");
	zassert_str_equal(pqcp_edge_incident_state_str(
		(enum pqcp_edge_incident_state)42), "invalid");
}

ZTEST(edge_security, test_common_text_validation)
{
	char text[8] = "abc";
	char unterminated[4] = { 'a', 'b', 'c', 'd' };
	char empty[4] = { 0 };

	zassert_true(pqcp_edge_internal_text_valid(text, sizeof(text)));
	zassert_false(pqcp_edge_internal_text_valid(NULL, 8U));
	zassert_false(pqcp_edge_internal_text_valid(text, 1U));
	zassert_false(pqcp_edge_internal_text_valid(
		unterminated, sizeof(unterminated)));
	zassert_false(pqcp_edge_internal_text_valid(
		empty, sizeof(empty)));
	/* Capacity shorter than the string: no terminator in range. */
	zassert_false(pqcp_edge_internal_text_valid(text, 3U));

	zassert_equal(pqcp_edge_internal_copy_text(NULL, 8U, "x"),
		      -EINVAL);
	zassert_equal(pqcp_edge_internal_copy_text(text, 8U, NULL),
		      -EINVAL);
	zassert_equal(pqcp_edge_internal_copy_text(text, 1U, "x"),
		      -EINVAL);
	zassert_equal(pqcp_edge_internal_copy_text(text, 8U, ""),
		      -ENAMETOOLONG);
	zassert_equal(pqcp_edge_internal_copy_text(text, 4U, "abcd"),
		      -ENAMETOOLONG);
	zassert_equal(pqcp_edge_internal_copy_text(text, 4U, "abc"), 0);
	zassert_str_equal(text, "abc");
}

ZTEST(edge_security, test_common_counters_and_saturation)
{
	uint32_t generation = UINT32_MAX;
	uint64_t identifier = UINT64_MAX;

	zassert_equal(pqcp_edge_internal_next_generation(NULL), 0U);
	zassert_equal(pqcp_edge_internal_next_identifier(NULL), 0U);
	/* Counters never return zero, even across wrap or from zero. */
	zassert_equal(pqcp_edge_internal_next_generation(&generation), 1U);
	generation = 0U;
	zassert_equal(pqcp_edge_internal_next_generation(&generation), 1U);
	zassert_equal(pqcp_edge_internal_next_generation(&generation), 2U);
	zassert_equal(pqcp_edge_internal_next_identifier(&identifier), 1U);
	identifier = 0U;
	zassert_equal(pqcp_edge_internal_next_identifier(&identifier), 1U);
	zassert_equal(pqcp_edge_internal_next_identifier(&identifier), 2U);

	zassert_equal(pqcp_edge_internal_saturating_add_u64(
		UINT64_MAX - 1U, 5U), UINT64_MAX);
	zassert_equal(pqcp_edge_internal_saturating_add_u64(2U, 3U), 5U);
	zassert_equal(pqcp_edge_internal_saturating_add_u32(
		UINT32_MAX, 1U), UINT32_MAX);
	zassert_equal(pqcp_edge_internal_saturating_add_u32(2U, 3U), 5U);
}

ZTEST(edge_security, test_common_backoff)
{
	zassert_equal(pqcp_edge_internal_backoff(0U, 100U, 3U), 0U);
	zassert_equal(pqcp_edge_internal_backoff(100U, 50U, 3U), 0U);
	zassert_equal(pqcp_edge_internal_backoff(1000U, 4000U, 0U), 1000U);
	zassert_equal(pqcp_edge_internal_backoff(1000U, 4000U, 1U), 1000U);
	zassert_equal(pqcp_edge_internal_backoff(1000U, 4000U, 2U), 2000U);
	zassert_equal(pqcp_edge_internal_backoff(1000U, 4000U, 3U), 4000U);
	zassert_equal(pqcp_edge_internal_backoff(1000U, 4000U, 40U), 4000U);
	zassert_equal(pqcp_edge_internal_backoff(
		UINT64_MAX / 2U + 1U, UINT64_MAX, 40U), UINT64_MAX);
}

ZTEST(edge_security, test_common_byte_helpers)
{
	uint8_t buffer[8];
	const uint8_t zeros[4] = { 0 };
	const uint8_t a[4] = { 1, 2, 3, 4 };
	const uint8_t b[4] = { 1, 2, 3, 5 };

	zassert_true(pqcp_edge_internal_all_zero(zeros, sizeof(zeros)));
	zassert_false(pqcp_edge_internal_all_zero(a, sizeof(a)));
	zassert_true(pqcp_edge_internal_all_zero(NULL, 0U));
	zassert_false(pqcp_edge_internal_all_zero(NULL, 4U));

	zassert_true(pqcp_edge_internal_equal(a, a, sizeof(a)));
	zassert_false(pqcp_edge_internal_equal(a, b, sizeof(a)));
	zassert_true(pqcp_edge_internal_equal(a, b, 3U));
	zassert_false(pqcp_edge_internal_equal(NULL, a, 4U));
	zassert_true(pqcp_edge_internal_equal(NULL, NULL, 0U));

	pqcp_edge_internal_write_u16(buffer, 0x1234U);
	zassert_equal(buffer[0], 0x12U);
	zassert_equal(pqcp_edge_internal_read_u16(buffer), 0x1234U);
	pqcp_edge_internal_write_u32(buffer, 0xA1B2C3D4U);
	zassert_equal(buffer[0], 0xA1U);
	zassert_equal(buffer[3], 0xD4U);
	zassert_equal(pqcp_edge_internal_read_u32(buffer), 0xA1B2C3D4U);
	pqcp_edge_internal_write_u64(buffer, 0x0102030405060708ULL);
	zassert_equal(buffer[0], 0x01U);
	zassert_equal(buffer[7], 0x08U);
	zassert_equal(pqcp_edge_internal_read_u64(buffer),
		      0x0102030405060708ULL);
}

ZTEST(edge_security, test_common_crypto_wrappers)
{
	static const uint8_t abc_digest[32] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
	};
	uint8_t digest[32];
	uint8_t split[32];
	uint8_t tag1[32];
	uint8_t tag2[32];
	uint8_t key1[32];
	uint8_t key2[32];
	uint8_t derived1[32];
	uint8_t derived2[32];
	const uint8_t *parts[2] = {
		(const uint8_t *)"a", (const uint8_t *)"bc" };
	const size_t lengths[2] = { 1U, 2U };

	zassert_equal(pqcp_edge_internal_sha256(
		(const uint8_t *)"abc", 3U, digest), 0);
	zassert_mem_equal(digest, abc_digest, sizeof(digest));
	zassert_equal(pqcp_edge_internal_sha256_parts(
		parts, lengths, 2U, split), 0);
	zassert_mem_equal(split, abc_digest, sizeof(split));

	edge_key(key1, 1U);
	edge_key(key2, 2U);
	zassert_equal(pqcp_edge_internal_hmac(NULL,
		(const uint8_t *)"m", 1U, tag1), -EINVAL);
	zassert_equal(pqcp_edge_internal_hmac(key1, NULL, 1U, tag1),
		      -EINVAL);
	zassert_equal(pqcp_edge_internal_hmac(key1,
		(const uint8_t *)"m", 1U, NULL), -EINVAL);
	zassert_equal(pqcp_edge_internal_hmac(key1,
		(const uint8_t *)"m", 1U, tag1), 0);
	zassert_equal(pqcp_edge_internal_hmac(key1,
		(const uint8_t *)"m", 1U, tag2), 0);
	zassert_mem_equal(tag1, tag2, sizeof(tag1));
	zassert_equal(pqcp_edge_internal_hmac(key2,
		(const uint8_t *)"m", 1U, tag2), 0);
	zassert_true(memcmp(tag1, tag2, sizeof(tag1)) != 0);

	zassert_equal(pqcp_edge_internal_hkdf(NULL, key1,
		(const uint8_t *)"i", 1U, derived1), -EINVAL);
	zassert_equal(pqcp_edge_internal_hkdf(key1, NULL,
		(const uint8_t *)"i", 1U, derived1), -EINVAL);
	zassert_equal(pqcp_edge_internal_hkdf(key1, key2, NULL, 2U,
		derived1), -EINVAL);
	zassert_equal(pqcp_edge_internal_hkdf(key1, key2,
		(const uint8_t *)"i", 1U, NULL), -EINVAL);
	zassert_equal(pqcp_edge_internal_hkdf(key1, key2,
		(const uint8_t *)"i", 1U, derived1), 0);
	zassert_equal(pqcp_edge_internal_hkdf(key1, key2,
		(const uint8_t *)"j", 1U, derived2), 0);
	zassert_true(memcmp(derived1, derived2, sizeof(derived1)) != 0);
}

ZTEST(edge_security, test_common_object_and_incident_digest)
{
	static struct pqcp_edge_vault_object object;
	static struct pqcp_edge_incident incident;
	uint8_t d1[32];
	uint8_t d2[32];

	memset(&object, 0, sizeof(object));
	SETSTR(object.object_id, "obj");
	SETSTR(object.namespace_id, "ns");
	SETSTR(object.owner_id, "owner");
	SETSTR(object.classification, "secret");
	object.schema_version = 1U;
	object.value_length = 3U;
	memcpy(object.value, "xyz", 3U);

	zassert_equal(pqcp_edge_internal_object_digest(NULL, d1), -EINVAL);
	zassert_equal(pqcp_edge_internal_object_digest(&object, NULL),
		      -EINVAL);
	zassert_equal(pqcp_edge_internal_object_digest(&object, d1), 0);
	zassert_equal(pqcp_edge_internal_object_digest(&object, d2), 0);
	zassert_mem_equal(d1, d2, sizeof(d1));
	object.version = 2U;
	zassert_equal(pqcp_edge_internal_object_digest(&object, d2), 0);
	zassert_true(memcmp(d1, d2, sizeof(d1)) != 0);
	object.value_length = sizeof(object.value) + 1U;
	zassert_equal(pqcp_edge_internal_object_digest(&object, d2),
		      -EINVAL);
	object.value_length = 3U;
	object.owner_id[0] = '\0';
	zassert_equal(pqcp_edge_internal_object_digest(&object, d2),
		      -EINVAL);

	memset(&incident, 0, sizeof(incident));
	SETSTR(incident.title, "title");
	SETSTR(incident.subject_id, "subject");
	SETSTR(incident.owner_id, "owner");
	incident.schema_version = 1U;
	incident.incident_id = 9U;
	incident.signal_count = 2U;
	incident.signal_ids[0] = 4U;
	incident.signal_ids[1] = 5U;
	zassert_equal(pqcp_edge_internal_incident_digest(NULL, d1),
		      -EINVAL);
	zassert_equal(pqcp_edge_internal_incident_digest(&incident, d1), 0);
	incident.signal_ids[1] = 6U;
	zassert_equal(pqcp_edge_internal_incident_digest(&incident, d2), 0);
	zassert_true(memcmp(d1, d2, sizeof(d1)) != 0);
	incident.signal_count = PQCP_EDGE_MAX_INCIDENT_SIGNALS + 1U;
	zassert_equal(pqcp_edge_internal_incident_digest(&incident, d2),
		      -EINVAL);
}
