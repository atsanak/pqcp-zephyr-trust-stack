/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tests for the evidence continuity foundation: validators, canonical
 * encoders, domain-separated digests and the two-phase record store.
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/evidence_continuity.h>

#include "evidence_continuity_internal.h"

#define DIG PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES
#define HDR PQCP_EVIDENCE_CONTINUITY_RECORD_HEADER_BYTES
#define COMMITTED PQCP_EVIDENCE_CONTINUITY_RECORD_COMMITTED

#define OK(expr) zassert_equal((expr), 0, "%s", #expr)
#define ERR(code, expr) zassert_equal((expr), (code), "%s", #expr)

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void fill_pattern(uint8_t *buf, size_t len, uint8_t seed)
{
	for (size_t i = 0U; i < len; ++i) {
		buf[i] = (uint8_t)(seed + i * 7U);
	}
}

static void set_text(char *dst, size_t cap, const char *src)
{
	memset(dst, 0, cap);
	memcpy(dst, src, strlen(src));
}

static bool dig_equal(const uint8_t *a, const uint8_t *b)
{
	return pqcp_evidence_continuity_digest_equal(a, b);
}

static bool all_bytes(const uint8_t *buf, size_t len, uint8_t value)
{
	for (size_t i = 0U; i < len; ++i) {
		if (buf[i] != value) {
			return false;
		}
	}
	return true;
}

/*
 * Flip one field of a copy of BASE and require the digest to differ from
 * REF. MUT may refer to the copy as `c`.
 */
#define CHANGES(FN, TYPE, BASE, REF, MUT)                                     \
	do {                                                                  \
		TYPE c = (BASE);                                              \
		uint8_t d[DIG];                                               \
		MUT;                                                          \
		zassert_equal(FN(&c, d), 0, "%s", #MUT);                      \
		zassert_false(dig_equal(d, (REF)), "digest ignores: %s",      \
			      #MUT);                                          \
	} while (0)

/* Same, but the digest must NOT depend on the mutated field. */
#define UNCHANGED(FN, TYPE, BASE, REF, MUT)                                   \
	do {                                                                  \
		TYPE c = (BASE);                                              \
		uint8_t d[DIG];                                               \
		MUT;                                                          \
		zassert_equal(FN(&c, d), 0, "%s", #MUT);                      \
		zassert_true(dig_equal(d, (REF)), "digest depends on: %s",    \
			     #MUT);                                           \
	} while (0)

/* ------------------------------------------------------------------ */
/* In-test RAM store                                                   */
/* ------------------------------------------------------------------ */

#define RAM_SLOTS 4U
#define RAM_SLOT_BYTES 512U
#define OBJ_COUNT PQCP_EVIDENCE_CONTINUITY_OBJECT_COUNT

struct ram_store {
	uint8_t data[OBJ_COUNT][RAM_SLOTS][RAM_SLOT_BYTES];
	size_t length[OBJ_COUNT][RAM_SLOTS];
	bool present[OBJ_COUNT][RAM_SLOTS];
	int reads;
	int writes;
	int erases;
	int syncs;
	int fail_erase;
	int fail_write_at; /* 1-based write call that fails, 0 = never */
	int fail_sync_at;  /* 1-based sync call that fails, 0 = never */
	bool bogus_length; /* read reports the stored size, not the bytes delivered */
};

static struct ram_store ram;

static int ram_read(void *ctx, enum pqcp_evidence_continuity_object object,
		    uint32_t slot, size_t offset, uint8_t *output,
		    size_t capacity, size_t *out_length)
{
	struct ram_store *s = ctx;
	size_t n;

	if (object >= OBJ_COUNT || slot >= RAM_SLOTS) {
		return -EINVAL;
	}
	s->reads++;
	if (!s->present[object][slot]) {
		return -ENOENT;
	}
	if (offset > s->length[object][slot]) {
		return -EINVAL;
	}
	n = s->length[object][slot] - offset;
	if (n > capacity) {
		n = capacity;
	}
	memcpy(output, &s->data[object][slot][offset], n);
	*out_length = s->bogus_length ? s->length[object][slot] - offset : n;
	return 0;
}

static int ram_write(void *ctx, enum pqcp_evidence_continuity_object object,
		     uint32_t slot, size_t offset, const uint8_t *input,
		     size_t length)
{
	struct ram_store *s = ctx;

	if (object >= OBJ_COUNT || slot >= RAM_SLOTS) {
		return -EINVAL;
	}
	s->writes++;
	if (s->fail_write_at != 0 && s->writes == s->fail_write_at) {
		return -EIO;
	}
	if (offset + length > RAM_SLOT_BYTES) {
		return -ENOSPC;
	}
	memcpy(&s->data[object][slot][offset], input, length);
	if (offset + length > s->length[object][slot]) {
		s->length[object][slot] = offset + length;
	}
	s->present[object][slot] = true;
	return 0;
}

static int ram_erase(void *ctx, enum pqcp_evidence_continuity_object object,
		     uint32_t slot)
{
	struct ram_store *s = ctx;

	if (object >= OBJ_COUNT || slot >= RAM_SLOTS) {
		return -EINVAL;
	}
	s->erases++;
	if (s->fail_erase != 0) {
		return -EIO;
	}
	memset(s->data[object][slot], 0xFF, RAM_SLOT_BYTES);
	s->length[object][slot] = 0U;
	s->present[object][slot] = false;
	return 0;
}

static int ram_sync(void *ctx)
{
	struct ram_store *s = ctx;

	s->syncs++;
	if (s->fail_sync_at != 0 && s->syncs == s->fail_sync_at) {
		return -EIO;
	}
	return 0;
}

static struct pqcp_evidence_continuity_store store;

static void before_each(void *fixture)
{
	ARG_UNUSED(fixture);
	memset(&ram, 0, sizeof(ram));
	memset(&store, 0, sizeof(store));
	store.read = ram_read;
	store.write = ram_write;
	store.erase = ram_erase;
	store.sync = ram_sync;
	store.context = &ram;
	store.maximum_record_bytes = 0U;
}

ZTEST_SUITE(evidence_continuity, NULL, NULL, before_each, NULL, NULL);

/* ------------------------------------------------------------------ */
/* Small primitives                                                    */
/* ------------------------------------------------------------------ */

ZTEST(evidence_continuity, test_text_valid)
{
	char buf[16];

	zassert_true(pqcp_evidence_continuity_text_valid("dev-1", 16U));
	zassert_true(pqcp_evidence_continuity_text_valid("a", 16U));
	/* every allowed punctuation class */
	zassert_true(pqcp_evidence_continuity_text_valid(
		"aZ09-_.:/@", 16U));
	/* exactly capacity - 1 characters is the longest accepted */
	zassert_true(pqcp_evidence_continuity_text_valid("abcdefg", 8U));
	zassert_false(pqcp_evidence_continuity_text_valid("abcdefgh", 8U));

	/* empty, NULL, degenerate capacity */
	zassert_false(pqcp_evidence_continuity_text_valid("", 16U));
	zassert_false(pqcp_evidence_continuity_text_valid(NULL, 16U));
	zassert_false(pqcp_evidence_continuity_text_valid("a", 0U));
	zassert_false(pqcp_evidence_continuity_text_valid("a", 1U));

	/* unterminated within capacity */
	memset(buf, 'x', sizeof(buf));
	zassert_false(pqcp_evidence_continuity_text_valid(buf, sizeof(buf)));
	buf[sizeof(buf) - 1U] = '\0';
	zassert_true(pqcp_evidence_continuity_text_valid(buf, sizeof(buf)));

	/* characters outside the allowed set */
	zassert_false(pqcp_evidence_continuity_text_valid("a b", 16U));
	zassert_false(pqcp_evidence_continuity_text_valid("a\n", 16U));
	zassert_false(pqcp_evidence_continuity_text_valid("a\\b", 16U));
	zassert_false(pqcp_evidence_continuity_text_valid("a;b", 16U));
	zassert_false(pqcp_evidence_continuity_text_valid("a\x7f", 16U));
	zassert_false(pqcp_evidence_continuity_text_valid("a\xc3\xa9", 16U));
	zassert_false(pqcp_evidence_continuity_text_valid("a=b", 16U));
}

ZTEST(evidence_continuity, test_digest_equal_and_zero)
{
	uint8_t a[DIG];
	uint8_t b[DIG];

	memset(a, 0, sizeof(a));
	memset(b, 0, sizeof(b));
	zassert_true(pqcp_evidence_continuity_digest_zero(a));
	zassert_true(pqcp_evidence_continuity_digest_equal(a, b));

	/* every byte position matters for both predicates */
	for (size_t i = 0U; i < DIG; ++i) {
		b[i] = 0x01U;
		zassert_false(pqcp_evidence_continuity_digest_zero(b));
		zassert_false(pqcp_evidence_continuity_digest_equal(a, b));
		zassert_false(pqcp_evidence_continuity_digest_equal(b, a));
		b[i] = 0x00U;
	}
	fill_pattern(a, sizeof(a), 3U);
	memcpy(b, a, sizeof(b));
	zassert_true(pqcp_evidence_continuity_digest_equal(a, b));
	zassert_false(pqcp_evidence_continuity_digest_zero(a));

	/* NULL: equal fails closed, zero reports "treat as zero" */
	zassert_false(pqcp_evidence_continuity_digest_equal(NULL, b));
	zassert_false(pqcp_evidence_continuity_digest_equal(a, NULL));
	zassert_false(pqcp_evidence_continuity_digest_equal(NULL, NULL));
	zassert_true(pqcp_evidence_continuity_digest_zero(NULL));
}

ZTEST(evidence_continuity, test_enum_validators)
{
	zassert_false(pqcp_evidence_continuity_event_type_valid(
		PQCP_EVIDENCE_CONTINUITY_EVENT_NONE));
	zassert_true(pqcp_evidence_continuity_event_type_valid(
		PQCP_EVIDENCE_CONTINUITY_EVENT_BOOT_OPENED));
	zassert_true(pqcp_evidence_continuity_event_type_valid(
		PQCP_EVIDENCE_CONTINUITY_EVENT_OPERATOR_NOTE));
	zassert_false(pqcp_evidence_continuity_event_type_valid(
		PQCP_EVIDENCE_CONTINUITY_EVENT_COUNT));
	zassert_false(pqcp_evidence_continuity_event_type_valid(
		(enum pqcp_evidence_continuity_event_type)-1));

	zassert_true(pqcp_evidence_continuity_severity_valid(
		PQCP_EVIDENCE_CONTINUITY_SEVERITY_DEBUG));
	zassert_true(pqcp_evidence_continuity_severity_valid(
		PQCP_EVIDENCE_CONTINUITY_SEVERITY_CRITICAL));
	zassert_false(pqcp_evidence_continuity_severity_valid(
		(enum pqcp_evidence_continuity_severity)
			(PQCP_EVIDENCE_CONTINUITY_SEVERITY_CRITICAL + 1)));
	zassert_false(pqcp_evidence_continuity_severity_valid(
		(enum pqcp_evidence_continuity_severity)-1));

	/* EMPTY is deliberately not a valid committed anchor state */
	zassert_false(pqcp_evidence_continuity_anchor_state_valid(
		PQCP_EVIDENCE_CONTINUITY_ANCHOR_EMPTY));
	zassert_true(pqcp_evidence_continuity_anchor_state_valid(
		PQCP_EVIDENCE_CONTINUITY_ANCHOR_BOOTSTRAP));
	zassert_true(pqcp_evidence_continuity_anchor_state_valid(
		PQCP_EVIDENCE_CONTINUITY_ANCHOR_QUARANTINED));
	zassert_false(pqcp_evidence_continuity_anchor_state_valid(
		(enum pqcp_evidence_continuity_anchor_state)
			(PQCP_EVIDENCE_CONTINUITY_ANCHOR_QUARANTINED + 1)));
}

ZTEST(evidence_continuity, test_next_generation)
{
	uint32_t gen;

	/* NULL is inert */
	zassert_equal(pqcp_evidence_continuity_next_generation(NULL), 0U);

	/* zero starts the sequence at 1 */
	gen = 0U;
	zassert_equal(pqcp_evidence_continuity_next_generation(&gen), 1U);
	zassert_equal(gen, 2U);
	zassert_equal(pqcp_evidence_continuity_next_generation(&gen), 2U);
	zassert_equal(gen, 3U);

	gen = 41U;
	zassert_equal(pqcp_evidence_continuity_next_generation(&gen), 41U);
	zassert_equal(gen, 42U);

	/* the last distinct value is handed out and then the counter wraps
	 * past zero, which is never a valid generation
	 */
	gen = UINT32_MAX - 1U;
	zassert_equal(pqcp_evidence_continuity_next_generation(&gen),
		      UINT32_MAX - 1U);
	zassert_equal(gen, UINT32_MAX);
	/* as implemented UINT32_MAX restarts the sequence at 1 */
	zassert_equal(pqcp_evidence_continuity_next_generation(&gen), 1U);
	zassert_equal(gen, 2U);

	/* a returned generation is never 0 */
	gen = UINT32_MAX;
	zassert_not_equal(pqcp_evidence_continuity_next_generation(&gen), 0U);
	zassert_not_equal(gen, 0U);
}

ZTEST(evidence_continuity, test_add_u64_saturates)
{
	zassert_equal(pqcp_evidence_continuity_add_u64(0U, 0U), 0U);
	zassert_equal(pqcp_evidence_continuity_add_u64(1U, 2U), 3U);
	zassert_equal(pqcp_evidence_continuity_add_u64(UINT64_MAX, 0U),
		      UINT64_MAX);
	zassert_equal(pqcp_evidence_continuity_add_u64(0U, UINT64_MAX),
		      UINT64_MAX);
	/* exactly reaching the maximum is not saturation */
	zassert_equal(pqcp_evidence_continuity_add_u64(UINT64_MAX - 5U, 5U),
		      UINT64_MAX);
	/* one past it saturates instead of wrapping */
	zassert_equal(pqcp_evidence_continuity_add_u64(UINT64_MAX - 5U, 6U),
		      UINT64_MAX);
	zassert_equal(pqcp_evidence_continuity_add_u64(UINT64_MAX, 1U),
		      UINT64_MAX);
	zassert_equal(pqcp_evidence_continuity_add_u64(UINT64_MAX,
						       UINT64_MAX),
		      UINT64_MAX);
	zassert_equal(pqcp_evidence_continuity_add_u64(1ULL << 63,
						       1ULL << 63),
		      UINT64_MAX);
}

ZTEST(evidence_continuity, test_endian_round_trip)
{
	static const uint8_t u32_bytes[4] = {0x01, 0x02, 0x03, 0x04};
	static const uint8_t u64_bytes[8] = {0x01, 0x02, 0x03, 0x04,
					     0x05, 0x06, 0x07, 0x08};
	uint8_t out4[4];
	uint8_t out8[8];
	static const uint32_t u32_values[] = {
		0U, 1U, 0x80U, 0x0100U, 0x01020304U, 0x80000000U,
		UINT32_MAX};
	static const uint64_t u64_values[] = {
		0ULL, 1ULL, 0x0102030405060708ULL, 0x8000000000000000ULL,
		0x00000000FFFFFFFFULL, 0xFFFFFFFF00000000ULL, UINT64_MAX};

	pqcp_evidence_continuity_write_u32(out4, 0x01020304U);
	zassert_mem_equal(out4, u32_bytes, sizeof(out4));
	zassert_equal(pqcp_evidence_continuity_read_u32(u32_bytes),
		      0x01020304U);

	pqcp_evidence_continuity_write_u64(out8, 0x0102030405060708ULL);
	zassert_mem_equal(out8, u64_bytes, sizeof(out8));
	zassert_equal(pqcp_evidence_continuity_read_u64(u64_bytes),
		      0x0102030405060708ULL);

	for (size_t i = 0U; i < ARRAY_SIZE(u32_values); ++i) {
		pqcp_evidence_continuity_write_u32(out4, u32_values[i]);
		zassert_equal(pqcp_evidence_continuity_read_u32(out4),
			      u32_values[i]);
	}
	for (size_t i = 0U; i < ARRAY_SIZE(u64_values); ++i) {
		pqcp_evidence_continuity_write_u64(out8, u64_values[i]);
		zassert_equal(pqcp_evidence_continuity_read_u64(out8),
			      u64_values[i]);
	}

	/* high-bit and low-bit extremes land in the right byte */
	pqcp_evidence_continuity_write_u64(out8, 0x8000000000000001ULL);
	zassert_equal(out8[0], 0x80U);
	zassert_equal(out8[7], 0x01U);
	pqcp_evidence_continuity_write_u32(out4, 0x80000001U);
	zassert_equal(out4[0], 0x80U);
	zassert_equal(out4[3], 0x01U);
}

ZTEST(evidence_continuity, test_copy_text)
{
	char dst[16];

	memset(dst, 0x55, sizeof(dst));
	OK(pqcp_evidence_continuity_copy_text(dst, sizeof(dst), "dev-1"));
	zassert_mem_equal(dst, "dev-1", 6);
	/* the tail is zero filled, not left as stale bytes */
	zassert_true(all_bytes((const uint8_t *)dst + 5U, sizeof(dst) - 5U,
			       0U));

	/* longest accepted source is capacity - 1 characters */
	OK(pqcp_evidence_continuity_copy_text(dst, 8U, "abcdefg"));
	zassert_equal(dst[7], '\0');
	zassert_equal(strlen(dst), 7U);

	/* a source that does not fit is rejected, never truncated */
	memset(dst, 0x55, sizeof(dst));
	ERR(-EINVAL, pqcp_evidence_continuity_copy_text(dst, 8U, "abcdefgh"));
	zassert_true(all_bytes((const uint8_t *)dst, sizeof(dst), 0x55U),
		     "destination touched on failure");

	/* invalid text, NULL arguments, degenerate capacity */
	ERR(-EINVAL, pqcp_evidence_continuity_copy_text(dst, 16U, ""));
	ERR(-EINVAL, pqcp_evidence_continuity_copy_text(dst, 16U, "a b"));
	ERR(-EINVAL, pqcp_evidence_continuity_copy_text(dst, 16U, NULL));
	ERR(-EINVAL, pqcp_evidence_continuity_copy_text(NULL, 16U, "a"));
	ERR(-EINVAL, pqcp_evidence_continuity_copy_text(dst, 1U, "a"));
	ERR(-EINVAL, pqcp_evidence_continuity_copy_text(dst, 0U, "a"));
	zassert_true(all_bytes((const uint8_t *)dst, sizeof(dst), 0x55U));
}

/* ------------------------------------------------------------------ */
/* Hashing                                                             */
/* ------------------------------------------------------------------ */

ZTEST(evidence_continuity, test_hash_known_answer_and_framing)
{
	static const uint8_t abc_sha256[DIG] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
	uint8_t out[DIG];
	uint8_t state[DIG];
	uint8_t frame[DIG + 8U + 1U];
	uint8_t expected[DIG];
	const uint8_t part_a[] = {'a'};
	const uint8_t *parts[1] = {part_a};
	size_t lengths[1] = {1U};

	OK(pqcp_evidence_continuity_hash((const uint8_t *)"abc", 3U, out));
	zassert_mem_equal(out, abc_sha256, DIG);

	/* hash_parts is SHA(domain) chained with length-framed parts */
	OK(pqcp_evidence_continuity_hash((const uint8_t *)"dom", 3U, state));
	memcpy(frame, state, DIG);
	pqcp_evidence_continuity_write_u64(frame + DIG, 1U);
	frame[DIG + 8U] = 'a';
	OK(pqcp_evidence_continuity_hash(frame, sizeof(frame), expected));
	OK(pqcp_evidence_continuity_hash_parts("dom", parts, lengths, 1U,
					       out));
	zassert_mem_equal(out, expected, DIG);

	/* zero parts is just SHA(domain) */
	OK(pqcp_evidence_continuity_hash_parts("dom", NULL, NULL, 0U, out));
	zassert_mem_equal(out, state, DIG);
}

ZTEST(evidence_continuity, test_hash_parts_determinism_and_separation)
{
	uint8_t d1[DIG];
	uint8_t d2[DIG];
	uint8_t d3[DIG];
	const uint8_t a[] = {'a'};
	const uint8_t b[] = {'b'};
	const uint8_t c[] = {'c'};
	const uint8_t ab[] = {'a', 'b'};
	const uint8_t *p_ab_c[2] = {ab, c};
	const size_t l_ab_c[2] = {2U, 1U};
	const uint8_t *p_a_bc[2] = {a, (const uint8_t *)"bc"};
	const size_t l_a_bc[2] = {1U, 2U};
	const uint8_t *p_ab[1] = {ab};
	const size_t l_ab[1] = {2U};
	const uint8_t *p_a_b[2] = {a, b};
	const size_t l_a_b[2] = {1U, 1U};
	const uint8_t *p_b_a[2] = {b, a};

	/* deterministic */
	OK(pqcp_evidence_continuity_hash_parts("D", p_a_b, l_a_b, 2U, d1));
	OK(pqcp_evidence_continuity_hash_parts("D", p_a_b, l_a_b, 2U, d2));
	zassert_true(dig_equal(d1, d2));

	/* the domain separates */
	OK(pqcp_evidence_continuity_hash_parts("E", p_a_b, l_a_b, 2U, d2));
	zassert_false(dig_equal(d1, d2));

	/* order matters */
	OK(pqcp_evidence_continuity_hash_parts("D", p_b_a, l_a_b, 2U, d2));
	zassert_false(dig_equal(d1, d2));

	/* {"ab","c"} and {"a","bc"} concatenate equally but must differ */
	OK(pqcp_evidence_continuity_hash_parts("D", p_ab_c, l_ab_c, 2U, d1));
	OK(pqcp_evidence_continuity_hash_parts("D", p_a_bc, l_a_bc, 2U, d2));
	zassert_false(dig_equal(d1, d2));

	/* one part "ab" differs from two parts "a","b" */
	OK(pqcp_evidence_continuity_hash_parts("D", p_ab, l_ab, 1U, d1));
	OK(pqcp_evidence_continuity_hash_parts("D", p_a_b, l_a_b, 2U, d2));
	zassert_false(dig_equal(d1, d2));

	/* an extra empty part is observable */
	OK(pqcp_evidence_continuity_hash_parts("D", NULL, NULL, 0U, d1));
	{
		const uint8_t *p_empty[1] = {NULL};
		const size_t l_empty[1] = {0U};

		OK(pqcp_evidence_continuity_hash_parts(
			"D", p_empty, l_empty, 1U, d2));
	}
	zassert_false(dig_equal(d1, d2));

	/* a part of exactly the maximum size (512) is accepted */
	{
		static uint8_t big[512];
		const uint8_t *p_big[1] = {big};
		const size_t l_big[1] = {sizeof(big)};

		fill_pattern(big, sizeof(big), 9U);
		OK(pqcp_evidence_continuity_hash_parts(
			"D", p_big, l_big, 1U, d3));
		zassert_false(dig_equal(d3, d1));
	}

	/* NULL / malformed arguments */
	memset(d3, 0xAA, sizeof(d3));
	ERR(-EINVAL, pqcp_evidence_continuity_hash_parts(
			     NULL, p_a_b, l_a_b, 2U, d3));
	ERR(-EINVAL, pqcp_evidence_continuity_hash_parts(
			     "D", p_a_b, l_a_b, 2U, NULL));
	ERR(-EINVAL, pqcp_evidence_continuity_hash_parts(
			     "D", NULL, l_a_b, 2U, d3));
	ERR(-EINVAL, pqcp_evidence_continuity_hash_parts(
			     "D", p_a_b, NULL, 2U, d3));
	zassert_true(all_bytes(d3, sizeof(d3), 0xAAU));
}

/*
 * REGRESSION: digest_builder_finish used to wipe the builder and then return
 * builder->error, so every hashing failure was reported as success while the
 * output stayed unwritten (fail-open). Errors must be returned and the
 * output must stay untouched.
 */
ZTEST(evidence_continuity, test_hash_error_is_returned_not_swallowed)
{
	static uint8_t oversize[513];
	static char long_domain[514];
	uint8_t out[DIG];
	const uint8_t *parts[1] = {oversize};
	const size_t lengths[1] = {sizeof(oversize)};
	const uint8_t *null_part[1] = {NULL};
	const size_t null_len[1] = {4U};
	const uint8_t one[] = {1};
	const uint8_t *good[2] = {one, oversize};
	const size_t good_len[2] = {1U, sizeof(oversize)};

	memset(oversize, 0x11, sizeof(oversize));

	/* part longer than the builder limit */
	memset(out, 0xAA, sizeof(out));
	ERR(-E2BIG, pqcp_evidence_continuity_hash_parts(
			    "D", parts, lengths, 1U, out));
	zassert_true(all_bytes(out, sizeof(out), 0xAAU),
		     "output written on failure");

	/* the failure is sticky: a valid part first does not clear it */
	memset(out, 0xAA, sizeof(out));
	ERR(-E2BIG, pqcp_evidence_continuity_hash_parts(
			    "D", good, good_len, 2U, out));
	zassert_true(all_bytes(out, sizeof(out), 0xAAU));

	/* NULL part with a non-zero length */
	memset(out, 0xAA, sizeof(out));
	ERR(-E2BIG, pqcp_evidence_continuity_hash_parts(
			    "D", null_part, null_len, 1U, out));
	zassert_true(all_bytes(out, sizeof(out), 0xAAU));

	/* empty domain and over-long domain fail in builder init */
	memset(out, 0xAA, sizeof(out));
	ERR(-EINVAL, pqcp_evidence_continuity_hash_parts(
			     "", NULL, NULL, 0U, out));
	zassert_true(all_bytes(out, sizeof(out), 0xAAU));
	memset(long_domain, 'd', sizeof(long_domain) - 1U);
	long_domain[sizeof(long_domain) - 1U] = '\0';
	ERR(-EINVAL, pqcp_evidence_continuity_hash_parts(
			     long_domain, NULL, NULL, 0U, out));
	zassert_true(all_bytes(out, sizeof(out), 0xAAU));

	/* the same fail-open path through a typed digest: an unterminated
	 * identifier is a builder error and must not look like success
	 */
	{
		struct pqcp_evidence_continuity_anchor anchor;

		memset(&anchor, 0, sizeof(anchor));
		memset(anchor.device_id, 'a', sizeof(anchor.device_id));
		memset(out, 0xAA, sizeof(out));
		ERR(-EINVAL, pqcp_evidence_continuity_anchor_digest(
				     &anchor, out));
		zassert_true(all_bytes(out, sizeof(out), 0xAAU),
			     "anchor digest written on failure");
	}
}

/* ------------------------------------------------------------------ */
/* Typed digests                                                       */
/* ------------------------------------------------------------------ */

static struct pqcp_evidence_continuity_anchor anchor_base;
static struct pqcp_evidence_continuity_boot_session session_base;
static struct pqcp_evidence_continuity_event event_base;
static struct pqcp_evidence_continuity_checkpoint checkpoint_base;
static struct pqcp_evidence_continuity_witness_receipt receipt_base;

static void make_anchor(struct pqcp_evidence_continuity_anchor *a)
{
	memset(a, 0, sizeof(*a));
	a->schema_version = PQCP_EVIDENCE_CONTINUITY_SCHEMA_VERSION;
	a->generation = 3U;
	a->state = PQCP_EVIDENCE_CONTINUITY_ANCHOR_OPEN;
	a->flags = 0x5U;
	set_text(a->device_id, sizeof(a->device_id), "dev-1");
	set_text(a->domain_id, sizeof(a->domain_id), "dom:1");
	a->monotonic_counter = 11U;
	a->boot_epoch = 12U;
	a->session_id = 13U;
	a->first_event_sequence = 14U;
	a->last_event_sequence = 15U;
	a->latest_checkpoint_sequence = 16U;
	a->created_at_ms = 17U;
	a->updated_at_ms = 18U;
	a->closed_at_ms = 19U;
	a->policy_epoch = 20U;
	a->firmware_epoch = 21U;
	a->witness_epoch = 22U;
	a->replication_epoch = 23U;
	a->compaction_epoch = 24U;
	a->recovery_epoch = 25U;
	fill_pattern(a->device_digest, DIG, 1U);
	fill_pattern(a->firmware_digest, DIG, 2U);
	fill_pattern(a->policy_digest, DIG, 3U);
	fill_pattern(a->previous_anchor_digest, DIG, 4U);
	fill_pattern(a->journal_root, DIG, 5U);
	fill_pattern(a->checkpoint_root, DIG, 6U);
	fill_pattern(a->witness_root, DIG, 7U);
	fill_pattern(a->replication_root, DIG, 8U);
	fill_pattern(a->compaction_root, DIG, 9U);
	fill_pattern(a->recovery_root, DIG, 10U);
	a->occupied = true;
}

ZTEST(evidence_continuity, test_anchor_digest)
{
	uint8_t ref[DIG];
	uint8_t again[DIG];
	uint8_t out[DIG];
	struct pqcp_evidence_continuity_anchor oversized_id;

	make_anchor(&anchor_base);
	OK(pqcp_evidence_continuity_anchor_digest(&anchor_base, ref));
	OK(pqcp_evidence_continuity_anchor_digest(&anchor_base, again));
	zassert_true(dig_equal(ref, again));
	zassert_false(pqcp_evidence_continuity_digest_zero(ref));

#define A_CHANGES(MUT) \
	CHANGES(pqcp_evidence_continuity_anchor_digest, \
		struct pqcp_evidence_continuity_anchor, anchor_base, ref, MUT)
	A_CHANGES(c.schema_version ^= 1U);
	A_CHANGES(c.generation ^= 1U);
	A_CHANGES(c.state = PQCP_EVIDENCE_CONTINUITY_ANCHOR_CHECKPOINTED);
	A_CHANGES(c.flags ^= 0x80U);
	A_CHANGES(c.device_id[0] = 'x');
	A_CHANGES(c.domain_id[4] = 'x');
	A_CHANGES(c.monotonic_counter ^= 1U);
	A_CHANGES(c.boot_epoch ^= 1U);
	A_CHANGES(c.session_id ^= 1U);
	A_CHANGES(c.first_event_sequence ^= 1U);
	A_CHANGES(c.last_event_sequence ^= 1U);
	A_CHANGES(c.latest_checkpoint_sequence ^= 1U);
	A_CHANGES(c.created_at_ms ^= 1U);
	A_CHANGES(c.updated_at_ms ^= 1U);
	A_CHANGES(c.closed_at_ms ^= 1U);
	A_CHANGES(c.policy_epoch ^= 1U);
	A_CHANGES(c.firmware_epoch ^= 1U);
	A_CHANGES(c.witness_epoch ^= 1U);
	A_CHANGES(c.replication_epoch ^= 1U);
	A_CHANGES(c.compaction_epoch ^= 1U);
	A_CHANGES(c.recovery_epoch ^= 1U);
	A_CHANGES(c.device_digest[0] ^= 1U);
	A_CHANGES(c.firmware_digest[DIG - 1U] ^= 1U);
	A_CHANGES(c.policy_digest[7] ^= 1U);
	A_CHANGES(c.previous_anchor_digest[0] ^= 1U);
	A_CHANGES(c.journal_root[0] ^= 1U);
	A_CHANGES(c.checkpoint_root[0] ^= 1U);
	A_CHANGES(c.witness_root[0] ^= 1U);
	A_CHANGES(c.replication_root[0] ^= 1U);
	A_CHANGES(c.compaction_root[0] ^= 1U);
	A_CHANGES(c.recovery_root[DIG - 1U] ^= 1U);
	A_CHANGES(c.occupied = false);
#undef A_CHANGES

	/* the digest field itself is the output and is not an input */
	UNCHANGED(pqcp_evidence_continuity_anchor_digest,
		  struct pqcp_evidence_continuity_anchor, anchor_base, ref,
		  c.anchor_digest[0] ^= 1U);
	/* bytes after the identifier terminator are not an input either */
	UNCHANGED(pqcp_evidence_continuity_anchor_digest,
		  struct pqcp_evidence_continuity_anchor, anchor_base, ref,
		  c.device_id[10] = 'z');

	/* argument and identifier validation */
	memset(out, 0xAA, sizeof(out));
	ERR(-EINVAL, pqcp_evidence_continuity_anchor_digest(NULL, out));
	ERR(-EINVAL, pqcp_evidence_continuity_anchor_digest(
			     &anchor_base, NULL));
	oversized_id = anchor_base;
	memset(oversized_id.domain_id, 'q', sizeof(oversized_id.domain_id));
	ERR(-EINVAL, pqcp_evidence_continuity_anchor_digest(
			     &oversized_id, out));
	zassert_true(all_bytes(out, sizeof(out), 0xAAU));
}

ZTEST(evidence_continuity, test_session_digest)
{
	uint8_t ref[DIG];
	uint8_t again[DIG];
	uint8_t other_kind[DIG];
	struct pqcp_evidence_continuity_boot_session *s = &session_base;

	memset(s, 0, sizeof(*s));
	s->schema_version = PQCP_EVIDENCE_CONTINUITY_SCHEMA_VERSION;
	s->generation = 2U;
	s->state = PQCP_EVIDENCE_CONTINUITY_SESSION_OPEN;
	s->flags = 1U;
	set_text(s->device_id, sizeof(s->device_id), "dev-1");
	set_text(s->domain_id, sizeof(s->domain_id), "dom-1");
	s->boot_epoch = 5U;
	s->session_id = 6U;
	s->opened_at_ms = 7U;
	s->closed_at_ms = 8U;
	s->first_event_sequence = 9U;
	s->last_event_sequence = 10U;
	s->event_count = 11U;
	s->rejected_event_count = 12U;
	s->policy_epoch = 13U;
	s->firmware_epoch = 14U;
	fill_pattern(s->boot_nonce_digest, DIG, 21U);
	fill_pattern(s->device_digest, DIG, 22U);
	fill_pattern(s->firmware_digest, DIG, 23U);
	fill_pattern(s->policy_digest, DIG, 24U);
	fill_pattern(s->inherited_anchor_digest, DIG, 25U);
	fill_pattern(s->journal_root, DIG, 26U);
	fill_pattern(s->terminal_evidence_digest, DIG, 27U);
	s->require_witness = true;
	s->occupied = true;

	OK(pqcp_evidence_continuity_session_digest(s, ref));
	OK(pqcp_evidence_continuity_session_digest(s, again));
	zassert_true(dig_equal(ref, again));

#define S_CHANGES(MUT) \
	CHANGES(pqcp_evidence_continuity_session_digest, \
		struct pqcp_evidence_continuity_boot_session, session_base, \
		ref, MUT)
	S_CHANGES(c.schema_version ^= 1U);
	S_CHANGES(c.generation ^= 1U);
	S_CHANGES(c.state = PQCP_EVIDENCE_CONTINUITY_SESSION_CLOSED);
	S_CHANGES(c.flags ^= 2U);
	S_CHANGES(c.device_id[0] = 'z');
	S_CHANGES(c.domain_id[0] = 'z');
	S_CHANGES(c.boot_epoch ^= 1U);
	S_CHANGES(c.session_id ^= 1U);
	S_CHANGES(c.opened_at_ms ^= 1U);
	S_CHANGES(c.closed_at_ms ^= 1U);
	S_CHANGES(c.first_event_sequence ^= 1U);
	S_CHANGES(c.last_event_sequence ^= 1U);
	S_CHANGES(c.event_count ^= 1U);
	S_CHANGES(c.rejected_event_count ^= 1U);
	S_CHANGES(c.policy_epoch ^= 1U);
	S_CHANGES(c.firmware_epoch ^= 1U);
	S_CHANGES(c.boot_nonce_digest[0] ^= 1U);
	S_CHANGES(c.device_digest[0] ^= 1U);
	S_CHANGES(c.firmware_digest[0] ^= 1U);
	S_CHANGES(c.policy_digest[0] ^= 1U);
	S_CHANGES(c.inherited_anchor_digest[0] ^= 1U);
	S_CHANGES(c.journal_root[0] ^= 1U);
	S_CHANGES(c.terminal_evidence_digest[DIG - 1U] ^= 1U);
	S_CHANGES(c.require_witness = false);
	S_CHANGES(c.require_replication = true);
	S_CHANGES(c.occupied = false);
#undef S_CHANGES
	UNCHANGED(pqcp_evidence_continuity_session_digest,
		  struct pqcp_evidence_continuity_boot_session, session_base,
		  ref, c.session_digest[0] ^= 1U);

	/* object kinds are domain separated: an all-zero session and an
	 * all-zero anchor never share a digest
	 */
	{
		struct pqcp_evidence_continuity_boot_session zs;
		struct pqcp_evidence_continuity_anchor za;
		uint8_t sd[DIG];

		memset(&zs, 0, sizeof(zs));
		memset(&za, 0, sizeof(za));
		OK(pqcp_evidence_continuity_session_digest(&zs, sd));
		OK(pqcp_evidence_continuity_anchor_digest(&za, other_kind));
		zassert_false(dig_equal(sd, other_kind));
	}

	ERR(-EINVAL, pqcp_evidence_continuity_session_digest(NULL, ref));
	ERR(-EINVAL, pqcp_evidence_continuity_session_digest(s, NULL));
}

ZTEST(evidence_continuity, test_event_digest)
{
	uint8_t ref[DIG];
	uint8_t again[DIG];
	struct pqcp_evidence_continuity_event *e = &event_base;

	memset(e, 0, sizeof(*e));
	e->schema_version = PQCP_EVIDENCE_CONTINUITY_SCHEMA_VERSION;
	e->generation = 4U;
	e->boot_epoch = 5U;
	e->session_id = 6U;
	e->sequence = 7U;
	e->timestamp_ms = 8U;
	e->correlation_id = 9U;
	e->policy_epoch = 10U;
	e->firmware_epoch = 11U;
	e->type = PQCP_EVIDENCE_CONTINUITY_EVENT_POLICY_CHANGED;
	e->severity = PQCP_EVIDENCE_CONTINUITY_SEVERITY_WARNING;
	e->flags = 0x10U;
	e->result = -5;
	e->reason = 77U;
	set_text(e->component, sizeof(e->component), "policy/engine");
	set_text(e->subject, sizeof(e->subject), "subject-1");
	memcpy(e->detail, "hello", 5U);
	e->detail_length = 5U;
	fill_pattern(e->payload_digest, DIG, 31U);
	fill_pattern(e->previous_digest, DIG, 32U);
	e->occupied = true;

	OK(pqcp_evidence_continuity_event_digest(e, ref));
	OK(pqcp_evidence_continuity_event_digest(e, again));
	zassert_true(dig_equal(ref, again));

#define E_CHANGES(MUT) \
	CHANGES(pqcp_evidence_continuity_event_digest, \
		struct pqcp_evidence_continuity_event, event_base, ref, MUT)
	E_CHANGES(c.schema_version ^= 1U);
	E_CHANGES(c.generation ^= 1U);
	E_CHANGES(c.boot_epoch ^= 1U);
	E_CHANGES(c.session_id ^= 1U);
	E_CHANGES(c.sequence ^= 1U);
	E_CHANGES(c.timestamp_ms ^= 1U);
	E_CHANGES(c.correlation_id ^= 1U);
	E_CHANGES(c.policy_epoch ^= 1U);
	E_CHANGES(c.firmware_epoch ^= 1U);
	E_CHANGES(c.type = PQCP_EVIDENCE_CONTINUITY_EVENT_KEY_ROTATED);
	E_CHANGES(c.severity = PQCP_EVIDENCE_CONTINUITY_SEVERITY_ERROR);
	E_CHANGES(c.flags ^= 1U);
	E_CHANGES(c.result = 5);
	E_CHANGES(c.result = 0);
	E_CHANGES(c.reason ^= 1U);
	E_CHANGES(c.component[0] = 'P');
	E_CHANGES(c.subject[8] = '2');
	E_CHANGES(c.detail[0] ^= 1U);
	E_CHANGES(c.detail_length = 4U);
	E_CHANGES(c.detail_length = 0U);
	E_CHANGES(c.payload_digest[0] ^= 1U);
	E_CHANGES(c.previous_digest[0] ^= 1U);
	E_CHANGES(c.occupied = false);
#undef E_CHANGES

	/* only detail_length bytes of detail are covered */
	UNCHANGED(pqcp_evidence_continuity_event_digest,
		  struct pqcp_evidence_continuity_event, event_base, ref,
		  c.detail[5] ^= 0xFFU);
	UNCHANGED(pqcp_evidence_continuity_event_digest,
		  struct pqcp_evidence_continuity_event, event_base, ref,
		  c.detail[PQCP_EVIDENCE_CONTINUITY_DETAIL_MAX_BYTES - 1U] ^=
		  0xFFU);
	/* the event's own digest field is the output, not an input */
	UNCHANGED(pqcp_evidence_continuity_event_digest,
		  struct pqcp_evidence_continuity_event, event_base, ref,
		  c.event_digest[0] ^= 1U);

	/* full-size detail is accepted */
	{
		struct pqcp_evidence_continuity_event full = *e;
		uint8_t d[DIG];

		fill_pattern(full.detail, sizeof(full.detail), 1U);
		full.detail_length =
			PQCP_EVIDENCE_CONTINUITY_DETAIL_MAX_BYTES;
		OK(pqcp_evidence_continuity_event_digest(&full, d));
		zassert_false(dig_equal(d, ref));
	}

	ERR(-EINVAL, pqcp_evidence_continuity_event_digest(NULL, ref));
	ERR(-EINVAL, pqcp_evidence_continuity_event_digest(e, NULL));
}

/*
 * REGRESSION: detail_length is attacker-influenced record content. A value
 * above sizeof(detail) used to make the digest read past the detail array
 * into the neighbouring fields (and beyond the struct for large values).
 * It is now rejected and the output stays unwritten.
 */
ZTEST(evidence_continuity, test_event_digest_rejects_oversized_detail)
{
	struct pqcp_evidence_continuity_event e;
	uint8_t out[DIG];

	memset(&e, 0, sizeof(e));
	e.schema_version = PQCP_EVIDENCE_CONTINUITY_SCHEMA_VERSION;
	e.type = PQCP_EVIDENCE_CONTINUITY_EVENT_OPERATOR_NOTE;
	set_text(e.component, sizeof(e.component), "c");
	set_text(e.subject, sizeof(e.subject), "s");

	e.detail_length = PQCP_EVIDENCE_CONTINUITY_DETAIL_MAX_BYTES;
	OK(pqcp_evidence_continuity_event_digest(&e, out));

	e.detail_length = PQCP_EVIDENCE_CONTINUITY_DETAIL_MAX_BYTES + 1U;
	memset(out, 0xAA, sizeof(out));
	ERR(-EINVAL, pqcp_evidence_continuity_event_digest(&e, out));
	zassert_true(all_bytes(out, sizeof(out), 0xAAU));

	e.detail_length = 513U;
	ERR(-EINVAL, pqcp_evidence_continuity_event_digest(&e, out));
	e.detail_length = UINT32_MAX;
	ERR(-EINVAL, pqcp_evidence_continuity_event_digest(&e, out));
	zassert_true(all_bytes(out, sizeof(out), 0xAAU));
}

ZTEST(evidence_continuity, test_checkpoint_digest)
{
	uint8_t ref[DIG];
	uint8_t again[DIG];
	struct pqcp_evidence_continuity_checkpoint *k = &checkpoint_base;

	memset(k, 0, sizeof(*k));
	k->schema_version = PQCP_EVIDENCE_CONTINUITY_SCHEMA_VERSION;
	k->generation = 2U;
	k->state = PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_SEALED;
	k->flags = 3U;
	set_text(k->device_id, sizeof(k->device_id), "dev-1");
	set_text(k->domain_id, sizeof(k->domain_id), "dom-1");
	k->checkpoint_sequence = 4U;
	k->boot_epoch = 5U;
	k->session_id = 6U;
	k->first_event_sequence = 7U;
	k->last_event_sequence = 8U;
	k->event_count = 9U;
	k->created_at_ms = 10U;
	k->sealed_at_ms = 11U;
	k->policy_epoch = 12U;
	k->firmware_epoch = 13U;
	k->monotonic_counter = 14U;
	k->security_event_count = 15U;
	k->recovery_event_count = 16U;
	k->witness_receipt_count = 17U;
	k->replica_ack_count = 18U;
	fill_pattern(k->previous_checkpoint_digest, DIG, 41U);
	fill_pattern(k->anchor_digest, DIG, 42U);
	fill_pattern(k->event_root, DIG, 43U);
	fill_pattern(k->witness_root, DIG, 44U);
	fill_pattern(k->replica_root, DIG, 45U);
	k->occupied = true;

	OK(pqcp_evidence_continuity_checkpoint_digest(k, ref));
	OK(pqcp_evidence_continuity_checkpoint_digest(k, again));
	zassert_true(dig_equal(ref, again));

#define K_CHANGES(MUT) \
	CHANGES(pqcp_evidence_continuity_checkpoint_digest, \
		struct pqcp_evidence_continuity_checkpoint, checkpoint_base, \
		ref, MUT)
	K_CHANGES(c.schema_version ^= 1U);
	K_CHANGES(c.generation ^= 1U);
	K_CHANGES(c.state = PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_WITNESSED);
	K_CHANGES(c.flags ^= 1U);
	K_CHANGES(c.device_id[0] = 'z');
	K_CHANGES(c.domain_id[0] = 'z');
	K_CHANGES(c.checkpoint_sequence ^= 1U);
	K_CHANGES(c.boot_epoch ^= 1U);
	K_CHANGES(c.session_id ^= 1U);
	K_CHANGES(c.first_event_sequence ^= 1U);
	K_CHANGES(c.last_event_sequence ^= 1U);
	K_CHANGES(c.event_count ^= 1U);
	K_CHANGES(c.created_at_ms ^= 1U);
	K_CHANGES(c.sealed_at_ms ^= 1U);
	K_CHANGES(c.policy_epoch ^= 1U);
	K_CHANGES(c.firmware_epoch ^= 1U);
	K_CHANGES(c.monotonic_counter ^= 1U);
	K_CHANGES(c.security_event_count ^= 1U);
	K_CHANGES(c.recovery_event_count ^= 1U);
	K_CHANGES(c.witness_receipt_count ^= 1U);
	K_CHANGES(c.replica_ack_count ^= 1U);
	K_CHANGES(c.previous_checkpoint_digest[0] ^= 1U);
	K_CHANGES(c.anchor_digest[0] ^= 1U);
	K_CHANGES(c.event_root[0] ^= 1U);
	K_CHANGES(c.witness_root[0] ^= 1U);
	K_CHANGES(c.replica_root[DIG - 1U] ^= 1U);
	K_CHANGES(c.occupied = false);
#undef K_CHANGES
	UNCHANGED(pqcp_evidence_continuity_checkpoint_digest,
		  struct pqcp_evidence_continuity_checkpoint,
		  checkpoint_base, ref, c.checkpoint_digest[3] ^= 1U);

	ERR(-EINVAL, pqcp_evidence_continuity_checkpoint_digest(NULL, ref));
	ERR(-EINVAL, pqcp_evidence_continuity_checkpoint_digest(k, NULL));
}

ZTEST(evidence_continuity, test_receipt_digest)
{
	uint8_t ref[DIG];
	uint8_t again[DIG];
	uint8_t out[DIG];
	struct pqcp_evidence_continuity_witness_receipt *r = &receipt_base;

	memset(r, 0, sizeof(*r));
	r->schema_version = PQCP_EVIDENCE_CONTINUITY_SCHEMA_VERSION;
	r->generation = 2U;
	r->status = PQCP_EVIDENCE_CONTINUITY_RECEIPT_ACCEPTED;
	set_text(r->witness_id, sizeof(r->witness_id), "witness-1");
	set_text(r->jurisdiction, sizeof(r->jurisdiction), "eu");
	set_text(r->failure_domain, sizeof(r->failure_domain), "fd-a");
	r->receipt_sequence = 3U;
	r->checkpoint_sequence = 4U;
	r->monotonic_counter = 5U;
	r->observed_at_ms = 6U;
	r->expires_at_ms = 7U;
	r->policy_epoch = 8U;
	r->witness_epoch = 9U;
	r->weight = 10U;
	r->signature_length = 64U;
	fill_pattern(r->challenge_digest, DIG, 51U);
	fill_pattern(r->checkpoint_digest, DIG, 52U);
	fill_pattern(r->previous_receipt_digest, DIG, 53U);
	fill_pattern(r->signature, sizeof(r->signature), 54U);
	r->verified = true;
	r->occupied = true;

	OK(pqcp_evidence_continuity_receipt_digest(r, ref));
	OK(pqcp_evidence_continuity_receipt_digest(r, again));
	zassert_true(dig_equal(ref, again));

#define R_CHANGES(MUT) \
	CHANGES(pqcp_evidence_continuity_receipt_digest, \
		struct pqcp_evidence_continuity_witness_receipt, \
		receipt_base, ref, MUT)
	R_CHANGES(c.schema_version ^= 1U);
	R_CHANGES(c.generation ^= 1U);
	R_CHANGES(c.status = PQCP_EVIDENCE_CONTINUITY_RECEIPT_EMPTY);
	R_CHANGES(c.witness_id[0] = 'x');
	R_CHANGES(c.jurisdiction[0] = 'x');
	R_CHANGES(c.failure_domain[0] = 'x');
	R_CHANGES(c.receipt_sequence ^= 1U);
	R_CHANGES(c.checkpoint_sequence ^= 1U);
	R_CHANGES(c.monotonic_counter ^= 1U);
	R_CHANGES(c.observed_at_ms ^= 1U);
	R_CHANGES(c.expires_at_ms ^= 1U);
	R_CHANGES(c.policy_epoch ^= 1U);
	R_CHANGES(c.witness_epoch ^= 1U);
	R_CHANGES(c.weight ^= 1U);
	R_CHANGES(c.signature_length = 65U);
	R_CHANGES(c.challenge_digest[0] ^= 1U);
	R_CHANGES(c.checkpoint_digest[0] ^= 1U);
	R_CHANGES(c.previous_receipt_digest[0] ^= 1U);
	R_CHANGES(c.signature[0] ^= 1U);
	R_CHANGES(c.signature[63] ^= 1U);
	R_CHANGES(c.verified = false);
	R_CHANGES(c.occupied = false);
#undef R_CHANGES

	/* signature bytes past signature_length are not covered */
	UNCHANGED(pqcp_evidence_continuity_receipt_digest,
		  struct pqcp_evidence_continuity_witness_receipt,
		  receipt_base, ref, c.signature[64] ^= 1U);
	UNCHANGED(pqcp_evidence_continuity_receipt_digest,
		  struct pqcp_evidence_continuity_witness_receipt,
		  receipt_base, ref, c.receipt_digest[0] ^= 1U);

	/* a zero-length signature is acceptable and distinct */
	{
		struct pqcp_evidence_continuity_witness_receipt z = *r;
		uint8_t d[DIG];

		z.signature_length = 0U;
		OK(pqcp_evidence_continuity_receipt_digest(&z, d));
		zassert_false(dig_equal(d, ref));
	}

	/* signature_length beyond the buffer is refused before any read */
	memset(out, 0xAA, sizeof(out));
	{
		struct pqcp_evidence_continuity_witness_receipt bad = *r;

		bad.signature_length = sizeof(bad.signature) + 1U;
		ERR(-EINVAL, pqcp_evidence_continuity_receipt_digest(
				     &bad, out));
		bad.signature_length = UINT32_MAX;
		ERR(-EINVAL, pqcp_evidence_continuity_receipt_digest(
				     &bad, out));
		bad = *r;
		bad.signature_length = sizeof(bad.signature);
		OK(pqcp_evidence_continuity_receipt_digest(&bad, out));
	}
	memset(out, 0xAA, sizeof(out));
	ERR(-EINVAL, pqcp_evidence_continuity_receipt_digest(NULL, out));
	ERR(-EINVAL, pqcp_evidence_continuity_receipt_digest(r, NULL));
	{
		struct pqcp_evidence_continuity_witness_receipt bad = *r;

		memset(bad.witness_id, 'w', sizeof(bad.witness_id));
		ERR(-EINVAL, pqcp_evidence_continuity_receipt_digest(
				     &bad, out));
		zassert_true(all_bytes(out, sizeof(out), 0xAAU));
	}
}

/* ------------------------------------------------------------------ */
/* Record codec                                                        */
/* ------------------------------------------------------------------ */

static void make_header(struct pqcp_evidence_continuity_record_header *h,
			const uint8_t *payload, size_t length)
{
	memset(h, 0, sizeof(*h));
	h->magic = PQCP_EVIDENCE_CONTINUITY_RECORD_MAGIC;
	h->schema_version = PQCP_EVIDENCE_CONTINUITY_SCHEMA_VERSION;
	h->object = PQCP_EVIDENCE_CONTINUITY_OBJECT_CHECKPOINT;
	h->slot = 3U;
	h->generation = 0x0102030405060708ULL;
	h->monotonic_counter = 9U;
	h->payload_length = (uint32_t)length;
	h->flags = COMMITTED;
	OK(pqcp_evidence_continuity_hash(payload, length,
					 h->payload_digest));
}

ZTEST(evidence_continuity, test_record_encode_decode_round_trip)
{
	uint8_t payload[100];
	uint8_t record[HDR + sizeof(payload)];
	struct pqcp_evidence_continuity_record_header in;
	struct pqcp_evidence_continuity_record_header out;
	const uint8_t *decoded = NULL;
	size_t length = 0U;

	fill_pattern(payload, sizeof(payload), 0x40U);
	make_header(&in, payload, sizeof(payload));
	OK(pqcp_evidence_continuity_record_encode(
		&in, payload, record, sizeof(record), &length));
	zassert_equal(length, sizeof(record));

	/* canonical big-endian layout */
	zassert_equal(record[0], 0x50U);
	zassert_equal(record[1], 0x45U);
	zassert_equal(record[2], 0x43U);
	zassert_equal(record[3], 0x31U);
	zassert_equal(pqcp_evidence_continuity_read_u32(record + 4U), 1U);
	zassert_equal(pqcp_evidence_continuity_read_u32(record + 8U),
		      (uint32_t)PQCP_EVIDENCE_CONTINUITY_OBJECT_CHECKPOINT);
	zassert_equal(pqcp_evidence_continuity_read_u32(record + 12U), 3U);
	zassert_equal(pqcp_evidence_continuity_read_u64(record + 16U),
		      0x0102030405060708ULL);
	zassert_equal(record[16], 0x01U);
	zassert_equal(pqcp_evidence_continuity_read_u64(record + 24U), 9U);
	zassert_equal(pqcp_evidence_continuity_read_u32(record + 32U),
		      sizeof(payload));
	zassert_equal(pqcp_evidence_continuity_read_u32(record + 36U),
		      COMMITTED);
	zassert_mem_equal(record + 40U, in.payload_digest, DIG);
	zassert_mem_equal(record + HDR, payload, sizeof(payload));

	OK(pqcp_evidence_continuity_record_decode(
		record, length, &out, &decoded));
	zassert_equal(out.magic, in.magic);
	zassert_equal(out.schema_version, in.schema_version);
	zassert_equal(out.object, in.object);
	zassert_equal(out.slot, in.slot);
	zassert_equal(out.generation, in.generation);
	zassert_equal(out.monotonic_counter, in.monotonic_counter);
	zassert_equal(out.payload_length, in.payload_length);
	zassert_equal(out.flags, in.flags);
	zassert_mem_equal(out.payload_digest, in.payload_digest, DIG);
	zassert_equal(decoded, record + HDR);
	zassert_mem_equal(decoded, payload, sizeof(payload));

	/* an empty payload round-trips with a NULL pointer */
	make_header(&in, NULL, 0U);
	OK(pqcp_evidence_continuity_record_encode(
		&in, NULL, record, sizeof(record), &length));
	zassert_equal(length, HDR);
	OK(pqcp_evidence_continuity_record_decode(
		record, length, &out, &decoded));
	zassert_equal(out.payload_length, 0U);

	/* encode argument and capacity validation */
	make_header(&in, payload, sizeof(payload));
	ERR(-EINVAL, pqcp_evidence_continuity_record_encode(
			     NULL, payload, record, sizeof(record), &length));
	ERR(-EINVAL, pqcp_evidence_continuity_record_encode(
			     &in, payload, NULL, sizeof(record), &length));
	ERR(-EINVAL, pqcp_evidence_continuity_record_encode(
			     &in, payload, record, sizeof(record), NULL));
	ERR(-EINVAL, pqcp_evidence_continuity_record_encode(
			     &in, NULL, record, sizeof(record), &length));
	ERR(-ENOSPC, pqcp_evidence_continuity_record_encode(
			     &in, payload, record, sizeof(record) - 1U,
			     &length));
	/* payload that does not match the declared digest is refused */
	payload[0] ^= 1U;
	ERR(-EBADMSG, pqcp_evidence_continuity_record_encode(
			      &in, payload, record, sizeof(record), &length));

	/* decode argument validation */
	payload[0] ^= 1U;
	OK(pqcp_evidence_continuity_record_encode(
		&in, payload, record, sizeof(record), &length));
	ERR(-EINVAL, pqcp_evidence_continuity_record_decode(
			     NULL, length, &out, &decoded));
	ERR(-EINVAL, pqcp_evidence_continuity_record_decode(
			     record, length, NULL, &decoded));
	ERR(-EINVAL, pqcp_evidence_continuity_record_decode(
			     record, length, &out, NULL));
}

ZTEST(evidence_continuity, test_record_decode_rejects_damage)
{
	uint8_t payload[64];
	uint8_t record[HDR + sizeof(payload)];
	uint8_t damaged[sizeof(record) + 1U];
	struct pqcp_evidence_continuity_record_header in;
	struct pqcp_evidence_continuity_record_header out;
	const uint8_t *decoded = NULL;
	size_t length = 0U;

	fill_pattern(payload, sizeof(payload), 0x10U);
	make_header(&in, payload, sizeof(payload));
	OK(pqcp_evidence_continuity_record_encode(
		&in, payload, record, sizeof(record), &length));
	OK(pqcp_evidence_continuity_record_decode(
		record, length, &out, &decoded));

	/* bad magic */
	memcpy(damaged, record, length);
	damaged[0] ^= 0x01U;
	ERR(-EBADMSG, pqcp_evidence_continuity_record_decode(
			      damaged, length, &out, &decoded));

	/* bad schema version */
	memcpy(damaged, record, length);
	damaged[7] = 2U;
	ERR(-EBADMSG, pqcp_evidence_continuity_record_decode(
			      damaged, length, &out, &decoded));

	/* object NONE and object >= COUNT */
	memcpy(damaged, record, length);
	pqcp_evidence_continuity_write_u32(
		damaged + 8U, PQCP_EVIDENCE_CONTINUITY_OBJECT_NONE);
	ERR(-EBADMSG, pqcp_evidence_continuity_record_decode(
			      damaged, length, &out, &decoded));
	pqcp_evidence_continuity_write_u32(
		damaged + 8U, PQCP_EVIDENCE_CONTINUITY_OBJECT_COUNT);
	ERR(-EBADMSG, pqcp_evidence_continuity_record_decode(
			      damaged, length, &out, &decoded));

	/* generation zero is never valid */
	memcpy(damaged, record, length);
	pqcp_evidence_continuity_write_u64(damaged + 16U, 0U);
	ERR(-EBADMSG, pqcp_evidence_continuity_record_decode(
			      damaged, length, &out, &decoded));

	/* missing COMMITTED flag (a torn two-phase write) */
	memcpy(damaged, record, length);
	pqcp_evidence_continuity_write_u32(damaged + 36U, 0U);
	ERR(-EBADMSG, pqcp_evidence_continuity_record_decode(
			      damaged, length, &out, &decoded));
	pqcp_evidence_continuity_write_u32(
		damaged + 36U, PQCP_EVIDENCE_CONTINUITY_RECORD_TOMBSTONE);
	ERR(-EBADMSG, pqcp_evidence_continuity_record_decode(
			      damaged, length, &out, &decoded));

	/* length mismatch: short by one byte and one byte too long */
	memcpy(damaged, record, length);
	ERR(-EBADMSG, pqcp_evidence_continuity_record_decode(
			      damaged, length - 1U, &out, &decoded));
	damaged[length] = 0U;
	ERR(-EBADMSG, pqcp_evidence_continuity_record_decode(
			      damaged, length + 1U, &out, &decoded));

	/* declared payload length larger than the buffer */
	memcpy(damaged, record, length);
	pqcp_evidence_continuity_write_u32(damaged + 32U, UINT32_MAX);
	ERR(-EBADMSG, pqcp_evidence_continuity_record_decode(
			      damaged, length, &out, &decoded));

	/* flipped payload byte (any position) and flipped digest byte */
	for (size_t i = 0U; i < sizeof(payload); i += 9U) {
		memcpy(damaged, record, length);
		damaged[HDR + i] ^= 0x80U;
		ERR(-EBADMSG, pqcp_evidence_continuity_record_decode(
				      damaged, length, &out, &decoded));
	}
	memcpy(damaged, record, length);
	damaged[40] ^= 0x01U;
	ERR(-EBADMSG, pqcp_evidence_continuity_record_decode(
			      damaged, length, &out, &decoded));

	/* truncated below the fixed header, and a header-only prefix of a
	 * record that declares a payload
	 */
	ERR(-EINVAL, pqcp_evidence_continuity_record_decode(
			     record, HDR - 1U, &out, &decoded));
	ERR(-EINVAL, pqcp_evidence_continuity_record_decode(
			     record, 0U, &out, &decoded));
	ERR(-EBADMSG, pqcp_evidence_continuity_record_decode(
			      record, HDR, &out, &decoded));

	/* the pristine record still decodes */
	OK(pqcp_evidence_continuity_record_decode(
		record, length, &out, &decoded));
}

/* ------------------------------------------------------------------ */
/* Two-phase store / load                                              */
/* ------------------------------------------------------------------ */

ZTEST(evidence_continuity, test_store_load_round_trip)
{
	uint8_t payload[120];
	uint8_t buffer[HDR + sizeof(payload)];
	struct pqcp_evidence_continuity_record_header h;
	const uint8_t *decoded = NULL;
	uint8_t first[HDR + sizeof(payload)];

	fill_pattern(payload, sizeof(payload), 0x22U);
	OK(pqcp_evidence_continuity_store_record(
		&store, PQCP_EVIDENCE_CONTINUITY_OBJECT_JOURNAL, 2U, 5U, 11U,
		payload, sizeof(payload)));
	/* erase, header, payload, header-commit; sync after both phases */
	zassert_equal(ram.erases, 1);
	zassert_equal(ram.writes, 3);
	zassert_equal(ram.syncs, 2);

	OK(pqcp_evidence_continuity_load_record(
		&store, PQCP_EVIDENCE_CONTINUITY_OBJECT_JOURNAL, 2U, buffer,
		sizeof(buffer), &h, &decoded));
	zassert_equal(h.object, PQCP_EVIDENCE_CONTINUITY_OBJECT_JOURNAL);
	zassert_equal(h.slot, 2U);
	zassert_equal(h.generation, 5U);
	zassert_equal(h.monotonic_counter, 11U);
	zassert_equal(h.payload_length, sizeof(payload));
	zassert_true((h.flags & COMMITTED) != 0U);
	zassert_mem_equal(decoded, payload, sizeof(payload));
	memcpy(first, buffer, sizeof(first));

	/* a second store replaces the slot with the new generation */
	payload[0] ^= 0xFFU;
	OK(pqcp_evidence_continuity_store_record(
		&store, PQCP_EVIDENCE_CONTINUITY_OBJECT_JOURNAL, 2U, 6U, 12U,
		payload, sizeof(payload)));
	OK(pqcp_evidence_continuity_load_record(
		&store, PQCP_EVIDENCE_CONTINUITY_OBJECT_JOURNAL, 2U, buffer,
		sizeof(buffer), &h, &decoded));
	zassert_equal(h.generation, 6U);
	zassert_equal(h.monotonic_counter, 12U);
	zassert_mem_equal(decoded, payload, sizeof(payload));
	zassert_true(memcmp(first, buffer, sizeof(first)) != 0);

	/* other slots and objects are independent and still empty */
	ERR(-ENOENT, pqcp_evidence_continuity_load_record(
			     &store, PQCP_EVIDENCE_CONTINUITY_OBJECT_JOURNAL,
			     1U, buffer, sizeof(buffer), &h, &decoded));
	ERR(-ENOENT, pqcp_evidence_continuity_load_record(
			     &store, PQCP_EVIDENCE_CONTINUITY_OBJECT_ANCHOR,
			     2U, buffer, sizeof(buffer), &h, &decoded));

	/* empty payloads store as header-only records (two writes) */
	ram.writes = 0;
	OK(pqcp_evidence_continuity_store_record(
		&store, PQCP_EVIDENCE_CONTINUITY_OBJECT_ANCHOR, 0U, 1U, 0U,
		NULL, 0U));
	zassert_equal(ram.writes, 2);
	OK(pqcp_evidence_continuity_load_record(
		&store, PQCP_EVIDENCE_CONTINUITY_OBJECT_ANCHOR, 0U, buffer,
		sizeof(buffer), &h, &decoded));
	zassert_equal(h.payload_length, 0U);

	/* buffer too small for the record: the truncated read is rejected */
	ERR(-EBADMSG, pqcp_evidence_continuity_load_record(
			      &store, PQCP_EVIDENCE_CONTINUITY_OBJECT_JOURNAL,
			      2U, buffer, HDR + 10U, &h, &decoded));
	/* buffer smaller than a header and NULL arguments */
	ERR(-EINVAL, pqcp_evidence_continuity_load_record(
			     &store, PQCP_EVIDENCE_CONTINUITY_OBJECT_JOURNAL,
			     2U, buffer, HDR - 1U, &h, &decoded));
	ERR(-EINVAL, pqcp_evidence_continuity_load_record(
			     NULL, PQCP_EVIDENCE_CONTINUITY_OBJECT_JOURNAL,
			     2U, buffer, sizeof(buffer), &h, &decoded));
	ERR(-EINVAL, pqcp_evidence_continuity_load_record(
			     &store, PQCP_EVIDENCE_CONTINUITY_OBJECT_JOURNAL,
			     2U, NULL, sizeof(buffer), &h, &decoded));
	ERR(-EINVAL, pqcp_evidence_continuity_load_record(
			     &store, PQCP_EVIDENCE_CONTINUITY_OBJECT_JOURNAL,
			     2U, buffer, sizeof(buffer), NULL, &decoded));
	ERR(-EINVAL, pqcp_evidence_continuity_load_record(
			     &store, PQCP_EVIDENCE_CONTINUITY_OBJECT_JOURNAL,
			     2U, buffer, sizeof(buffer), &h, NULL));
	{
		struct pqcp_evidence_continuity_store no_read = store;

		no_read.read = NULL;
		ERR(-EINVAL, pqcp_evidence_continuity_load_record(
				     &no_read,
				     PQCP_EVIDENCE_CONTINUITY_OBJECT_JOURNAL,
				     2U, buffer, sizeof(buffer), &h,
				     &decoded));
	}
}

ZTEST(evidence_continuity, test_load_rejects_swapped_object_or_slot)
{
	uint8_t payload[32];
	uint8_t buffer[HDR + sizeof(payload)];
	struct pqcp_evidence_continuity_record_header h;
	const uint8_t *decoded = NULL;
	const size_t total = HDR + sizeof(payload);

	fill_pattern(payload, sizeof(payload), 0x77U);
	OK(pqcp_evidence_continuity_store_record(
		&store, PQCP_EVIDENCE_CONTINUITY_OBJECT_CHECKPOINT, 1U, 9U,
		3U, payload, sizeof(payload)));

	/* an attacker (or a bug) copies a valid record into another slot */
	memcpy(ram.data[PQCP_EVIDENCE_CONTINUITY_OBJECT_CHECKPOINT][0],
	       ram.data[PQCP_EVIDENCE_CONTINUITY_OBJECT_CHECKPOINT][1],
	       total);
	ram.length[PQCP_EVIDENCE_CONTINUITY_OBJECT_CHECKPOINT][0] = total;
	ram.present[PQCP_EVIDENCE_CONTINUITY_OBJECT_CHECKPOINT][0] = true;
	ERR(-EBADMSG, pqcp_evidence_continuity_load_record(
			      &store, PQCP_EVIDENCE_CONTINUITY_OBJECT_CHECKPOINT,
			      0U, buffer, sizeof(buffer), &h, &decoded));

	/* ... or into a different object's namespace */
	memcpy(ram.data[PQCP_EVIDENCE_CONTINUITY_OBJECT_ANCHOR][1],
	       ram.data[PQCP_EVIDENCE_CONTINUITY_OBJECT_CHECKPOINT][1],
	       total);
	ram.length[PQCP_EVIDENCE_CONTINUITY_OBJECT_ANCHOR][1] = total;
	ram.present[PQCP_EVIDENCE_CONTINUITY_OBJECT_ANCHOR][1] = true;
	ERR(-EBADMSG, pqcp_evidence_continuity_load_record(
			      &store, PQCP_EVIDENCE_CONTINUITY_OBJECT_ANCHOR,
			      1U, buffer, sizeof(buffer), &h, &decoded));

	/* the genuine location still loads */
	OK(pqcp_evidence_continuity_load_record(
		&store, PQCP_EVIDENCE_CONTINUITY_OBJECT_CHECKPOINT, 1U,
		buffer, sizeof(buffer), &h, &decoded));
	zassert_equal(h.generation, 9U);

	/* an at-rest bit flip in the payload is caught by the digest */
	ram.data[PQCP_EVIDENCE_CONTINUITY_OBJECT_CHECKPOINT][1][HDR + 5U] ^=
		0x04U;
	ERR(-EBADMSG, pqcp_evidence_continuity_load_record(
			      &store, PQCP_EVIDENCE_CONTINUITY_OBJECT_CHECKPOINT,
			      1U, buffer, sizeof(buffer), &h, &decoded));
}

ZTEST(evidence_continuity, test_store_failures_leave_uncommitted_record)
{
	uint8_t payload[48];
	uint8_t buffer[HDR + sizeof(payload)];
	struct pqcp_evidence_continuity_record_header h;
	const uint8_t *decoded = NULL;
	const enum pqcp_evidence_continuity_object obj =
		PQCP_EVIDENCE_CONTINUITY_OBJECT_ANCHOR;

	fill_pattern(payload, sizeof(payload), 0x31U);

	/* a failing first sync: the record is written but never committed */
	ram.fail_sync_at = 1;
	ERR(-EIO, pqcp_evidence_continuity_store_record(
			  &store, obj, 1U, 4U, 8U, payload, sizeof(payload)));
	zassert_equal(ram.syncs, 1);
	zassert_true(ram.present[obj][1]);
	zassert_equal(ram.length[obj][1], HDR + sizeof(payload));
	zassert_equal(pqcp_evidence_continuity_read_u32(
			      &ram.data[obj][1][36]) & COMMITTED, 0U);
	ERR(-EBADMSG, pqcp_evidence_continuity_load_record(
			      &store, obj, 1U, buffer, sizeof(buffer), &h,
			      &decoded));

	/* a failing commit-header write leaves the record uncommitted too */
	memset(&ram, 0, sizeof(ram));
	ram.fail_write_at = 3;
	ERR(-EIO, pqcp_evidence_continuity_store_record(
			  &store, obj, 1U, 4U, 8U, payload, sizeof(payload)));
	ERR(-EBADMSG, pqcp_evidence_continuity_load_record(
			      &store, obj, 1U, buffer, sizeof(buffer), &h,
			      &decoded));

	/* a failing payload write stops before any sync */
	memset(&ram, 0, sizeof(ram));
	ram.fail_write_at = 2;
	ERR(-EIO, pqcp_evidence_continuity_store_record(
			  &store, obj, 1U, 4U, 8U, payload, sizeof(payload)));
	zassert_equal(ram.syncs, 0);
	ERR(-EBADMSG, pqcp_evidence_continuity_load_record(
			      &store, obj, 1U, buffer, sizeof(buffer), &h,
			      &decoded));

	/* a failing erase writes nothing at all */
	memset(&ram, 0, sizeof(ram));
	ram.fail_erase = 1;
	ERR(-EIO, pqcp_evidence_continuity_store_record(
			  &store, obj, 1U, 4U, 8U, payload, sizeof(payload)));
	zassert_equal(ram.writes, 0);
	ERR(-ENOENT, pqcp_evidence_continuity_load_record(
			     &store, obj, 1U, buffer, sizeof(buffer), &h,
			     &decoded));

	/* a failing final sync is reported to the caller */
	memset(&ram, 0, sizeof(ram));
	ram.fail_sync_at = 2;
	ERR(-EIO, pqcp_evidence_continuity_store_record(
			  &store, obj, 1U, 4U, 8U, payload, sizeof(payload)));

	/* a failed overwrite must not resurrect the previous committed
	 * record as if it were the new one: the old record was erased
	 */
	memset(&ram, 0, sizeof(ram));
	OK(pqcp_evidence_continuity_store_record(
		&store, obj, 1U, 1U, 1U, payload, sizeof(payload)));
	ram.fail_sync_at = ram.syncs + 1;
	ERR(-EIO, pqcp_evidence_continuity_store_record(
			  &store, obj, 1U, 2U, 2U, payload, sizeof(payload)));
	ERR(-EBADMSG, pqcp_evidence_continuity_load_record(
			      &store, obj, 1U, buffer, sizeof(buffer), &h,
			      &decoded));
}

ZTEST(evidence_continuity, test_store_record_argument_validation)
{
	uint8_t payload[40];
	struct pqcp_evidence_continuity_store bad;
	const enum pqcp_evidence_continuity_object obj =
		PQCP_EVIDENCE_CONTINUITY_OBJECT_SNAPSHOT;

	fill_pattern(payload, sizeof(payload), 0x55U);

	ERR(-EINVAL, pqcp_evidence_continuity_store_record(
			     NULL, obj, 0U, 1U, 1U, payload,
			     sizeof(payload)));
	bad = store;
	bad.write = NULL;
	ERR(-EINVAL, pqcp_evidence_continuity_store_record(
			     &bad, obj, 0U, 1U, 1U, payload,
			     sizeof(payload)));
	bad = store;
	bad.erase = NULL;
	ERR(-EINVAL, pqcp_evidence_continuity_store_record(
			     &bad, obj, 0U, 1U, 1U, payload,
			     sizeof(payload)));
	bad = store;
	bad.sync = NULL;
	ERR(-EINVAL, pqcp_evidence_continuity_store_record(
			     &bad, obj, 0U, 1U, 1U, payload,
			     sizeof(payload)));
	ERR(-EINVAL, pqcp_evidence_continuity_store_record(
			     &store, PQCP_EVIDENCE_CONTINUITY_OBJECT_NONE, 0U,
			     1U, 1U, payload, sizeof(payload)));
	ERR(-EINVAL, pqcp_evidence_continuity_store_record(
			     &store, PQCP_EVIDENCE_CONTINUITY_OBJECT_COUNT,
			     0U, 1U, 1U, payload, sizeof(payload)));
	ERR(-EINVAL, pqcp_evidence_continuity_store_record(
			     &store, obj, 0U, 0U, 1U, payload,
			     sizeof(payload)));
	ERR(-EINVAL, pqcp_evidence_continuity_store_record(
			     &store, obj, 0U, 1U, 1U, NULL,
			     sizeof(payload)));
	zassert_equal(ram.erases, 0);
	zassert_equal(ram.writes, 0);

	/* maximum_record_bytes bounds header + payload exactly */
	bad = store;
	bad.maximum_record_bytes = HDR + sizeof(payload) - 1U;
	ERR(-EINVAL, pqcp_evidence_continuity_store_record(
			     &bad, obj, 0U, 1U, 1U, payload,
			     sizeof(payload)));
	zassert_equal(ram.writes, 0);
	bad.maximum_record_bytes = HDR + sizeof(payload);
	OK(pqcp_evidence_continuity_store_record(
		&bad, obj, 0U, 1U, 1U, payload, sizeof(payload)));

	/* the largest slot payload fits, one more byte does not */
	{
		uint8_t big[RAM_SLOT_BYTES];

		fill_pattern(big, sizeof(big), 1U);
		OK(pqcp_evidence_continuity_store_record(
			&store, obj, 1U, 1U, 1U, big,
			RAM_SLOT_BYTES - HDR));
		ERR(-ENOSPC, pqcp_evidence_continuity_store_record(
				     &store, obj, 2U, 1U, 1U, big,
				     RAM_SLOT_BYTES - HDR + 1U));
	}
}

/*
 * REGRESSION: load_record trusted the length reported by the read callback.
 * A callback (or corrupted backend) reporting the stored size instead of the
 * bytes it delivered made decode read and hash past the end of the caller's
 * buffer. The arena below holds the rest of the record just after the
 * buffer, so an unguarded decode would "validate" it and return success.
 */
ZTEST(evidence_continuity, test_load_rejects_overlong_read_length)
{
	uint8_t payload[24];
	uint8_t arena[HDR + sizeof(payload)];
	struct pqcp_evidence_continuity_record_header h;
	const uint8_t *decoded = NULL;
	const enum pqcp_evidence_continuity_object obj =
		PQCP_EVIDENCE_CONTINUITY_OBJECT_COMPACTION_STATE;
	const size_t cap = HDR + 8U;

	fill_pattern(payload, sizeof(payload), 0x66U);
	OK(pqcp_evidence_continuity_store_record(
		&store, obj, 3U, 2U, 2U, payload, sizeof(payload)));

	/* honest read with full capacity works */
	memset(arena, 0xCC, sizeof(arena));
	OK(pqcp_evidence_continuity_load_record(
		&store, obj, 3U, arena, sizeof(arena), &h, &decoded));

	/* dishonest read: only `cap` bytes delivered, full size reported,
	 * and the remainder of the record sits right behind the buffer
	 */
	memcpy(arena, ram.data[obj][3], sizeof(arena));
	ram.bogus_length = true;
	ERR(-EBADMSG, pqcp_evidence_continuity_load_record(
			      &store, obj, 3U, arena, cap, &h, &decoded));
}
