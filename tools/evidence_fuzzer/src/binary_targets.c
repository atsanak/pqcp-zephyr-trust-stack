/*
 * SPDX-License-Identifier: MIT
 *
 * Binary parser targets for pqcp-evidence-fuzz.
 *
 * The text targets in main.c consume serial transcript lines. The fleet
 * stack's wire formats are length-delimited byte strings, so they get their
 * own coverage-guided campaign here, driving the UNMODIFIED firmware
 * parsers (compiled for host in the instrumented fuzz_targets library):
 *
 *   cbor        fleet deterministic-CBOR validator, skipper, map/array
 *               accessors and writer (src/fleet_cbor_map.c)
 *   cose_sign1  COSE_Sign1 decode/encode/verify and the protected-header
 *               codec (src/fleet_cose_sign1.c)
 *   cose_key    COSE_Key decode/encode/thumbprint (src/fleet_cose_key.c)
 *   policy      policy bytecode module codec, structural verifier and VM
 *               (src/fleet_policy_codec.c, _verify.c, _vm.c)
 *
 * The channel frame codecs (protected_channel_codec.c,
 * sovereign_channel_codec.c) are intentionally NOT here: they are only
 * reachable through runtime_internal.h, whose helpers live in
 * runtime_common.c next to PSA and kernel-clock calls, and whose header
 * chain needs a fake zephyr/kernel.h (k_mutex, k_sem, k_thread, ...). That
 * is a larger shim than the pure printk alias this harness allows itself.
 *
 * Invariants asserted per input, beyond "ASan+UBSan stay silent":
 *   - every input is handed over in an exact-size heap buffer, so any
 *     over-read of even one byte is an ASan report;
 *   - decode(encode(x)) round-trips byte-for-byte whenever the decoder
 *     accepts an input (canonical formats leave no slack);
 *   - rejected inputs leave outputs unused: untouched, zeroed, or (for
 *     slices) bounded by the input, never dangling;
 *   - the structural verifier and the VM agree: a verified module may only
 *     fault at run time for data-dependent reasons.
 *
 * A violated invariant prints the reproducer as hex and aborts.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pqcp_zephyr/fleet_cose.h>
#include <pqcp_zephyr/fleet_policy_vm.h>

#include "fuzz_common.h"

#define BIN_MAX 8192U
#define BIN_CORPUS_MAX 2048U

enum bin_target {
	T_CBOR = 0,
	T_COSE_SIGN1,
	T_COSE_KEY,
	T_POLICY,
};

static const char *const target_names[BINARY_TARGET_COUNT] = {
	"cbor", "cose_sign1", "cose_key", "policy",
};

static uint8_t bin_corpus[BIN_CORPUS_MAX][BIN_MAX];
static size_t bin_lengths[BIN_CORPUS_MAX];
static uint8_t bin_tags[BIN_CORPUS_MAX];
static size_t bin_count;

/* Per-target inputs the parser ACCEPTED, plus policy modules that passed
 * the structural verifier and ran to a decision in the VM. These show the
 * campaign gets past the rejection gates instead of only bouncing off
 * them; they are reported next to the PASS marker.
 */
static unsigned long accepted[BINARY_TARGET_COUNT];
static unsigned long policy_verified;
static unsigned long policy_vm_decided;

/* ------------------------------------------------------------------ */
/* Failure reporting                                                    */
/* ------------------------------------------------------------------ */

static const uint8_t *current_input;
static size_t current_length;
static unsigned current_target;

static void fuzz_fail(const char *what, const char *expr, int line)
{
	fflush(stdout);
	fprintf(stderr,
		"PQCP_FUZZ INVARIANT VIOLATION target=%s line=%d: %s [%s]\n"
		"input_len=%zu input_hex=",
		target_names[current_target], line, what, expr,
		current_length);
	for (size_t i = 0U; i < current_length && i < 1024U; ++i) {
		fprintf(stderr, "%02x", current_input[i]);
	}
	fprintf(stderr, "%s\n",
		current_length > 1024U ? "... (truncated; rerun with the same --seed)" : "");
	abort();
}

#define REQUIRE(cond, what) \
	do { \
		if (!(cond)) { \
			fuzz_fail((what), #cond, __LINE__); \
		} \
	} while (0)

static uint8_t *exact_alloc(size_t length)
{
	uint8_t *p = malloc(length != 0U ? length : 1U);

	if (p == NULL) {
		abort();
	}
	return p;
}

static bool bytes_zero(const void *data, size_t length)
{
	const uint8_t *p = data;

	for (size_t i = 0U; i < length; ++i) {
		if (p[i] != 0U) {
			return false;
		}
	}
	return true;
}

static bool slice_inside(const struct pqcp_fleet_cbor_slice *slice,
			 const uint8_t *in, size_t length)
{
	const uintptr_t base = (uintptr_t)in;
	const uintptr_t data = (uintptr_t)slice->data;

	if (slice->data == NULL) {
		return slice->length == 0U;
	}
	return data >= base && data - base <= length &&
	       slice->length <= length - (data - base);
}

static uint32_t be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* ------------------------------------------------------------------ */
/* Compact SHA-256 (digest fix-up for the policy wire format)           */
/* ------------------------------------------------------------------ */

static const uint32_t sha_k[64] = {
	0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU,
	0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U,
	0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U,
	0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
	0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U,
	0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
	0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
	0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
	0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U,
	0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U, 0x1e376c08U,
	0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU,
	0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
	0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static uint32_t rotr(uint32_t x, unsigned n)
{
	return (x >> n) | (x << (32U - n));
}

static void sha_block(uint32_t h[8], const uint8_t *p)
{
	uint32_t w[64];
	uint32_t v[8];

	for (unsigned i = 0U; i < 16U; ++i) {
		w[i] = be32(p + 4U * i);
	}
	for (unsigned i = 16U; i < 64U; ++i) {
		const uint32_t s0 = rotr(w[i - 15U], 7U) ^
				    rotr(w[i - 15U], 18U) ^ (w[i - 15U] >> 3);
		const uint32_t s1 = rotr(w[i - 2U], 17U) ^
				    rotr(w[i - 2U], 19U) ^ (w[i - 2U] >> 10);

		w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
	}
	memcpy(v, h, sizeof(v));
	for (unsigned i = 0U; i < 64U; ++i) {
		const uint32_t s1 = rotr(v[4], 6U) ^ rotr(v[4], 11U) ^
				    rotr(v[4], 25U);
		const uint32_t ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
		const uint32_t t1 = v[7] + s1 + ch + sha_k[i] + w[i];
		const uint32_t s0 = rotr(v[0], 2U) ^ rotr(v[0], 13U) ^
				    rotr(v[0], 22U);
		const uint32_t mj = (v[0] & v[1]) ^ (v[0] & v[2]) ^
				    (v[1] & v[2]);
		const uint32_t t2 = s0 + mj;

		v[7] = v[6];
		v[6] = v[5];
		v[5] = v[4];
		v[4] = v[3] + t1;
		v[3] = v[2];
		v[2] = v[1];
		v[1] = v[0];
		v[0] = t1 + t2;
	}
	for (unsigned i = 0U; i < 8U; ++i) {
		h[i] += v[i];
	}
}

static void sha256(const uint8_t *data, size_t length, uint8_t out[32])
{
	uint32_t h[8] = {
		0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
		0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
	};
	uint8_t tail[128];
	size_t full = length / 64U;
	size_t rest = length % 64U;
	size_t tail_len = rest < 56U ? 64U : 128U;
	const uint64_t bits = (uint64_t)length * 8U;

	for (size_t i = 0U; i < full; ++i) {
		sha_block(h, data + 64U * i);
	}
	memset(tail, 0, sizeof(tail));
	memcpy(tail, data + 64U * full, rest);
	tail[rest] = 0x80U;
	for (unsigned i = 0U; i < 8U; ++i) {
		tail[tail_len - 1U - i] = (uint8_t)(bits >> (8U * i));
	}
	sha_block(h, tail);
	if (tail_len == 128U) {
		sha_block(h, tail + 64U);
	}
	for (unsigned i = 0U; i < 8U; ++i) {
		out[4U * i] = (uint8_t)(h[i] >> 24);
		out[4U * i + 1U] = (uint8_t)(h[i] >> 16);
		out[4U * i + 2U] = (uint8_t)(h[i] >> 8);
		out[4U * i + 3U] = (uint8_t)h[i];
	}
}

#define POLICY_HEADER_BYTES 104U
#define POLICY_DIGEST_OFFSET 72U

/* Recompute the self-digest so mutated modules get past the digest gate
 * and exercise the second decode pass, the verifier and the VM.
 */
static void policy_fix_digest(uint8_t *buf, size_t length)
{
	uint8_t digest[32];

	if (length < POLICY_HEADER_BYTES) {
		return;
	}
	memset(buf + POLICY_DIGEST_OFFSET, 0, 32U);
	sha256(buf, length, digest);
	memcpy(buf + POLICY_DIGEST_OFFSET, digest, 32U);
}

/* ------------------------------------------------------------------ */
/* Mock crypto callbacks (accept/reject chosen by the harness)          */
/* ------------------------------------------------------------------ */

struct mock_crypto {
	bool accept;
	unsigned verify_calls;
};

static volatile uint8_t touch_sink;

static void touch(const uint8_t *p, size_t n)
{
	uint8_t acc = 0U;

	for (size_t i = 0U; i < n; ++i) {
		acc ^= p[i];
	}
	touch_sink ^= acc;
}

static int mock_verify(void *context, int32_t algorithm,
		       const uint8_t *key_id, size_t key_id_length,
		       const uint8_t *message, size_t message_length,
		       const uint8_t *signature, size_t signature_length)
{
	struct mock_crypto *mock = context;

	(void)algorithm;
	mock->verify_calls++;
	touch(key_id, key_id_length);
	touch(message, message_length);
	touch(signature, signature_length);
	return mock->accept ? 0 : -1;
}

static int mock_sign(void *context, int32_t algorithm,
		     const uint8_t *key_id, size_t key_id_length,
		     const uint8_t *message, size_t message_length,
		     uint8_t *signature, size_t signature_capacity,
		     size_t *signature_length)
{
	(void)context;
	(void)algorithm;
	touch(key_id, key_id_length);
	touch(message, message_length);
	for (size_t i = 0U; i < signature_capacity; ++i) {
		signature[i] = (uint8_t)(i * 31U + 7U);
	}
	*signature_length = signature_capacity;
	return 0;
}

static int mock_hash(void *context, const uint8_t *message,
		     size_t message_length, uint8_t *digest,
		     size_t digest_capacity, size_t *digest_length)
{
	(void)context;
	if (digest_capacity < 32U) {
		return -1;
	}
	sha256(message, message_length, digest);
	*digest_length = 32U;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Target: fleet CBOR                                                   */
/* ------------------------------------------------------------------ */

#define REENCODE_UNREPRESENTABLE 1000

static int reencode_item(struct pqcp_fleet_cbor_reader *reader,
			 struct pqcp_fleet_cbor_writer *writer,
			 unsigned depth)
{
	struct pqcp_fleet_cbor_reader probe = *reader;
	struct pqcp_fleet_cbor_head head;
	int ret;

	if (depth > 40U) {
		return PQCP_FLEET_COSE_ERR_CAPACITY;
	}
	ret = pqcp_fleet_cbor_read_head(&probe, &head);
	if (ret != 0) {
		return ret;
	}
	switch (head.major) {
	case PQCP_FLEET_CBOR_UNSIGNED: {
		uint64_t value;

		ret = pqcp_fleet_cbor_read_uint(reader, &value);
		return ret != 0 ? ret :
			pqcp_fleet_cbor_write_uint(writer, value);
	}
	case PQCP_FLEET_CBOR_NEGATIVE: {
		int64_t value;

		if (head.argument > (uint64_t)INT64_MAX) {
			return REENCODE_UNREPRESENTABLE;
		}
		ret = pqcp_fleet_cbor_read_int(reader, &value);
		return ret != 0 ? ret :
			pqcp_fleet_cbor_write_int(writer, value);
	}
	case PQCP_FLEET_CBOR_BYTES: {
		struct pqcp_fleet_cbor_slice slice;

		ret = pqcp_fleet_cbor_read_bytes(reader, &slice);
		return ret != 0 ? ret :
			pqcp_fleet_cbor_write_bytes(writer, slice.data,
						    slice.length);
	}
	case PQCP_FLEET_CBOR_TEXT: {
		struct pqcp_fleet_cbor_slice slice;

		ret = pqcp_fleet_cbor_read_text(reader, &slice);
		return ret != 0 ? ret :
			pqcp_fleet_cbor_write_text(
				writer, (const char *)slice.data,
				slice.length);
	}
	case PQCP_FLEET_CBOR_TAG:
		ret = pqcp_fleet_cbor_read_tag(reader, head.argument);
		if (ret == 0) {
			ret = pqcp_fleet_cbor_write_tag(writer,
							head.argument);
		}
		return ret != 0 ? ret :
			reencode_item(reader, writer, depth + 1U);
	case PQCP_FLEET_CBOR_ARRAY: {
		size_t count;

		ret = pqcp_fleet_cbor_read_array(reader, &count);
		if (ret == 0) {
			ret = pqcp_fleet_cbor_write_array(writer, count);
		}
		for (size_t i = 0U; ret == 0 && i < count; ++i) {
			ret = reencode_item(reader, writer, depth + 1U);
		}
		return ret;
	}
	case PQCP_FLEET_CBOR_MAP: {
		struct pqcp_fleet_cbor_map_cursor cursor;
		size_t count;

		ret = pqcp_fleet_cbor_read_map(reader, &cursor);
		count = cursor.remaining;
		if (ret == 0) {
			ret = pqcp_fleet_cbor_write_map(writer, count);
		}
		for (size_t i = 0U; ret == 0 && i < count * 2U; ++i) {
			ret = reencode_item(reader, writer, depth + 1U);
		}
		return ret;
	}
	case PQCP_FLEET_CBOR_SIMPLE:
		if (head.argument == PQCP_FLEET_CBOR_NULL) {
			ret = pqcp_fleet_cbor_read_null(reader);
			return ret != 0 ? ret :
				pqcp_fleet_cbor_write_null(writer);
		} else {
			bool value;

			ret = pqcp_fleet_cbor_read_bool(reader, &value);
			return ret != 0 ? ret :
				pqcp_fleet_cbor_write_bool(writer, value);
		}
	default:
		return PQCP_FLEET_COSE_ERR_UNSUPPORTED;
	}
}

static void check_cbor_container(const uint8_t *in, size_t len)
{
	struct pqcp_fleet_cbor_reader reader;
	struct pqcp_fleet_cbor_slice slice;
	size_t count = 123U;
	int ret;

	/* Arrays. */
	ret = pqcp_fleet_cbor_array_count(in, len, &count);
	if (ret != 0) {
		REQUIRE(count == 0U, "array_count leaves count set on error");
	} else {
		pqcp_fleet_cbor_reader_init(&reader, in, len);
		REQUIRE(pqcp_fleet_cbor_read_array(&reader, &count) == 0,
			"array_count ok but read_array failed");
		REQUIRE(count <= len, "array count exceeds input size");
		for (size_t i = 0U; i < count; ++i) {
			REQUIRE(pqcp_fleet_cbor_skip(&reader) == 0,
				"valid array element failed to skip");
		}
		REQUIRE(pqcp_fleet_cbor_reader_finish(&reader) == 0,
			"valid array has trailing bytes after count items");
		for (size_t index = 0U; index <= count && index < 4U;
		     ++index) {
			memset(&slice, 0xA5, sizeof(slice));
			ret = pqcp_fleet_cbor_array_get(in, len, index,
							&slice);
			if (index < count) {
				REQUIRE(ret == 0, "array_get in range failed");
				REQUIRE(slice.length != 0U &&
						slice_inside(&slice, in, len),
					"array_get slice escapes input");
				REQUIRE(pqcp_fleet_cbor_validate(
						slice.data, slice.length) == 0,
					"array element is not valid CBOR");
			} else {
				REQUIRE(ret == PQCP_FLEET_COSE_ERR_REQUIRED,
					"array_get out of range accepted");
				REQUIRE(slice.data == NULL &&
						slice.length == 0U,
					"array_get left output set on error");
			}
		}
	}

	/* Maps. */
	count = 123U;
	ret = pqcp_fleet_cbor_map_count(in, len, &count);
	if (ret != 0) {
		REQUIRE(count == 0U, "map_count leaves count set on error");
		memset(&slice, 0xA5, sizeof(slice));
		(void)pqcp_fleet_cbor_map_find_int(in, len, 1, &slice);
		REQUIRE(slice.data == NULL && slice.length == 0U,
			"map_find_int left output set on error");
	} else {
		struct pqcp_fleet_cbor_map_cursor cursor;
		struct pqcp_fleet_cbor_map_key key;
		size_t seen = 0U;

		pqcp_fleet_cbor_reader_init(&reader, in, len);
		REQUIRE(pqcp_fleet_cbor_read_map(&reader, &cursor) == 0,
			"map_count ok but read_map failed");
		REQUIRE(cursor.remaining == count, "map cursor count drift");
		while (cursor.remaining != 0U) {
			size_t value_start;

			REQUIRE(pqcp_fleet_cbor_map_next(&reader, &cursor,
							 &key) == 0,
				"valid map key rejected by map_next");
			value_start = reader.offset;
			REQUIRE(pqcp_fleet_cbor_skip(&reader) == 0,
				"valid map value failed to skip");
			seen++;
			if (key.integer) {
				memset(&slice, 0xA5, sizeof(slice));
				REQUIRE(pqcp_fleet_cbor_map_find_int(
						in, len, key.integer_value,
						&slice) == 0,
					"find_int misses a present key");
				REQUIRE(slice.data == in + value_start &&
						slice.length ==
							reader.offset -
								value_start,
					"find_int returned the wrong value");
			}
		}
		REQUIRE(seen == count, "map iteration count drift");
		REQUIRE(pqcp_fleet_cbor_reader_finish(&reader) == 0,
			"valid map has trailing bytes");
		memset(&slice, 0xA5, sizeof(slice));
		ret = pqcp_fleet_cbor_map_find_int(in, len, INT64_MIN + 7,
						   &slice);
		REQUIRE(ret == PQCP_FLEET_COSE_ERR_REQUIRED,
			"find_int invented a key");
		REQUIRE(slice.data == NULL && slice.length == 0U,
			"find_int left output set on miss");
	}
}

static void fuzz_cbor(const uint8_t *in, size_t len)
{
	struct pqcp_fleet_cbor_reader reader;
	size_t span = 77U;
	const int valid = pqcp_fleet_cbor_validate(in, len);
	const int sret = pqcp_fleet_cbor_item_span(in, len, &span);

	if (len == 0U) {
		REQUIRE(valid == PQCP_FLEET_COSE_ERR_ARGUMENT,
			"empty input not an argument error");
		return;
	}

	/* validate() and item_span() agree, and item_span reports 0 length
	 * for everything it rejects.
	 */
	if (sret != 0) {
		REQUIRE(span == 0U, "item_span leaves length set on error");
	} else {
		REQUIRE(span != 0U && span <= len, "item_span out of range");
		REQUIRE(pqcp_fleet_cbor_validate(in, span) == 0,
			"item_span returned a non-valid prefix");
	}
	REQUIRE((valid == 0) == (sret == 0 && span == len),
		"validate and item_span disagree");

	/* copy_item at several capacities, into exact-size buffers. */
	{
		const size_t caps[4] = { 0U, span != 0U ? span - 1U : 0U,
					 span, len + 8U };

		for (unsigned i = 0U; i < 4U; ++i) {
			uint8_t *out = exact_alloc(caps[i]);
			size_t olen = 55U;
			const int ret = pqcp_fleet_cbor_copy_item(
				in, len, out, caps[i], &olen);

			if (ret != 0) {
				REQUIRE(olen == 0U,
					"copy_item leaves length set on error");
			} else {
				REQUIRE(olen == span && olen <= caps[i] &&
						memcmp(out, in, olen) == 0,
					"copy_item wrong content");
			}
			if (sret == 0 && caps[i] < span) {
				REQUIRE(ret == PQCP_FLEET_COSE_ERR_CAPACITY,
					"copy_item overflowed capacity");
			}
			free(out);
		}
	}

	/* Antisymmetry of the canonical key order on two halves. */
	{
		const size_t half = len / 2U;
		const int ab = pqcp_fleet_cbor_compare_encoded_keys(
			in, half, in + half, len - half);
		const int ba = pqcp_fleet_cbor_compare_encoded_keys(
			in + half, len - half, in, half);

		REQUIRE(ab == -ba, "compare_encoded_keys not antisymmetric");
		REQUIRE(pqcp_fleet_cbor_compare_encoded_keys(
				in, len, in, len) == 0,
			"compare_encoded_keys not reflexive");
	}

	/* Invalid input must never be splicable into deterministic output. */
	{
		uint8_t *out = exact_alloc(len);
		struct pqcp_fleet_cbor_writer writer;
		size_t olen = 0U;
		int ret;

		memset(out, 0xA5, len);
		pqcp_fleet_cbor_writer_init(&writer, out, len);
		ret = pqcp_fleet_cbor_write_encoded(&writer, in, len);
		if (valid != 0) {
			REQUIRE(ret != 0, "write_encoded accepted invalid CBOR");
			REQUIRE(writer.offset == 0U,
				"write_encoded advanced on rejection");
			for (size_t i = 0U; i < len; ++i) {
				REQUIRE(out[i] == 0xA5U,
					"write_encoded wrote on rejection");
			}
		} else {
			REQUIRE(ret == 0, "write_encoded rejected valid CBOR");
			REQUIRE(pqcp_fleet_cbor_writer_finish(&writer,
							       &olen) == 0 &&
					olen == len &&
					memcmp(out, in, len) == 0,
				"write_encoded changed the item");
		}
		free(out);
	}

	if (valid != 0) {
		/* Skipper on invalid input must stay in bounds. */
		pqcp_fleet_cbor_reader_init(&reader, in, len);
		(void)pqcp_fleet_cbor_skip(&reader);
		REQUIRE(reader.offset <= len, "skip ran past the input");
		check_cbor_container(in, len);
		return;
	}

	/* Valid canonical CBOR: the skipper consumes exactly the item. */
	accepted[T_CBOR]++;
	pqcp_fleet_cbor_reader_init(&reader, in, len);
	REQUIRE(pqcp_fleet_cbor_skip(&reader) == 0 && reader.offset == len,
		"skip disagrees with validate");
	REQUIRE(pqcp_fleet_cbor_reader_finish(&reader) == 0,
		"valid item leaves trailing bytes");
	check_cbor_container(in, len);

	/* decode(encode(x)) == x: re-encode through the typed reader/writer
	 * pair into an exact-size buffer; one byte less must be refused.
	 */
	{
		uint8_t *out = exact_alloc(len);
		struct pqcp_fleet_cbor_writer writer;
		size_t olen = 0U;
		int ret;

		pqcp_fleet_cbor_reader_init(&reader, in, len);
		pqcp_fleet_cbor_writer_init(&writer, out, len);
		ret = reencode_item(&reader, &writer, 0U);
		if (ret != REENCODE_UNREPRESENTABLE) {
			REQUIRE(ret == 0, "typed re-encode of valid CBOR failed");
			REQUIRE(pqcp_fleet_cbor_writer_finish(&writer,
							       &olen) == 0 &&
					olen == len &&
					memcmp(out, in, len) == 0,
				"CBOR round trip is not byte-identical");
			if (len > 1U) {
				uint8_t *small = exact_alloc(len - 1U);

				pqcp_fleet_cbor_reader_init(&reader, in, len);
				pqcp_fleet_cbor_writer_init(&writer, small,
							    len - 1U);
				ret = reencode_item(&reader, &writer, 0U);
				REQUIRE(ret == PQCP_FLEET_COSE_ERR_CAPACITY,
					"writer overflowed its capacity");
				free(small);
			}
		}
		free(out);
	}
}

/* ------------------------------------------------------------------ */
/* Target: COSE_Sign1 and protected headers                             */
/* ------------------------------------------------------------------ */

static const uint8_t aad_bytes[3] = { 'a', 'b', 'c' };
static const uint8_t detached_bytes[16] = {
	'd', 'e', 't', 'a', 'c', 'h', 'e', 'd',
	'p', 'a', 'y', 'l', 'o', 'a', 'd', '!',
};

static bool headers_all_zero_or_canary(const void *h, size_t n)
{
	const uint8_t *p = h;
	bool zero = true;
	bool canary = true;

	for (size_t i = 0U; i < n; ++i) {
		zero = zero && p[i] == 0U;
		canary = canary && p[i] == 0xA5U;
	}
	return zero || canary;
}

static void check_protected(const uint8_t *in, size_t len)
{
	struct pqcp_fleet_cose_headers headers;
	int ret;

	memset(&headers, 0xA5, sizeof(headers));
	ret = pqcp_fleet_cose_protected_decode(in, len, &headers);
	if (ret != 0) {
		REQUIRE(headers_all_zero_or_canary(&headers, sizeof(headers)),
			"protected_decode left partial headers on rejection");
		return;
	}
	REQUIRE(pqcp_fleet_cose_headers_validate(&headers, true) == 0,
		"decoded protected headers fail validation");
	{
		uint8_t *out = exact_alloc(len);
		size_t olen = 0U;

		REQUIRE(pqcp_fleet_cose_protected_encode(&headers, out, len,
							  &olen) == 0 &&
				olen == len && memcmp(out, in, len) == 0,
			"protected header round trip is not byte-identical");
		free(out);
		if (len > 1U) {
			out = exact_alloc(len - 1U);
			REQUIRE(pqcp_fleet_cose_protected_encode(
					&headers, out, len - 1U, &olen) ==
					PQCP_FLEET_COSE_ERR_CAPACITY,
				"protected_encode overflowed its capacity");
			free(out);
		}
	}
}

static void check_sig_structure(const uint8_t *in, size_t len)
{
	const size_t half = len / 2U;
	const size_t cap = 24U + len + sizeof(aad_bytes);
	uint8_t *out = exact_alloc(cap);
	size_t olen = 0U;
	int ret;

	ret = pqcp_fleet_cose_sig_structure(in, half, aad_bytes,
					    sizeof(aad_bytes), in + half,
					    len - half, out, cap, &olen);
	if (ret == 0) {
		REQUIRE(olen <= cap, "sig_structure exceeded capacity");
		REQUIRE(pqcp_fleet_cbor_validate(out, olen) == 0,
			"sig_structure is not valid CBOR");
		free(out);
		out = exact_alloc(olen > 1U ? olen - 1U : 1U);
		REQUIRE(pqcp_fleet_cose_sig_structure(
				in, half, aad_bytes, sizeof(aad_bytes),
				in + half, len - half, out,
				olen > 1U ? olen - 1U : 0U, &olen) ==
				PQCP_FLEET_COSE_ERR_CAPACITY,
			"sig_structure overflowed its capacity");
	}
	free(out);
}

static void fuzz_cose_sign1(const uint8_t *in, size_t len)
{
	struct pqcp_fleet_cose_sign1 message;
	struct pqcp_fleet_cose_sign1 again;
	struct mock_crypto mock = { .accept = true };
	struct pqcp_fleet_cose_crypto crypto = {
		.context = &mock, .sign = mock_sign, .verify = mock_verify,
		.hash = mock_hash,
	};
	const size_t caps[5] = { 0U, 16U, 300U, len + 96U, 3U * len + 8192U };
	size_t ws_cap = caps[rng_below(5U)];
	uint8_t *ws;
	int dret;
	int vret;

	if (len == 0U) {
		memset(&message, 0xA5, sizeof(message));
		REQUIRE(pqcp_fleet_cose_sign1_decode(in, 0U, &message) ==
				PQCP_FLEET_COSE_ERR_ARGUMENT,
			"empty COSE_Sign1 not an argument error");
		return;
	}

	check_protected(in, len);
	check_sig_structure(in, len);

	memset(&message, 0xA5, sizeof(message));
	dret = pqcp_fleet_cose_sign1_decode(in, len, &message);
	if (dret != 0) {
		/* Rejected: nothing in the output may point outside the
		 * input, and the destination must not carry a half-built
		 * message that a careless caller could mistake for valid.
		 */
		REQUIRE(slice_inside(&message.protected_serialized, in, len) &&
				slice_inside(&message.payload, in, len) &&
				slice_inside(&message.signature, in, len),
			"rejected COSE_Sign1 output escapes the input");
		REQUIRE(bytes_zero(&message, sizeof(message)),
			"rejected COSE_Sign1 left a partially decoded message");
	} else {
		uint8_t *out = exact_alloc(len);
		size_t olen = 0U;

		accepted[T_COSE_SIGN1]++;
		REQUIRE(slice_inside(&message.protected_serialized, in, len) &&
				slice_inside(&message.payload, in, len) &&
				slice_inside(&message.signature, in, len),
			"decoded COSE_Sign1 slice escapes the input");
		REQUIRE(message.signature.length ==
				pqcp_fleet_cose_algorithm_signature_bytes(
					message.protected_headers.algorithm),
			"signature length does not match algorithm");
		REQUIRE(pqcp_fleet_cose_headers_validate(
				&message.protected_headers, true) == 0 &&
				pqcp_fleet_cose_headers_validate(
					&message.unprotected_headers, false) == 0,
			"decoded COSE headers fail validation");
		REQUIRE(pqcp_fleet_cose_sign1_encode(&message, out, len,
						      &olen) == 0 &&
				olen == len && memcmp(out, in, len) == 0,
			"COSE_Sign1 round trip is not byte-identical");
		free(out);
		if (len > 1U) {
			out = exact_alloc(len - 1U);
			REQUIRE(pqcp_fleet_cose_sign1_encode(
					&message, out, len - 1U, &olen) ==
					PQCP_FLEET_COSE_ERR_CAPACITY,
				"sign1_encode overflowed its capacity");
			free(out);
		}
	}

	/* verify(): exactly one crypto call, and only for decodable input. */
	for (unsigned accept = 0U; accept < 2U; ++accept) {
		const bool detached = dret == 0 && message.detached_payload;

		mock.accept = accept != 0U;
		mock.verify_calls = 0U;
		ws = exact_alloc(ws_cap);
		memset(&again, 0xA5, sizeof(again));
		vret = pqcp_fleet_cose_sign1_verify(
			in, len, detached ? detached_bytes : NULL,
			detached ? sizeof(detached_bytes) : 0U, aad_bytes,
			sizeof(aad_bytes), &crypto, ws, ws_cap, &again);
		if (dret != 0) {
			REQUIRE(vret == dret && mock.verify_calls == 0U,
				"verify disagrees with decode on a bad token");
		} else if (vret == 0) {
			REQUIRE(mock.accept && mock.verify_calls == 1U,
				"verify accepted without the crypto callback");
		} else if (mock.verify_calls == 1U) {
			REQUIRE(vret == PQCP_FLEET_COSE_ERR_SIGNATURE,
				"rejected signature not reported as such");
		} else {
			REQUIRE(mock.verify_calls == 0U &&
					vret != PQCP_FLEET_COSE_ERR_SIGNATURE,
				"verify failure ambiguity");
		}
		if (dret == 0 && vret == 0) {
			REQUIRE(again.payload.data == message.payload.data &&
					again.signature.data ==
						message.signature.data &&
					again.detached_payload ==
						message.detached_payload,
				"verify decoded a different message");
		}
		free(ws);
	}

	if (dret == 0) {
		/* Payload placement rules. */
		mock.accept = true;
		mock.verify_calls = 0U;
		ws_cap = 3U * len + 8192U;
		ws = exact_alloc(ws_cap);
		if (message.detached_payload) {
			vret = pqcp_fleet_cose_sign1_verify(
				in, len, NULL, 0U, NULL, 0U, &crypto, ws,
				ws_cap, &again);
			REQUIRE(vret == PQCP_FLEET_COSE_ERR_REQUIRED &&
					mock.verify_calls == 0U,
				"detached token verified without payload");
		} else {
			vret = pqcp_fleet_cose_sign1_verify(
				in, len, detached_bytes,
				sizeof(detached_bytes), NULL, 0U, &crypto, ws,
				ws_cap, &again);
			REQUIRE(vret == PQCP_FLEET_COSE_ERR_POLICY &&
					mock.verify_calls == 0U,
				"attached token accepted a detached payload");
		}
		free(ws);
	}
}

/* ------------------------------------------------------------------ */
/* Target: COSE_Key                                                     */
/* ------------------------------------------------------------------ */

static void fuzz_cose_key(const uint8_t *in, size_t len)
{
	struct pqcp_fleet_cose_crypto crypto = {
		.context = NULL, .sign = mock_sign, .verify = mock_verify,
		.hash = mock_hash,
	};

	for (unsigned allow = 0U; allow < 2U; ++allow) {
		struct pqcp_fleet_cose_key key;
		struct pqcp_fleet_cose_key again;
		int ret;

		memset(&key, 0xA5, sizeof(key));
		ret = pqcp_fleet_cose_key_decode(in, len, allow != 0U, &key);
		if (len == 0U) {
			REQUIRE(ret == PQCP_FLEET_COSE_ERR_ARGUMENT,
				"empty COSE_Key not an argument error");
			continue;
		}
		if (ret != 0) {
			REQUIRE(bytes_zero(&key, sizeof(key)),
				"rejected COSE_Key left key material in output");
			continue;
		}
		accepted[T_COSE_KEY]++;
		REQUIRE(pqcp_fleet_cose_key_validate(&key, allow != 0U) == 0,
			"decoded COSE_Key fails validation");
		{
			const bool priv = key.private_seed_length != 0U;
			uint8_t *out = exact_alloc(len);
			size_t olen = 0U;

			REQUIRE(pqcp_fleet_cose_key_encode(&key, priv, out,
							    len, &olen) == 0 &&
					olen == len &&
					memcmp(out, in, len) == 0,
				"COSE_Key round trip is not byte-identical");
			free(out);
			if (len > 1U) {
				out = exact_alloc(len - 1U);
				REQUIRE(pqcp_fleet_cose_key_encode(
						&key, priv, out, len - 1U,
						&olen) ==
						PQCP_FLEET_COSE_ERR_CAPACITY,
					"key_encode overflowed its capacity");
				free(out);
			}
			if (priv) {
				/* Public-only export must drop the seed. */
				out = exact_alloc(len);
				if (pqcp_fleet_cose_key_encode(
					    &key, false, out, len, &olen) == 0) {
					REQUIRE(olen < len,
						"public export did not shrink");
					REQUIRE(pqcp_fleet_cose_key_decode(
							out, olen, false,
							&again) == 0 &&
							again.private_seed_length ==
								0U,
						"public export still carries a seed");
				}
				free(out);
			}
		}
		{
			uint8_t thumb[PQCP_FLEET_COSE_THUMBPRINT_BYTES];
			uint8_t *tin = exact_alloc(
				PQCP_FLEET_COSE_MAX_PUBLIC_KEY_BYTES + 64U);
			size_t tlen = 0U;

			REQUIRE(pqcp_fleet_cose_key_thumbprint(&key, &crypto,
								thumb) == 0,
				"thumbprint of a valid key failed");
			REQUIRE(pqcp_fleet_cose_key_thumbprint_input(
					&key, tin,
					PQCP_FLEET_COSE_MAX_PUBLIC_KEY_BYTES +
						64U,
					&tlen) == 0 &&
					pqcp_fleet_cbor_validate(tin, tlen) == 0,
				"thumbprint input is not valid CBOR");
			free(tin);
		}
	}
}

/* ------------------------------------------------------------------ */
/* Target: policy module codec, verifier and VM                         */
/* ------------------------------------------------------------------ */

static int claim_load(void *context, uint32_t claim_id,
		      struct pqcp_fleet_policy_value *value)
{
	(void)context;
	if (claim_id % 7U == 0U) {
		return -1;
	}
	memset(value, 0, sizeof(*value));
	value->type = PQCP_FLEET_POLICY_VALUE_I64;
	value->as.i64 = (int64_t)claim_id * 3 - 5;
	return 0;
}

static void run_policy_vm(const struct pqcp_fleet_policy_module *module)
{
	const struct pqcp_fleet_policy_claim_source claims = {
		.load = claim_load, .context = NULL,
	};
	const struct pqcp_fleet_policy_execution_context context = {
		.claims = &claims, .builtins = NULL,
		.builtin_state = NULL, .application_context = NULL,
		.instruction_limit = 2000U, .flags = 0U,
	};
	struct pqcp_fleet_policy_vm_workspace workspace;
	struct pqcp_fleet_policy_execution_result result;
	const size_t stack_n = module->bounds.max_stack_values;
	const size_t frame_n = module->bounds.max_call_frames;
	const size_t local_n = module->bounds.max_local_values;
	const size_t action_n = module->bounds.max_actions;
	int ret;

	if (stack_n > 512U || frame_n > 64U || local_n > 512U ||
	    action_n > 16U) {
		return;
	}
	workspace.stack = malloc((stack_n != 0U ? stack_n : 1U) *
				 sizeof(*workspace.stack));
	workspace.stack_capacity = stack_n;
	workspace.frames = malloc((frame_n != 0U ? frame_n : 1U) *
				  sizeof(*workspace.frames));
	workspace.frame_capacity = frame_n;
	workspace.locals = local_n != 0U ?
		malloc(local_n * sizeof(*workspace.locals)) : NULL;
	workspace.local_capacity = local_n;
	memset(&result, 0, sizeof(result));
	result.actions = action_n != 0U ?
		malloc(action_n * sizeof(*result.actions)) : NULL;
	result.action_capacity = action_n;
	if (workspace.stack == NULL || workspace.frames == NULL ||
	    (local_n != 0U && workspace.locals == NULL) ||
	    (action_n != 0U && result.actions == NULL)) {
		abort();
	}

	ret = pqcp_fleet_policy_vm_execute(module, &context, &workspace,
					   &result);
	REQUIRE(result.status == ret, "VM result status differs from return");
	if (ret == 0) {
		policy_vm_decided++;
		REQUIRE(result.decision.outcome <=
				PQCP_FLEET_POLICY_DECISION_DEFER &&
				result.action_count <= action_n &&
				result.instructions_executed <=
					module->bounds.instruction_budget &&
				result.maximum_stack_depth <= stack_n,
			"VM success result out of bounds");
	} else {
		REQUIRE(result.decision.outcome ==
				PQCP_FLEET_POLICY_DECISION_DENY &&
				result.decision.reason_code ==
					PQCP_FLEET_POLICY_REASON_VM_FAULT &&
				result.action_count == 0U,
			"VM fault did not fail closed");
		/* The verifier guarantees structure; only data-dependent
		 * faults may remain.
		 */
		REQUIRE(ret != PQCP_FLEET_POLICY_ERR_BAD_OPCODE &&
				ret != PQCP_FLEET_POLICY_ERR_BAD_OPERAND &&
				ret != PQCP_FLEET_POLICY_ERR_STACK &&
				ret != PQCP_FLEET_POLICY_ERR_CALL_DEPTH &&
				ret != PQCP_FLEET_POLICY_ERR_CONTROL_FLOW &&
				ret != PQCP_FLEET_POLICY_ERR_BAD_MODULE &&
				ret != PQCP_FLEET_POLICY_ERR_INVALID_ARGUMENT,
			"verified module faulted structurally in the VM");
	}
	free(workspace.stack);
	free(workspace.frames);
	free(workspace.locals);
	free(result.actions);
}

static void run_policy_verify(const struct pqcp_fleet_policy_module *module)
{
	const size_t ic = module->instruction_count;
	const size_t fc = module->function_count;
	struct pqcp_fleet_policy_verify_workspace ws;
	struct pqcp_fleet_policy_verify_report report;
	int ret;

	ws.stack_depths = malloc(ic * sizeof(int32_t));
	ws.path_flags = malloc(ic);
	ws.instruction_queue = malloc(ic * sizeof(uint32_t));
	ws.instruction_capacity = ic;
	ws.function_marks = malloc(fc);
	ws.function_depths = malloc(fc * sizeof(uint16_t));
	ws.function_stack_peaks = malloc(fc * sizeof(uint32_t));
	ws.function_local_peaks = malloc(fc * sizeof(uint32_t));
	ws.function_stack = malloc(fc * sizeof(uint32_t));
	ws.function_cursors = malloc(fc * sizeof(uint32_t));
	ws.function_capacity = fc;
	if (ws.stack_depths == NULL || ws.path_flags == NULL ||
	    ws.instruction_queue == NULL || ws.function_marks == NULL ||
	    ws.function_depths == NULL || ws.function_stack_peaks == NULL ||
	    ws.function_local_peaks == NULL || ws.function_stack == NULL ||
	    ws.function_cursors == NULL) {
		abort();
	}
	memset(&report, 0xA5, sizeof(report));
	ret = pqcp_fleet_policy_module_verify(module, &ws, &report);
	REQUIRE(report.status == ret, "verify report status differs");
	if (ret == 0) {
		REQUIRE(report.reachable_instructions <= ic,
			"verify reachable count exceeds the module");
		policy_verified++;
		run_policy_vm(module);
	}
	free(ws.stack_depths);
	free(ws.path_flags);
	free(ws.instruction_queue);
	free(ws.function_marks);
	free(ws.function_depths);
	free(ws.function_stack_peaks);
	free(ws.function_local_peaks);
	free(ws.function_stack);
	free(ws.function_cursors);
}

static void fuzz_policy(const uint8_t *in, size_t len)
{
	struct pqcp_fleet_policy_codec_storage storage;
	struct pqcp_fleet_policy_codec_result result;
	struct pqcp_fleet_policy_module module;
	struct pqcp_fleet_policy_module before;
	uint32_t ic = 0U;
	uint32_t cc = 0U;
	uint32_t fc = 0U;
	bool fit;
	int ret;

	if (len >= 44U) {
		ic = be32(in + 32U);
		cc = be32(in + 36U);
		fc = be32(in + 40U);
	}
	fit = ic <= 512U && cc <= 128U && fc <= 32U;

	memset(&storage, 0, sizeof(storage));
	if (fit) {
		storage.instructions = malloc((ic != 0U ? ic : 1U) *
					      sizeof(*storage.instructions));
		storage.instruction_capacity = ic;
		storage.constants = malloc((cc != 0U ? cc : 1U) *
					   sizeof(*storage.constants));
		storage.constant_capacity = cc;
		storage.functions = malloc((fc != 0U ? fc : 1U) *
					   sizeof(*storage.functions));
		storage.function_capacity = fc;
		if (storage.instructions == NULL || storage.constants == NULL ||
		    storage.functions == NULL) {
			abort();
		}
	}

	memset(&module, 0xA5, sizeof(module));
	before = module;
	memset(&result, 0x5A, sizeof(result));
	ret = pqcp_fleet_policy_module_decode(in, len, &storage, &module,
					      &result);
	if (ret != 0) {
		REQUIRE(memcmp(&module, &before, sizeof(module)) == 0,
			"rejected policy module overwrote the output");
		REQUIRE(result.status == ret, "codec result status differs");
	} else {
		uint8_t digest[32];
		uint8_t *out = exact_alloc(len);
		size_t esize = 0U;
		struct pqcp_fleet_policy_codec_result eres;

		accepted[T_POLICY]++;
		REQUIRE(result.status == 0 && result.bytes_consumed == len,
			"policy decode result inconsistent");
		REQUIRE(module.instruction_count == ic &&
				module.constant_count == cc &&
				module.function_count == fc,
			"policy decode counts drift from the header");
		REQUIRE(pqcp_fleet_policy_module_encoded_size(
				&module, &esize) == 0 && esize == len,
			"policy encoded_size differs from the input size");
		REQUIRE(pqcp_fleet_policy_module_encode(&module, out, len,
							 &eres) == 0 &&
				eres.bytes_produced == len &&
				memcmp(out, in, len) == 0,
			"policy round trip is not byte-identical");
		free(out);
		if (len > 1U) {
			out = exact_alloc(len - 1U);
			REQUIRE(pqcp_fleet_policy_module_encode(
					&module, out, len - 1U, &eres) ==
					PQCP_FLEET_POLICY_ERR_CAPACITY,
				"policy encode overflowed its capacity");
			free(out);
		}
		REQUIRE(pqcp_fleet_policy_module_digest(&module, digest) == 0 &&
				memcmp(digest, module.digest, 32U) == 0,
			"policy digest differs from the wire digest");

		/* One slot short on each array must be refused, untouched. */
		if (ic > 0U) {
			struct pqcp_fleet_policy_codec_storage tight = storage;

			tight.instruction_capacity = ic - 1U;
			memset(&module, 0xA5, sizeof(module));
			REQUIRE(pqcp_fleet_policy_module_decode(
					in, len, &tight, &module, &result) ==
					PQCP_FLEET_POLICY_ERR_CAPACITY &&
					memcmp(&module, &before,
					       sizeof(module)) == 0,
				"undersized storage was not refused cleanly");
		}
		if (cc > 0U) {
			struct pqcp_fleet_policy_codec_storage tight = storage;

			tight.constant_capacity = cc - 1U;
			memset(&module, 0xA5, sizeof(module));
			REQUIRE(pqcp_fleet_policy_module_decode(
					in, len, &tight, &module, &result) ==
					PQCP_FLEET_POLICY_ERR_CAPACITY &&
					memcmp(&module, &before,
					       sizeof(module)) == 0,
				"undersized constants not refused cleanly");
		}
		/* Re-decode for the verifier/VM (module was clobbered above
		 * when a tight decode ran).
		 */
		REQUIRE(pqcp_fleet_policy_module_decode(in, len, &storage,
							 &module, &result) == 0,
			"policy re-decode failed");
		run_policy_verify(&module);
	}
	free(storage.instructions);
	free(storage.constants);
	free(storage.functions);
}

/* ------------------------------------------------------------------ */
/* Dispatch                                                             */
/* ------------------------------------------------------------------ */

static void exercise(unsigned target, const uint8_t *data, size_t length)
{
	uint8_t *exact = exact_alloc(length);

	if (length != 0U) {
		memcpy(exact, data, length);
	}
	current_input = exact;
	current_length = length;
	current_target = target;
	switch (target) {
	case T_CBOR:
		fuzz_cbor(exact, length);
		break;
	case T_COSE_SIGN1:
		fuzz_cose_sign1(exact, length);
		break;
	case T_COSE_KEY:
		fuzz_cose_key(exact, length);
		break;
	case T_POLICY:
	default:
		fuzz_policy(exact, length);
		break;
	}
	free(exact);
	current_input = NULL;
	current_length = 0U;
}

/* ------------------------------------------------------------------ */
/* Seed corpus                                                          */
/* ------------------------------------------------------------------ */

static int add_seed(unsigned target, const uint8_t *data, size_t length)
{
	if (bin_count >= BIN_CORPUS_MAX || length > BIN_MAX - 1U) {
		fprintf(stderr, "pqcp-evidence-fuzz: seed does not fit\n");
		return -1;
	}
	memcpy(bin_corpus[bin_count], data, length);
	bin_lengths[bin_count] = length;
	bin_tags[bin_count] = (uint8_t)target;
	bin_count++;
	return 0;
}

static int hex_seed(unsigned target, const char *hex)
{
	uint8_t bytes[256];
	size_t n = 0U;

	for (; hex[0] != '\0' && hex[1] != '\0'; hex += 2) {
		unsigned v;

		if (sscanf(hex, "%2x", &v) != 1 || n >= sizeof(bytes)) {
			return -1;
		}
		bytes[n++] = (uint8_t)v;
	}
	return add_seed(target, bytes, n);
}

static const char *const cbor_hex_seeds[] = {
	/* RFC 8949 Appendix A integers, strings, containers, tags. */
	"00", "01", "17", "1818", "1819", "1864", "1903e8", "1a000f4240",
	"1b000000e8d4a51000", "1bffffffffffffffff", "20", "29", "3863",
	"3903e7", "3bffffffffffffffff", "40", "4401020304", "60", "6161",
	"6449455446", "62225c", "80", "83010203", "8301820203820405",
	"a0", "a201020304", "a26161016162820203", "a56161614161626142616361"
	"43616461446165614561",
	"c11a514b67b0", "d82076687474703a2f2f7777772e6578616d706c652e636f6d",
	"f4", "f5", "f6", "d28449a1013822a054546869732069732074686520636f6e74"
	"656e742e58",
	/* Map keyed by ints in canonical order (negative after positive). */
	"a40102020303042001",
	/* Non-canonical / invalid shapes the validator must refuse. */
	"1800", "1a00000001", "1b0000000000000001", "5f4101ff", "9f01ff",
	"bf6161 01ff", "f7", "f8ff", "fb3ff0000000000000", "a2020101 02",
	"a201020102", "a2616101616201", "ff", "1c", "5a00ffffff",
	"9bffffffffffffffff",
};

static int seed_cbor(void)
{
	uint8_t buf[512];
	struct pqcp_fleet_cbor_writer w;
	size_t n;

	for (size_t i = 0U;
	     i < sizeof(cbor_hex_seeds) / sizeof(cbor_hex_seeds[0]); ++i) {
		char compact[160];
		size_t k = 0U;

		for (const char *s = cbor_hex_seeds[i]; *s != '\0'; ++s) {
			if (*s != ' ' && k + 1U < sizeof(compact)) {
				compact[k++] = *s;
			}
		}
		compact[k] = '\0';
		if (hex_seed(T_CBOR, compact) != 0) {
			return -1;
		}
	}

	/* Writer-produced documents: nesting, every major type, tags. */
	pqcp_fleet_cbor_writer_init(&w, buf, sizeof(buf));
	(void)pqcp_fleet_cbor_write_tag(&w, 55799U);
	(void)pqcp_fleet_cbor_write_map(&w, 5U);
	(void)pqcp_fleet_cbor_write_int(&w, 1);
	(void)pqcp_fleet_cbor_write_text(&w, "fleet", 5U);
	(void)pqcp_fleet_cbor_write_int(&w, 2);
	(void)pqcp_fleet_cbor_write_array(&w, 5U);
	(void)pqcp_fleet_cbor_write_uint(&w, UINT64_MAX);
	(void)pqcp_fleet_cbor_write_int(&w, INT64_MIN);
	(void)pqcp_fleet_cbor_write_bool(&w, true);
	(void)pqcp_fleet_cbor_write_null(&w);
	(void)pqcp_fleet_cbor_write_bytes(&w, (const uint8_t *)"\x01\x02", 2U);
	(void)pqcp_fleet_cbor_write_int(&w, 3);
	(void)pqcp_fleet_cbor_write_map(&w, 1U);
	(void)pqcp_fleet_cbor_write_int(&w, 10);
	(void)pqcp_fleet_cbor_write_array(&w, 0U);
	(void)pqcp_fleet_cbor_write_int(&w, 4);
	(void)pqcp_fleet_cbor_write_tag(&w, 24U);
	(void)pqcp_fleet_cbor_write_bytes(&w, (const uint8_t *)"\xa0", 1U);
	(void)pqcp_fleet_cbor_write_int(&w, -1);
	(void)pqcp_fleet_cbor_write_bool(&w, false);
	if (pqcp_fleet_cbor_writer_finish(&w, &n) != 0 ||
	    pqcp_fleet_cbor_validate(buf, n) != 0 ||
	    add_seed(T_CBOR, buf, n) != 0) {
		fprintf(stderr, "pqcp-evidence-fuzz: CBOR seed failed\n");
		return -1;
	}
	return 0;
}

/* Build a COSE_Sign1 token with the real signer and mock crypto. */
static int make_sign1(int32_t alg, bool tagged, bool unprot_kid,
		      int ctype, const uint8_t *payload, size_t payload_len,
		      bool detached, uint8_t *out, size_t cap, size_t *olen)
{
	static uint8_t ws[16384];
	struct mock_crypto mock = { .accept = true };
	struct pqcp_fleet_cose_crypto crypto = {
		.context = &mock, .sign = mock_sign, .verify = mock_verify,
		.hash = mock_hash,
	};
	struct pqcp_fleet_cose_headers prot;
	struct pqcp_fleet_cose_headers unprot;
	struct pqcp_fleet_cose_sign1 decoded;
	int ret;

	memset(&prot, 0, sizeof(prot));
	memset(&unprot, 0, sizeof(unprot));
	prot.algorithm = alg;
	prot.tagged = tagged;
	if (ctype == 1) {
		prot.content_type_kind = PQCP_FLEET_COSE_CONTENT_TYPE_TEXT;
		memcpy(prot.content_type_text, "application/pqcp-fleet", 22U);
		prot.critical[0] = PQCP_FLEET_COSE_HEADER_ALG;
		prot.critical[1] = PQCP_FLEET_COSE_HEADER_CONTENT_TYPE;
		prot.critical_count = 2U;
	} else if (ctype == 2) {
		unprot.content_type_kind =
			PQCP_FLEET_COSE_CONTENT_TYPE_INTEGER;
		unprot.content_type_integer = 50;
	}
	if (unprot_kid) {
		memcpy(unprot.kid, "node-unprotected", 16U);
		unprot.kid_length = 16U;
	} else {
		memcpy(prot.kid, "fleet-k1", 8U);
		prot.kid_length = 8U;
	}
	ret = pqcp_fleet_cose_sign1_sign(&prot, &unprot, payload,
					 payload_len, NULL, 0U, &crypto, ws,
					 sizeof(ws), out, cap, olen);
	if (ret != 0 || !detached) {
		return ret;
	}
	ret = pqcp_fleet_cose_sign1_decode(out, *olen, &decoded);
	if (ret != 0) {
		return ret;
	}
	decoded.detached_payload = true;
	decoded.payload.data = NULL;
	decoded.payload.length = 0U;
	{
		/* The decoded slices alias `out`; encode elsewhere first. */
		static uint8_t tmp[BIN_MAX];

		ret = pqcp_fleet_cose_sign1_encode(&decoded, tmp,
						    sizeof(tmp), olen);
		if (ret == 0 && *olen <= cap) {
			memcpy(out, tmp, *olen);
		}
	}
	return ret;
}

static int seed_cose_sign1(void)
{
	static uint8_t buf[BIN_MAX];
	static const uint8_t payload[40] = {
		0xa1, 0x01, 0x02, 'f', 'l', 'e', 'e', 't',
	};
	static const int32_t algs[3] = {
		PQCP_FLEET_COSE_ALG_ML_DSA_44, PQCP_FLEET_COSE_ALG_ML_DSA_65,
		PQCP_FLEET_COSE_ALG_ML_DSA_87,
	};
	size_t n;

	for (unsigned a = 0U; a < 3U; ++a) {
		for (unsigned variant = 0U; variant < 4U; ++variant) {
			const bool tagged = (variant & 1U) == 0U;
			const bool unprot_kid = variant >= 2U;
			const int ctype = (int)((a + variant) % 3U);
			const bool detached = variant == 3U;
			const size_t plen = variant == 1U ? 0U : sizeof(payload);

			if (make_sign1(algs[a], tagged, unprot_kid, ctype,
				       payload, plen, detached, buf,
				       sizeof(buf), &n) != 0) {
				fprintf(stderr,
					"pqcp-evidence-fuzz: COSE_Sign1 seed %u/%u failed\n",
					a, variant);
				return -1;
			}
			if (add_seed(T_COSE_SIGN1, buf, n) != 0) {
				return -1;
			}
		}
	}

	/* Protected-header buckets alone (also fed to the sign1 target). */
	{
		struct pqcp_fleet_cose_headers h;

		memset(&h, 0, sizeof(h));
		h.algorithm = PQCP_FLEET_COSE_ALG_ML_DSA_65;
		h.content_type_kind = PQCP_FLEET_COSE_CONTENT_TYPE_TEXT;
		memcpy(h.content_type_text, "application/cose", 16U);
		memcpy(h.kid, "k", 1U);
		h.kid_length = 1U;
		h.critical[0] = PQCP_FLEET_COSE_HEADER_ALG;
		h.critical_count = 1U;
		if (pqcp_fleet_cose_protected_encode(&h, buf, sizeof(buf),
						      &n) != 0 ||
		    add_seed(T_COSE_SIGN1, buf, n) != 0) {
			return -1;
		}
	}
	return 0;
}

static int seed_cose_key(void)
{
	static const int32_t algs[3] = {
		PQCP_FLEET_COSE_ALG_ML_DSA_44, PQCP_FLEET_COSE_ALG_ML_DSA_65,
		PQCP_FLEET_COSE_ALG_ML_DSA_87,
	};
	static uint8_t buf[BIN_MAX];

	for (unsigned a = 0U; a < 3U; ++a) {
		for (unsigned variant = 0U; variant < 4U; ++variant) {
			struct pqcp_fleet_cose_key key;
			size_t n;
			const bool priv = (variant & 2U) != 0U;

			memset(&key, 0, sizeof(key));
			key.key_type = PQCP_FLEET_COSE_KTY_AKP;
			key.algorithm = algs[a];
			key.tagged = (variant & 1U) != 0U;
			key.public_key_length =
				pqcp_fleet_cose_algorithm_public_key_bytes(
					algs[a]);
			for (size_t i = 0U; i < key.public_key_length; ++i) {
				key.public_key[i] = (uint8_t)(i * 13U + a);
			}
			if (variant != 0U) {
				memcpy(key.kid, "device-key-01", 13U);
				key.kid_length = 13U;
				key.key_operations[0] =
					PQCP_FLEET_COSE_KEY_OP_VERIFY;
				key.key_operation_count = 1U;
			}
			if (priv) {
				key.private_seed_length =
					PQCP_FLEET_COSE_ML_DSA_PRIVATE_SEED_BYTES;
				for (size_t i = 0U;
				     i < key.private_seed_length; ++i) {
					key.private_seed[i] = (uint8_t)(0x40U + i);
				}
				key.key_operations[0] =
					PQCP_FLEET_COSE_KEY_OP_SIGN;
				key.key_operations[1] =
					PQCP_FLEET_COSE_KEY_OP_VERIFY;
				key.key_operation_count = 2U;
			}
			if (pqcp_fleet_cose_key_encode(&key, priv, buf,
							sizeof(buf), &n) != 0 ||
			    add_seed(T_COSE_KEY, buf, n) != 0) {
				fprintf(stderr,
					"pqcp-evidence-fuzz: COSE_Key seed %u/%u failed\n",
					a, variant);
				return -1;
			}
		}
	}
	return 0;
}

static int seed_policy_module(const struct pqcp_fleet_policy_module *module)
{
	static uint8_t buf[BIN_MAX];
	struct pqcp_fleet_policy_codec_result result;

	if (pqcp_fleet_policy_module_encode(module, buf, sizeof(buf),
					    &result) != 0) {
		fprintf(stderr, "pqcp-evidence-fuzz: policy encode failed (%d)\n",
			result.status);
		return -1;
	}
	return add_seed(T_POLICY, buf, result.bytes_produced);
}

#define INSN(op, a_, b_, imm) \
	{ .opcode = (op), .a = (a_), .b = (b_), .immediate = (imm) }

static int seed_policy(void)
{
	static const uint8_t blob[5] = { 1, 2, 3, 4, 5 };
	static const uint8_t dgst[32] = { 0xd1, 0x9e, 0x57 };
	const struct pqcp_fleet_policy_bounds bounds = {
		.instruction_budget = 1000U, .max_stack_values = 8U,
		.max_call_frames = 4U, .max_local_values = 4U,
		.max_actions = 4U, .max_action_arguments = 4U,
	};

	/* 1. Threshold rule: allow when claim 1 exceeds 10. */
	{
		static const struct pqcp_fleet_policy_instruction ins[] = {
			INSN(PQCP_FLEET_POLICY_OP_LOAD_CLAIM, 0, 0, 1),
			INSN(PQCP_FLEET_POLICY_OP_PUSH_I32, 0, 0, 10),
			INSN(PQCP_FLEET_POLICY_OP_GREATER, 0, 0, 0),
			INSN(PQCP_FLEET_POLICY_OP_JUMP_IF_FALSE, 0, 0, 6),
			INSN(PQCP_FLEET_POLICY_OP_EMIT_DECISION,
			     PQCP_FLEET_POLICY_DECISION_ALLOW, 0, 0),
			INSN(PQCP_FLEET_POLICY_OP_HALT, 0, 0, 0),
			INSN(PQCP_FLEET_POLICY_OP_EMIT_DECISION,
			     PQCP_FLEET_POLICY_DECISION_DENY, 0, 0),
			INSN(PQCP_FLEET_POLICY_OP_HALT, 0, 0, 0),
		};
		static const struct pqcp_fleet_policy_function fn[] = {
			{ .first_instruction = 0U, .instruction_count = 8U,
			  .parameter_count = 0U, .local_count = 0U,
			  .result_count = 0U,
			  .flags = PQCP_FLEET_POLICY_FUNCTION_ENTRY },
		};
		const struct pqcp_fleet_policy_module m = {
			.abi_version = PQCP_FLEET_POLICY_ABI_VERSION,
			.bytecode_version = PQCP_FLEET_POLICY_BYTECODE_VERSION,
			.flags = PQCP_FLEET_POLICY_MODULE_CANONICAL,
			.entry_function = 0U, .instructions = ins,
			.instruction_count = 8U, .constants = NULL,
			.constant_count = 0U, .functions = fn,
			.function_count = 1U, .bounds = bounds,
		};

		if (seed_policy_module(&m) != 0) {
			return -1;
		}
	}

	/* 2. Constants of every type, locals, a call, an action. */
	{
		static const struct pqcp_fleet_policy_value consts[] = {
			{ .type = PQCP_FLEET_POLICY_VALUE_I64,
			  .as.i64 = -5 },
			{ .type = PQCP_FLEET_POLICY_VALUE_U64,
			  .as.u64 = UINT64_MAX },
			{ .type = PQCP_FLEET_POLICY_VALUE_BOOL,
			  .as.boolean = true },
			{ .type = PQCP_FLEET_POLICY_VALUE_BYTES,
			  .as.bytes = { blob, sizeof(blob) } },
			{ .type = PQCP_FLEET_POLICY_VALUE_DIGEST,
			  .as.bytes = { dgst, sizeof(dgst) } },
		};
		static const struct pqcp_fleet_policy_instruction ins[] = {
			INSN(PQCP_FLEET_POLICY_OP_PUSH_CONST, 0, 0, 0),
			INSN(PQCP_FLEET_POLICY_OP_PUSH_I32, 0, 0, 3),
			INSN(PQCP_FLEET_POLICY_OP_CALL, 0, 0, 1),
			INSN(PQCP_FLEET_POLICY_OP_STORE_LOCAL, 0, 0, 0),
			INSN(PQCP_FLEET_POLICY_OP_LOAD_LOCAL, 0, 0, 0),
			INSN(PQCP_FLEET_POLICY_OP_PUSH_CONST, 0, 0, 3),
			INSN(PQCP_FLEET_POLICY_OP_EMIT_ACTION, 0, 2, 77),
			INSN(PQCP_FLEET_POLICY_OP_EMIT_DECISION,
			     PQCP_FLEET_POLICY_DECISION_DEFER, 0, 0),
			INSN(PQCP_FLEET_POLICY_OP_HALT, 0, 0, 0),
			INSN(PQCP_FLEET_POLICY_OP_LOAD_LOCAL, 0, 0, 0),
			INSN(PQCP_FLEET_POLICY_OP_LOAD_LOCAL, 0, 0, 1),
			INSN(PQCP_FLEET_POLICY_OP_ADD, 0, 0, 0),
			INSN(PQCP_FLEET_POLICY_OP_RETURN, 0, 0, 0),
		};
		static const struct pqcp_fleet_policy_function fn[] = {
			{ .first_instruction = 0U, .instruction_count = 9U,
			  .parameter_count = 0U, .local_count = 1U,
			  .result_count = 0U,
			  .flags = PQCP_FLEET_POLICY_FUNCTION_ENTRY },
			{ .first_instruction = 9U, .instruction_count = 4U,
			  .parameter_count = 2U, .local_count = 2U,
			  .result_count = 1U, .flags = 0U },
		};
		const struct pqcp_fleet_policy_module m = {
			.abi_version = PQCP_FLEET_POLICY_ABI_VERSION,
			.bytecode_version = PQCP_FLEET_POLICY_BYTECODE_VERSION,
			.flags = PQCP_FLEET_POLICY_MODULE_CANONICAL,
			.entry_function = 0U, .instructions = ins,
			.instruction_count = 13U, .constants = consts,
			.constant_count = 5U, .functions = fn,
			.function_count = 2U, .bounds = bounds,
		};

		if (seed_policy_module(&m) != 0) {
			return -1;
		}
	}

	/* 3. Builtin call, bit/shift/select ops, loop-free branching. */
	{
		static const struct pqcp_fleet_policy_instruction ins[] = {
			INSN(PQCP_FLEET_POLICY_OP_LOAD_CLAIM, 0, 0, 2),
			INSN(PQCP_FLEET_POLICY_OP_PUSH_U32, 0, 0, 3),
			INSN(PQCP_FLEET_POLICY_OP_SHIFT_LEFT, 0, 0, 0),
			INSN(PQCP_FLEET_POLICY_OP_PUSH_I32, 0, 0, 255),
			INSN(PQCP_FLEET_POLICY_OP_BIT_AND, 0, 0, 0),
			INSN(PQCP_FLEET_POLICY_OP_CALL_BUILTIN,
			     PQCP_FLEET_POLICY_VALUE_BOOL, 1, 9),
			INSN(PQCP_FLEET_POLICY_OP_PUSH_I32, 0, 0, 1),
			INSN(PQCP_FLEET_POLICY_OP_PUSH_I32, 0, 0, 2),
			INSN(PQCP_FLEET_POLICY_OP_SELECT, 0, 0, 0),
			INSN(PQCP_FLEET_POLICY_OP_NEG, 0, 0, 0),
			INSN(PQCP_FLEET_POLICY_OP_POP, 0, 0, 0),
			INSN(PQCP_FLEET_POLICY_OP_EMIT_DECISION,
			     PQCP_FLEET_POLICY_DECISION_ALLOW, 0, 0),
			INSN(PQCP_FLEET_POLICY_OP_HALT, 0, 0, 0),
		};
		static const struct pqcp_fleet_policy_function fn[] = {
			{ .first_instruction = 0U, .instruction_count = 13U,
			  .parameter_count = 0U, .local_count = 0U,
			  .result_count = 0U,
			  .flags = PQCP_FLEET_POLICY_FUNCTION_ENTRY },
		};
		const struct pqcp_fleet_policy_module m = {
			.abi_version = PQCP_FLEET_POLICY_ABI_VERSION,
			.bytecode_version = PQCP_FLEET_POLICY_BYTECODE_VERSION,
			.flags = 0U, .entry_function = 0U, .instructions = ins,
			.instruction_count = 13U, .constants = NULL,
			.constant_count = 0U, .functions = fn,
			.function_count = 1U, .bounds = bounds,
		};

		if (seed_policy_module(&m) != 0) {
			return -1;
		}
	}
	return 0;
}

int binary_seed_corpus(void)
{
	bin_count = 0U;
	if (seed_cbor() != 0 || seed_cose_sign1() != 0 ||
	    seed_cose_key() != 0 || seed_policy() != 0) {
		return -1;
	}
	return 0;
}

size_t binary_corpus_size(void)
{
	return bin_count;
}

/* ------------------------------------------------------------------ */
/* Binary mutators and campaign                                         */
/* ------------------------------------------------------------------ */

static const uint8_t interesting_bytes[] = {
	0x00, 0x01, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1f, 0x20, 0x37, 0x38,
	0x40, 0x58, 0x5a, 0x5b, 0x5f, 0x60, 0x7b, 0x7f, 0x80, 0x98, 0x9f,
	0xa0, 0xa1, 0xb8, 0xbf, 0xc0, 0xd8, 0xe0, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xfb, 0xfe, 0xff,
};

static size_t mutate_binary(uint8_t *buf, size_t len, unsigned target)
{
	const uint32_t ops = 1U + rng_below(6U);

	for (uint32_t op = 0U; op < ops; ++op) {
		switch (rng_below(12U)) {
		case 0:
			if (len > 0U) {
				buf[rng_below((uint32_t)len)] ^=
					(uint8_t)(1U << rng_below(8U));
			}
			break;
		case 1:
			if (len > 0U) {
				buf[rng_below((uint32_t)len)] =
					(uint8_t)rng_below(256U);
			}
			break;
		case 2:
			if (len > 0U) {
				buf[rng_below((uint32_t)len)] =
					interesting_bytes[rng_below(
						sizeof(interesting_bytes))];
			}
			break;
		case 3: /* truncate */
			if (len > 0U) {
				len = rng_below((uint32_t)len);
			}
			break;
		case 4: /* delete a span */
			if (len > 1U) {
				const uint32_t start = rng_below((uint32_t)len);
				uint32_t span = 1U + rng_below(
					(uint32_t)(len - start));

				if (start + span > len) {
					span = (uint32_t)(len - start);
				}
				memmove(&buf[start], &buf[start + span],
					len - start - span);
				len -= span;
			}
			break;
		case 5: /* duplicate a span at the end */
			if (len > 0U && len < BIN_MAX - 130U) {
				const uint32_t start = rng_below((uint32_t)len);
				uint32_t span = 1U + rng_below(127U);

				if (start + span > len) {
					span = (uint32_t)(len - start);
				}
				memcpy(&buf[len], &buf[start], span);
				len += span;
			}
			break;
		case 6: /* insert a byte */
			if (len < BIN_MAX - 2U) {
				const uint32_t at = rng_below((uint32_t)len + 1U);

				memmove(&buf[at + 1U], &buf[at], len - at);
				buf[at] = (uint8_t)rng_below(256U);
				len++;
			}
			break;
		case 7: { /* splice with another entry for the same target */
			const uint32_t other = rng_below((uint32_t)bin_count);

			if (bin_tags[other] == target) {
				const size_t cut = rng_below((uint32_t)len + 1U);
				size_t take = rng_below(
					(uint32_t)bin_lengths[other] + 1U);

				if (cut + take >= BIN_MAX) {
					take = BIN_MAX - 1U - cut;
				}
				memcpy(&buf[cut], bin_corpus[other], take);
				len = cut + take;
			}
			break;
		}
		case 8: /* append a run of one byte */
			if (len < BIN_MAX - 2U) {
				uint32_t span = 1U + rng_below(255U);
				const uint8_t fill = (uint8_t)rng_below(256U);

				if (len + span >= BIN_MAX) {
					span = (uint32_t)(BIN_MAX - 1U - len);
				}
				memset(&buf[len], fill, span);
				len += span;
			}
			break;
		case 9: /* insert a CBOR head with a boundary argument */
			if (len < BIN_MAX - 12U) {
				static const uint64_t args[] = {
					0U, 23U, 24U, 255U, 256U, 65535U,
					65536U, 0xffffffffU, 0x100000000ULL,
					0x7fffffffffffffffULL,
					0xffffffffffffffffULL,
				};
				const uint64_t arg = args[rng_below(
					sizeof(args) / sizeof(args[0]))];
				const uint8_t major = (uint8_t)(rng_below(8U) << 5);
				const uint32_t at = rng_below((uint32_t)len + 1U);
				uint8_t head[9];
				size_t hl;

				if (arg < 24U) {
					head[0] = major | (uint8_t)arg;
					hl = 1U;
				} else if (arg <= 0xffU) {
					head[0] = major | 24U;
					head[1] = (uint8_t)arg;
					hl = 2U;
				} else if (arg <= 0xffffU) {
					head[0] = major | 25U;
					head[1] = (uint8_t)(arg >> 8);
					head[2] = (uint8_t)arg;
					hl = 3U;
				} else if (arg <= 0xffffffffU) {
					head[0] = major | 26U;
					for (unsigned i = 0U; i < 4U; ++i) {
						head[1U + i] = (uint8_t)(
							arg >> (24U - 8U * i));
					}
					hl = 5U;
				} else {
					head[0] = major | 27U;
					for (unsigned i = 0U; i < 8U; ++i) {
						head[1U + i] = (uint8_t)(
							arg >> (56U - 8U * i));
					}
					hl = 9U;
				}
				memmove(&buf[at + hl], &buf[at], len - at);
				memcpy(&buf[at], head, hl);
				len += hl;
			}
			break;
		case 10: /* overwrite a big-endian word with a boundary */
			if (len >= 4U) {
				static const uint32_t words[] = {
					0U, 1U, 0x7fffffffU, 0x80000000U,
					0xffffffffU, 0x10000U, 0xffffU, 0x100U,
				};
				const uint32_t at = rng_below((uint32_t)len - 3U);
				const uint32_t v = words[rng_below(
					sizeof(words) / sizeof(words[0]))];

				buf[at] = (uint8_t)(v >> 24);
				buf[at + 1U] = (uint8_t)(v >> 16);
				buf[at + 2U] = (uint8_t)(v >> 8);
				buf[at + 3U] = (uint8_t)v;
			}
			break;
		case 11: /* swap two bytes */
		default:
			if (len > 1U) {
				const uint32_t a = rng_below((uint32_t)len);
				const uint32_t b = rng_below((uint32_t)len);
				const uint8_t t = buf[a];

				buf[a] = buf[b];
				buf[b] = t;
			}
			break;
		}
	}
	if (target == T_POLICY && rng_below(4U) != 0U) {
		policy_fix_digest(buf, len);
	}
	return len;
}

void binary_campaign(unsigned long iterations)
{
	static uint8_t buffer[BIN_MAX];

	/* Regression pass: every seed, unmutated. */
	for (size_t i = 0U; i < bin_count; ++i) {
		exercise(bin_tags[i], bin_corpus[i], bin_lengths[i]);
	}
	for (unsigned long i = 0UL; i < iterations; ++i) {
		const uint32_t pick = rng_below((uint32_t)bin_count);
		const unsigned target = bin_tags[pick];
		size_t len = bin_lengths[pick];

		memcpy(buffer, bin_corpus[pick], len);
		len = mutate_binary(buffer, len, target);
		new_edge_this_run = 0;
		exercise(target, buffer, len);
		if (new_edge_this_run && bin_count < BIN_CORPUS_MAX) {
			memcpy(bin_corpus[bin_count], buffer, len);
			bin_lengths[bin_count] = len;
			bin_tags[bin_count] = (uint8_t)target;
			bin_count++;
		}
	}
}

void binary_print_stats(void)
{
	printf("PQCP_FUZZ BINARY_ACCEPTED cbor=%lu cose_sign1=%lu cose_key=%lu policy=%lu policy_verified=%lu policy_vm_decided=%lu\n",
	       accepted[T_CBOR], accepted[T_COSE_SIGN1], accepted[T_COSE_KEY],
	       accepted[T_POLICY], policy_verified, policy_vm_decided);
}
