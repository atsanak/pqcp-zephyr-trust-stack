/*
 * SPDX-License-Identifier: MIT
 *
 * FIPS 180-4 known-answer tests for host_sha256 plus hash_ops parts[] and
 * incremental-update equivalence.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/host_sha256.h"

static int failures;

static void check_hex(const char *name, const uint8_t *msg, size_t len,
		      const char *expect)
{
	uint8_t digest[32];
	char hex[65];

	host_sha256(msg, len, digest);
	host_sha256_hex(digest, hex);
	if (strcmp(hex, expect) != 0) {
		printf("FAIL %s: got %s want %s\n", name, hex, expect);
		failures++;
	} else {
		printf("ok   %s\n", name);
	}
}

int main(void)
{
	static const char abc[] = "abc";
	static const char two_block[] =
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	static const char long_msg[] =
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
		"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	struct pqcp_fleet_transparency_hash_ops ops;
	struct pqcp_fleet_transparency_part parts[3];
	struct host_sha256_ctx ctx;
	uint8_t d1[32], d2[32];
	uint8_t *million = malloc(1000000U);

	check_hex("empty", (const uint8_t *)"", 0U,
		  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	check_hex("abc", (const uint8_t *)abc, 3U,
		  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	check_hex("448-bit", (const uint8_t *)two_block, strlen(two_block),
		  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
	check_hex("896-bit", (const uint8_t *)long_msg, strlen(long_msg),
		  "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
	if (million == NULL) {
		return 2;
	}
	memset(million, 'a', 1000000U);
	check_hex("one million a", million, 1000000U,
		  "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

	/* Boundary lengths 55/56/63/64/65 against incremental feeding. */
	for (size_t len = 0U; len <= 130U; ++len) {
		host_sha256(million, len, d1);
		host_sha256_init(&ctx);
		for (size_t i = 0U; i < len; ++i) {
			host_sha256_update(&ctx, million + i, 1U);
		}
		host_sha256_final(&ctx, d2);
		if (memcmp(d1, d2, 32U) != 0) {
			printf("FAIL incremental len=%zu\n", len);
			failures++;
		}
	}
	printf("ok   incremental==oneshot for 0..130\n");

	/* hash_ops: parts concatenation equals one-shot over the whole. */
	host_sha256_hash_ops(&ops);
	parts[0] = (struct pqcp_fleet_transparency_part){
		(const uint8_t *)"a", 1U };
	parts[1] = (struct pqcp_fleet_transparency_part){ NULL, 0U };
	parts[2] = (struct pqcp_fleet_transparency_part){
		(const uint8_t *)"bc", 2U };
	if (ops.digest(ops.context, parts, 3U, d1) != 0) {
		printf("FAIL hash_ops error\n");
		failures++;
	}
	host_sha256((const uint8_t *)"abc", 3U, d2);
	if (memcmp(d1, d2, 32U) != 0) {
		printf("FAIL hash_ops parts\n");
		failures++;
	} else {
		printf("ok   hash_ops parts[]\n");
	}
	if (ops.digest(ops.context, NULL, 0U, d1) != 0) {
		failures++;
	}
	host_sha256((const uint8_t *)"", 0U, d2);
	if (memcmp(d1, d2, 32U) != 0) {
		printf("FAIL hash_ops zero parts\n");
		failures++;
	}
	free(million);

	printf("host_sha256 %s failures=%d\n", failures ? "FAIL" : "PASS",
	       failures);
	return failures != 0;
}
