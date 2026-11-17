/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Bounded fleet transparency log and multi-party fleet approval tests.
 *
 * Hash scheme: the implementation is RFC 6962 / RFC 9162 compatible
 * (SHA-256, leaf = H(0x00 || data), node = H(0x01 || left || right), empty
 * tree = H("")), so the public Certificate Transparency reference vectors
 * are used verbatim. Inclusion and consistency proofs are additionally
 * compared byte-for-byte with an independent recursive implementation of the
 * RFC 9162 PATH / SUBPROOF algorithms written in this file and hashed with
 * PSA one-shot SHA-256 (the module under test uses multipart hashing through
 * a callback).
 *
 * Signatures: the module is signer-agnostic. A deterministic keyed mock
 * (SHA-256 over secret, key id, and transcript parts) stands in for ML-DSA;
 * a different secret models a wrong key / attacker signature.
 *
 * All state lives in static storage; every test is deterministic.
 */

#include <errno.h>
#include <string.h>

#include <psa/crypto.h>
#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/errno.h>
#include <pqcp_zephyr/fleet_approval.h>
#include <pqcp_zephyr/fleet_transparency.h>

#define DIG PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES
#define PROOF_MAX PQCP_FLEET_TRANSPARENCY_MAX_PROOF_NODES
#define SIGLEN 32U
#define SIGBUF 64U
#define LOG_CAP 16U
#define NO_FORK ((size_t)1000U)

typedef struct pqcp_fleet_transparency_log tlog_t;
typedef struct pqcp_fleet_transparency_inclusion_proof tinc_t;
typedef struct pqcp_fleet_transparency_consistency_proof tcons_t;
typedef struct pqcp_fleet_transparency_checkpoint tcp_t;
typedef struct pqcp_fleet_transparency_evidence tev_t;
typedef struct pqcp_fleet_transparency_part tpart_t;

#define OK(expr) zassert_equal((expr), 0)
#define EQ(a, b) zassert_equal((a), (b))
#define NZ(expr) zassert_not_equal((expr), 0)

/* ------------------------------------------------------------------ */
/* Hash and signature providers                                        */
/* ------------------------------------------------------------------ */

struct hash_ctx {
	int calls;
	int fail_at;
};

struct sig_ctx {
	uint8_t secret[DIG];
	bool fail_sign;
};

static struct hash_ctx g_hctx = { .fail_at = -1 };
static struct sig_ctx g_sctx;
static struct sig_ctx g_bad_sctx;

static int sha_parts(
	const tpart_t *parts, size_t count, uint8_t out[DIG])
{
	psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
	size_t length = 0U;

	if (psa_hash_setup(&op, PSA_ALG_SHA_256) != PSA_SUCCESS) {
		return -EIO;
	}
	for (size_t i = 0U; i < count; ++i) {
		if (parts[i].length == 0U) {
			continue;
		}
		if (parts[i].data == NULL ||
		    psa_hash_update(&op, parts[i].data,
				    parts[i].length) != PSA_SUCCESS) {
			psa_hash_abort(&op);
			return -EIO;
		}
	}
	if (psa_hash_finish(&op, out, DIG, &length) != PSA_SUCCESS ||
	    length != DIG) {
		psa_hash_abort(&op);
		return -EIO;
	}
	return 0;
}

static int test_digest(
	void *context, const tpart_t *parts, size_t count,
	uint8_t out[DIG])
{
	struct hash_ctx *ctx = context;

	if (ctx != NULL) {
		if (ctx->fail_at >= 0 && ctx->calls == ctx->fail_at) {
			++ctx->calls;
			return -EIO;
		}
		++ctx->calls;
	}
	return sha_parts(parts, count, out);
}

static const struct pqcp_fleet_transparency_hash_ops g_hash = {
	.context = &g_hctx,
	.digest = test_digest,
};

static int mock_mac(
	const struct sig_ctx *ctx, const uint8_t key_id[DIG],
	const tpart_t *parts, size_t count, uint8_t out[DIG])
{
	static const uint8_t tag[] = "MOCKSIG";
	tpart_t all[40];

	if (count + 3U > ARRAY_SIZE(all)) {
		return -E2BIG;
	}
	all[0] = (tpart_t){ .data = tag, .length = sizeof(tag) - 1U };
	all[1] = (tpart_t){ .data = ctx->secret, .length = DIG };
	all[2] = (tpart_t){ .data = key_id, .length = DIG };
	memcpy(&all[3], parts, count * sizeof(parts[0]));
	return sha_parts(all, count + 3U, out);
}

static int mock_sign(
	void *context, const uint8_t key_id[DIG], const tpart_t *parts,
	size_t count, uint8_t *signature, size_t capacity, size_t *length)
{
	struct sig_ctx *ctx = context;

	if (ctx->fail_sign) {
		return -EIO;
	}
	if (capacity < SIGLEN) {
		return -ENOSPC;
	}
	if (mock_mac(ctx, key_id, parts, count, signature) != 0) {
		return -EIO;
	}
	*length = SIGLEN;
	return 0;
}

static int mock_verify(
	void *context, const uint8_t key_id[DIG], const tpart_t *parts,
	size_t count, const uint8_t *signature, size_t length)
{
	struct sig_ctx *ctx = context;
	uint8_t expected[DIG];

	if (length != SIGLEN ||
	    mock_mac(ctx, key_id, parts, count, expected) != 0 ||
	    memcmp(expected, signature, SIGLEN) != 0) {
		return -EKEYREJECTED;
	}
	return 0;
}

static const struct pqcp_fleet_transparency_signature_ops g_sig = {
	.context = &g_sctx,
	.sign = mock_sign,
	.verify = mock_verify,
};

static const struct pqcp_fleet_transparency_signature_ops g_bad_sig = {
	.context = &g_bad_sctx,
	.sign = mock_sign,
	.verify = mock_verify,
};

/* ------------------------------------------------------------------ */
/* Fixture data                                                        */
/* ------------------------------------------------------------------ */

struct leaf_def {
	const uint8_t *data;
	size_t length;
};

static const uint8_t l_empty[1] = { 0 };
static const uint8_t l1[] = { 0x00 };
static const uint8_t l2[] = { 0x10 };
static const uint8_t l3[] = { 0x20, 0x21 };
static const uint8_t l4[] = { 0x30, 0x31 };
static const uint8_t l5[] = { 0x40, 0x41, 0x42, 0x43 };
static const uint8_t l6[] = { 0x50, 0x51, 0x52, 0x53,
			      0x54, 0x55, 0x56, 0x57 };
static const uint8_t l7[] = { 0x60, 0x61, 0x62, 0x63, 0x64, 0x65,
			      0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
			      0x6c, 0x6d, 0x6e, 0x6f };
/* Ninth leaf is project-specific (the RFC set has only eight). */
static const uint8_t l8[] = { 0x70, 0x71, 0x72 };

static const struct leaf_def g_leaves[9] = {
	{ l_empty, 0U }, { l1, sizeof(l1) }, { l2, sizeof(l2) },
	{ l3, sizeof(l3) }, { l4, sizeof(l4) }, { l5, sizeof(l5) },
	{ l6, sizeof(l6) }, { l7, sizeof(l7) }, { l8, sizeof(l8) },
};

#define ALT(i) { 0xEE, (i), 0xEE, 0xEE }
static const uint8_t alt_bytes[16][4] = {
	ALT(0), ALT(1), ALT(2), ALT(3), ALT(4), ALT(5), ALT(6), ALT(7),
	ALT(8), ALT(9), ALT(10), ALT(11), ALT(12), ALT(13), ALT(14),
	ALT(15),
};

/* Roots after 1..8 leaves of the RFC 6962 / CT reference tree. The 7-leaf
 * root was cross-checked with an independent Python SHA-256 implementation
 * of RFC 6962 section 2.1 (it ends in ...c2942b7942a34b77e122c9594a74c8c).
 */
static const char *const rfc_roots[8] = {
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
};
static const char rfc_empty_root[] =
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

static uint8_t g_log_id[DIG];
static uint8_t g_other_log_id[DIG];
static uint8_t g_logkey[DIG];
static uint8_t g_otherkey[DIG];

static uint8_t g_store_a[LOG_CAP][DIG];
static uint8_t g_store_b[LOG_CAP][DIG];
static tlog_t g_log_a;
static tlog_t g_log_b;
static struct pqcp_fleet_transparency_workspace g_ws;

static void fill_id(uint8_t id[DIG], uint8_t tag)
{
	for (size_t i = 0U; i < DIG; ++i) {
		id[i] = (uint8_t)(tag + i);
	}
	id[0] = tag;
}

static void hexbin(const char *hex, uint8_t out[DIG])
{
	zassert_equal(hex2bin(hex, strlen(hex), out, DIG), DIG);
}

static void flip(uint8_t *bytes, size_t index, uint8_t mask)
{
	bytes[index] ^= mask;
}

static void *suite_setup(void)
{
	zassert_equal(psa_crypto_init(), PSA_SUCCESS);
	return NULL;
}

static void before_each(void *fixture)
{
	ARG_UNUSED(fixture);
	g_hctx.calls = 0;
	g_hctx.fail_at = -1;
	memset(g_sctx.secret, 0x5A, sizeof(g_sctx.secret));
	g_sctx.fail_sign = false;
	memset(g_bad_sctx.secret, 0xA5, sizeof(g_bad_sctx.secret));
	g_bad_sctx.fail_sign = false;
	fill_id(g_log_id, 0x10);
	fill_id(g_other_log_id, 0x77);
	fill_id(g_logkey, 0x4C);
	fill_id(g_otherkey, 0x99);
}

/* ------------------------------------------------------------------ */
/* Independent RFC 9162 reference implementation                       */
/* ------------------------------------------------------------------ */

static size_t ref_lpot(size_t n)
{
	size_t p = 1U;

	while ((p << 1U) < n) {
		p <<= 1U;
	}
	return p;
}

static void ref_sha(const uint8_t *in, size_t length, uint8_t out[DIG])
{
	static const uint8_t dummy;
	size_t out_len = 0U;

	zassert_equal(
		psa_hash_compute(PSA_ALG_SHA_256,
				 in != NULL ? in : &dummy, length, out,
				 DIG, &out_len), PSA_SUCCESS);
	zassert_equal(out_len, DIG);
}

static void ref_leaf(const uint8_t *data, size_t length, uint8_t out[DIG])
{
	uint8_t buffer[64];

	zassert_true(length < sizeof(buffer));
	buffer[0] = 0x00;
	if (length != 0U) {
		memcpy(&buffer[1], data, length);
	}
	ref_sha(buffer, length + 1U, out);
}

static void ref_node(
	const uint8_t left[DIG], const uint8_t right[DIG], uint8_t out[DIG])
{
	uint8_t buffer[1U + 2U * DIG];

	buffer[0] = 0x01;
	memcpy(&buffer[1], left, DIG);
	memcpy(&buffer[1U + DIG], right, DIG);
	ref_sha(buffer, sizeof(buffer), out);
}

static void ref_leaf_hashes(
	uint8_t (*lh)[DIG], size_t n, size_t diverge)
{
	for (size_t i = 0U; i < n; ++i) {
		if (i >= diverge) {
			ref_leaf(alt_bytes[i], 4U, lh[i]);
		} else {
			ref_leaf(g_leaves[i].data, g_leaves[i].length,
				 lh[i]);
		}
	}
}

static void ref_mth(const uint8_t (*lh)[DIG], size_t n, uint8_t out[DIG])
{
	uint8_t left[DIG];
	uint8_t right[DIG];
	size_t k;

	if (n == 0U) {
		ref_sha(NULL, 0U, out);
		return;
	}
	if (n == 1U) {
		memcpy(out, lh[0], DIG);
		return;
	}
	k = ref_lpot(n);
	ref_mth(lh, k, left);
	ref_mth(lh + k, n - k, right);
	ref_node(left, right, out);
}

static void ref_path(
	size_t m, const uint8_t (*lh)[DIG], size_t n,
	uint8_t (*nodes)[DIG], size_t *count)
{
	size_t k;

	if (n == 1U) {
		return;
	}
	k = ref_lpot(n);
	if (m < k) {
		ref_path(m, lh, k, nodes, count);
		ref_mth(lh + k, n - k, nodes[*count]);
	} else {
		ref_path(m - k, lh + k, n - k, nodes, count);
		ref_mth(lh, k, nodes[*count]);
	}
	++(*count);
}

static void ref_subproof(
	size_t m, const uint8_t (*lh)[DIG], size_t n, bool b,
	uint8_t (*nodes)[DIG], size_t *count)
{
	size_t k;

	if (m == n) {
		if (!b) {
			ref_mth(lh, n, nodes[*count]);
			++(*count);
		}
		return;
	}
	k = ref_lpot(n);
	if (m <= k) {
		ref_subproof(m, lh, k, b, nodes, count);
		ref_mth(lh + k, n - k, nodes[*count]);
	} else {
		ref_subproof(m - k, lh + k, n - k, false, nodes, count);
		ref_mth(lh, k, nodes[*count]);
	}
	++(*count);
}

/* ------------------------------------------------------------------ */
/* Log helpers                                                         */
/* ------------------------------------------------------------------ */

static void build_log_id(
	tlog_t *log, uint8_t (*store)[DIG], size_t cap, size_t n,
	size_t diverge, const uint8_t *id)
{
	memset(store, 0, cap * DIG);
	OK(pqcp_fleet_transparency_log_init(log, id, store, cap, &g_hash));
	for (size_t i = 0U; i < n; ++i) {
		const uint8_t *data = i >= diverge ? alt_bytes[i] :
			g_leaves[i].data;
		size_t length = i >= diverge ? 4U : g_leaves[i].length;
		uint64_t index = UINT64_MAX;

		OK(pqcp_fleet_transparency_log_append(
			log, data, length, &g_ws, &index));
		EQ(index, i);
	}
	EQ(log->tree_size, n);
}

static void build_log(
	tlog_t *log, uint8_t (*store)[DIG], size_t n, size_t diverge)
{
	build_log_id(log, store, LOG_CAP, n, diverge, g_log_id);
}

static void expect_ref_root(
	const tlog_t *log, size_t n, size_t diverge)
{
	uint8_t lh[16][DIG];
	uint8_t expected[DIG];

	ref_leaf_hashes(lh, n, diverge);
	ref_mth((const uint8_t (*)[DIG])lh, n, expected);
	zassert_mem_equal(log->root, expected, DIG);
}

static void mk_cp(
	tcp_t *cp, uint8_t *sig, const tlog_t *log, uint64_t ts,
	uint64_t seq)
{
	struct pqcp_fleet_transparency_snapshot snap;

	OK(pqcp_fleet_transparency_log_snapshot(log, &snap));
	OK(pqcp_fleet_transparency_checkpoint_sign(
		&snap, ts, seq, g_logkey, &g_hash, &g_sig, sig, SIGBUF, cp));
}

static void expect_log_same(const tlog_t *a, const tlog_t *b)
{
	EQ(a->tree_size, b->tree_size);
	EQ(a->generation, b->generation);
	EQ(a->capacity, b->capacity);
	EQ(a->frontier_mask, b->frontier_mask);
	zassert_mem_equal(a->root, b->root, DIG);
	zassert_mem_equal(a->frontier, b->frontier, sizeof(a->frontier));
	zassert_mem_equal(a->log_id, b->log_id, DIG);
}

static int inc_verify(const tinc_t *proof)
{
	return pqcp_fleet_transparency_inclusion_proof_verify(
		&g_hash, proof);
}

static int cons_verify(const tcons_t *proof)
{
	return pqcp_fleet_transparency_consistency_proof_verify(
		&g_hash, proof);
}

static tinc_t g_inc;
static tinc_t g_inc_work;
static tcons_t g_cons;
static tcons_t g_cons_work;

/* ------------------------------------------------------------------ */
/* Suite 1: Merkle hashing, known answers, bounded log                  */
/* ------------------------------------------------------------------ */

ZTEST_SUITE(fleet_transparency, NULL, suite_setup, before_each, NULL, NULL);

ZTEST(fleet_transparency, test_empty_root_matches_rfc_vector)
{
	uint8_t root[DIG];
	uint8_t expected[DIG];

	hexbin(rfc_empty_root, expected);
	OK(pqcp_fleet_transparency_empty_root(&g_hash, root));
	zassert_mem_equal(root, expected, DIG);
	OK(pqcp_fleet_transparency_root_from_hashes(
		&g_hash, NULL, 0U, root));
	zassert_mem_equal(root, expected, DIG);
	EQ(pqcp_fleet_transparency_empty_root(NULL, root), -EINVAL);
	EQ(pqcp_fleet_transparency_empty_root(&g_hash, NULL), -EINVAL);
}

ZTEST(fleet_transparency, test_leaf_and_node_hash_domain_separation)
{
	uint8_t out[DIG];
	uint8_t expected[DIG];
	uint8_t raw[DIG];
	uint8_t a[DIG];
	uint8_t b[DIG];
	uint8_t swapped[DIG];

	/* Leaf hash of the empty string is the 1-leaf RFC root. */
	hexbin(rfc_roots[0], expected);
	OK(pqcp_fleet_transparency_leaf_hash(&g_hash, NULL, 0U, out));
	zassert_mem_equal(out, expected, DIG);
	OK(pqcp_fleet_transparency_leaf_hash(&g_hash, l_empty, 0U, out));
	zassert_mem_equal(out, expected, DIG);

	/* Domain separation: H(0x00||x) != H(x). */
	OK(pqcp_fleet_transparency_leaf_hash(&g_hash, l7, sizeof(l7), out));
	ref_sha(l7, sizeof(l7), raw);
	zassert_not_equal(memcmp(out, raw, DIG), 0);
	ref_leaf(l7, sizeof(l7), expected);
	zassert_mem_equal(out, expected, DIG);

	OK(pqcp_fleet_transparency_leaf_hash(&g_hash, l1, 1U, a));
	OK(pqcp_fleet_transparency_leaf_hash(&g_hash, l2, 1U, b));
	OK(pqcp_fleet_transparency_node_hash(&g_hash, a, b, out));
	ref_node(a, b, expected);
	zassert_mem_equal(out, expected, DIG);
	/* Node hash is order sensitive. */
	OK(pqcp_fleet_transparency_node_hash(&g_hash, b, a, swapped));
	zassert_not_equal(memcmp(out, swapped, DIG), 0);

	EQ(pqcp_fleet_transparency_leaf_hash(&g_hash, NULL, 1U, out),
	   -EINVAL);
	EQ(pqcp_fleet_transparency_leaf_hash(&g_hash, l1, 1U, NULL),
	   -EINVAL);
	EQ(pqcp_fleet_transparency_node_hash(&g_hash, NULL, b, out),
	   -EINVAL);
	EQ(pqcp_fleet_transparency_node_hash(&g_hash, a, NULL, out),
	   -EINVAL);
}

ZTEST(fleet_transparency, test_rfc9162_eight_leaf_vectors_incrementally)
{
	uint8_t expected[DIG];
	struct pqcp_fleet_transparency_snapshot snap;
	uint8_t empty[DIG];

	OK(pqcp_fleet_transparency_log_init(
		&g_log_a, g_log_id, g_store_a, LOG_CAP, &g_hash));
	hexbin(rfc_empty_root, empty);
	zassert_mem_equal(g_log_a.root, empty, DIG);

	for (size_t i = 0U; i < 8U; ++i) {
		uint64_t index = 99U;
		uint64_t generation = g_log_a.generation;

		OK(pqcp_fleet_transparency_log_append(
			&g_log_a, g_leaves[i].data, g_leaves[i].length,
			&g_ws, &index));
		EQ(index, i);
		EQ(g_log_a.generation, generation + 1U);
		hexbin(rfc_roots[i], expected);
		zassert_mem_equal(g_log_a.root, expected, DIG);
		OK(pqcp_fleet_transparency_log_snapshot(&g_log_a, &snap));
		EQ(snap.tree_size, i + 1U);
		zassert_mem_equal(snap.root, expected, DIG);
		zassert_mem_equal(snap.log_id, g_log_id, DIG);
		OK(pqcp_fleet_transparency_log_verify(&g_log_a, &g_ws));
	}
}

ZTEST(fleet_transparency, test_root_from_hashes_matches_reference_0_to_9)
{
	uint8_t lh[9][DIG];
	uint8_t root[DIG];
	uint8_t expected[DIG];

	ref_leaf_hashes(lh, 9U, NO_FORK);
	for (size_t n = 0U; n <= 9U; ++n) {
		OK(pqcp_fleet_transparency_root_from_hashes(
			&g_hash, (const uint8_t (*)[DIG])lh, n, root));
		ref_mth((const uint8_t (*)[DIG])lh, n, expected);
		zassert_mem_equal(root, expected, DIG);
		if (n > 0U && n <= 8U) {
			hexbin(rfc_roots[n - 1U], expected);
			zassert_mem_equal(root, expected, DIG);
		}
		build_log(&g_log_a, g_store_a, n, NO_FORK);
		zassert_mem_equal(g_log_a.root, root, DIG);
		expect_ref_root(&g_log_a, n, NO_FORK);
	}
	EQ(pqcp_fleet_transparency_root_from_hashes(
		   &g_hash, NULL, 3U, root), -EINVAL);
}

ZTEST(fleet_transparency, test_forked_logs_share_prefix_roots_only)
{
	build_log(&g_log_a, g_store_a, 9U, NO_FORK);
	build_log(&g_log_b, g_store_b, 9U, 3U);
	/* Diverging at leaf index 3: sizes <= 3 agree, >= 4 differ. */
	for (size_t n = 1U; n <= 3U; ++n) {
		uint8_t ra[DIG];
		uint8_t rb[DIG];

		OK(pqcp_fleet_transparency_root_from_hashes(
			&g_hash, (const uint8_t (*)[DIG])g_store_a, n, ra));
		OK(pqcp_fleet_transparency_root_from_hashes(
			&g_hash, (const uint8_t (*)[DIG])g_store_b, n, rb));
		zassert_mem_equal(ra, rb, DIG);
	}
	for (size_t n = 4U; n <= 9U; ++n) {
		uint8_t ra[DIG];
		uint8_t rb[DIG];

		OK(pqcp_fleet_transparency_root_from_hashes(
			&g_hash, (const uint8_t (*)[DIG])g_store_a, n, ra));
		OK(pqcp_fleet_transparency_root_from_hashes(
			&g_hash, (const uint8_t (*)[DIG])g_store_b, n, rb));
		zassert_not_equal(memcmp(ra, rb, DIG), 0);
	}
	expect_ref_root(&g_log_b, 9U, 3U);
}

ZTEST(fleet_transparency, test_empty_log_snapshot_and_verify)
{
	struct pqcp_fleet_transparency_snapshot snap;
	uint8_t empty[DIG];

	build_log(&g_log_a, g_store_a, 0U, NO_FORK);
	hexbin(rfc_empty_root, empty);
	OK(pqcp_fleet_transparency_log_snapshot(&g_log_a, &snap));
	EQ(snap.tree_size, 0U);
	EQ(snap.generation, 1U);
	EQ(snap.schema_version, PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION);
	zassert_mem_equal(snap.root, empty, DIG);
	OK(pqcp_fleet_transparency_log_verify(&g_log_a, &g_ws));
	EQ(pqcp_fleet_transparency_log_snapshot(&g_log_a, NULL), -EINVAL);
}

ZTEST(fleet_transparency, test_log_init_argument_validation)
{
	uint8_t zero_id[DIG] = { 0 };

	EQ(pqcp_fleet_transparency_log_init(
		   NULL, g_log_id, g_store_a, LOG_CAP, &g_hash), -EINVAL);
	EQ(pqcp_fleet_transparency_log_init(
		   &g_log_a, zero_id, g_store_a, LOG_CAP, &g_hash), -EINVAL);
	EQ(pqcp_fleet_transparency_log_init(
		   &g_log_a, g_log_id, NULL, LOG_CAP, &g_hash), -EINVAL);
	EQ(pqcp_fleet_transparency_log_init(
		   &g_log_a, g_log_id, g_store_a, 0U, &g_hash), -EINVAL);
	EQ(pqcp_fleet_transparency_log_init(
		   &g_log_a, g_log_id, g_store_a, LOG_CAP, NULL), -EINVAL);
	/* Hash provider failure during init (empty-root computation). */
	g_hctx.fail_at = 0;
	g_hctx.calls = 0;
	EQ(pqcp_fleet_transparency_log_init(
		   &g_log_a, g_log_id, g_store_a, LOG_CAP, &g_hash), -EIO);
	g_hctx.fail_at = -1;
	/* A zeroed (uninitialized) log is rejected everywhere. */
	memset(&g_log_a, 0, sizeof(g_log_a));
	EQ(pqcp_fleet_transparency_log_append(
		   &g_log_a, l1, 1U, &g_ws, &(uint64_t){ 0 }), -EINVAL);
	EQ(pqcp_fleet_transparency_log_verify(&g_log_a, &g_ws), -EINVAL);
}

ZTEST(fleet_transparency, test_log_restore_rebuilds_identical_state)
{
	uint8_t saved_root[DIG];
	uint64_t index = 0U;

	build_log(&g_log_a, g_store_a, 7U, NO_FORK);
	memcpy(saved_root, g_log_a.root, DIG);

	/* Restore a fresh log over the same retained leaf storage. */
	OK(pqcp_fleet_transparency_log_init(
		&g_log_b, g_log_id, g_store_a, LOG_CAP, &g_hash));
	OK(pqcp_fleet_transparency_log_restore(&g_log_b, 7U, 42U, &g_ws));
	EQ(g_log_b.tree_size, 7U);
	EQ(g_log_b.generation, 42U);
	EQ(g_log_b.frontier_mask, g_log_a.frontier_mask);
	zassert_mem_equal(g_log_b.root, saved_root, DIG);
	OK(pqcp_fleet_transparency_log_verify(&g_log_b, &g_ws));

	/* Restored log keeps appending correctly (RFC 8-leaf root). */
	OK(pqcp_fleet_transparency_log_append(
		&g_log_b, l7, sizeof(l7), &g_ws, &index));
	EQ(index, 7U);
	{
		uint8_t expected[DIG];

		hexbin(rfc_roots[7], expected);
		zassert_mem_equal(g_log_b.root, expected, DIG);
	}

	/* Zero-leaf restore yields the empty tree. */
	OK(pqcp_fleet_transparency_log_restore(&g_log_b, 0U, 5U, &g_ws));
	EQ(g_log_b.tree_size, 0U);
	hexbin(rfc_empty_root, saved_root);
	zassert_mem_equal(g_log_b.root, saved_root, DIG);
}

ZTEST(fleet_transparency, test_log_restore_rejections_leave_state_intact)
{
	tlog_t before;

	build_log(&g_log_a, g_store_a, 5U, NO_FORK);
	before = g_log_a;

	EQ(pqcp_fleet_transparency_log_restore(
		   &g_log_a, LOG_CAP + 1U, 9U, &g_ws), -EINVAL);
	EQ(pqcp_fleet_transparency_log_restore(
		   &g_log_a, 3U, 0U, &g_ws), -EINVAL);
	EQ(pqcp_fleet_transparency_log_restore(
		   &g_log_a, 3U, 9U, NULL), -EINVAL);
	expect_log_same(&before, &g_log_a);

	/* Restoring 5 leaves takes exactly 6 hash calls (empty root plus
	 * frontier merges); a failure at any of them commits nothing.
	 */
	for (int k = 0; k < 6; ++k) {
		g_hctx.calls = 0;
		g_hctx.fail_at = k;
		EQ(pqcp_fleet_transparency_log_restore(
			   &g_log_a, 5U, 9U, &g_ws), -EIO);
		g_hctx.fail_at = -1;
		expect_log_same(&before, &g_log_a);
	}
	OK(pqcp_fleet_transparency_log_restore(&g_log_a, 5U, 9U, &g_ws));
	EQ(g_log_a.generation, 9U);
	zassert_mem_equal(g_log_a.root, before.root, DIG);
}

ZTEST(fleet_transparency, test_log_verify_detects_tampering)
{
	build_log(&g_log_a, g_store_a, 5U, NO_FORK);
	OK(pqcp_fleet_transparency_log_verify(&g_log_a, &g_ws));

	flip(g_store_a[2], 7U, 0x01);
	EQ(pqcp_fleet_transparency_log_verify(&g_log_a, &g_ws), -EILSEQ);
	flip(g_store_a[2], 7U, 0x01);
	OK(pqcp_fleet_transparency_log_verify(&g_log_a, &g_ws));

	flip(g_log_a.root, 0U, 0x80);
	EQ(pqcp_fleet_transparency_log_verify(&g_log_a, &g_ws), -EILSEQ);
	flip(g_log_a.root, 0U, 0x80);

	/* tree_size 5 = binary 101: frontier levels 0 and 2 are populated. */
	flip(g_log_a.frontier[2], 3U, 0x10);
	EQ(pqcp_fleet_transparency_log_verify(&g_log_a, &g_ws), -EILSEQ);
	flip(g_log_a.frontier[2], 3U, 0x10);

	g_log_a.frontier_mask ^= 1U;
	EQ(pqcp_fleet_transparency_log_verify(&g_log_a, &g_ws), -EILSEQ);
	g_log_a.frontier_mask ^= 1U;

	OK(pqcp_fleet_transparency_log_verify(&g_log_a, &g_ws));
	g_log_a.tree_size = LOG_CAP + 1U;
	EQ(pqcp_fleet_transparency_log_verify(&g_log_a, &g_ws), -EINVAL);
}

ZTEST(fleet_transparency, test_append_at_capacity_fails_without_corruption)
{
	uint8_t saved_store[4][DIG];
	struct pqcp_fleet_transparency_snapshot before;
	struct pqcp_fleet_transparency_snapshot after;
	uint8_t expected[DIG];
	uint64_t index = 0xDEADU;
	tlog_t saved;

	build_log_id(&g_log_a, g_store_a, 4U, 4U, NO_FORK, g_log_id);
	OK(pqcp_fleet_transparency_log_snapshot(&g_log_a, &before));
	memcpy(saved_store, g_store_a, sizeof(saved_store));
	saved = g_log_a;

	for (int attempt = 0; attempt < 3; ++attempt) {
		EQ(pqcp_fleet_transparency_log_append(
			   &g_log_a, l5, sizeof(l5), &g_ws, &index), -ENOSPC);
		EQ(index, 0xDEADU);
		OK(pqcp_fleet_transparency_log_snapshot(&g_log_a, &after));
		zassert_mem_equal(&before, &after, sizeof(before));
		zassert_mem_equal(saved_store, g_store_a, sizeof(saved_store));
		/* No write past capacity into the neighbouring slot. */
		{
			uint8_t zero[DIG] = { 0 };

			zassert_mem_equal(g_store_a[4], zero, DIG);
		}
		expect_log_same(&saved, &g_log_a);
		OK(pqcp_fleet_transparency_log_verify(&g_log_a, &g_ws));
	}
	hexbin(rfc_roots[3], expected);
	zassert_mem_equal(g_log_a.root, expected, DIG);

	/* Capacity one: exactly one append succeeds. */
	build_log_id(&g_log_b, g_store_b, 1U, 1U, NO_FORK, g_log_id);
	EQ(pqcp_fleet_transparency_log_append(
		   &g_log_b, l1, 1U, &g_ws, &index), -ENOSPC);
	EQ(g_log_b.tree_size, 1U);
	hexbin(rfc_roots[0], expected);
	zassert_mem_equal(g_log_b.root, expected, DIG);
}

ZTEST(fleet_transparency, test_append_hash_failure_is_transactional)
{
	int failures = 0;
	uint64_t index = 0xBEEFU;

	for (int k = 0; k < 6; ++k) {
		tlog_t before;
		int ret;

		build_log(&g_log_a, g_store_a, 3U, NO_FORK);
		before = g_log_a;
		g_hctx.calls = 0;
		g_hctx.fail_at = k;
		ret = pqcp_fleet_transparency_log_append(
			&g_log_a, l3, sizeof(l3), &g_ws, &index);
		g_hctx.fail_at = -1;
		if (ret != 0) {
			uint8_t zero[DIG] = { 0 };

			++failures;
			EQ(ret, -EIO);
			expect_log_same(&before, &g_log_a);
			zassert_mem_equal(g_store_a[3], zero, DIG);
			OK(pqcp_fleet_transparency_log_verify(
				&g_log_a, &g_ws));
		} else {
			EQ(g_log_a.tree_size, 4U);
			EQ(index, 3U);
			OK(pqcp_fleet_transparency_log_verify(
				&g_log_a, &g_ws));
		}
	}
	/* Appending the 4th leaf to a 3-leaf log needs 3 hash calls. */
	EQ(failures, 3);
}

ZTEST(fleet_transparency, test_append_argument_validation)
{
	uint64_t index = 0U;
	uint8_t expected[DIG];

	build_log(&g_log_a, g_store_a, 0U, NO_FORK);
	EQ(pqcp_fleet_transparency_log_append(
		   &g_log_a, NULL, 1U, &g_ws, &index), -EINVAL);
	EQ(pqcp_fleet_transparency_log_append(
		   &g_log_a, l1, 1U, NULL, &index), -EINVAL);
	EQ(pqcp_fleet_transparency_log_append(
		   &g_log_a, l1, 1U, &g_ws, NULL), -EINVAL);
	EQ(g_log_a.tree_size, 0U);
	/* NULL statement with zero length is the empty leaf. */
	OK(pqcp_fleet_transparency_log_append(
		&g_log_a, NULL, 0U, &g_ws, &index));
	hexbin(rfc_roots[0], expected);
	zassert_mem_equal(g_log_a.root, expected, DIG);
	/* Duplicate statements still occupy distinct indexes. */
	OK(pqcp_fleet_transparency_log_append(
		&g_log_a, NULL, 0U, &g_ws, &index));
	EQ(index, 1U);
	EQ(g_log_a.tree_size, 2U);
}

/* ------------------------------------------------------------------ */
/* Inclusion proofs                                                    */
/* ------------------------------------------------------------------ */

static void check_inclusion_vs_reference(
	const tlog_t *log, uint64_t idx, uint64_t size, size_t diverge)
{
	uint8_t lh[16][DIG];
	uint8_t ref_nodes[PROOF_MAX][DIG];
	uint8_t ref_root[DIG];
	size_t ref_count = 0U;

	ref_leaf_hashes(lh, (size_t)size, diverge);
	ref_path((size_t)idx, (const uint8_t (*)[DIG])lh, (size_t)size,
		 ref_nodes, &ref_count);
	ref_mth((const uint8_t (*)[DIG])lh, (size_t)size, ref_root);

	OK(pqcp_fleet_transparency_inclusion_proof_generate(
		log, idx, size, &g_inc));
	EQ(g_inc.tree_size, size);
	EQ(g_inc.leaf_index, idx);
	EQ(g_inc.node_count, ref_count);
	for (size_t k = 0U; k < ref_count; ++k) {
		zassert_mem_equal(g_inc.nodes[k], ref_nodes[k], DIG);
	}
	zassert_mem_equal(g_inc.leaf_hash, lh[idx], DIG);
	zassert_mem_equal(g_inc.root, ref_root, DIG);
	OK(inc_verify(&g_inc));
}

ZTEST(fleet_transparency, test_inclusion_proofs_valid_for_all_leaves_1_to_9)
{
	for (size_t n = 1U; n <= 9U; ++n) {
		build_log(&g_log_a, g_store_a, n, NO_FORK);
		for (size_t i = 0U; i < n; ++i) {
			check_inclusion_vs_reference(
				&g_log_a, i, n, NO_FORK);
		}
	}
}

ZTEST(fleet_transparency, test_inclusion_proofs_for_historic_tree_sizes)
{
	build_log(&g_log_a, g_store_a, 9U, NO_FORK);
	for (size_t size = 1U; size <= 9U; ++size) {
		uint8_t expected[DIG];

		for (size_t i = 0U; i < size; ++i) {
			check_inclusion_vs_reference(
				&g_log_a, i, size, NO_FORK);
		}
		if (size <= 8U) {
			hexbin(rfc_roots[size - 1U], expected);
			zassert_mem_equal(g_inc.root, expected, DIG);
		}
	}
	/* Forked log proofs use the forked leaves. */
	build_log(&g_log_b, g_store_b, 9U, 4U);
	for (size_t i = 0U; i < 9U; ++i) {
		check_inclusion_vs_reference(&g_log_b, i, 9U, 4U);
	}
}

ZTEST(fleet_transparency, test_inclusion_generate_rejects_bad_requests)
{
	build_log(&g_log_a, g_store_a, 5U, NO_FORK);
	EQ(pqcp_fleet_transparency_inclusion_proof_generate(
		   &g_log_a, 5U, 5U, &g_inc), -EINVAL);
	EQ(pqcp_fleet_transparency_inclusion_proof_generate(
		   &g_log_a, 0U, 0U, &g_inc), -EINVAL);
	EQ(pqcp_fleet_transparency_inclusion_proof_generate(
		   &g_log_a, 0U, 6U, &g_inc), -EINVAL);
	EQ(pqcp_fleet_transparency_inclusion_proof_generate(
		   &g_log_a, 4U, 4U, &g_inc), -EINVAL);
	EQ(pqcp_fleet_transparency_inclusion_proof_generate(
		   &g_log_a, 0U, 5U, NULL), -EINVAL);
	EQ(pqcp_fleet_transparency_inclusion_proof_generate(
		   NULL, 0U, 5U, &g_inc), -EINVAL);
	memset(&g_log_b, 0, sizeof(g_log_b));
	EQ(pqcp_fleet_transparency_inclusion_proof_generate(
		   &g_log_b, 0U, 1U, &g_inc), -EINVAL);
}

ZTEST(fleet_transparency, test_inclusion_rejects_wrong_leaf_index_and_size)
{
	for (size_t n = 1U; n <= 9U; ++n) {
		build_log(&g_log_a, g_store_a, n, NO_FORK);
		for (size_t i = 0U; i < n; ++i) {
			OK(pqcp_fleet_transparency_inclusion_proof_generate(
				&g_log_a, i, n, &g_inc));
			g_inc_work = g_inc;

			/* Wrong leaf: flipped bit. */
			flip(g_inc_work.leaf_hash, 0U, 0x01);
			NZ(inc_verify(&g_inc_work));
			g_inc_work = g_inc;

			/* Wrong leaf: a different, legitimate leaf hash. */
			if (n > 1U) {
				memcpy(g_inc_work.leaf_hash,
				       g_log_a.leaf_hashes[(i + 1U) % n], DIG);
				NZ(inc_verify(&g_inc_work));
				g_inc_work = g_inc;

				/* Wrong index within range. */
				g_inc_work.leaf_index = (i + 1U) % n;
				NZ(inc_verify(&g_inc_work));
				g_inc_work = g_inc;
			}
			/* Index out of range. */
			g_inc_work.leaf_index = n;
			EQ(inc_verify(&g_inc_work), -EINVAL);
			g_inc_work = g_inc;

			/* Wrong sizes: the verifier trusts a (size, root) pair
			 * from a checkpoint, so a proof built for size n must
			 * fail against the true root of size n+1 and n-1.
			 */
			{
				uint8_t lh[16][DIG];
				uint8_t true_root[DIG];

				ref_leaf_hashes(lh, 10U, 9U);
				ref_mth((const uint8_t (*)[DIG])lh, n + 1U,
					true_root);
				g_inc_work.tree_size = n + 1U;
				memcpy(g_inc_work.root, true_root, DIG);
				NZ(inc_verify(&g_inc_work));
				g_inc_work = g_inc;
				if (n > 1U && i < n - 1U) {
					ref_mth((const uint8_t (*)[DIG])lh,
						n - 1U, true_root);
					g_inc_work.tree_size = n - 1U;
					memcpy(g_inc_work.root, true_root, DIG);
					NZ(inc_verify(&g_inc_work));
					g_inc_work = g_inc;
				}
			}
			g_inc_work.tree_size = 0U;
			EQ(inc_verify(&g_inc_work), -EINVAL);
			g_inc_work = g_inc;

			/* Wrong root. */
			flip(g_inc_work.root, 31U, 0x80);
			EQ(inc_verify(&g_inc_work), -EKEYREJECTED);
			/* Original still verifies. */
			OK(inc_verify(&g_inc));
		}
	}
}

ZTEST(fleet_transparency, test_inclusion_rejects_truncated_and_extended_paths)
{
	for (size_t n = 2U; n <= 9U; ++n) {
		build_log(&g_log_a, g_store_a, n, NO_FORK);
		for (size_t i = 0U; i < n; ++i) {
			OK(pqcp_fleet_transparency_inclusion_proof_generate(
				&g_log_a, i, n, &g_inc));
			zassert_true(g_inc.node_count >= 1U);

			g_inc_work = g_inc;
			g_inc_work.node_count -= 1U;
			NZ(inc_verify(&g_inc_work));

			g_inc_work = g_inc;
			g_inc_work.node_count = 0U;
			NZ(inc_verify(&g_inc_work));

			g_inc_work = g_inc;
			memcpy(g_inc_work.nodes[g_inc.node_count],
			       g_inc.nodes[0], DIG);
			g_inc_work.node_count += 1U;
			NZ(inc_verify(&g_inc_work));

			/* Extended by an all-zero node. */
			g_inc_work = g_inc;
			memset(g_inc_work.nodes[g_inc.node_count], 0, DIG);
			g_inc_work.node_count += 1U;
			NZ(inc_verify(&g_inc_work));

			g_inc_work = g_inc;
			g_inc_work.node_count = PROOF_MAX + 1U;
			EQ(inc_verify(&g_inc_work), -EINVAL);
		}
	}
	/* Single-leaf tree: any extension is rejected. */
	build_log(&g_log_a, g_store_a, 1U, NO_FORK);
	OK(pqcp_fleet_transparency_inclusion_proof_generate(
		&g_log_a, 0U, 1U, &g_inc));
	EQ(g_inc.node_count, 0U);
	zassert_mem_equal(g_inc.leaf_hash, g_inc.root, DIG);
	OK(inc_verify(&g_inc));
	g_inc.node_count = 1U;
	NZ(inc_verify(&g_inc));
}

ZTEST(fleet_transparency, test_inclusion_rejects_any_flipped_proof_hash)
{
	static const struct { size_t byte; uint8_t mask; } flips[] = {
		{ 0U, 0x01 }, { 15U, 0x10 }, { 31U, 0x80 },
	};

	for (size_t n = 1U; n <= 9U; ++n) {
		build_log(&g_log_a, g_store_a, n, NO_FORK);
		for (size_t i = 0U; i < n; ++i) {
			OK(pqcp_fleet_transparency_inclusion_proof_generate(
				&g_log_a, i, n, &g_inc));
			for (size_t k = 0U; k < g_inc.node_count; ++k) {
				for (size_t f = 0U; f < ARRAY_SIZE(flips);
				     ++f) {
					flip(g_inc.nodes[k], flips[f].byte,
					     flips[f].mask);
					EQ(inc_verify(&g_inc),
					   -EKEYREJECTED);
					flip(g_inc.nodes[k], flips[f].byte,
					     flips[f].mask);
				}
			}
			OK(inc_verify(&g_inc));
		}
	}
}

ZTEST(fleet_transparency, test_inclusion_verify_argument_validation)
{
	struct pqcp_fleet_transparency_hash_ops no_digest = { 0 };

	build_log(&g_log_a, g_store_a, 4U, NO_FORK);
	OK(pqcp_fleet_transparency_inclusion_proof_generate(
		&g_log_a, 2U, 4U, &g_inc));
	OK(inc_verify(&g_inc));
	EQ(pqcp_fleet_transparency_inclusion_proof_verify(NULL, &g_inc),
	   -EINVAL);
	EQ(pqcp_fleet_transparency_inclusion_proof_verify(
		   &no_digest, &g_inc), -EINVAL);
	EQ(pqcp_fleet_transparency_inclusion_proof_verify(&g_hash, NULL),
	   -EINVAL);
	g_inc_work = g_inc;
	g_inc_work.schema_version = 0U;
	EQ(inc_verify(&g_inc_work), -EINVAL);
	g_inc_work.schema_version = 2U;
	EQ(inc_verify(&g_inc_work), -EINVAL);
	/* A proof verifies against a different log's root only if equal. */
	build_log(&g_log_b, g_store_b, 4U, 2U);
	g_inc_work = g_inc;
	memcpy(g_inc_work.root, g_log_b.root, DIG);
	EQ(inc_verify(&g_inc_work), -EKEYREJECTED);
}

/* ------------------------------------------------------------------ */
/* Consistency proofs                                                  */
/* ------------------------------------------------------------------ */

ZTEST(fleet_transparency, test_consistency_proofs_valid_for_all_pairs_to_9)
{
	build_log(&g_log_a, g_store_a, 9U, NO_FORK);
	for (size_t old_size = 0U; old_size <= 9U; ++old_size) {
		for (size_t new_size = old_size; new_size <= 9U;
		     ++new_size) {
			uint8_t lh[16][DIG];
			uint8_t ref_nodes[PROOF_MAX][DIG];
			uint8_t ref_old[DIG];
			uint8_t ref_new[DIG];
			size_t ref_count = 0U;

			ref_leaf_hashes(lh, 9U, NO_FORK);
			ref_mth((const uint8_t (*)[DIG])lh, old_size, ref_old);
			ref_mth((const uint8_t (*)[DIG])lh, new_size, ref_new);
			if (old_size != 0U && old_size != new_size) {
				ref_subproof(old_size,
					     (const uint8_t (*)[DIG])lh,
					     new_size, true, ref_nodes,
					     &ref_count);
			}
			OK(pqcp_fleet_transparency_consistency_proof_generate(
				&g_log_a, old_size, new_size, &g_cons));
			EQ(g_cons.old_tree_size, old_size);
			EQ(g_cons.new_tree_size, new_size);
			EQ(g_cons.node_count, ref_count);
			for (size_t k = 0U; k < ref_count; ++k) {
				zassert_mem_equal(
					g_cons.nodes[k], ref_nodes[k], DIG);
			}
			zassert_mem_equal(g_cons.old_root, ref_old, DIG);
			zassert_mem_equal(g_cons.new_root, ref_new, DIG);
			OK(cons_verify(&g_cons));
		}
	}
	/* Known RFC endpoints. */
	{
		uint8_t expected[DIG];

		OK(pqcp_fleet_transparency_consistency_proof_generate(
			&g_log_a, 3U, 8U, &g_cons));
		hexbin(rfc_roots[2], expected);
		zassert_mem_equal(g_cons.old_root, expected, DIG);
		hexbin(rfc_roots[7], expected);
		zassert_mem_equal(g_cons.new_root, expected, DIG);
	}
}

ZTEST(fleet_transparency, test_consistency_generate_rejects_bad_requests)
{
	build_log(&g_log_a, g_store_a, 6U, NO_FORK);
	EQ(pqcp_fleet_transparency_consistency_proof_generate(
		   &g_log_a, 4U, 3U, &g_cons), -EINVAL);
	EQ(pqcp_fleet_transparency_consistency_proof_generate(
		   &g_log_a, 2U, 7U, &g_cons), -EINVAL);
	EQ(pqcp_fleet_transparency_consistency_proof_generate(
		   &g_log_a, 2U, 4U, NULL), -EINVAL);
	EQ(pqcp_fleet_transparency_consistency_proof_generate(
		   NULL, 2U, 4U, &g_cons), -EINVAL);
	/* Boundary: whole log is allowed. */
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_a, 6U, 6U, &g_cons));
	EQ(g_cons.node_count, 0U);
}

ZTEST(fleet_transparency, test_consistency_rejects_tampered_proofs)
{
	static const struct { size_t byte; uint8_t mask; } flips[] = {
		{ 0U, 0x01 }, { 31U, 0x80 },
	};

	build_log(&g_log_a, g_store_a, 9U, NO_FORK);
	for (size_t old_size = 1U; old_size < 9U; ++old_size) {
		for (size_t new_size = old_size + 1U; new_size <= 9U;
		     ++new_size) {
			OK(pqcp_fleet_transparency_consistency_proof_generate(
				&g_log_a, old_size, new_size, &g_cons));
			zassert_true(g_cons.node_count >= 1U);

			for (size_t k = 0U; k < g_cons.node_count; ++k) {
				for (size_t f = 0U; f < ARRAY_SIZE(flips);
				     ++f) {
					flip(g_cons.nodes[k], flips[f].byte,
					     flips[f].mask);
					NZ(cons_verify(&g_cons));
					flip(g_cons.nodes[k], flips[f].byte,
					     flips[f].mask);
				}
			}
			g_cons_work = g_cons;
			flip(g_cons_work.old_root, 0U, 0x01);
			EQ(cons_verify(&g_cons_work), -EKEYREJECTED);
			g_cons_work = g_cons;
			flip(g_cons_work.new_root, 9U, 0x40);
			EQ(cons_verify(&g_cons_work), -EKEYREJECTED);

			/* Truncated. */
			g_cons_work = g_cons;
			g_cons_work.node_count -= 1U;
			NZ(cons_verify(&g_cons_work));
			g_cons_work.node_count = 0U;
			NZ(cons_verify(&g_cons_work));

			/* Extended with junk. */
			g_cons_work = g_cons;
			memcpy(g_cons_work.nodes[g_cons.node_count],
			       g_cons.nodes[0], DIG);
			g_cons_work.node_count += 1U;
			NZ(cons_verify(&g_cons_work));

			/* Roots swapped between old and new. */
			g_cons_work = g_cons;
			memcpy(g_cons_work.old_root, g_cons.new_root, DIG);
			memcpy(g_cons_work.new_root, g_cons.old_root, DIG);
			NZ(cons_verify(&g_cons_work));

			/* Wrong claimed sizes with the same nodes, paired with
			 * the true root of the claimed size.
			 */
			{
				uint8_t lh[16][DIG];
				uint8_t true_root[DIG];

				ref_leaf_hashes(lh, 9U, NO_FORK);
				if (new_size < 9U) {
					ref_mth((const uint8_t (*)[DIG])lh,
						new_size + 1U, true_root);
					g_cons_work = g_cons;
					g_cons_work.new_tree_size =
						new_size + 1U;
					memcpy(g_cons_work.new_root, true_root,
					       DIG);
					NZ(cons_verify(&g_cons_work));
				}
				if (old_size > 1U) {
					ref_mth((const uint8_t (*)[DIG])lh,
						old_size - 1U, true_root);
					g_cons_work = g_cons;
					g_cons_work.old_tree_size =
						old_size - 1U;
					memcpy(g_cons_work.old_root, true_root,
					       DIG);
					NZ(cons_verify(&g_cons_work));
				}
			}
			OK(cons_verify(&g_cons));
		}
	}
}

ZTEST(fleet_transparency, test_consistency_rejects_reversed_and_equal_size_forgeries)
{
	build_log(&g_log_a, g_store_a, 9U, NO_FORK);
	build_log(&g_log_b, g_store_b, 9U, 5U);

	/* Reversed sizes. */
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_a, 3U, 7U, &g_cons));
	g_cons_work = g_cons;
	g_cons_work.old_tree_size = 7U;
	g_cons_work.new_tree_size = 3U;
	memcpy(g_cons_work.old_root, g_cons.new_root, DIG);
	memcpy(g_cons_work.new_root, g_cons.old_root, DIG);
	EQ(cons_verify(&g_cons_work), -EINVAL);

	/* Equal size, equal root: trivially consistent. */
	for (size_t n = 1U; n <= 9U; ++n) {
		OK(pqcp_fleet_transparency_consistency_proof_generate(
			&g_log_a, n, n, &g_cons));
		OK(cons_verify(&g_cons));

		/* Same size but different root. */
		g_cons_work = g_cons;
		flip(g_cons_work.new_root, 0U, 0x01);
		EQ(cons_verify(&g_cons_work), -EKEYREJECTED);

		/* Same size with a smuggled node. */
		g_cons_work = g_cons;
		g_cons_work.node_count = 1U;
		EQ(cons_verify(&g_cons_work), -EKEYREJECTED);
	}

	/* Equal-size split view: roots of two diverged logs. */
	memset(&g_cons_work, 0, sizeof(g_cons_work));
	g_cons_work.schema_version = PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION;
	g_cons_work.old_tree_size = 9U;
	g_cons_work.new_tree_size = 9U;
	memcpy(g_cons_work.old_root, g_log_a.root, DIG);
	memcpy(g_cons_work.new_root, g_log_b.root, DIG);
	EQ(cons_verify(&g_cons_work), -EKEYREJECTED);

	/* Empty old tree demands the exact empty root and no nodes. */
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_a, 0U, 5U, &g_cons));
	EQ(g_cons.node_count, 0U);
	OK(cons_verify(&g_cons));
	g_cons_work = g_cons;
	flip(g_cons_work.old_root, 5U, 0x04);
	EQ(cons_verify(&g_cons_work), -EKEYREJECTED);
	g_cons_work = g_cons;
	g_cons_work.node_count = 1U;
	EQ(cons_verify(&g_cons_work), -EKEYREJECTED);

	/* Argument validation. */
	g_cons_work = g_cons;
	g_cons_work.schema_version = 0U;
	EQ(cons_verify(&g_cons_work), -EINVAL);
	g_cons_work = g_cons;
	g_cons_work.node_count = PROOF_MAX + 1U;
	EQ(cons_verify(&g_cons_work), -EINVAL);
	EQ(pqcp_fleet_transparency_consistency_proof_verify(NULL, &g_cons),
	   -EINVAL);
	EQ(pqcp_fleet_transparency_consistency_proof_verify(&g_hash, NULL),
	   -EINVAL);
}

ZTEST(fleet_transparency, test_consistency_proof_cannot_bridge_forked_history)
{
	/* Logs agree on leaves 0..4 and diverge from index 5. */
	build_log(&g_log_a, g_store_a, 9U, NO_FORK);
	build_log(&g_log_b, g_store_b, 9U, 5U);

	/* Prefix property: honest proof of a shared prefix verifies on both. */
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_a, 5U, 9U, &g_cons));
	OK(cons_verify(&g_cons));
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_b, 5U, 9U, &g_cons_work));
	OK(cons_verify(&g_cons_work));
	zassert_mem_equal(g_cons.old_root, g_cons_work.old_root, DIG);
	zassert_not_equal(memcmp(g_cons.new_root, g_cons_work.new_root, DIG), 0);

	/* A's growth proof cannot be re-targeted at B's new root. */
	g_cons_work = g_cons;
	memcpy(g_cons_work.new_root, g_log_b.root, DIG);
	EQ(cons_verify(&g_cons_work), -EKEYREJECTED);

	/* Diverge before the old size: B's old root is not a prefix of A. */
	build_log(&g_log_b, g_store_b, 9U, 2U);
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_b, 5U, 9U, &g_cons_work));
	g_cons = g_cons_work;
	{
		tcons_t honest_a;

		OK(pqcp_fleet_transparency_consistency_proof_generate(
			&g_log_a, 5U, 9U, &honest_a));
		/* Attacker splices B's old root onto A's growth nodes. */
		g_cons_work = honest_a;
		memcpy(g_cons_work.old_root, g_cons.old_root, DIG);
		EQ(cons_verify(&g_cons_work), -EKEYREJECTED);
	}
}

/* ------------------------------------------------------------------ */
/* Checkpoints                                                         */
/* ------------------------------------------------------------------ */

static tcp_t g_cp[6];
static uint8_t g_cpsig[6][SIGBUF];

ZTEST(fleet_transparency, test_checkpoint_sign_verify_roundtrip)
{
	build_log(&g_log_a, g_store_a, 5U, NO_FORK);
	mk_cp(&g_cp[0], g_cpsig[0], &g_log_a, 1000U, 7U);

	EQ(g_cp[0].schema_version, PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION);
	EQ(g_cp[0].tree_size, 5U);
	EQ(g_cp[0].timestamp_ms, 1000U);
	EQ(g_cp[0].sequence, 7U);
	EQ(g_cp[0].signature_length, SIGLEN);
	zassert_mem_equal(g_cp[0].root, g_log_a.root, DIG);
	zassert_mem_equal(g_cp[0].log_id, g_log_id, DIG);
	zassert_mem_equal(g_cp[0].signer_key_id, g_logkey, DIG);
	OK(pqcp_fleet_transparency_checkpoint_verify(
		&g_cp[0], &g_hash, &g_sig));

	/* Deterministic: re-signing identical inputs yields identical bytes. */
	mk_cp(&g_cp[1], g_cpsig[1], &g_log_a, 1000U, 7U);
	zassert_mem_equal(g_cp[0].transcript_digest,
			  g_cp[1].transcript_digest, DIG);
	zassert_mem_equal(g_cpsig[0], g_cpsig[1], SIGLEN);

	/* Any signed field change changes the transcript digest. */
	mk_cp(&g_cp[2], g_cpsig[2], &g_log_a, 1001U, 7U);
	zassert_not_equal(memcmp(g_cp[0].transcript_digest,
				 g_cp[2].transcript_digest, DIG), 0);
	mk_cp(&g_cp[2], g_cpsig[2], &g_log_a, 1000U, 8U);
	zassert_not_equal(memcmp(g_cp[0].transcript_digest,
				 g_cp[2].transcript_digest, DIG), 0);

	/* An empty tree can be checkpointed (empty root is non-zero). */
	build_log(&g_log_b, g_store_b, 0U, NO_FORK);
	mk_cp(&g_cp[3], g_cpsig[3], &g_log_b, 5U, 1U);
	EQ(g_cp[3].tree_size, 0U);
	OK(pqcp_fleet_transparency_checkpoint_verify(
		&g_cp[3], &g_hash, &g_sig));
}

ZTEST(fleet_transparency, test_checkpoint_rejects_wrong_key_and_forged_signature)
{
	build_log(&g_log_a, g_store_a, 5U, NO_FORK);
	mk_cp(&g_cp[0], g_cpsig[0], &g_log_a, 1000U, 7U);

	/* Verifier holds a different key than the signer. */
	EQ(pqcp_fleet_transparency_checkpoint_verify(
		   &g_cp[0], &g_hash, &g_bad_sig), -EKEYREJECTED);

	/* Attacker signs a self-consistent checkpoint with its own key. */
	{
		struct pqcp_fleet_transparency_snapshot snap;

		OK(pqcp_fleet_transparency_log_snapshot(&g_log_a, &snap));
		OK(pqcp_fleet_transparency_checkpoint_sign(
			&snap, 1000U, 7U, g_logkey, &g_hash, &g_bad_sig,
			g_cpsig[1], SIGBUF, &g_cp[1]));
	}
	EQ(pqcp_fleet_transparency_checkpoint_verify(
		   &g_cp[1], &g_hash, &g_sig), -EKEYREJECTED);

	/* Signature bit flips, truncation, extension. */
	g_cp[2] = g_cp[0];
	memcpy(g_cpsig[2], g_cpsig[0], SIGBUF);
	g_cp[2].signature = g_cpsig[2];
	for (size_t byte = 0U; byte < SIGLEN; byte += 7U) {
		flip(g_cpsig[2], byte, 0x04);
		EQ(pqcp_fleet_transparency_checkpoint_verify(
			   &g_cp[2], &g_hash, &g_sig), -EKEYREJECTED);
		flip(g_cpsig[2], byte, 0x04);
	}
	OK(pqcp_fleet_transparency_checkpoint_verify(
		&g_cp[2], &g_hash, &g_sig));
	g_cp[2].signature_length = SIGLEN - 1U;
	NZ(pqcp_fleet_transparency_checkpoint_verify(
		&g_cp[2], &g_hash, &g_sig));
	g_cp[2].signature_length = SIGLEN + 1U;
	NZ(pqcp_fleet_transparency_checkpoint_verify(
		&g_cp[2], &g_hash, &g_sig));
	g_cp[2].signature_length = 0U;
	EQ(pqcp_fleet_transparency_checkpoint_verify(
		   &g_cp[2], &g_hash, &g_sig), -EINVAL);
	g_cp[2].signature_length = SIGLEN;
	g_cp[2].signature = NULL;
	EQ(pqcp_fleet_transparency_checkpoint_verify(
		   &g_cp[2], &g_hash, &g_sig), -EINVAL);
}

ZTEST(fleet_transparency, test_checkpoint_rejects_tampered_fields)
{
	build_log(&g_log_a, g_store_a, 5U, NO_FORK);
	mk_cp(&g_cp[0], g_cpsig[0], &g_log_a, 1000U, 7U);

	g_cp[1] = g_cp[0];
	g_cp[1].tree_size += 1U;
	EQ(pqcp_fleet_transparency_checkpoint_verify(
		   &g_cp[1], &g_hash, &g_sig), -EKEYREJECTED);

	g_cp[1] = g_cp[0];
	g_cp[1].tree_size -= 1U;
	EQ(pqcp_fleet_transparency_checkpoint_verify(
		   &g_cp[1], &g_hash, &g_sig), -EKEYREJECTED);

	g_cp[1] = g_cp[0];
	flip(g_cp[1].root, 0U, 0x01);
	EQ(pqcp_fleet_transparency_checkpoint_verify(
		   &g_cp[1], &g_hash, &g_sig), -EKEYREJECTED);

	g_cp[1] = g_cp[0];
	g_cp[1].timestamp_ms += 1U;
	EQ(pqcp_fleet_transparency_checkpoint_verify(
		   &g_cp[1], &g_hash, &g_sig), -EKEYREJECTED);

	g_cp[1] = g_cp[0];
	g_cp[1].sequence += 1U;
	EQ(pqcp_fleet_transparency_checkpoint_verify(
		   &g_cp[1], &g_hash, &g_sig), -EKEYREJECTED);

	g_cp[1] = g_cp[0];
	flip(g_cp[1].log_id, 31U, 0x01);
	EQ(pqcp_fleet_transparency_checkpoint_verify(
		   &g_cp[1], &g_hash, &g_sig), -EKEYREJECTED);

	g_cp[1] = g_cp[0];
	flip(g_cp[1].signer_key_id, 4U, 0x01);
	EQ(pqcp_fleet_transparency_checkpoint_verify(
		   &g_cp[1], &g_hash, &g_sig), -EKEYREJECTED);

	g_cp[1] = g_cp[0];
	flip(g_cp[1].transcript_digest, 0U, 0x01);
	EQ(pqcp_fleet_transparency_checkpoint_verify(
		   &g_cp[1], &g_hash, &g_sig), -EKEYREJECTED);

	g_cp[1] = g_cp[0];
	g_cp[1].schema_version = 2U;
	EQ(pqcp_fleet_transparency_checkpoint_verify(
		   &g_cp[1], &g_hash, &g_sig), -EINVAL);
	g_cp[1] = g_cp[0];
	g_cp[1].sequence = 0U;
	EQ(pqcp_fleet_transparency_checkpoint_verify(
		   &g_cp[1], &g_hash, &g_sig), -EINVAL);

	OK(pqcp_fleet_transparency_checkpoint_verify(
		&g_cp[0], &g_hash, &g_sig));
}

ZTEST(fleet_transparency, test_checkpoint_sign_rejects_bad_inputs)
{
	struct pqcp_fleet_transparency_snapshot snap;
	uint8_t zero[DIG] = { 0 };
	tcp_t cp;

	build_log(&g_log_a, g_store_a, 3U, NO_FORK);
	OK(pqcp_fleet_transparency_log_snapshot(&g_log_a, &snap));

	EQ(pqcp_fleet_transparency_checkpoint_sign(
		   &snap, 1U, 0U, g_logkey, &g_hash, &g_sig, g_cpsig[0],
		   SIGBUF, &cp), -EINVAL);
	EQ(pqcp_fleet_transparency_checkpoint_sign(
		   &snap, 1U, 1U, zero, &g_hash, &g_sig, g_cpsig[0],
		   SIGBUF, &cp), -EINVAL);
	EQ(pqcp_fleet_transparency_checkpoint_sign(
		   &snap, 1U, 1U, NULL, &g_hash, &g_sig, g_cpsig[0],
		   SIGBUF, &cp), -EINVAL);
	EQ(pqcp_fleet_transparency_checkpoint_sign(
		   &snap, 1U, 1U, g_logkey, &g_hash, &g_sig, NULL, SIGBUF,
		   &cp), -EINVAL);
	EQ(pqcp_fleet_transparency_checkpoint_sign(
		   &snap, 1U, 1U, g_logkey, &g_hash, &g_sig, g_cpsig[0], 0U,
		   &cp), -EINVAL);
	EQ(pqcp_fleet_transparency_checkpoint_sign(
		   NULL, 1U, 1U, g_logkey, &g_hash, &g_sig, g_cpsig[0],
		   SIGBUF, &cp), -EINVAL);
	{
		struct pqcp_fleet_transparency_snapshot bad = snap;

		memset(bad.root, 0, sizeof(bad.root));
		EQ(pqcp_fleet_transparency_checkpoint_sign(
			   &bad, 1U, 1U, g_logkey, &g_hash, &g_sig,
			   g_cpsig[0], SIGBUF, &cp), -EINVAL);
		bad = snap;
		memset(bad.log_id, 0, sizeof(bad.log_id));
		EQ(pqcp_fleet_transparency_checkpoint_sign(
			   &bad, 1U, 1U, g_logkey, &g_hash, &g_sig,
			   g_cpsig[0], SIGBUF, &cp), -EINVAL);
		bad = snap;
		bad.schema_version = 9U;
		EQ(pqcp_fleet_transparency_checkpoint_sign(
			   &bad, 1U, 1U, g_logkey, &g_hash, &g_sig,
			   g_cpsig[0], SIGBUF, &cp), -EINVAL);
	}
	/* Signer capacity too small / signer failure: output zeroized. */
	memset(g_cpsig[0], 0xCC, SIGBUF);
	EQ(pqcp_fleet_transparency_checkpoint_sign(
		   &snap, 1U, 1U, g_logkey, &g_hash, &g_sig, g_cpsig[0],
		   SIGLEN - 1U, &cp), -ENOSPC);
	g_sctx.fail_sign = true;
	EQ(pqcp_fleet_transparency_checkpoint_sign(
		   &snap, 1U, 1U, g_logkey, &g_hash, &g_sig, g_cpsig[0],
		   SIGBUF, &cp), -EIO);
	g_sctx.fail_sign = false;
	EQ(cp.signature_length, 0U);
	EQ(cp.tree_size, 0U);
	/* Hash failure. */
	g_hctx.calls = 0;
	g_hctx.fail_at = 0;
	EQ(pqcp_fleet_transparency_checkpoint_sign(
		   &snap, 1U, 1U, g_logkey, &g_hash, &g_sig, g_cpsig[0],
		   SIGBUF, &cp), -EIO);
	g_hctx.fail_at = -1;
}

/* Guard persistence mock. */
struct store_ctx {
	tcp_t saved;
	uint8_t sig[SIGBUF];
	bool has;
	bool fail_store;
	int stores;
};

static struct store_ctx g_store;

static int store_load(
	void *context, tcp_t *checkpoint, uint8_t *signature_storage,
	size_t capacity)
{
	struct store_ctx *ctx = context;

	if (!ctx->has) {
		return -ENOENT;
	}
	if (ctx->saved.signature_length > capacity) {
		return -ENOSPC;
	}
	*checkpoint = ctx->saved;
	memcpy(signature_storage, ctx->sig, ctx->saved.signature_length);
	checkpoint->signature = signature_storage;
	return 0;
}

static int store_store(void *context, const tcp_t *checkpoint)
{
	struct store_ctx *ctx = context;

	if (ctx->fail_store) {
		return -EIO;
	}
	ctx->saved = *checkpoint;
	memcpy(ctx->sig, checkpoint->signature, checkpoint->signature_length);
	ctx->saved.signature = ctx->sig;
	ctx->has = true;
	++ctx->stores;
	return 0;
}

static const struct pqcp_fleet_transparency_checkpoint_store_ops g_persist = {
	.context = &g_store,
	.load = store_load,
	.store = store_store,
};

static struct pqcp_fleet_transparency_checkpoint_guard g_guard;
static uint8_t g_guard_sig[SIGBUF];

static void guard_init(
	const struct pqcp_fleet_transparency_checkpoint_store_ops *persist)
{
	OK(pqcp_fleet_transparency_checkpoint_guard_init(
		&g_guard, g_log_id, g_logkey, g_guard_sig, SIGBUF, &g_hash,
		&g_sig, persist));
}

static void guard_expect_latest(uint64_t size, uint64_t seq)
{
	zassert_true(g_guard.has_checkpoint);
	EQ(g_guard.latest.tree_size, size);
	EQ(g_guard.latest.sequence, seq);
}

ZTEST(fleet_transparency, test_guard_accepts_monotonic_growth)
{
	tcons_t p3_6;
	tcons_t p6_9;

	build_log(&g_log_a, g_store_a, 9U, NO_FORK);
	build_log(&g_log_b, g_store_b, 3U, NO_FORK);
	mk_cp(&g_cp[0], g_cpsig[0], &g_log_b, 100U, 1U); /* size 3 */
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_a, 3U, 6U, &p3_6));
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_a, 6U, 9U, &p6_9));
	{
		tlog_t six;
		static uint8_t store_six[LOG_CAP][DIG];

		build_log(&six, store_six, 6U, NO_FORK);
		mk_cp(&g_cp[1], g_cpsig[1], &six, 200U, 2U);
	}
	mk_cp(&g_cp[2], g_cpsig[2], &g_log_a, 300U, 3U);

	guard_init(NULL);
	zassert_false(g_guard.has_checkpoint);
	/* First checkpoint needs no proof. */
	OK(pqcp_fleet_transparency_checkpoint_guard_accept(
		&g_guard, &g_cp[0], NULL));
	guard_expect_latest(3U, 1U);
	OK(pqcp_fleet_transparency_checkpoint_guard_accept(
		&g_guard, &g_cp[1], &p3_6));
	guard_expect_latest(6U, 2U);
	OK(pqcp_fleet_transparency_checkpoint_guard_accept(
		&g_guard, &g_cp[2], &p6_9));
	guard_expect_latest(9U, 3U);
	zassert_mem_equal(g_guard.latest.root, g_log_a.root, DIG);
	/* The guard copied the signature into its own storage. */
	zassert_true(g_guard.latest.signature == g_guard_sig);
	OK(pqcp_fleet_transparency_checkpoint_verify(
		&g_guard.latest, &g_hash, &g_sig));
}

ZTEST(fleet_transparency, test_guard_rejects_rollback_replay_and_stale)
{
	tlog_t small;
	static uint8_t store_small[LOG_CAP][DIG];

	build_log(&g_log_a, g_store_a, 9U, NO_FORK);
	build_log(&small, store_small, 3U, NO_FORK);
	mk_cp(&g_cp[0], g_cpsig[0], &g_log_a, 300U, 3U);
	guard_init(NULL);
	OK(pqcp_fleet_transparency_checkpoint_guard_accept(
		&g_guard, &g_cp[0], NULL));
	guard_expect_latest(9U, 3U);

	/* Rollback to a smaller, validly signed tree with newer sequence. */
	mk_cp(&g_cp[1], g_cpsig[1], &small, 500U, 10U);
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[1], NULL), -ESTALE);
	guard_expect_latest(9U, 3U);

	/* Replay of the very same checkpoint. */
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[0], NULL), -EALREADY);
	/* Older sequence, same content. */
	mk_cp(&g_cp[2], g_cpsig[2], &g_log_a, 301U, 2U);
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[2], NULL), -EALREADY);
	/* Newer sequence but older timestamp. */
	mk_cp(&g_cp[3], g_cpsig[3], &g_log_a, 50U, 20U);
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[3], NULL), -ESTALE);
	guard_expect_latest(9U, 3U);
	zassert_mem_equal(g_guard.latest.root, g_log_a.root, DIG);

	/* Same tree, newer sequence and timestamp: allowed heartbeat. */
	mk_cp(&g_cp[4], g_cpsig[4], &g_log_a, 400U, 4U);
	OK(pqcp_fleet_transparency_checkpoint_guard_accept(
		&g_guard, &g_cp[4], NULL));
	guard_expect_latest(9U, 4U);
}

ZTEST(fleet_transparency, test_guard_detects_split_view_same_size_different_root)
{
	build_log(&g_log_a, g_store_a, 9U, NO_FORK);
	build_log(&g_log_b, g_store_b, 9U, 8U);
	mk_cp(&g_cp[0], g_cpsig[0], &g_log_a, 300U, 3U);
	/* Both are individually valid, correctly signed, newer checkpoints. */
	mk_cp(&g_cp[1], g_cpsig[1], &g_log_b, 600U, 30U);
	OK(pqcp_fleet_transparency_checkpoint_verify(
		&g_cp[0], &g_hash, &g_sig));
	OK(pqcp_fleet_transparency_checkpoint_verify(
		&g_cp[1], &g_hash, &g_sig));
	EQ(g_cp[0].tree_size, g_cp[1].tree_size);
	zassert_not_equal(memcmp(g_cp[0].root, g_cp[1].root, DIG), 0);

	guard_init(NULL);
	OK(pqcp_fleet_transparency_checkpoint_guard_accept(
		&g_guard, &g_cp[0], NULL));
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[1], NULL), -EKEYREJECTED);
	guard_expect_latest(9U, 3U);
	zassert_mem_equal(g_guard.latest.root, g_log_a.root, DIG);

	/* Reverse order is detected symmetrically. */
	guard_init(NULL);
	OK(pqcp_fleet_transparency_checkpoint_guard_accept(
		&g_guard, &g_cp[1], NULL));
	mk_cp(&g_cp[2], g_cpsig[2], &g_log_a, 700U, 31U);
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[2], NULL), -EKEYREJECTED);
	guard_expect_latest(9U, 30U);
	zassert_mem_equal(g_guard.latest.root, g_log_b.root, DIG);
}

ZTEST(fleet_transparency, test_guard_rejects_untrusted_signer_log_and_forgery)
{
	build_log(&g_log_a, g_store_a, 4U, NO_FORK);
	guard_init(NULL);

	/* Valid signature but not the trusted signer key id. */
	{
		struct pqcp_fleet_transparency_snapshot snap;

		OK(pqcp_fleet_transparency_log_snapshot(&g_log_a, &snap));
		OK(pqcp_fleet_transparency_checkpoint_sign(
			&snap, 10U, 1U, g_otherkey, &g_hash, &g_sig,
			g_cpsig[0], SIGBUF, &g_cp[0]));
	}
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[0], NULL), -EKEYREJECTED);
	zassert_false(g_guard.has_checkpoint);

	/* Right key id, but a different log. */
	build_log_id(&g_log_b, g_store_b, LOG_CAP, 4U, NO_FORK,
		     g_other_log_id);
	mk_cp(&g_cp[1], g_cpsig[1], &g_log_b, 10U, 1U);
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[1], NULL), -EKEYREJECTED);
	zassert_false(g_guard.has_checkpoint);

	/* Attacker-signed. */
	{
		struct pqcp_fleet_transparency_snapshot snap;

		OK(pqcp_fleet_transparency_log_snapshot(&g_log_a, &snap));
		OK(pqcp_fleet_transparency_checkpoint_sign(
			&snap, 10U, 1U, g_logkey, &g_hash, &g_bad_sig,
			g_cpsig[2], SIGBUF, &g_cp[2]));
	}
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[2], NULL), -EKEYREJECTED);
	zassert_false(g_guard.has_checkpoint);

	/* Tampered root. */
	mk_cp(&g_cp[3], g_cpsig[3], &g_log_a, 10U, 1U);
	flip(g_cp[3].root, 1U, 0x20);
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[3], NULL), -EKEYREJECTED);
	zassert_false(g_guard.has_checkpoint);

	/* Signature larger than guard storage. */
	{
		static uint8_t tiny[8];

		OK(pqcp_fleet_transparency_checkpoint_guard_init(
			&g_guard, g_log_id, g_logkey, tiny, sizeof(tiny),
			&g_hash, &g_sig, NULL));
		mk_cp(&g_cp[4], g_cpsig[4], &g_log_a, 10U, 1U);
		EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
			   &g_guard, &g_cp[4], NULL), -ENOSPC);
		zassert_false(g_guard.has_checkpoint);
	}
	/* The honest checkpoint is accepted by a correct guard. */
	guard_init(NULL);
	mk_cp(&g_cp[5], g_cpsig[5], &g_log_a, 10U, 1U);
	OK(pqcp_fleet_transparency_checkpoint_guard_accept(
		&g_guard, &g_cp[5], NULL));
}

ZTEST(fleet_transparency, test_guard_rejects_bad_growth_proofs_without_state_change)
{
	tcons_t good;
	tcons_t bad;
	tlog_t three;
	static uint8_t store_three[LOG_CAP][DIG];

	build_log(&g_log_a, g_store_a, 9U, NO_FORK);
	build_log(&three, store_three, 3U, NO_FORK);
	mk_cp(&g_cp[0], g_cpsig[0], &three, 100U, 1U);
	mk_cp(&g_cp[1], g_cpsig[1], &g_log_a, 200U, 2U);
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_a, 3U, 9U, &good));

	guard_init(NULL);
	OK(pqcp_fleet_transparency_checkpoint_guard_accept(
		&g_guard, &g_cp[0], NULL));

	/* Missing proof. */
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[1], NULL), -EBADMSG);
	guard_expect_latest(3U, 1U);

	/* Proof for the wrong sizes. */
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_a, 3U, 6U, &bad));
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[1], &bad), -EBADMSG);
	guard_expect_latest(3U, 1U);

	/* Correct sizes and roots but tampered path. */
	bad = good;
	flip(bad.nodes[0], 0U, 0x01);
	EQ(pqcp_fleet_transparency_consistency_proof_verify(&g_hash, &bad),
	   -EKEYREJECTED);
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[1], &bad), -EKEYREJECTED);
	guard_expect_latest(3U, 1U);

	/* Checkpoint from a fork that diverged inside the old prefix. */
	build_log(&g_log_b, g_store_b, 9U, 1U);
	mk_cp(&g_cp[2], g_cpsig[2], &g_log_b, 300U, 3U);
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_b, 3U, 9U, &bad));
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[2], &bad), -EBADMSG);
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[2], &good), -EBADMSG);
	guard_expect_latest(3U, 1U);

	/* The legitimate growth still works afterwards. */
	OK(pqcp_fleet_transparency_checkpoint_guard_accept(
		&g_guard, &g_cp[1], &good));
	guard_expect_latest(9U, 2U);
}

ZTEST(fleet_transparency, test_guard_persistence_restore_and_store_failure)
{
	tcons_t p3_9;
	tlog_t three;
	static uint8_t store_three[LOG_CAP][DIG];
	int stores;

	memset(&g_store, 0, sizeof(g_store));
	build_log(&g_log_a, g_store_a, 9U, NO_FORK);
	build_log(&three, store_three, 3U, NO_FORK);
	mk_cp(&g_cp[0], g_cpsig[0], &three, 100U, 1U);
	mk_cp(&g_cp[1], g_cpsig[1], &g_log_a, 200U, 2U);
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_a, 3U, 9U, &p3_9));

	guard_init(&g_persist);
	EQ(pqcp_fleet_transparency_checkpoint_guard_restore(&g_guard),
	   -ENOENT);
	zassert_false(g_guard.has_checkpoint);
	OK(pqcp_fleet_transparency_checkpoint_guard_accept(
		&g_guard, &g_cp[0], NULL));
	EQ(g_store.stores, 1);

	/* Store failure must not advance the in-memory guard. */
	g_store.fail_store = true;
	stores = g_store.stores;
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[1], &p3_9), -EIO);
	g_store.fail_store = false;
	EQ(g_store.stores, stores);
	guard_expect_latest(3U, 1U);
	OK(pqcp_fleet_transparency_checkpoint_guard_accept(
		&g_guard, &g_cp[1], &p3_9));
	EQ(g_store.stores, 2);

	/* A rebooted guard restores the persisted state and enforces it. */
	guard_init(&g_persist);
	OK(pqcp_fleet_transparency_checkpoint_guard_restore(&g_guard));
	guard_expect_latest(9U, 2U);
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[0], NULL), -ESTALE);
	EQ(pqcp_fleet_transparency_checkpoint_guard_accept(
		   &g_guard, &g_cp[1], NULL), -EALREADY);

	/* Tampered persistent record is refused. */
	flip(g_store.saved.root, 0U, 0x01);
	guard_init(&g_persist);
	EQ(pqcp_fleet_transparency_checkpoint_guard_restore(&g_guard),
	   -EKEYREJECTED);
	zassert_false(g_guard.has_checkpoint);
	flip(g_store.saved.root, 0U, 0x01);

	/* Restore without persistence ops, and half-configured persistence. */
	guard_init(NULL);
	EQ(pqcp_fleet_transparency_checkpoint_guard_restore(&g_guard),
	   -EINVAL);
	{
		struct pqcp_fleet_transparency_checkpoint_store_ops half = {
			.context = &g_store,
			.load = store_load,
		};

		EQ(pqcp_fleet_transparency_checkpoint_guard_init(
			   &g_guard, g_log_id, g_logkey, g_guard_sig, SIGBUF,
			   &g_hash, &g_sig, &half), -EINVAL);
	}
}

/* ------------------------------------------------------------------ */
/* Witnesses                                                           */
/* ------------------------------------------------------------------ */

#define WIT_CAP 4U
#define W_EXPIRES 100000U

static struct pqcp_fleet_transparency_witness_registry g_wreg;
static struct pqcp_fleet_transparency_witness_record g_wrec[WIT_CAP];
static uint8_t g_warena[WIT_CAP * SIGLEN];
static struct pqcp_fleet_transparency_witness_authority g_wauth[WIT_CAP];
static struct pqcp_fleet_transparency_witness_statement g_wst[WIT_CAP];
static uint8_t g_wsig[WIT_CAP][SIGBUF];

static void wit_registry_init(void)
{
	OK(pqcp_fleet_transparency_witness_registry_init(
		&g_wreg, g_log_id, g_logkey, g_wrec, WIT_CAP, g_warena,
		SIGLEN, &g_hash, &g_sig));
}

static void wit_make(size_t i, uint32_t roles, uint32_t weight)
{
	memset(&g_wauth[i], 0, sizeof(g_wauth[i]));
	g_wauth[i].schema_version = PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION;
	g_wauth[i].generation = 1U;
	g_wauth[i].roles = roles;
	g_wauth[i].weight = weight;
	g_wauth[i].not_before_ms = 0U;
	g_wauth[i].expires_at_ms = W_EXPIRES;
	g_wauth[i].state = PQCP_FLEET_TRANSPARENCY_WITNESS_ACTIVE;
	fill_id(g_wauth[i].witness_id, (uint8_t)(0xB0U + i));
	fill_id(g_wauth[i].key_id, (uint8_t)(0xD0U + i));
}

static void wit_setup(size_t count)
{
	static const uint32_t roles[WIT_CAP] = {
		PQCP_FLEET_TRANSPARENCY_WITNESS_OPERATOR,
		PQCP_FLEET_TRANSPARENCY_WITNESS_AUDITOR,
		PQCP_FLEET_TRANSPARENCY_WITNESS_VENDOR,
		PQCP_FLEET_TRANSPARENCY_WITNESS_REGULATOR,
	};
	static const uint32_t weights[WIT_CAP] = { 1U, 2U, 1U, 1U };

	wit_registry_init();
	for (size_t i = 0U; i < count; ++i) {
		wit_make(i, roles[i], weights[i]);
		OK(pqcp_fleet_transparency_witness_upsert(
			&g_wreg, &g_wauth[i]));
	}
}

static void wit_sign(
	size_t i, const tcp_t *cp, uint64_t observed, uint64_t seq)
{
	OK(pqcp_fleet_transparency_witness_statement_sign(
		&g_wauth[i], cp, observed, seq, &g_hash, &g_sig, g_wsig[i],
		SIGBUF, &g_wst[i]));
}

static int wit_observe(
	size_t i, const tcp_t *cp, const tcons_t *proof, uint64_t observed,
	uint64_t seq, uint64_t now, tev_t *ev)
{
	wit_sign(i, cp, observed, seq);
	return pqcp_fleet_transparency_witness_observe(
		&g_wreg, &g_wst[i], cp, proof, now, ev);
}

static const struct pqcp_fleet_transparency_witness_policy *
wit_policy(uint32_t min_w, uint32_t min_weight, uint32_t roles,
	   uint64_t max_age)
{
	static struct pqcp_fleet_transparency_witness_policy policy;

	policy.minimum_witnesses = min_w;
	policy.minimum_weight = min_weight;
	policy.required_roles = roles;
	policy.maximum_observation_age_ms = max_age;
	return &policy;
}

ZTEST(fleet_transparency, test_witness_registry_lifecycle_and_limits)
{
	struct pqcp_fleet_transparency_witness_authority upd;
	uint8_t zero[DIG] = { 0 };
	uint64_t generation;

	EQ(pqcp_fleet_transparency_witness_registry_init(
		   &g_wreg, zero, g_logkey, g_wrec, WIT_CAP, g_warena, SIGLEN,
		   &g_hash, &g_sig), -EINVAL);
	EQ(pqcp_fleet_transparency_witness_registry_init(
		   &g_wreg, g_log_id, zero, g_wrec, WIT_CAP, g_warena, SIGLEN,
		   &g_hash, &g_sig), -EINVAL);
	EQ(pqcp_fleet_transparency_witness_registry_init(
		   &g_wreg, g_log_id, g_logkey, g_wrec, 0U, g_warena, SIGLEN,
		   &g_hash, &g_sig), -EINVAL);
	EQ(pqcp_fleet_transparency_witness_registry_init(
		   &g_wreg, g_log_id, g_logkey, g_wrec, WIT_CAP, g_warena, 0U,
		   &g_hash, &g_sig), -EINVAL);
	EQ(pqcp_fleet_transparency_witness_registry_init(
		   &g_wreg, g_log_id, g_logkey, g_wrec, WIT_CAP, NULL, SIGLEN,
		   &g_hash, &g_sig), -EINVAL);

	wit_setup(0U);
	OK(pqcp_fleet_transparency_witness_registry_verify(&g_wreg));
	generation = g_wreg.generation;

	/* Fill to capacity, then overflow. */
	for (size_t i = 0U; i < WIT_CAP; ++i) {
		wit_make(i, PQCP_FLEET_TRANSPARENCY_WITNESS_OPERATOR, 1U);
		OK(pqcp_fleet_transparency_witness_upsert(
			&g_wreg, &g_wauth[i]));
	}
	EQ(g_wreg.generation, generation + WIT_CAP);
	{
		struct pqcp_fleet_transparency_witness_authority extra;

		wit_make(0U, PQCP_FLEET_TRANSPARENCY_WITNESS_OPERATOR, 1U);
		extra = g_wauth[0];
		fill_id(extra.witness_id, 0xEF);
		EQ(pqcp_fleet_transparency_witness_upsert(&g_wreg, &extra),
		   -ENOSPC);
	}
	/* Same id, same generation: stale; higher generation: replaced. */
	upd = g_wauth[1];
	EQ(pqcp_fleet_transparency_witness_upsert(&g_wreg, &upd), -ESTALE);
	upd.generation = 2U;
	upd.weight = 5U;
	OK(pqcp_fleet_transparency_witness_upsert(&g_wreg, &upd));
	EQ(g_wrec[1].authority.weight, 5U);
	{
		size_t occupied = 0U;

		for (size_t i = 0U; i < WIT_CAP; ++i) {
			if (g_wrec[i].authority.state !=
			    PQCP_FLEET_TRANSPARENCY_WITNESS_EMPTY) {
				++occupied;
			}
		}
		EQ(occupied, WIT_CAP);
	}

	/* Invalid authorities. */
	upd = g_wauth[0];
	upd.generation = 9U;
	upd.weight = 0U;
	EQ(pqcp_fleet_transparency_witness_upsert(&g_wreg, &upd), -EINVAL);
	upd.weight = 1U;
	upd.roles = 0U;
	EQ(pqcp_fleet_transparency_witness_upsert(&g_wreg, &upd), -EINVAL);
	upd.roles = 1U << 9;
	EQ(pqcp_fleet_transparency_witness_upsert(&g_wreg, &upd), -EINVAL);
	upd.roles = PQCP_FLEET_TRANSPARENCY_WITNESS_OPERATOR;
	upd.expires_at_ms = upd.not_before_ms;
	EQ(pqcp_fleet_transparency_witness_upsert(&g_wreg, &upd), -EINVAL);
	upd.expires_at_ms = W_EXPIRES;
	upd.state = PQCP_FLEET_TRANSPARENCY_WITNESS_REVOKED;
	EQ(pqcp_fleet_transparency_witness_upsert(&g_wreg, &upd), -EINVAL);
	upd.state = PQCP_FLEET_TRANSPARENCY_WITNESS_EMPTY;
	EQ(pqcp_fleet_transparency_witness_upsert(&g_wreg, &upd), -EINVAL);

	/* Revocation. */
	EQ(pqcp_fleet_transparency_witness_revoke(
		   &g_wreg, g_wauth[2].witness_id, 0U), -EINVAL);
	{
		uint8_t unknown[DIG];

		fill_id(unknown, 0xFA);
		EQ(pqcp_fleet_transparency_witness_revoke(
			   &g_wreg, unknown, 5U), -ENOENT);
	}
	OK(pqcp_fleet_transparency_witness_revoke(
		&g_wreg, g_wauth[2].witness_id, 5U));
	EQ(g_wrec[2].authority.state,
	   PQCP_FLEET_TRANSPARENCY_WITNESS_REVOKED);
	EQ(g_wrec[2].authority.generation, 2U);
	EQ(pqcp_fleet_transparency_witness_revoke(
		   &g_wreg, g_wauth[2].witness_id, 6U), -EALREADY);
	OK(pqcp_fleet_transparency_witness_registry_verify(&g_wreg));

	/* Registry audit catches duplicate ids and phantom observations. */
	g_wrec[3].authority = g_wrec[0].authority;
	EQ(pqcp_fleet_transparency_witness_registry_verify(&g_wreg),
	   -EILSEQ);
}

ZTEST(fleet_transparency, test_witness_quorum_count_weight_and_roles)
{
	struct pqcp_fleet_transparency_witness_quorum q;
	tev_t ev;

	build_log(&g_log_a, g_store_a, 5U, NO_FORK);
	mk_cp(&g_cp[0], g_cpsig[0], &g_log_a, 100U, 1U);
	wit_setup(3U); /* weights 1,2,1; roles OPERATOR, AUDITOR, VENDOR */

	/* No observations: nothing counted. */
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[0], wit_policy(1U, 1U, 0U, 0U), 200U, &q));
	EQ(q.witness_count, 0U);
	zassert_false(q.reached);
	zassert_mem_equal(q.checkpoint_digest, g_cp[0].transcript_digest, DIG);

	OK(wit_observe(0U, &g_cp[0], NULL, 100U, 1U, 150U, &ev));
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[0], wit_policy(2U, 2U, 0U, 0U), 200U, &q));
	EQ(q.witness_count, 1U);
	EQ(q.total_weight, 1U);
	zassert_false(q.count_met);
	zassert_false(q.weight_met);
	zassert_true(q.roles_met);
	zassert_false(q.reached);

	OK(wit_observe(1U, &g_cp[0], NULL, 110U, 1U, 150U, &ev));
	/* count 2, weight 3, roles OPERATOR|AUDITOR */
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[0],
		wit_policy(2U, 3U,
			   PQCP_FLEET_TRANSPARENCY_WITNESS_AUDITOR, 0U),
		200U, &q));
	EQ(q.witness_count, 2U);
	EQ(q.total_weight, 3U);
	EQ(q.observed_roles, PQCP_FLEET_TRANSPARENCY_WITNESS_OPERATOR |
			     PQCP_FLEET_TRANSPARENCY_WITNESS_AUDITOR);
	zassert_true(q.reached);

	/* Each dimension failing independently blocks the quorum. */
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[0], wit_policy(3U, 3U, 0U, 0U), 200U, &q));
	zassert_false(q.count_met);
	zassert_true(q.weight_met);
	zassert_false(q.reached);
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[0], wit_policy(2U, 4U, 0U, 0U), 200U, &q));
	zassert_true(q.count_met);
	zassert_false(q.weight_met);
	zassert_false(q.reached);
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[0],
		wit_policy(2U, 3U,
			   PQCP_FLEET_TRANSPARENCY_WITNESS_VENDOR, 0U),
		200U, &q));
	zassert_true(q.count_met);
	zassert_true(q.weight_met);
	zassert_false(q.roles_met);
	zassert_false(q.reached);

	/* Third witness completes a stricter policy. */
	OK(wit_observe(2U, &g_cp[0], NULL, 120U, 1U, 150U, &ev));
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[0],
		wit_policy(3U, 4U,
			   PQCP_FLEET_TRANSPARENCY_WITNESS_VENDOR, 0U),
		200U, &q));
	EQ(q.witness_count, 3U);
	EQ(q.total_weight, 4U);
	zassert_true(q.reached);

	/* Invalid policies. */
	EQ(pqcp_fleet_transparency_witness_quorum_evaluate(
		   &g_wreg, &g_cp[0], wit_policy(0U, 1U, 0U, 0U), 200U, &q),
	   -EINVAL);
	EQ(pqcp_fleet_transparency_witness_quorum_evaluate(
		   &g_wreg, &g_cp[0], wit_policy(1U, 0U, 0U, 0U), 200U, &q),
	   -EINVAL);
	EQ(pqcp_fleet_transparency_witness_quorum_evaluate(
		   &g_wreg, &g_cp[0], NULL, 200U, &q), -EINVAL);
}

ZTEST(fleet_transparency, test_witness_duplicate_witness_counted_once)
{
	struct pqcp_fleet_transparency_witness_quorum q;
	tev_t ev;
	tcp_t cp_again;
	uint8_t sig_again[SIGBUF];

	build_log(&g_log_a, g_store_a, 5U, NO_FORK);
	mk_cp(&g_cp[0], g_cpsig[0], &g_log_a, 100U, 1U);
	wit_setup(2U);

	OK(wit_observe(0U, &g_cp[0], NULL, 100U, 1U, 150U, &ev));
	/* Same witness re-observes the same tree in a newer statement. */
	mk_cp(&cp_again, sig_again, &g_log_a, 110U, 2U);
	OK(wit_observe(0U, &cp_again, NULL, 120U, 2U, 150U, &ev));
	EQ(g_wrec[0].latest_sequence, 2U);

	/* The witness' latest statement covers cp_again, not g_cp[0]. */
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &cp_again, wit_policy(1U, 1U, 0U, 0U), 200U, &q));
	EQ(q.witness_count, 1U);
	EQ(q.total_weight, 1U);
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[0], wit_policy(1U, 1U, 0U, 0U), 200U, &q));
	EQ(q.witness_count, 0U);

	/* Replaying the old statement is refused and flagged. */
	wit_sign(0U, &g_cp[0], 100U, 1U);
	EQ(pqcp_fleet_transparency_witness_observe(
		   &g_wreg, &g_wst[0], &g_cp[0], NULL, 150U, &ev), -EALREADY);
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_REPLAY);
	EQ(g_wrec[0].latest_sequence, 2U);

	/* Same sequence resubmitted also counts as replay. */
	wit_sign(0U, &cp_again, 120U, 2U);
	EQ(pqcp_fleet_transparency_witness_observe(
		   &g_wreg, &g_wst[0], &cp_again, NULL, 150U, &ev), -EALREADY);
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_REPLAY);

	/* A second record for the same witness id cannot be created. */
	{
		struct pqcp_fleet_transparency_witness_authority dup =
			g_wauth[0];

		EQ(pqcp_fleet_transparency_witness_upsert(&g_wreg, &dup),
		   -ESTALE);
	}
	OK(pqcp_fleet_transparency_witness_registry_verify(&g_wreg));
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &cp_again, wit_policy(2U, 2U, 0U, 0U), 200U, &q));
	EQ(q.witness_count, 1U);
	zassert_false(q.reached);
}

ZTEST(fleet_transparency, test_witness_rejects_unknown_revoked_expired_forged)
{
	struct pqcp_fleet_transparency_witness_quorum q;
	tev_t ev;

	build_log(&g_log_a, g_store_a, 5U, NO_FORK);
	mk_cp(&g_cp[0], g_cpsig[0], &g_log_a, 100U, 1U);
	wit_setup(2U);

	/* Unknown witness. */
	wit_make(3U, PQCP_FLEET_TRANSPARENCY_WITNESS_DEVICE, 1U);
	EQ(wit_observe(3U, &g_cp[0], NULL, 100U, 1U, 150U, &ev), -ENOENT);

	/* Observation claimed from the future. */
	wit_sign(0U, &g_cp[0], 500U, 1U);
	EQ(pqcp_fleet_transparency_witness_observe(
		   &g_wreg, &g_wst[0], &g_cp[0], NULL, 150U, &ev), -EINVAL);

	/* Forged statement: signed with a key the registry does not trust. */
	OK(pqcp_fleet_transparency_witness_statement_sign(
		&g_wauth[0], &g_cp[0], 100U, 1U, &g_hash, &g_bad_sig,
		g_wsig[0], SIGBUF, &g_wst[0]));
	EQ(pqcp_fleet_transparency_witness_observe(
		   &g_wreg, &g_wst[0], &g_cp[0], NULL, 150U, &ev),
	   -EKEYREJECTED);
	zassert_false(g_wrec[0].has_observation);

	/* Tampered statement fields. */
	wit_sign(0U, &g_cp[0], 100U, 1U);
	g_wst[0].sequence += 1U;
	EQ(pqcp_fleet_transparency_witness_observe(
		   &g_wreg, &g_wst[0], &g_cp[0], NULL, 150U, &ev),
	   -EKEYREJECTED);
	wit_sign(0U, &g_cp[0], 100U, 1U);
	flip(g_wsig[0], 3U, 0x02);
	EQ(pqcp_fleet_transparency_witness_observe(
		   &g_wreg, &g_wst[0], &g_cp[0], NULL, 150U, &ev),
	   -EKEYREJECTED);
	zassert_false(g_wrec[0].has_observation);

	/* Statement about a different checkpoint than the one presented. */
	mk_cp(&g_cp[1], g_cpsig[1], &g_log_a, 101U, 2U);
	wit_sign(0U, &g_cp[1], 100U, 1U);
	EQ(pqcp_fleet_transparency_witness_observe(
		   &g_wreg, &g_wst[0], &g_cp[0], NULL, 150U, &ev),
	   -EKEYREJECTED);

	/* Checkpoint signed by a key that is not the trusted log key. */
	{
		struct pqcp_fleet_transparency_snapshot snap;

		OK(pqcp_fleet_transparency_log_snapshot(&g_log_a, &snap));
		OK(pqcp_fleet_transparency_checkpoint_sign(
			&snap, 100U, 1U, g_otherkey, &g_hash, &g_sig,
			g_cpsig[2], SIGBUF, &g_cp[2]));
	}
	EQ(wit_observe(0U, &g_cp[2], NULL, 100U, 1U, 150U, &ev),
	   -EKEYREJECTED);

	/* Registry-side expiry: statement outside the registered window. */
	{
		struct pqcp_fleet_transparency_witness_authority shrunk =
			g_wauth[1];

		shrunk.generation = 2U;
		shrunk.expires_at_ms = 1000U;
		OK(pqcp_fleet_transparency_witness_upsert(&g_wreg, &shrunk));
		g_wauth[1] = shrunk;
		g_wauth[1].expires_at_ms = W_EXPIRES;
		EQ(wit_observe(1U, &g_cp[0], NULL, 1500U, 1U, 2000U, &ev),
		   -EKEYEXPIRED);
	}

	/* Revoked witness: old-generation statement is refused. */
	OK(pqcp_fleet_transparency_witness_revoke(
		&g_wreg, g_wauth[0].witness_id, 140U));
	EQ(wit_observe(0U, &g_cp[0], NULL, 100U, 1U, 150U, &ev),
	   -EKEYREVOKED);

	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[0], wit_policy(1U, 1U, 0U, 0U), 200U, &q));
	EQ(q.witness_count, 0U);
	OK(pqcp_fleet_transparency_witness_registry_verify(&g_wreg));
}

ZTEST(fleet_transparency, test_witness_revocation_and_expiry_remove_from_quorum)
{
	struct pqcp_fleet_transparency_witness_quorum q;
	tev_t ev;

	build_log(&g_log_a, g_store_a, 5U, NO_FORK);
	mk_cp(&g_cp[0], g_cpsig[0], &g_log_a, 100U, 1U);
	wit_setup(2U);
	OK(wit_observe(0U, &g_cp[0], NULL, 100U, 1U, 150U, &ev));
	OK(wit_observe(1U, &g_cp[0], NULL, 100U, 1U, 150U, &ev));
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[0], wit_policy(2U, 3U, 0U, 0U), 200U, &q));
	zassert_true(q.reached);

	/* Observation older than the allowed age is not counted. */
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[0], wit_policy(2U, 3U, 0U, 50U), 200U, &q));
	EQ(q.witness_count, 0U);
	zassert_false(q.reached);
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[0], wit_policy(2U, 3U, 0U, 100U), 200U, &q));
	EQ(q.witness_count, 2U);

	/* Evaluation clock before the observation. */
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[0], wit_policy(1U, 1U, 0U, 0U), 50U, &q));
	EQ(q.witness_count, 0U);

	/* Authority expiry window. */
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[0], wit_policy(1U, 1U, 0U, 0U), W_EXPIRES,
		&q));
	EQ(q.witness_count, 0U);

	/* Revoked witnesses lose their vote immediately. */
	OK(pqcp_fleet_transparency_witness_revoke(
		&g_wreg, g_wauth[1].witness_id, 160U));
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[0], wit_policy(1U, 1U, 0U, 0U), 200U, &q));
	EQ(q.witness_count, 1U);
	EQ(q.total_weight, 1U);

	/* Quorum is bound to the exact checkpoint transcript. */
	mk_cp(&g_cp[1], g_cpsig[1], &g_log_a, 101U, 2U);
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[1], wit_policy(1U, 1U, 0U, 0U), 200U, &q));
	EQ(q.witness_count, 0U);

	/* A checkpoint with an untrusted signer cannot be evaluated. */
	{
		struct pqcp_fleet_transparency_snapshot snap;

		OK(pqcp_fleet_transparency_log_snapshot(&g_log_a, &snap));
		OK(pqcp_fleet_transparency_checkpoint_sign(
			&snap, 100U, 1U, g_otherkey, &g_hash, &g_sig,
			g_cpsig[2], SIGBUF, &g_cp[2]));
	}
	EQ(pqcp_fleet_transparency_witness_quorum_evaluate(
		   &g_wreg, &g_cp[2], wit_policy(1U, 1U, 0U, 0U), 200U, &q),
	   -EKEYREJECTED);
}

ZTEST(fleet_transparency, test_witness_equivocation_evidence_for_split_view)
{
	struct pqcp_fleet_transparency_witness_quorum q;
	tev_t ev;
	tev_t ev2;
	uint8_t zero[DIG] = { 0 };

	build_log(&g_log_a, g_store_a, 5U, NO_FORK);
	build_log(&g_log_b, g_store_b, 5U, 4U);
	mk_cp(&g_cp[0], g_cpsig[0], &g_log_a, 100U, 1U);
	mk_cp(&g_cp[1], g_cpsig[1], &g_log_b, 120U, 2U);
	/* Both checkpoints are validly signed by the trusted log key. */
	OK(pqcp_fleet_transparency_checkpoint_verify(
		&g_cp[0], &g_hash, &g_sig));
	OK(pqcp_fleet_transparency_checkpoint_verify(
		&g_cp[1], &g_hash, &g_sig));
	EQ(g_cp[0].tree_size, g_cp[1].tree_size);

	wit_setup(1U);
	OK(wit_observe(0U, &g_cp[0], NULL, 100U, 1U, 150U, &ev));
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_NONE);

	EQ(wit_observe(0U, &g_cp[1], NULL, 120U, 2U, 150U, &ev),
	   -EKEYREJECTED);
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_EQUIVOCATION);
	EQ(ev.first_tree_size, 5U);
	EQ(ev.second_tree_size, 5U);
	EQ(ev.first_sequence, 1U);
	EQ(ev.second_sequence, 2U);
	EQ(ev.detected_at_ms, 150U);
	zassert_mem_equal(ev.first_root, g_log_a.root, DIG);
	zassert_mem_equal(ev.second_root, g_log_b.root, DIG);
	zassert_mem_equal(ev.participant_id, g_wauth[0].witness_id, DIG);
	zassert_not_equal(memcmp(ev.evidence_digest, zero, DIG), 0);
	zassert_not_equal(memcmp(ev.first_statement_digest,
				 ev.second_statement_digest, DIG), 0);

	/* Evidence digest is deterministic for the same incident. */
	EQ(wit_observe(0U, &g_cp[1], NULL, 120U, 2U, 150U, &ev2),
	   -EKEYREJECTED);
	zassert_mem_equal(ev.evidence_digest, ev2.evidence_digest, DIG);
	/* ...and sensitive to the detection details. */
	EQ(wit_observe(0U, &g_cp[1], NULL, 120U, 2U, 151U, &ev2),
	   -EKEYREJECTED);
	zassert_not_equal(memcmp(ev.evidence_digest, ev2.evidence_digest,
				 DIG), 0);

	/* The recorded view is untouched by the conflicting statement. */
	EQ(g_wrec[0].latest_sequence, 1U);
	zassert_mem_equal(g_wrec[0].latest_root, g_log_a.root, DIG);
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[0], wit_policy(1U, 1U, 0U, 0U), 200U, &q));
	zassert_true(q.reached);
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[1], wit_policy(1U, 1U, 0U, 0U), 200U, &q));
	zassert_false(q.reached);
	OK(pqcp_fleet_transparency_witness_registry_verify(&g_wreg));

	/* Passing NULL evidence still rejects. */
	EQ(wit_observe(0U, &g_cp[1], NULL, 120U, 2U, 150U, NULL),
	   -EKEYREJECTED);
}

ZTEST(fleet_transparency, test_witness_rollback_and_growth_evidence)
{
	tcons_t p5_9;
	tcons_t wrong;
	tlog_t five;
	tev_t ev;
	static uint8_t store_five[LOG_CAP][DIG];

	build_log(&g_log_a, g_store_a, 9U, NO_FORK);
	build_log(&five, store_five, 5U, NO_FORK);
	build_log(&g_log_b, g_store_b, 9U, 2U);
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_a, 5U, 9U, &p5_9));

	mk_cp(&g_cp[0], g_cpsig[0], &five, 100U, 1U);
	mk_cp(&g_cp[1], g_cpsig[1], &g_log_a, 200U, 2U);
	mk_cp(&g_cp[2], g_cpsig[2], &five, 300U, 3U);
	mk_cp(&g_cp[3], g_cpsig[3], &g_log_b, 400U, 4U);

	wit_setup(1U);
	OK(wit_observe(0U, &g_cp[0], NULL, 100U, 1U, 500U, &ev));

	/* Missing proof for growth: inconsistent-growth evidence. */
	EQ(wit_observe(0U, &g_cp[1], NULL, 200U, 2U, 500U, &ev), -EBADMSG);
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_INCONSISTENT_GROWTH);
	EQ(ev.first_tree_size, 5U);
	EQ(ev.second_tree_size, 9U);
	EQ(g_wrec[0].latest_tree_size, 5U);

	/* Valid growth with the right proof. */
	OK(wit_observe(0U, &g_cp[1], &p5_9, 200U, 2U, 500U, &ev));
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_NONE);
	EQ(g_wrec[0].latest_tree_size, 9U);
	zassert_mem_equal(g_wrec[0].latest_root, g_log_a.root, DIG);

	/* Rolling back to the smaller tree is rejected with evidence. */
	EQ(wit_observe(0U, &g_cp[2], NULL, 300U, 3U, 500U, &ev), -ESTALE);
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_ROLLBACK);
	EQ(ev.first_tree_size, 9U);
	EQ(ev.second_tree_size, 5U);
	EQ(g_wrec[0].latest_tree_size, 9U);
	EQ(g_wrec[0].latest_sequence, 2U);

	/* A fork of the same size is equivocation, not growth. */
	EQ(wit_observe(0U, &g_cp[3], NULL, 400U, 4U, 500U, &ev),
	   -EKEYREJECTED);
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_EQUIVOCATION);

	/* Fork that grows from a diverged history cannot reuse A's proof. */
	{
		tlog_t seven;
		static uint8_t store_seven[LOG_CAP][DIG];

		build_log(&seven, store_seven, 7U, NO_FORK);
		mk_cp(&g_cp[4], g_cpsig[4], &seven, 450U, 5U);
		/* Fresh witness state at size 7, then B(9) with A's 5->9. */
		wit_setup(1U);
		OK(wit_observe(0U, &g_cp[4], NULL, 450U, 1U, 500U, &ev));
		OK(pqcp_fleet_transparency_consistency_proof_generate(
			&g_log_a, 7U, 9U, &wrong));
		/* Proof for correct sizes but B's new root is not covered. */
		EQ(wit_observe(0U, &g_cp[3], &wrong, 400U, 2U, 500U, &ev),
		   -EBADMSG);
		EQ(ev.kind,
		   PQCP_FLEET_TRANSPARENCY_EVIDENCE_INCONSISTENT_GROWTH);
		EQ(g_wrec[0].latest_tree_size, 7U);
	}
}

/* ------------------------------------------------------------------ */
/* Gossip / split-view detection                                       */
/* ------------------------------------------------------------------ */

#define PEER_CAP 4U

static struct pqcp_fleet_transparency_gossip_monitor g_mon;
static struct pqcp_fleet_transparency_gossip_peer g_peers[PEER_CAP];
static struct pqcp_fleet_transparency_gossip_peer g_peer_def[PEER_CAP];
static struct pqcp_fleet_transparency_gossip_message g_msg[PEER_CAP];
static uint8_t g_msgsig[PEER_CAP][SIGBUF];

static void gossip_setup(size_t peer_count)
{
	OK(pqcp_fleet_transparency_gossip_monitor_init(
		&g_mon, g_log_id, g_peers, PEER_CAP, &g_hash, &g_sig));
	for (size_t i = 0U; i < peer_count; ++i) {
		memset(&g_peer_def[i], 0, sizeof(g_peer_def[i]));
		g_peer_def[i].schema_version =
			PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION;
		g_peer_def[i].generation = 1U;
		g_peer_def[i].not_before_ms = 0U;
		g_peer_def[i].expires_at_ms = 100000U;
		g_peer_def[i].state =
			PQCP_FLEET_TRANSPARENCY_GOSSIP_PEER_ACTIVE;
		fill_id(g_peer_def[i].peer_id, (uint8_t)(0xC0U + i));
		fill_id(g_peer_def[i].key_id, (uint8_t)(0xE0U + i));
		OK(pqcp_fleet_transparency_gossip_peer_upsert(
			&g_mon, &g_peer_def[i]));
	}
}

static int gossip_send(
	size_t peer, const tcp_t *cp, uint64_t sent, uint64_t seq,
	const tcons_t *proof, uint64_t received, tev_t *ev)
{
	OK(pqcp_fleet_transparency_gossip_message_sign(
		&g_peer_def[peer], cp, sent, seq, &g_hash, &g_sig,
		g_msgsig[peer], SIGBUF, &g_msg[peer]));
	return pqcp_fleet_transparency_gossip_submit(
		&g_mon, &g_msg[peer], proof, received, ev);
}

ZTEST(fleet_transparency, test_gossip_detects_split_view_between_peers)
{
	tev_t ev;
	uint64_t generation;

	build_log(&g_log_a, g_store_a, 5U, NO_FORK);
	build_log(&g_log_b, g_store_b, 5U, 4U);
	mk_cp(&g_cp[0], g_cpsig[0], &g_log_a, 100U, 1U);
	mk_cp(&g_cp[1], g_cpsig[1], &g_log_b, 100U, 1U);
	gossip_setup(3U);

	OK(gossip_send(0U, &g_cp[0], 110U, 1U, NULL, 120U, &ev));
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_NONE);
	generation = g_mon.generation;

	/* Peer 1 reports a different root for the same tree size. */
	EQ(gossip_send(1U, &g_cp[1], 110U, 1U, NULL, 120U, &ev),
	   -EKEYREJECTED);
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_EQUIVOCATION);
	zassert_mem_equal(ev.participant_id, g_peer_def[1].peer_id, DIG);
	EQ(ev.first_tree_size, 5U);
	EQ(ev.second_tree_size, 5U);
	zassert_mem_equal(ev.first_root, g_log_a.root, DIG);
	zassert_mem_equal(ev.second_root, g_log_b.root, DIG);
	/* Monitor state is not advanced by the conflicting message. */
	EQ(g_mon.generation, generation);
	zassert_false(g_peers[1].has_summary);

	/* A peer that agrees with the first is accepted. */
	OK(gossip_send(2U, &g_cp[0], 110U, 1U, NULL, 120U, &ev));
	EQ(g_mon.generation, generation + 1U);
	zassert_true(g_peers[2].has_summary);

	/* Local view comparison. */
	OK(pqcp_fleet_transparency_gossip_compare(
		&g_mon, &g_cp[0], NULL, 130U, &ev));
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_NONE);
	EQ(pqcp_fleet_transparency_gossip_compare(
		   &g_mon, &g_cp[1], NULL, 130U, &ev), -EKEYREJECTED);
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_EQUIVOCATION);
	zassert_mem_equal(ev.second_root, g_log_b.root, DIG);
}

ZTEST(fleet_transparency, test_gossip_detects_fork_after_shared_prefix)
{
	tcons_t a5_9;
	tcons_t b5_9;
	tlog_t five;
	tev_t ev;
	static uint8_t store_five[LOG_CAP][DIG];

	/* Fork diverges at index 6: both histories contain A's 5-leaf tree. */
	build_log(&g_log_a, g_store_a, 9U, NO_FORK);
	build_log(&g_log_b, g_store_b, 9U, 6U);
	build_log(&five, store_five, 5U, NO_FORK);
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_a, 5U, 9U, &a5_9));
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_b, 5U, 9U, &b5_9));
	zassert_mem_equal(a5_9.old_root, b5_9.old_root, DIG);
	mk_cp(&g_cp[0], g_cpsig[0], &five, 100U, 1U);
	mk_cp(&g_cp[1], g_cpsig[1], &g_log_a, 200U, 2U);
	mk_cp(&g_cp[2], g_cpsig[2], &g_log_b, 200U, 3U);

	gossip_setup(2U);
	OK(gossip_send(0U, &g_cp[0], 100U, 1U, NULL, 110U, &ev));
	OK(gossip_send(1U, &g_cp[0], 100U, 1U, NULL, 110U, &ev));
	OK(gossip_send(0U, &g_cp[1], 200U, 2U, &a5_9, 210U, &ev));
	/* Peer 1 grows along the forked branch with a perfectly valid proof;
	 * only the cross-peer check can expose the split view.
	 */
	EQ(gossip_send(1U, &g_cp[2], 200U, 2U, &b5_9, 210U, &ev),
	   -EKEYREJECTED);
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_EQUIVOCATION);
	zassert_mem_equal(ev.participant_id, g_peer_def[1].peer_id, DIG);
	zassert_mem_equal(ev.first_root, g_log_a.root, DIG);
	zassert_mem_equal(ev.second_root, g_log_b.root, DIG);
	EQ(g_peers[1].latest_tree_size, 5U);
}

ZTEST(fleet_transparency, test_gossip_rejects_rollback_replay_and_bad_growth)
{
	tcons_t a5_9;
	tlog_t five;
	tev_t ev;
	static uint8_t store_five[LOG_CAP][DIG];

	build_log(&g_log_a, g_store_a, 9U, NO_FORK);
	build_log(&five, store_five, 5U, NO_FORK);
	build_log(&g_log_b, g_store_b, 9U, 1U);
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_a, 5U, 9U, &a5_9));
	mk_cp(&g_cp[0], g_cpsig[0], &five, 100U, 1U);
	mk_cp(&g_cp[1], g_cpsig[1], &g_log_a, 200U, 2U);
	mk_cp(&g_cp[2], g_cpsig[2], &g_log_b, 300U, 3U);

	gossip_setup(1U);
	OK(gossip_send(0U, &g_cp[0], 100U, 1U, NULL, 110U, &ev));

	/* Growth requires a proof. */
	EQ(gossip_send(0U, &g_cp[1], 200U, 2U, NULL, 210U, &ev), -EBADMSG);
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_INCONSISTENT_GROWTH);
	/* Growth onto a diverged history cannot reuse A's proof. */
	EQ(gossip_send(0U, &g_cp[2], 300U, 3U, &a5_9, 310U, &ev), -EBADMSG);
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_INCONSISTENT_GROWTH);
	EQ(g_peers[0].latest_tree_size, 5U);

	OK(gossip_send(0U, &g_cp[1], 200U, 2U, &a5_9, 210U, &ev));
	EQ(g_peers[0].latest_tree_size, 9U);

	/* Rollback to 5 with a fresh sequence. */
	EQ(gossip_send(0U, &g_cp[0], 400U, 4U, NULL, 410U, &ev), -ESTALE);
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_ROLLBACK);
	/* Replay of an old sequence number. */
	EQ(gossip_send(0U, &g_cp[1], 400U, 2U, NULL, 410U, &ev), -EALREADY);
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_REPLAY);
	/* Same peer flip-flops to another root at the same size. */
	EQ(gossip_send(0U, &g_cp[2], 400U, 5U, NULL, 410U, &ev),
	   -EKEYREJECTED);
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_EQUIVOCATION);
	EQ(g_peers[0].latest_tree_size, 9U);
	EQ(g_peers[0].latest_sequence, 2U);
	zassert_mem_equal(g_peers[0].latest_root, g_log_a.root, DIG);
}

ZTEST(fleet_transparency, test_gossip_rejects_unknown_tampered_and_revoked_peers)
{
	struct pqcp_fleet_transparency_gossip_peer upd;
	tev_t ev;
	uint8_t zero[DIG] = { 0 };

	build_log(&g_log_a, g_store_a, 5U, NO_FORK);
	mk_cp(&g_cp[0], g_cpsig[0], &g_log_a, 100U, 1U);
	gossip_setup(1U);

	/* Unknown peer. */
	memset(&g_peer_def[3], 0, sizeof(g_peer_def[3]));
	g_peer_def[3] = g_peer_def[0];
	fill_id(g_peer_def[3].peer_id, 0xF3);
	EQ(gossip_send(3U, &g_cp[0], 110U, 1U, NULL, 120U, &ev), -ENOENT);

	/* Tampered fields invalidate the transcript. */
	OK(pqcp_fleet_transparency_gossip_message_sign(
		&g_peer_def[0], &g_cp[0], 110U, 1U, &g_hash, &g_sig,
		g_msgsig[0], SIGBUF, &g_msg[0]));
	g_msg[0].tree_size += 1U;
	EQ(pqcp_fleet_transparency_gossip_submit(
		   &g_mon, &g_msg[0], NULL, 120U, &ev), -EKEYREJECTED);
	g_msg[0].tree_size -= 1U;
	flip(g_msg[0].root, 0U, 0x01);
	EQ(pqcp_fleet_transparency_gossip_submit(
		   &g_mon, &g_msg[0], NULL, 120U, &ev), -EKEYREJECTED);
	flip(g_msg[0].root, 0U, 0x01);
	flip(g_msgsig[0], 1U, 0x08);
	EQ(pqcp_fleet_transparency_gossip_submit(
		   &g_mon, &g_msg[0], NULL, 120U, &ev), -EKEYREJECTED);
	flip(g_msgsig[0], 1U, 0x08);
	/* Wrong log. */
	flip(g_msg[0].log_id, 0U, 0x01);
	EQ(pqcp_fleet_transparency_gossip_submit(
		   &g_mon, &g_msg[0], NULL, 120U, &ev), -EKEYREJECTED);
	flip(g_msg[0].log_id, 0U, 0x01);
	/* Sent in the future. */
	EQ(pqcp_fleet_transparency_gossip_submit(
		   &g_mon, &g_msg[0], NULL, 100U, &ev), -EINVAL);
	/* Forged by another key. */
	OK(pqcp_fleet_transparency_gossip_message_sign(
		&g_peer_def[0], &g_cp[0], 110U, 1U, &g_hash, &g_bad_sig,
		g_msgsig[0], SIGBUF, &g_msg[0]));
	EQ(pqcp_fleet_transparency_gossip_submit(
		   &g_mon, &g_msg[0], NULL, 120U, &ev), -EKEYREJECTED);
	zassert_false(g_peers[0].has_summary);

	/* Genuine message passes; then the peer is suspended. */
	OK(gossip_send(0U, &g_cp[0], 110U, 1U, NULL, 120U, &ev));
	upd = g_peer_def[0];
	upd.generation = 2U;
	upd.state = PQCP_FLEET_TRANSPARENCY_GOSSIP_PEER_SUSPENDED;
	OK(pqcp_fleet_transparency_gossip_peer_upsert(&g_mon, &upd));
	zassert_false(g_peers[0].has_summary);
	EQ(gossip_send(0U, &g_cp[0], 130U, 2U, NULL, 140U, &ev),
	   -EKEYREVOKED);
	/* Stale peer generation upsert is refused. */
	EQ(pqcp_fleet_transparency_gossip_peer_upsert(&g_mon, &g_peer_def[0]),
	   -ESTALE);
	/* Outside the validity window. */
	upd.generation = 3U;
	upd.state = PQCP_FLEET_TRANSPARENCY_GOSSIP_PEER_ACTIVE;
	upd.expires_at_ms = 200U;
	OK(pqcp_fleet_transparency_gossip_peer_upsert(&g_mon, &upd));
	g_peer_def[0] = upd;
	g_peer_def[0].expires_at_ms = 100000U; /* signer still willing */
	EQ(gossip_send(0U, &g_cp[0], 250U, 1U, NULL, 260U, &ev),
	   -EKEYREVOKED);

	/* Init argument validation. */
	EQ(pqcp_fleet_transparency_gossip_monitor_init(
		   &g_mon, zero, g_peers, PEER_CAP, &g_hash, &g_sig),
	   -EINVAL);
	EQ(pqcp_fleet_transparency_gossip_monitor_init(
		   &g_mon, g_log_id, g_peers, 0U, &g_hash, &g_sig),
	   -EINVAL);
}

ZTEST(fleet_transparency, test_gossip_compare_validates_growth_against_peers)
{
	tcons_t a5_9;
	tcons_t a5_9_bad;
	tlog_t five;
	tev_t ev;
	static uint8_t store_five[LOG_CAP][DIG];

	build_log(&g_log_a, g_store_a, 9U, NO_FORK);
	build_log(&five, store_five, 5U, NO_FORK);
	build_log(&g_log_b, g_store_b, 9U, 3U);
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_a, 5U, 9U, &a5_9));
	OK(pqcp_fleet_transparency_consistency_proof_generate(
		&g_log_b, 5U, 9U, &a5_9_bad));
	mk_cp(&g_cp[0], g_cpsig[0], &five, 100U, 1U);
	mk_cp(&g_cp[1], g_cpsig[1], &g_log_a, 200U, 2U);
	mk_cp(&g_cp[2], g_cpsig[2], &g_log_b, 200U, 3U);

	gossip_setup(2U);
	/* No summaries yet: nothing to compare against. */
	OK(pqcp_fleet_transparency_gossip_compare(
		&g_mon, &g_cp[1], NULL, 300U, &ev));
	OK(gossip_send(0U, &g_cp[0], 100U, 1U, NULL, 110U, &ev));

	/* Local tree is newer than the peer's: needs a valid proof. */
	OK(pqcp_fleet_transparency_gossip_compare(
		&g_mon, &g_cp[1], &a5_9, 300U, &ev));
	EQ(pqcp_fleet_transparency_gossip_compare(
		   &g_mon, &g_cp[1], NULL, 300U, &ev), -EBADMSG);
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_INCONSISTENT_GROWTH);
	EQ(pqcp_fleet_transparency_gossip_compare(
		   &g_mon, &g_cp[2], &a5_9, 300U, &ev), -EBADMSG);
	/* Peer's own prefix does not belong to a fork diverged at index 3. */
	EQ(pqcp_fleet_transparency_gossip_compare(
		   &g_mon, &g_cp[2], &a5_9_bad, 300U, &ev), -EBADMSG);
	EQ(ev.kind, PQCP_FLEET_TRANSPARENCY_EVIDENCE_INCONSISTENT_GROWTH);

	/* Local tree older than the peer's: proof direction is reversed. */
	OK(gossip_send(1U, &g_cp[1], 200U, 1U, NULL, 210U, &ev));
	/* Peer 1 had no prior summary, so it accepted size 9 directly. */
	zassert_true(g_peers[1].has_summary);
	OK(pqcp_fleet_transparency_gossip_compare(
		&g_mon, &g_cp[0], &a5_9, 300U, &ev));
	EQ(pqcp_fleet_transparency_gossip_compare(
		   &g_mon, &g_cp[0], NULL, 300U, &ev), -EBADMSG);

	/* Untrusted/tampered local checkpoint is refused before comparing. */
	g_cp[3] = g_cp[1];
	flip(g_cp[3].root, 0U, 0x01);
	EQ(pqcp_fleet_transparency_gossip_compare(
		   &g_mon, &g_cp[3], &a5_9, 300U, &ev), -EKEYREJECTED);
	/* Checkpoint for another log. */
	build_log_id(&g_log_b, g_store_b, LOG_CAP, 5U, NO_FORK,
		     g_other_log_id);
	mk_cp(&g_cp[4], g_cpsig[4], &g_log_b, 100U, 1U);
	EQ(pqcp_fleet_transparency_gossip_compare(
		   &g_mon, &g_cp[4], NULL, 300U, &ev), -EINVAL);
}

/* ------------------------------------------------------------------ */
/* Fleet approval                                                      */
/* ------------------------------------------------------------------ */

typedef struct pqcp_fleet_approval_authority aauth_t;
typedef struct pqcp_fleet_approval_policy apol_t;
typedef struct pqcp_fleet_approval_session asess_t;
typedef struct pqcp_fleet_approval_vote avote_t;
typedef struct pqcp_fleet_approval_certificate acert_t;

#define A_CAP 8U
#define A_VOTES 8U
#define A_EXPIRES 1000000U
#define ALL_ACTIONS \
	(((UINT64_C(1) << PQCP_FLEET_APPROVAL_ACTION_COUNT) - 1U) & \
	 ~UINT64_C(1))
#define ACT_BIT(a) PQCP_FLEET_APPROVAL_ACTION_BIT(a)

#define R_SEC PQCP_FLEET_APPROVAL_ROLE_SECURITY
#define R_OPS PQCP_FLEET_APPROVAL_ROLE_OPERATIONS
#define R_COMP PQCP_FLEET_APPROVAL_ROLE_COMPLIANCE
#define R_VEND PQCP_FLEET_APPROVAL_ROLE_VENDOR
#define R_OWN PQCP_FLEET_APPROVAL_ROLE_OWNER
#define R_REC PQCP_FLEET_APPROVAL_ROLE_RECOVERY

#define D_APPROVE PQCP_FLEET_APPROVAL_DECISION_APPROVE
#define D_DENY PQCP_FLEET_APPROVAL_DECISION_DENY

static aauth_t g_auth[A_CAP];
static aauth_t g_auth_def[A_CAP];
static struct pqcp_fleet_approval_authority_set g_aset;
static apol_t g_pol;
static struct pqcp_fleet_approval_session_request g_req;
static asess_t g_sess;
static struct pqcp_fleet_approval_vote_record g_vrec[A_VOTES];
static uint8_t g_varena[A_VOTES * SIGLEN];
static avote_t g_vote[A_CAP];
static uint8_t g_vsig[A_CAP][SIGBUF];
static struct pqcp_fleet_approval_certificate_vote g_cvotes[A_VOTES];
static uint8_t g_carena[A_VOTES * SIGLEN];
static acert_t g_cert;

/* Backups to restore after mutating the certificate. */
static struct pqcp_fleet_approval_certificate_vote g_cvotes_bak[A_VOTES];
static uint8_t g_carena_bak[A_VOTES * SIGLEN];
static acert_t g_cert_bak;

static const struct {
	uint32_t roles;
	uint32_t weight;
} k_auth[6] = {
	{ R_SEC, 1U },
	{ R_OPS, 1U },
	{ R_COMP, 2U },
	{ R_VEND, 1U },
	{ R_OWN, 3U },
	{ R_SEC | R_REC, 1U },
};

static void approval_setup_set(void)
{
	OK(pqcp_fleet_approval_authority_set_init(
		&g_aset, g_auth, A_CAP, 1U, 1U, &g_hash, &g_sig));
	for (size_t i = 0U; i < 6U; ++i) {
		memset(&g_auth_def[i], 0, sizeof(g_auth_def[i]));
		g_auth_def[i].schema_version =
			PQCP_FLEET_APPROVAL_SCHEMA_VERSION;
		g_auth_def[i].generation = 1U;
		g_auth_def[i].roles = k_auth[i].roles;
		g_auth_def[i].weight = k_auth[i].weight;
		g_auth_def[i].action_mask = ALL_ACTIONS;
		g_auth_def[i].not_before_ms = 0U;
		g_auth_def[i].expires_at_ms = A_EXPIRES;
		g_auth_def[i].state = PQCP_FLEET_APPROVAL_AUTHORITY_ACTIVE;
		fill_id(g_auth_def[i].authority_id,
			(uint8_t)(0x10U * (i + 1U)));
		fill_id(g_auth_def[i].key_id, (uint8_t)(0x80U + i));
		OK(pqcp_fleet_approval_authority_upsert(
			&g_aset, &g_auth_def[i]));
	}
}

static void approval_setup_policy(
	uint32_t min_approvals, uint32_t min_weight, uint32_t req_roles,
	uint32_t veto_roles)
{
	memset(&g_pol, 0, sizeof(g_pol));
	g_pol.schema_version = PQCP_FLEET_APPROVAL_SCHEMA_VERSION;
	g_pol.generation = 1U;
	g_pol.minimum_approvals = min_approvals;
	g_pol.minimum_weight = min_weight;
	g_pol.required_roles = req_roles;
	g_pol.veto_roles = veto_roles;
	g_pol.policy_epoch = 1U;
	g_pol.revocation_epoch = 1U;
	g_pol.action_mask = ACT_BIT(PQCP_FLEET_APPROVAL_ACTION_UPDATE_ACTIVATE) |
			    ACT_BIT(PQCP_FLEET_APPROVAL_ACTION_POLICY_ACTIVATE);
	g_pol.maximum_session_lifetime_ms = 10000U;
	g_pol.enabled = true;
	fill_id(g_pol.policy_id, 0x31);
}

static void approval_default_request(void)
{
	memset(&g_req, 0, sizeof(g_req));
	g_req.action = PQCP_FLEET_APPROVAL_ACTION_UPDATE_ACTIVATE;
	g_req.created_at_ms = 1000U;
	g_req.deadline_ms = 5000U;
	g_req.policy_epoch = 1U;
	g_req.revocation_epoch = 1U;
	memset(g_req.target_id, 0x11, sizeof(g_req.target_id));
	memset(g_req.artifact_digest, 0x22, sizeof(g_req.artifact_digest));
	memset(g_req.nonce, 0x33, sizeof(g_req.nonce));
}

static int approval_open(
	const struct pqcp_fleet_approval_session_request *req,
	asess_t *session, struct pqcp_fleet_approval_vote_record *records,
	uint8_t *arena)
{
	return pqcp_fleet_approval_session_open(
		&g_aset, &g_pol, req, records, A_VOTES, arena, SIGLEN,
		session);
}

static void approval_setup_all(
	uint32_t min_approvals, uint32_t min_weight, uint32_t req_roles,
	uint32_t veto_roles)
{
	approval_setup_set();
	approval_setup_policy(min_approvals, min_weight, req_roles, veto_roles);
	approval_default_request();
	OK(approval_open(&g_req, &g_sess, g_vrec, g_varena));
}

static void sign_vote(
	size_t a, enum pqcp_fleet_approval_decision decision,
	uint64_t issued, uint64_t seq)
{
	OK(pqcp_fleet_approval_vote_sign(
		&g_auth_def[a], &g_sess, decision, issued, seq, &g_hash,
		&g_sig, g_vsig[a], SIGBUF, &g_vote[a]));
}

static int submit_vote(size_t a, uint64_t now)
{
	return pqcp_fleet_approval_vote_submit(
		&g_aset, &g_pol, &g_vote[a], now, &g_sess);
}

static int cast(
	size_t a, enum pqcp_fleet_approval_decision decision)
{
	sign_vote(a, decision, 1100U + a, a + 1U);
	return submit_vote(a, 1200U);
}

ZTEST_SUITE(fleet_approval, NULL, suite_setup, before_each, NULL, NULL);

static void expect_session_counts(uint32_t count, uint32_t weight)
{
	EQ(g_sess.approved_count, count);
	EQ(g_sess.approved_weight, weight);
}

ZTEST(fleet_approval, test_policy_validation)
{
	apol_t p;

	approval_setup_policy(2U, 2U, R_SEC, R_COMP);
	OK(pqcp_fleet_approval_policy_validate(&g_pol));
	p = g_pol;

#define EXPECT_INVALID(mutation) \
	do { \
		g_pol = p; \
		mutation; \
		EQ(pqcp_fleet_approval_policy_validate(&g_pol), -EINVAL); \
	} while (0)

	EXPECT_INVALID(g_pol.schema_version = 0U);
	EXPECT_INVALID(g_pol.generation = 0U);
	EXPECT_INVALID(g_pol.minimum_approvals = 0U);
	EXPECT_INVALID(g_pol.minimum_approvals =
		       PQCP_FLEET_APPROVAL_MAX_CERTIFICATE_VOTES + 1U);
	EXPECT_INVALID(g_pol.minimum_weight = 0U);
	EXPECT_INVALID(g_pol.policy_epoch = 0U);
	EXPECT_INVALID(g_pol.revocation_epoch = 0U);
	EXPECT_INVALID(g_pol.action_mask = 0U);
	EXPECT_INVALID(g_pol.action_mask = ACT_BIT(
		PQCP_FLEET_APPROVAL_ACTION_COUNT));
	EXPECT_INVALID(g_pol.action_mask |= 1U); /* ACTION_NONE bit */
	EXPECT_INVALID(g_pol.maximum_session_lifetime_ms = 0U);
	EXPECT_INVALID(g_pol.required_roles = 1U << 8);
	EXPECT_INVALID(g_pol.veto_roles = 1U << 9);
	EXPECT_INVALID(memset(g_pol.policy_id, 0, sizeof(g_pol.policy_id)));
	EXPECT_INVALID(g_pol.enabled = false);
	/* Witness fields must be consistent with the witness requirement. */
	EXPECT_INVALID(g_pol.minimum_witnesses = 1U);
	EXPECT_INVALID(g_pol.required_witness_roles =
		       PQCP_FLEET_TRANSPARENCY_WITNESS_AUDITOR);
	EXPECT_INVALID(g_pol.require_witnessed_checkpoint = true);
	EXPECT_INVALID({
		g_pol.require_witnessed_checkpoint = true;
		g_pol.minimum_witnesses = 2U;
	});
	EXPECT_INVALID({
		g_pol.require_witnessed_checkpoint = true;
		g_pol.minimum_witnesses = 2U;
		g_pol.minimum_witness_weight = 2U;
		g_pol.required_witness_roles = 1U << 9;
	});
#undef EXPECT_INVALID

	g_pol = p;
	g_pol.require_witnessed_checkpoint = true;
	g_pol.minimum_witnesses = 2U;
	g_pol.minimum_witness_weight = 3U;
	g_pol.required_witness_roles =
		PQCP_FLEET_TRANSPARENCY_WITNESS_AUDITOR;
	OK(pqcp_fleet_approval_policy_validate(&g_pol));
	EQ(pqcp_fleet_approval_policy_validate(NULL), -EINVAL);
}

ZTEST(fleet_approval, test_authority_set_lifecycle_and_limits)
{
	aauth_t extra;
	aauth_t small[2];
	struct pqcp_fleet_approval_authority_set tiny;
	uint64_t generation;
	uint64_t revocation_epoch;
	uint8_t unknown[PQCP_FLEET_APPROVAL_ID_BYTES];

	/* Init validation. */
	EQ(pqcp_fleet_approval_authority_set_init(
		   &g_aset, g_auth, 0U, 1U, 1U, &g_hash, &g_sig), -EINVAL);
	EQ(pqcp_fleet_approval_authority_set_init(
		   &g_aset, g_auth, A_CAP, 0U, 1U, &g_hash, &g_sig), -EINVAL);
	EQ(pqcp_fleet_approval_authority_set_init(
		   &g_aset, g_auth, A_CAP, 1U, 0U, &g_hash, &g_sig), -EINVAL);
	EQ(pqcp_fleet_approval_authority_set_init(
		   &g_aset, NULL, A_CAP, 1U, 1U, &g_hash, &g_sig), -EINVAL);
	EQ(pqcp_fleet_approval_authority_set_init(
		   &g_aset, g_auth, A_CAP, 1U, 1U, NULL, &g_sig), -EINVAL);

	approval_setup_set();
	OK(pqcp_fleet_approval_authority_set_verify(&g_aset));
	EQ(g_aset.generation, 7U);
	generation = g_aset.generation;

	/* Stale / equal generation is refused, higher is accepted. */
	extra = g_auth_def[2];
	EQ(pqcp_fleet_approval_authority_upsert(&g_aset, &extra), -ESTALE);
	extra.generation = 2U;
	extra.weight = 9U;
	OK(pqcp_fleet_approval_authority_upsert(&g_aset, &extra));
	EQ(g_auth[2].weight, 9U);
	EQ(g_aset.generation, generation + 1U);

	/* Invalid authority records. */
#define EXPECT_BAD_AUTH(mutation) \
	do { \
		extra = g_auth_def[0]; \
		extra.generation = 50U; \
		mutation; \
		EQ(pqcp_fleet_approval_authority_upsert(&g_aset, &extra), \
		   -EINVAL); \
	} while (0)
	EXPECT_BAD_AUTH(extra.weight = 0U);
	EXPECT_BAD_AUTH(extra.roles = 0U);
	EXPECT_BAD_AUTH(extra.roles = 1U << 8);
	EXPECT_BAD_AUTH(extra.action_mask = 0U);
	EXPECT_BAD_AUTH(extra.action_mask = 1U); /* ACTION_NONE only */
	EXPECT_BAD_AUTH(extra.action_mask |= ACT_BIT(
		PQCP_FLEET_APPROVAL_ACTION_COUNT));
	EXPECT_BAD_AUTH(extra.expires_at_ms = extra.not_before_ms);
	EXPECT_BAD_AUTH(memset(extra.authority_id, 0,
			       sizeof(extra.authority_id)));
	EXPECT_BAD_AUTH(memset(extra.key_id, 0, sizeof(extra.key_id)));
	EXPECT_BAD_AUTH(extra.state = PQCP_FLEET_APPROVAL_AUTHORITY_REVOKED);
	EXPECT_BAD_AUTH(extra.revoked_at_ms = 5U);
	EXPECT_BAD_AUTH(extra.state = PQCP_FLEET_APPROVAL_AUTHORITY_EMPTY);
	EXPECT_BAD_AUTH(extra.schema_version = 0U);
#undef EXPECT_BAD_AUTH
	OK(pqcp_fleet_approval_authority_set_verify(&g_aset));

	/* Capacity. */
	OK(pqcp_fleet_approval_authority_set_init(
		&tiny, small, 2U, 1U, 1U, &g_hash, &g_sig));
	OK(pqcp_fleet_approval_authority_upsert(&tiny, &g_auth_def[0]));
	OK(pqcp_fleet_approval_authority_upsert(&tiny, &g_auth_def[1]));
	EQ(pqcp_fleet_approval_authority_upsert(&tiny, &g_auth_def[2]),
	   -ENOSPC);

	/* Revocation bumps authority generation and the revocation epoch. */
	fill_id(unknown, 0xFE);
	EQ(pqcp_fleet_approval_authority_revoke(&g_aset, unknown, 10U),
	   -ENOENT);
	EQ(pqcp_fleet_approval_authority_revoke(
		   &g_aset, g_auth_def[1].authority_id, 0U), -EINVAL);
	generation = g_aset.generation;
	revocation_epoch = g_aset.revocation_epoch;
	OK(pqcp_fleet_approval_authority_revoke(
		&g_aset, g_auth_def[1].authority_id, 10U));
	EQ(g_auth[1].state, PQCP_FLEET_APPROVAL_AUTHORITY_REVOKED);
	EQ(g_auth[1].generation, 2U);
	EQ(g_auth[1].revoked_at_ms, 10U);
	EQ(g_aset.revocation_epoch, revocation_epoch + 1U);
	EQ(g_aset.generation, generation + 1U);
	EQ(pqcp_fleet_approval_authority_revoke(
		   &g_aset, g_auth_def[1].authority_id, 11U), -EALREADY);
	OK(pqcp_fleet_approval_authority_set_verify(&g_aset));

	/* Epoch advancement is monotonic and must change something. */
	EQ(pqcp_fleet_approval_authority_set_advance_epochs(
		   &g_aset, g_aset.policy_epoch, g_aset.revocation_epoch),
	   -EINVAL);
	EQ(pqcp_fleet_approval_authority_set_advance_epochs(
		   &g_aset, g_aset.policy_epoch - 1U,
		   g_aset.revocation_epoch + 1U), -EINVAL);
	EQ(pqcp_fleet_approval_authority_set_advance_epochs(
		   &g_aset, g_aset.policy_epoch + 1U,
		   g_aset.revocation_epoch - 1U), -EINVAL);
	generation = g_aset.generation;
	OK(pqcp_fleet_approval_authority_set_advance_epochs(
		&g_aset, g_aset.policy_epoch + 1U, g_aset.revocation_epoch));
	EQ(g_aset.generation, generation + 1U);

	/* Audit detects a duplicated authority id. */
	g_auth[6] = g_auth[0];
	EQ(pqcp_fleet_approval_authority_set_verify(&g_aset), -EILSEQ);
}

ZTEST(fleet_approval, test_session_open_validation)
{
	struct pqcp_fleet_approval_session_request r;
	asess_t s;
	struct pqcp_fleet_approval_vote_record recs[A_VOTES];
	uint8_t arena[A_VOTES * SIGLEN];

	approval_setup_set();
	approval_setup_policy(3U, 4U, R_SEC, R_COMP);
	approval_default_request();
	OK(approval_open(&g_req, &s, recs, arena));
	EQ(s.state, PQCP_FLEET_APPROVAL_SESSION_OPEN);
	EQ(s.approved_count, 0U);
	EQ(s.vote_count, 0U);
	EQ(s.authority_set_generation, g_aset.generation);
	EQ(s.policy_generation, g_pol.generation);
	EQ(s.action, PQCP_FLEET_APPROVAL_ACTION_UPDATE_ACTIVATE);
	zassert_false(s.checkpoint_bound);
	{
		uint8_t zero[DIG] = { 0 };

		zassert_not_equal(
			memcmp(s.session_id, zero, sizeof(s.session_id)), 0);
	}
	r = g_req;

#define EXPECT_OPEN_FAIL(mutation, code) \
	do { \
		g_req = r; \
		mutation; \
		EQ(approval_open(&g_req, &s, recs, arena), (code)); \
	} while (0)

	EXPECT_OPEN_FAIL(g_req.policy_epoch = 2U, -EINVAL);
	EXPECT_OPEN_FAIL(g_req.revocation_epoch = 2U, -EINVAL);
	EXPECT_OPEN_FAIL(g_req.deadline_ms = g_req.created_at_ms, -EINVAL);
	EXPECT_OPEN_FAIL(g_req.deadline_ms = g_req.created_at_ms - 1U,
			 -EINVAL);
	EXPECT_OPEN_FAIL(g_req.deadline_ms = g_req.created_at_ms + 10001U,
			 -EINVAL);
	EXPECT_OPEN_FAIL(g_req.action = PQCP_FLEET_APPROVAL_ACTION_NONE,
			 -EINVAL);
	EXPECT_OPEN_FAIL(g_req.action = PQCP_FLEET_APPROVAL_ACTION_COUNT,
			 -EINVAL);
	EXPECT_OPEN_FAIL(g_req.action = PQCP_FLEET_APPROVAL_ACTION_DECOMMISSION,
			 -EINVAL);
	EXPECT_OPEN_FAIL(memset(g_req.target_id, 0, sizeof(g_req.target_id)),
			 -EINVAL);
	EXPECT_OPEN_FAIL(memset(g_req.artifact_digest, 0,
				sizeof(g_req.artifact_digest)), -EINVAL);
	EXPECT_OPEN_FAIL(memset(g_req.nonce, 0, sizeof(g_req.nonce)),
			 -EINVAL);
	/* Exactly the maximum lifetime is allowed. */
	g_req = r;
	g_req.deadline_ms = g_req.created_at_ms + 10000U;
	OK(approval_open(&g_req, &s, recs, arena));
#undef EXPECT_OPEN_FAIL

	g_req = r;
	EQ(pqcp_fleet_approval_session_open(
		   &g_aset, &g_pol, &g_req, recs, 2U, arena, SIGLEN, &s),
	   -EINVAL); /* fewer vote slots than minimum_approvals */
	EQ(pqcp_fleet_approval_session_open(
		   &g_aset, &g_pol, &g_req, NULL, A_VOTES, arena, SIGLEN, &s),
	   -EINVAL);
	EQ(pqcp_fleet_approval_session_open(
		   &g_aset, &g_pol, &g_req, recs, A_VOTES, NULL, SIGLEN, &s),
	   -EINVAL);
	EQ(pqcp_fleet_approval_session_open(
		   &g_aset, &g_pol, &g_req, recs, A_VOTES, arena, 0U, &s),
	   -EINVAL);
	EQ(pqcp_fleet_approval_session_open(
		   &g_aset, &g_pol, NULL, recs, A_VOTES, arena, SIGLEN, &s),
	   -EINVAL);

	/* Disabled policy / epoch skew between policy and authority set. */
	g_pol.enabled = false;
	EQ(approval_open(&g_req, &s, recs, arena), -EINVAL);
	g_pol.enabled = true;
	g_pol.policy_epoch = 2U;
	EQ(approval_open(&g_req, &s, recs, arena), -EINVAL);
	g_pol.policy_epoch = 1U;
	g_pol.revocation_epoch = 2U;
	EQ(approval_open(&g_req, &s, recs, arena), -EINVAL);
}

ZTEST(fleet_approval, test_threshold_quorum_progression)
{
	/* 3 approvals, weight >= 5, SECURITY role mandatory. */
	approval_setup_all(3U, 5U, R_SEC, 0U);

	OK(cast(0U, D_APPROVE)); /* SEC w1 */
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_OPEN);
	expect_session_counts(1U, 1U);
	OK(cast(1U, D_APPROVE)); /* OPS w1 */
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_OPEN);
	expect_session_counts(2U, 2U);
	OK(cast(2U, D_APPROVE)); /* COMP w2: count 3, weight 4 < 5 */
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_OPEN);
	expect_session_counts(3U, 4U);
	OK(cast(4U, D_APPROVE)); /* OWN w3 */
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_QUORUM);
	expect_session_counts(4U, 7U);
	EQ(g_sess.approved_roles, R_SEC | R_OPS | R_COMP | R_OWN);
	EQ(g_sess.vote_count, 4U);
}

ZTEST(fleet_approval, test_quorum_blocks_further_signing_and_votes)
{
	approval_setup_all(2U, 2U, 0U, 0U);
	OK(cast(0U, D_APPROVE));
	OK(cast(1U, D_APPROVE));
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_QUORUM);

	/* Signing requires an OPEN session. */
	EQ(pqcp_fleet_approval_vote_sign(
		   &g_auth_def[3], &g_sess, D_APPROVE, 1200U, 9U, &g_hash,
		   &g_sig, g_vsig[3], SIGBUF, &g_vote[3]), -EINVAL);

	/* A vote signed while OPEN but delivered after quorum is refused. */
	approval_setup_all(2U, 2U, 0U, 0U);
	sign_vote(3U, D_APPROVE, 1100U, 9U);
	OK(cast(0U, D_APPROVE));
	OK(cast(1U, D_APPROVE));
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_QUORUM);
	EQ(submit_vote(3U, 1200U), -EALREADY);
	expect_session_counts(2U, 2U);
	EQ(g_sess.vote_count, 2U);
}

ZTEST(fleet_approval, test_weight_threshold_gates_quorum)
{
	/* Two approvals are enough by count but not by weight. */
	approval_setup_all(2U, 5U, 0U, 0U);
	OK(cast(0U, D_APPROVE));
	OK(cast(1U, D_APPROVE));
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_OPEN);
	expect_session_counts(2U, 2U);
	OK(cast(4U, D_APPROVE)); /* OWN w3: weight 5 */
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_QUORUM);

	/* A single heavyweight cannot satisfy the approval count alone. */
	approval_setup_all(2U, 3U, 0U, 0U);
	OK(cast(4U, D_APPROVE));
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_OPEN);
	expect_session_counts(1U, 3U);
}

ZTEST(fleet_approval, test_required_role_gates_quorum)
{
	approval_setup_all(2U, 1U, R_VEND, 0U);
	OK(cast(0U, D_APPROVE));
	OK(cast(1U, D_APPROVE));
	/* Count and weight satisfied, mandatory VENDOR role absent. */
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_OPEN);
	OK(cast(3U, D_APPROVE));
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_QUORUM);

	/* A multi-role authority supplies several roles at once. */
	approval_setup_all(2U, 2U, R_SEC | R_REC, 0U);
	OK(cast(5U, D_APPROVE)); /* SEC|RECOVERY */
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_OPEN);
	OK(cast(1U, D_APPROVE));
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_QUORUM);
}

ZTEST(fleet_approval, test_duplicate_approver_counted_once)
{
	approval_setup_all(2U, 2U, 0U, 0U);
	OK(cast(0U, D_APPROVE));
	expect_session_counts(1U, 1U);

	/* Identical vote re-submitted. */
	EQ(submit_vote(0U, 1250U), -EALREADY);
	/* A fresh vote (new sequence/time) from the same authority. */
	sign_vote(0U, D_APPROVE, 1150U, 77U);
	EQ(submit_vote(0U, 1250U), -EALREADY);
	/* A DENY after approving cannot flip the recorded decision. */
	sign_vote(0U, D_DENY, 1160U, 78U);
	EQ(submit_vote(0U, 1250U), -EALREADY);

	expect_session_counts(1U, 1U);
	EQ(g_sess.vote_count, 1U);
	EQ(g_sess.denied_roles, 0U);
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_OPEN);

	/* A second distinct approver still reaches quorum exactly then. */
	OK(cast(1U, D_APPROVE));
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_QUORUM);
	expect_session_counts(2U, 2U);
}

ZTEST(fleet_approval, test_vote_rejects_unknown_revoked_expired_authority)
{
	approval_setup_all(2U, 2U, 0U, 0U);

	/* Authority not present in the set. */
	memset(&g_auth_def[7], 0, sizeof(g_auth_def[7]));
	g_auth_def[7] = g_auth_def[0];
	fill_id(g_auth_def[7].authority_id, 0xA7);
	sign_vote(7U, D_APPROVE, 1100U, 1U);
	EQ(submit_vote(7U, 1200U), -ENOENT);

	/* Authority generation drift (key rotation). */
	sign_vote(0U, D_APPROVE, 1100U, 1U);
	g_auth[0].generation += 1U;
	EQ(submit_vote(0U, 1200U), -EKEYREVOKED);
	g_auth[0].generation -= 1U;

	/* Suspended / revoked authority. */
	g_auth[0].state = PQCP_FLEET_APPROVAL_AUTHORITY_SUSPENDED;
	EQ(submit_vote(0U, 1200U), -EKEYREVOKED);
	g_auth[0].state = PQCP_FLEET_APPROVAL_AUTHORITY_ACTIVE;

	/* Authority lost permission for the action. */
	g_auth[0].action_mask = ACT_BIT(PQCP_FLEET_APPROVAL_ACTION_DECOMMISSION);
	EQ(submit_vote(0U, 1200U), -EACCES);
	g_auth[0].action_mask = ALL_ACTIONS;

	/* Authority validity window ended before the vote was delivered. */
	g_auth[0].expires_at_ms = 1150U;
	EQ(submit_vote(0U, 1200U), -EKEYEXPIRED);
	g_auth[0].expires_at_ms = A_EXPIRES;

	EQ(g_sess.vote_count, 0U);
	expect_session_counts(0U, 0U);

	/* Nothing above poisoned the session: the honest vote still lands. */
	OK(submit_vote(0U, 1200U));
	expect_session_counts(1U, 1U);

	/* Revocation through the API invalidates the whole session. */
	OK(pqcp_fleet_approval_authority_revoke(
		&g_aset, g_auth_def[1].authority_id, 1300U));
	sign_vote(1U, D_APPROVE, 1250U, 1U);
	EQ(submit_vote(1U, 1300U), -ESTALE);
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_CANCELLED);
}

ZTEST(fleet_approval, test_vote_rejects_tampered_votes_without_state_change)
{
	approval_setup_all(2U, 2U, 0U, 0U);

	sign_vote(0U, D_DENY, 1100U, 1U);
	g_vote[0].decision = D_APPROVE; /* flip decision */
	EQ(submit_vote(0U, 1200U), -EKEYREJECTED);

	sign_vote(0U, D_APPROVE, 1100U, 1U);
	g_vote[0].issued_at_ms += 1U;
	EQ(submit_vote(0U, 1200U), -EKEYREJECTED);

	sign_vote(0U, D_APPROVE, 1100U, 1U);
	g_vote[0].sequence += 1U;
	EQ(submit_vote(0U, 1200U), -EKEYREJECTED);

	sign_vote(0U, D_APPROVE, 1100U, 1U);
	flip(g_vote[0].session_id, 0U, 0x01);
	EQ(submit_vote(0U, 1200U), -EKEYREJECTED);

	sign_vote(0U, D_APPROVE, 1100U, 1U);
	flip(g_vote[0].transcript_digest, 3U, 0x01);
	EQ(submit_vote(0U, 1200U), -EKEYREJECTED);

	sign_vote(0U, D_APPROVE, 1100U, 1U);
	flip(g_vsig[0], 5U, 0x10);
	EQ(submit_vote(0U, 1200U), -EKEYREJECTED);

	sign_vote(0U, D_APPROVE, 1100U, 1U);
	g_vote[0].signature_length = 0U;
	EQ(submit_vote(0U, 1200U), -EINVAL);

	/* Vote signed by an attacker key (right authority id, wrong key). */
	OK(pqcp_fleet_approval_vote_sign(
		&g_auth_def[0], &g_sess, D_APPROVE, 1100U, 1U, &g_hash,
		&g_bad_sig, g_vsig[0], SIGBUF, &g_vote[0]));
	EQ(submit_vote(0U, 1200U), -EKEYREJECTED);

	/* Vote timestamped in the future relative to delivery. */
	sign_vote(0U, D_APPROVE, 1300U, 1U);
	EQ(submit_vote(0U, 1200U), -EKEYREJECTED);

	/* Vote impersonating another authority id. */
	sign_vote(0U, D_APPROVE, 1100U, 1U);
	memcpy(g_vote[0].authority_id, g_auth_def[1].authority_id,
	       sizeof(g_vote[0].authority_id));
	EQ(submit_vote(0U, 1200U), -EKEYREJECTED);

	/* Wrong schema. */
	sign_vote(0U, D_APPROVE, 1100U, 1U);
	g_vote[0].schema_version = 0U;
	EQ(submit_vote(0U, 1200U), -EINVAL);

	EQ(g_sess.vote_count, 0U);
	expect_session_counts(0U, 0U);
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_OPEN);

	/* Signing guards. */
	EQ(pqcp_fleet_approval_vote_sign(
		   &g_auth_def[0], &g_sess, D_APPROVE, 999U, 1U, &g_hash,
		   &g_sig, g_vsig[0], SIGBUF, &g_vote[0]), -EINVAL);
	EQ(pqcp_fleet_approval_vote_sign(
		   &g_auth_def[0], &g_sess, D_APPROVE, 5001U, 1U, &g_hash,
		   &g_sig, g_vsig[0], SIGBUF, &g_vote[0]), -EINVAL);
	EQ(pqcp_fleet_approval_vote_sign(
		   &g_auth_def[0], &g_sess, D_APPROVE, 1100U, 0U, &g_hash,
		   &g_sig, g_vsig[0], SIGBUF, &g_vote[0]), -EINVAL);
	EQ(pqcp_fleet_approval_vote_sign(
		   &g_auth_def[0], &g_sess, PQCP_FLEET_APPROVAL_DECISION_NONE,
		   1100U, 1U, &g_hash, &g_sig, g_vsig[0], SIGBUF, &g_vote[0]),
	   -EINVAL);
}

ZTEST(fleet_approval, test_session_binds_request_digest_and_context)
{
	asess_t other;
	struct pqcp_fleet_approval_vote_record recs[A_VOTES];
	uint8_t arena[A_VOTES * SIGLEN];
	struct pqcp_fleet_approval_session_request r;
	uint8_t base_id[PQCP_FLEET_APPROVAL_ID_BYTES];

	approval_setup_all(2U, 2U, 0U, 0U);
	memcpy(base_id, g_sess.session_id, sizeof(base_id));
	r = g_req;

	/* Deterministic: opening the identical request yields the same id. */
	OK(approval_open(&r, &other, recs, arena));
	zassert_mem_equal(other.session_id, base_id, sizeof(base_id));

	/* Every bound request field changes the session identity. */
#define EXPECT_DIFFERENT_ID(mutation) \
	do { \
		g_req = r; \
		mutation; \
		OK(approval_open(&g_req, &other, recs, arena)); \
		zassert_not_equal(memcmp(other.session_id, base_id, \
					 sizeof(base_id)), 0); \
	} while (0)
	EXPECT_DIFFERENT_ID(flip(g_req.artifact_digest, 31U, 0x01));
	EXPECT_DIFFERENT_ID(flip(g_req.target_id, 0U, 0x01));
	EXPECT_DIFFERENT_ID(flip(g_req.nonce, 7U, 0x80));
	EXPECT_DIFFERENT_ID(g_req.created_at_ms += 1U);
	EXPECT_DIFFERENT_ID(g_req.deadline_ms += 1U);
	EXPECT_DIFFERENT_ID(g_req.action =
			    PQCP_FLEET_APPROVAL_ACTION_POLICY_ACTIVATE);
#undef EXPECT_DIFFERENT_ID

	/* A vote for the original request is rejected by a session whose
	 * artifact digest differs (tampered request digest / replay on
	 * another artifact).
	 */
	sign_vote(0U, D_APPROVE, 1100U, 1U);
	g_req = r;
	flip(g_req.artifact_digest, 0U, 0x01);
	OK(approval_open(&g_req, &other, recs, arena));
	EQ(pqcp_fleet_approval_vote_submit(
		   &g_aset, &g_pol, &g_vote[0], 1200U, &other),
	   -EKEYREJECTED);
	EQ(other.vote_count, 0U);
	/* The same vote is fine on the session it was issued for. */
	OK(submit_vote(0U, 1200U));

	/* Same for a different nonce (replay in a new session instance). */
	sign_vote(1U, D_APPROVE, 1100U, 1U);
	g_req = r;
	flip(g_req.nonce, 0U, 0x01);
	OK(approval_open(&g_req, &other, recs, arena));
	EQ(pqcp_fleet_approval_vote_submit(
		   &g_aset, &g_pol, &g_vote[1], 1200U, &other),
	   -EKEYREJECTED);
}

ZTEST(fleet_approval, test_veto_role_denies_session)
{
	approval_setup_all(2U, 2U, 0U, R_COMP);

	/* A deny from a non-veto role is only recorded. */
	OK(cast(1U, D_DENY));
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_OPEN);
	EQ(g_sess.denied_roles, R_OPS);
	expect_session_counts(0U, 0U);
	/* That authority has spent its vote. */
	sign_vote(1U, D_APPROVE, 1150U, 50U);
	EQ(submit_vote(1U, 1200U), -EALREADY);

	/* Votes prepared before the veto lands. */
	sign_vote(0U, D_APPROVE, 1100U, 1U);
	sign_vote(4U, D_APPROVE, 1100U, 1U);

	/* COMPLIANCE veto kills the session immediately. */
	EQ(cast(2U, D_DENY), -EACCES);
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_DENIED);
	EQ(g_sess.denied_roles, R_OPS | R_COMP);

	/* Even a complete set of approvals can no longer revive it. */
	EQ(submit_vote(0U, 1200U), -EACCES);
	EQ(submit_vote(4U, 1200U), -EACCES);
	expect_session_counts(0U, 0U);
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_DENIED);
	{
		struct pqcp_fleet_approval_certificate_vote cv[A_VOTES];
		uint8_t carena[A_VOTES * SIGLEN];
		acert_t cert;

		EQ(pqcp_fleet_approval_certificate_build(
			   &g_aset, &g_pol, &g_sess, 1300U, cv, A_VOTES,
			   carena, SIGLEN, &cert), -EACCES);
	}
}

ZTEST(fleet_approval, test_vote_before_session_start_is_not_accepted)
{
	approval_setup_all(2U, 2U, 0U, 0U);
	sign_vote(0U, D_APPROVE, 1100U, 1U);

	/* Delivery before the session starts: not yet live, nothing recorded. */
	EQ(submit_vote(0U, 999U), -EAGAIN);
	EQ(g_sess.vote_count, 0U);
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_OPEN);
	OK(submit_vote(0U, 1200U));
}

ZTEST(fleet_approval, test_session_deadline_expires_fail_closed)
{
	approval_setup_all(2U, 2U, 0U, 0U);
	sign_vote(0U, D_APPROVE, 1100U, 1U);
	sign_vote(1U, D_APPROVE, 1100U, 1U);

	/* The deadline instant itself is still valid. */
	OK(pqcp_fleet_approval_session_refresh(
		&g_aset, &g_pol, 5000U, &g_sess));
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_OPEN);
	/* Before creation the session is not yet live and is not damaged. */
	EQ(pqcp_fleet_approval_session_refresh(
		   &g_aset, &g_pol, 999U, &g_sess), -EAGAIN);
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_OPEN);

	/* One millisecond past the deadline: expired, sticky. */
	EQ(submit_vote(0U, 5001U), -ETIMEDOUT);
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_EXPIRED);
	EQ(submit_vote(1U, 1200U), -ETIMEDOUT);
	EQ(g_sess.vote_count, 0U);
	EQ(pqcp_fleet_approval_session_refresh(
		   &g_aset, &g_pol, 1200U, &g_sess), -ETIMEDOUT);
	EQ(pqcp_fleet_approval_session_cancel(&g_sess), -EALREADY);

	/* A quorum session that expires cannot yield a certificate. */
	approval_setup_all(1U, 1U, 0U, 0U);
	OK(cast(0U, D_APPROVE));
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_QUORUM);
	{
		struct pqcp_fleet_approval_certificate_vote cv[A_VOTES];
		uint8_t carena[A_VOTES * SIGLEN];
		acert_t cert;

		EQ(pqcp_fleet_approval_certificate_build(
			   &g_aset, &g_pol, &g_sess, 5001U, cv, A_VOTES,
			   carena, SIGLEN, &cert), -ETIMEDOUT);
		EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_EXPIRED);
	}
}

ZTEST(fleet_approval, test_bound_state_change_invalidates_session)
{
	/* Epoch advance. */
	approval_setup_all(2U, 2U, 0U, 0U);
	sign_vote(0U, D_APPROVE, 1100U, 1U);
	OK(pqcp_fleet_approval_authority_set_advance_epochs(&g_aset, 2U, 1U));
	EQ(submit_vote(0U, 1200U), -ESTALE);
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_CANCELLED);
	EQ(g_sess.vote_count, 0U);
	/* Cancellation is sticky: restoring nothing revives it. */
	EQ(pqcp_fleet_approval_session_refresh(
		   &g_aset, &g_pol, 1200U, &g_sess), -ESTALE);

	/* Authority-set mutation (new approver added). */
	approval_setup_all(2U, 2U, 0U, 0U);
	sign_vote(0U, D_APPROVE, 1100U, 1U);
	{
		aauth_t joiner = g_auth_def[0];

		fill_id(joiner.authority_id, 0x77);
		OK(pqcp_fleet_approval_authority_upsert(&g_aset, &joiner));
	}
	EQ(submit_vote(0U, 1200U), -ESTALE);
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_CANCELLED);

	/* Policy generation change. */
	approval_setup_all(2U, 2U, 0U, 0U);
	sign_vote(0U, D_APPROVE, 1100U, 1U);
	g_pol.generation += 1U;
	EQ(submit_vote(0U, 1200U), -ESTALE);
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_CANCELLED);

	/* Policy no longer covering the action. */
	approval_setup_all(2U, 2U, 0U, 0U);
	sign_vote(0U, D_APPROVE, 1100U, 1U);
	g_pol.action_mask = ACT_BIT(PQCP_FLEET_APPROVAL_ACTION_POLICY_ACTIVATE);
	EQ(submit_vote(0U, 1200U), -ESTALE);

	/* Quorum reached sessions are also cancelled by bound changes. */
	approval_setup_all(1U, 1U, 0U, 0U);
	OK(cast(0U, D_APPROVE));
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_QUORUM);
	OK(pqcp_fleet_approval_authority_set_advance_epochs(&g_aset, 1U, 2U));
	g_pol.revocation_epoch = 2U;
	EQ(pqcp_fleet_approval_session_refresh(
		   &g_aset, &g_pol, 1300U, &g_sess), -ESTALE);
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_CANCELLED);
}

ZTEST(fleet_approval, test_session_cancel)
{
	approval_setup_all(2U, 2U, 0U, 0U);
	sign_vote(0U, D_APPROVE, 1100U, 1U);
	OK(pqcp_fleet_approval_session_cancel(&g_sess));
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_CANCELLED);
	EQ(pqcp_fleet_approval_session_cancel(&g_sess), -EALREADY);
	EQ(submit_vote(0U, 1200U), -ECANCELED);
	EQ(g_sess.vote_count, 0U);
	EQ(pqcp_fleet_approval_session_cancel(NULL), -EINVAL);
}

/* Drive a deterministic quorum scenario and build a certificate. */
static void run_quorum_and_certify(
	const size_t *order, size_t count, uint8_t nonce_fill, uint64_t now)
{
	approval_setup_set();
	approval_setup_policy(3U, 4U, R_SEC, 0U);
	approval_default_request();
	memset(g_req.nonce, nonce_fill, sizeof(g_req.nonce));
	OK(approval_open(&g_req, &g_sess, g_vrec, g_varena));
	for (size_t i = 0U; i < count; ++i) {
		/* Same (issued_at, sequence) per authority irrespective of
		 * delivery order, so certificates must be identical.
		 */
		OK(cast(order[i], D_APPROVE));
	}
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_QUORUM);
	OK(pqcp_fleet_approval_certificate_build(
		&g_aset, &g_pol, &g_sess, now, g_cvotes, A_VOTES, g_carena,
		SIGLEN, &g_cert));
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_CERTIFIED);
}

static void backup_cert(void)
{
	memcpy(g_cvotes_bak, g_cvotes, sizeof(g_cvotes));
	memcpy(g_carena_bak, g_carena, sizeof(g_carena));
	g_cert_bak = g_cert;
}

static void restore_cert(void)
{
	memcpy(g_cvotes, g_cvotes_bak, sizeof(g_cvotes));
	memcpy(g_carena, g_carena_bak, sizeof(g_carena));
	g_cert = g_cert_bak;
}

static int verify_cert(uint64_t now)
{
	return pqcp_fleet_approval_certificate_verify(
		&g_aset, &g_pol, &g_sess, &g_cert, now);
}

ZTEST(fleet_approval, test_certificate_build_verify_and_determinism)
{
	static const size_t order_a[] = { 0U, 4U, 2U };
	static const size_t order_b[] = { 2U, 0U, 4U };
	uint8_t id_a[PQCP_FLEET_APPROVAL_ID_BYTES];
	struct pqcp_fleet_approval_certificate_vote cv[A_VOTES];
	uint8_t carena[A_VOTES * SIGLEN];
	acert_t other;

	run_quorum_and_certify(order_a, ARRAY_SIZE(order_a), 0x33U, 1500U);
	EQ(g_cert.approval_count, 3U);
	EQ(g_cert.approval_weight, 6U);
	EQ(g_cert.approval_roles, R_SEC | R_COMP | R_OWN);
	EQ(g_cert.vote_count, 3U);
	EQ(g_cert.issued_at_ms, 1500U);
	EQ(g_cert.expires_at_ms, 5000U);
	EQ(g_cert.action, PQCP_FLEET_APPROVAL_ACTION_UPDATE_ACTIVATE);
	zassert_mem_equal(g_cert.session_id, g_sess.session_id,
			  sizeof(g_cert.session_id));
	zassert_mem_equal(g_cert.artifact_digest, g_req.artifact_digest,
			  sizeof(g_cert.artifact_digest));
	zassert_mem_equal(g_cert.target_id, g_req.target_id,
			  sizeof(g_cert.target_id));
	/* Votes sorted strictly ascending by authority id. */
	for (size_t i = 1U; i < g_cert.vote_count; ++i) {
		zassert_true(memcmp(g_cvotes[i - 1U].authority_id,
				    g_cvotes[i].authority_id,
				    PQCP_FLEET_APPROVAL_ID_BYTES) < 0);
	}
	zassert_mem_equal(g_cvotes[0].authority_id,
			  g_auth_def[0].authority_id,
			  PQCP_FLEET_APPROVAL_ID_BYTES);
	OK(verify_cert(1600U));
	OK(verify_cert(1500U));
	OK(verify_cert(5000U));
	memcpy(id_a, g_cert.certificate_id, sizeof(id_a));

	/* Delivery order does not influence the certificate. */
	run_quorum_and_certify(order_b, ARRAY_SIZE(order_b), 0x33U, 1500U);
	zassert_mem_equal(id_a, g_cert.certificate_id, sizeof(id_a));
	OK(verify_cert(1600U));

	/* Different issuance time changes the certificate id. */
	run_quorum_and_certify(order_b, ARRAY_SIZE(order_b), 0x33U, 1501U);
	zassert_not_equal(memcmp(id_a, g_cert.certificate_id, sizeof(id_a)), 0);
	/* Different session nonce changes it too. */
	run_quorum_and_certify(order_b, ARRAY_SIZE(order_b), 0x34U, 1500U);
	zassert_not_equal(memcmp(id_a, g_cert.certificate_id, sizeof(id_a)), 0);

	/* Build is only possible from QUORUM, exactly once. */
	EQ(pqcp_fleet_approval_certificate_build(
		   &g_aset, &g_pol, &g_sess, 1500U, cv, A_VOTES, carena,
		   SIGLEN, &other), -EACCES);
	approval_setup_all(3U, 4U, R_SEC, 0U);
	OK(cast(0U, D_APPROVE));
	EQ(pqcp_fleet_approval_certificate_build(
		   &g_aset, &g_pol, &g_sess, 1500U, cv, A_VOTES, carena,
		   SIGLEN, &other), -EACCES);
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_OPEN);
	/* Not enough output capacity for the approvals. */
	approval_setup_all(2U, 2U, 0U, 0U);
	OK(cast(0U, D_APPROVE));
	OK(cast(1U, D_APPROVE));
	EQ(pqcp_fleet_approval_certificate_build(
		   &g_aset, &g_pol, &g_sess, 1500U, cv, 1U, carena, SIGLEN,
		   &other), -EINVAL);
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_QUORUM);
	/* Denied votes never enter the certificate. */
	approval_setup_all(2U, 2U, 0U, 0U);
	OK(cast(2U, D_DENY));
	OK(cast(0U, D_APPROVE));
	OK(cast(1U, D_APPROVE));
	OK(pqcp_fleet_approval_certificate_build(
		&g_aset, &g_pol, &g_sess, 1500U, g_cvotes, A_VOTES, g_carena,
		SIGLEN, &g_cert));
	EQ(g_cert.vote_count, 2U);
	EQ(g_cert.approval_roles, R_SEC | R_OPS);
	/* Second build from CERTIFIED is refused. */
	EQ(pqcp_fleet_approval_certificate_build(
		   &g_aset, &g_pol, &g_sess, 1500U, cv, A_VOTES, carena,
		   SIGLEN, &other), -EACCES);
}

ZTEST(fleet_approval, test_certificate_tampering_is_rejected)
{
	static const size_t order[] = { 4U, 0U, 2U };
	asess_t other;
	struct pqcp_fleet_approval_vote_record recs[A_VOTES];
	uint8_t arena[A_VOTES * SIGLEN];

	run_quorum_and_certify(order, ARRAY_SIZE(order), 0x33U, 1500U);
	backup_cert();
	OK(verify_cert(1600U));

#define EXPECT_CERT_FAIL(mutation, code) \
	do { \
		restore_cert(); \
		mutation; \
		EQ(verify_cert(1600U), (code)); \
		restore_cert(); \
	} while (0)

	/* Summary counters inflated/deflated. */
	EXPECT_CERT_FAIL(g_cert.approval_count += 1U, -EACCES);
	EXPECT_CERT_FAIL(g_cert.approval_weight += 1U, -EACCES);
	EXPECT_CERT_FAIL(g_cert.approval_roles |= R_VEND, -EACCES);
	/* Context fields are bound to the session. */
	EXPECT_CERT_FAIL(flip(g_cert.artifact_digest, 4U, 0x01), -EINVAL);
	EXPECT_CERT_FAIL(flip(g_cert.target_id, 4U, 0x01), -EINVAL);
	EXPECT_CERT_FAIL(flip(g_cert.session_id, 4U, 0x01), -EINVAL);
	EXPECT_CERT_FAIL(flip(g_cert.policy_id, 4U, 0x01), -EINVAL);
	EXPECT_CERT_FAIL(g_cert.action =
			 PQCP_FLEET_APPROVAL_ACTION_POLICY_ACTIVATE, -EINVAL);
	EXPECT_CERT_FAIL(g_cert.policy_generation += 1U, -EINVAL);
	EXPECT_CERT_FAIL(g_cert.authority_set_generation += 1U, -EINVAL);
	EXPECT_CERT_FAIL(g_cert.policy_epoch += 1U, -EINVAL);
	EXPECT_CERT_FAIL(g_cert.revocation_epoch += 1U, -EINVAL);
	EXPECT_CERT_FAIL(g_cert.schema_version = 0U, -EINVAL);
	EXPECT_CERT_FAIL(g_cert.vote_count = 0U, -EINVAL);
	EXPECT_CERT_FAIL(g_cert.vote_count = A_VOTES + 1U, -EINVAL);
	/* Certificate id covers all fields. */
	EXPECT_CERT_FAIL(flip(g_cert.certificate_id, 0U, 0x01), -EKEYREJECTED);
	EXPECT_CERT_FAIL(g_cert.issued_at_ms += 1U, -EKEYREJECTED);
	EXPECT_CERT_FAIL(g_cert.expires_at_ms -= 1U, -EKEYREJECTED);
	/* Per-vote evidence. */
	EXPECT_CERT_FAIL(flip(g_cvotes[0].vote_digest, 0U, 0x01),
			 -EKEYREJECTED);
	EXPECT_CERT_FAIL(flip(g_cvotes[1].signature_digest, 0U, 0x01),
			 -EKEYREJECTED);
	EXPECT_CERT_FAIL(flip(g_cvotes[2].signer_commitment, 0U, 0x01),
			 -EKEYREJECTED);
	EXPECT_CERT_FAIL(flip(g_cvotes[0].signature, 2U, 0x40),
			 -EKEYREJECTED);
	EXPECT_CERT_FAIL(g_cvotes[1].sequence += 1U, -EKEYREJECTED);
	EXPECT_CERT_FAIL(g_cvotes[1].issued_at_ms += 1U, -EKEYREJECTED);
	EXPECT_CERT_FAIL(g_cvotes[0].signature_length = 0U, -EKEYREVOKED);
	/* Ordering and duplicate defences. */
	EXPECT_CERT_FAIL({
		struct pqcp_fleet_approval_certificate_vote tmp = g_cvotes[0];

		g_cvotes[0] = g_cvotes[1];
		g_cvotes[1] = tmp;
	}, -EKEYREJECTED);
	EXPECT_CERT_FAIL(g_cvotes[1] = g_cvotes[0], -EKEYREJECTED);
	/* Dropping an approval breaks the committed totals. */
	EXPECT_CERT_FAIL(g_cert.vote_count -= 1U, -EACCES);
	/* An approver unknown to the authority set. */
	EXPECT_CERT_FAIL(fill_id(g_cvotes[0].authority_id, 0xEE) , -ENOENT);
	/* Authority generation drift. */
	EXPECT_CERT_FAIL(g_cvotes[0].authority_generation += 1U,
			 -EKEYREVOKED);
#undef EXPECT_CERT_FAIL

	/* Time window. */
	EQ(verify_cert(1499U), -EINVAL);
	EQ(verify_cert(5001U), -EINVAL);
	OK(verify_cert(1500U));

	/* Certificate cannot be applied to a different session. */
	approval_default_request();
	flip(g_req.artifact_digest, 0U, 0x01);
	OK(approval_open(&g_req, &other, recs, arena));
	other.state = PQCP_FLEET_APPROVAL_SESSION_CERTIFIED;
	EQ(pqcp_fleet_approval_certificate_verify(
		   &g_aset, &g_pol, &other, &g_cert, 1600U), -EINVAL);

	/* Session must itself be certified/consumed. */
	g_sess.state = PQCP_FLEET_APPROVAL_SESSION_QUORUM;
	EQ(verify_cert(1600U), -EINVAL);
	g_sess.state = PQCP_FLEET_APPROVAL_SESSION_CERTIFIED;
	OK(verify_cert(1600U));

	/* Bound authority state moved on after the certificate was made. */
	OK(pqcp_fleet_approval_authority_revoke(
		&g_aset, g_auth_def[3].authority_id, 1700U));
	EQ(verify_cert(1800U), -EINVAL);
}

ZTEST(fleet_approval, test_certificate_revoked_signer_is_rejected)
{
	static const size_t order[] = { 0U, 4U, 2U };

	run_quorum_and_certify(order, ARRAY_SIZE(order), 0x33U, 1500U);
	OK(verify_cert(1600U));
	/* A signer is suspended in place (no epoch change): rejected. */
	g_auth[4].state = PQCP_FLEET_APPROVAL_AUTHORITY_SUSPENDED;
	EQ(verify_cert(1600U), -EKEYREVOKED);
	g_auth[4].state = PQCP_FLEET_APPROVAL_AUTHORITY_ACTIVE;
	OK(verify_cert(1600U));
	/* Signer lost its right to the action. */
	g_auth[4].action_mask = ACT_BIT(PQCP_FLEET_APPROVAL_ACTION_DECOMMISSION);
	EQ(verify_cert(1600U), -EKEYREVOKED);
	g_auth[4].action_mask = ALL_ACTIONS;
	/* Signer key rotated. */
	g_auth[4].generation += 1U;
	EQ(verify_cert(1600U), -EKEYREVOKED);
	g_auth[4].generation -= 1U;
	OK(verify_cert(1600U));
}

static struct pqcp_fleet_approval_replay_guard g_guard_a;
static struct pqcp_fleet_approval_replay_entry g_replay[2];

ZTEST(fleet_approval, test_certificate_consumed_exactly_once)
{
	static const size_t order[] = { 0U, 4U, 2U };
	asess_t saved;

	OK(pqcp_fleet_approval_replay_guard_init(&g_guard_a, g_replay, 2U));
	run_quorum_and_certify(order, ARRAY_SIZE(order), 0x33U, 1500U);
	saved = g_sess;

	/* An uncertified (QUORUM) session cannot be consumed. */
	{
		asess_t quorum = g_sess;

		quorum.state = PQCP_FLEET_APPROVAL_SESSION_QUORUM;
		EQ(pqcp_fleet_approval_certificate_consume(
			   &g_guard_a, &g_aset, &g_pol, &g_cert, 1600U,
			   &quorum), -EINVAL);
	}
	/* Expired certificate leaves the session untouched. */
	EQ(pqcp_fleet_approval_certificate_consume(
		   &g_guard_a, &g_aset, &g_pol, &g_cert, 5001U, &g_sess),
	   -EINVAL);
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_CERTIFIED);
	zassert_false(g_replay[0].occupied);

	OK(pqcp_fleet_approval_certificate_consume(
		&g_guard_a, &g_aset, &g_pol, &g_cert, 1600U, &g_sess));
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_CONSUMED);
	zassert_true(g_replay[0].occupied);
	EQ(g_replay[0].consumed_at_ms, 1600U);
	zassert_mem_equal(g_replay[0].certificate_id, g_cert.certificate_id,
			  PQCP_FLEET_APPROVAL_ID_BYTES);
	EQ(g_guard_a.generation, 2U);

	/* Immediate replay on the same session object. */
	EQ(pqcp_fleet_approval_certificate_consume(
		   &g_guard_a, &g_aset, &g_pol, &g_cert, 1601U, &g_sess),
	   -EALREADY);
	/* Replay via a restored copy of the pre-consumption session. */
	g_sess = saved;
	EQ(pqcp_fleet_approval_certificate_consume(
		   &g_guard_a, &g_aset, &g_pol, &g_cert, 1601U, &g_sess),
	   -EALREADY);
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_CERTIFIED);
	EQ(g_guard_a.generation, 2U);
	/* A consumed session still verifies its certificate (audit). */
	g_sess.state = PQCP_FLEET_APPROVAL_SESSION_CONSUMED;
	OK(verify_cert(1700U));

	/* Guard replay protection spans guards only within one instance: a
	 * tampered certificate id cannot dodge the replay check.
	 */
	g_sess = saved;
	flip(g_cert.certificate_id, 0U, 0x01);
	EQ(pqcp_fleet_approval_certificate_consume(
		   &g_guard_a, &g_aset, &g_pol, &g_cert, 1601U, &g_sess),
	   -EKEYREJECTED);
	zassert_false(g_replay[1].occupied);
}

ZTEST(fleet_approval, test_replay_guard_capacity_exhaustion)
{
	static const size_t order[] = { 0U, 4U, 2U };
	static struct pqcp_fleet_approval_replay_entry one[1];
	static struct pqcp_fleet_approval_replay_guard guard_one;

	OK(pqcp_fleet_approval_replay_guard_init(&guard_one, one, 1U));
	EQ(pqcp_fleet_approval_replay_guard_init(NULL, one, 1U), -EINVAL);
	EQ(pqcp_fleet_approval_replay_guard_init(&guard_one, NULL, 1U),
	   -EINVAL);
	EQ(pqcp_fleet_approval_replay_guard_init(&guard_one, one, 0U),
	   -EINVAL);
	OK(pqcp_fleet_approval_replay_guard_init(&guard_one, one, 1U));

	run_quorum_and_certify(order, ARRAY_SIZE(order), 0x41U, 1500U);
	OK(pqcp_fleet_approval_certificate_consume(
		&guard_one, &g_aset, &g_pol, &g_cert, 1600U, &g_sess));

	/* A different, perfectly valid certificate finds the guard full. */
	run_quorum_and_certify(order, ARRAY_SIZE(order), 0x42U, 1500U);
	EQ(pqcp_fleet_approval_certificate_consume(
		   &guard_one, &g_aset, &g_pol, &g_cert, 1600U, &g_sess),
	   -ENOSPC);
	/* Fail-closed: the session is not consumed, guard unchanged. */
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_CERTIFIED);
	EQ(guard_one.generation, 2U);
	/* Uninitialized guard refuses everything. */
	{
		struct pqcp_fleet_approval_replay_guard blank = { 0 };

		EQ(pqcp_fleet_approval_certificate_consume(
			   &blank, &g_aset, &g_pol, &g_cert, 1600U, &g_sess),
		   -EINVAL);
	}
}

ZTEST(fleet_approval, test_witnessed_checkpoint_policy_binding)
{
	struct pqcp_fleet_transparency_witness_quorum q;
	struct pqcp_fleet_transparency_witness_quorum q2;
	tcp_t late;
	uint8_t late_sig[SIGBUF];
	tev_t ev;
	asess_t s;
	struct pqcp_fleet_approval_vote_record recs[A_VOTES];
	uint8_t arena[A_VOTES * SIGLEN];

	build_log(&g_log_a, g_store_a, 5U, NO_FORK);
	mk_cp(&g_cp[0], g_cpsig[0], &g_log_a, 500U, 1U);
	mk_cp(&late, late_sig, &g_log_a, 2000U, 2U);
	wit_setup(2U); /* OPERATOR w1, AUDITOR w2 */
	OK(wit_observe(0U, &g_cp[0], NULL, 600U, 1U, 700U, &ev));
	OK(wit_observe(1U, &g_cp[0], NULL, 600U, 1U, 700U, &ev));
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &g_cp[0],
		wit_policy(2U, 3U, PQCP_FLEET_TRANSPARENCY_WITNESS_AUDITOR,
			   0U), 900U, &q));
	zassert_true(q.reached);

	approval_setup_set();
	approval_setup_policy(2U, 2U, 0U, 0U);
	g_pol.require_witnessed_checkpoint = true;
	g_pol.minimum_witnesses = 2U;
	g_pol.minimum_witness_weight = 3U;
	g_pol.required_witness_roles =
		PQCP_FLEET_TRANSPARENCY_WITNESS_AUDITOR;
	OK(pqcp_fleet_approval_policy_validate(&g_pol));
	approval_default_request();

	/* Witnessed policy without a checkpoint. */
	EQ(approval_open(&g_req, &s, recs, arena), -EACCES);
	/* Checkpoint without its quorum evidence (non-witnessed policies
	 * enforce the pairing too).
	 */
	g_req.checkpoint = &g_cp[0];
	EQ(approval_open(&g_req, &s, recs, arena), -EACCES);

	g_req.witness_quorum = &q;
	OK(approval_open(&g_req, &g_sess, g_vrec, g_varena));
	zassert_true(g_sess.checkpoint_bound);
	EQ(g_sess.checkpoint_tree_size, 5U);
	zassert_mem_equal(g_sess.checkpoint_root, g_log_a.root, DIG);
	zassert_mem_equal(g_sess.checkpoint_digest,
			  g_cp[0].transcript_digest, DIG);
	zassert_mem_equal(g_sess.checkpoint_log_id, g_log_id, DIG);

	/* Quorum evidence that does not meet the policy. */
	q2 = q;
	q2.reached = false;
	g_req.witness_quorum = &q2;
	EQ(approval_open(&g_req, &s, recs, arena), -EACCES);
	q2 = q;
	q2.witness_count = 1U;
	EQ(approval_open(&g_req, &s, recs, arena), -EACCES);
	q2 = q;
	q2.total_weight = 2U;
	EQ(approval_open(&g_req, &s, recs, arena), -EACCES);
	q2 = q;
	q2.observed_roles = PQCP_FLEET_TRANSPARENCY_WITNESS_OPERATOR;
	EQ(approval_open(&g_req, &s, recs, arena), -EACCES);
	/* Evidence about a different checkpoint. */
	q2 = q;
	flip(q2.checkpoint_digest, 0U, 0x01);
	EQ(approval_open(&g_req, &s, recs, arena), -EKEYREJECTED);
	/* Tampered / unsigned checkpoint. */
	g_req.witness_quorum = &q;
	g_cp[1] = g_cp[0];
	g_cp[1].tree_size += 1U;
	g_req.checkpoint = &g_cp[1];
	EQ(approval_open(&g_req, &s, recs, arena), -EKEYREJECTED);
	/* Checkpoint newer than the session creation time. */
	OK(wit_observe(0U, &late, NULL, 2100U, 2U, 2200U, &ev));
	OK(wit_observe(1U, &late, NULL, 2100U, 2U, 2200U, &ev));
	OK(pqcp_fleet_transparency_witness_quorum_evaluate(
		&g_wreg, &late,
		wit_policy(2U, 3U, PQCP_FLEET_TRANSPARENCY_WITNESS_AUDITOR,
			   0U), 2300U, &q2));
	zassert_true(q2.reached);
	g_req.checkpoint = &late;
	g_req.witness_quorum = &q2;
	EQ(approval_open(&g_req, &s, recs, arena), -EKEYREJECTED);
	zassert_mem_equal(s.session_id,
			  (uint8_t[PQCP_FLEET_APPROVAL_ID_BYTES]){ 0 },
			  PQCP_FLEET_APPROVAL_ID_BYTES);

	/* The bound session reaches quorum and the certificate carries the
	 * transparency binding.
	 */
	OK(cast(0U, D_APPROVE));
	OK(cast(1U, D_APPROVE));
	EQ(g_sess.state, PQCP_FLEET_APPROVAL_SESSION_QUORUM);
	OK(pqcp_fleet_approval_certificate_build(
		&g_aset, &g_pol, &g_sess, 1500U, g_cvotes, A_VOTES, g_carena,
		SIGLEN, &g_cert));
	EQ(g_cert.checkpoint_tree_size, 5U);
	zassert_mem_equal(g_cert.checkpoint_root, g_log_a.root, DIG);
	zassert_mem_equal(g_cert.checkpoint_digest,
			  g_cp[0].transcript_digest, DIG);
	OK(verify_cert(1600U));
	/* Binding fields are covered by the certificate id. */
	flip(g_cert.checkpoint_root, 0U, 0x01);
	EQ(verify_cert(1600U), -EINVAL);
}

ZTEST(fleet_approval, test_unwitnessed_policy_allows_optional_checkpoint)
{
	struct pqcp_fleet_transparency_witness_quorum q = { 0 };
	asess_t s;
	struct pqcp_fleet_approval_vote_record recs[A_VOTES];
	uint8_t arena[A_VOTES * SIGLEN];

	build_log(&g_log_a, g_store_a, 3U, NO_FORK);
	mk_cp(&g_cp[0], g_cpsig[0], &g_log_a, 500U, 1U);
	approval_setup_set();
	approval_setup_policy(2U, 2U, 0U, 0U);
	approval_default_request();

	/* Quorum without checkpoint is a malformed request. */
	g_req.witness_quorum = &q;
	EQ(approval_open(&g_req, &s, recs, arena), -EINVAL);
	/* Checkpoint plus matching (not necessarily reached) evidence. */
	memcpy(q.checkpoint_digest, g_cp[0].transcript_digest, DIG);
	g_req.checkpoint = &g_cp[0];
	OK(approval_open(&g_req, &s, recs, arena));
	zassert_true(s.checkpoint_bound);
	EQ(s.checkpoint_tree_size, 3U);
}

