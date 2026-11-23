/*
 * SPDX-License-Identifier: MIT
 *
 * Contract tests for the sovereign policy engines: policy helpers,
 * residency, network intent, privacy budget, consent, data contract,
 * placement, egress, retention and namespace management.
 *
 * All timestamps are explicit; no wall-clock reads are made.
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <psa/crypto.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/sovereign_policy.h>

#include "sovereign_policy_internal.h"

#define BIT_OP(op) PQCP_SOVEREIGN_BIT(op)
#define BIT_CLASS(c) (1U << (uint32_t)(c))
#define ALL_CLASSES ((1U << PQCP_SOVEREIGN_DATA_CLASS_COUNT) - 1U)

static void cp(char *dst, size_t cap, const char *src)
{
	size_t len = strlen(src);

	zassert_true(len < cap, "test string too long");
	memset(dst, 0, cap);
	memcpy(dst, src, len);
}

#define CP(field, text) cp((field), sizeof(field), (text))

static const uint8_t DIGEST_A[PQCP_SOVEREIGN_DIGEST_BYTES] = {
	1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U, 16U,
	17U, 18U, 19U, 20U, 21U, 22U, 23U, 24U, 25U, 26U, 27U, 28U, 29U, 30U,
	31U, 32U,
};
static const uint8_t DIGEST_ZERO[PQCP_SOVEREIGN_DIGEST_BYTES];

/* ------------------------------------------------------------------ */
/* sovereign_policy_common.c                                          */
/* ------------------------------------------------------------------ */

ZTEST(pqcp_sovereign_policy, test_common_text_validation)
{
	char full[8];

	zassert_false(pqcp_sovereign_policy_text_valid(NULL, 8U));
	zassert_false(pqcp_sovereign_policy_text_valid("a", 1U));
	zassert_false(pqcp_sovereign_policy_text_valid("a", 0U));
	zassert_false(pqcp_sovereign_policy_text_valid("", 8U));
	zassert_true(pqcp_sovereign_policy_text_valid("a", 2U));
	zassert_true(pqcp_sovereign_policy_text_valid("Az09-_.:/@", 16U));
	/* Disallowed characters. */
	zassert_false(pqcp_sovereign_policy_text_valid("a b", 8U));
	zassert_false(pqcp_sovereign_policy_text_valid("a!", 8U));
	zassert_false(pqcp_sovereign_policy_text_valid("a\n", 8U));
	/* Exactly capacity-1 characters is the longest valid string. */
	zassert_true(pqcp_sovereign_policy_text_valid("1234567", 8U));
	/* No terminator within capacity must be rejected. */
	memset(full, 'x', sizeof(full));
	zassert_false(pqcp_sovereign_policy_text_valid(full, sizeof(full)));
	zassert_false(pqcp_sovereign_policy_text_valid("12345678", 8U));
}

ZTEST(pqcp_sovereign_policy, test_common_copy_text_is_bounded)
{
	char dest[8];

	memset(dest, 0x5A, sizeof(dest));
	zassert_equal(pqcp_sovereign_policy_copy_text(dest, sizeof(dest), NULL),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_policy_copy_text(NULL, sizeof(dest), "ab"),
		      -EINVAL);
	/* Too long / invalid source must not touch the destination. */
	zassert_equal(pqcp_sovereign_policy_copy_text(
			      dest, sizeof(dest), "12345678"),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_policy_copy_text(
			      dest, sizeof(dest), "a b"),
		      -EINVAL);
	for (size_t i = 0U; i < sizeof(dest); ++i) {
		zassert_equal(dest[i], 0x5A);
	}
	/* Boundary: capacity-1 characters fit and are NUL terminated. */
	zassert_ok(pqcp_sovereign_policy_copy_text(
		dest, sizeof(dest), "1234567"));
	zassert_equal(strcmp(dest, "1234567"), 0);
}

ZTEST(pqcp_sovereign_policy, test_common_numeric_helpers)
{
	uint32_t generation = 0U;
	uint64_t id = 0U;
	uint8_t a[4] = { 1U, 2U, 3U, 4U };
	uint8_t b[4] = { 1U, 2U, 3U, 4U };
	uint8_t out[8];

	/* Generation never yields zero, even across wrap. */
	zassert_equal(pqcp_sovereign_policy_next_generation(&generation), 1U);
	generation = UINT32_MAX;
	zassert_equal(pqcp_sovereign_policy_next_generation(&generation), 1U);
	zassert_equal(pqcp_sovereign_policy_next_generation(NULL), 0U);

	/* Identifier allocator: 0 seeds to 1, wraps UINT64_MAX -> 1. */
	zassert_equal(pqcp_sovereign_policy_next_id(&id), 1U);
	zassert_equal(id, 2U);
	id = UINT64_MAX;
	zassert_equal(pqcp_sovereign_policy_next_id(&id), UINT64_MAX);
	zassert_equal(id, 1U);
	zassert_equal(pqcp_sovereign_policy_next_id(NULL), 0U);

	/* Saturating add. */
	zassert_equal(pqcp_sovereign_policy_add_u64(1U, 2U), 3U);
	zassert_equal(pqcp_sovereign_policy_add_u64(UINT64_MAX, 1U), UINT64_MAX);
	zassert_equal(pqcp_sovereign_policy_add_u64(UINT64_MAX - 1U, 1U),
		      UINT64_MAX);

	/* all_zero / equal. */
	zassert_true(pqcp_sovereign_policy_all_zero(DIGEST_ZERO,
						    sizeof(DIGEST_ZERO)));
	zassert_false(pqcp_sovereign_policy_all_zero(DIGEST_A,
						     sizeof(DIGEST_A)));
	zassert_false(pqcp_sovereign_policy_all_zero(NULL, 4U));
	zassert_true(pqcp_sovereign_policy_equal(a, b, sizeof(a)));
	b[3] ^= 0x80U;
	zassert_false(pqcp_sovereign_policy_equal(a, b, sizeof(a)));
	zassert_false(pqcp_sovereign_policy_equal(a, NULL, sizeof(a)));
	zassert_true(pqcp_sovereign_policy_equal(NULL, NULL, 0U));

	/* Big-endian serialisation. */
	pqcp_sovereign_policy_write_u16(out, 0x0102U);
	zassert_equal(out[0], 0x01U);
	zassert_equal(out[1], 0x02U);
	pqcp_sovereign_policy_write_u32(out, 0x01020304U);
	zassert_equal(out[0], 0x01U);
	zassert_equal(out[3], 0x04U);
	pqcp_sovereign_policy_write_u64(out, 0x0102030405060708ULL);
	for (size_t i = 0U; i < 8U; ++i) {
		zassert_equal(out[i], (uint8_t)(i + 1U));
	}
}

ZTEST(pqcp_sovereign_policy, test_common_sha256)
{
	/* FIPS 180-2 SHA-256("abc"). */
	static const uint8_t expected[PQCP_SOVEREIGN_DIGEST_BYTES] = {
		0xbaU, 0x78U, 0x16U, 0xbfU, 0x8fU, 0x01U, 0xcfU, 0xeaU,
		0x41U, 0x41U, 0x40U, 0xdeU, 0x5dU, 0xaeU, 0x22U, 0x23U,
		0xb0U, 0x03U, 0x61U, 0xa3U, 0x96U, 0x17U, 0x7aU, 0x9cU,
		0xb4U, 0x10U, 0xffU, 0x61U, 0xf2U, 0x00U, 0x15U, 0xadU,
	};
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t split[PQCP_SOVEREIGN_DIGEST_BYTES];
	const uint8_t *parts[2] = { (const uint8_t *)"a", (const uint8_t *)"bc" };
	size_t lengths[2] = { 1U, 2U };

	zassert_ok(pqcp_sovereign_policy_sha256(
		(const uint8_t *)"abc", 3U, digest));
	zassert_mem_equal(digest, expected, sizeof(expected));
	zassert_ok(pqcp_sovereign_policy_sha256_parts(
		parts, lengths, 2U, split));
	zassert_mem_equal(split, expected, sizeof(expected));

	/* Invalid arguments. */
	zassert_equal(pqcp_sovereign_policy_sha256(NULL, 3U, digest), -EINVAL);
	zassert_equal(pqcp_sovereign_policy_sha256(
			      (const uint8_t *)"abc", 3U, NULL), -EINVAL);
	zassert_equal(pqcp_sovereign_policy_sha256_parts(
			      NULL, lengths, 2U, split), -EINVAL);
	zassert_equal(pqcp_sovereign_policy_sha256_parts(
			      parts, lengths, 0U, split), -EINVAL);
	parts[1] = NULL;
	zassert_equal(pqcp_sovereign_policy_sha256_parts(
			      parts, lengths, 2U, split), -EINVAL);
}

/* ------------------------------------------------------------------ */
/* Residency engine                                                   */
/* ------------------------------------------------------------------ */

static struct pqcp_sovereign_residency_rule res_rules[4];
static struct pqcp_sovereign_residency_rule res_snapshot[4];
static struct pqcp_sovereign_residency_engine res_eng;

static void mk_res_rule(struct pqcp_sovereign_residency_rule *r, uint32_t id,
			uint32_t priority, const char *src, const char *dst,
			enum pqcp_sovereign_decision effect)
{
	memset(r, 0, sizeof(*r));
	r->rule_id = id;
	r->priority = priority;
	CP(r->tenant_id, "t1");
	CP(r->source_zone, src);
	CP(r->destination_zone, dst);
	CP(r->legal_basis, "gdpr:art6");
	r->data_class_mask = BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL);
	r->not_before_ms = 100U;
	r->not_after_ms = 1000U;
	r->effect = effect;
	r->enabled = true;
}

static void mk_res_ctx(struct pqcp_sovereign_residency_context *c,
		       const char *src, const char *dst, uint64_t now)
{
	memset(c, 0, sizeof(*c));
	CP(c->tenant_id, "t1");
	CP(c->source_zone, src);
	CP(c->destination_zone, dst);
	c->data_class = PQCP_SOVEREIGN_DATA_PERSONAL;
	c->now_ms = now;
	c->encrypted = true;
	c->approved = true;
}

static int res_eval(const struct pqcp_sovereign_residency_context *c,
		    enum pqcp_sovereign_decision *d, uint32_t *id)
{
	return pqcp_sovereign_residency_evaluate(&res_eng, c, d, id);
}

ZTEST(pqcp_sovereign_policy, test_residency_init_validation)
{
	memset(res_rules, 0xA5, sizeof(res_rules));
	zassert_equal(pqcp_sovereign_residency_engine_init(
			      NULL, res_rules, 4U, PQCP_SOVEREIGN_DECISION_DENY),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_residency_engine_init(
			      &res_eng, NULL, 4U, PQCP_SOVEREIGN_DECISION_DENY),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_residency_engine_init(
			      &res_eng, res_rules, 0U, PQCP_SOVEREIGN_DECISION_DENY),
		      -EINVAL);
	/* A default-allow engine would defeat fail-closed behaviour. */
	zassert_equal(pqcp_sovereign_residency_engine_init(
			      &res_eng, res_rules, 4U, PQCP_SOVEREIGN_DECISION_ALLOW),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_residency_engine_init(
			      &res_eng, res_rules, 4U, PQCP_SOVEREIGN_DECISION_UNSET),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_residency_engine_init(
			      &res_eng, res_rules, 4U,
			      (enum pqcp_sovereign_decision)99),
		      -EINVAL);
	/* Failed init must not have touched caller storage. */
	zassert_equal(res_rules[0].rule_id, 0xA5A5A5A5U);
	zassert_ok(pqcp_sovereign_residency_engine_init(
		&res_eng, res_rules, 4U, PQCP_SOVEREIGN_DECISION_REVIEW));
	zassert_ok(pqcp_sovereign_residency_engine_init(
		&res_eng, res_rules, 4U, PQCP_SOVEREIGN_DECISION_QUARANTINE));
	zassert_ok(pqcp_sovereign_residency_engine_audit(&res_eng));
}

ZTEST(pqcp_sovereign_policy, test_residency_default_deny_and_allow)
{
	struct pqcp_sovereign_residency_rule rule;
	struct pqcp_sovereign_residency_context ctx;
	enum pqcp_sovereign_decision decision = PQCP_SOVEREIGN_DECISION_UNSET;
	uint32_t rule_id = 77U;

	zassert_ok(pqcp_sovereign_residency_engine_init(
		&res_eng, res_rules, 4U, PQCP_SOVEREIGN_DECISION_DENY));
	mk_res_ctx(&ctx, "eu-west", "eu-central", 500U);

	/* No rules: fail closed with the default effect and rule id 0. */
	zassert_equal(res_eval(&ctx, &decision, &rule_id), -EACCES);
	zassert_equal(decision, PQCP_SOVEREIGN_DECISION_DENY);
	zassert_equal(rule_id, 0U);
	zassert_equal(res_eng.deny_count, 1U);
	zassert_equal(res_eng.allow_count, 0U);

	mk_res_rule(&rule, 1U, 10U, "eu-west", "eu-central",
		    PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_ok(pqcp_sovereign_residency_rule_put(&res_eng, &rule));
	zassert_ok(res_eval(&ctx, &decision, &rule_id));
	zassert_equal(decision, PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_equal(rule_id, 1U);
	zassert_equal(res_eng.allow_count, 1U);
	zassert_ok(pqcp_sovereign_residency_engine_audit(&res_eng));
}

ZTEST(pqcp_sovereign_policy, test_residency_validity_window_boundaries)
{
	struct pqcp_sovereign_residency_rule rule;
	struct pqcp_sovereign_residency_context ctx;
	enum pqcp_sovereign_decision decision;
	uint32_t rule_id;

	zassert_ok(pqcp_sovereign_residency_engine_init(
		&res_eng, res_rules, 4U, PQCP_SOVEREIGN_DECISION_DENY));
	mk_res_rule(&rule, 1U, 10U, "a", "b", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_ok(pqcp_sovereign_residency_rule_put(&res_eng, &rule));

	/* not_before inclusive, not_after exclusive. */
	mk_res_ctx(&ctx, "a", "b", rule.not_before_ms - 1U);
	zassert_equal(res_eval(&ctx, &decision, &rule_id), -EACCES);
	mk_res_ctx(&ctx, "a", "b", rule.not_before_ms);
	zassert_ok(res_eval(&ctx, &decision, &rule_id));
	mk_res_ctx(&ctx, "a", "b", rule.not_after_ms - 1U);
	zassert_ok(res_eval(&ctx, &decision, &rule_id));
	mk_res_ctx(&ctx, "a", "b", rule.not_after_ms);
	zassert_equal(res_eval(&ctx, &decision, &rule_id), -EACCES);
	zassert_equal(decision, PQCP_SOVEREIGN_DECISION_DENY);
}

ZTEST(pqcp_sovereign_policy, test_residency_mismatch_rejection)
{
	struct pqcp_sovereign_residency_rule rule;
	struct pqcp_sovereign_residency_context ctx;
	enum pqcp_sovereign_decision decision;
	uint32_t rule_id;

	zassert_ok(pqcp_sovereign_residency_engine_init(
		&res_eng, res_rules, 4U, PQCP_SOVEREIGN_DECISION_DENY));
	mk_res_rule(&rule, 1U, 10U, "eu-west", "eu-central",
		    PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_ok(pqcp_sovereign_residency_rule_put(&res_eng, &rule));

	/* Tenant mismatch. */
	mk_res_ctx(&ctx, "eu-west", "eu-central", 500U);
	CP(ctx.tenant_id, "other");
	zassert_equal(res_eval(&ctx, &decision, &rule_id), -EACCES);
	zassert_equal(rule_id, 0U);
	/* Destination region mismatch (data leaving the residency zone). */
	mk_res_ctx(&ctx, "eu-west", "us-east", 500U);
	zassert_equal(res_eval(&ctx, &decision, &rule_id), -EACCES);
	zassert_equal(decision, PQCP_SOVEREIGN_DECISION_DENY);
	/* Source region mismatch. */
	mk_res_ctx(&ctx, "ap-south", "eu-central", 500U);
	zassert_equal(res_eval(&ctx, &decision, &rule_id), -EACCES);
	/* Data class not covered by the rule. */
	mk_res_ctx(&ctx, "eu-west", "eu-central", 500U);
	ctx.data_class = PQCP_SOVEREIGN_DATA_SECRET;
	zassert_equal(res_eval(&ctx, &decision, &rule_id), -EACCES);
	/* The matching context still passes. */
	mk_res_ctx(&ctx, "eu-west", "eu-central", 500U);
	zassert_ok(res_eval(&ctx, &decision, &rule_id));
}

ZTEST(pqcp_sovereign_policy, test_residency_wildcard_and_conditions)
{
	struct pqcp_sovereign_residency_rule rule;
	struct pqcp_sovereign_residency_context ctx;
	enum pqcp_sovereign_decision decision;
	uint32_t rule_id;

	zassert_ok(pqcp_sovereign_residency_engine_init(
		&res_eng, res_rules, 4U, PQCP_SOVEREIGN_DECISION_DENY));
	mk_res_rule(&rule, 1U, 10U, "*", "eu-central",
		    PQCP_SOVEREIGN_DECISION_ALLOW);
	rule.require_encryption = true;
	rule.require_approval = true;
	zassert_ok(pqcp_sovereign_residency_rule_put(&res_eng, &rule));

	mk_res_ctx(&ctx, "anywhere", "eu-central", 500U);
	zassert_ok(res_eval(&ctx, &decision, &rule_id));

	/* Unencrypted transfer is denied even though the rule allows. */
	ctx.encrypted = false;
	zassert_equal(res_eval(&ctx, &decision, &rule_id), -EACCES);
	zassert_equal(decision, PQCP_SOVEREIGN_DECISION_DENY);
	zassert_equal(rule_id, 1U);
	/* Missing approval downgrades to REVIEW, never ALLOW. */
	ctx.encrypted = true;
	ctx.approved = false;
	zassert_equal(res_eval(&ctx, &decision, &rule_id), -EACCES);
	zassert_equal(decision, PQCP_SOVEREIGN_DECISION_REVIEW);
}

ZTEST(pqcp_sovereign_policy, test_residency_priority_and_tiebreak)
{
	struct pqcp_sovereign_residency_rule rule;
	struct pqcp_sovereign_residency_context ctx;
	enum pqcp_sovereign_decision decision;
	uint32_t rule_id;

	zassert_ok(pqcp_sovereign_residency_engine_init(
		&res_eng, res_rules, 4U, PQCP_SOVEREIGN_DECISION_DENY));
	mk_res_ctx(&ctx, "a", "b", 500U);

	/* Equal priority: the most restrictive effect wins. */
	mk_res_rule(&rule, 1U, 5U, "a", "b", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_ok(pqcp_sovereign_residency_rule_put(&res_eng, &rule));
	mk_res_rule(&rule, 2U, 5U, "a", "b", PQCP_SOVEREIGN_DECISION_DENY);
	zassert_ok(pqcp_sovereign_residency_rule_put(&res_eng, &rule));
	zassert_equal(res_eval(&ctx, &decision, &rule_id), -EACCES);
	zassert_equal(decision, PQCP_SOVEREIGN_DECISION_DENY);
	zassert_equal(rule_id, 2U);

	/* A higher-priority allow overrides a lower-priority deny. */
	mk_res_rule(&rule, 3U, 9U, "a", "b", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_ok(pqcp_sovereign_residency_rule_put(&res_eng, &rule));
	zassert_ok(res_eval(&ctx, &decision, &rule_id));
	zassert_equal(rule_id, 3U);

	/* Same priority and effect: lowest rule id is deterministic. */
	mk_res_rule(&rule, 2U, 9U, "a", "b", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_ok(pqcp_sovereign_residency_rule_put(&res_eng, &rule));
	zassert_ok(res_eval(&ctx, &decision, &rule_id));
	zassert_equal(rule_id, 2U);
}

ZTEST(pqcp_sovereign_policy, test_residency_rule_put_rejects_invalid_unchanged)
{
	struct pqcp_sovereign_residency_rule rule;

	zassert_ok(pqcp_sovereign_residency_engine_init(
		&res_eng, res_rules, 4U, PQCP_SOVEREIGN_DECISION_DENY));
	mk_res_rule(&rule, 1U, 5U, "a", "b", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_ok(pqcp_sovereign_residency_rule_put(&res_eng, &rule));
	memcpy(res_snapshot, res_rules, sizeof(res_rules));

	zassert_equal(pqcp_sovereign_residency_rule_put(&res_eng, NULL), -EINVAL);
	zassert_equal(pqcp_sovereign_residency_rule_put(NULL, &rule), -EINVAL);

	mk_res_rule(&rule, 0U, 5U, "a", "b", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_equal(pqcp_sovereign_residency_rule_put(&res_eng, &rule), -EINVAL);
	mk_res_rule(&rule, 2U, 0U, "a", "b", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_equal(pqcp_sovereign_residency_rule_put(&res_eng, &rule), -EINVAL);
	mk_res_rule(&rule, 2U, 5U, "a", "b", PQCP_SOVEREIGN_DECISION_UNSET);
	zassert_equal(pqcp_sovereign_residency_rule_put(&res_eng, &rule), -EINVAL);
	mk_res_rule(&rule, 2U, 5U, "a", "b", PQCP_SOVEREIGN_DECISION_ALLOW);
	rule.not_after_ms = rule.not_before_ms; /* empty window */
	zassert_equal(pqcp_sovereign_residency_rule_put(&res_eng, &rule), -EINVAL);
	mk_res_rule(&rule, 2U, 5U, "a", "b", PQCP_SOVEREIGN_DECISION_ALLOW);
	rule.data_class_mask = 0U;
	zassert_equal(pqcp_sovereign_residency_rule_put(&res_eng, &rule), -EINVAL);
	rule.data_class_mask = 1U << PQCP_SOVEREIGN_DATA_CLASS_COUNT; /* one past */
	zassert_equal(pqcp_sovereign_residency_rule_put(&res_eng, &rule), -EINVAL);
	mk_res_rule(&rule, 2U, 5U, "a", "b", PQCP_SOVEREIGN_DECISION_ALLOW);
	rule.enabled = false;
	zassert_equal(pqcp_sovereign_residency_rule_put(&res_eng, &rule), -EINVAL);
	mk_res_rule(&rule, 2U, 5U, "a", "b", PQCP_SOVEREIGN_DECISION_ALLOW);
	CP(rule.tenant_id, "");
	zassert_equal(pqcp_sovereign_residency_rule_put(&res_eng, &rule), -EINVAL);

	zassert_mem_equal(res_snapshot, res_rules, sizeof(res_rules));
	zassert_equal(res_eng.count, 1U);
}

ZTEST(pqcp_sovereign_policy, test_residency_capacity_replace_remove)
{
	struct pqcp_sovereign_residency_rule rule;
	struct pqcp_sovereign_residency_context ctx;
	enum pqcp_sovereign_decision decision;
	uint32_t rule_id;

	zassert_ok(pqcp_sovereign_residency_engine_init(
		&res_eng, res_rules, 4U, PQCP_SOVEREIGN_DECISION_DENY));
	for (uint32_t id = 1U; id <= 4U; ++id) {
		mk_res_rule(&rule, id, 5U, "a", "b",
			    PQCP_SOVEREIGN_DECISION_ALLOW);
		zassert_ok(pqcp_sovereign_residency_rule_put(&res_eng, &rule));
	}
	zassert_equal(res_eng.count, 4U);
	mk_res_rule(&rule, 5U, 5U, "a", "b", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_equal(pqcp_sovereign_residency_rule_put(&res_eng, &rule), -ENOSPC);
	zassert_equal(res_eng.count, 4U);
	/* Replacing an existing id when full is still allowed. */
	mk_res_rule(&rule, 4U, 5U, "a", "b", PQCP_SOVEREIGN_DECISION_DENY);
	zassert_ok(pqcp_sovereign_residency_rule_put(&res_eng, &rule));
	zassert_equal(res_eng.count, 4U);
	zassert_ok(pqcp_sovereign_residency_engine_audit(&res_eng));

	/* Remove: invalid / unknown / success / idempotence. */
	zassert_equal(pqcp_sovereign_residency_rule_remove(&res_eng, 0U), -EINVAL);
	zassert_equal(pqcp_sovereign_residency_rule_remove(NULL, 1U), -EINVAL);
	zassert_equal(pqcp_sovereign_residency_rule_remove(&res_eng, 99U),
		      -ENOENT);
	for (uint32_t id = 1U; id <= 4U; ++id) {
		zassert_ok(pqcp_sovereign_residency_rule_remove(&res_eng, id));
		zassert_equal(pqcp_sovereign_residency_rule_remove(&res_eng, id),
			      -ENOENT);
	}
	zassert_equal(res_eng.count, 0U);
	/* With every rule gone the engine is back to default-deny. */
	mk_res_ctx(&ctx, "a", "b", 500U);
	zassert_equal(res_eval(&ctx, &decision, &rule_id), -EACCES);
	zassert_equal(rule_id, 0U);
	zassert_ok(pqcp_sovereign_residency_engine_audit(&res_eng));
}

ZTEST(pqcp_sovereign_policy, test_residency_evaluate_invalid_arguments)
{
	struct pqcp_sovereign_residency_context ctx;
	enum pqcp_sovereign_decision decision;
	uint32_t rule_id;

	zassert_ok(pqcp_sovereign_residency_engine_init(
		&res_eng, res_rules, 4U, PQCP_SOVEREIGN_DECISION_DENY));
	mk_res_ctx(&ctx, "a", "b", 500U);
	zassert_equal(pqcp_sovereign_residency_evaluate(
			      NULL, &ctx, &decision, &rule_id), -EINVAL);
	zassert_equal(pqcp_sovereign_residency_evaluate(
			      &res_eng, NULL, &decision, &rule_id), -EINVAL);
	zassert_equal(pqcp_sovereign_residency_evaluate(
			      &res_eng, &ctx, NULL, &rule_id), -EINVAL);
	zassert_equal(pqcp_sovereign_residency_evaluate(
			      &res_eng, &ctx, &decision, NULL), -EINVAL);
	ctx.now_ms = 0U;
	zassert_equal(res_eval(&ctx, &decision, &rule_id), -EINVAL);
	mk_res_ctx(&ctx, "a", "b", 500U);
	ctx.data_class = (enum pqcp_sovereign_data_class)
		PQCP_SOVEREIGN_DATA_CLASS_COUNT;
	zassert_equal(res_eval(&ctx, &decision, &rule_id), -EINVAL);
	ctx.data_class = (enum pqcp_sovereign_data_class)99;
	zassert_equal(res_eval(&ctx, &decision, &rule_id), -EINVAL);
	mk_res_ctx(&ctx, "a", "b", 500U);
	CP(ctx.destination_zone, "");
	zassert_equal(res_eval(&ctx, &decision, &rule_id), -EINVAL);
	/* Invalid requests are not counted as policy decisions. */
	zassert_equal(res_eng.deny_count, 0U);
	zassert_equal(res_eng.allow_count, 0U);
	/* Uninitialised engine is rejected. */
	memset(&res_eng, 0, sizeof(res_eng));
	mk_res_ctx(&ctx, "a", "b", 500U);
	zassert_equal(res_eval(&ctx, &decision, &rule_id), -EINVAL);
}

/* ------------------------------------------------------------------ */
/* Network intent                                                     */
/* ------------------------------------------------------------------ */

static struct pqcp_sovereign_network_intent net_intents[2];
static struct pqcp_sovereign_network_intent net_snapshot[2];
static struct pqcp_sovereign_network_intent_manager net_mgr;

#define NET_EPOCH 7U

static void mk_intent(struct pqcp_sovereign_network_intent *i,
		      uint16_t port_start, uint16_t port_end,
		      uint32_t max_connections)
{
	memset(i, 0, sizeof(*i));
	CP(i->tenant_id, "t1");
	CP(i->source_namespace, "ns-a");
	CP(i->destination_namespace, "ns-b");
	CP(i->protocol, "tcp");
	i->port_start = port_start;
	i->port_end = port_end;
	i->operation_mask = BIT_OP(PQCP_SOVEREIGN_OPERATION_EXECUTE) |
			    BIT_OP(PQCP_SOVEREIGN_OPERATION_READ_DATA);
	i->policy_epoch = NET_EPOCH;
	i->expires_at_ms = 0U;
	i->maximum_connections = max_connections;
	i->maximum_risk = 500U;
	i->state = PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
}

static int net_auth(uint16_t port, enum pqcp_sovereign_operation op,
		    uint32_t risk, bool mtls, bool enc, uint64_t epoch,
		    uint64_t now, uint64_t *id)
{
	return pqcp_sovereign_network_intent_authorize(
		&net_mgr, "t1", "ns-a", "ns-b", "tcp", port, op, risk, mtls,
		enc, epoch, now, id);
}

ZTEST(pqcp_sovereign_policy, test_network_default_deny_and_allow)
{
	struct pqcp_sovereign_network_intent intent;
	uint64_t id = 99U;

	zassert_equal(pqcp_sovereign_network_intent_manager_init(
			      NULL, net_intents, 2U), -EINVAL);
	zassert_equal(pqcp_sovereign_network_intent_manager_init(
			      &net_mgr, NULL, 2U), -EINVAL);
	zassert_equal(pqcp_sovereign_network_intent_manager_init(
			      &net_mgr, net_intents, 0U), -EINVAL);
	zassert_ok(pqcp_sovereign_network_intent_manager_init(
		&net_mgr, net_intents, 2U));

	/* No intent registered: deny. */
	zassert_equal(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U,
			       true, true, NET_EPOCH, 1000U, &id), -EACCES);
	zassert_equal(id, 0U);
	zassert_equal(net_mgr.deny_count, 1U);

	mk_intent(&intent, 443U, 443U, 2U);
	zassert_ok(pqcp_sovereign_network_intent_put(&net_mgr, &intent, 1000U));
	zassert_ok(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true,
			    true, NET_EPOCH, 1000U, &id));
	zassert_not_equal(id, 0U);
	zassert_equal(net_mgr.allow_count, 1U);
	zassert_equal(net_intents[0].active_connections, 1U);
	zassert_ok(pqcp_sovereign_network_intent_manager_audit(&net_mgr));
}

ZTEST(pqcp_sovereign_policy, test_network_connection_limit_and_release)
{
	struct pqcp_sovereign_network_intent intent;
	uint64_t id1 = 0U;
	uint64_t id2 = 0U;
	uint64_t id3 = 0U;

	zassert_ok(pqcp_sovereign_network_intent_manager_init(
		&net_mgr, net_intents, 2U));
	mk_intent(&intent, 443U, 443U, 2U);
	zassert_ok(pqcp_sovereign_network_intent_put(&net_mgr, &intent, 1000U));

	zassert_ok(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true,
			    true, NET_EPOCH, 1000U, &id1));
	zassert_ok(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true,
			    true, NET_EPOCH, 1000U, &id2));
	/* One past the limit is refused and must not change the counter. */
	zassert_equal(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U,
			       true, true, NET_EPOCH, 1000U, &id3), -EACCES);
	zassert_equal(id3, 0U);
	zassert_equal(net_intents[0].active_connections, 2U);

	zassert_ok(pqcp_sovereign_network_intent_release(&net_mgr, id1));
	zassert_equal(net_intents[0].active_connections, 1U);
	zassert_ok(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true,
			    true, NET_EPOCH, 1000U, &id3));
	zassert_ok(pqcp_sovereign_network_intent_release(&net_mgr, id1));
	zassert_ok(pqcp_sovereign_network_intent_release(&net_mgr, id1));
	/* Releasing with no active connections is an error, not an underflow. */
	zassert_equal(pqcp_sovereign_network_intent_release(&net_mgr, id1),
		      -EALREADY);
	zassert_equal(net_intents[0].active_connections, 0U);
	zassert_equal(pqcp_sovereign_network_intent_release(&net_mgr, 0U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_network_intent_release(&net_mgr, 424242U),
		      -ENOENT);
}

ZTEST(pqcp_sovereign_policy, test_network_port_range_boundaries)
{
	struct pqcp_sovereign_network_intent intent;
	uint64_t id;

	zassert_ok(pqcp_sovereign_network_intent_manager_init(
		&net_mgr, net_intents, 2U));
	mk_intent(&intent, 8000U, 8010U, 100U);
	zassert_ok(pqcp_sovereign_network_intent_put(&net_mgr, &intent, 1000U));

	zassert_equal(net_auth(7999U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true,
			       true, NET_EPOCH, 1000U, &id), -EACCES);
	zassert_ok(net_auth(8000U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true,
			    true, NET_EPOCH, 1000U, &id));
	zassert_ok(net_auth(8010U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true,
			    true, NET_EPOCH, 1000U, &id));
	zassert_equal(net_auth(8011U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true,
			       true, NET_EPOCH, 1000U, &id), -EACCES);
}

ZTEST(pqcp_sovereign_policy, test_network_attribute_mismatch_denied)
{
	struct pqcp_sovereign_network_intent intent;
	uint64_t id;

	zassert_ok(pqcp_sovereign_network_intent_manager_init(
		&net_mgr, net_intents, 2U));
	mk_intent(&intent, 443U, 443U, 10U);
	intent.require_mutual_auth = true;
	intent.require_encryption = true;
	zassert_ok(pqcp_sovereign_network_intent_put(&net_mgr, &intent, 1000U));

	/* Operation not in mask. */
	zassert_equal(net_auth(443U, PQCP_SOVEREIGN_OPERATION_ADMINISTER, 0U,
			       true, true, NET_EPOCH, 1000U, &id), -EACCES);
	/* Risk boundary: at max ok, one above denied. */
	zassert_ok(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 500U, true,
			    true, NET_EPOCH, 1000U, &id));
	zassert_equal(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 501U,
			       true, true, NET_EPOCH, 1000U, &id), -EACCES);
	/* mTLS / encryption requirements. */
	zassert_equal(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, false,
			       true, NET_EPOCH, 1000U, &id), -EACCES);
	zassert_equal(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true,
			       false, NET_EPOCH, 1000U, &id), -EACCES);
	/* Policy epoch mismatch (stale and future). */
	zassert_equal(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true,
			       true, NET_EPOCH - 1U, 1000U, &id), -EACCES);
	zassert_equal(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true,
			       true, NET_EPOCH + 1U, 1000U, &id), -EACCES);
	/* Tenant / namespace / protocol mismatches. */
	zassert_equal(pqcp_sovereign_network_intent_authorize(
			      &net_mgr, "t2", "ns-a", "ns-b", "tcp", 443U,
			      PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true, true,
			      NET_EPOCH, 1000U, &id), -EACCES);
	zassert_equal(pqcp_sovereign_network_intent_authorize(
			      &net_mgr, "t1", "ns-x", "ns-b", "tcp", 443U,
			      PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true, true,
			      NET_EPOCH, 1000U, &id), -EACCES);
	zassert_equal(pqcp_sovereign_network_intent_authorize(
			      &net_mgr, "t1", "ns-a", "ns-x", "tcp", 443U,
			      PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true, true,
			      NET_EPOCH, 1000U, &id), -EACCES);
	zassert_equal(pqcp_sovereign_network_intent_authorize(
			      &net_mgr, "t1", "ns-a", "ns-b", "udp", 443U,
			      PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true, true,
			      NET_EPOCH, 1000U, &id), -EACCES);
}

ZTEST(pqcp_sovereign_policy, test_network_expiry_and_tick)
{
	struct pqcp_sovereign_network_intent intent;
	uint64_t id;
	uint32_t expired = 99U;

	zassert_ok(pqcp_sovereign_network_intent_manager_init(
		&net_mgr, net_intents, 2U));
	mk_intent(&intent, 443U, 443U, 10U);
	intent.expires_at_ms = 2000U;
	/* Already-expired (<= now) intents are refused at put time. */
	intent.expires_at_ms = 1000U;
	zassert_equal(pqcp_sovereign_network_intent_put(&net_mgr, &intent, 1000U),
		      -EINVAL);
	intent.expires_at_ms = 2000U;
	zassert_ok(pqcp_sovereign_network_intent_put(&net_mgr, &intent, 1000U));

	zassert_ok(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true,
			    true, NET_EPOCH, 1999U, &id));
	zassert_equal(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true,
			       true, NET_EPOCH, 2000U, &id), -EACCES);

	zassert_ok(pqcp_sovereign_network_intent_tick(&net_mgr, 1999U, &expired));
	zassert_equal(expired, 0U);
	zassert_ok(pqcp_sovereign_network_intent_tick(&net_mgr, 2000U, &expired));
	zassert_equal(expired, 1U);
	zassert_equal(net_intents[0].state, PQCP_SOVEREIGN_LIFECYCLE_RETIRED);
	zassert_ok(pqcp_sovereign_network_intent_tick(&net_mgr, 3000U, &expired));
	zassert_equal(expired, 0U);
	zassert_equal(pqcp_sovereign_network_intent_tick(&net_mgr, 0U, &expired),
		      -EINVAL);
}

ZTEST(pqcp_sovereign_policy, test_network_most_specific_intent_selected)
{
	struct pqcp_sovereign_network_intent broad;
	struct pqcp_sovereign_network_intent narrow;
	uint64_t id = 0U;

	zassert_ok(pqcp_sovereign_network_intent_manager_init(
		&net_mgr, net_intents, 2U));
	mk_intent(&broad, 1U, 65535U, 5U);
	mk_intent(&narrow, 443U, 443U, 5U);
	zassert_ok(pqcp_sovereign_network_intent_put(&net_mgr, &broad, 1000U));
	zassert_ok(pqcp_sovereign_network_intent_put(&net_mgr, &narrow, 1000U));
	zassert_ok(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true,
			    true, NET_EPOCH, 1000U, &id));
	zassert_equal(net_intents[1].intent_id, id);
	zassert_equal(net_intents[1].active_connections, 1U);
	zassert_equal(net_intents[0].active_connections, 0U);
	/* Capacity exhausted: a third distinct intent cannot be stored. */
	mk_intent(&narrow, 80U, 80U, 5U);
	zassert_equal(pqcp_sovereign_network_intent_put(&net_mgr, &narrow, 1000U),
		      -ENOSPC);
	zassert_ok(pqcp_sovereign_network_intent_manager_audit(&net_mgr));
}

ZTEST(pqcp_sovereign_policy, test_network_put_invalid_leaves_state_unchanged)
{
	struct pqcp_sovereign_network_intent intent;
	uint64_t id;

	zassert_ok(pqcp_sovereign_network_intent_manager_init(
		&net_mgr, net_intents, 2U));
	mk_intent(&intent, 443U, 443U, 2U);
	zassert_ok(pqcp_sovereign_network_intent_put(&net_mgr, &intent, 1000U));
	memcpy(net_snapshot, net_intents, sizeof(net_intents));

	zassert_equal(pqcp_sovereign_network_intent_put(&net_mgr, NULL, 1000U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_network_intent_put(NULL, &intent, 1000U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_network_intent_put(&net_mgr, &intent, 0U),
		      -EINVAL);
	mk_intent(&intent, 500U, 499U, 2U); /* inverted range */
	zassert_equal(pqcp_sovereign_network_intent_put(&net_mgr, &intent, 1000U),
		      -EINVAL);
	mk_intent(&intent, 443U, 443U, 0U); /* no connection budget */
	zassert_equal(pqcp_sovereign_network_intent_put(&net_mgr, &intent, 1000U),
		      -EINVAL);
	mk_intent(&intent, 443U, 443U, 2U);
	intent.operation_mask = 0U;
	zassert_equal(pqcp_sovereign_network_intent_put(&net_mgr, &intent, 1000U),
		      -EINVAL);
	mk_intent(&intent, 443U, 443U, 2U);
	intent.policy_epoch = 0U;
	zassert_equal(pqcp_sovereign_network_intent_put(&net_mgr, &intent, 1000U),
		      -EINVAL);
	mk_intent(&intent, 443U, 443U, 2U);
	intent.active_connections = 3U; /* over max */
	zassert_equal(pqcp_sovereign_network_intent_put(&net_mgr, &intent, 1000U),
		      -EINVAL);
	mk_intent(&intent, 443U, 443U, 2U);
	CP(intent.protocol, "bad proto");
	zassert_equal(pqcp_sovereign_network_intent_put(&net_mgr, &intent, 1000U),
		      -EINVAL);
	zassert_mem_equal(net_snapshot, net_intents, sizeof(net_intents));

	/* Authorize argument validation. */
	zassert_equal(net_auth(443U, PQCP_SOVEREIGN_OPERATION_NONE, 0U, true,
			       true, NET_EPOCH, 1000U, &id), -EINVAL);
	zassert_equal(net_auth(443U, PQCP_SOVEREIGN_OPERATION_COUNT, 0U, true,
			       true, NET_EPOCH, 1000U, &id), -EINVAL);
	zassert_equal(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true,
			       true, 0U, 1000U, &id), -EINVAL);
	zassert_equal(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true,
			       true, NET_EPOCH, 0U, &id), -EINVAL);
	zassert_equal(net_auth(443U, PQCP_SOVEREIGN_OPERATION_EXECUTE, 0U, true,
			       true, NET_EPOCH, 1000U, NULL), -EINVAL);
	zassert_mem_equal(net_snapshot, net_intents, sizeof(net_intents));
}

/* ------------------------------------------------------------------ */
/* Privacy budget                                                     */
/* ------------------------------------------------------------------ */

static struct pqcp_sovereign_privacy_budget pb_budgets[2];
static struct pqcp_sovereign_privacy_budget pb_snapshot[2];
static struct pqcp_sovereign_privacy_budget_manager pb_mgr;

#define PB_EPOCH 5U
#define PB_START 10000U

static void mk_budget(struct pqcp_sovereign_privacy_budget *b, const char *id)
{
	memset(b, 0, sizeof(*b));
	CP(b->budget_id, id);
	CP(b->tenant_id, "t1");
	CP(b->subject_scope, "subject-1");
	CP(b->purpose, "analytics");
	b->window_ms = 1000U;
	b->policy_epoch = PB_EPOCH;
	b->epsilon_limit_micros = 1000U;
	b->delta_limit_nanos = 100U;
	b->query_limit = 10U;
	b->state = PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
}

static void pb_setup(void)
{
	struct pqcp_sovereign_privacy_budget b;

	zassert_ok(pqcp_sovereign_privacy_budget_manager_init(
		&pb_mgr, pb_budgets, 2U));
	mk_budget(&b, "b1");
	zassert_ok(pqcp_sovereign_privacy_budget_put(&pb_mgr, &b, PB_START));
}

ZTEST(pqcp_sovereign_policy, test_privacy_budget_init_put_and_remaining)
{
	uint64_t eps = 0U;
	uint64_t delta = 0U;
	uint64_t queries = 0U;
	struct pqcp_sovereign_privacy_budget b;

	zassert_equal(pqcp_sovereign_privacy_budget_manager_init(
			      NULL, pb_budgets, 2U), -EINVAL);
	zassert_equal(pqcp_sovereign_privacy_budget_manager_init(
			      &pb_mgr, NULL, 2U), -EINVAL);
	zassert_equal(pqcp_sovereign_privacy_budget_manager_init(
			      &pb_mgr, pb_budgets, 0U), -EINVAL);
	pb_setup();
	zassert_ok(pqcp_sovereign_privacy_budget_remaining(
		&pb_mgr, "b1", PB_START, &eps, &delta, &queries));
	zassert_equal(eps, 1000U);
	zassert_equal(delta, 100U);
	zassert_equal(queries, 10U);

	/* Unknown budget: fail closed. */
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "nope", 1U, 1U, 1U, PB_EPOCH, PB_START),
		      -ENOENT);
	zassert_equal(pqcp_sovereign_privacy_budget_remaining(
			      &pb_mgr, "nope", PB_START, &eps, &delta, &queries),
		      -ENOENT);
	/* Invalid put arguments. */
	mk_budget(&b, "b2");
	b.epsilon_limit_micros = 0U;
	zassert_equal(pqcp_sovereign_privacy_budget_put(&pb_mgr, &b, PB_START),
		      -EINVAL);
	mk_budget(&b, "b2");
	b.query_limit = 0U;
	zassert_equal(pqcp_sovereign_privacy_budget_put(&pb_mgr, &b, PB_START),
		      -EINVAL);
	mk_budget(&b, "b2");
	b.epsilon_used_micros = b.epsilon_limit_micros + 1U;
	zassert_equal(pqcp_sovereign_privacy_budget_put(&pb_mgr, &b, PB_START),
		      -EINVAL);
	mk_budget(&b, "b2");
	b.state = PQCP_SOVEREIGN_LIFECYCLE_SUSPENDED;
	zassert_equal(pqcp_sovereign_privacy_budget_put(&pb_mgr, &b, PB_START),
		      -EINVAL);
	mk_budget(&b, "b2");
	zassert_equal(pqcp_sovereign_privacy_budget_put(&pb_mgr, &b, 0U), -EINVAL);
	zassert_equal(pqcp_sovereign_privacy_budget_put(&pb_mgr, NULL, PB_START),
		      -EINVAL);
	zassert_ok(pqcp_sovereign_privacy_budget_manager_audit(&pb_mgr));
}

ZTEST(pqcp_sovereign_policy, test_privacy_budget_exact_limit_then_exhausted)
{
	uint64_t eps;
	uint64_t delta;
	uint64_t queries;

	pb_setup();
	/* Spending exactly the whole budget is allowed. */
	zassert_ok(pqcp_sovereign_privacy_budget_consume(
		&pb_mgr, "b1", 1000U, 100U, 10U, PB_EPOCH, PB_START));
	zassert_ok(pqcp_sovereign_privacy_budget_remaining(
		&pb_mgr, "b1", PB_START, &eps, &delta, &queries));
	zassert_equal(eps, 0U);
	zassert_equal(delta, 0U);
	zassert_equal(queries, 0U);
	/* Any further spend is refused. */
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "b1", 1U, 1U, 1U, PB_EPOCH, PB_START),
		      -EDQUOT);
	zassert_equal(pb_mgr.accepted_count, 1U);
	zassert_equal(pb_mgr.denied_count, 1U);
	zassert_ok(pqcp_sovereign_privacy_budget_manager_audit(&pb_mgr));
}

ZTEST(pqcp_sovereign_policy, test_privacy_budget_overspend_no_partial_mutation)
{
	pb_setup();
	zassert_ok(pqcp_sovereign_privacy_budget_consume(
		&pb_mgr, "b1", 400U, 40U, 4U, PB_EPOCH, PB_START));
	memcpy(pb_snapshot, pb_budgets, sizeof(pb_budgets));

	/* Each dimension, one past the remaining headroom. */
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "b1", 601U, 1U, 1U, PB_EPOCH, PB_START),
		      -EDQUOT);
	zassert_mem_equal(pb_snapshot, pb_budgets, sizeof(pb_budgets));
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "b1", 1U, 61U, 1U, PB_EPOCH, PB_START),
		      -EDQUOT);
	zassert_mem_equal(pb_snapshot, pb_budgets, sizeof(pb_budgets));
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "b1", 1U, 1U, 7U, PB_EPOCH, PB_START),
		      -EDQUOT);
	zassert_mem_equal(pb_snapshot, pb_budgets, sizeof(pb_budgets));
	/* Arithmetic overflow attempts must be refused, not wrapped. */
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "b1", UINT64_MAX, 1U, 1U, PB_EPOCH,
			      PB_START), -EDQUOT);
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "b1", 1U, UINT64_MAX, 1U, PB_EPOCH,
			      PB_START), -EDQUOT);
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "b1", 1U, 1U, UINT64_MAX, PB_EPOCH,
			      PB_START), -EDQUOT);
	zassert_mem_equal(pb_snapshot, pb_budgets, sizeof(pb_budgets));
	/* The exact remaining headroom is still spendable afterwards. */
	zassert_ok(pqcp_sovereign_privacy_budget_consume(
		&pb_mgr, "b1", 600U, 60U, 6U, PB_EPOCH, PB_START));
}

ZTEST(pqcp_sovereign_policy, test_privacy_budget_invalid_stale_and_time)
{
	pb_setup();
	memcpy(pb_snapshot, pb_budgets, sizeof(pb_budgets));

	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      NULL, "b1", 1U, 1U, 1U, PB_EPOCH, PB_START),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, NULL, 1U, 1U, 1U, PB_EPOCH, PB_START),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "b1", 0U, 1U, 1U, PB_EPOCH, PB_START),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "b1", 1U, 0U, 1U, PB_EPOCH, PB_START),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "b1", 1U, 1U, 0U, PB_EPOCH, PB_START),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "b1", 1U, 1U, 1U, 0U, PB_START), -EINVAL);
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "b1", 1U, 1U, 1U, PB_EPOCH, 0U), -EINVAL);
	/* Policy-epoch mismatch in both directions. */
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "b1", 1U, 1U, 1U, PB_EPOCH - 1U,
			      PB_START), -ESTALE);
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "b1", 1U, 1U, 1U, PB_EPOCH + 1U,
			      PB_START), -ESTALE);
	/* Clock going backwards relative to the window start. */
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "b1", 1U, 1U, 1U, PB_EPOCH,
			      PB_START - 1U), -ETIME);
	zassert_mem_equal(pb_snapshot, pb_budgets, sizeof(pb_budgets));
}

ZTEST(pqcp_sovereign_policy, test_privacy_budget_window_reset_boundaries)
{
	uint32_t resets = 99U;
	uint64_t eps;
	uint64_t delta;
	uint64_t queries;

	pb_setup();
	zassert_ok(pqcp_sovereign_privacy_budget_consume(
		&pb_mgr, "b1", 1000U, 100U, 10U, PB_EPOCH, PB_START));
	/* One tick before the window ends nothing is replenished. */
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "b1", 1U, 1U, 1U, PB_EPOCH,
			      PB_START + 999U), -EDQUOT);
	zassert_ok(pqcp_sovereign_privacy_budget_tick(
		&pb_mgr, PB_START + 999U, &resets));
	zassert_equal(resets, 0U);
	/* At the boundary the window rolls over. */
	zassert_ok(pqcp_sovereign_privacy_budget_remaining(
		&pb_mgr, "b1", PB_START + 1000U, &eps, &delta, &queries));
	zassert_equal(eps, 1000U);
	zassert_equal(queries, 10U);
	zassert_equal(pb_budgets[0].window_started_ms, PB_START + 1000U);
	zassert_ok(pqcp_sovereign_privacy_budget_consume(
		&pb_mgr, "b1", 1000U, 100U, 10U, PB_EPOCH, PB_START + 1000U));
	zassert_ok(pqcp_sovereign_privacy_budget_tick(
		&pb_mgr, PB_START + 2000U, &resets));
	zassert_equal(resets, 1U);
	zassert_equal(pb_budgets[0].epsilon_used_micros, 0U);
	zassert_equal(pqcp_sovereign_privacy_budget_tick(
			      &pb_mgr, 0U, &resets), -EINVAL);
	zassert_equal(pqcp_sovereign_privacy_budget_tick(
			      &pb_mgr, PB_START, NULL), -EINVAL);
}

ZTEST(pqcp_sovereign_policy, test_privacy_budget_put_rollback_and_identity)
{
	struct pqcp_sovereign_privacy_budget b;
	struct pqcp_sovereign_privacy_budget c;

	pb_setup();
	zassert_ok(pqcp_sovereign_privacy_budget_consume(
		&pb_mgr, "b1", 10U, 1U, 1U, PB_EPOCH, PB_START));
	memcpy(pb_snapshot, pb_budgets, sizeof(pb_budgets));

	/* Same or older epoch is a rollback and must not reset the usage. */
	mk_budget(&b, "b1");
	zassert_equal(pqcp_sovereign_privacy_budget_put(&pb_mgr, &b, PB_START),
		      -ESTALE);
	b.policy_epoch = PB_EPOCH - 1U;
	zassert_equal(pqcp_sovereign_privacy_budget_put(&pb_mgr, &b, PB_START),
		      -ESTALE);
	/* Re-binding an existing budget id to another tenant is refused. */
	mk_budget(&b, "b1");
	b.policy_epoch = PB_EPOCH + 1U;
	CP(b.tenant_id, "t2");
	zassert_equal(pqcp_sovereign_privacy_budget_put(&pb_mgr, &b, PB_START),
		      -EACCES);
	mk_budget(&b, "b1");
	b.policy_epoch = PB_EPOCH + 1U;
	CP(b.purpose, "marketing");
	zassert_equal(pqcp_sovereign_privacy_budget_put(&pb_mgr, &b, PB_START),
		      -EACCES);
	zassert_mem_equal(pb_snapshot, pb_budgets, sizeof(pb_budgets));
	zassert_equal(pb_mgr.denied_count, 4U);

	/* A strictly newer epoch is accepted and moves the epoch forward. */
	mk_budget(&b, "b1");
	b.policy_epoch = PB_EPOCH + 1U;
	zassert_ok(pqcp_sovereign_privacy_budget_put(&pb_mgr, &b, PB_START));
	zassert_equal(pb_budgets[0].policy_epoch, PB_EPOCH + 1U);
	zassert_equal(pqcp_sovereign_privacy_budget_consume(
			      &pb_mgr, "b1", 1U, 1U, 1U, PB_EPOCH, PB_START),
		      -ESTALE);

	/* Capacity. */
	mk_budget(&c, "b2");
	zassert_ok(pqcp_sovereign_privacy_budget_put(&pb_mgr, &c, PB_START));
	mk_budget(&c, "b3");
	zassert_equal(pqcp_sovereign_privacy_budget_put(&pb_mgr, &c, PB_START),
		      -ENOSPC);
	zassert_ok(pqcp_sovereign_privacy_budget_manager_audit(&pb_mgr));
}

/* ------------------------------------------------------------------ */
/* Consent ledger                                                     */
/* ------------------------------------------------------------------ */

static struct pqcp_sovereign_consent_record cl_records[2];
static struct pqcp_sovereign_consent_record cl_snapshot[2];
static struct pqcp_sovereign_consent_ledger cl_ledger;

#define CL_EPOCH 3U

static int cl_grant(const char *subject, const char *purpose, uint32_t mask,
		    uint64_t now, uint64_t expires,
		    struct pqcp_sovereign_consent_record **rec)
{
	return pqcp_sovereign_consent_grant(
		&cl_ledger, "t1", subject, "ctrl", purpose, mask, CL_EPOCH,
		DIGEST_A, DIGEST_A, now, expires, rec);
}

static int cl_auth(const char *subject, const char *purpose,
		   enum pqcp_sovereign_data_class cls, uint64_t epoch,
		   uint64_t now)
{
	return pqcp_sovereign_consent_authorize(
		&cl_ledger, "t1", subject, "ctrl", purpose, cls, epoch, now);
}

ZTEST(pqcp_sovereign_policy, test_consent_default_deny_and_grant)
{
	struct pqcp_sovereign_consent_record *rec = NULL;

	zassert_equal(pqcp_sovereign_consent_ledger_init(
			      NULL, cl_records, 2U), -EINVAL);
	zassert_equal(pqcp_sovereign_consent_ledger_init(
			      &cl_ledger, NULL, 2U), -EINVAL);
	zassert_equal(pqcp_sovereign_consent_ledger_init(
			      &cl_ledger, cl_records, 0U), -EINVAL);
	zassert_ok(pqcp_sovereign_consent_ledger_init(&cl_ledger, cl_records, 2U));

	/* Without a recorded consent every use is refused. */
	zassert_equal(cl_auth("s1", "marketing", PQCP_SOVEREIGN_DATA_PERSONAL,
			      CL_EPOCH, 1000U), -EACCES);
	zassert_ok(cl_grant("s1", "marketing",
			    BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL), 1000U,
			    2000U, &rec));
	zassert_not_null(rec);
	zassert_equal(rec->state, PQCP_SOVEREIGN_LIFECYCLE_ACTIVE);
	zassert_not_equal(rec->consent_id, 0U);
	zassert_equal(cl_ledger.grant_count, 1U);
	zassert_ok(cl_auth("s1", "marketing", PQCP_SOVEREIGN_DATA_PERSONAL,
			   CL_EPOCH, 1000U));
	zassert_ok(pqcp_sovereign_consent_ledger_audit(&cl_ledger));
}

ZTEST(pqcp_sovereign_policy, test_consent_scope_mismatch_denied)
{
	struct pqcp_sovereign_consent_record *rec;

	zassert_ok(pqcp_sovereign_consent_ledger_init(&cl_ledger, cl_records, 2U));
	zassert_ok(cl_grant("s1", "marketing",
			    BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL), 1000U,
			    2000U, &rec));
	/* Data class, subject, purpose, controller and tenant are all bound. */
	zassert_equal(cl_auth("s1", "marketing",
			      PQCP_SOVEREIGN_DATA_SENSITIVE_PERSONAL, CL_EPOCH,
			      1000U), -EACCES);
	zassert_equal(cl_auth("s2", "marketing", PQCP_SOVEREIGN_DATA_PERSONAL,
			      CL_EPOCH, 1000U), -EACCES);
	zassert_equal(cl_auth("s1", "billing", PQCP_SOVEREIGN_DATA_PERSONAL,
			      CL_EPOCH, 1000U), -EACCES);
	zassert_equal(pqcp_sovereign_consent_authorize(
			      &cl_ledger, "t1", "s1", "other-ctrl", "marketing",
			      PQCP_SOVEREIGN_DATA_PERSONAL, CL_EPOCH, 1000U),
		      -EACCES);
	zassert_equal(pqcp_sovereign_consent_authorize(
			      &cl_ledger, "t2", "s1", "ctrl", "marketing",
			      PQCP_SOVEREIGN_DATA_PERSONAL, CL_EPOCH, 1000U),
		      -EACCES);
}

ZTEST(pqcp_sovereign_policy, test_consent_expiry_epoch_and_clock_boundaries)
{
	struct pqcp_sovereign_consent_record *rec;
	uint32_t expired = 0U;

	zassert_ok(pqcp_sovereign_consent_ledger_init(&cl_ledger, cl_records, 2U));
	zassert_ok(cl_grant("s1", "marketing",
			    BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL), 1000U,
			    2000U, &rec));
	/* Before the grant instant, and at/after expiry. */
	zassert_equal(cl_auth("s1", "marketing", PQCP_SOVEREIGN_DATA_PERSONAL,
			      CL_EPOCH, 999U), -ETIME);
	zassert_ok(cl_auth("s1", "marketing", PQCP_SOVEREIGN_DATA_PERSONAL,
			   CL_EPOCH, 1999U));
	zassert_equal(cl_auth("s1", "marketing", PQCP_SOVEREIGN_DATA_PERSONAL,
			      CL_EPOCH, 2000U), -ETIME);
	/* Policy-epoch mismatch. */
	zassert_equal(cl_auth("s1", "marketing", PQCP_SOVEREIGN_DATA_PERSONAL,
			      CL_EPOCH + 1U, 1500U), -ESTALE);
	zassert_equal(cl_auth("s1", "marketing", PQCP_SOVEREIGN_DATA_PERSONAL,
			      CL_EPOCH - 1U, 1500U), -ESTALE);

	zassert_ok(pqcp_sovereign_consent_tick(&cl_ledger, 1999U, &expired));
	zassert_equal(expired, 0U);
	zassert_ok(pqcp_sovereign_consent_tick(&cl_ledger, 2000U, &expired));
	zassert_equal(expired, 1U);
	zassert_equal(cl_records[0].state, PQCP_SOVEREIGN_LIFECYCLE_RETIRED);
	/* An expired consent never authorises, even with a rewound clock. */
	zassert_equal(cl_auth("s1", "marketing", PQCP_SOVEREIGN_DATA_PERSONAL,
			      CL_EPOCH, 1500U), -EACCES);
	zassert_equal(pqcp_sovereign_consent_tick(&cl_ledger, 0U, &expired),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_consent_tick(&cl_ledger, 2000U, NULL),
		      -EINVAL);
}

ZTEST(pqcp_sovereign_policy, test_consent_revoke_and_regrant)
{
	struct pqcp_sovereign_consent_record *rec;
	struct pqcp_sovereign_consent_record *dup;
	uint64_t first_id;

	zassert_ok(pqcp_sovereign_consent_ledger_init(&cl_ledger, cl_records, 2U));
	zassert_ok(cl_grant("s1", "marketing",
			    BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL), 1000U,
			    5000U, &rec));
	first_id = rec->consent_id;
	/* A second overlapping active consent is a replay/duplicate. */
	zassert_equal(cl_grant("s1", "marketing",
			       BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL) |
				       BIT_CLASS(PQCP_SOVEREIGN_DATA_INTERNAL),
			       1100U, 5000U, &dup), -EALREADY);
	zassert_equal(cl_ledger.grant_count, 1U);

	zassert_equal(pqcp_sovereign_consent_revoke(&cl_ledger, 0U, 1500U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_consent_revoke(&cl_ledger, 424242U, 1500U),
		      -ENOENT);
	zassert_equal(pqcp_sovereign_consent_revoke(&cl_ledger, first_id, 999U),
		      -ETIME);
	zassert_equal(cl_records[0].state, PQCP_SOVEREIGN_LIFECYCLE_ACTIVE);
	zassert_ok(pqcp_sovereign_consent_revoke(&cl_ledger, first_id, 1500U));
	zassert_equal(cl_records[0].revoked_at_ms, 1500U);
	zassert_equal(pqcp_sovereign_consent_revoke(&cl_ledger, first_id, 1600U),
		      -EALREADY);
	zassert_equal(cl_ledger.revoke_count, 1U);
	/* Withdrawn consent is immediately unusable. */
	zassert_equal(cl_auth("s1", "marketing", PQCP_SOVEREIGN_DATA_PERSONAL,
			      CL_EPOCH, 1500U), -EACCES);
	zassert_ok(pqcp_sovereign_consent_ledger_audit(&cl_ledger));

	/* A fresh consent is allowed after revocation and gets a new id. */
	zassert_ok(cl_grant("s1", "marketing",
			    BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL), 1600U,
			    5000U, &rec));
	zassert_true(rec->consent_id > first_id);
	zassert_ok(cl_auth("s1", "marketing", PQCP_SOVEREIGN_DATA_PERSONAL,
			   CL_EPOCH, 1600U));
}

ZTEST(pqcp_sovereign_policy, test_consent_grant_rejections_do_not_mutate)
{
	struct pqcp_sovereign_consent_record *rec = NULL;
	uint8_t bad_digest[PQCP_SOVEREIGN_DIGEST_BYTES] = { 0 };

	zassert_ok(pqcp_sovereign_consent_ledger_init(&cl_ledger, cl_records, 2U));
	memcpy(cl_snapshot, cl_records, sizeof(cl_records));

	/* expires_at must be strictly after now. */
	zassert_equal(cl_grant("s1", "p", BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL),
			       1000U, 1000U, &rec), -EINVAL);
	zassert_equal(cl_grant("s1", "p", BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL),
			       1000U, 999U, &rec), -EINVAL);
	zassert_equal(cl_grant("s1", "p", BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL),
			       0U, 2000U, &rec), -EINVAL);
	zassert_equal(cl_grant("s1", "p", 0U, 1000U, 2000U, &rec), -EINVAL);
	zassert_equal(cl_grant("s1", "p", 1U << PQCP_SOVEREIGN_DATA_CLASS_COUNT,
			       1000U, 2000U, &rec), -EINVAL);
	zassert_equal(cl_grant("s1", "p", BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL),
			       1000U, 2000U, NULL), -EINVAL);
	zassert_equal(pqcp_sovereign_consent_grant(
			      &cl_ledger, "t1", "s1", "ctrl", "p",
			      BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL), 0U,
			      DIGEST_A, DIGEST_A, 1000U, 2000U, &rec), -EINVAL);
	/* Zero (absent) terms or receipt digests are not evidence. */
	zassert_equal(pqcp_sovereign_consent_grant(
			      &cl_ledger, "t1", "s1", "ctrl", "p",
			      BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL), CL_EPOCH,
			      bad_digest, DIGEST_A, 1000U, 2000U, &rec),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_consent_grant(
			      &cl_ledger, "t1", "s1", "ctrl", "p",
			      BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL), CL_EPOCH,
			      DIGEST_A, NULL, 1000U, 2000U, &rec), -EINVAL);
	zassert_equal(pqcp_sovereign_consent_grant(
			      NULL, "t1", "s1", "ctrl", "p",
			      BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL), CL_EPOCH,
			      DIGEST_A, DIGEST_A, 1000U, 2000U, &rec), -EINVAL);
	zassert_mem_equal(cl_snapshot, cl_records, sizeof(cl_records));
	zassert_equal(cl_ledger.grant_count, 0U);
	zassert_equal(cl_ledger.next_consent_id, 1U);

	/* Capacity exhaustion with distinct subjects. */
	zassert_ok(cl_grant("s1", "p", BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL),
			    1000U, 2000U, &rec));
	zassert_ok(cl_grant("s2", "p", BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL),
			    1000U, 2000U, &rec));
	zassert_equal(cl_grant("s3", "p", BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL),
			       1000U, 2000U, &rec), -ENOSPC);
	zassert_equal(cl_ledger.grant_count, 2U);
	/* Authorize argument validation. */
	zassert_equal(pqcp_sovereign_consent_authorize(
			      &cl_ledger, "t1", "s1", "ctrl", "p",
			      (enum pqcp_sovereign_data_class)
				      PQCP_SOVEREIGN_DATA_CLASS_COUNT,
			      CL_EPOCH, 1500U), -EINVAL);
	zassert_equal(cl_auth("s1", "p", PQCP_SOVEREIGN_DATA_PERSONAL, 0U, 1500U),
		      -EINVAL);
	zassert_equal(cl_auth("s1", "p", PQCP_SOVEREIGN_DATA_PERSONAL,
			      CL_EPOCH, 0U), -EINVAL);
	zassert_equal(cl_auth(NULL, "p", PQCP_SOVEREIGN_DATA_PERSONAL,
			      CL_EPOCH, 1500U), -EINVAL);
	zassert_ok(pqcp_sovereign_consent_ledger_audit(&cl_ledger));
}

/* ------------------------------------------------------------------ */
/* Data contract                                                      */
/* ------------------------------------------------------------------ */

static struct pqcp_sovereign_data_contract dc_contracts[3];
static struct pqcp_sovereign_data_contract dc_snapshot[3];
static struct pqcp_sovereign_data_contract_manager dc_mgr;

#define DC_EPOCH 3U
#define DC_NOW 1000U

static void mk_contract(struct pqcp_sovereign_data_contract *c,
			const char *dataset)
{
	memset(c, 0, sizeof(*c));
	CP(c->provider_id, "prov");
	CP(c->consumer_id, "cons");
	CP(c->dataset_id, dataset);
	CP(c->purpose, "research");
	CP(c->source_zone, "eu-west");
	CP(c->destination_zone, "eu-central");
	c->data_class = PQCP_SOVEREIGN_DATA_PERSONAL;
	c->operation_mask = BIT_OP(PQCP_SOVEREIGN_OPERATION_READ_DATA) |
			    BIT_OP(PQCP_SOVEREIGN_OPERATION_EXPORT_DATA);
	c->policy_epoch = DC_EPOCH;
	c->effective_at_ms = DC_NOW;
	c->expires_at_ms = 5000U;
	c->maximum_records = 100U;
	c->maximum_bytes = 10000U;
	c->maximum_risk = 500U;
	c->require_consent = true;
	c->require_encryption = true;
	memcpy(c->terms_digest, DIGEST_A, sizeof(c->terms_digest));
	c->state = PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
}

static int dc_auth(uint64_t id, enum pqcp_sovereign_operation op,
		   uint64_t records, uint64_t bytes, uint32_t risk,
		   bool consent, bool enc, uint64_t epoch, uint64_t now)
{
	return pqcp_sovereign_data_contract_authorize(
		&dc_mgr, id, "prov", "cons", "ds1", "research", op, records,
		bytes, risk, consent, enc, epoch, now);
}

static void dc_setup_one(void)
{
	struct pqcp_sovereign_data_contract c;

	zassert_ok(pqcp_sovereign_data_contract_manager_init(
		&dc_mgr, dc_contracts, 3U));
	mk_contract(&c, "ds1");
	zassert_ok(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW));
	zassert_equal(dc_contracts[0].contract_id, 1U);
}

ZTEST(pqcp_sovereign_policy, test_data_contract_default_deny_and_allow)
{
	zassert_equal(pqcp_sovereign_data_contract_manager_init(
			      NULL, dc_contracts, 3U), -EINVAL);
	zassert_equal(pqcp_sovereign_data_contract_manager_init(
			      &dc_mgr, NULL, 3U), -EINVAL);
	zassert_equal(pqcp_sovereign_data_contract_manager_init(
			      &dc_mgr, dc_contracts, 0U), -EINVAL);
	zassert_ok(pqcp_sovereign_data_contract_manager_init(
		&dc_mgr, dc_contracts, 3U));
	/* No contract: nothing is authorised. */
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U,
			      0U, true, true, DC_EPOCH, DC_NOW), -ENOENT);
	zassert_equal(dc_mgr.denial_count, 1U);

	dc_setup_one();
	zassert_ok(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U, 0U,
			   true, true, DC_EPOCH, DC_NOW));
	zassert_equal(dc_mgr.authorize_count, 1U);
	zassert_equal(dc_contracts[0].records_used, 1U);
	zassert_equal(dc_contracts[0].bytes_used, 1U);
	zassert_ok(pqcp_sovereign_data_contract_manager_audit(&dc_mgr));
}

ZTEST(pqcp_sovereign_policy, test_data_contract_quota_boundaries_atomic)
{
	dc_setup_one();
	/* Spend 60 records / 6000 bytes, then probe each dimension. */
	zassert_ok(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 60U, 6000U,
			   0U, true, true, DC_EPOCH, DC_NOW));
	memcpy(dc_snapshot, dc_contracts, sizeof(dc_contracts));
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 41U, 1U,
			      0U, true, true, DC_EPOCH, DC_NOW), -EDQUOT);
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 4001U,
			      0U, true, true, DC_EPOCH, DC_NOW), -EDQUOT);
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA,
			      UINT64_MAX, 1U, 0U, true, true, DC_EPOCH, DC_NOW),
		      -EDQUOT);
	zassert_mem_equal(dc_snapshot, dc_contracts, sizeof(dc_contracts));
	/* Exactly the remaining quota is permitted. */
	zassert_ok(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 40U, 4000U,
			   0U, true, true, DC_EPOCH, DC_NOW));
	zassert_equal(dc_contracts[0].records_used, 100U);
	zassert_equal(dc_contracts[0].bytes_used, 10000U);
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U,
			      0U, true, true, DC_EPOCH, DC_NOW), -EDQUOT);
}

ZTEST(pqcp_sovereign_policy, test_data_contract_party_epoch_time_and_conditions)
{
	dc_setup_one();
	memcpy(dc_snapshot, dc_contracts, sizeof(dc_contracts));

	/* Party / dataset / purpose binding. */
	zassert_equal(pqcp_sovereign_data_contract_authorize(
			      &dc_mgr, 1U, "evil", "cons", "ds1", "research",
			      PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U, 0U,
			      true, true, DC_EPOCH, DC_NOW), -EACCES);
	zassert_equal(pqcp_sovereign_data_contract_authorize(
			      &dc_mgr, 1U, "prov", "evil", "ds1", "research",
			      PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U, 0U,
			      true, true, DC_EPOCH, DC_NOW), -EACCES);
	zassert_equal(pqcp_sovereign_data_contract_authorize(
			      &dc_mgr, 1U, "prov", "cons", "ds2", "research",
			      PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U, 0U,
			      true, true, DC_EPOCH, DC_NOW), -EACCES);
	zassert_equal(pqcp_sovereign_data_contract_authorize(
			      &dc_mgr, 1U, "prov", "cons", "ds1", "ads",
			      PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U, 0U,
			      true, true, DC_EPOCH, DC_NOW), -EACCES);
	/* Epoch. */
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U,
			      0U, true, true, DC_EPOCH - 1U, DC_NOW), -ESTALE);
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U,
			      0U, true, true, DC_EPOCH + 1U, DC_NOW), -ESTALE);
	/* Validity window: [effective, expires). */
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U,
			      0U, true, true, DC_EPOCH, DC_NOW - 1U), -ETIME);
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U,
			      0U, true, true, DC_EPOCH, 5000U), -ETIME);
	/* Operation outside the mask. */
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_WRITE_DATA, 1U, 1U,
			      0U, true, true, DC_EPOCH, DC_NOW), -EACCES);
	/* Risk boundary. */
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U,
			      501U, true, true, DC_EPOCH, DC_NOW), -ERANGE);
	/* Consent / encryption preconditions. */
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U,
			      0U, false, true, DC_EPOCH, DC_NOW), -EACCES);
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U,
			      0U, true, false, DC_EPOCH, DC_NOW), -EACCES);
	/* Nothing above consumed quota. */
	zassert_mem_equal(dc_snapshot, dc_contracts, sizeof(dc_contracts));
	zassert_equal(dc_mgr.authorize_count, 0U);
	/* Last valid instant is still allowed. */
	zassert_ok(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U, 500U,
			   true, true, DC_EPOCH, 4999U));
}

ZTEST(pqcp_sovereign_policy, test_data_contract_invalid_arguments)
{
	struct pqcp_sovereign_data_contract c;

	dc_setup_one();
	memcpy(dc_snapshot, dc_contracts, sizeof(dc_contracts));
	zassert_equal(dc_auth(0U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U,
			      0U, true, true, DC_EPOCH, DC_NOW), -EINVAL);
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_NONE, 1U, 1U, 0U,
			      true, true, DC_EPOCH, DC_NOW), -EINVAL);
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_COUNT, 1U, 1U, 0U,
			      true, true, DC_EPOCH, DC_NOW), -EINVAL);
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 0U, 1U,
			      0U, true, true, DC_EPOCH, DC_NOW), -EINVAL);
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 0U,
			      0U, true, true, DC_EPOCH, DC_NOW), -EINVAL);
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U,
			      1001U, true, true, DC_EPOCH, DC_NOW), -EINVAL);
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U,
			      0U, true, true, 0U, DC_NOW), -EINVAL);
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U,
			      0U, true, true, DC_EPOCH, 0U), -EINVAL);

	/* put() validation. */
	mk_contract(&c, "ds2");
	c.effective_at_ms = DC_NOW - 1U; /* backdated */
	zassert_equal(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW),
		      -EINVAL);
	mk_contract(&c, "ds2");
	c.expires_at_ms = c.effective_at_ms;
	zassert_equal(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW),
		      -EINVAL);
	mk_contract(&c, "ds2");
	CP(c.consumer_id, "prov"); /* self-dealing contract */
	zassert_equal(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW),
		      -EINVAL);
	mk_contract(&c, "ds2");
	memset(c.terms_digest, 0, sizeof(c.terms_digest));
	zassert_equal(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW),
		      -EINVAL);
	mk_contract(&c, "ds2");
	c.maximum_risk = 1001U;
	zassert_equal(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW),
		      -EINVAL);
	mk_contract(&c, "ds2");
	c.maximum_records = 0U;
	zassert_equal(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW),
		      -EINVAL);
	mk_contract(&c, "ds2");
	c.operation_mask = 0U;
	zassert_equal(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW),
		      -EINVAL);
	mk_contract(&c, "ds2");
	c.data_class = (enum pqcp_sovereign_data_class)
		PQCP_SOVEREIGN_DATA_CLASS_COUNT;
	zassert_equal(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW),
		      -EINVAL);
	mk_contract(&c, "ds2");
	c.state = PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
	zassert_equal(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_data_contract_put(&dc_mgr, NULL, DC_NOW),
		      -EINVAL);
	zassert_mem_equal(dc_snapshot, dc_contracts, sizeof(dc_contracts));
}

ZTEST(pqcp_sovereign_policy, test_data_contract_revoke_tick_and_duplicates)
{
	struct pqcp_sovereign_data_contract c;
	uint32_t expired = 0U;

	dc_setup_one();
	/* Overlapping contract for the same tuple is a duplicate. */
	mk_contract(&c, "ds1");
	zassert_equal(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW),
		      -EALREADY);
	/* Different dataset is fine. */
	mk_contract(&c, "ds2");
	zassert_ok(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW));
	mk_contract(&c, "ds3");
	zassert_ok(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW));
	mk_contract(&c, "ds4");
	zassert_equal(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW),
		      -ENOSPC);
	zassert_ok(pqcp_sovereign_data_contract_manager_audit(&dc_mgr));

	/* Revocation. */
	zassert_equal(pqcp_sovereign_data_contract_revoke(&dc_mgr, 0U), -EINVAL);
	zassert_equal(pqcp_sovereign_data_contract_revoke(&dc_mgr, 999U),
		      -ENOENT);
	zassert_ok(pqcp_sovereign_data_contract_revoke(&dc_mgr, 1U));
	zassert_equal(pqcp_sovereign_data_contract_revoke(&dc_mgr, 1U),
		      -EALREADY);
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U,
			      0U, true, true, DC_EPOCH, DC_NOW), -EACCES);

	/* Expiry tick retires the others at exactly expires_at_ms. */
	zassert_ok(pqcp_sovereign_data_contract_tick(&dc_mgr, 4999U, &expired));
	zassert_equal(expired, 0U);
	zassert_ok(pqcp_sovereign_data_contract_tick(&dc_mgr, 5000U, &expired));
	zassert_equal(expired, 2U);
	zassert_equal(pqcp_sovereign_data_contract_tick(&dc_mgr, 0U, &expired),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_data_contract_tick(&dc_mgr, 5000U, NULL),
		      -EINVAL);
}

ZTEST(pqcp_sovereign_policy, test_data_contract_update_rules)
{
	struct pqcp_sovereign_data_contract c;

	dc_setup_one();
	zassert_ok(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 50U, 5000U,
			   0U, true, true, DC_EPOCH, DC_NOW));

	/* Same-epoch update is a rollback/replay. */
	mk_contract(&c, "ds1");
	c.contract_id = 1U;
	zassert_equal(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW),
		      -ESTALE);
	/* Shrinking the cap below what was already used is refused. */
	mk_contract(&c, "ds1");
	c.contract_id = 1U;
	c.policy_epoch = DC_EPOCH + 1U;
	c.maximum_records = 49U;
	zassert_equal(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW),
		      -ESTALE);
	/* Cannot re-point an existing id at a different dataset. */
	mk_contract(&c, "other-ds");
	c.contract_id = 1U;
	c.policy_epoch = DC_EPOCH + 1U;
	zassert_equal(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW),
		      -EACCES);
	/* Valid update keeps the consumption counters. */
	mk_contract(&c, "ds1");
	c.contract_id = 1U;
	c.policy_epoch = DC_EPOCH + 1U;
	c.maximum_records = 50U;
	c.maximum_bytes = 5000U;
	zassert_ok(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW));
	zassert_equal(dc_contracts[0].records_used, 50U);
	zassert_equal(dc_contracts[0].bytes_used, 5000U);
	zassert_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U,
			      0U, true, true, DC_EPOCH + 1U, DC_NOW), -EDQUOT);
}

ZTEST(pqcp_sovereign_policy, test_data_contract_revoked_stays_revoked)
{
	/* Regression: put() of a REVOKED contract id with a higher epoch used
	 * to force the state back to ACTIVE, so revocation was not terminal.
	 */
	struct pqcp_sovereign_data_contract c;

	dc_setup_one();
	zassert_ok(pqcp_sovereign_data_contract_revoke(&dc_mgr, 1U));
	/* Re-submitting the revoked id with a newer epoch. */
	mk_contract(&c, "ds1");
	c.contract_id = 1U;
	c.policy_epoch = DC_EPOCH + 1U;
	(void)pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW);
	/* Revocation is terminal: a revoked contract must never authorise. */
	zassert_not_equal(dc_auth(1U, PQCP_SOVEREIGN_OPERATION_READ_DATA, 1U, 1U,
				  0U, true, true, DC_EPOCH + 1U, DC_NOW), 0,
			  "revoked contract authorises again after put()");
}

ZTEST(pqcp_sovereign_policy, test_data_contract_generated_id_not_colliding)
{
	/* Regression: a caller-chosen non-zero id for a new contract did not
	 * advance next_contract_id, so a later auto-assigned id (0) was handed
	 * out equal to it and the audit reported -EEXIST.
	 */
	struct pqcp_sovereign_data_contract c;

	zassert_ok(pqcp_sovereign_data_contract_manager_init(
		&dc_mgr, dc_contracts, 3U));
	/* Caller-chosen id 1 ... */
	mk_contract(&c, "ds1");
	c.contract_id = 1U;
	zassert_ok(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW));
	/* ... then an auto-assigned contract must get a distinct id. */
	mk_contract(&c, "ds2");
	zassert_ok(pqcp_sovereign_data_contract_put(&dc_mgr, &c, DC_NOW));
	zassert_not_equal(dc_contracts[0].contract_id,
			  dc_contracts[1].contract_id,
			  "auto-assigned contract id collides with caller id");
	zassert_ok(pqcp_sovereign_data_contract_manager_audit(&dc_mgr));
}

/* ------------------------------------------------------------------ */
/* Placement engine                                                   */
/* ------------------------------------------------------------------ */

static struct pqcp_sovereign_placement_node pl_nodes[3];
static struct pqcp_sovereign_placement_node pl_snapshot[3];
static struct pqcp_sovereign_placement_reservation pl_res[3];
static struct pqcp_sovereign_placement_engine pl_eng;

#define PL_EPOCH 4U
#define PL_NOW 1000U

static void mk_node(struct pqcp_sovereign_placement_node *n, const char *id,
		    const char *tenant, uint32_t risk)
{
	memset(n, 0, sizeof(*n));
	CP(n->node_id, id);
	CP(n->tenant_id, tenant);
	CP(n->zone, "eu-west");
	CP(n->jurisdiction, "EU");
	n->capability_mask = 0x7U;
	n->total_compute_units = 100U;
	n->available_compute_units = 100U;
	n->total_memory_bytes = 1000U;
	n->available_memory_bytes = 1000U;
	n->policy_epoch = PL_EPOCH;
	n->attested_at_ms = 500U;
	n->attestation_expires_at_ms = 5000U;
	n->risk_score = risk;
	n->maximum_workloads = 4U;
	n->confidential_compute = true;
}

static void mk_req(struct pqcp_sovereign_placement_request *r)
{
	memset(r, 0, sizeof(*r));
	CP(r->workload_id, "w1");
	CP(r->tenant_id, "t1");
	CP(r->required_zone, "eu-west");
	r->required_capabilities = 0x1U;
	r->compute_units = 10U;
	r->memory_bytes = 100U;
	r->policy_epoch = PL_EPOCH;
	r->now_ms = PL_NOW;
	r->maximum_risk = 50U;
}

static void pl_setup(size_t res_capacity)
{
	zassert_ok(pqcp_sovereign_placement_engine_init(
		&pl_eng, pl_nodes, 3U, pl_res, res_capacity));
}

ZTEST(pqcp_sovereign_policy, test_placement_default_deny_and_validation)
{
	struct pqcp_sovereign_placement_node node;
	struct pqcp_sovereign_placement_request req;
	struct pqcp_sovereign_placement_reservation *res = (void *)1;

	zassert_equal(pqcp_sovereign_placement_engine_init(
			      NULL, pl_nodes, 3U, pl_res, 3U), -EINVAL);
	zassert_equal(pqcp_sovereign_placement_engine_init(
			      &pl_eng, NULL, 3U, pl_res, 3U), -EINVAL);
	zassert_equal(pqcp_sovereign_placement_engine_init(
			      &pl_eng, pl_nodes, 0U, pl_res, 3U), -EINVAL);
	zassert_equal(pqcp_sovereign_placement_engine_init(
			      &pl_eng, pl_nodes, 3U, NULL, 3U), -EINVAL);
	zassert_equal(pqcp_sovereign_placement_engine_init(
			      &pl_eng, pl_nodes, 3U, pl_res, 0U), -EINVAL);
	pl_setup(3U);

	/* No node registered: placement is refused and reported as such. */
	mk_req(&req);
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -ENODEV);
	zassert_is_null(res);
	zassert_equal(pl_eng.denial_count, 1U);
	zassert_equal(pl_eng.placement_count, 0U);

	/* Node validation. */
	mk_node(&node, "n1", "t1", 10U);
	node.attestation_expires_at_ms = PL_NOW; /* already expired */
	zassert_equal(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW),
		      -EINVAL);
	mk_node(&node, "n1", "t1", 10U);
	node.attested_at_ms = 0U;
	zassert_equal(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW),
		      -EINVAL);
	mk_node(&node, "n1", "t1", 10U);
	node.policy_epoch = 0U;
	zassert_equal(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW),
		      -EINVAL);
	mk_node(&node, "n1", "t1", 10U);
	node.available_compute_units = node.total_compute_units + 1U;
	zassert_equal(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW),
		      -EINVAL);
	mk_node(&node, "n1", "t1", 10U);
	node.available_memory_bytes = node.total_memory_bytes + 1U;
	zassert_equal(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW),
		      -EINVAL);
	mk_node(&node, "n1", "t1", 10U);
	node.active_workloads = node.maximum_workloads + 1U;
	zassert_equal(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW),
		      -EINVAL);
	mk_node(&node, "n1", "t1", 10U);
	CP(node.zone, "bad zone");
	zassert_equal(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_placement_node_put(&pl_eng, NULL, PL_NOW),
		      -EINVAL);
	mk_node(&node, "n1", "t1", 10U);
	zassert_equal(pqcp_sovereign_placement_node_put(&pl_eng, &node, 0U),
		      -EINVAL);
	zassert_ok(pqcp_sovereign_placement_engine_audit(&pl_eng));
	for (size_t i = 0U; i < 3U; ++i) {
		zassert_false(pl_nodes[i].occupied);
	}
}

ZTEST(pqcp_sovereign_policy, test_placement_reserve_activate_release_accounting)
{
	struct pqcp_sovereign_placement_node node;
	struct pqcp_sovereign_placement_request req;
	struct pqcp_sovereign_placement_reservation *res = NULL;
	uint64_t id;

	pl_setup(3U);
	mk_node(&node, "n1", "t1", 10U);
	zassert_ok(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW));
	mk_req(&req);
	zassert_ok(pqcp_sovereign_placement_reserve(&pl_eng, &req, 100U, &res));
	zassert_not_null(res);
	id = res->reservation_id;
	zassert_equal(res->state, PQCP_SOVEREIGN_LIFECYCLE_DRAFT);
	zassert_equal(strcmp(res->node_id, "n1"), 0);
	zassert_equal(res->expires_at_ms, PL_NOW + 100U);
	zassert_equal(pl_nodes[0].available_compute_units, 90U);
	zassert_equal(pl_nodes[0].available_memory_bytes, 900U);
	zassert_equal(pl_nodes[0].active_workloads, 1U);
	zassert_equal(pl_eng.placement_count, 1U);

	zassert_equal(pqcp_sovereign_placement_activate(&pl_eng, 0U), -EINVAL);
	zassert_equal(pqcp_sovereign_placement_activate(&pl_eng, 999U), -ENOENT);
	zassert_ok(pqcp_sovereign_placement_activate(&pl_eng, id));
	zassert_equal(res->state, PQCP_SOVEREIGN_LIFECYCLE_ACTIVE);
	zassert_equal(pqcp_sovereign_placement_activate(&pl_eng, id), -EALREADY);

	zassert_ok(pqcp_sovereign_placement_engine_audit(&pl_eng));
	zassert_ok(pqcp_sovereign_placement_release(&pl_eng, id));
	zassert_equal(pl_nodes[0].available_compute_units, 100U);
	zassert_equal(pl_nodes[0].available_memory_bytes, 1000U);
	zassert_equal(pl_nodes[0].active_workloads, 0U);
	/* Double release must not credit capacity twice. */
	zassert_equal(pqcp_sovereign_placement_release(&pl_eng, id), -EALREADY);
	zassert_equal(pl_nodes[0].available_compute_units, 100U);
	zassert_equal(pqcp_sovereign_placement_release(&pl_eng, 0U), -EINVAL);
	zassert_equal(pqcp_sovereign_placement_release(&pl_eng, 999U), -ENOENT);
}

ZTEST(pqcp_sovereign_policy, test_placement_resource_boundaries_no_mutation)
{
	struct pqcp_sovereign_placement_node node;
	struct pqcp_sovereign_placement_request req;
	struct pqcp_sovereign_placement_reservation *res = NULL;

	pl_setup(3U);
	mk_node(&node, "n1", "t1", 10U);
	zassert_ok(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW));
	memcpy(pl_snapshot, pl_nodes, sizeof(pl_nodes));

	mk_req(&req);
	req.compute_units = 101U; /* one past */
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -ENODEV);
	mk_req(&req);
	req.memory_bytes = 1001U; /* one past */
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -ENODEV);
	zassert_mem_equal(pl_snapshot, pl_nodes, sizeof(pl_nodes));
	zassert_false(pl_res[0].occupied);

	/* Exactly everything that is available fits. */
	mk_req(&req);
	req.compute_units = 100U;
	req.memory_bytes = 1000U;
	zassert_ok(pqcp_sovereign_placement_reserve(&pl_eng, &req, 100U, &res));
	zassert_equal(pl_nodes[0].available_compute_units, 0U);
	zassert_equal(pl_nodes[0].available_memory_bytes, 0U);
	/* And nothing more. */
	mk_req(&req);
	req.compute_units = 1U;
	req.memory_bytes = 1U;
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -ENODEV);
	zassert_is_null(res);
}

ZTEST(pqcp_sovereign_policy, test_placement_constraint_mismatches_rejected)
{
	struct pqcp_sovereign_placement_node node;
	struct pqcp_sovereign_placement_request req;
	struct pqcp_sovereign_placement_reservation *res = NULL;

	pl_setup(3U);
	mk_node(&node, "n1", "t1", 10U);
	node.maximum_workloads = 1U;
	zassert_ok(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW));
	memcpy(pl_snapshot, pl_nodes, sizeof(pl_nodes));

	mk_req(&req);
	CP(req.required_zone, "us-east"); /* region mismatch */
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -ENODEV);
	mk_req(&req);
	CP(req.required_jurisdiction, "US");
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -ENODEV);
	mk_req(&req);
	CP(req.tenant_id, "t2"); /* tenant mismatch */
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -ENODEV);
	mk_req(&req);
	req.policy_epoch = PL_EPOCH + 1U;
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -ENODEV);
	mk_req(&req);
	req.policy_epoch = PL_EPOCH - 1U;
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -ENODEV);
	mk_req(&req);
	req.required_capabilities = 0x8U; /* not offered */
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -ENODEV);
	mk_req(&req);
	req.maximum_risk = 9U; /* node risk is 10 */
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -ENODEV);
	/* Attestation validity: [attested, expires). */
	mk_req(&req);
	req.now_ms = 5000U;
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -ENODEV);
	zassert_mem_equal(pl_snapshot, pl_nodes, sizeof(pl_nodes));
	req.now_ms = 4999U;
	zassert_ok(pqcp_sovereign_placement_reserve(&pl_eng, &req, 100U, &res));
	/* Maximum workloads reached (limit 1). */
	mk_req(&req);
	CP(req.workload_id, "w2");
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -ENODEV);
	zassert_equal(pl_nodes[0].active_workloads, 1U);
}

ZTEST(pqcp_sovereign_policy, test_placement_confidential_and_lowest_risk_selection)
{
	struct pqcp_sovereign_placement_node node;
	struct pqcp_sovereign_placement_request req;
	struct pqcp_sovereign_placement_reservation *res = NULL;

	pl_setup(3U);
	mk_node(&node, "n-risky", "t1", 40U);
	zassert_ok(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW));
	mk_node(&node, "n-safe-plain", "t1", 5U);
	node.confidential_compute = false;
	zassert_ok(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW));
	mk_node(&node, "n-safe-cc", "t1", 20U);
	zassert_ok(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW));

	/* Lowest risk node wins when no confidentiality is demanded. */
	mk_req(&req);
	zassert_ok(pqcp_sovereign_placement_reserve(&pl_eng, &req, 100U, &res));
	zassert_equal(strcmp(res->node_id, "n-safe-plain"), 0);
	zassert_ok(pqcp_sovereign_placement_release(&pl_eng, res->reservation_id));

	/* Confidential compute demanded: the plain node is ineligible. */
	mk_req(&req);
	req.require_confidential_compute = true;
	zassert_ok(pqcp_sovereign_placement_reserve(&pl_eng, &req, 100U, &res));
	zassert_equal(strcmp(res->node_id, "n-safe-cc"), 0);
}

ZTEST(pqcp_sovereign_policy, test_placement_tick_expires_only_unactivated)
{
	struct pqcp_sovereign_placement_node node;
	struct pqcp_sovereign_placement_request req;
	struct pqcp_sovereign_placement_reservation *draft = NULL;
	struct pqcp_sovereign_placement_reservation *active = NULL;
	uint32_t expired = 99U;

	pl_setup(3U);
	mk_node(&node, "n1", "t1", 10U);
	zassert_ok(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW));
	mk_req(&req);
	zassert_ok(pqcp_sovereign_placement_reserve(&pl_eng, &req, 100U, &draft));
	CP(req.workload_id, "w2");
	zassert_ok(pqcp_sovereign_placement_reserve(&pl_eng, &req, 100U, &active));
	zassert_ok(pqcp_sovereign_placement_activate(
		&pl_eng, active->reservation_id));
	zassert_equal(pl_nodes[0].available_compute_units, 80U);

	zassert_ok(pqcp_sovereign_placement_tick(&pl_eng, PL_NOW + 99U, &expired));
	zassert_equal(expired, 0U);
	zassert_ok(pqcp_sovereign_placement_tick(&pl_eng, PL_NOW + 100U, &expired));
	zassert_equal(expired, 1U);
	zassert_equal(draft->state, PQCP_SOVEREIGN_LIFECYCLE_REVOKED);
	zassert_equal(active->state, PQCP_SOVEREIGN_LIFECYCLE_ACTIVE);
	/* Capacity of the expired draft is returned, active one is held. */
	zassert_equal(pl_nodes[0].available_compute_units, 90U);
	zassert_equal(pl_nodes[0].active_workloads, 1U);
	zassert_ok(pqcp_sovereign_placement_tick(&pl_eng, PL_NOW + 100000U,
						 &expired));
	zassert_equal(expired, 0U);
	zassert_equal(pqcp_sovereign_placement_tick(&pl_eng, 0U, &expired),
		      -EINVAL);
	zassert_ok(pqcp_sovereign_placement_engine_audit(&pl_eng));
}

ZTEST(pqcp_sovereign_policy, test_placement_reserve_invalid_args_and_capacity)
{
	struct pqcp_sovereign_placement_node node;
	struct pqcp_sovereign_placement_request req;
	struct pqcp_sovereign_placement_reservation *res = NULL;

	pl_setup(1U);
	mk_node(&node, "n1", "t1", 10U);
	zassert_ok(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW));
	memcpy(pl_snapshot, pl_nodes, sizeof(pl_nodes));

	mk_req(&req);
	zassert_equal(pqcp_sovereign_placement_reserve(
			      NULL, &req, 100U, &res), -EINVAL);
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, NULL, 100U, &res), -EINVAL);
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, NULL), -EINVAL);
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 0U, &res), -EINVAL);
	req.compute_units = 0U;
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -EINVAL);
	mk_req(&req);
	req.memory_bytes = 0U;
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -EINVAL);
	mk_req(&req);
	req.policy_epoch = 0U;
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -EINVAL);
	mk_req(&req);
	req.now_ms = 0U;
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -EINVAL);
	mk_req(&req);
	CP(req.workload_id, "");
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -EINVAL);
	zassert_mem_equal(pl_snapshot, pl_nodes, sizeof(pl_nodes));

	/* Reservation table of capacity 1 is full after one reservation, and
	 * the refused request must not leak node capacity.
	 */
	mk_req(&req);
	zassert_ok(pqcp_sovereign_placement_reserve(&pl_eng, &req, 100U, &res));
	memcpy(pl_snapshot, pl_nodes, sizeof(pl_nodes));
	CP(req.workload_id, "w2");
	zassert_equal(pqcp_sovereign_placement_reserve(
			      &pl_eng, &req, 100U, &res), -ENOSPC);
	zassert_mem_equal(pl_snapshot, pl_nodes, sizeof(pl_nodes));
}

ZTEST(pqcp_sovereign_policy, test_placement_node_update_blocked_when_shrinking_busy)
{
	struct pqcp_sovereign_placement_node node;
	struct pqcp_sovereign_placement_request req;
	struct pqcp_sovereign_placement_reservation *res = NULL;

	pl_setup(3U);
	mk_node(&node, "n1", "t1", 10U);
	zassert_ok(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW));
	mk_req(&req);
	zassert_ok(pqcp_sovereign_placement_reserve(&pl_eng, &req, 100U, &res));
	memcpy(pl_snapshot, pl_nodes, sizeof(pl_nodes));
	/* Re-registering the node with *less* availability while a workload
	 * is active would silently double-book, so it is rejected.
	 */
	mk_node(&node, "n1", "t1", 10U);
	node.available_compute_units = 50U;
	zassert_equal(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW),
		      -EBUSY);
	zassert_mem_equal(pl_snapshot, pl_nodes, sizeof(pl_nodes));
}

ZTEST(pqcp_sovereign_policy, test_placement_released_slot_is_reusable)
{
	/* Regression (reservation slot leak): see the sovereign_placement_engine.c fix; the assertions below are the contract. */

	struct pqcp_sovereign_placement_node node;
	struct pqcp_sovereign_placement_request req;
	struct pqcp_sovereign_placement_reservation *res = NULL;
	int ret;

	pl_setup(1U);
	mk_node(&node, "n1", "t1", 10U);
	zassert_ok(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW));
	mk_req(&req);
	zassert_ok(pqcp_sovereign_placement_reserve(&pl_eng, &req, 100U, &res));
	zassert_ok(pqcp_sovereign_placement_release(&pl_eng, res->reservation_id));
	/* After release the node capacity is back; the one-slot reservation
	 * table must be able to serve a new workload.
	 */
	CP(req.workload_id, "w2");
	ret = pqcp_sovereign_placement_reserve(&pl_eng, &req, 100U, &res);
	zassert_equal(ret, 0,
		      "released/expired reservation slot never reclaimed");
}

ZTEST(pqcp_sovereign_policy, test_placement_release_credits_correct_tenant_node)
{
	/* Regression (tenant-ambiguous node restore): see the sovereign_placement_engine.c fix; the assertions below are the contract. */

	struct pqcp_sovereign_placement_node node;
	struct pqcp_sovereign_placement_request req;
	struct pqcp_sovereign_placement_reservation *res = NULL;

	pl_setup(3U);
	/* Two tenants may use the same node id; node identity is
	 * (tenant_id, node_id).
	 */
	mk_node(&node, "n1", "t1", 90U);
	zassert_ok(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW));
	mk_node(&node, "n1", "t2", 10U);
	zassert_ok(pqcp_sovereign_placement_node_put(&pl_eng, &node, PL_NOW));
	mk_req(&req);
	CP(req.tenant_id, "t2");
	zassert_ok(pqcp_sovereign_placement_reserve(&pl_eng, &req, 100U, &res));
	zassert_equal(pl_nodes[1].available_compute_units, 90U);
	zassert_ok(pqcp_sovereign_placement_release(&pl_eng, res->reservation_id));
	zassert_equal(pl_nodes[1].available_compute_units, 100U,
		      "release credited the wrong tenant's node");
	zassert_equal(pl_nodes[1].active_workloads, 0U);
}

/* ------------------------------------------------------------------ */
/* Egress engine                                                      */
/* ------------------------------------------------------------------ */

static struct pqcp_sovereign_egress_rule eg_rules[3];
static struct pqcp_sovereign_egress_rule eg_rule_snapshot[3];
static struct pqcp_sovereign_egress_usage eg_usage[2];
static struct pqcp_sovereign_egress_usage eg_usage_snapshot[2];
static struct pqcp_sovereign_egress_engine eg_eng;

static void mk_eg_rule(struct pqcp_sovereign_egress_rule *r, uint32_t id,
		       uint32_t priority, const char *dest,
		       enum pqcp_sovereign_decision effect)
{
	memset(r, 0, sizeof(*r));
	r->rule_id = id;
	r->priority = priority;
	CP(r->tenant_id, "t1");
	CP(r->workload_id, "*");
	CP(r->destination_domain, dest);
	r->data_class_mask = ALL_CLASSES;
	r->operation_mask = BIT_OP(PQCP_SOVEREIGN_OPERATION_EXPORT_DATA);
	r->maximum_bytes_per_window = 1000U;
	r->window_ms = 1000U;
	r->maximum_risk = 500U;
	r->effect = effect;
	r->enabled = true;
}

static int eg_auth(const char *dest, uint64_t bytes, uint64_t now,
		   uint32_t *rule_id)
{
	return pqcp_sovereign_egress_authorize(
		&eg_eng, "t1", "wl-1", dest,
		PQCP_SOVEREIGN_OPERATION_EXPORT_DATA,
		PQCP_SOVEREIGN_DATA_PERSONAL, bytes, 0U, true, true, now,
		rule_id);
}

static void eg_setup(void)
{
	zassert_ok(pqcp_sovereign_egress_engine_init(
		&eg_eng, eg_rules, 3U, eg_usage, 2U,
		PQCP_SOVEREIGN_DECISION_DENY));
}

ZTEST(pqcp_sovereign_policy, test_egress_init_default_deny_and_allow)
{
	struct pqcp_sovereign_egress_rule rule;
	uint32_t rid = 99U;

	zassert_equal(pqcp_sovereign_egress_engine_init(
			      &eg_eng, eg_rules, 3U, eg_usage, 2U,
			      PQCP_SOVEREIGN_DECISION_ALLOW), -EINVAL);
	zassert_equal(pqcp_sovereign_egress_engine_init(
			      &eg_eng, eg_rules, 3U, eg_usage, 2U,
			      PQCP_SOVEREIGN_DECISION_UNSET), -EINVAL);
	zassert_equal(pqcp_sovereign_egress_engine_init(
			      NULL, eg_rules, 3U, eg_usage, 2U,
			      PQCP_SOVEREIGN_DECISION_DENY), -EINVAL);
	zassert_equal(pqcp_sovereign_egress_engine_init(
			      &eg_eng, eg_rules, 0U, eg_usage, 2U,
			      PQCP_SOVEREIGN_DECISION_DENY), -EINVAL);
	zassert_equal(pqcp_sovereign_egress_engine_init(
			      &eg_eng, eg_rules, 3U, eg_usage, 0U,
			      PQCP_SOVEREIGN_DECISION_DENY), -EINVAL);
	eg_setup();

	zassert_equal(eg_auth("example.org", 1U, 5000U, &rid), -EACCES);
	zassert_equal(rid, 0U);
	zassert_equal(eg_eng.deny_count, 1U);

	mk_eg_rule(&rule, 1U, 10U, "example.org",
		   PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_ok(pqcp_sovereign_egress_rule_put(&eg_eng, &rule));
	zassert_ok(eg_auth("example.org", 1U, 5000U, &rid));
	zassert_equal(rid, 1U);
	zassert_equal(eg_eng.allow_count, 1U);
	/* Other destination has no rule. */
	zassert_equal(eg_auth("evil.example", 1U, 5000U, &rid), -EACCES);
	zassert_ok(pqcp_sovereign_egress_engine_audit(&eg_eng));
}

ZTEST(pqcp_sovereign_policy, test_egress_byte_budget_boundaries)
{
	struct pqcp_sovereign_egress_rule rule;
	uint32_t rid;

	eg_setup();
	mk_eg_rule(&rule, 1U, 10U, "*", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_ok(pqcp_sovereign_egress_rule_put(&eg_eng, &rule));

	zassert_ok(eg_auth("a.example", 600U, 5000U, &rid));
	memcpy(eg_usage_snapshot, eg_usage, sizeof(eg_usage));
	/* One byte over the window cap is refused and not accounted. */
	zassert_equal(eg_auth("a.example", 401U, 5000U, &rid), -EDQUOT);
	zassert_equal(eg_auth("a.example", UINT64_MAX, 5000U, &rid), -EDQUOT);
	zassert_mem_equal(eg_usage_snapshot, eg_usage, sizeof(eg_usage));
	/* Exactly the cap is allowed, then nothing more. */
	zassert_ok(eg_auth("a.example", 400U, 5000U, &rid));
	zassert_equal(eg_usage[0].bytes_used, 1000U);
	zassert_equal(eg_usage[0].request_count, 2U);
	zassert_equal(eg_auth("a.example", 1U, 5999U, &rid), -EDQUOT);
	/* Window rollover exactly at window_ms. */
	zassert_ok(eg_auth("a.example", 1000U, 6000U, &rid));
	/* Time going backwards relative to the window is refused. */
	zassert_equal(eg_auth("a.example", 1U, 5999U, &rid), -ETIME);
	/* Zero-byte transfer is invalid. */
	zassert_equal(eg_auth("a.example", 0U, 6000U, &rid), -EINVAL);
}

ZTEST(pqcp_sovereign_policy, test_egress_conditions_and_effects)
{
	struct pqcp_sovereign_egress_rule rule;
	uint32_t rid;

	eg_setup();
	mk_eg_rule(&rule, 1U, 10U, "*", PQCP_SOVEREIGN_DECISION_ALLOW);
	rule.require_encryption = true;
	rule.require_dlp = true;
	zassert_ok(pqcp_sovereign_egress_rule_put(&eg_eng, &rule));

	zassert_ok(pqcp_sovereign_egress_authorize(
		&eg_eng, "t1", "wl-1", "x.example",
		PQCP_SOVEREIGN_OPERATION_EXPORT_DATA,
		PQCP_SOVEREIGN_DATA_PERSONAL, 1U, 500U, true, true, 5000U,
		&rid));
	/* Risk boundary. */
	zassert_equal(pqcp_sovereign_egress_authorize(
			      &eg_eng, "t1", "wl-1", "x.example",
			      PQCP_SOVEREIGN_OPERATION_EXPORT_DATA,
			      PQCP_SOVEREIGN_DATA_PERSONAL, 1U, 501U, true, true,
			      5000U, &rid), -EACCES);
	/* Unencrypted / un-scanned data. */
	zassert_equal(pqcp_sovereign_egress_authorize(
			      &eg_eng, "t1", "wl-1", "x.example",
			      PQCP_SOVEREIGN_OPERATION_EXPORT_DATA,
			      PQCP_SOVEREIGN_DATA_PERSONAL, 1U, 0U, false, true,
			      5000U, &rid), -EACCES);
	zassert_equal(pqcp_sovereign_egress_authorize(
			      &eg_eng, "t1", "wl-1", "x.example",
			      PQCP_SOVEREIGN_OPERATION_EXPORT_DATA,
			      PQCP_SOVEREIGN_DATA_PERSONAL, 1U, 0U, true, false,
			      5000U, &rid), -EACCES);
	/* Operation and tenant mismatch. */
	zassert_equal(pqcp_sovereign_egress_authorize(
			      &eg_eng, "t1", "wl-1", "x.example",
			      PQCP_SOVEREIGN_OPERATION_WRITE_DATA,
			      PQCP_SOVEREIGN_DATA_PERSONAL, 1U, 0U, true, true,
			      5000U, &rid), -EACCES);
	zassert_equal(pqcp_sovereign_egress_authorize(
			      &eg_eng, "t2", "wl-1", "x.example",
			      PQCP_SOVEREIGN_OPERATION_EXPORT_DATA,
			      PQCP_SOVEREIGN_DATA_PERSONAL, 1U, 0U, true, true,
			      5000U, &rid), -EACCES);
	/* Only one transfer was accounted. */
	zassert_equal(eg_usage[0].request_count, 1U);

	/* A higher-priority deny rule overrides the allow. */
	mk_eg_rule(&rule, 2U, 20U, "x.example", PQCP_SOVEREIGN_DECISION_DENY);
	zassert_ok(pqcp_sovereign_egress_rule_put(&eg_eng, &rule));
	zassert_equal(eg_auth("x.example", 1U, 5000U, &rid), -EACCES);
	zassert_equal(rid, 2U);
	/* Review/quarantine effects never allow either. */
	mk_eg_rule(&rule, 2U, 20U, "x.example", PQCP_SOVEREIGN_DECISION_REVIEW);
	zassert_ok(pqcp_sovereign_egress_rule_put(&eg_eng, &rule));
	zassert_equal(eg_auth("x.example", 1U, 5000U, &rid), -EACCES);
	mk_eg_rule(&rule, 2U, 20U, "x.example",
		   PQCP_SOVEREIGN_DECISION_QUARANTINE);
	zassert_ok(pqcp_sovereign_egress_rule_put(&eg_eng, &rule));
	zassert_equal(eg_auth("x.example", 1U, 5000U, &rid), -EACCES);
	/* Equal priority: deny wins over allow. */
	mk_eg_rule(&rule, 2U, 10U, "x.example", PQCP_SOVEREIGN_DECISION_DENY);
	zassert_ok(pqcp_sovereign_egress_rule_put(&eg_eng, &rule));
	zassert_equal(eg_auth("x.example", 1U, 5000U, &rid), -EACCES);
	zassert_equal(rid, 2U);
}

ZTEST(pqcp_sovereign_policy, test_egress_rule_put_validation_and_capacity)
{
	struct pqcp_sovereign_egress_rule rule;

	eg_setup();
	mk_eg_rule(&rule, 1U, 10U, "a.example", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_ok(pqcp_sovereign_egress_rule_put(&eg_eng, &rule));
	memcpy(eg_rule_snapshot, eg_rules, sizeof(eg_rules));

	mk_eg_rule(&rule, 2U, 10U, "a.example", PQCP_SOVEREIGN_DECISION_ALLOW);
	rule.maximum_bytes_per_window = 0U; /* allow with zero budget */
	zassert_equal(pqcp_sovereign_egress_rule_put(&eg_eng, &rule), -EINVAL);
	mk_eg_rule(&rule, 2U, 10U, "a.example", PQCP_SOVEREIGN_DECISION_ALLOW);
	rule.window_ms = 0U;
	zassert_equal(pqcp_sovereign_egress_rule_put(&eg_eng, &rule), -EINVAL);
	mk_eg_rule(&rule, 2U, 10U, "a.example", PQCP_SOVEREIGN_DECISION_ALLOW);
	rule.maximum_risk = 1001U;
	zassert_equal(pqcp_sovereign_egress_rule_put(&eg_eng, &rule), -EINVAL);
	mk_eg_rule(&rule, 2U, 10U, "a.example", PQCP_SOVEREIGN_DECISION_ALLOW);
	rule.effect = PQCP_SOVEREIGN_DECISION_UNSET;
	zassert_equal(pqcp_sovereign_egress_rule_put(&eg_eng, &rule), -EINVAL);
	mk_eg_rule(&rule, 2U, 10U, "a.example", PQCP_SOVEREIGN_DECISION_ALLOW);
	rule.operation_mask = 0U;
	zassert_equal(pqcp_sovereign_egress_rule_put(&eg_eng, &rule), -EINVAL);
	mk_eg_rule(&rule, 2U, 10U, "a.example", PQCP_SOVEREIGN_DECISION_ALLOW);
	rule.data_class_mask = 1U << PQCP_SOVEREIGN_DATA_CLASS_COUNT;
	zassert_equal(pqcp_sovereign_egress_rule_put(&eg_eng, &rule), -EINVAL);
	mk_eg_rule(&rule, 0U, 10U, "a.example", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_equal(pqcp_sovereign_egress_rule_put(&eg_eng, &rule), -EINVAL);
	mk_eg_rule(&rule, 2U, 0U, "a.example", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_equal(pqcp_sovereign_egress_rule_put(&eg_eng, &rule), -EINVAL);
	zassert_equal(pqcp_sovereign_egress_rule_put(&eg_eng, NULL), -EINVAL);
	zassert_mem_equal(eg_rule_snapshot, eg_rules, sizeof(eg_rules));

	/* Capacity: 3 rules max, replacing in place still works when full. */
	mk_eg_rule(&rule, 2U, 10U, "b.example", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_ok(pqcp_sovereign_egress_rule_put(&eg_eng, &rule));
	mk_eg_rule(&rule, 3U, 10U, "c.example", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_ok(pqcp_sovereign_egress_rule_put(&eg_eng, &rule));
	mk_eg_rule(&rule, 4U, 10U, "d.example", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_equal(pqcp_sovereign_egress_rule_put(&eg_eng, &rule), -ENOSPC);
	mk_eg_rule(&rule, 3U, 10U, "c.example", PQCP_SOVEREIGN_DECISION_DENY);
	zassert_ok(pqcp_sovereign_egress_rule_put(&eg_eng, &rule));
	zassert_ok(pqcp_sovereign_egress_engine_audit(&eg_eng));
}

ZTEST(pqcp_sovereign_policy, test_egress_usage_table_exhaustion_fails_closed)
{
	struct pqcp_sovereign_egress_rule rule;
	uint32_t rid;
	uint64_t allowed_before;

	eg_setup();
	mk_eg_rule(&rule, 1U, 10U, "*", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_ok(pqcp_sovereign_egress_rule_put(&eg_eng, &rule));
	zassert_ok(eg_auth("a.example", 1U, 5000U, &rid));
	zassert_ok(eg_auth("b.example", 1U, 5000U, &rid));
	allowed_before = eg_eng.allow_count;
	/* Both usage slots taken: a third destination cannot be tracked and
	 * therefore must not be allowed.
	 */
	zassert_equal(eg_auth("c.example", 1U, 5000U, &rid), -ENOSPC);
	zassert_equal(eg_eng.allow_count, allowed_before);
}

ZTEST(pqcp_sovereign_policy, test_egress_tick_resets_elapsed_windows)
{
	struct pqcp_sovereign_egress_rule rule;
	uint32_t rid;
	uint32_t resets = 99U;

	eg_setup();
	mk_eg_rule(&rule, 1U, 10U, "*", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_ok(pqcp_sovereign_egress_rule_put(&eg_eng, &rule));
	zassert_ok(eg_auth("a.example", 1000U, 5000U, &rid));
	zassert_ok(pqcp_sovereign_egress_tick(&eg_eng, 5999U, &resets));
	zassert_equal(resets, 0U);
	zassert_equal(eg_usage[0].bytes_used, 1000U);
	zassert_ok(pqcp_sovereign_egress_tick(&eg_eng, 6000U, &resets));
	zassert_equal(resets, 1U);
	zassert_equal(eg_usage[0].bytes_used, 0U);
	zassert_equal(pqcp_sovereign_egress_tick(&eg_eng, 0U, &resets), -EINVAL);
	zassert_equal(pqcp_sovereign_egress_tick(&eg_eng, 6000U, NULL), -EINVAL);
	zassert_equal(pqcp_sovereign_egress_tick(NULL, 6000U, &resets), -EINVAL);
}

ZTEST(pqcp_sovereign_policy, test_egress_authorize_invalid_arguments)
{
	uint32_t rid;

	eg_setup();
	zassert_equal(pqcp_sovereign_egress_authorize(
			      &eg_eng, "t1", "wl", "d.example",
			      PQCP_SOVEREIGN_OPERATION_NONE,
			      PQCP_SOVEREIGN_DATA_PERSONAL, 1U, 0U, true, true,
			      5000U, &rid), -EINVAL);
	zassert_equal(pqcp_sovereign_egress_authorize(
			      &eg_eng, "t1", "wl", "d.example",
			      PQCP_SOVEREIGN_OPERATION_EXPORT_DATA,
			      (enum pqcp_sovereign_data_class)
				      PQCP_SOVEREIGN_DATA_CLASS_COUNT,
			      1U, 0U, true, true, 5000U, &rid), -EINVAL);
	zassert_equal(pqcp_sovereign_egress_authorize(
			      &eg_eng, "t1", "wl", "d.example",
			      PQCP_SOVEREIGN_OPERATION_EXPORT_DATA,
			      PQCP_SOVEREIGN_DATA_PERSONAL, 1U, 1001U, true,
			      true, 5000U, &rid), -EINVAL);
	zassert_equal(pqcp_sovereign_egress_authorize(
			      &eg_eng, "t1", "wl", "d.example",
			      PQCP_SOVEREIGN_OPERATION_EXPORT_DATA,
			      PQCP_SOVEREIGN_DATA_PERSONAL, 1U, 0U, true, true,
			      0U, &rid), -EINVAL);
	zassert_equal(pqcp_sovereign_egress_authorize(
			      &eg_eng, "t1", "wl", "d.example",
			      PQCP_SOVEREIGN_OPERATION_EXPORT_DATA,
			      PQCP_SOVEREIGN_DATA_PERSONAL, 1U, 0U, true, true,
			      5000U, NULL), -EINVAL);
	zassert_equal(pqcp_sovereign_egress_authorize(
			      &eg_eng, NULL, "wl", "d.example",
			      PQCP_SOVEREIGN_OPERATION_EXPORT_DATA,
			      PQCP_SOVEREIGN_DATA_PERSONAL, 1U, 0U, true, true,
			      5000U, &rid), -EINVAL);
	zassert_equal(pqcp_sovereign_egress_authorize(
			      NULL, "t1", "wl", "d.example",
			      PQCP_SOVEREIGN_OPERATION_EXPORT_DATA,
			      PQCP_SOVEREIGN_DATA_PERSONAL, 1U, 0U, true, true,
			      5000U, &rid), -EINVAL);
	zassert_equal(eg_eng.deny_count, 0U);
}

ZTEST(pqcp_sovereign_policy, test_egress_tightened_rule_enforced_immediately)
{
	/* Regression: authorize() used to compute
	 * maximum_bytes_per_window - usage->bytes_used in unsigned arithmetic.
	 * A rule re-put with a cap below the bytes already used in the window
	 * wrapped the subtraction and allowed the transfer instead of -EDQUOT.
	 */
	struct pqcp_sovereign_egress_rule rule;
	uint32_t rid;

	eg_setup();
	mk_eg_rule(&rule, 1U, 10U, "*", PQCP_SOVEREIGN_DECISION_ALLOW);
	zassert_ok(pqcp_sovereign_egress_rule_put(&eg_eng, &rule));
	zassert_ok(eg_auth("a.example", 800U, 5000U, &rid));
	/* Operator lowers the cap below what the window already used. */
	rule.maximum_bytes_per_window = 500U;
	zassert_ok(pqcp_sovereign_egress_rule_put(&eg_eng, &rule));
	zassert_equal(eg_auth("a.example", 1U, 5000U, &rid), -EDQUOT,
		      "usage above a tightened cap still allows egress");
}

/* ------------------------------------------------------------------ */
/* Retention manager                                                  */
/* ------------------------------------------------------------------ */

static struct pqcp_sovereign_retention_rule rt_rules[2];
static struct pqcp_sovereign_retention_record rt_records[2];
static struct pqcp_sovereign_retention_record rt_snapshot[2];
static struct pqcp_sovereign_retention_manager rt_mgr;

#define RT_NOW 10000U

static void mk_rt_rule(struct pqcp_sovereign_retention_rule *r, uint32_t id)
{
	memset(r, 0, sizeof(*r));
	r->rule_id = id;
	CP(r->tenant_id, "t1");
	CP(r->purpose, "billing");
	r->data_class_mask = BIT_CLASS(PQCP_SOVEREIGN_DATA_PERSONAL);
	r->minimum_retention_ms = 100U;
	r->maximum_retention_ms = 1000U;
	r->deletion_method = 1U /* cryptographic erasure */;
	r->priority = 1U;
	r->enabled = true;
}

static void rt_setup(void)
{
	struct pqcp_sovereign_retention_rule rule;

	zassert_ok(pqcp_sovereign_retention_manager_init(
		&rt_mgr, rt_rules, 2U, rt_records, 2U));
	mk_rt_rule(&rule, 1U);
	zassert_ok(pqcp_sovereign_retention_rule_put(&rt_mgr, &rule));
}

static int rt_track(const char *object, uint64_t now,
		    struct pqcp_sovereign_retention_record **rec)
{
	return pqcp_sovereign_retention_track(
		&rt_mgr, object, "t1", "billing", PQCP_SOVEREIGN_DATA_PERSONAL,
		DIGEST_A, now, rec);
}

ZTEST(pqcp_sovereign_policy, test_retention_no_rule_fails_closed)
{
	struct pqcp_sovereign_retention_record *rec = NULL;

	zassert_equal(pqcp_sovereign_retention_manager_init(
			      NULL, rt_rules, 2U, rt_records, 2U), -EINVAL);
	zassert_equal(pqcp_sovereign_retention_manager_init(
			      &rt_mgr, NULL, 2U, rt_records, 2U), -EINVAL);
	zassert_equal(pqcp_sovereign_retention_manager_init(
			      &rt_mgr, rt_rules, 0U, rt_records, 2U), -EINVAL);
	zassert_equal(pqcp_sovereign_retention_manager_init(
			      &rt_mgr, rt_rules, 2U, NULL, 2U), -EINVAL);
	zassert_equal(pqcp_sovereign_retention_manager_init(
			      &rt_mgr, rt_rules, 2U, rt_records, 0U), -EINVAL);
	zassert_ok(pqcp_sovereign_retention_manager_init(
		&rt_mgr, rt_rules, 2U, rt_records, 2U));
	/* Data without a retention schedule must not be tracked. */
	zassert_equal(rt_track("obj-1", RT_NOW, &rec), -EACCES);
	zassert_false(rt_records[0].occupied);
	zassert_equal(pqcp_sovereign_retention_due(
			      &rt_mgr, RT_NOW, &rec), -ENOENT);
	zassert_ok(pqcp_sovereign_retention_manager_audit(&rt_mgr));
}

ZTEST(pqcp_sovereign_policy, test_retention_rule_validation)
{
	struct pqcp_sovereign_retention_rule rule;

	zassert_ok(pqcp_sovereign_retention_manager_init(
		&rt_mgr, rt_rules, 2U, rt_records, 2U));
	mk_rt_rule(&rule, 1U);
	rule.maximum_retention_ms = rule.minimum_retention_ms - 1U;
	zassert_equal(pqcp_sovereign_retention_rule_put(&rt_mgr, &rule), -EINVAL);
	mk_rt_rule(&rule, 1U);
	rule.maximum_retention_ms = rule.minimum_retention_ms; /* boundary ok */
	zassert_ok(pqcp_sovereign_retention_rule_put(&rt_mgr, &rule));
	mk_rt_rule(&rule, 2U);
	rule.maximum_retention_ms = 0U;
	zassert_equal(pqcp_sovereign_retention_rule_put(&rt_mgr, &rule), -EINVAL);
	mk_rt_rule(&rule, 2U);
	rule.deletion_method = 0U;
	zassert_equal(pqcp_sovereign_retention_rule_put(&rt_mgr, &rule), -EINVAL);
	mk_rt_rule(&rule, 2U);
	rule.priority = 0U;
	zassert_equal(pqcp_sovereign_retention_rule_put(&rt_mgr, &rule), -EINVAL);
	mk_rt_rule(&rule, 0U);
	zassert_equal(pqcp_sovereign_retention_rule_put(&rt_mgr, &rule), -EINVAL);
	mk_rt_rule(&rule, 2U);
	rule.data_class_mask = 0U;
	zassert_equal(pqcp_sovereign_retention_rule_put(&rt_mgr, &rule), -EINVAL);
	rule.data_class_mask = 1U << PQCP_SOVEREIGN_DATA_CLASS_COUNT;
	zassert_equal(pqcp_sovereign_retention_rule_put(&rt_mgr, &rule), -EINVAL);
	zassert_equal(pqcp_sovereign_retention_rule_put(&rt_mgr, NULL), -EINVAL);
	/* Capacity 2: one more distinct rule fits, the next does not. */
	mk_rt_rule(&rule, 2U);
	zassert_ok(pqcp_sovereign_retention_rule_put(&rt_mgr, &rule));
	mk_rt_rule(&rule, 3U);
	zassert_equal(pqcp_sovereign_retention_rule_put(&rt_mgr, &rule), -ENOSPC);
	zassert_ok(pqcp_sovereign_retention_manager_audit(&rt_mgr));
}

ZTEST(pqcp_sovereign_policy, test_retention_track_due_and_minimum_boundary)
{
	struct pqcp_sovereign_retention_record *rec = NULL;
	struct pqcp_sovereign_retention_record *due = NULL;
	uint64_t id;

	rt_setup();
	zassert_ok(rt_track("obj-1", RT_NOW, &rec));
	id = rec->record_id;
	zassert_equal(rec->delete_after_ms, RT_NOW + 1000U);
	zassert_equal(rec->state, PQCP_SOVEREIGN_LIFECYCLE_ACTIVE);
	/* Duplicate tracking of an active object is refused. */
	zassert_equal(rt_track("obj-1", RT_NOW + 1U, &rec), -EALREADY);

	/* Not due before the maximum retention; due exactly at it. */
	zassert_equal(pqcp_sovereign_retention_due(
			      &rt_mgr, RT_NOW + 999U, &due), -ENOENT);
	zassert_ok(pqcp_sovereign_retention_due(&rt_mgr, RT_NOW + 1000U, &due));
	zassert_equal(due->record_id, id);

	/* Early deletion before the minimum retention is refused. */
	memcpy(rt_snapshot, rt_records, sizeof(rt_records));
	zassert_equal(pqcp_sovereign_retention_mark_deleted(
			      &rt_mgr, id, RT_NOW + 99U), -EPERM);
	zassert_mem_equal(rt_snapshot, rt_records, sizeof(rt_records));
	zassert_ok(pqcp_sovereign_retention_mark_deleted(
		&rt_mgr, id, RT_NOW + 100U));
	zassert_equal(rt_records[0].state, PQCP_SOVEREIGN_LIFECYCLE_RETIRED);
	zassert_equal(rt_records[0].deleted_at_ms, RT_NOW + 100U);
	zassert_equal(pqcp_sovereign_retention_mark_deleted(
			      &rt_mgr, id, RT_NOW + 200U), -EALREADY);
	/* Deleted records are no longer due. */
	zassert_equal(pqcp_sovereign_retention_due(
			      &rt_mgr, RT_NOW + 5000U, &due), -ENOENT);
	zassert_ok(pqcp_sovereign_retention_manager_audit(&rt_mgr));
	/* The object may be tracked again after deletion. */
	zassert_ok(rt_track("obj-1", RT_NOW + 300U, &rec));
	zassert_equal(pqcp_sovereign_retention_mark_deleted(
			      &rt_mgr, 999U, RT_NOW), -ENOENT);
	zassert_equal(pqcp_sovereign_retention_mark_deleted(
			      &rt_mgr, 0U, RT_NOW), -EINVAL);
}

ZTEST(pqcp_sovereign_policy, test_retention_legal_hold_blocks_deletion)
{
	struct pqcp_sovereign_retention_record *rec = NULL;
	struct pqcp_sovereign_retention_record *due = NULL;
	uint64_t id;

	rt_setup();
	zassert_ok(rt_track("obj-1", RT_NOW, &rec));
	id = rec->record_id;

	zassert_equal(pqcp_sovereign_retention_hold(&rt_mgr, 0U, 20000U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_retention_hold(&rt_mgr, id, 0U), -EINVAL);
	zassert_equal(pqcp_sovereign_retention_hold(&rt_mgr, 999U, 20000U),
		      -ENOENT);
	zassert_equal(pqcp_sovereign_retention_hold(&rt_mgr, id, RT_NOW),
		      -ERANGE); /* not after creation */
	zassert_ok(pqcp_sovereign_retention_hold(&rt_mgr, id, 20000U));
	/* A hold can only be extended, never shortened or repeated. */
	zassert_equal(pqcp_sovereign_retention_hold(&rt_mgr, id, 20000U),
		      -ERANGE);
	zassert_equal(pqcp_sovereign_retention_hold(&rt_mgr, id, 15000U),
		      -ERANGE);
	zassert_ok(pqcp_sovereign_retention_hold(&rt_mgr, id, 21000U));

	/* While held: neither due nor deletable, even past max retention. */
	zassert_equal(pqcp_sovereign_retention_due(
			      &rt_mgr, 12000U, &due), -ENOENT);
	zassert_equal(pqcp_sovereign_retention_mark_deleted(
			      &rt_mgr, id, 12000U), -EBUSY);
	zassert_equal(rt_records[0].state, PQCP_SOVEREIGN_LIFECYCLE_ACTIVE);
	zassert_equal(pqcp_sovereign_retention_mark_deleted(
			      &rt_mgr, id, 20999U), -EBUSY);
	/* Hold expires exactly at hold_until. */
	zassert_ok(pqcp_sovereign_retention_due(&rt_mgr, 21000U, &due));
	zassert_ok(pqcp_sovereign_retention_mark_deleted(&rt_mgr, id, 21000U));
}

ZTEST(pqcp_sovereign_policy, test_retention_rule_hold_inherited_by_records)
{
	struct pqcp_sovereign_retention_rule rule;
	struct pqcp_sovereign_retention_record *rec = NULL;

	zassert_ok(pqcp_sovereign_retention_manager_init(
		&rt_mgr, rt_rules, 2U, rt_records, 2U));
	mk_rt_rule(&rule, 1U);
	rule.legal_hold_until_ms = RT_NOW + 5000U;
	zassert_ok(pqcp_sovereign_retention_rule_put(&rt_mgr, &rule));
	zassert_ok(rt_track("obj-1", RT_NOW, &rec));
	zassert_equal(rec->legal_hold_until_ms, RT_NOW + 5000U);
	zassert_equal(pqcp_sovereign_retention_mark_deleted(
			      &rt_mgr, rec->record_id, RT_NOW + 2000U), -EBUSY);
	/* A rule hold already in the past is not inherited. */
	zassert_ok(rt_track("obj-2", RT_NOW + 6000U, &rec));
	zassert_equal(rec->legal_hold_until_ms, 0U);
}

ZTEST(pqcp_sovereign_policy, test_retention_track_rejections_do_not_mutate)
{
	struct pqcp_sovereign_retention_rule rule;
	struct pqcp_sovereign_retention_record *rec = NULL;
	uint8_t zero[PQCP_SOVEREIGN_DIGEST_BYTES] = { 0 };

	rt_setup();
	memcpy(rt_snapshot, rt_records, sizeof(rt_records));
	zassert_equal(pqcp_sovereign_retention_track(
			      &rt_mgr, "obj", "t1", "billing",
			      PQCP_SOVEREIGN_DATA_PERSONAL, zero, RT_NOW, &rec),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_retention_track(
			      &rt_mgr, "obj", "t1", "billing",
			      PQCP_SOVEREIGN_DATA_PERSONAL, NULL, RT_NOW, &rec),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_retention_track(
			      &rt_mgr, "obj", "t1", "billing",
			      (enum pqcp_sovereign_data_class)
				      PQCP_SOVEREIGN_DATA_CLASS_COUNT,
			      DIGEST_A, RT_NOW, &rec), -EINVAL);
	zassert_equal(rt_track("obj", 0U, &rec), -EINVAL);
	zassert_equal(rt_track("obj", RT_NOW, NULL), -EINVAL);
	/* Wrong tenant / purpose / class have no schedule. */
	zassert_equal(pqcp_sovereign_retention_track(
			      &rt_mgr, "obj", "t2", "billing",
			      PQCP_SOVEREIGN_DATA_PERSONAL, DIGEST_A, RT_NOW,
			      &rec), -EACCES);
	zassert_equal(pqcp_sovereign_retention_track(
			      &rt_mgr, "obj", "t1", "marketing",
			      PQCP_SOVEREIGN_DATA_PERSONAL, DIGEST_A, RT_NOW,
			      &rec), -EACCES);
	zassert_equal(pqcp_sovereign_retention_track(
			      &rt_mgr, "obj", "t1", "billing",
			      PQCP_SOVEREIGN_DATA_SECRET, DIGEST_A, RT_NOW,
			      &rec), -EACCES);
	zassert_mem_equal(rt_snapshot, rt_records, sizeof(rt_records));
	zassert_equal(rt_mgr.next_record_id, 1U);

	/* Deadline overflow is detected. */
	mk_rt_rule(&rule, 1U);
	rule.minimum_retention_ms = 1U;
	rule.maximum_retention_ms = UINT64_MAX;
	zassert_ok(pqcp_sovereign_retention_rule_put(&rt_mgr, &rule));
	zassert_equal(rt_track("obj", 2U, &rec), -EOVERFLOW);
	zassert_mem_equal(rt_snapshot, rt_records, sizeof(rt_records));
	mk_rt_rule(&rule, 1U);
	zassert_ok(pqcp_sovereign_retention_rule_put(&rt_mgr, &rule));

	/* Capacity. */
	zassert_ok(rt_track("obj-1", RT_NOW, &rec));
	zassert_ok(rt_track("obj-2", RT_NOW, &rec));
	zassert_equal(rt_track("obj-3", RT_NOW, &rec), -ENOSPC);
	zassert_ok(pqcp_sovereign_retention_manager_audit(&rt_mgr));
}

/* ------------------------------------------------------------------ */
/* Namespace manager (with tenant registry)                           */
/* ------------------------------------------------------------------ */

static struct pqcp_sovereign_tenant ns_tenants[2];
static struct pqcp_sovereign_tenant_registry ns_registry;
static struct pqcp_sovereign_namespace ns_spaces[2];
static struct pqcp_sovereign_namespace ns_snapshot[2];
static struct pqcp_sovereign_namespace_manager ns_mgr;

#define NS_EPOCH 3U
#define NS_NOW 1000U

static void ns_setup(uint32_t max_namespaces)
{
	struct pqcp_sovereign_tenant t;

	zassert_ok(pqcp_sovereign_tenant_registry_init(
		&ns_registry, ns_tenants, 2U));
	zassert_ok(pqcp_sovereign_namespace_manager_init(
		&ns_mgr, ns_spaces, 2U));
	memset(&t, 0, sizeof(t));
	CP(t.tenant_id, "t1");
	CP(t.trust_domain, "example.org");
	CP(t.home_zone, "eu-west");
	t.capabilities = 1U;
	t.operation_mask = 0xFFFFU;
	t.policy_epoch = NS_EPOCH;
	t.revocation_epoch = 1U;
	t.expires_at_ms = 100000U;
	t.storage_quota_bytes = 1000000U;
	t.compute_quota_units = 100U;
	t.maximum_namespaces = max_namespaces;
	t.state = PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
	zassert_ok(pqcp_sovereign_tenant_register(&ns_registry, &t, NS_NOW));
}

static void mk_ns(struct pqcp_sovereign_namespace *n, const char *id)
{
	memset(n, 0, sizeof(*n));
	CP(n->namespace_id, id);
	CP(n->tenant_id, "t1");
	CP(n->residency_zone, "eu-west");
	CP(n->security_label, "internal");
	n->operation_mask = BIT_OP(PQCP_SOVEREIGN_OPERATION_READ_DATA) |
			    BIT_OP(PQCP_SOVEREIGN_OPERATION_WRITE_DATA);
	n->policy_epoch = NS_EPOCH;
	n->expires_at_ms = 50000U;
	n->storage_limit_bytes = 1000U;
	n->maximum_workloads = 2U;
	n->maximum_data_class = PQCP_SOVEREIGN_DATA_CONFIDENTIAL;
	n->state = PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
}

ZTEST(pqcp_sovereign_policy, test_namespace_create_requires_known_tenant)
{
	struct pqcp_sovereign_namespace n;
	struct pqcp_sovereign_namespace *found = NULL;

	zassert_equal(pqcp_sovereign_namespace_manager_init(
			      NULL, ns_spaces, 2U), -EINVAL);
	zassert_equal(pqcp_sovereign_namespace_manager_init(
			      &ns_mgr, NULL, 2U), -EINVAL);
	zassert_equal(pqcp_sovereign_namespace_manager_init(
			      &ns_mgr, ns_spaces, 0U), -EINVAL);
	ns_setup(2U);
	mk_ns(&n, "ns1");
	CP(n.tenant_id, "ghost");
	zassert_equal(pqcp_sovereign_namespace_create(
			      &ns_mgr, &ns_registry, &n, NS_NOW), -ENOENT);
	zassert_equal(pqcp_sovereign_namespace_find(
			      &ns_mgr, "ns1", &found), -ENOENT);
	mk_ns(&n, "ns1");
	zassert_ok(pqcp_sovereign_namespace_create(
		&ns_mgr, &ns_registry, &n, NS_NOW));
	zassert_ok(pqcp_sovereign_namespace_find(&ns_mgr, "ns1", &found));
	zassert_not_null(found);
	zassert_not_equal(found->generation, 0U);
	zassert_equal(found->created_at_ms, NS_NOW);
	zassert_equal(ns_mgr.creation_count, 1U);
	zassert_equal(ns_tenants[0].active_namespaces, 1U);
	zassert_ok(pqcp_sovereign_namespace_manager_audit(&ns_mgr));
}

ZTEST(pqcp_sovereign_policy, test_namespace_create_rejections_do_not_mutate)
{
	struct pqcp_sovereign_namespace n;

	ns_setup(1U);
	memcpy(ns_snapshot, ns_spaces, sizeof(ns_spaces));

	/* Tenant policy epoch mismatch. */
	mk_ns(&n, "ns1");
	n.policy_epoch = NS_EPOCH + 1U;
	zassert_equal(pqcp_sovereign_namespace_create(
			      &ns_mgr, &ns_registry, &n, NS_NOW), -EACCES);
	/* Residency zone differs from the tenant's home zone. */
	mk_ns(&n, "ns1");
	CP(n.residency_zone, "us-east");
	zassert_equal(pqcp_sovereign_namespace_create(
			      &ns_mgr, &ns_registry, &n, NS_NOW), -EXDEV);
	/* Tenant expired by the time of creation. */
	mk_ns(&n, "ns1");
	zassert_equal(pqcp_sovereign_namespace_create(
			      &ns_mgr, &ns_registry, &n, 100000U), -EINVAL);
	zassert_mem_equal(ns_snapshot, ns_spaces, sizeof(ns_spaces));
	zassert_equal(ns_tenants[0].active_namespaces, 0U);
	zassert_equal(ns_mgr.creation_count, 0U);

	/* Structural validation. */
	mk_ns(&n, "ns1");
	n.storage_used_bytes = 1U;
	zassert_equal(pqcp_sovereign_namespace_create(
			      &ns_mgr, &ns_registry, &n, NS_NOW), -EINVAL);
	mk_ns(&n, "ns1");
	n.active_workloads = 1U;
	zassert_equal(pqcp_sovereign_namespace_create(
			      &ns_mgr, &ns_registry, &n, NS_NOW), -EINVAL);
	mk_ns(&n, "ns1");
	n.expires_at_ms = NS_NOW; /* not strictly in the future */
	zassert_equal(pqcp_sovereign_namespace_create(
			      &ns_mgr, &ns_registry, &n, NS_NOW), -EINVAL);
	mk_ns(&n, "ns1");
	n.storage_limit_bytes = 0U;
	zassert_equal(pqcp_sovereign_namespace_create(
			      &ns_mgr, &ns_registry, &n, NS_NOW), -EINVAL);
	mk_ns(&n, "ns1");
	n.maximum_workloads = 0U;
	zassert_equal(pqcp_sovereign_namespace_create(
			      &ns_mgr, &ns_registry, &n, NS_NOW), -EINVAL);
	mk_ns(&n, "ns1");
	n.operation_mask = 0U;
	zassert_equal(pqcp_sovereign_namespace_create(
			      &ns_mgr, &ns_registry, &n, NS_NOW), -EINVAL);
	mk_ns(&n, "ns1");
	n.maximum_data_class = (enum pqcp_sovereign_data_class)
		PQCP_SOVEREIGN_DATA_CLASS_COUNT;
	zassert_equal(pqcp_sovereign_namespace_create(
			      &ns_mgr, &ns_registry, &n, NS_NOW), -EINVAL);
	mk_ns(&n, "ns1");
	n.state = PQCP_SOVEREIGN_LIFECYCLE_SUSPENDED;
	zassert_equal(pqcp_sovereign_namespace_create(
			      &ns_mgr, &ns_registry, &n, NS_NOW), -EINVAL);
	zassert_equal(pqcp_sovereign_namespace_create(
			      &ns_mgr, &ns_registry, NULL, NS_NOW), -EINVAL);
	zassert_equal(pqcp_sovereign_namespace_create(
			      &ns_mgr, NULL, &n, NS_NOW), -EINVAL);
	zassert_mem_equal(ns_snapshot, ns_spaces, sizeof(ns_spaces));
}

ZTEST(pqcp_sovereign_policy, test_namespace_tenant_quota_duplicate_and_capacity)
{
	struct pqcp_sovereign_namespace n;

	ns_setup(2U);
	mk_ns(&n, "ns1");
	zassert_ok(pqcp_sovereign_namespace_create(
		&ns_mgr, &ns_registry, &n, NS_NOW));
	/* Duplicate namespace id. */
	zassert_equal(pqcp_sovereign_namespace_create(
			      &ns_mgr, &ns_registry, &n, NS_NOW), -EALREADY);
	zassert_equal(ns_tenants[0].active_namespaces, 1U);
	mk_ns(&n, "ns2");
	zassert_ok(pqcp_sovereign_namespace_create(
		&ns_mgr, &ns_registry, &n, NS_NOW));
	/* Tenant limit of 2 reached: one past is refused. */
	mk_ns(&n, "ns3");
	zassert_equal(pqcp_sovereign_namespace_create(
			      &ns_mgr, &ns_registry, &n, NS_NOW), -EDQUOT);
	zassert_equal(ns_tenants[0].active_namespaces, 2U);
	zassert_equal(ns_mgr.creation_count, 2U);
	zassert_ok(pqcp_sovereign_namespace_manager_audit(&ns_mgr));
}

ZTEST(pqcp_sovereign_policy, test_namespace_manager_capacity_exhaustion)
{
	struct pqcp_sovereign_namespace n;

	ns_setup(8U);
	mk_ns(&n, "ns1");
	zassert_ok(pqcp_sovereign_namespace_create(
		&ns_mgr, &ns_registry, &n, NS_NOW));
	mk_ns(&n, "ns2");
	zassert_ok(pqcp_sovereign_namespace_create(
		&ns_mgr, &ns_registry, &n, NS_NOW));
	memcpy(ns_snapshot, ns_spaces, sizeof(ns_spaces));
	mk_ns(&n, "ns3");
	zassert_equal(pqcp_sovereign_namespace_create(
			      &ns_mgr, &ns_registry, &n, NS_NOW), -ENOSPC);
	zassert_mem_equal(ns_snapshot, ns_spaces, sizeof(ns_spaces));
	zassert_equal(ns_tenants[0].active_namespaces, 2U);
}

ZTEST(pqcp_sovereign_policy, test_namespace_workload_quota_boundaries)
{
	struct pqcp_sovereign_namespace n;

	ns_setup(2U);
	mk_ns(&n, "ns1");
	zassert_ok(pqcp_sovereign_namespace_create(
		&ns_mgr, &ns_registry, &n, NS_NOW));

	zassert_equal(pqcp_sovereign_namespace_reserve_workload(
			      &ns_mgr, "ns1", 0U), -EINVAL);
	zassert_equal(pqcp_sovereign_namespace_reserve_workload(
			      &ns_mgr, NULL, 1U), -EINVAL);
	zassert_equal(pqcp_sovereign_namespace_reserve_workload(
			      &ns_mgr, "missing", 1U), -ENOENT);
	zassert_ok(pqcp_sovereign_namespace_reserve_workload(
		&ns_mgr, "ns1", 400U));
	memcpy(ns_snapshot, ns_spaces, sizeof(ns_spaces));
	/* One byte past the remaining storage (600). */
	zassert_equal(pqcp_sovereign_namespace_reserve_workload(
			      &ns_mgr, "ns1", 601U), -ENOSPC);
	zassert_equal(pqcp_sovereign_namespace_reserve_workload(
			      &ns_mgr, "ns1", UINT64_MAX), -ENOSPC);
	zassert_mem_equal(ns_snapshot, ns_spaces, sizeof(ns_spaces));
	/* Exactly the rest of the storage. */
	zassert_ok(pqcp_sovereign_namespace_reserve_workload(
		&ns_mgr, "ns1", 600U));
	zassert_equal(ns_spaces[0].storage_used_bytes, 1000U);
	zassert_equal(ns_spaces[0].active_workloads, 2U);
	/* Workload limit (2) reached: refused even for 1 byte. */
	memcpy(ns_snapshot, ns_spaces, sizeof(ns_spaces));
	zassert_equal(pqcp_sovereign_namespace_reserve_workload(
			      &ns_mgr, "ns1", 1U), -EDQUOT);
	zassert_mem_equal(ns_snapshot, ns_spaces, sizeof(ns_spaces));

	/* Release: cannot give back more than was used. */
	zassert_equal(pqcp_sovereign_namespace_release_workload(
			      &ns_mgr, "ns1", 1001U), -ERANGE);
	zassert_equal(pqcp_sovereign_namespace_release_workload(
			      &ns_mgr, "ns1", 0U), -EINVAL);
	zassert_equal(pqcp_sovereign_namespace_release_workload(
			      &ns_mgr, "missing", 1U), -ENOENT);
	zassert_mem_equal(ns_snapshot, ns_spaces, sizeof(ns_spaces));
	zassert_ok(pqcp_sovereign_namespace_release_workload(
		&ns_mgr, "ns1", 600U));
	zassert_ok(pqcp_sovereign_namespace_release_workload(
		&ns_mgr, "ns1", 400U));
	zassert_equal(ns_spaces[0].storage_used_bytes, 0U);
	zassert_equal(ns_spaces[0].active_workloads, 0U);
	/* No workloads left: further release would underflow. */
	zassert_equal(pqcp_sovereign_namespace_release_workload(
			      &ns_mgr, "ns1", 1U), -ERANGE);
	zassert_ok(pqcp_sovereign_namespace_manager_audit(&ns_mgr));
}

ZTEST(pqcp_sovereign_policy, test_namespace_authorize_contract)
{
	struct pqcp_sovereign_namespace n;

	ns_setup(2U);
	/* Unknown namespace: deny. */
	zassert_equal(pqcp_sovereign_namespace_authorize(
			      &ns_mgr, "ns1", PQCP_SOVEREIGN_OPERATION_READ_DATA,
			      PQCP_SOVEREIGN_DATA_INTERNAL, NS_EPOCH, NS_NOW),
		      -ENOENT);
	mk_ns(&n, "ns1");
	zassert_ok(pqcp_sovereign_namespace_create(
		&ns_mgr, &ns_registry, &n, NS_NOW));
	zassert_ok(pqcp_sovereign_namespace_authorize(
		&ns_mgr, "ns1", PQCP_SOVEREIGN_OPERATION_READ_DATA,
		PQCP_SOVEREIGN_DATA_CONFIDENTIAL, NS_EPOCH, NS_NOW));
	/* Data class above the namespace ceiling. */
	zassert_equal(pqcp_sovereign_namespace_authorize(
			      &ns_mgr, "ns1", PQCP_SOVEREIGN_OPERATION_READ_DATA,
			      PQCP_SOVEREIGN_DATA_RESTRICTED, NS_EPOCH, NS_NOW),
		      -EACCES);
	/* Operation not granted. */
	zassert_equal(pqcp_sovereign_namespace_authorize(
			      &ns_mgr, "ns1",
			      PQCP_SOVEREIGN_OPERATION_EXPORT_DATA,
			      PQCP_SOVEREIGN_DATA_INTERNAL, NS_EPOCH, NS_NOW),
		      -EACCES);
	/* Stale epoch, both directions. */
	zassert_equal(pqcp_sovereign_namespace_authorize(
			      &ns_mgr, "ns1", PQCP_SOVEREIGN_OPERATION_READ_DATA,
			      PQCP_SOVEREIGN_DATA_INTERNAL, NS_EPOCH - 1U,
			      NS_NOW), -ESTALE);
	zassert_equal(pqcp_sovereign_namespace_authorize(
			      &ns_mgr, "ns1", PQCP_SOVEREIGN_OPERATION_READ_DATA,
			      PQCP_SOVEREIGN_DATA_INTERNAL, NS_EPOCH + 1U,
			      NS_NOW), -ESTALE);
	/* Expiry boundary. */
	zassert_ok(pqcp_sovereign_namespace_authorize(
		&ns_mgr, "ns1", PQCP_SOVEREIGN_OPERATION_READ_DATA,
		PQCP_SOVEREIGN_DATA_INTERNAL, NS_EPOCH, 49999U));
	zassert_equal(pqcp_sovereign_namespace_authorize(
			      &ns_mgr, "ns1", PQCP_SOVEREIGN_OPERATION_READ_DATA,
			      PQCP_SOVEREIGN_DATA_INTERNAL, NS_EPOCH, 50000U),
		      -ETIME);
	/* Non-active namespace is denied. */
	ns_spaces[0].state = PQCP_SOVEREIGN_LIFECYCLE_SUSPENDED;
	zassert_equal(pqcp_sovereign_namespace_authorize(
			      &ns_mgr, "ns1", PQCP_SOVEREIGN_OPERATION_READ_DATA,
			      PQCP_SOVEREIGN_DATA_INTERNAL, NS_EPOCH, NS_NOW),
		      -EACCES);
	ns_spaces[0].state = PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
	/* Invalid enums / arguments. */
	zassert_equal(pqcp_sovereign_namespace_authorize(
			      &ns_mgr, "ns1", PQCP_SOVEREIGN_OPERATION_NONE,
			      PQCP_SOVEREIGN_DATA_INTERNAL, NS_EPOCH, NS_NOW),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_namespace_authorize(
			      &ns_mgr, "ns1", PQCP_SOVEREIGN_OPERATION_COUNT,
			      PQCP_SOVEREIGN_DATA_INTERNAL, NS_EPOCH, NS_NOW),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_namespace_authorize(
			      &ns_mgr, "ns1", PQCP_SOVEREIGN_OPERATION_READ_DATA,
			      (enum pqcp_sovereign_data_class)
				      PQCP_SOVEREIGN_DATA_CLASS_COUNT,
			      NS_EPOCH, NS_NOW), -EINVAL);
	zassert_equal(pqcp_sovereign_namespace_authorize(
			      &ns_mgr, "ns1", PQCP_SOVEREIGN_OPERATION_READ_DATA,
			      PQCP_SOVEREIGN_DATA_INTERNAL, 0U, NS_NOW), -EINVAL);
	zassert_equal(pqcp_sovereign_namespace_authorize(
			      &ns_mgr, "ns1", PQCP_SOVEREIGN_OPERATION_READ_DATA,
			      PQCP_SOVEREIGN_DATA_INTERNAL, NS_EPOCH, 0U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_namespace_authorize(
			      NULL, "ns1", PQCP_SOVEREIGN_OPERATION_READ_DATA,
			      PQCP_SOVEREIGN_DATA_INTERNAL, NS_EPOCH, NS_NOW),
		      -EINVAL);
}

ZTEST(pqcp_sovereign_policy, test_namespace_audit_detects_policy_tampering)
{
	struct pqcp_sovereign_namespace n;

	ns_setup(2U);
	mk_ns(&n, "ns1");
	zassert_ok(pqcp_sovereign_namespace_create(
		&ns_mgr, &ns_registry, &n, NS_NOW));
	zassert_ok(pqcp_sovereign_namespace_manager_audit(&ns_mgr));
	/* The policy digest binds the quota and expiry: editing them in
	 * place (without going through create) must be detected.
	 */
	ns_spaces[0].storage_limit_bytes += 1U;
	zassert_equal(pqcp_sovereign_namespace_manager_audit(&ns_mgr), -EBADMSG);
	ns_spaces[0].storage_limit_bytes -= 1U;
	zassert_ok(pqcp_sovereign_namespace_manager_audit(&ns_mgr));
	ns_spaces[0].expires_at_ms += 1U;
	zassert_equal(pqcp_sovereign_namespace_manager_audit(&ns_mgr), -EBADMSG);
	ns_spaces[0].expires_at_ms -= 1U;
	/* Uninitialised manager is refused. */
	memset(&ns_mgr, 0, sizeof(ns_mgr));
	zassert_equal(pqcp_sovereign_namespace_manager_audit(&ns_mgr), -EINVAL);
}

/* ------------------------------------------------------------------ */
/* Audit guards on uninitialised engines                              */
/* ------------------------------------------------------------------ */

ZTEST(pqcp_sovereign_policy, test_audits_reject_uninitialised_engines)
{
	static struct pqcp_sovereign_residency_engine r;
	static struct pqcp_sovereign_network_intent_manager n;
	static struct pqcp_sovereign_privacy_budget_manager p;
	static struct pqcp_sovereign_consent_ledger c;
	static struct pqcp_sovereign_data_contract_manager d;
	static struct pqcp_sovereign_placement_engine pl;
	static struct pqcp_sovereign_egress_engine e;
	static struct pqcp_sovereign_retention_manager rt;

	memset(&r, 0, sizeof(r));
	memset(&n, 0, sizeof(n));
	memset(&p, 0, sizeof(p));
	memset(&c, 0, sizeof(c));
	memset(&d, 0, sizeof(d));
	memset(&pl, 0, sizeof(pl));
	memset(&e, 0, sizeof(e));
	memset(&rt, 0, sizeof(rt));
	zassert_equal(pqcp_sovereign_residency_engine_audit(&r), -EINVAL);
	zassert_equal(pqcp_sovereign_network_intent_manager_audit(&n), -EINVAL);
	zassert_equal(pqcp_sovereign_privacy_budget_manager_audit(&p), -EINVAL);
	zassert_equal(pqcp_sovereign_consent_ledger_audit(&c), -EINVAL);
	zassert_equal(pqcp_sovereign_data_contract_manager_audit(&d), -EINVAL);
	zassert_equal(pqcp_sovereign_placement_engine_audit(&pl), -EINVAL);
	zassert_equal(pqcp_sovereign_egress_engine_audit(&e), -EINVAL);
	zassert_equal(pqcp_sovereign_retention_manager_audit(&rt), -EINVAL);
	zassert_equal(pqcp_sovereign_residency_engine_audit(NULL), -EINVAL);
	zassert_equal(pqcp_sovereign_namespace_manager_audit(NULL), -EINVAL);
}

static void *sovereign_setup(void)
{
	zassert_equal(psa_crypto_init(), PSA_SUCCESS);
	return NULL;
}

ZTEST_SUITE(pqcp_sovereign_policy, NULL, sovereign_setup, NULL, NULL, NULL);
