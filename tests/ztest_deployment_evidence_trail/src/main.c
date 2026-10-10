/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tests for the hash-chained deployment evidence trail.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_evidence_trail.h>

static const char top_a[] = "hybrid768_65_campaign";
static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char digest_a[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char digest_b[] =
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char digest_c[] =
	"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

static struct pqcp_deployment_evidence_trail trail;
static struct pqcp_deployment_evidence_trail_entry entries[
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES];

static void init_trail(void)
{
	zassert_equal(pqcp_deployment_evidence_trail_init(
			      &trail,
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      top_a, nonce_a),
		      0);
}

static void append_terminal_chain(void)
{
	zassert_equal(pqcp_deployment_evidence_trail_append(
			      &trail, entries, ARRAY_SIZE(entries),
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_VERDICT,
			      digest_a),
		      0);
	zassert_equal(pqcp_deployment_evidence_trail_append(
			      &trail, entries, ARRAY_SIZE(entries),
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_SEAL,
			      digest_b),
		      0);
	zassert_equal(pqcp_deployment_evidence_trail_append(
			      &trail, entries, ARRAY_SIZE(entries),
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_PASSPORT,
			      digest_c),
		      0);
}

ZTEST(pqcp_deployment_evidence_trail, test_stage_tokens_are_stable)
{
	zassert_str_equal(pqcp_deployment_evidence_trail_stage_str(
				  PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_VERDICT),
			  "verdict");
	zassert_str_equal(pqcp_deployment_evidence_trail_stage_str(
				  PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_SEAL),
			  "seal");
	zassert_str_equal(pqcp_deployment_evidence_trail_stage_str(
				  PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_SEAL_AUDIT),
			  "seal_audit");
	zassert_str_equal(pqcp_deployment_evidence_trail_stage_str(
				  PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_PASSPORT),
			  "passport");
	zassert_str_equal(pqcp_deployment_evidence_trail_stage_str(
				  PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_TAMPER_MATRIX),
			  "tamper_matrix");
	zassert_str_equal(pqcp_deployment_evidence_trail_stage_str(
				  PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_CUSTOM),
			  "custom");
	zassert_str_equal(pqcp_deployment_evidence_trail_stage_str(99),
			  "unknown");
}

ZTEST(pqcp_deployment_evidence_trail, test_init_validates_identity)
{
	zassert_equal(pqcp_deployment_evidence_trail_init(
			      NULL,
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      top_a, nonce_a),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_init(
			      &trail, 99, top_a, nonce_a),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_init(
			      &trail,
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      "", nonce_a),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_init(
			      &trail,
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      "top with spaces", nonce_a),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_init(
			      &trail,
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      top_a, "1234"),
		      -EINVAL);

	init_trail();
	zassert_equal(trail.entry_count, 0U);
	zassert_equal(trail.observed_stage_mask, 0U);
	zassert_equal(strlen(trail.head_digest_hex), 64U);
}

ZTEST(pqcp_deployment_evidence_trail, test_append_chains_links)
{
	char genesis_head[
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U];

	init_trail();
	(void)snprintk(genesis_head, sizeof(genesis_head), "%s",
		       trail.head_digest_hex);

	append_terminal_chain();

	zassert_equal(trail.entry_count, 3U);
	zassert_equal(entries[0].sequence, 0U);
	zassert_equal(entries[1].sequence, 1U);
	zassert_equal(entries[2].sequence, 2U);
	/* The head is always the most recent link. */
	zassert_str_equal(trail.head_digest_hex,
			  entries[2].link_digest_hex);
	/* Each link differs from its predecessor and the genesis. */
	zassert_true(strcmp(entries[0].link_digest_hex, genesis_head) != 0);
	zassert_true(strcmp(entries[1].link_digest_hex,
			    entries[0].link_digest_hex) != 0);
	zassert_true(strcmp(entries[2].link_digest_hex,
			    entries[1].link_digest_hex) != 0);
	zassert_equal(trail.observed_stage_mask,
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_BIT(
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_VERDICT) |
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_BIT(
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_SEAL) |
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_BIT(
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_PASSPORT));
}

ZTEST(pqcp_deployment_evidence_trail, test_identity_binds_genesis)
{
	struct pqcp_deployment_evidence_trail other;
	struct pqcp_deployment_evidence_trail_entry other_entries[4];

	init_trail();
	append_terminal_chain();

	/* Same digests, different nonce: every link must differ. */
	zassert_equal(pqcp_deployment_evidence_trail_init(
			      &other,
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      top_a, "ffeeddccbbaa99887766554433221100"),
		      0);
	zassert_equal(pqcp_deployment_evidence_trail_append(
			      &other, other_entries,
			      ARRAY_SIZE(other_entries),
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_VERDICT,
			      digest_a),
		      0);
	zassert_true(strcmp(other_entries[0].link_digest_hex,
			    entries[0].link_digest_hex) != 0);
}

ZTEST(pqcp_deployment_evidence_trail, test_append_validates_inputs)
{
	init_trail();

	zassert_equal(pqcp_deployment_evidence_trail_append(
			      NULL, entries, ARRAY_SIZE(entries),
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_VERDICT,
			      digest_a),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_append(
			      &trail, NULL, ARRAY_SIZE(entries),
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_VERDICT,
			      digest_a),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_append(
			      &trail, entries, ARRAY_SIZE(entries), 99,
			      digest_a),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_append(
			      &trail, entries, ARRAY_SIZE(entries),
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_VERDICT,
			      "deadbeef"),
		      -EINVAL);

	/* Capacity limit. */
	for (uint32_t i = 0U;
	     i < PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES; ++i) {
		zassert_equal(pqcp_deployment_evidence_trail_append(
				      &trail, entries, ARRAY_SIZE(entries),
				      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_CUSTOM,
				      digest_a),
			      0);
	}
	zassert_equal(pqcp_deployment_evidence_trail_append(
			      &trail, entries, ARRAY_SIZE(entries),
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_CUSTOM,
			      digest_a),
		      -ENOSPC);
}

ZTEST(pqcp_deployment_evidence_trail, test_finish_enforces_policy)
{
	struct pqcp_deployment_evidence_trail_policy policy;

	init_trail();
	append_terminal_chain();
	zassert_equal(pqcp_deployment_evidence_trail_default_policy(&policy),
		      0);
	zassert_equal(pqcp_deployment_evidence_trail_finish(&trail, &policy),
		      0);
	zassert_equal(trail.status, PQCP_DEPLOYMENT_EVIDENCE_TRAIL_PASS);
	zassert_equal(trail.error_mask, 0U);

	/* Missing required passport stage. */
	init_trail();
	zassert_equal(pqcp_deployment_evidence_trail_append(
			      &trail, entries, ARRAY_SIZE(entries),
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_VERDICT,
			      digest_a),
		      0);
	zassert_equal(pqcp_deployment_evidence_trail_append(
			      &trail, entries, ARRAY_SIZE(entries),
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_SEAL,
			      digest_b),
		      0);
	zassert_equal(pqcp_deployment_evidence_trail_append(
			      &trail, entries, ARRAY_SIZE(entries),
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_SEAL_AUDIT,
			      digest_c),
		      0);
	zassert_equal(pqcp_deployment_evidence_trail_finish(&trail, &policy),
		      -EBADMSG);
	zassert_true((trail.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_MISSING_STAGE) !=
		     0U);

	/* Too few entries. */
	init_trail();
	zassert_equal(pqcp_deployment_evidence_trail_append(
			      &trail, entries, ARRAY_SIZE(entries),
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_VERDICT,
			      digest_a),
		      0);
	zassert_equal(pqcp_deployment_evidence_trail_finish(&trail, &policy),
		      -EBADMSG);
	zassert_true((trail.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_MIN_ENTRIES) !=
		     0U);

	/* Empty trail. */
	init_trail();
	zassert_equal(pqcp_deployment_evidence_trail_finish(&trail, &policy),
		      -EBADMSG);
	zassert_true((trail.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_NO_ENTRIES) != 0U);

	/* Custom stages only warn when minimums are met. */
	init_trail();
	append_terminal_chain();
	zassert_equal(pqcp_deployment_evidence_trail_append(
			      &trail, entries, ARRAY_SIZE(entries),
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_CUSTOM,
			      digest_a),
		      0);
	zassert_equal(pqcp_deployment_evidence_trail_finish(&trail, &policy),
		      0);
	zassert_equal(trail.status, PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARN);
	zassert_true((trail.warning_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARNING_CUSTOM_STAGE) !=
		     0U);

	/* Invalid policy. */
	init_trail();
	zassert_equal(pqcp_deployment_evidence_trail_finish(&trail, NULL),
		      -EINVAL);
}

ZTEST(pqcp_deployment_evidence_trail, test_emit_validates_shapes)
{
	struct pqcp_deployment_evidence_trail_policy policy;

	init_trail();
	append_terminal_chain();
	zassert_equal(pqcp_deployment_evidence_trail_default_policy(&policy),
		      0);
	zassert_equal(pqcp_deployment_evidence_trail_finish(&trail, &policy),
		      0);

	for (uint32_t i = 0U; i < trail.entry_count; ++i) {
		zassert_equal(pqcp_deployment_evidence_trail_entry_emit(
				      &entries[i]),
			      0);
	}
	zassert_equal(pqcp_deployment_evidence_trail_emit(&trail), 0);

	zassert_equal(pqcp_deployment_evidence_trail_entry_emit(NULL),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_emit(NULL), -EINVAL);

	entries[0].schema_version = 99U;
	zassert_equal(pqcp_deployment_evidence_trail_entry_emit(&entries[0]),
		      -EINVAL);

	trail.entry_count = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES + 1U;
	zassert_equal(pqcp_deployment_evidence_trail_emit(&trail), -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_evidence_trail, NULL, NULL, NULL, NULL, NULL);
