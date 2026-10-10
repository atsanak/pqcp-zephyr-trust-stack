/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tests for deployment marker render-to-buffer support.
 *
 * The decisive property is the round trip: a rendered marker fed into the
 * matching replay verifier must parse and verify exactly like the printk
 * emission it mirrors.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_assurance_passport_replay.h>
#include <pqcp_zephyr/deployment_marker_render.h>

static const char top_a[] = "hybrid768_65_campaign";
static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char verdict_digest_a[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char audit_digest_a[] =
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char trace_a[] =
	"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static const char review_a[] =
	"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
static const char device_a[] =
	"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
static const char token_a[] =
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

struct chain_fixture {
	struct pqcp_deployment_evidence_verdict verdict;
	struct pqcp_deployment_evidence_verdict_replay_result verdict_replay;
	struct pqcp_deployment_evidence_verdict_audit_report verdict_audit;
	struct pqcp_deployment_evidence_seal_policy seal_policy;
	struct pqcp_deployment_evidence_seal seal;
	struct pqcp_deployment_evidence_seal_replay_result seal_replay;
	struct pqcp_deployment_evidence_seal_audit_policy seal_audit_policy;
	struct pqcp_deployment_evidence_seal_audit_report seal_audit;
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_assurance_passport_policy passport_policy;
	struct pqcp_deployment_assurance_passport passport;
};

static void set_text(char *dst, size_t dst_size, const char *src)
{
	zassert_not_null(dst);
	zassert_not_null(src);
	zassert_true(dst_size > 0U);
	(void)snprintk(dst, dst_size, "%s", src);
}

static uint32_t full_caps(void)
{
	return PQCP_CAPABILITY_EVIDENCE_KNOWN_MASK;
}

static void fill_verdict(struct pqcp_deployment_evidence_verdict *verdict)
{
	memset(verdict, 0, sizeof(*verdict));
	verdict->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_SCHEMA_VERSION;
	verdict->status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS;
	verdict->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	verdict->verdict_score = 87U;
	verdict->min_chain_score = 87U;
	verdict->stage_count = 16U;
	verdict->pass_count = 16U;
	verdict->consistency_checks = 7U;
	verdict->consistency_pass_count = 7U;
	verdict->evidence_capabilities_all = full_caps();
	verdict->evidence_capabilities_any = full_caps();
	verdict->top_consistent = true;
	verdict->nonce_consistent = true;
	verdict->trace_digest_consistent = true;
	verdict->review_packet_digest_consistent = true;
	verdict->device_packet_digest_consistent = true;
	verdict->token_digest_consistent = true;
	set_text(verdict->top_candidate_id, sizeof(verdict->top_candidate_id),
		 top_a);
	set_text(verdict->nonce_hex, sizeof(verdict->nonce_hex), nonce_a);
	set_text(verdict->trace_digest_hex, sizeof(verdict->trace_digest_hex),
		 trace_a);
	set_text(verdict->review_packet_digest_hex,
		 sizeof(verdict->review_packet_digest_hex), review_a);
	set_text(verdict->device_packet_digest_hex,
		 sizeof(verdict->device_packet_digest_hex), device_a);
	set_text(verdict->token_digest_hex, sizeof(verdict->token_digest_hex),
		 token_a);
	set_text(verdict->packet_audit_digest_hex,
		 sizeof(verdict->packet_audit_digest_hex), device_a);
	set_text(verdict->verdict_digest_hex,
		 sizeof(verdict->verdict_digest_hex), verdict_digest_a);
}

static void fill_verdict_replay(
	struct pqcp_deployment_evidence_verdict_replay_result *replay)
{
	memset(replay, 0, sizeof(*replay));
	replay->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_SCHEMA_VERSION;
	replay->lines_seen = 1U;
	replay->marker_mask =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_REQUIRED_MASK;
	replay->first_error =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_NONE;
	replay->verdict_status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS;
	replay->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	replay->verdict_score = 87U;
	replay->min_chain_score = 87U;
	replay->stage_count = 16U;
	replay->consistency_checks = 7U;
	replay->consistency_pass_count = 7U;
	replay->evidence_capabilities_all = full_caps();
	replay->evidence_capabilities_any = full_caps();
	replay->passed = true;
	set_text(replay->top_candidate_id, sizeof(replay->top_candidate_id),
		 top_a);
	set_text(replay->nonce_hex, sizeof(replay->nonce_hex), nonce_a);
	set_text(replay->computed_digest_hex,
		 sizeof(replay->computed_digest_hex), verdict_digest_a);
}

static void fill_verdict_audit(
	struct pqcp_deployment_evidence_verdict_audit_report *audit)
{
	memset(audit, 0, sizeof(*audit));
	audit->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_SCHEMA_VERSION;
	audit->status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_PASS;
	audit->result_count = 1U;
	audit->replay_pass_count = 1U;
	audit->verdict_pass_count = 1U;
	audit->unique_verdict_digest_count = 1U;
	audit->min_verdict_score = 87U;
	audit->max_verdict_score = 87U;
	audit->avg_verdict_score = 87U;
	audit->min_chain_score = 87U;
	audit->max_chain_score = 87U;
	audit->avg_chain_score = 87U;
	audit->evidence_capabilities_all = full_caps();
	audit->evidence_capabilities_any = full_caps();
	audit->stable_top_candidate = true;
	audit->stable_nonce = true;
	audit->stable_verdict_digest = true;
	audit->stable_capabilities = true;
	audit->stable_verdict_status = true;
	audit->stable_profile = true;
	audit->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	set_text(audit->top_candidate_id, sizeof(audit->top_candidate_id),
		 top_a);
	set_text(audit->nonce_hex, sizeof(audit->nonce_hex), nonce_a);
	set_text(audit->verdict_digest_hex, sizeof(audit->verdict_digest_hex),
		 verdict_digest_a);
	set_text(audit->audit_digest_hex, sizeof(audit->audit_digest_hex),
		 audit_digest_a);
}

static void fill_capability(struct pqcp_capability_descriptor *capability)
{
	memset(capability, 0, sizeof(*capability));
	capability->schema_version = PQCP_CAPABILITY_DESCRIPTOR_SCHEMA_VERSION;
	capability->pqcp_version = "1.0.0";
	capability->zephyr_version = "4.4.0";
	capability->board = "qemu_x86_64";
	capability->profile = PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL;
	capability->mlkem_level_mask = 0x00000300U;
	capability->mldsa_level_mask = 0x00000041U;
	capability->rng_mode = "zephyr_entropy";
	capability->provider_summary = PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE;
	capability->backend_selector = "auto";
	capability->evidence_capabilities = full_caps();
	capability->policy_passed = true;
	capability->production_allowed = true;
	capability->evidence_readiness_score = 96U;
}

static void build_chain(struct chain_fixture *chain)
{
	memset(chain, 0, sizeof(*chain));
	fill_verdict(&chain->verdict);
	fill_verdict_replay(&chain->verdict_replay);
	fill_verdict_audit(&chain->verdict_audit);
	zassert_equal(pqcp_deployment_evidence_seal_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &chain->seal_policy),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_run(
			      &chain->verdict, &chain->verdict_replay,
			      &chain->verdict_audit, &chain->seal_policy,
			      &chain->seal),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_verify(
			      &chain->seal, &chain->seal_replay),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_audit_default_policy(
			      &chain->seal_audit_policy),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_audit_run(
			      &chain->seal_replay, 1U,
			      &chain->seal_audit_policy, &chain->seal_audit),
		      0);
	fill_capability(&chain->capability);
	zassert_equal(pqcp_deployment_assurance_passport_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &chain->passport_policy),
		      0);
	zassert_equal(pqcp_deployment_assurance_passport_run(
			      &chain->capability, &chain->seal,
			      &chain->seal_replay, &chain->seal_audit,
			      &chain->passport_policy, &chain->passport),
		      0);
}

ZTEST(pqcp_deployment_marker_render, test_seal_render_round_trips)
{
	static struct chain_fixture chain;
	static char line[PQCP_DEPLOYMENT_MARKER_RENDER_LINE_MAX];
	struct pqcp_deployment_evidence_seal_replay_state state;
	struct pqcp_deployment_evidence_seal_replay_result result;
	int written;

	build_chain(&chain);
	written = pqcp_deployment_marker_render_seal(&chain.seal, line,
						     sizeof(line));
	zassert_true(written > 0);
	zassert_equal((size_t)written, strlen(line));
	zassert_true(strncmp(line, "PQCP_DEPLOYMENT_EVIDENCE_SEAL ",
			     strlen("PQCP_DEPLOYMENT_EVIDENCE_SEAL ")) == 0);

	zassert_equal(pqcp_deployment_evidence_seal_replay_init(&state), 0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_ingest_line(
			      &state, line),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_finish(&state,
								  &result),
		      0);
	zassert_true(result.passed);
	zassert_str_equal(result.computed_digest_hex,
			  chain.seal.seal_digest_hex);
}

ZTEST(pqcp_deployment_marker_render, test_passport_render_round_trips)
{
	static struct chain_fixture chain;
	static char line[PQCP_DEPLOYMENT_MARKER_RENDER_LINE_MAX];
	static struct pqcp_deployment_assurance_passport_replay_state state;
	struct pqcp_deployment_assurance_passport_replay_result result;
	int written;

	build_chain(&chain);
	written = pqcp_deployment_marker_render_passport(&chain.passport,
							 line, sizeof(line));
	zassert_true(written > 0);
	zassert_true(strncmp(line, "PQCP_DEPLOYMENT_ASSURANCE_PASSPORT ",
			     strlen("PQCP_DEPLOYMENT_ASSURANCE_PASSPORT ")) ==
		     0);

	zassert_equal(pqcp_deployment_assurance_passport_replay_init(&state),
		      0);
	zassert_equal(pqcp_deployment_assurance_passport_replay_ingest_line(
			      &state, line),
		      0);
	zassert_equal(pqcp_deployment_assurance_passport_replay_finish(
			      &state, &result),
		      0);
	zassert_true(result.passed);
	zassert_str_equal(result.computed_digest_hex,
			  chain.passport.passport_digest_hex);
}

ZTEST(pqcp_deployment_marker_render, test_verdict_render_parses_cleanly)
{
	static struct chain_fixture chain;
	static char line[PQCP_DEPLOYMENT_MARKER_RENDER_LINE_MAX];
	struct pqcp_deployment_evidence_verdict_replay_state state;
	struct pqcp_deployment_evidence_verdict_replay_result result;
	int written;

	build_chain(&chain);
	written = pqcp_deployment_marker_render_verdict(&chain.verdict, line,
							sizeof(line));
	zassert_true(written > 0);

	/* The fixture verdict carries a placeholder digest, so a correct
	 * round trip must reach the digest comparison (proving every field
	 * parsed) and fail exactly there.
	 */
	zassert_equal(pqcp_deployment_evidence_verdict_replay_init(&state),
		      0);
	(void)pqcp_deployment_evidence_verdict_replay_ingest_line(&state,
								  line);
	zassert_equal(pqcp_deployment_evidence_verdict_replay_finish(&state,
								     &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_DIGEST_MISMATCH);
}

ZTEST(pqcp_deployment_marker_render, test_render_rejects_invalid_inputs)
{
	static struct chain_fixture chain;
	static char line[PQCP_DEPLOYMENT_MARKER_RENDER_LINE_MAX];
	char tiny[64];

	build_chain(&chain);

	zassert_equal(pqcp_deployment_marker_render_seal(NULL, line,
							 sizeof(line)),
		      -EINVAL);
	zassert_equal(pqcp_deployment_marker_render_seal(&chain.seal, NULL,
							 0U),
		      -EINVAL);
	zassert_equal(pqcp_deployment_marker_render_seal(&chain.seal, tiny,
							 sizeof(tiny)),
		      -ENOSPC);

	chain.seal.schema_version = 99U;
	zassert_equal(pqcp_deployment_marker_render_seal(&chain.seal, line,
							 sizeof(line)),
		      -EINVAL);

	build_chain(&chain);
	chain.passport.passport_score = 101U;
	zassert_equal(pqcp_deployment_marker_render_passport(
			      &chain.passport, line, sizeof(line)),
		      -EINVAL);

	build_chain(&chain);
	chain.verdict.warning_mask = 0x80000000U;
	zassert_equal(pqcp_deployment_marker_render_verdict(
			      &chain.verdict, line, sizeof(line)),
		      -EINVAL);
}

ZTEST(pqcp_deployment_marker_render, test_passport_ingest_rejects_duplicates)
{
	static struct chain_fixture chain;
	static char line[PQCP_DEPLOYMENT_MARKER_RENDER_LINE_MAX];
	static struct pqcp_deployment_assurance_passport_replay_state state;
	struct pqcp_deployment_assurance_passport_replay_result result;

	build_chain(&chain);
	zassert_true(pqcp_deployment_marker_render_passport(
			     &chain.passport, line, sizeof(line)) > 0);

	zassert_equal(pqcp_deployment_assurance_passport_replay_init(&state),
		      0);
	zassert_equal(pqcp_deployment_assurance_passport_replay_ingest_line(
			      &state, line),
		      0);
	zassert_equal(pqcp_deployment_assurance_passport_replay_ingest_line(
			      &state, line),
		      -EINVAL);
	zassert_equal(pqcp_deployment_assurance_passport_replay_finish(
			      &state, &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_DUPLICATE_MARKER);
}

ZTEST(pqcp_deployment_marker_render, test_passport_ingest_requires_marker)
{
	static struct pqcp_deployment_assurance_passport_replay_state state;
	struct pqcp_deployment_assurance_passport_replay_result result;

	zassert_equal(pqcp_deployment_assurance_passport_replay_init(&state),
		      0);
	zassert_equal(pqcp_deployment_assurance_passport_replay_ingest_line(
			      &state, "unrelated line"),
		      0);
	zassert_equal(pqcp_deployment_assurance_passport_replay_finish(
			      &state, &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_MISSING_REQUIRED);
}

ZTEST_SUITE(pqcp_deployment_marker_render, NULL, NULL, NULL, NULL, NULL);
