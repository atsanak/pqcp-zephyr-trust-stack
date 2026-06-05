/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 */

#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_device_token_replay.h>

static const char nonce_hex[] = "00112233445566778899aabbccddeeff";
static const char wrong_nonce_hex[] = "ffeeddccbbaa99887766554433221100";
static const char trace_digest[] =
	"4b4bb88a348a502d14463d286ae65e56d1e7404fc94ee8980ff5359df65ee05e";
static const char packet_digest[] =
	"863c3f8ab7b174d111c5b497449e0d6f47e556b43aabef93c7caa7616f4416c3";

struct fixture {
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_release_gate_report gate;
	struct pqcp_deployment_device_token_policy policy;
	struct pqcp_deployment_device_token token;
	struct pqcp_deployment_device_token_verification verification;
};

static void fill_capability(struct pqcp_capability_descriptor *descriptor)
{
	memset(descriptor, 0, sizeof(*descriptor));
	descriptor->schema_version = PQCP_CAPABILITY_DESCRIPTOR_SCHEMA_VERSION;
	descriptor->pqcp_version = "1.0.0";
	descriptor->zephyr_version = "4.4.0";
	descriptor->board = "nucleo_h743zi";
	descriptor->profile = PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL;
	descriptor->mlkem_level_mask = PQCP_BUILD_MLKEM_LEVEL_768;
	descriptor->mldsa_level_mask = PQCP_BUILD_MLDSA_LEVEL_65;
	descriptor->rng_mode = "zephyr_entropy";
	descriptor->provider_summary = PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE;
	descriptor->backend_selector = "auto";
	descriptor->evidence_capabilities =
		PQCP_CAPABILITY_EVIDENCE_BUILD_MANIFEST |
		PQCP_CAPABILITY_EVIDENCE_PROVIDER_CONTRACT |
		PQCP_CAPABILITY_EVIDENCE_FIRMWARE_POLICY |
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_RELEASE_GATE |
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_TOKEN |
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_TOKEN_REPLAY;
	descriptor->policy_passed = true;
	descriptor->production_allowed = true;
	descriptor->evidence_readiness_score = 100U;
}

static void fill_gate(struct pqcp_deployment_release_gate_report *gate)
{
	memset(gate, 0, sizeof(*gate));
	gate->schema_version = PQCP_DEPLOYMENT_RELEASE_GATE_SCHEMA_VERSION;
	gate->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	gate->status = PQCP_DEPLOYMENT_RELEASE_GATE_PASS;
	gate->candidate_count = 3U;
	gate->readiness_score = 100U;
	gate->claim_score = 94U;
	gate->review_score = 100U;
	gate->gate_score = 94U;
	gate->top_consistent = true;
	gate->digest_bound = true;
	gate->pipeline_passed = true;
	gate->budget_passed = true;
	gate->experiment_plan_passed = true;
	gate->packet_passed = true;
	gate->replay_passed = true;
	gate->audit_passed = true;
	(void)snprintk(gate->top_candidate_id,
		       sizeof(gate->top_candidate_id), "%s", "mlkem768_m7");
	(void)snprintk(gate->trace_digest_hex,
		       sizeof(gate->trace_digest_hex), "%s", trace_digest);
	(void)snprintk(gate->packet_digest_hex,
		       sizeof(gate->packet_digest_hex), "%s", packet_digest);
}

static void fill_fixture(struct fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	fill_capability(&fixture->capability);
	fill_gate(&fixture->gate);
	zassert_equal(pqcp_deployment_device_token_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &fixture->policy),
		      0);
	zassert_equal(pqcp_deployment_device_token_build(
			      &fixture->capability, &fixture->gate, nonce_hex,
			      &fixture->policy, &fixture->token),
		      0);
	zassert_equal(pqcp_deployment_device_token_verify(
			      &fixture->token, &fixture->capability,
			      &fixture->gate, nonce_hex, &fixture->policy,
			      &fixture->verification),
		      0);
}

static int append(char *buffer, size_t buffer_size, size_t *offset,
		  const char *fmt, ...)
{
	va_list args;
	int written;

	va_start(args, fmt);
	written = vsnprintk(&buffer[*offset], buffer_size - *offset, fmt,
			    args);
	va_end(args);
	if (written < 0 || (size_t)written >= buffer_size - *offset) {
		return -ENOSPC;
	}
	*offset += (size_t)written;
	return 0;
}

static void append_capability(char *buffer, size_t buffer_size, size_t *offset,
			      const struct pqcp_capability_descriptor *cap)
{
	zassert_equal(append(
			      buffer, buffer_size, offset,
			      "PQCP_CAPABILITY_DESCRIPTOR schema=%u profile=%s status=%s production_allowed=%u provider=%s backend=%s mlkem_levels=0x%08x mldsa_levels=0x%08x rng=%s evidence=0x%08x blockers=0x%08x readiness=%u\n",
			      cap->schema_version,
			      pqcp_firmware_policy_profile_str(cap->profile),
			      cap->policy_passed ? "PASS" : "FAIL",
			      cap->production_allowed ? 1U : 0U,
			      pqcp_capability_provider_summary_str(
				      cap->provider_summary),
			      cap->backend_selector,
			      cap->mlkem_level_mask,
			      cap->mldsa_level_mask,
			      cap->rng_mode,
			      cap->evidence_capabilities,
			      cap->policy_blockers,
			      cap->evidence_readiness_score),
		      0);
}

static void append_gate(char *buffer, size_t buffer_size, size_t *offset,
			const struct pqcp_deployment_release_gate_report *gate)
{
	zassert_equal(append(
			      buffer, buffer_size, offset,
			      "PQCP_DEPLOYMENT_RELEASE_GATE schema=%u profile=%s status=%s errors=0x%08x warnings=0x%08x candidates=%u gaps=%u experiments=%u blocking=%u readiness=%u claim_score=%u review_score=%u gate_score=%u top_consistent=%u digest_bound=%u pipeline=%s budget=%s experiment_plan=%s packet=%s replay=%s audit=%s top=%s trace_digest=%s packet_digest=%s\n",
			      gate->schema_version,
			      pqcp_deployment_release_gate_profile_str(
				      gate->profile),
			      pqcp_deployment_release_gate_status_str(
				      gate->status),
			      gate->error_mask,
			      gate->warning_mask,
			      gate->candidate_count,
			      gate->gap_count,
			      gate->experiment_count,
			      gate->blocking_experiment_count,
			      gate->readiness_score,
			      gate->claim_score,
			      gate->review_score,
			      gate->gate_score,
			      gate->top_consistent ? 1U : 0U,
			      gate->digest_bound ? 1U : 0U,
			      gate->pipeline_passed ? "PASS" : "FAIL",
			      gate->budget_passed ? "PASS" : "FAIL",
			      gate->experiment_plan_passed ? "PASS" : "FAIL",
			      gate->packet_passed ? "PASS" : "FAIL",
			      gate->replay_passed ? "PASS" : "FAIL",
			      gate->audit_passed ? "PASS" : "FAIL",
			      gate->top_candidate_id,
			      gate->trace_digest_hex,
			      gate->packet_digest_hex),
		      0);
}

static void append_token(char *buffer, size_t buffer_size, size_t *offset,
			 const struct pqcp_deployment_device_token *token)
{
	zassert_equal(append(
			      buffer, buffer_size, offset,
			      "PQCP_DEPLOYMENT_DEVICE_TOKEN schema=%u profile=%s status=%s nonce=%s errors=0x%08x warnings=0x%08x evidence=0x%08x cap_readiness=%u gate_score=%u gate_status=%s capability_policy=%u production_allowed=%u native_provider=%u gate_digest_bound=%u top=%s trace_digest=%s packet_digest=%s token_digest=%s\n",
			      token->schema_version,
			      pqcp_deployment_release_gate_profile_str(
				      token->profile),
			      pqcp_deployment_device_token_status_str(
				      token->status),
			      token->nonce_hex,
			      token->error_mask,
			      token->warning_mask,
			      token->evidence_capabilities,
			      token->capability_readiness_score,
			      token->gate_score,
			      pqcp_deployment_release_gate_status_str(
				      token->gate_status),
			      token->capability_policy_passed ? 1U : 0U,
			      token->production_allowed ? 1U : 0U,
			      token->native_provider ? 1U : 0U,
			      token->gate_digest_bound ? 1U : 0U,
			      token->top_candidate_id,
			      token->trace_digest_hex,
			      token->packet_digest_hex,
			      token->token_digest_hex),
		      0);
}

static void append_verify(
	char *buffer, size_t buffer_size, size_t *offset,
	const struct pqcp_deployment_device_token_verification *verification)
{
	zassert_equal(append(
			      buffer, buffer_size, offset,
			      "PQCP_DEPLOYMENT_DEVICE_TOKEN_VERIFY schema=%u status=%s errors=0x%08x expected_status=%s observed_status=%s expected_digest=%s observed_digest=%s\n",
			      verification->schema_version,
			      verification->passed ? "PASS" : "FAIL",
			      verification->error_mask,
			      pqcp_deployment_device_token_status_str(
				      verification->expected_status),
			      pqcp_deployment_device_token_status_str(
				      verification->observed_status),
			      verification->expected_digest_hex,
			      verification->observed_digest_hex),
		      0);
}

static void build_transcript(const struct fixture *fixture, char *buffer,
			     size_t buffer_size)
{
	size_t offset = 0U;

	memset(buffer, 0, buffer_size);
	zassert_equal(append(buffer, buffer_size, &offset,
			     "*** Booting Zephyr OS build v4.4.0 ***\n"),
		      0);
	append_capability(buffer, buffer_size, &offset,
			  &fixture->capability);
	append_gate(buffer, buffer_size, &offset, &fixture->gate);
	append_token(buffer, buffer_size, &offset, &fixture->token);
	append_verify(buffer, buffer_size, &offset, &fixture->verification);
}

ZTEST(pqcp_deployment_device_token_replay, test_error_tokens_are_stable)
{
	zassert_str_equal(
		pqcp_deployment_device_token_replay_error_str(
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_NONE),
		"none");
	zassert_str_equal(
		pqcp_deployment_device_token_replay_error_str(
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_NONCE_MISMATCH),
		"nonce_mismatch");
	zassert_str_equal(
		pqcp_deployment_device_token_replay_error_str(
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_VERIFY_MISMATCH),
		"verify_mismatch");
}

ZTEST(pqcp_deployment_device_token_replay, test_valid_transcript_replays)
{
	struct fixture fixture;
	struct pqcp_deployment_device_token_replay_result result;
	char transcript[4096];

	fill_fixture(&fixture);
	build_transcript(&fixture, transcript, sizeof(transcript));
	zassert_equal(pqcp_deployment_device_token_replay_verify_transcript(
			      transcript, nonce_hex, &result),
		      0);
	zassert_true(result.passed);
	zassert_equal(result.marker_mask,
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_REQUIRED_MASK);
	zassert_str_equal(result.top_candidate_id, "mlkem768_m7");
	zassert_str_equal(result.token_digest_hex,
			  fixture.token.token_digest_hex);
	zassert_str_equal(result.computed_digest_hex,
			  fixture.token.token_digest_hex);
	zassert_equal(pqcp_deployment_device_token_replay_emit_result(&result),
		      0);
}

ZTEST(pqcp_deployment_device_token_replay, test_missing_capability_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_device_token_replay_result result;
	char transcript[4096];
	size_t offset = 0U;

	fill_fixture(&fixture);
	memset(transcript, 0, sizeof(transcript));
	append_gate(transcript, sizeof(transcript), &offset, &fixture.gate);
	append_token(transcript, sizeof(transcript), &offset, &fixture.token);
	append_verify(transcript, sizeof(transcript), &offset,
		      &fixture.verification);
	zassert_equal(pqcp_deployment_device_token_replay_verify_transcript(
			      transcript, nonce_hex, &result),
		      -EBADMSG);
	zassert_false(result.passed);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MISSING_REQUIRED);
}

ZTEST(pqcp_deployment_device_token_replay, test_duplicate_token_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_device_token_replay_result result;
	char transcript[4096];
	size_t offset = 0U;

	fill_fixture(&fixture);
	memset(transcript, 0, sizeof(transcript));
	append_capability(transcript, sizeof(transcript), &offset,
			  &fixture.capability);
	append_gate(transcript, sizeof(transcript), &offset, &fixture.gate);
	append_token(transcript, sizeof(transcript), &offset, &fixture.token);
	append_token(transcript, sizeof(transcript), &offset, &fixture.token);
	append_verify(transcript, sizeof(transcript), &offset,
		      &fixture.verification);
	zassert_equal(pqcp_deployment_device_token_replay_verify_transcript(
			      transcript, nonce_hex, &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_DUPLICATE_MARKER);
}

ZTEST(pqcp_deployment_device_token_replay, test_tampered_digest_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_device_token_replay_result result;
	char transcript[4096];

	fill_fixture(&fixture);
	fixture.token.token_digest_hex[0] =
		fixture.token.token_digest_hex[0] == '0' ? '1' : '0';
	build_transcript(&fixture, transcript, sizeof(transcript));
	zassert_equal(pqcp_deployment_device_token_replay_verify_transcript(
			      transcript, nonce_hex, &result),
		      -EBADMSG);
	zassert_equal(
		result.first_error,
		PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_TOKEN_DIGEST_MISMATCH);
}

ZTEST(pqcp_deployment_device_token_replay, test_wrong_nonce_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_device_token_replay_result result;
	char transcript[4096];

	fill_fixture(&fixture);
	build_transcript(&fixture, transcript, sizeof(transcript));
	zassert_equal(pqcp_deployment_device_token_replay_verify_transcript(
			      transcript, wrong_nonce_hex, &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_NONCE_MISMATCH);
}

ZTEST(pqcp_deployment_device_token_replay, test_gate_top_mismatch_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_device_token_replay_result result;
	char transcript[4096];

	fill_fixture(&fixture);
	(void)snprintk(fixture.gate.top_candidate_id,
		       sizeof(fixture.gate.top_candidate_id), "%s",
		       "other_candidate");
	build_transcript(&fixture, transcript, sizeof(transcript));
	zassert_equal(pqcp_deployment_device_token_replay_verify_transcript(
			      transcript, nonce_hex, &result),
		      -EBADMSG);
	zassert_equal(
		result.first_error,
		PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_RELEASE_GATE_MISMATCH);
}

ZTEST(pqcp_deployment_device_token_replay, test_capability_mismatch_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_device_token_replay_result result;
	char transcript[4096];

	fill_fixture(&fixture);
	fixture.capability.evidence_readiness_score = 90U;
	build_transcript(&fixture, transcript, sizeof(transcript));
	zassert_equal(pqcp_deployment_device_token_replay_verify_transcript(
			      transcript, nonce_hex, &result),
		      -EBADMSG);
	zassert_equal(
		result.first_error,
		PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_CAPABILITY_MISMATCH);
}

ZTEST(pqcp_deployment_device_token_replay, test_verify_marker_mismatch_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_device_token_replay_result result;
	char transcript[4096];

	fill_fixture(&fixture);
	fixture.verification.passed = false;
	fixture.verification.error_mask =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_TOKEN_MISMATCH;
	build_transcript(&fixture, transcript, sizeof(transcript));
	zassert_equal(pqcp_deployment_device_token_replay_verify_transcript(
			      transcript, nonce_hex, &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_VERIFY_MISMATCH);
}

ZTEST(pqcp_deployment_device_token_replay, test_incremental_ingest_replays)
{
	struct fixture fixture;
	struct pqcp_deployment_device_token_replay_state state;
	struct pqcp_deployment_device_token_replay_result result;
	char line[1024];

	fill_fixture(&fixture);
	zassert_equal(pqcp_deployment_device_token_replay_init(&state), 0);
	(void)snprintk(
		line, sizeof(line),
		"PQCP_CAPABILITY_DESCRIPTOR schema=%u profile=mcu_minimal status=PASS production_allowed=1 provider=pqcp_native backend=auto mlkem_levels=0x%08x mldsa_levels=0x%08x rng=zephyr_entropy evidence=0x%08x blockers=0x00000000 readiness=%u",
		fixture.capability.schema_version,
		fixture.capability.mlkem_level_mask,
		fixture.capability.mldsa_level_mask,
		fixture.capability.evidence_capabilities,
		fixture.capability.evidence_readiness_score);
	zassert_equal(pqcp_deployment_device_token_replay_ingest_line(&state,
								       line),
		      0);
	(void)snprintk(
		line, sizeof(line),
		"PQCP_DEPLOYMENT_RELEASE_GATE schema=1 profile=product status=PASS errors=0x00000000 warnings=0x00000000 candidates=3 gaps=0 experiments=0 blocking=0 readiness=100 claim_score=94 review_score=100 gate_score=94 top_consistent=1 digest_bound=1 pipeline=PASS budget=PASS experiment_plan=PASS packet=PASS replay=PASS audit=PASS top=mlkem768_m7 trace_digest=%s packet_digest=%s",
		trace_digest, packet_digest);
	zassert_equal(pqcp_deployment_device_token_replay_ingest_line(&state,
								       line),
		      0);
	(void)snprintk(
		line, sizeof(line),
		"PQCP_DEPLOYMENT_DEVICE_TOKEN schema=1 profile=product status=PASS nonce=%s errors=0x00000000 warnings=0x00000000 evidence=0x%08x cap_readiness=100 gate_score=94 gate_status=PASS capability_policy=1 production_allowed=1 native_provider=1 gate_digest_bound=1 top=mlkem768_m7 trace_digest=%s packet_digest=%s token_digest=%s",
		nonce_hex, fixture.token.evidence_capabilities, trace_digest,
		packet_digest, fixture.token.token_digest_hex);
	zassert_equal(pqcp_deployment_device_token_replay_ingest_line(&state,
								       line),
		      0);
	(void)snprintk(
		line, sizeof(line),
		"PQCP_DEPLOYMENT_DEVICE_TOKEN_VERIFY schema=1 status=PASS errors=0x00000000 expected_status=PASS observed_status=PASS expected_digest=%s observed_digest=%s",
		fixture.token.token_digest_hex, fixture.token.token_digest_hex);
	zassert_equal(pqcp_deployment_device_token_replay_ingest_line(&state,
								       line),
		      0);
	zassert_equal(pqcp_deployment_device_token_replay_finish(
			      &state, nonce_hex, &result),
		      0);
	zassert_true(result.passed);
}

ZTEST_SUITE(pqcp_deployment_device_token_replay, NULL, NULL, NULL, NULL,
	    NULL);
