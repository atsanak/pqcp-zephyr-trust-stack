/*
 * SPDX-License-Identifier: MIT
 *
 * Tests for firmware-native deployment device evidence packets.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_device_packet.h>

static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char nonce_b[] = "ffeeddccbbaa99887766554433221100";
static const char top_a[] = "hybrid768_65_campaign";
static const char top_b[] = "hybrid1024_87_campaign";
static const char trace_a[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char trace_b[] =
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char packet_a[] =
	"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static const char token_digest_a[] =
	"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
static const char token_digest_b[] =
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

struct fixture {
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_release_gate_report release_gate;
	struct pqcp_deployment_device_token token;
	struct pqcp_deployment_device_token_verification verification;
	struct pqcp_deployment_device_token_replay_result replay;
	struct pqcp_deployment_device_token_audit_report audit;
	struct pqcp_deployment_device_gate_report device_gate;
};

static void set_text(char *dst, size_t dst_size, const char *src)
{
	zassert_not_null(dst);
	zassert_not_null(src);
	zassert_true(dst_size > 0U);
	(void)snprintk(dst, dst_size, "%s", src);
}

static uint32_t full_device_packet_capabilities(void)
{
	return PQCP_CAPABILITY_EVIDENCE_BUILD_MANIFEST |
	       PQCP_CAPABILITY_EVIDENCE_PROVIDER_CONTRACT |
	       PQCP_CAPABILITY_EVIDENCE_FIRMWARE_POLICY |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_RELEASE_GATE |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_TOKEN |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_TOKEN_REPLAY |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_TOKEN_AUDIT |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_GATE |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_PACKET;
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
	capability->evidence_capabilities = full_device_packet_capabilities();
	capability->policy_passed = true;
	capability->production_allowed = true;
	capability->evidence_readiness_score = 100U;
}

static void fill_release_gate(
	struct pqcp_deployment_release_gate_report *release_gate)
{
	memset(release_gate, 0, sizeof(*release_gate));
	release_gate->schema_version = PQCP_DEPLOYMENT_RELEASE_GATE_SCHEMA_VERSION;
	release_gate->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	release_gate->status = PQCP_DEPLOYMENT_RELEASE_GATE_PASS;
	release_gate->candidate_count = 3U;
	release_gate->readiness_score = 100U;
	release_gate->claim_score = 95U;
	release_gate->review_score = 92U;
	release_gate->gate_score = 94U;
	release_gate->top_consistent = true;
	release_gate->digest_bound = true;
	release_gate->pipeline_passed = true;
	release_gate->budget_passed = true;
	release_gate->experiment_plan_passed = true;
	release_gate->packet_passed = true;
	release_gate->replay_passed = true;
	release_gate->audit_passed = true;
	set_text(release_gate->top_candidate_id,
		 sizeof(release_gate->top_candidate_id), top_a);
	set_text(release_gate->trace_digest_hex,
		 sizeof(release_gate->trace_digest_hex), trace_a);
	set_text(release_gate->packet_digest_hex,
		 sizeof(release_gate->packet_digest_hex), packet_a);
}

static void fill_token(struct pqcp_deployment_device_token *token)
{
	memset(token, 0, sizeof(*token));
	token->schema_version = PQCP_DEPLOYMENT_DEVICE_TOKEN_SCHEMA_VERSION;
	token->status = PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS;
	token->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	token->evidence_capabilities = full_device_packet_capabilities();
	token->capability_readiness_score = 100U;
	token->gate_score = 94U;
	token->gate_status = PQCP_DEPLOYMENT_RELEASE_GATE_PASS;
	token->capability_policy_passed = true;
	token->production_allowed = true;
	token->native_provider = true;
	token->gate_digest_bound = true;
	set_text(token->nonce_hex, sizeof(token->nonce_hex), nonce_a);
	set_text(token->top_candidate_id, sizeof(token->top_candidate_id),
		 top_a);
	set_text(token->trace_digest_hex, sizeof(token->trace_digest_hex),
		 trace_a);
	set_text(token->packet_digest_hex, sizeof(token->packet_digest_hex),
		 packet_a);
	set_text(token->token_digest_hex, sizeof(token->token_digest_hex),
		 token_digest_a);
}

static void fill_verification(
	struct pqcp_deployment_device_token_verification *verification)
{
	memset(verification, 0, sizeof(*verification));
	verification->schema_version =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_SCHEMA_VERSION;
	verification->passed = true;
	verification->expected_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS;
	verification->observed_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS;
	set_text(verification->expected_digest_hex,
		 sizeof(verification->expected_digest_hex), token_digest_a);
	set_text(verification->observed_digest_hex,
		 sizeof(verification->observed_digest_hex), token_digest_a);
}

static void fill_replay(
	struct pqcp_deployment_device_token_replay_result *replay)
{
	memset(replay, 0, sizeof(*replay));
	replay->schema_version =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_SCHEMA_VERSION;
	replay->passed = true;
	replay->lines_seen = 4U;
	replay->marker_mask = PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_REQUIRED_MASK;
	replay->first_error = PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_NONE;
	replay->token_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS;
	replay->gate_status = PQCP_DEPLOYMENT_RELEASE_GATE_PASS;
	replay->capability_readiness_score = 100U;
	replay->gate_score = 94U;
	set_text(replay->top_candidate_id, sizeof(replay->top_candidate_id),
		 top_a);
	set_text(replay->nonce_hex, sizeof(replay->nonce_hex), nonce_a);
	set_text(replay->token_digest_hex, sizeof(replay->token_digest_hex),
		 token_digest_a);
	set_text(replay->computed_digest_hex,
		 sizeof(replay->computed_digest_hex), token_digest_a);
}

static void fill_audit(
	struct pqcp_deployment_device_token_audit_report *audit)
{
	memset(audit, 0, sizeof(*audit));
	audit->schema_version =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_SCHEMA_VERSION;
	audit->status = PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS;
	audit->result_count = 1U;
	audit->replay_pass_count = 1U;
	audit->token_pass_count = 1U;
	audit->gate_pass_count = 1U;
	audit->unique_token_digest_count = 1U;
	audit->min_capability_readiness_score = 100U;
	audit->min_gate_score = 94U;
	audit->max_gate_score = 94U;
	audit->avg_gate_score = 94U;
	audit->stable_nonce = true;
	audit->stable_top_candidate = true;
	audit->stable_token_digest = true;
	audit->stable_gate_status = true;
	set_text(audit->nonce_hex, sizeof(audit->nonce_hex), nonce_a);
	set_text(audit->top_candidate_id, sizeof(audit->top_candidate_id),
		 top_a);
	set_text(audit->token_digest_hex, sizeof(audit->token_digest_hex),
		 token_digest_a);
}

static void fill_device_gate(
	struct pqcp_deployment_device_gate_report *device_gate)
{
	memset(device_gate, 0, sizeof(*device_gate));
	device_gate->schema_version = PQCP_DEPLOYMENT_DEVICE_GATE_SCHEMA_VERSION;
	device_gate->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	device_gate->status = PQCP_DEPLOYMENT_DEVICE_GATE_PASS;
	device_gate->evidence_capabilities = full_device_packet_capabilities();
	device_gate->capability_readiness_score = 100U;
	device_gate->release_gate_score = 94U;
	device_gate->audit_min_gate_score = 94U;
	device_gate->release_gate_status = PQCP_DEPLOYMENT_RELEASE_GATE_PASS;
	device_gate->token_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS;
	device_gate->audit_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS;
	device_gate->capability_policy_passed = true;
	device_gate->production_allowed = true;
	device_gate->native_provider = true;
	device_gate->verification_passed = true;
	device_gate->replay_passed = true;
	device_gate->top_consistent = true;
	device_gate->nonce_consistent = true;
	device_gate->token_digest_consistent = true;
	device_gate->release_digest_consistent = true;
	set_text(device_gate->top_candidate_id,
		 sizeof(device_gate->top_candidate_id), top_a);
	set_text(device_gate->nonce_hex, sizeof(device_gate->nonce_hex),
		 nonce_a);
	set_text(device_gate->trace_digest_hex,
		 sizeof(device_gate->trace_digest_hex), trace_a);
	set_text(device_gate->packet_digest_hex,
		 sizeof(device_gate->packet_digest_hex), packet_a);
	set_text(device_gate->token_digest_hex,
		 sizeof(device_gate->token_digest_hex), token_digest_a);
}

static void fill_fixture(struct fixture *fixture)
{
	fill_capability(&fixture->capability);
	fill_release_gate(&fixture->release_gate);
	fill_token(&fixture->token);
	fill_verification(&fixture->verification);
	fill_replay(&fixture->replay);
	fill_audit(&fixture->audit);
	fill_device_gate(&fixture->device_gate);
}

static int build_packet(const struct fixture *fixture,
			char *buffer,
			size_t buffer_size,
			struct pqcp_deployment_device_packet *packet)
{
	return pqcp_deployment_device_packet_build(
		&fixture->capability, &fixture->release_gate, &fixture->token,
		&fixture->verification, &fixture->replay, &fixture->audit,
		&fixture->device_gate, buffer, buffer_size, packet);
}

static void make_consistent_nonce_b(struct fixture *fixture)
{
	set_text(fixture->token.nonce_hex, sizeof(fixture->token.nonce_hex),
		 nonce_b);
	set_text(fixture->replay.nonce_hex, sizeof(fixture->replay.nonce_hex),
		 nonce_b);
	set_text(fixture->audit.nonce_hex, sizeof(fixture->audit.nonce_hex),
		 nonce_b);
	set_text(fixture->device_gate.nonce_hex,
		 sizeof(fixture->device_gate.nonce_hex), nonce_b);
}

ZTEST(pqcp_deployment_device_packet, test_status_tokens_are_stable)
{
	zassert_str_equal(
		pqcp_deployment_device_packet_status_str(
			PQCP_DEPLOYMENT_DEVICE_PACKET_PASS),
		"PASS");
	zassert_str_equal(
		pqcp_deployment_device_packet_status_str(
			PQCP_DEPLOYMENT_DEVICE_PACKET_WARN),
		"WARN");
	zassert_str_equal(
		pqcp_deployment_device_packet_status_str(
			PQCP_DEPLOYMENT_DEVICE_PACKET_FAIL),
		"FAIL");
	zassert_str_equal(pqcp_deployment_device_packet_status_str(42),
			  "UNKNOWN");
}

ZTEST(pqcp_deployment_device_packet, test_clean_packet_passes_and_emits)
{
	struct fixture fixture;
	struct pqcp_deployment_device_packet packet;
	char buffer[4096];

	fill_fixture(&fixture);
	zassert_equal(build_packet(&fixture, buffer, sizeof(buffer), &packet),
		      0);
	zassert_equal(packet.status, PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	zassert_equal(packet.error_mask, 0U);
	zassert_equal(packet.warning_mask, 0U);
	zassert_equal(packet.line_count, 6U);
	zassert_true(packet.byte_count == strlen(buffer));
	zassert_true(packet.device_packet_digest_hex[0] != '\0');
	zassert_equal(pqcp_deployment_device_packet_emit_facts(buffer,
							      &packet),
		      0);
	zassert_equal(pqcp_deployment_device_packet_emit(&packet), 0);
}

ZTEST(pqcp_deployment_device_packet, test_device_gate_fail_blocks_packet)
{
	struct fixture fixture;
	struct pqcp_deployment_device_packet packet;
	char buffer[4096];

	fill_fixture(&fixture);
	fixture.device_gate.status = PQCP_DEPLOYMENT_DEVICE_GATE_FAIL;
	fixture.device_gate.error_mask =
		PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_SCORE_FLOOR;
	zassert_equal(build_packet(&fixture, buffer, sizeof(buffer), &packet),
		      -EBADMSG);
	zassert_equal(packet.status, PQCP_DEPLOYMENT_DEVICE_PACKET_FAIL);
	zassert_true((packet.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_DEVICE_GATE) != 0U);
}

ZTEST(pqcp_deployment_device_packet, test_warning_path_does_not_block)
{
	struct fixture fixture;
	struct pqcp_deployment_device_packet packet;
	char buffer[4096];

	fill_fixture(&fixture);
	fixture.audit.status = PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARN;
	fixture.audit.warning_mask =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_LOW_SAMPLE_COUNT;
	fixture.device_gate.status = PQCP_DEPLOYMENT_DEVICE_GATE_WARN;
	fixture.device_gate.warning_mask =
		PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_AUDIT;
	fixture.device_gate.audit_status =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARN;
	zassert_equal(build_packet(&fixture, buffer, sizeof(buffer), &packet),
		      0);
	zassert_equal(packet.status, PQCP_DEPLOYMENT_DEVICE_PACKET_WARN);
	zassert_equal(packet.error_mask, 0U);
	zassert_true((packet.warning_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_AUDIT) != 0U);
}

ZTEST(pqcp_deployment_device_packet, test_buffer_too_small_fails_overflow)
{
	struct fixture fixture;
	struct pqcp_deployment_device_packet packet;
	char buffer[96];

	fill_fixture(&fixture);
	zassert_equal(build_packet(&fixture, buffer, sizeof(buffer), &packet),
		      -ENOSPC);
	zassert_equal(packet.status, PQCP_DEPLOYMENT_DEVICE_PACKET_FAIL);
	zassert_true((packet.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_OVERFLOW) != 0U);
}

ZTEST(pqcp_deployment_device_packet, test_missing_packet_capability_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_device_packet packet;
	char buffer[4096];

	fill_fixture(&fixture);
	fixture.capability.evidence_capabilities &=
		~PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_PACKET;
	zassert_equal(build_packet(&fixture, buffer, sizeof(buffer), &packet),
		      -EBADMSG);
	zassert_true((packet.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_MISSING_CAPABILITY) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet, test_top_mismatch_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_device_packet packet;
	char buffer[4096];

	fill_fixture(&fixture);
	set_text(fixture.replay.top_candidate_id,
		 sizeof(fixture.replay.top_candidate_id), top_b);
	zassert_equal(build_packet(&fixture, buffer, sizeof(buffer), &packet),
		      -EBADMSG);
	zassert_true((packet.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_TOP_MISMATCH) != 0U);
}

ZTEST(pqcp_deployment_device_packet, test_nonce_mismatch_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_device_packet packet;
	char buffer[4096];

	fill_fixture(&fixture);
	set_text(fixture.audit.nonce_hex, sizeof(fixture.audit.nonce_hex),
		 nonce_b);
	zassert_equal(build_packet(&fixture, buffer, sizeof(buffer), &packet),
		      -EBADMSG);
	zassert_true((packet.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_NONCE_MISMATCH) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet, test_token_digest_mismatch_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_device_packet packet;
	char buffer[4096];

	fill_fixture(&fixture);
	set_text(fixture.verification.observed_digest_hex,
		 sizeof(fixture.verification.observed_digest_hex),
		 token_digest_b);
	zassert_equal(build_packet(&fixture, buffer, sizeof(buffer), &packet),
		      -EBADMSG);
	zassert_true((packet.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_TOKEN_DIGEST) != 0U);
}

ZTEST(pqcp_deployment_device_packet, test_release_digest_mismatch_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_device_packet packet;
	char buffer[4096];

	fill_fixture(&fixture);
	set_text(fixture.token.trace_digest_hex,
		 sizeof(fixture.token.trace_digest_hex), trace_b);
	zassert_equal(build_packet(&fixture, buffer, sizeof(buffer), &packet),
		      -EBADMSG);
	zassert_true((packet.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_RELEASE_DIGEST) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet, test_profile_mismatch_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_device_packet packet;
	char buffer[4096];

	fill_fixture(&fixture);
	fixture.token.profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER;
	zassert_equal(build_packet(&fixture, buffer, sizeof(buffer), &packet),
		      -EBADMSG);
	zassert_true((packet.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_PROFILE_MISMATCH) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet, test_replay_failure_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_device_packet packet;
	char buffer[4096];

	fill_fixture(&fixture);
	fixture.replay.passed = false;
	fixture.device_gate.replay_passed = false;
	zassert_equal(build_packet(&fixture, buffer, sizeof(buffer), &packet),
		      -EBADMSG);
	zassert_true((packet.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_REPLAY) != 0U);
}

ZTEST(pqcp_deployment_device_packet, test_status_mismatch_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_device_packet packet;
	char buffer[4096];

	fill_fixture(&fixture);
	fixture.replay.gate_status = PQCP_DEPLOYMENT_RELEASE_GATE_WARN;
	zassert_equal(build_packet(&fixture, buffer, sizeof(buffer), &packet),
		      -EBADMSG);
	zassert_true((packet.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_STATUS_MISMATCH) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet, test_invalid_schema_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_device_packet packet;
	char buffer[4096];

	fill_fixture(&fixture);
	fixture.release_gate.schema_version = 99U;
	zassert_equal(build_packet(&fixture, buffer, sizeof(buffer), &packet),
		      -EINVAL);
	zassert_equal(packet.status, PQCP_DEPLOYMENT_DEVICE_PACKET_FAIL);
	zassert_true((packet.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_INVALID_INPUT) != 0U);
}

ZTEST(pqcp_deployment_device_packet, test_score_range_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_device_packet packet;
	char buffer[4096];

	fill_fixture(&fixture);
	fixture.capability.evidence_readiness_score = 101U;
	zassert_equal(build_packet(&fixture, buffer, sizeof(buffer), &packet),
		      -EINVAL);
}

ZTEST(pqcp_deployment_device_packet, test_digest_is_stable)
{
	struct fixture fixture_a;
	struct fixture fixture_b;
	struct pqcp_deployment_device_packet packet_a;
	struct pqcp_deployment_device_packet packet_b;
	char buffer_a[4096];
	char buffer_b[4096];

	fill_fixture(&fixture_a);
	fill_fixture(&fixture_b);
	zassert_equal(build_packet(&fixture_a, buffer_a, sizeof(buffer_a),
				   &packet_a),
		      0);
	zassert_equal(build_packet(&fixture_b, buffer_b, sizeof(buffer_b),
				   &packet_b),
		      0);
	zassert_str_equal(packet_a.device_packet_digest_hex,
			  packet_b.device_packet_digest_hex);
	zassert_str_equal(buffer_a, buffer_b);
}

ZTEST(pqcp_deployment_device_packet, test_digest_changes_with_canonical_nonce)
{
	struct fixture fixture_a;
	struct fixture fixture_b;
	struct pqcp_deployment_device_packet packet_a;
	struct pqcp_deployment_device_packet packet_b;
	char buffer_a[4096];
	char buffer_b[4096];

	fill_fixture(&fixture_a);
	fill_fixture(&fixture_b);
	make_consistent_nonce_b(&fixture_b);
	zassert_equal(build_packet(&fixture_a, buffer_a, sizeof(buffer_a),
				   &packet_a),
		      0);
	zassert_equal(build_packet(&fixture_b, buffer_b, sizeof(buffer_b),
				   &packet_b),
		      0);
	zassert_not_equal(strcmp(packet_a.device_packet_digest_hex,
				 packet_b.device_packet_digest_hex),
			  0);
}

ZTEST(pqcp_deployment_device_packet, test_emit_rejects_byte_count_drift)
{
	struct fixture fixture;
	struct pqcp_deployment_device_packet packet;
	char buffer[4096];

	fill_fixture(&fixture);
	zassert_equal(build_packet(&fixture, buffer, sizeof(buffer), &packet),
		      0);
	packet.byte_count++;
	zassert_equal(pqcp_deployment_device_packet_emit_facts(buffer,
							      &packet),
		      -EBADMSG);
}

ZTEST_SUITE(pqcp_deployment_device_packet, NULL, NULL, NULL, NULL, NULL);
