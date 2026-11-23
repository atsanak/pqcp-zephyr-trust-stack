/*
 * SPDX-License-Identifier: MIT
 *
 * Tests for firmware-native deployment device-packet replay verification.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_device_packet_replay.h>

static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char top_a[] = "hybrid768_65_campaign";
static const char trace_a[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char packet_a[] =
	"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static const char token_digest_a[] =
	"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

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

static uint32_t full_device_packet_replay_capabilities(void)
{
	return PQCP_CAPABILITY_EVIDENCE_BUILD_MANIFEST |
	       PQCP_CAPABILITY_EVIDENCE_PROVIDER_CONTRACT |
	       PQCP_CAPABILITY_EVIDENCE_FIRMWARE_POLICY |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_RELEASE_GATE |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_TOKEN |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_TOKEN_REPLAY |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_TOKEN_AUDIT |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_GATE |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_PACKET |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_PACKET_REPLAY;
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
	capability->evidence_capabilities =
		full_device_packet_replay_capabilities();
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
	token->evidence_capabilities = full_device_packet_replay_capabilities();
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
	device_gate->evidence_capabilities =
		full_device_packet_replay_capabilities();
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

static void build_clean_packet(
	struct pqcp_deployment_device_packet *packet,
	char *buffer,
	size_t buffer_size)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	zassert_equal(pqcp_deployment_device_packet_build(
			      &fixture.capability, &fixture.release_gate,
			      &fixture.token, &fixture.verification,
			      &fixture.replay, &fixture.audit,
			      &fixture.device_gate, buffer, buffer_size, packet),
		      0);
}

static void first_line(const char *buffer, char *line, size_t line_size)
{
	const char *end = strchr(buffer, '\n');
	size_t len;

	zassert_not_null(end);
	len = (size_t)(end - buffer);
	zassert_true(len < line_size);
	memcpy(line, buffer, len);
	line[len] = '\0';
}

static void mutate_first_char_after(char *buffer, const char *needle)
{
	char *p = strstr(buffer, needle);

	zassert_not_null(p);
	p += strlen(needle);
	zassert_true(*p != '\0');
	*p = *p == 'x' ? 'y' : 'x';
}

static void mutate_first_hex_after(char *buffer, const char *needle)
{
	char *p = strstr(buffer, needle);

	zassert_not_null(p);
	p += strlen(needle);
	zassert_true(*p != '\0');
	*p = *p == '0' ? '1' : '0';
}

ZTEST(pqcp_deployment_device_packet_replay, test_error_tokens_are_stable)
{
	zassert_str_equal(
		pqcp_deployment_device_packet_replay_error_str(
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_NONE),
		"none");
	zassert_str_equal(
		pqcp_deployment_device_packet_replay_error_str(
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_DIGEST_MISMATCH),
		"digest_mismatch");
	zassert_str_equal(
		pqcp_deployment_device_packet_replay_error_str(
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_CAPABILITY_MISMATCH),
		"capability_mismatch");
	zassert_str_equal(
		pqcp_deployment_device_packet_replay_error_str(42),
		"unknown");
}

ZTEST(pqcp_deployment_device_packet_replay, test_clean_packet_replays)
{
	struct pqcp_deployment_device_packet packet;
	struct pqcp_deployment_device_packet_replay_result result;
	char buffer[4096];

	build_clean_packet(&packet, buffer, sizeof(buffer));
	zassert_equal(pqcp_deployment_device_packet_replay_verify_packet(
			      buffer, &packet, &result),
		      0);
	zassert_true(result.passed);
	zassert_equal(result.marker_mask,
		      PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_REQUIRED_MASK);
	zassert_equal(result.fact_lines, 6U);
	zassert_str_equal(result.top_candidate_id, top_a);
	zassert_str_equal(result.nonce_hex, nonce_a);
	zassert_str_equal(result.computed_digest_hex,
			  packet.device_packet_digest_hex);
	zassert_equal(pqcp_deployment_device_packet_replay_emit_result(
			      &result),
		      0);
}

ZTEST(pqcp_deployment_device_packet_replay, test_duplicate_fact_fails)
{
	struct pqcp_deployment_device_packet packet;
	struct pqcp_deployment_device_packet_replay_state state;
	char buffer[4096];
	char line[1024];

	build_clean_packet(&packet, buffer, sizeof(buffer));
	first_line(buffer, line, sizeof(line));
	zassert_equal(pqcp_deployment_device_packet_replay_init(&state), 0);
	zassert_equal(pqcp_deployment_device_packet_replay_ingest_line(
			      &state, line),
		      0);
	zassert_equal(pqcp_deployment_device_packet_replay_ingest_line(
			      &state, line),
		      -EBADMSG);
	zassert_equal(
		state.first_error,
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_DUPLICATE_MARKER);
}

ZTEST(pqcp_deployment_device_packet_replay, test_missing_packet_marker_fails)
{
	struct pqcp_deployment_device_packet packet;
	struct pqcp_deployment_device_packet_replay_state state;
	struct pqcp_deployment_device_packet_replay_result result;
	char buffer[4096];
	char line[1024];
	const char *line_start;

	build_clean_packet(&packet, buffer, sizeof(buffer));
	zassert_equal(pqcp_deployment_device_packet_replay_init(&state), 0);
	line_start = buffer;
	while (*line_start != '\0') {
		const char *line_end = strchr(line_start, '\n');
		size_t len = line_end == NULL ? strlen(line_start) :
						(size_t)(line_end - line_start);

		if (len != 0U) {
			zassert_true(len < sizeof(line));
			memcpy(line, line_start, len);
			line[len] = '\0';
			zassert_equal(
				pqcp_deployment_device_packet_replay_ingest_line(
					&state, line),
				0);
		}
		if (line_end == NULL) {
			break;
		}
		line_start = line_end + 1U;
	}
	zassert_equal(pqcp_deployment_device_packet_replay_finish(
			      &state, &result),
		      -EBADMSG);
	zassert_equal(
		result.first_error,
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_MISSING_REQUIRED);
}

ZTEST(pqcp_deployment_device_packet_replay, test_digest_tamper_fails)
{
	struct pqcp_deployment_device_packet packet;
	struct pqcp_deployment_device_packet_replay_result result;
	char buffer[4096];

	build_clean_packet(&packet, buffer, sizeof(buffer));
	packet.device_packet_digest_hex[0] =
		packet.device_packet_digest_hex[0] == '0' ? '1' : '0';
	zassert_equal(pqcp_deployment_device_packet_replay_verify_packet(
			      buffer, &packet, &result),
		      -EBADMSG);
	zassert_equal(
		result.first_error,
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_DIGEST_MISMATCH);
}

ZTEST(pqcp_deployment_device_packet_replay, test_byte_count_tamper_fails)
{
	struct pqcp_deployment_device_packet packet;
	struct pqcp_deployment_device_packet_replay_result result;
	char buffer[4096];

	build_clean_packet(&packet, buffer, sizeof(buffer));
	packet.byte_count++;
	zassert_equal(pqcp_deployment_device_packet_replay_verify_packet(
			      buffer, &packet, &result),
		      -EBADMSG);
	zassert_equal(
		result.first_error,
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_BYTE_COUNT_MISMATCH);
}

ZTEST(pqcp_deployment_device_packet_replay, test_line_count_tamper_fails)
{
	struct pqcp_deployment_device_packet packet;
	struct pqcp_deployment_device_packet_replay_result result;
	char buffer[4096];

	build_clean_packet(&packet, buffer, sizeof(buffer));
	packet.line_count++;
	zassert_equal(pqcp_deployment_device_packet_replay_verify_packet(
			      buffer, &packet, &result),
		      -EBADMSG);
	zassert_equal(
		result.first_error,
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_LINE_COUNT_MISMATCH);
}

ZTEST(pqcp_deployment_device_packet_replay, test_top_tamper_fails)
{
	struct pqcp_deployment_device_packet packet;
	struct pqcp_deployment_device_packet_replay_result result;
	char buffer[4096];

	build_clean_packet(&packet, buffer, sizeof(buffer));
	mutate_first_char_after(buffer, "top=");
	zassert_equal(pqcp_deployment_device_packet_replay_verify_packet(
			      buffer, &packet, &result),
		      -EBADMSG);
	zassert_equal(
		result.first_error,
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOP_MISMATCH);
}

ZTEST(pqcp_deployment_device_packet_replay, test_nonce_tamper_fails)
{
	struct pqcp_deployment_device_packet packet;
	struct pqcp_deployment_device_packet_replay_result result;
	char buffer[4096];

	build_clean_packet(&packet, buffer, sizeof(buffer));
	mutate_first_hex_after(buffer, "nonce=");
	zassert_equal(pqcp_deployment_device_packet_replay_verify_packet(
			      buffer, &packet, &result),
		      -EBADMSG);
	zassert_equal(
		result.first_error,
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_NONCE_MISMATCH);
}

ZTEST(pqcp_deployment_device_packet_replay, test_token_digest_tamper_fails)
{
	struct pqcp_deployment_device_packet packet;
	struct pqcp_deployment_device_packet_replay_result result;
	char buffer[4096];

	build_clean_packet(&packet, buffer, sizeof(buffer));
	mutate_first_hex_after(buffer, "token_digest=");
	zassert_equal(pqcp_deployment_device_packet_replay_verify_packet(
			      buffer, &packet, &result),
		      -EBADMSG);
	zassert_equal(
		result.first_error,
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOKEN_DIGEST_MISMATCH);
}

ZTEST(pqcp_deployment_device_packet_replay, test_status_tamper_fails)
{
	struct pqcp_deployment_device_packet packet;
	struct pqcp_deployment_device_packet_replay_result result;
	char buffer[4096];

	build_clean_packet(&packet, buffer, sizeof(buffer));
	packet.error_mask = PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_DEVICE_GATE;
	packet.status = PQCP_DEPLOYMENT_DEVICE_PACKET_PASS;
	zassert_equal(pqcp_deployment_device_packet_replay_verify_packet(
			      buffer, &packet, &result),
		      -EBADMSG);
	zassert_equal(
		result.first_error,
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_STATUS_MISMATCH);
}

ZTEST(pqcp_deployment_device_packet_replay, test_evidence_tamper_fails)
{
	struct pqcp_deployment_device_packet packet;
	struct pqcp_deployment_device_packet_replay_result result;
	char buffer[4096];

	build_clean_packet(&packet, buffer, sizeof(buffer));
	packet.evidence_capabilities ^=
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_PACKET_REPLAY;
	zassert_equal(pqcp_deployment_device_packet_replay_verify_packet(
			      buffer, &packet, &result),
		      -EBADMSG);
	zassert_equal(
		result.first_error,
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_CAPABILITY_MISMATCH);
}

ZTEST(pqcp_deployment_device_packet_replay, test_unknown_marker_fails)
{
	struct pqcp_deployment_device_packet_replay_state state;

	zassert_equal(pqcp_deployment_device_packet_replay_init(&state), 0);
	zassert_equal(pqcp_deployment_device_packet_replay_ingest_line(
			      &state, "PQCP_DEPLOYMENT_UNKNOWN schema=1"),
		      -EBADMSG);
	zassert_equal(
		state.first_error,
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_UNKNOWN_MARKER);
}

ZTEST_SUITE(pqcp_deployment_device_packet_replay, NULL, NULL, NULL, NULL,
	    NULL);
