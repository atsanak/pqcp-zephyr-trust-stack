/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tests for the ML-DSA-signed deployment assurance passport.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_assurance_passport_replay.h>
#include <pqcp_zephyr/deployment_passport_signature.h>
#include <pqcp_zephyr/rng.h>

static const char top_a[] = "hybrid768_65_campaign";
static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char seal_digest_a[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char audit_digest_a[] =
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct fixture {
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_evidence_seal seal;
	struct pqcp_deployment_evidence_seal_replay_result seal_replay;
	struct pqcp_deployment_evidence_seal_audit_report seal_audit;
	struct pqcp_deployment_assurance_passport_policy policy;
	struct pqcp_deployment_assurance_passport passport;
};

static struct fixture fixture;
static struct pqcp_deployment_passport_signing_state signing_state;
static struct pqcp_deployment_passport_signature signature;

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
	capability->rng_mode = "deterministic_test";
	capability->provider_summary = PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE;
	capability->backend_selector = "auto";
	capability->evidence_capabilities = full_caps();
	capability->policy_passed = true;
	capability->production_allowed = true;
	capability->evidence_readiness_score = 96U;
}

static void fill_seal(struct pqcp_deployment_evidence_seal *seal)
{
	memset(seal, 0, sizeof(*seal));
	seal->schema_version = PQCP_DEPLOYMENT_EVIDENCE_SEAL_SCHEMA_VERSION;
	seal->status = PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS;
	seal->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	seal->seal_score = 87U;
	seal->min_terminal_score = 87U;
	seal->verdict_status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS;
	seal->audit_status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_PASS;
	seal->audited_result_count = 1U;
	seal->chain_stage_count = 16U;
	seal->chain_consistency_checks = 7U;
	seal->evidence_capabilities_all = full_caps();
	seal->evidence_capabilities_any = full_caps();
	seal->replay_passed = true;
	seal->top_consistent = true;
	seal->nonce_consistent = true;
	seal->verdict_digest_consistent = true;
	seal->profile_consistent = true;
	seal->status_consistent = true;
	set_text(seal->top_candidate_id, sizeof(seal->top_candidate_id),
		 top_a);
	set_text(seal->nonce_hex, sizeof(seal->nonce_hex), nonce_a);
	set_text(seal->verdict_digest_hex, sizeof(seal->verdict_digest_hex),
		 seal_digest_a);
	set_text(seal->audit_digest_hex, sizeof(seal->audit_digest_hex),
		 audit_digest_a);
	set_text(seal->seal_digest_hex, sizeof(seal->seal_digest_hex),
		 seal_digest_a);
}

static void fill_seal_replay(
	struct pqcp_deployment_evidence_seal_replay_result *replay)
{
	memset(replay, 0, sizeof(*replay));
	replay->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_SCHEMA_VERSION;
	replay->lines_seen = 1U;
	replay->marker_mask =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_REQUIRED_MASK;
	replay->first_error =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_NONE;
	replay->seal_status = PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS;
	replay->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	replay->seal_score = 87U;
	replay->min_terminal_score = 87U;
	replay->verdict_status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS;
	replay->audit_status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_PASS;
	replay->sealed_replay_passed = true;
	replay->audited_result_count = 1U;
	replay->chain_stage_count = 16U;
	replay->chain_consistency_checks = 7U;
	replay->evidence_capabilities_all = full_caps();
	replay->evidence_capabilities_any = full_caps();
	replay->passed = true;
	set_text(replay->top_candidate_id, sizeof(replay->top_candidate_id),
		 top_a);
	set_text(replay->nonce_hex, sizeof(replay->nonce_hex), nonce_a);
	set_text(replay->verdict_digest_hex,
		 sizeof(replay->verdict_digest_hex), seal_digest_a);
	set_text(replay->audit_digest_hex, sizeof(replay->audit_digest_hex),
		 audit_digest_a);
	set_text(replay->computed_digest_hex,
		 sizeof(replay->computed_digest_hex), seal_digest_a);
}

static void fill_seal_audit(
	struct pqcp_deployment_evidence_seal_audit_report *audit)
{
	memset(audit, 0, sizeof(*audit));
	audit->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_SCHEMA_VERSION;
	audit->status = PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_PASS;
	audit->result_count = 1U;
	audit->replay_pass_count = 1U;
	audit->seal_pass_count = 1U;
	audit->unique_seal_digest_count = 1U;
	audit->min_seal_score = 87U;
	audit->max_seal_score = 87U;
	audit->avg_seal_score = 87U;
	audit->min_terminal_score = 87U;
	audit->max_terminal_score = 87U;
	audit->avg_terminal_score = 87U;
	audit->evidence_capabilities_all = full_caps();
	audit->evidence_capabilities_any = full_caps();
	audit->stable_top_candidate = true;
	audit->stable_nonce = true;
	audit->stable_seal_digest = true;
	audit->stable_capabilities = true;
	audit->stable_seal_status = true;
	audit->stable_profile = true;
	audit->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	set_text(audit->top_candidate_id, sizeof(audit->top_candidate_id),
		 top_a);
	set_text(audit->nonce_hex, sizeof(audit->nonce_hex), nonce_a);
	set_text(audit->seal_digest_hex, sizeof(audit->seal_digest_hex),
		 seal_digest_a);
	set_text(audit->audit_digest_hex, sizeof(audit->audit_digest_hex),
		 audit_digest_a);
}

static void build_passport(struct fixture *fx)
{
	memset(fx, 0, sizeof(*fx));
	fill_capability(&fx->capability);
	fill_seal(&fx->seal);
	fill_seal_replay(&fx->seal_replay);
	fill_seal_audit(&fx->seal_audit);
	zassert_equal(pqcp_deployment_assurance_passport_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &fx->policy),
		      0);
	zassert_equal(pqcp_deployment_assurance_passport_run(
			      &fx->capability, &fx->seal, &fx->seal_replay,
			      &fx->seal_audit, &fx->policy, &fx->passport),
		      0);
	zassert_equal(fx->passport.status,
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS);
}

static bool buffer_is_zero(const uint8_t *buffer, size_t size)
{
	for (size_t i = 0U; i < size; ++i) {
		if (buffer[i] != 0U) {
			return false;
		}
	}

	return true;
}

ZTEST(pqcp_deployment_passport_signature, test_sign_verify_roundtrip)
{
	build_passport(&fixture);
	zassert_equal(pqcp_deployment_passport_signature_create(
			      &fixture.passport, &signing_state, &signature),
		      0);
	zassert_equal(signature.schema_version,
		      PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_SCHEMA_VERSION);
	zassert_equal(signature.mldsa_level, 65U);
	zassert_equal(signature.public_key_bytes, PQCP_MLDSA_65_PK_SIZE);
	zassert_equal(signature.signature_bytes, PQCP_MLDSA_65_SIG_SIZE);
	zassert_false(signature.boot_post_gated);
	zassert_str_equal(signature.passport_digest_hex,
			  fixture.passport.passport_digest_hex);
	zassert_false(buffer_is_zero(signature.public_key,
				     sizeof(signature.public_key)));
	zassert_false(buffer_is_zero(signature.signature,
				     sizeof(signature.signature)));
	zassert_equal(pqcp_deployment_passport_signature_verify(
			      &fixture.passport, &signature),
		      0);
}

ZTEST(pqcp_deployment_passport_signature, test_secret_key_is_zeroized)
{
	build_passport(&fixture);
	zassert_equal(pqcp_deployment_passport_signature_create(
			      &fixture.passport, &signing_state, &signature),
		      0);
	zassert_true(buffer_is_zero(signing_state.secret_key,
				    sizeof(signing_state.secret_key)));
}

ZTEST(pqcp_deployment_passport_signature, test_tampered_passport_rejected)
{
	build_passport(&fixture);
	zassert_equal(pqcp_deployment_passport_signature_create(
			      &fixture.passport, &signing_state, &signature),
		      0);

	/* Different passport content -> different digest -> rejected. */
	fixture.capability.board = "nucleo_h743zi";
	zassert_equal(pqcp_deployment_assurance_passport_run(
			      &fixture.capability, &fixture.seal,
			      &fixture.seal_replay, &fixture.seal_audit,
			      &fixture.policy, &fixture.passport),
		      0);
	zassert_equal(pqcp_deployment_passport_signature_verify(
			      &fixture.passport, &signature),
		      -EBADMSG);
}

ZTEST(pqcp_deployment_passport_signature, test_tampered_signature_rejected)
{
	build_passport(&fixture);
	zassert_equal(pqcp_deployment_passport_signature_create(
			      &fixture.passport, &signing_state, &signature),
		      0);
	signature.signature[0] ^= 0x01U;
	zassert_equal(pqcp_deployment_passport_signature_verify(
			      &fixture.passport, &signature),
		      -EBADMSG);
	signature.signature[0] ^= 0x01U;
	zassert_equal(pqcp_deployment_passport_signature_verify(
			      &fixture.passport, &signature),
		      0);
}

ZTEST(pqcp_deployment_passport_signature, test_tampered_public_key_rejected)
{
	build_passport(&fixture);
	zassert_equal(pqcp_deployment_passport_signature_create(
			      &fixture.passport, &signing_state, &signature),
		      0);
	signature.public_key[10] ^= 0x80U;
	zassert_equal(pqcp_deployment_passport_signature_verify(
			      &fixture.passport, &signature),
		      -EBADMSG);
}

ZTEST(pqcp_deployment_passport_signature, test_emit_produces_chunked_markers)
{
	build_passport(&fixture);
	zassert_equal(pqcp_deployment_passport_signature_create(
			      &fixture.passport, &signing_state, &signature),
		      0);
	zassert_equal(PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_PK_CHUNKS, 16U);
	zassert_equal(PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_SIG_CHUNKS, 26U);
	zassert_equal(pqcp_deployment_passport_signature_emit(&signature), 0);
}

ZTEST(pqcp_deployment_passport_signature, test_invalid_inputs_rejected)
{
	build_passport(&fixture);
	zassert_equal(pqcp_deployment_passport_signature_create(
			      NULL, &signing_state, &signature),
		      -EINVAL);
	zassert_equal(pqcp_deployment_passport_signature_create(
			      &fixture.passport, NULL, &signature),
		      -EINVAL);
	zassert_equal(pqcp_deployment_passport_signature_create(
			      &fixture.passport, &signing_state, NULL),
		      -EINVAL);

	zassert_equal(pqcp_deployment_passport_signature_create(
			      &fixture.passport, &signing_state, &signature),
		      0);
	zassert_equal(pqcp_deployment_passport_signature_verify(
			      NULL, &signature),
		      -EINVAL);
	zassert_equal(pqcp_deployment_passport_signature_verify(
			      &fixture.passport, NULL),
		      -EINVAL);
	zassert_equal(pqcp_deployment_passport_signature_emit(NULL), -EINVAL);

	signature.schema_version = 99U;
	zassert_equal(pqcp_deployment_passport_signature_verify(
			      &fixture.passport, &signature),
		      -EINVAL);
	zassert_equal(pqcp_deployment_passport_signature_emit(&signature),
		      -EINVAL);
}

static void *suite_setup(void)
{
	static const uint8_t seed[32] = {
		0x50, 0x51, 0x43, 0x50, 0x2d, 0x50, 0x41, 0x53,
		0x53, 0x50, 0x4f, 0x52, 0x54, 0x2d, 0x53, 0x49,
		0x47, 0x2d, 0x54, 0x45, 0x53, 0x54, 0x2d, 0x53,
		0x45, 0x45, 0x44, 0x2d, 0x30, 0x30, 0x30, 0x31,
	};

	zassert_equal(pqcp_rng_deterministic_seed(seed, sizeof(seed)),
		      PQCP_RNG_SUCCESS);
	return NULL;
}

ZTEST_SUITE(pqcp_deployment_passport_signature, NULL, suite_setup, NULL, NULL,
	    NULL);
