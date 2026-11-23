/*
 * SPDX-License-Identifier: MIT
 *
 * pqcp-evidence-verify - host replay of firmware deployment evidence.
 *
 * Ingests one captured device transcript (QEMU or serial console log),
 * replays the terminal evidence chain markers with the UNMODIFIED firmware
 * verifier translation units, recomputes every digest, and cross-binds the
 * layers (verdict digest into seal, seal digest into passport, passport
 * digest into the adversarial tamper matrix, chain identity into the
 * hash-chained evidence trail). Exit code 0 means the transcript's terminal
 * chain is internally consistent and tamper-free; any parse failure, digest
 * mismatch, or broken binding exits 1.
 *
 * No Zephyr toolchain, no python, no network: a reviewer needs only a C
 * compiler to independently check what a device claimed.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pqcp_zephyr/deployment_assurance_passport_replay.h>
#include <pqcp_zephyr/deployment_evidence_seal_replay.h>
#include <pqcp_zephyr/deployment_evidence_trail_replay.h>
#include <pqcp_zephyr/deployment_evidence_verdict_replay.h>
#include <pqcp_zephyr/deployment_tamper_matrix_replay.h>
#include "host_sha256.h"
#include "receipt_codec.h"
#include "receipt_mldsa_ops.h"
#include "receipt_verify.h"
#include "signature_check.h"

#define LINE_MAX_CHARS 4096U

struct transcript_summary {
	unsigned long total_lines;
	unsigned long verdict_markers;
	unsigned long seal_markers;
	unsigned long passport_markers;
	unsigned long tamper_markers;
	unsigned long trail_markers;
	bool verdict_passed;
	bool seal_passed;
	bool passport_passed;
	bool tamper_passed;
	bool trail_passed;
	bool verdict_seal_bound;
	bool seal_passport_bound;
	bool passport_tamper_bound;
	bool trail_identity_bound;
	bool signature_present;
	bool signature_complete;
	bool signature_digest_bound;
	bool signature_verified;
	/** SHA-256 of the reassembled device public key (when complete). */
	bool device_pk_hashed;
	uint8_t device_pk_hash[32];
	struct pqcp_deployment_evidence_verdict_replay_result verdict;
	struct pqcp_deployment_evidence_seal_replay_result seal;
	struct pqcp_deployment_assurance_passport_replay_result passport;
	struct pqcp_deployment_tamper_matrix_replay_result tamper;
	struct pqcp_deployment_evidence_trail_replay_result trail;
};

/* ------------------------------------------------------------------ */
/* Transcript processing                                                */
/* ------------------------------------------------------------------ */

static void strip_line_endings(char *line)
{
	size_t len = strlen(line);

	while (len > 0U &&
	       (line[len - 1U] == '\n' || line[len - 1U] == '\r')) {
		line[--len] = '\0';
	}
}

static const char *bool_token(bool value)
{
	return value ? "true" : "false";
}

static int process_transcript(FILE *input, bool lenient,
			      bool require_signature,
			      struct transcript_summary *summary)
{
	static char line[LINE_MAX_CHARS];
	struct pqcp_deployment_evidence_verdict_replay_state verdict_state;
	struct pqcp_deployment_evidence_seal_replay_state seal_state;
	static struct pqcp_deployment_assurance_passport_replay_state
		passport_state;
	static struct pqcp_deployment_tamper_matrix_replay_state tamper_state;
	static struct pqcp_deployment_evidence_trail_replay_state trail_state;
	struct signature_capture sig_capture;
	bool layers_ok;
	bool bindings_ok;
	int ret;

	memset(summary, 0, sizeof(*summary));
	if (pqcp_deployment_evidence_verdict_replay_init(&verdict_state) != 0 ||
	    pqcp_deployment_evidence_seal_replay_init(&seal_state) != 0 ||
	    pqcp_deployment_assurance_passport_replay_init(
		    &passport_state) != 0 ||
	    pqcp_deployment_tamper_matrix_replay_init(&tamper_state) != 0 ||
	    pqcp_deployment_evidence_trail_replay_init(&trail_state) != 0) {
		return -EINVAL;
	}
	signature_capture_init(&sig_capture);

	while (fgets(line, sizeof(line), input) != NULL) {
		summary->total_lines++;
		strip_line_endings(line);

		(void)signature_capture_ingest_line(&sig_capture, line);

		/* All replay state machines ignore non-matching lines. */
		(void)pqcp_deployment_evidence_verdict_replay_ingest_line(
			&verdict_state, line);
		(void)pqcp_deployment_evidence_seal_replay_ingest_line(
			&seal_state, line);
		(void)pqcp_deployment_assurance_passport_replay_ingest_line(
			&passport_state, line);
		(void)pqcp_deployment_tamper_matrix_replay_ingest_line(
			&tamper_state, line);
		(void)pqcp_deployment_evidence_trail_replay_ingest_line(
			&trail_state, line);
	}

	summary->verdict_markers = verdict_state.lines_seen;
	summary->seal_markers = seal_state.lines_seen;
	summary->passport_markers = passport_state.lines_seen;
	summary->tamper_markers = tamper_state.lines_seen;
	summary->trail_markers = trail_state.lines_seen;

	ret = pqcp_deployment_evidence_verdict_replay_finish(
		&verdict_state, &summary->verdict);
	summary->verdict_passed = ret == 0 && summary->verdict.passed;

	ret = pqcp_deployment_evidence_seal_replay_finish(
		&seal_state, &summary->seal);
	summary->seal_passed = ret == 0 && summary->seal.passed;

	ret = pqcp_deployment_assurance_passport_replay_finish(
		&passport_state, &summary->passport);
	summary->passport_passed = ret == 0 && summary->passport.passed;

	ret = pqcp_deployment_tamper_matrix_replay_finish(
		&tamper_state, &summary->tamper);
	summary->tamper_passed = ret == 0 && summary->tamper.passed;

	ret = pqcp_deployment_evidence_trail_replay_finish(
		&trail_state, &summary->trail);
	summary->trail_passed = ret == 0 && summary->trail.passed;

	summary->verdict_seal_bound =
		summary->verdict_passed && summary->seal_passed &&
		strcmp(summary->seal.verdict_digest_hex,
		       summary->verdict.computed_digest_hex) == 0;
	summary->seal_passport_bound =
		summary->seal_passed && summary->passport_passed &&
		strcmp(passport_state.passport.seal_digest_hex,
		       summary->seal.computed_digest_hex) == 0;
	summary->passport_tamper_bound =
		summary->passport_passed && summary->tamper_passed &&
		strcmp(summary->tamper.passport_digest_hex,
		       summary->passport.computed_digest_hex) == 0;
	summary->trail_identity_bound =
		summary->verdict_passed && summary->trail_passed &&
		strcmp(summary->trail.top_candidate_id,
		       summary->verdict.top_candidate_id) == 0 &&
		strcmp(summary->trail.nonce_hex,
		       summary->verdict.nonce_hex) == 0;

	summary->signature_present = sig_capture.present;
	summary->signature_complete = signature_capture_complete(&sig_capture);
	if (summary->signature_complete) {
		host_sha256(sig_capture.public_key, SIGNATURE_PK_BYTES,
			    summary->device_pk_hash);
		summary->device_pk_hashed = true;
	}
	if (summary->signature_complete && summary->passport_passed) {
		summary->signature_digest_bound =
			strcmp(sig_capture.passport_digest_hex,
			       summary->passport.computed_digest_hex) == 0;
		summary->signature_verified =
			summary->signature_digest_bound &&
			signature_capture_verify(
				&sig_capture,
				summary->passport.computed_digest_hex) == 0;
	}

	if (require_signature && !summary->signature_present) {
		return -EBADMSG;
	}
	if (summary->signature_present && !summary->signature_verified) {
		return -EBADMSG;
	}

	/* The adversarial tamper matrix and the evidence trail are newer
	 * layers: when present they must verify and bind; older transcripts
	 * without them remain fully verifiable.
	 */
	if (summary->tamper_markers != 0U &&
	    (!summary->tamper_passed ||
	     (summary->passport_markers != 0U &&
	      !summary->passport_tamper_bound))) {
		return -EBADMSG;
	}
	if (summary->trail_markers != 0U &&
	    (!summary->trail_passed ||
	     (summary->verdict_markers != 0U &&
	      !summary->trail_identity_bound))) {
		return -EBADMSG;
	}

	if (lenient) {
		bool any_layer_present = summary->verdict_markers != 0U ||
			summary->seal_markers != 0U ||
			summary->passport_markers != 0U;
		bool verdict_ok = summary->verdict_markers == 0U ||
			summary->verdict_passed;
		bool seal_ok = summary->seal_markers == 0U ||
			summary->seal_passed;
		bool passport_ok = summary->passport_markers == 0U ||
			summary->passport_passed;
		bool binding_ok =
			(summary->verdict_markers == 0U ||
			 summary->seal_markers == 0U ||
			 summary->verdict_seal_bound) &&
			(summary->seal_markers == 0U ||
			 summary->passport_markers == 0U ||
			 summary->seal_passport_bound);

		return (any_layer_present && verdict_ok && seal_ok &&
			passport_ok && binding_ok) ? 0 : -EBADMSG;
	}

	layers_ok = summary->verdict_passed && summary->seal_passed &&
		summary->passport_passed;
	bindings_ok = summary->verdict_seal_bound &&
		summary->seal_passport_bound;

	return (layers_ok && bindings_ok) ? 0 : -EBADMSG;
}

/* ------------------------------------------------------------------ */
/* Reporting                                                            */
/* ------------------------------------------------------------------ */

static void print_summary(FILE *out, const struct transcript_summary *summary,
			  bool chain_ok)
{
	fprintf(out, "pqcp-evidence-verify: %s\n",
		chain_ok ? "CHAIN OK" : "CHAIN BROKEN");
	fprintf(out,
		"  lines=%lu verdict_markers=%lu seal_markers=%lu passport_markers=%lu tamper_markers=%lu trail_markers=%lu\n",
		summary->total_lines, summary->verdict_markers,
		summary->seal_markers, summary->passport_markers,
		summary->tamper_markers, summary->trail_markers);
	fprintf(out, "  verdict_replay=%s error=%s digest=%s\n",
		bool_token(summary->verdict_passed),
		pqcp_deployment_evidence_verdict_replay_error_str(
			summary->verdict.first_error),
		summary->verdict.computed_digest_hex);
	fprintf(out, "  seal_replay=%s error=%s digest=%s\n",
		bool_token(summary->seal_passed),
		pqcp_deployment_evidence_seal_replay_error_str(
			summary->seal.first_error),
		summary->seal.computed_digest_hex);
	fprintf(out, "  passport_replay=%s error=%s digest=%s\n",
		bool_token(summary->passport_passed),
		pqcp_deployment_assurance_passport_replay_error_str(
			summary->passport.first_error),
		summary->passport.computed_digest_hex);
	if (summary->tamper_markers != 0U) {
		fprintf(out,
			"  tamper_matrix_replay=%s error=%s coverage_permille=%u attacks=%u detected=%u digest=%s\n",
			bool_token(summary->tamper_passed),
			pqcp_deployment_tamper_matrix_replay_error_str(
				summary->tamper.first_error),
			summary->tamper.coverage_permille,
			summary->tamper.attack_count,
			summary->tamper.detected_count,
			summary->tamper.computed_digest_hex);
	}
	if (summary->trail_markers != 0U) {
		fprintf(out,
			"  trail_replay=%s error=%s entries=%u head=%s\n",
			bool_token(summary->trail_passed),
			pqcp_deployment_evidence_trail_replay_error_str(
				summary->trail.first_error),
			summary->trail.entry_count,
			summary->trail.computed_head_digest_hex);
	}
	fprintf(out, "  verdict->seal_binding=%s seal->passport_binding=%s\n",
		bool_token(summary->verdict_seal_bound),
		bool_token(summary->seal_passport_bound));
	if (summary->tamper_markers != 0U || summary->trail_markers != 0U) {
		fprintf(out,
			"  passport->tamper_binding=%s trail_identity_binding=%s\n",
			bool_token(summary->passport_tamper_bound),
			bool_token(summary->trail_identity_bound));
	}
	fprintf(out,
		"  signature_present=%s complete=%s digest_bound=%s verified=%s\n",
		bool_token(summary->signature_present),
		bool_token(summary->signature_complete),
		bool_token(summary->signature_digest_bound),
		bool_token(summary->signature_verified));
}

static int write_json(const char *path,
		      const struct transcript_summary *summary,
		      bool chain_ok)
{
	FILE *out = fopen(path, "w");

	if (out == NULL) {
		return -EIO;
	}

	fprintf(out, "{\n");
	fprintf(out, "  \"schema_version\": 2,\n");
	fprintf(out, "  \"chain_ok\": %s,\n", bool_token(chain_ok));
	fprintf(out, "  \"total_lines\": %lu,\n", summary->total_lines);
	fprintf(out, "  \"verdict\": {\"markers\": %lu, \"passed\": %s, \"error\": \"%s\", \"computed_digest\": \"%s\"},\n",
		summary->verdict_markers,
		bool_token(summary->verdict_passed),
		pqcp_deployment_evidence_verdict_replay_error_str(
			summary->verdict.first_error),
		summary->verdict.computed_digest_hex);
	fprintf(out, "  \"seal\": {\"markers\": %lu, \"passed\": %s, \"error\": \"%s\", \"computed_digest\": \"%s\"},\n",
		summary->seal_markers,
		bool_token(summary->seal_passed),
		pqcp_deployment_evidence_seal_replay_error_str(
			summary->seal.first_error),
		summary->seal.computed_digest_hex);
	fprintf(out, "  \"passport\": {\"markers\": %lu, \"passed\": %s, \"error\": \"%s\", \"computed_digest\": \"%s\", \"board\": \"%s\"},\n",
		summary->passport_markers,
		bool_token(summary->passport_passed),
		pqcp_deployment_assurance_passport_replay_error_str(
			summary->passport.first_error),
		summary->passport.computed_digest_hex,
		summary->passport.board);
	fprintf(out, "  \"tamper_matrix\": {\"markers\": %lu, \"passed\": %s, \"error\": \"%s\", \"coverage_permille\": %u, \"attacks\": %u, \"detected\": %u, \"missed\": %u, \"computed_digest\": \"%s\"},\n",
		summary->tamper_markers,
		bool_token(summary->tamper_passed),
		pqcp_deployment_tamper_matrix_replay_error_str(
			summary->tamper.first_error),
		summary->tamper.coverage_permille,
		summary->tamper.attack_count,
		summary->tamper.detected_count,
		summary->tamper.missed_count,
		summary->tamper.computed_digest_hex);
	fprintf(out, "  \"trail\": {\"markers\": %lu, \"passed\": %s, \"error\": \"%s\", \"entries\": %u, \"computed_head\": \"%s\"},\n",
		summary->trail_markers,
		bool_token(summary->trail_passed),
		pqcp_deployment_evidence_trail_replay_error_str(
			summary->trail.first_error),
		summary->trail.entry_count,
		summary->trail.computed_head_digest_hex);
	fprintf(out, "  \"bindings\": {\"verdict_to_seal\": %s, \"seal_to_passport\": %s, \"passport_to_tamper\": %s, \"trail_identity\": %s},\n",
		bool_token(summary->verdict_seal_bound),
		bool_token(summary->seal_passport_bound),
		bool_token(summary->passport_tamper_bound),
		bool_token(summary->trail_identity_bound));
	fprintf(out, "  \"signature\": {\"present\": %s, \"complete\": %s, \"digest_bound\": %s, \"verified\": %s}\n",
		bool_token(summary->signature_present),
		bool_token(summary->signature_complete),
		bool_token(summary->signature_digest_bound),
		bool_token(summary->signature_verified));
	fprintf(out, "}\n");

	return fclose(out) == 0 ? 0 : -EIO;
}

/* ------------------------------------------------------------------ */
/* Transparent appraisal: statement emission, receipt, consistency      */
/* ------------------------------------------------------------------ */

#define PK_FILE_BYTES RECEIPT_MLDSA_PK_BYTES

/* Returns 0 or -EIO. Caller frees *data. */
static int slurp(const char *path, size_t max, uint8_t **data, size_t *length)
{
	FILE *f = fopen(path, "rb");
	long size;
	uint8_t *buf;

	if (f == NULL) {
		return -EIO;
	}
	if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0 ||
	    (unsigned long)size > max || fseek(f, 0, SEEK_SET) != 0) {
		(void)fclose(f);
		return -EIO;
	}
	buf = malloc((size_t)size + 1U);
	if (buf == NULL || fread(buf, 1U, (size_t)size, f) != (size_t)size) {
		free(buf);
		(void)fclose(f);
		return -EIO;
	}
	(void)fclose(f);
	*data = buf;
	*length = (size_t)size;
	return 0;
}

static int hash_file(const char *path, uint8_t digest[32])
{
	struct host_sha256_ctx ctx;
	uint8_t buf[4096];
	FILE *f = fopen(path, "rb");
	size_t n;

	if (f == NULL) {
		return -EIO;
	}
	host_sha256_init(&ctx);
	while ((n = fread(buf, 1U, sizeof(buf), f)) > 0U) {
		host_sha256_update(&ctx, buf, n);
	}
	if (ferror(f)) {
		(void)fclose(f);
		return -EIO;
	}
	(void)fclose(f);
	host_sha256_final(&ctx, digest);
	return 0;
}

static void hex_bytes(const uint8_t *in, size_t length, char *out)
{
	static const char hex[] = "0123456789abcdef";

	for (size_t i = 0U; i < length; ++i) {
		out[2U * i] = hex[in[i] >> 4];
		out[2U * i + 1U] = hex[in[i] & 0x0fU];
	}
	out[2U * length] = '\0';
}

/* Fresh appraisal statement fields derived from the replayed transcript. */
static void build_statement(const struct transcript_summary *summary,
			    bool chain_ok, const uint8_t transcript_sha[32],
			    const uint8_t verifier_sha[32],
			    struct rc_statement *out)
{
	memset(out, 0, sizeof(*out));
	if (summary->passport_passed) {
		(void)snprintf(out->passport_digest_hex,
			       sizeof(out->passport_digest_hex), "%s",
			       summary->passport.computed_digest_hex);
	}
	if (summary->trail_markers != 0U && summary->trail_passed) {
		(void)snprintf(out->trail_head_hex,
			       sizeof(out->trail_head_hex), "%s",
			       summary->trail.computed_head_digest_hex);
	}
	if (summary->device_pk_hashed) {
		out->has_device_pk_hash = true;
		memcpy(out->device_pk_hash, summary->device_pk_hash, 32U);
	}
	(void)snprintf(out->verdict, sizeof(out->verdict), "%s",
		       chain_ok ? RC_VERDICT_OK : RC_VERDICT_REJECT);
	memcpy(out->verifier_sha256, verifier_sha, 32U);
	out->signature_verified = summary->signature_verified;
	memcpy(out->transcript_sha256, transcript_sha, 32U);
}

static int emit_statement(const char *path, const struct rc_statement *s)
{
	uint8_t buf[RC_MAX_STATEMENT_BYTES];
	size_t length = 0U;
	FILE *f;

	if (rc_statement_encode(s, buf, sizeof(buf), &length) != 0) {
		return -EINVAL;
	}
	f = fopen(path, "wb");
	if (f == NULL) {
		return -EIO;
	}
	if (fwrite(buf, 1U, length, f) != length) {
		(void)fclose(f);
		return -EIO;
	}
	return fclose(f) == 0 ? 0 : -EIO;
}

static int load_log_pk(const char *path, uint8_t pk[PK_FILE_BYTES])
{
	uint8_t *data = NULL;
	size_t length = 0U;

	if (slurp(path, PK_FILE_BYTES, &data, &length) != 0) {
		return -EIO;
	}
	if (length != PK_FILE_BYTES) {
		free(data);
		return -EBADMSG;
	}
	memcpy(pk, data, length);
	free(data);
	return 0;
}

static int reject_line(const char *marker, const char *reason)
{
	printf("%s REJECT reason=%s\n", marker, reason);
	return 1;
}

static bool statement_matches(const struct rc_statement *a,
			      const struct rc_statement *b, const char **why)
{
	if (strcmp(a->passport_digest_hex, b->passport_digest_hex) != 0) {
		*why = "passport_digest_mismatch";
	} else if (strcmp(a->trail_head_hex, b->trail_head_hex) != 0) {
		*why = "trail_head_mismatch";
	} else if (memcmp(a->transcript_sha256, b->transcript_sha256, 32U) !=
		   0) {
		*why = "transcript_hash_mismatch";
	} else if (a->has_device_pk_hash != b->has_device_pk_hash ||
		   (a->has_device_pk_hash &&
		    memcmp(a->device_pk_hash, b->device_pk_hash, 32U) != 0)) {
		*why = "device_pk_mismatch";
	} else if (a->signature_verified != b->signature_verified) {
		*why = "signature_flag_mismatch";
	} else if (strcmp(a->verdict, b->verdict) != 0) {
		*why = "verdict_mismatch";
	} else {
		return true;
	}
	return false;
}

/* Receipt verification bound to a fresh replay. Returns 0 PASS, 1 REJECT,
 * 2 I/O error. Always prints exactly one PQCP_APPRAISAL_RECEIPT line.
 */
static int run_receipt(const char *receipt_path, const char *pk_path,
		       const struct transcript_summary *summary,
		       bool chain_ok, const uint8_t transcript_sha[32],
		       const char *verifier_bin)
{
	static const char marker[] = "PQCP_APPRAISAL_RECEIPT";
	uint8_t pk[PK_FILE_BYTES];
	uint8_t leaf_hash[32];
	uint8_t verifier_sha[32] = { 0 };
	struct rc_receipt *receipt = NULL;
	struct rc_statement *fresh = NULL;
	struct rc_statement *claimed = NULL;
	uint8_t *data = NULL;
	size_t length = 0U;
	const char *why = NULL;
	enum rv_reason reason;
	char id_hex[65];
	int ret = 1;
	int rc;

	rc = load_log_pk(pk_path, pk);
	if (rc == -EBADMSG) {
		return reject_line(marker, "log_pk_malformed");
	}
	if (rc != 0) {
		fprintf(stderr, "pqcp-evidence-verify: cannot read %s\n",
			pk_path);
		return 2;
	}
	if (slurp(receipt_path, RC_MAX_RECEIPT_BYTES, &data, &length) != 0) {
		fprintf(stderr, "pqcp-evidence-verify: cannot read %s\n",
			receipt_path);
		return 2;
	}
	receipt = calloc(1U, sizeof(*receipt));
	fresh = calloc(1U, sizeof(*fresh));
	claimed = calloc(1U, sizeof(*claimed));
	if (receipt == NULL || fresh == NULL || claimed == NULL) {
		ret = 2;
		goto out;
	}
	if (rc_receipt_decode(data, length, receipt) != 0) {
		ret = reject_line(marker, "malformed");
		goto out;
	}
	reason = rv_verify_receipt(receipt, pk, leaf_hash);
	if (reason != RV_OK) {
		ret = reject_line(marker, rv_reason_str(reason));
		goto out;
	}
	/* Invariant 4: the statement must match a fresh replay of the
	 * supplied transcript.
	 */
	if (rc_statement_decode(receipt->statement, receipt->statement_length,
				claimed) != 0) {
		ret = reject_line(marker, "statement_malformed");
		goto out;
	}
	if (verifier_bin != NULL) {
		if (hash_file(verifier_bin, verifier_sha) != 0) {
			fprintf(stderr,
				"pqcp-evidence-verify: cannot read %s\n",
				verifier_bin);
			ret = 2;
			goto out;
		}
		if (memcmp(claimed->verifier_sha256, verifier_sha, 32U) != 0) {
			ret = reject_line(marker, "verifier_hash_mismatch");
			goto out;
		}
	} else {
		memcpy(verifier_sha, claimed->verifier_sha256, 32U);
	}
	build_statement(summary, chain_ok, transcript_sha, verifier_sha,
			fresh);
	if (!statement_matches(claimed, fresh, &why)) {
		ret = reject_line(marker, why);
		goto out;
	}
	hex_bytes(receipt->checkpoint.log_id, 32U, id_hex);
	printf("%s PASS leaf_index=%llu tree_size=%llu verdict=%s log_id=%s\n",
	       marker, (unsigned long long)receipt->leaf_index,
	       (unsigned long long)receipt->tree_size, claimed->verdict,
	       id_hex);
	ret = 0;
out:
	free(receipt);
	free(fresh);
	free(claimed);
	free(data);
	return ret;
}

static int run_consistency(const char *path, const char *pk_path)
{
	static const char marker[] = "PQCP_APPRAISAL_CONSISTENCY";
	uint8_t pk[PK_FILE_BYTES];
	struct rc_consistency *c;
	uint8_t *data = NULL;
	size_t length = 0U;
	enum rv_reason reason;
	int rc;
	int ret;

	rc = load_log_pk(pk_path, pk);
	if (rc == -EBADMSG) {
		return reject_line(marker, "log_pk_malformed");
	}
	if (rc != 0) {
		fprintf(stderr, "pqcp-evidence-verify: cannot read %s\n",
			pk_path);
		return 2;
	}
	if (slurp(path, RC_MAX_CONSISTENCY_BYTES, &data, &length) != 0) {
		fprintf(stderr, "pqcp-evidence-verify: cannot read %s\n", path);
		return 2;
	}
	c = calloc(1U, sizeof(*c));
	if (c == NULL) {
		free(data);
		return 2;
	}
	if (rc_consistency_decode(data, length, c) != 0) {
		ret = reject_line(marker, "malformed");
	} else {
		reason = rv_verify_consistency(c, pk);
		if (reason == RV_OK) {
			printf("%s PASS consistency=ok old_size=%llu new_size=%llu\n",
			       marker, (unsigned long long)c->old_size,
			       (unsigned long long)c->new_size);
			ret = 0;
		} else {
			ret = reject_line(marker, rv_reason_str(reason));
		}
	}
	free(c);
	free(data);
	return ret;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s [--lenient] [--require-signature] [--quiet] [--json <path>]\n"
		"          [--verifier-bin <path>] [--emit-statement <path>]\n"
		"          [--receipt <path> --log-pk <path>] <transcript.log>\n"
		"       %s --consistency <path> --log-pk <path>\n"
		"\n"
		"Replays the firmware deployment evidence chain from a captured\n"
		"device transcript using the unmodified firmware verifier code.\n"
		"Exit 0: terminal chain consistent. Exit 1: missing, malformed,\n"
		"tampered, or unbound evidence. Exit 2: usage or I/O error.\n"
		"\n"
		"When adversarial tamper matrix or evidence trail markers are\n"
		"present they must verify and bind in every mode.\n"
		"\n"
		"  --lenient  verify only the layers present instead of\n"
		"             requiring the full verdict+seal+passport chain\n"
		"  --require-signature  fail unless an ML-DSA-65 passport\n"
		"             signature is present and verifies\n"
		"  --quiet    suppress the human-readable summary\n"
		"  --json     also write a machine-readable JSON summary\n"
		"\n"
		"Transparent appraisal (docs/transparent-appraisal-format.md):\n"
		"  --emit-statement <path>  write the appraisal statement (CBOR) for\n"
		"             this transcript; written for REJECT verdicts too, exit\n"
		"             code still reflects the chain verdict\n"
		"  --verifier-bin <path>    binary whose SHA-256 is recorded in the\n"
		"             statement (default argv[0]); with --receipt it is\n"
		"             compared to the statement's recorded verifier hash\n"
		"  --receipt <path>  verify an inclusion receipt against the pinned\n"
		"             --log-pk and bind its statement to a fresh replay of\n"
		"             <transcript.log>. Prints PQCP_APPRAISAL_RECEIPT PASS|REJECT\n"
		"             reason=<token>; exit 0 only on PASS (the chain verdict is\n"
		"             reported in verdict=, not in the exit code)\n"
		"  --consistency <path>  verify an append-only consistency file\n"
		"             (no transcript). Prints PQCP_APPRAISAL_CONSISTENCY\n"
		"             PASS consistency=ok | REJECT reason=<token>\n"
		"  --log-pk   raw 1952-byte ML-DSA-65 log public key (pinned)\n",
		argv0, argv0);
}

int main(int argc, char **argv)
{
	static struct transcript_summary summary;
	const char *transcript_path = NULL;
	const char *json_path = NULL;
	const char *emit_path = NULL;
	const char *verifier_bin = NULL;
	const char *receipt_path = NULL;
	const char *consistency_path = NULL;
	const char *log_pk_path = NULL;
	bool lenient = false;
	bool require_signature = false;
	bool quiet = false;
	bool chain_ok = false;
	uint8_t transcript_sha[32];
	int exit_code = 0;
	FILE *input;
	int ret;

	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--lenient") == 0) {
			lenient = true;
		} else if (strcmp(argv[i], "--require-signature") == 0) {
			require_signature = true;
		} else if (strcmp(argv[i], "--quiet") == 0) {
			quiet = true;
		} else if (strcmp(argv[i], "--json") == 0 && i + 1 < argc) {
			json_path = argv[++i];
		} else if (strcmp(argv[i], "--emit-statement") == 0 &&
			   i + 1 < argc) {
			emit_path = argv[++i];
		} else if (strcmp(argv[i], "--verifier-bin") == 0 &&
			   i + 1 < argc) {
			verifier_bin = argv[++i];
		} else if (strcmp(argv[i], "--receipt") == 0 && i + 1 < argc) {
			receipt_path = argv[++i];
		} else if (strcmp(argv[i], "--consistency") == 0 &&
			   i + 1 < argc) {
			consistency_path = argv[++i];
		} else if (strcmp(argv[i], "--log-pk") == 0 && i + 1 < argc) {
			log_pk_path = argv[++i];
		} else if (strcmp(argv[i], "--help") == 0 ||
			   strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return 0;
		} else if (argv[i][0] == '-') {
			usage(argv[0]);
			return 2;
		} else if (transcript_path == NULL) {
			transcript_path = argv[i];
		} else {
			usage(argv[0]);
			return 2;
		}
	}

	if ((receipt_path != NULL || consistency_path != NULL) &&
	    log_pk_path == NULL) {
		fprintf(stderr,
			"pqcp-evidence-verify: --receipt/--consistency need --log-pk\n");
		return 2;
	}
	if (consistency_path != NULL) {
		if (receipt_path != NULL || emit_path != NULL ||
		    transcript_path != NULL) {
			fprintf(stderr,
				"pqcp-evidence-verify: --consistency takes no transcript, --receipt or --emit-statement\n");
			return 2;
		}
		return run_consistency(consistency_path, log_pk_path);
	}

	if (transcript_path == NULL) {
		usage(argv[0]);
		return 2;
	}

	input = fopen(transcript_path, "r");
	if (input == NULL) {
		fprintf(stderr, "pqcp-evidence-verify: cannot open %s\n",
			transcript_path);
		return 2;
	}

	ret = process_transcript(input, lenient, require_signature,
				 &summary);
	(void)fclose(input);
	if (ret == -EINVAL) {
		fprintf(stderr, "pqcp-evidence-verify: internal init error\n");
		return 2;
	}
	chain_ok = ret == 0;

	if (!quiet) {
		print_summary(stdout, &summary, chain_ok);
	}
	if (json_path != NULL && write_json(json_path, &summary,
					    chain_ok) != 0) {
		fprintf(stderr, "pqcp-evidence-verify: cannot write %s\n",
			json_path);
		return 2;
	}

	if (emit_path != NULL || receipt_path != NULL) {
		if (hash_file(transcript_path, transcript_sha) != 0) {
			fprintf(stderr,
				"pqcp-evidence-verify: cannot hash %s\n",
				transcript_path);
			return 2;
		}
	}
	if (emit_path != NULL) {
		static struct rc_statement statement;
		uint8_t verifier_sha[32];
		const char *bin = verifier_bin != NULL ? verifier_bin :
							 argv[0];

		if (hash_file(bin, verifier_sha) != 0) {
			fprintf(stderr,
				"pqcp-evidence-verify: cannot hash verifier binary %s (use --verifier-bin)\n",
				bin);
			return 2;
		}
		build_statement(&summary, chain_ok, transcript_sha,
				verifier_sha, &statement);
		if (emit_statement(emit_path, &statement) != 0) {
			fprintf(stderr,
				"pqcp-evidence-verify: cannot write %s\n",
				emit_path);
			return 2;
		}
		printf("PQCP_APPRAISAL_STATEMENT written verdict=%s\n",
		       statement.verdict);
	}
	if (receipt_path != NULL) {
		/* The exit code of a receipt run is the receipt verdict. */
		return run_receipt(receipt_path, log_pk_path, &summary,
				   chain_ok, transcript_sha, verifier_bin);
	}

	exit_code = chain_ok ? 0 : 1;
	return exit_code;
}
