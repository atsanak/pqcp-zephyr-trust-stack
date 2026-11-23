/*
 * SPDX-License-Identifier: MIT
 *
 * Tests for the deployment evidence trail replay verifier.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_evidence_trail_replay.h>

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

static void build_trail(void)
{
	struct pqcp_deployment_evidence_trail_policy policy;

	zassert_equal(pqcp_deployment_evidence_trail_init(
			      &trail,
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      top_a, nonce_a),
		      0);
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
	zassert_equal(pqcp_deployment_evidence_trail_default_policy(&policy),
		      0);
	zassert_equal(pqcp_deployment_evidence_trail_finish(&trail, &policy),
		      0);
}

/* Mirror of the trail entry / head emit layouts for transcript-shaped
 * ingestion tests.
 */
static void render_entry_marker(
	const struct pqcp_deployment_evidence_trail_entry *entry,
	char *out, size_t out_size)
{
	int written = snprintk(
		out, out_size,
		"PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ENTRY schema=%u seq=%u stage=%s digest=%s link=%s",
		entry->schema_version,
		entry->sequence,
		pqcp_deployment_evidence_trail_stage_str(entry->stage),
		entry->digest_hex,
		entry->link_digest_hex);

	zassert_true(written > 0 && (size_t)written < out_size);
}

static void render_head_marker(
	const struct pqcp_deployment_evidence_trail *src,
	char *out, size_t out_size)
{
	int written = snprintk(
		out, out_size,
		"PQCP_DEPLOYMENT_EVIDENCE_TRAIL schema=%u profile=product status=%s errors=0x%08x warnings=0x%08x entries=%u required_stages=0x%02x observed_stages=0x%02x top=%s nonce=%s head_digest=%s",
		src->schema_version,
		pqcp_deployment_evidence_trail_status_str(src->status),
		src->error_mask,
		src->warning_mask,
		src->entry_count,
		src->required_stage_mask,
		src->observed_stage_mask,
		src->top_candidate_id,
		src->nonce_hex,
		src->head_digest_hex);

	zassert_true(written > 0 && (size_t)written < out_size);
}

ZTEST(pqcp_deployment_evidence_trail_replay, test_struct_verify_passes)
{
	struct pqcp_deployment_evidence_trail_replay_result result;

	build_trail();
	zassert_equal(pqcp_deployment_evidence_trail_replay_verify(
			      &trail, entries, trail.entry_count, &result),
		      0);
	zassert_true(result.passed);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_NONE);
	zassert_equal(result.entry_count, 3U);
	zassert_str_equal(result.computed_head_digest_hex,
			  trail.head_digest_hex);
	zassert_equal(pqcp_deployment_evidence_trail_replay_emit_result(
			      &result),
		      0);
}

ZTEST(pqcp_deployment_evidence_trail_replay, test_struct_tampering_is_detected)
{
	struct pqcp_deployment_evidence_trail_replay_result result;

	/* Entry digest tamper breaks its link. */
	build_trail();
	entries[1].digest_hex[0] = entries[1].digest_hex[0] == 'a' ? 'b' : 'a';
	zassert_equal(pqcp_deployment_evidence_trail_replay_verify(
			      &trail, entries, trail.entry_count, &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_LINK_MISMATCH);

	/* Head tamper breaks the head comparison. */
	build_trail();
	trail.head_digest_hex[0] =
		trail.head_digest_hex[0] == '0' ? '1' : '0';
	zassert_equal(pqcp_deployment_evidence_trail_replay_verify(
			      &trail, entries, trail.entry_count, &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_HEAD_MISMATCH);

	/* Reordered entries break the sequence. */
	build_trail();
	{
		struct pqcp_deployment_evidence_trail_entry tmp = entries[0];

		entries[0] = entries[1];
		entries[1] = tmp;
	}
	zassert_equal(pqcp_deployment_evidence_trail_replay_verify(
			      &trail, entries, trail.entry_count, &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_SEQUENCE_GAP);

	/* Removed entry breaks the count. */
	build_trail();
	zassert_equal(pqcp_deployment_evidence_trail_replay_verify(
			      &trail, entries, trail.entry_count - 1U,
			      &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_COUNT_MISMATCH);

	/* Forged stage kind breaks the link recomputation. */
	build_trail();
	entries[2].stage = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_CUSTOM;
	zassert_equal(pqcp_deployment_evidence_trail_replay_verify(
			      &trail, entries, trail.entry_count, &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_LINK_MISMATCH);
}

ZTEST(pqcp_deployment_evidence_trail_replay, test_marker_ingest_round_trips)
{
	static struct pqcp_deployment_evidence_trail_replay_state state;
	struct pqcp_deployment_evidence_trail_replay_result result;
	static char line[512];

	build_trail();

	zassert_equal(pqcp_deployment_evidence_trail_replay_init(&state), 0);
	zassert_equal(pqcp_deployment_evidence_trail_replay_ingest_line(
			      &state, "unrelated line"),
		      0);
	for (uint32_t i = 0U; i < trail.entry_count; ++i) {
		render_entry_marker(&entries[i], line, sizeof(line));
		zassert_equal(
			pqcp_deployment_evidence_trail_replay_ingest_line(
				&state, line),
			0);
	}
	render_head_marker(&trail, line, sizeof(line));
	zassert_equal(pqcp_deployment_evidence_trail_replay_ingest_line(
			      &state, line),
		      0);
	zassert_equal(pqcp_deployment_evidence_trail_replay_finish(&state,
								   &result),
		      0);
	zassert_true(result.passed);
	zassert_equal(result.entry_count, 3U);
	zassert_str_equal(result.computed_head_digest_hex,
			  trail.head_digest_hex);
	zassert_str_equal(result.top_candidate_id, top_a);
	zassert_str_equal(result.nonce_hex, nonce_a);
}

ZTEST(pqcp_deployment_evidence_trail_replay, test_marker_ingest_negative_paths)
{
	static struct pqcp_deployment_evidence_trail_replay_state state;
	struct pqcp_deployment_evidence_trail_replay_result result;
	static char line[512];

	build_trail();

	/* Entry after head. */
	zassert_equal(pqcp_deployment_evidence_trail_replay_init(&state), 0);
	render_head_marker(&trail, line, sizeof(line));
	zassert_equal(pqcp_deployment_evidence_trail_replay_ingest_line(
			      &state, line),
		      0);
	render_entry_marker(&entries[0], line, sizeof(line));
	zassert_equal(pqcp_deployment_evidence_trail_replay_ingest_line(
			      &state, line),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_replay_finish(&state,
								   &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_ENTRY_AFTER_HEAD);

	/* Duplicate head. */
	zassert_equal(pqcp_deployment_evidence_trail_replay_init(&state), 0);
	render_entry_marker(&entries[0], line, sizeof(line));
	zassert_equal(pqcp_deployment_evidence_trail_replay_ingest_line(
			      &state, line),
		      0);
	render_head_marker(&trail, line, sizeof(line));
	zassert_equal(pqcp_deployment_evidence_trail_replay_ingest_line(
			      &state, line),
		      0);
	zassert_equal(pqcp_deployment_evidence_trail_replay_ingest_line(
			      &state, line),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_replay_finish(&state,
								   &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_DUPLICATE_MARKER);

	/* Sequence gap at ingest time (skipping entry 0). */
	zassert_equal(pqcp_deployment_evidence_trail_replay_init(&state), 0);
	render_entry_marker(&entries[1], line, sizeof(line));
	zassert_equal(pqcp_deployment_evidence_trail_replay_ingest_line(
			      &state, line),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_replay_finish(&state,
								   &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_SEQUENCE_GAP);

	/* Missing head. */
	zassert_equal(pqcp_deployment_evidence_trail_replay_init(&state), 0);
	render_entry_marker(&entries[0], line, sizeof(line));
	zassert_equal(pqcp_deployment_evidence_trail_replay_ingest_line(
			      &state, line),
		      0);
	zassert_equal(pqcp_deployment_evidence_trail_replay_finish(&state,
								   &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_MISSING_REQUIRED);

	/* Malformed entry marker. */
	zassert_equal(pqcp_deployment_evidence_trail_replay_init(&state), 0);
	zassert_equal(pqcp_deployment_evidence_trail_replay_ingest_line(
			      &state,
			      "PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ENTRY schema=1 seq=0 stage=warp digest=00 link=00"),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_replay_finish(&state,
								   &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_MALFORMED_FIELD);
}

ZTEST(pqcp_deployment_evidence_trail_replay, test_invalid_arguments)
{
	struct pqcp_deployment_evidence_trail_replay_result result;

	build_trail();
	zassert_equal(pqcp_deployment_evidence_trail_replay_verify(
			      NULL, entries, trail.entry_count, &result),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_replay_verify(
			      &trail, NULL, trail.entry_count, &result),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_replay_verify(
			      &trail, entries, trail.entry_count, NULL),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_replay_verify(
			      &trail, entries,
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES + 1U,
			      &result),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_replay_init(NULL),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_replay_ingest_line(
			      NULL, "x"),
		      -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_evidence_trail_replay, NULL, NULL, NULL, NULL,
	    NULL);
