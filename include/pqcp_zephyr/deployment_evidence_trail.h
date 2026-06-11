/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Hash-chained deployment evidence trail
 *
 * Stability: experimental evidence API. The terminal evidence chain binds
 * stages to each other through embedded digests, but nothing commits to the
 * ORDER and COMPLETENESS of the terminal artifacts as a sequence. This
 * module adds an append-only, hash-chained commitment: every terminal stage
 * digest (verdict, seal, seal audit, passport, tamper matrix) is appended as
 * a sequenced entry whose link digest covers the previous link, so removing,
 * reordering, or splicing entries breaks the chain head. The trail is
 * forward-integrity evidence in the audit-log sense, scoped to one boot. It
 * performs no cryptographic operation beyond the project's evidence digest
 * and uses no dynamic allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_TRAIL_H_
#define PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_TRAIL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_device_token.h>
#include <pqcp_zephyr/deployment_release_gate.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment evidence trail reports and markers. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_SCHEMA_VERSION 1U

/** Maximum entries one evidence trail can carry. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES 12U

/** Hex characters in an evidence trail digest. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS 64U

/** Terminal stage kinds committed by the evidence trail. */
enum pqcp_deployment_evidence_trail_stage {
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_VERDICT = 0,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_SEAL,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_SEAL_AUDIT,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_PASSPORT,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_TAMPER_MATRIX,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_CUSTOM,
};

/** Number of evidence trail stage kinds known by this API version. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_COUNT 6U

/** Stage occurrence bit for one trail stage kind. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_BIT(stage) (1U << (uint32_t)(stage))

/** All stage occurrence bits known by this API version. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_KNOWN_MASK \
	((1U << PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_COUNT) - 1U)

/** Required pointer, schema, or policy input was invalid. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_INVALID_INPUT (1U << 0)
/** The trail carries no entries. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_NO_ENTRIES    (1U << 1)
/** Fewer entries than the policy minimum were appended. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_MIN_ENTRIES   (1U << 2)
/** A policy-required stage kind never appeared in the trail. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_MISSING_STAGE (1U << 3)

/** All deployment evidence trail error bits known by this API version. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_NO_ENTRIES | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_MIN_ENTRIES | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_MISSING_STAGE)

/** Entry count is low but not blocking under the active policy. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARNING_LOW_ENTRY_COUNT (1U << 0)
/** The trail carries at least one custom (non-terminal) stage kind. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARNING_CUSTOM_STAGE    (1U << 1)

/** All deployment evidence trail warning bits known by this API version. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARNING_LOW_ENTRY_COUNT | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARNING_CUSTOM_STAGE)

/** Overall deployment evidence trail status. */
enum pqcp_deployment_evidence_trail_status {
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_FAIL = 0,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARN,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_PASS,
};

/** One sequenced, hash-linked evidence trail entry. */
struct pqcp_deployment_evidence_trail_entry {
	/** Entry schema version. */
	uint32_t schema_version;
	/** Zero-based append sequence number. */
	uint32_t sequence;
	/** Stage kind committed by this entry. */
	enum pqcp_deployment_evidence_trail_stage stage;
	/** Stage digest committed by this entry. */
	char digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U];
	/** Link digest covering this entry and every previous link. */
	char link_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U];
};

/** Policy controlling evidence trail completion. */
struct pqcp_deployment_evidence_trail_policy {
	/** Minimum entries expected in the trail. */
	uint32_t min_entries;
	/** Stage occurrence bits that must be present. */
	uint32_t required_stage_mask;
	/** Treat a low entry count as a hard blocker. */
	bool min_entries_blocks;
};

/** Append-only hash-chained evidence trail. */
struct pqcp_deployment_evidence_trail {
	/** Report schema version. */
	uint32_t schema_version;
	/** Overall trail status (valid after finish). */
	enum pqcp_deployment_evidence_trail_status status;
	/** Error bit mask (valid after finish). */
	uint32_t error_mask;
	/** Warning bit mask (valid after finish). */
	uint32_t warning_mask;
	/** Policy profile represented by the trail. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Number of entries appended. */
	uint32_t entry_count;
	/** Stage occurrence bits observed across all entries. */
	uint32_t observed_stage_mask;
	/** Stage occurrence bits required by the finishing policy. */
	uint32_t required_stage_mask;
	/** Stable top candidate bound into the genesis link. */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Stable nonce bound into the genesis link. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Link digest of the most recent entry (the chain head). */
	char head_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U];
};

/** Convert deployment evidence trail status to a stable marker token. */
const char *pqcp_deployment_evidence_trail_status_str(
	enum pqcp_deployment_evidence_trail_status status);

/** Convert an evidence trail stage kind to a stable evidence token. */
const char *pqcp_deployment_evidence_trail_stage_str(
	enum pqcp_deployment_evidence_trail_stage stage);

/** Populate a conservative default evidence trail policy. */
int pqcp_deployment_evidence_trail_default_policy(
	struct pqcp_deployment_evidence_trail_policy *policy);

/**
 * @brief Initialize an empty evidence trail bound to one chain identity.
 *
 * @param trail Trail to initialize. Must not be NULL.
 * @param profile Release profile represented by the trail.
 * @param top_candidate_id Stable top candidate identity.
 * @param nonce_hex Stable 32-char lowercase hex nonce.
 *
 * @retval 0 on success.
 * @retval -EINVAL on NULL or malformed identity inputs.
 */
int pqcp_deployment_evidence_trail_init(
	struct pqcp_deployment_evidence_trail *trail,
	enum pqcp_deployment_release_gate_profile profile,
	const char *top_candidate_id,
	const char *nonce_hex);

/**
 * @brief Append one stage digest to the evidence trail.
 *
 * @param trail Initialized trail.
 * @param entries Caller-owned entry array backing the trail.
 * @param max_entries Capacity of the entry array.
 * @param stage Stage kind being committed.
 * @param digest_hex 64-char lowercase hex stage digest.
 *
 * @retval 0 on success.
 * @retval -EINVAL on NULL or malformed inputs.
 * @retval -ENOSPC when the trail or entry array is full.
 */
int pqcp_deployment_evidence_trail_append(
	struct pqcp_deployment_evidence_trail *trail,
	struct pqcp_deployment_evidence_trail_entry *entries,
	size_t max_entries,
	enum pqcp_deployment_evidence_trail_stage stage,
	const char *digest_hex);

/**
 * @brief Finish the evidence trail and evaluate it against a policy.
 *
 * @param trail Trail with all entries appended.
 * @param policy Completion policy. Must not be NULL.
 *
 * @retval 0 when the trail status is PASS or WARN.
 * @retval -EBADMSG when the trail status is FAIL.
 * @retval -EINVAL on NULL or invalid inputs.
 */
int pqcp_deployment_evidence_trail_finish(
	struct pqcp_deployment_evidence_trail *trail,
	const struct pqcp_deployment_evidence_trail_policy *policy);

/** Emit one stable evidence trail entry marker. */
int pqcp_deployment_evidence_trail_entry_emit(
	const struct pqcp_deployment_evidence_trail_entry *entry);

/** Emit one stable evidence trail head marker. */
int pqcp_deployment_evidence_trail_emit(
	const struct pqcp_deployment_evidence_trail *trail);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_TRAIL_H_ */
