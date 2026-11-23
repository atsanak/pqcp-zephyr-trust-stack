/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Deployment evidence seal
 *
 * Stability: experimental evidence API. This module is the terminal artifact
 * of the firmware deployment evidence chain. It consumes the final evidence
 * verdict, its replay verification, and the replay audit, checks that the
 * three terminal summaries agree on identity, digests, capabilities, and
 * status, then emits one stable sealed marker binding the chain end-to-end.
 * It performs no cryptographic operation and uses no dynamic allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_SEAL_H_
#define PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_SEAL_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_evidence_verdict_audit.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment evidence seal reports and markers. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_SCHEMA_VERSION 1U

/** Hex characters in a deployment evidence seal digest. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_DIGEST_HEX_CHARS 64U

/** Required pointer, schema, or policy input was invalid. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_INVALID_INPUT      (1U << 0)
/** Final evidence verdict failed required seal policy. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_VERDICT            (1U << 1)
/** Verdict replay verification failed required seal policy. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_REPLAY             (1U << 2)
/** Verdict replay audit failed required seal policy. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_AUDIT              (1U << 3)
/** Top candidate IDs disagreed across the terminal summaries. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_TOP_MISMATCH       (1U << 4)
/** Nonce values disagreed across the terminal summaries. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_NONCE_MISMATCH     (1U << 5)
/** Verdict digest values disagreed across the terminal summaries. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_DIGEST_MISMATCH    (1U << 6)
/** Release profiles disagreed across the terminal summaries. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_PROFILE_MISMATCH   (1U << 7)
/** Verdict status values disagreed across the terminal summaries. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_STATUS_MISMATCH    (1U << 8)
/** Required terminal evidence capability bits were absent. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_CAPABILITY         (1U << 9)
/** Required seal score floor was not met. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_SCORE_FLOOR        (1U << 10)

/** All deployment evidence seal error bits known by this API version. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_VERDICT | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_REPLAY | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_AUDIT | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_TOP_MISMATCH | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_NONCE_MISMATCH | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_DIGEST_MISMATCH | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_PROFILE_MISMATCH | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_STATUS_MISMATCH | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_CAPABILITY | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_SCORE_FLOOR)

/** One or more terminal summaries produced review-visible warnings. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_UPSTREAM_WARNINGS (1U << 0)
/** Chain is sealed but the final verdict status is not PASS. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_NOT_PRODUCT_PASS  (1U << 1)
/** Seal score is below warning floor but not hard-blocking. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_SCORE_FLOOR       (1U << 2)
/** Audit covered fewer replay samples than the seal policy desired. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_LOW_SAMPLE_COUNT  (1U << 3)

/** All deployment evidence seal warning bits known by this API version. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_UPSTREAM_WARNINGS | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_NOT_PRODUCT_PASS | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_SCORE_FLOOR | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_LOW_SAMPLE_COUNT)

/** Overall deployment evidence seal status. */
enum pqcp_deployment_evidence_seal_status {
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_FAIL = 0,
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARN,
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS,
};

/** Policy controlling terminal deployment evidence seal generation. */
struct pqcp_deployment_evidence_seal_policy {
	/** Policy profile represented by the seal. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Minimum seal score accepted before warning or failure. */
	uint32_t min_seal_score;
	/** Minimum audited replay samples desired before warning. */
	uint32_t min_audit_samples;
	/** Treat seal score floor misses as hard blockers. */
	bool score_floor_blocks;
	/** Require the final verdict status to be PASS. */
	bool require_verdict_pass;
	/** Require the verdict replay verification to pass. */
	bool require_replay_pass;
	/** Require the verdict replay audit status to be PASS. */
	bool require_audit_pass;
	/** Require terminal top/nonce/digest/profile/status consistency. */
	bool require_consistency;
	/** Require verdict, replay, and audit capability bits. */
	bool require_chain_capability;
};

/** Terminal firmware-side seal over the deployment evidence chain. */
struct pqcp_deployment_evidence_seal {
	/** Report schema version. */
	uint32_t schema_version;
	/** Overall seal status. */
	enum pqcp_deployment_evidence_seal_status status;
	/** Error bit mask. */
	uint32_t error_mask;
	/** Warning bit mask. */
	uint32_t warning_mask;
	/** Policy profile evaluated. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Final deterministic seal score from 0 to 100. */
	uint32_t seal_score;
	/** Lowest terminal score used by the seal. */
	uint32_t min_terminal_score;
	/** Final verdict status sealed by this report. */
	enum pqcp_deployment_evidence_verdict_status verdict_status;
	/** Verdict replay audit status sealed by this report. */
	enum pqcp_deployment_evidence_verdict_audit_status audit_status;
	/** Number of replay results covered by the sealed audit. */
	uint32_t audited_result_count;
	/** Number of upstream chain stages covered by the sealed verdict. */
	uint32_t chain_stage_count;
	/** Cross-chain consistency checks covered by the sealed verdict. */
	uint32_t chain_consistency_checks;
	/** Capability evidence bits present in every terminal summary. */
	uint32_t evidence_capabilities_all;
	/** Capability evidence bits present in at least one terminal summary. */
	uint32_t evidence_capabilities_any;
	/** True when the verdict replay verification passed. */
	bool replay_passed;
	/** True when terminal top candidate IDs matched. */
	bool top_consistent;
	/** True when terminal nonces matched. */
	bool nonce_consistent;
	/** True when terminal verdict digests matched. */
	bool verdict_digest_consistent;
	/** True when terminal release profiles matched. */
	bool profile_consistent;
	/** True when terminal verdict status values matched. */
	bool status_consistent;
	/** Stable top candidate identifier, or "none". */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Stable nonce, or all-zero nonce on inconsistency. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Stable terminal verdict digest. */
	char verdict_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_DIGEST_HEX_CHARS + 1U];
	/** Stable terminal audit digest. */
	char audit_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_DIGEST_HEX_CHARS + 1U];
	/** Stable digest over the final seal summary. */
	char seal_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_DIGEST_HEX_CHARS + 1U];
};

/** Convert deployment evidence seal status to a stable marker token. */
const char *pqcp_deployment_evidence_seal_status_str(
	enum pqcp_deployment_evidence_seal_status status);

/** Populate a default deployment evidence seal policy for one profile. */
int pqcp_deployment_evidence_seal_default_policy(
	enum pqcp_deployment_release_gate_profile profile,
	struct pqcp_deployment_evidence_seal_policy *policy);

/** Seal the terminal deployment evidence chain summaries. */
int pqcp_deployment_evidence_seal_run(
	const struct pqcp_deployment_evidence_verdict *verdict,
	const struct pqcp_deployment_evidence_verdict_replay_result *replay,
	const struct pqcp_deployment_evidence_verdict_audit_report *audit,
	const struct pqcp_deployment_evidence_seal_policy *policy,
	struct pqcp_deployment_evidence_seal *seal);

/** Emit one stable deployment evidence seal marker. */
int pqcp_deployment_evidence_seal_emit(
	const struct pqcp_deployment_evidence_seal *seal);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_SEAL_H_ */
