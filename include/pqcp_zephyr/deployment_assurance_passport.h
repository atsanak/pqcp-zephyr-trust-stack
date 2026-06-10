/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Firmware-native deployment assurance passport
 *
 * Stability: experimental evidence API. This module renders the terminal
 * deployment evidence chain into one compact firmware-native assurance
 * passport. It consumes the capability descriptor plus the seal, seal
 * replay, and seal audit summaries, cross-checks identity, digests,
 * capabilities, and status, and emits one stable passport marker carrying
 * the build identity and the terminal chain digests. It performs no
 * cryptographic operation and uses no dynamic allocation. The passport is
 * hash-bound and replay-checkable, not signed; signing remains an explicit
 * key-custody decision outside this module.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_ASSURANCE_PASSPORT_H_
#define PQCP_ZEPHYR_DEPLOYMENT_ASSURANCE_PASSPORT_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_evidence_seal_audit.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment assurance passport reports and markers. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_SCHEMA_VERSION 1U

/** Hex characters in a deployment assurance passport digest. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS 64U

/** Maximum characters for passport identity text fields. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS 48U

/** Required pointer, schema, or policy input was invalid. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_INVALID_INPUT  (1U << 0)
/** Capability descriptor failed validation or policy. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_CAPABILITY     (1U << 1)
/** Terminal evidence seal failed required passport policy. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_SEAL           (1U << 2)
/** Seal replay verification failed required passport policy. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_SEAL_REPLAY    (1U << 3)
/** Seal replay audit failed required passport policy. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_SEAL_AUDIT     (1U << 4)
/** Top candidate IDs disagreed across the terminal summaries. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_TOP_MISMATCH   (1U << 5)
/** Nonce values disagreed across the terminal summaries. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_NONCE_MISMATCH (1U << 6)
/** Seal digest values disagreed across the terminal summaries. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_DIGEST_MISMATCH (1U << 7)
/** Release profiles disagreed across the terminal summaries. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_PROFILE_MISMATCH (1U << 8)
/** Required terminal evidence capability bits were absent. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_CAPABILITY_MISMATCH (1U << 9)
/** Capability descriptor does not allow production deployment. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_NOT_PRODUCTION (1U << 10)
/** Required passport score floor was not met. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_SCORE_FLOOR    (1U << 11)

/** All deployment assurance passport error bits known by this API version. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_CAPABILITY | \
	 PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_SEAL | \
	 PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_SEAL_REPLAY | \
	 PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_SEAL_AUDIT | \
	 PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_TOP_MISMATCH | \
	 PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_NONCE_MISMATCH | \
	 PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_DIGEST_MISMATCH | \
	 PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_PROFILE_MISMATCH | \
	 PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_CAPABILITY_MISMATCH | \
	 PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_NOT_PRODUCTION | \
	 PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_SCORE_FLOOR)

/** One or more terminal summaries produced review-visible warnings. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_UPSTREAM_WARNINGS (1U << 0)
/** Passport is coherent but the terminal seal status is not PASS. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_NOT_PRODUCT_PASS (1U << 1)
/** Passport score is below warning floor but not hard-blocking. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_SCORE_FLOOR      (1U << 2)
/** Capability descriptor remains local/simulation oriented. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_LOCAL_ONLY       (1U << 3)

/** All deployment assurance passport warning bits known by this API version. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_UPSTREAM_WARNINGS | \
	 PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_NOT_PRODUCT_PASS | \
	 PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_SCORE_FLOOR | \
	 PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_LOCAL_ONLY)

/** Overall deployment assurance passport status. */
enum pqcp_deployment_assurance_passport_status {
	PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL = 0,
	PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARN,
	PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS,
};

/** Policy controlling deployment assurance passport generation. */
struct pqcp_deployment_assurance_passport_policy {
	/** Policy profile represented by the passport. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Minimum passport score accepted before warning or failure. */
	uint32_t min_passport_score;
	/** Treat passport score floor misses as hard blockers. */
	bool score_floor_blocks;
	/** Require the terminal seal status to be PASS. */
	bool require_seal_pass;
	/** Require the seal replay verification to pass. */
	bool require_seal_replay_pass;
	/** Require the seal replay audit status to be PASS. */
	bool require_seal_audit_pass;
	/** Require terminal top/nonce/digest/profile consistency. */
	bool require_consistency;
	/** Require verdict, replay, and audit capability bits. */
	bool require_chain_capability;
	/** Require capability production_allowed for passport PASS. */
	bool require_production_allowed;
};

/** Firmware-native deployment assurance passport. */
struct pqcp_deployment_assurance_passport {
	/** Report schema version. */
	uint32_t schema_version;
	/** Overall passport status. */
	enum pqcp_deployment_assurance_passport_status status;
	/** Error bit mask. */
	uint32_t error_mask;
	/** Warning bit mask. */
	uint32_t warning_mask;
	/** Policy profile evaluated. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Final deterministic passport score from 0 to 100. */
	uint32_t passport_score;
	/** Lowest terminal score used by the passport. */
	uint32_t min_terminal_score;
	/** Capability evidence readiness score. */
	uint32_t capability_readiness_score;
	/** Terminal seal status carried into the passport. */
	enum pqcp_deployment_evidence_seal_status seal_status;
	/** Terminal seal audit status carried into the passport. */
	enum pqcp_deployment_evidence_seal_audit_status seal_audit_status;
	/** Number of replay results covered by the sealed audit. */
	uint32_t audited_result_count;
	/** Number of upstream chain stages covered by the sealed verdict. */
	uint32_t chain_stage_count;
	/** Capability evidence bits present in every terminal summary. */
	uint32_t evidence_capabilities_all;
	/** Capability evidence bits present in at least one terminal summary. */
	uint32_t evidence_capabilities_any;
	/** Enabled ML-KEM parameter level mask from the capability descriptor. */
	uint32_t mlkem_level_mask;
	/** Enabled ML-DSA parameter level mask from the capability descriptor. */
	uint32_t mldsa_level_mask;
	/** True when the seal replay verification passed. */
	bool seal_replay_passed;
	/** True when terminal top candidate IDs matched. */
	bool top_consistent;
	/** True when terminal nonces matched. */
	bool nonce_consistent;
	/** True when terminal seal digests matched. */
	bool seal_digest_consistent;
	/** True when terminal release profiles matched. */
	bool profile_consistent;
	/** True when the capability descriptor allows production deployment. */
	bool production_allowed;
	/** PQCP version string carried from the capability descriptor. */
	char pqcp_version[PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS];
	/** Zephyr version string carried from the capability descriptor. */
	char zephyr_version[PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS];
	/** Board identity carried from the capability descriptor. */
	char board[PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS];
	/** Stable top candidate identifier, or "none". */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Stable nonce, or all-zero nonce on inconsistency. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Stable terminal seal digest. */
	char seal_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_DIGEST_HEX_CHARS + 1U];
	/** Stable terminal seal-audit digest. */
	char seal_audit_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_DIGEST_HEX_CHARS + 1U];
	/** Stable digest over the final passport summary. */
	char passport_digest_hex[
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS + 1U];
};

/** Convert deployment assurance passport status to a stable marker token. */
const char *pqcp_deployment_assurance_passport_status_str(
	enum pqcp_deployment_assurance_passport_status status);

/** Populate a default deployment assurance passport policy for one profile. */
int pqcp_deployment_assurance_passport_default_policy(
	enum pqcp_deployment_release_gate_profile profile,
	struct pqcp_deployment_assurance_passport_policy *policy);

/** Render the firmware-native deployment assurance passport. */
int pqcp_deployment_assurance_passport_run(
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_evidence_seal *seal,
	const struct pqcp_deployment_evidence_seal_replay_result *seal_replay,
	const struct pqcp_deployment_evidence_seal_audit_report *seal_audit,
	const struct pqcp_deployment_assurance_passport_policy *policy,
	struct pqcp_deployment_assurance_passport *passport);

/** Emit one stable deployment assurance passport marker. */
int pqcp_deployment_assurance_passport_emit(
	const struct pqcp_deployment_assurance_passport *passport);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_ASSURANCE_PASSPORT_H_ */
