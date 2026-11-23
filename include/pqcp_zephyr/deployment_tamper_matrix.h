/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Adversarial evidence tamper detection matrix
 *
 * Stability: experimental evidence API. This module closes the negative half
 * of the evidence argument: the chain proves it accepts genuine evidence,
 * the tamper matrix proves, in-image, that the same verifiers reject forged
 * evidence. For each terminal stage (final verdict, terminal seal, assurance
 * passport) it renders the genuine marker, applies every deterministic
 * tamper class from the tamper engine, feeds the result back into the
 * unmodified replay verifier for that stage, and requires rejection. Each
 * stage also runs one control cell that feeds the unmodified marker and
 * requires acceptance, so a verifier that rejects everything cannot fake
 * coverage. The aggregated detection matrix is emitted as stable markers and
 * digest-bound to the chain it attacked. It performs no cryptographic
 * operation and uses no dynamic allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_TAMPER_MATRIX_H_
#define PQCP_ZEPHYR_DEPLOYMENT_TAMPER_MATRIX_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_assurance_passport_replay.h>
#include <pqcp_zephyr/deployment_evidence_seal_replay.h>
#include <pqcp_zephyr/deployment_evidence_verdict_replay.h>
#include <pqcp_zephyr/deployment_marker_render.h>
#include <pqcp_zephyr/deployment_tamper_engine.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for tamper matrix reports and markers. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_SCHEMA_VERSION 1U

/** Hex characters in a tamper matrix digest. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_DIGEST_HEX_CHARS 64U

/** Maximum cells the matrix can produce (stages x tamper classes). */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_MAX_CELLS \
	(3U * PQCP_DEPLOYMENT_TAMPER_CLASS_COUNT)

/** Maximum characters for a cell error token (incl. terminator). */
#define PQCP_DEPLOYMENT_TAMPER_CELL_ERROR_MAX_CHARS 32U

/** Terminal evidence stages attacked by the matrix. */
enum pqcp_deployment_tamper_stage {
	PQCP_DEPLOYMENT_TAMPER_STAGE_VERDICT = 0,
	PQCP_DEPLOYMENT_TAMPER_STAGE_SEAL,
	PQCP_DEPLOYMENT_TAMPER_STAGE_PASSPORT,
};

/** Number of tamper stages known by this API version. */
#define PQCP_DEPLOYMENT_TAMPER_STAGE_COUNT 3U

/** Stage selection bit for the final evidence verdict marker. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_VERDICT_BIT  (1U << 0)
/** Stage selection bit for the terminal evidence seal marker. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_SEAL_BIT     (1U << 1)
/** Stage selection bit for the assurance passport marker. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_PASSPORT_BIT (1U << 2)

/** All stage selection bits known by this API version. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_KNOWN_MASK \
	(PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_VERDICT_BIT | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_SEAL_BIT | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_PASSPORT_BIT)

/** Required pointer, schema, or policy input was invalid. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_INVALID_INPUT  (1U << 0)
/** No stages were selected by the policy. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_NO_STAGES      (1U << 1)
/** Rendering a genuine stage marker failed. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_RENDER_FAILED  (1U << 2)
/** Applying a tamper class to a rendered marker failed. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_TAMPER_FAILED  (1U << 3)
/** A control cell with the unmodified marker did not pass replay. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_CONTROL_FAILED (1U << 4)
/** A tampered marker was accepted by the replay verifier. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_DETECTION_MISS (1U << 5)
/** Detection coverage was below the policy floor. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_COVERAGE_FLOOR (1U << 6)

/** All tamper matrix error bits known by this API version. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_NO_STAGES | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_RENDER_FAILED | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_TAMPER_FAILED | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_CONTROL_FAILED | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_DETECTION_MISS | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_COVERAGE_FLOOR)

/** Coverage is below the policy floor but the floor is non-blocking. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_WARNING_COVERAGE_FLOOR (1U << 0)
/** Not every known stage was attacked (partial stage mask). */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_WARNING_PARTIAL_STAGES (1U << 1)

/** All tamper matrix warning bits known by this API version. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_TAMPER_MATRIX_WARNING_COVERAGE_FLOOR | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_WARNING_PARTIAL_STAGES)

/** Overall tamper matrix status. */
enum pqcp_deployment_tamper_matrix_status {
	PQCP_DEPLOYMENT_TAMPER_MATRIX_FAIL = 0,
	PQCP_DEPLOYMENT_TAMPER_MATRIX_WARN,
	PQCP_DEPLOYMENT_TAMPER_MATRIX_PASS,
};

/** One stage x tamper-class detection cell. */
struct pqcp_deployment_tamper_cell {
	/** Cell schema version. */
	uint32_t schema_version;
	/** Stage attacked by this cell. */
	enum pqcp_deployment_tamper_stage stage;
	/** Tamper class applied by this cell. */
	enum pqcp_deployment_tamper_class tamper_class;
	/** True when the replay verifier must reject this cell. */
	bool expected_detection;
	/** True when the replay verifier rejected the cell input. */
	bool detected;
	/** True when the observed outcome matched the expected outcome. */
	bool ok;
	/** Stable replay error token observed for this cell. */
	char error_token[PQCP_DEPLOYMENT_TAMPER_CELL_ERROR_MAX_CHARS];
};

/** Policy controlling tamper matrix generation. */
struct pqcp_deployment_tamper_matrix_policy {
	/** Policy profile represented by the matrix. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Stages to attack (PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_*_BIT). */
	uint32_t stage_mask;
	/** Deterministic seed for the tamper engine. */
	uint32_t tamper_seed;
	/** Minimum detection coverage in permille before warning/failure. */
	uint32_t min_coverage_permille;
	/** Treat any missed detection as a hard blocker. */
	bool require_full_detection;
	/** Treat any failed control cell as a hard blocker. */
	bool require_controls_pass;
	/** Treat coverage floor misses as hard blockers. */
	bool coverage_floor_blocks;
};

/** Aggregated adversarial detection matrix report. */
struct pqcp_deployment_tamper_matrix_report {
	/** Report schema version. */
	uint32_t schema_version;
	/** Overall matrix status. */
	enum pqcp_deployment_tamper_matrix_status status;
	/** Error bit mask. */
	uint32_t error_mask;
	/** Warning bit mask. */
	uint32_t warning_mask;
	/** Policy profile evaluated. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Stages attacked by this matrix. */
	uint32_t stage_mask;
	/** Total cells evaluated. */
	uint32_t cell_count;
	/** Control cells evaluated. */
	uint32_t control_count;
	/** Attack cells evaluated. */
	uint32_t attack_count;
	/** Attack cells rejected by the replay verifiers. */
	uint32_t detected_count;
	/** Attack cells wrongly accepted by the replay verifiers. */
	uint32_t missed_count;
	/** Control cells accepted by the replay verifiers. */
	uint32_t control_pass_count;
	/** Detection coverage over attack cells, in permille. */
	uint32_t coverage_permille;
	/** Per-class ok bits for the verdict stage. */
	uint32_t verdict_class_mask;
	/** Per-class ok bits for the seal stage. */
	uint32_t seal_class_mask;
	/** Per-class ok bits for the passport stage. */
	uint32_t passport_class_mask;
	/** Stable top candidate carried from the attacked chain. */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Stable nonce carried from the attacked chain. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Verdict digest of the attacked chain, or all-zero. */
	char verdict_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_DIGEST_HEX_CHARS + 1U];
	/** Seal digest of the attacked chain, or all-zero. */
	char seal_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_DIGEST_HEX_CHARS + 1U];
	/** Passport digest of the attacked chain, or all-zero. */
	char passport_digest_hex[
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS + 1U];
	/** Stable digest over the final matrix summary. */
	char matrix_digest_hex[
		PQCP_DEPLOYMENT_TAMPER_MATRIX_DIGEST_HEX_CHARS + 1U];
};

/** Caller-owned scratch space for one tamper matrix run. */
struct pqcp_deployment_tamper_matrix_workspace {
	/** Rendered genuine marker line. */
	char line[PQCP_DEPLOYMENT_MARKER_RENDER_LINE_MAX + 256U];
	/** Mutated marker line. */
	char mutated[PQCP_DEPLOYMENT_MARKER_RENDER_LINE_MAX + 256U];
	/** Verdict replay scratch state. */
	struct pqcp_deployment_evidence_verdict_replay_state verdict_state;
	/** Seal replay scratch state. */
	struct pqcp_deployment_evidence_seal_replay_state seal_state;
	/** Passport replay scratch state. */
	struct pqcp_deployment_assurance_passport_replay_state passport_state;
	/** Verdict replay scratch result. */
	struct pqcp_deployment_evidence_verdict_replay_result verdict_result;
	/** Seal replay scratch result. */
	struct pqcp_deployment_evidence_seal_replay_result seal_result;
	/** Passport replay scratch result. */
	struct pqcp_deployment_assurance_passport_replay_result passport_result;
	/** Tamper engine record for the current cell. */
	struct pqcp_deployment_tamper_record record;
};

/** Convert tamper matrix status to a stable marker token. */
const char *pqcp_deployment_tamper_matrix_status_str(
	enum pqcp_deployment_tamper_matrix_status status);

/** Convert a tamper stage to a stable evidence token. */
const char *pqcp_deployment_tamper_stage_str(
	enum pqcp_deployment_tamper_stage stage);

/** Populate a conservative default tamper matrix policy for one profile. */
int pqcp_deployment_tamper_matrix_default_policy(
	enum pqcp_deployment_release_gate_profile profile,
	struct pqcp_deployment_tamper_matrix_policy *policy);

/**
 * @brief Run the adversarial tamper detection matrix in-image.
 *
 * Inputs selected by the policy stage mask must be non-NULL and already
 * replay-valid; the control cells re-prove that assumption inside the run.
 *
 * @param verdict Final evidence verdict, or NULL when not selected.
 * @param seal Terminal evidence seal, or NULL when not selected.
 * @param passport Assurance passport, or NULL when not selected.
 * @param policy Matrix policy. Must not be NULL.
 * @param workspace Caller-owned scratch space. Must not be NULL.
 * @param cells Output cell array.
 * @param max_cells Capacity of the cell array; must be at least
 *                  PQCP_DEPLOYMENT_TAMPER_CLASS_COUNT per selected stage.
 * @param report Output matrix report. Must not be NULL.
 *
 * @retval 0 when the matrix status is PASS or WARN.
 * @retval -EBADMSG when the matrix status is FAIL.
 * @retval -EINVAL on NULL or invalid inputs.
 */
int pqcp_deployment_tamper_matrix_run(
	const struct pqcp_deployment_evidence_verdict *verdict,
	const struct pqcp_deployment_evidence_seal *seal,
	const struct pqcp_deployment_assurance_passport *passport,
	const struct pqcp_deployment_tamper_matrix_policy *policy,
	struct pqcp_deployment_tamper_matrix_workspace *workspace,
	struct pqcp_deployment_tamper_cell *cells,
	size_t max_cells,
	struct pqcp_deployment_tamper_matrix_report *report);

/** Emit one stable tamper cell marker. */
int pqcp_deployment_tamper_cell_emit(
	const struct pqcp_deployment_tamper_cell *cell);

/** Emit one stable tamper matrix summary marker. */
int pqcp_deployment_tamper_matrix_emit(
	const struct pqcp_deployment_tamper_matrix_report *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_TAMPER_MATRIX_H_ */
