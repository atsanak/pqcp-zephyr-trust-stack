/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Deterministic evidence tamper engine
 *
 * Stability: experimental evidence API. This module applies one deterministic,
 * fully described mutation to a single key=value evidence marker line. It is
 * the attack half of the adversarial self-validation loop: the tamper matrix
 * renders a genuine marker, mutates it with this engine, and requires the
 * matching replay verifier to reject the result. Every mutation is
 * reproducible from (class, seed) and reported in a tamper record so a
 * reviewer can replay the exact attack. It performs no cryptographic
 * operation and uses no dynamic allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_TAMPER_ENGINE_H_
#define PQCP_ZEPHYR_DEPLOYMENT_TAMPER_ENGINE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for tamper engine records. */
#define PQCP_DEPLOYMENT_TAMPER_ENGINE_SCHEMA_VERSION 1U

/** Maximum characters for a tamper record field key (incl. terminator). */
#define PQCP_DEPLOYMENT_TAMPER_FIELD_KEY_MAX_CHARS 32U

/** Deterministic single-line tamper classes. */
enum pqcp_deployment_tamper_class {
	/** Control cell: line passes through unmodified. */
	PQCP_DEPLOYMENT_TAMPER_NONE = 0,
	/** Flip one hex nibble inside the value of a digest field. */
	PQCP_DEPLOYMENT_TAMPER_DIGEST_FLIP,
	/** Rewrite the status= token to the next tri-state token. */
	PQCP_DEPLOYMENT_TAMPER_STATUS_FORGE,
	/** Rewrite the score= value without recomputing the digest. */
	PQCP_DEPLOYMENT_TAMPER_SCORE_INFLATE,
	/** Increment the schema= value past the supported version. */
	PQCP_DEPLOYMENT_TAMPER_SCHEMA_BUMP,
	/** Replace the nonce= value with a different valid-shaped nonce. */
	PQCP_DEPLOYMENT_TAMPER_NONCE_SWAP,
	/** Rewrite the profile= token to a different valid profile. */
	PQCP_DEPLOYMENT_TAMPER_PROFILE_SWAP,
	/** Remove one required key=value field from the line. */
	PQCP_DEPLOYMENT_TAMPER_FIELD_STRIP,
	/** Truncate the line to two thirds of its length. */
	PQCP_DEPLOYMENT_TAMPER_TRUNCATE,
	/** Mutate one seed-selected value character in place. */
	PQCP_DEPLOYMENT_TAMPER_BIT_NOISE,
	/** Matrix-level: feed the unmodified line twice. */
	PQCP_DEPLOYMENT_TAMPER_DUPLICATE,
	/** Matrix-level: omit the line entirely. */
	PQCP_DEPLOYMENT_TAMPER_OMIT,
};

/** Number of tamper classes known by this API version. */
#define PQCP_DEPLOYMENT_TAMPER_CLASS_COUNT 12U

/** Description of one applied (or skipped) mutation. */
struct pqcp_deployment_tamper_record {
	/** Record schema version. */
	uint32_t schema_version;
	/** Tamper class that was requested. */
	enum pqcp_deployment_tamper_class tamper_class;
	/** True when the output line differs from the input line. */
	bool applied;
	/** Zero-based offset of the first mutated character, or 0. */
	uint32_t offset;
	/** Original character at the mutation offset, or '\0'. */
	char original_char;
	/** Mutated character at the mutation offset, or '\0'. */
	char mutated_char;
	/** Field key targeted by the mutation, or "". */
	char field_key[PQCP_DEPLOYMENT_TAMPER_FIELD_KEY_MAX_CHARS];
};

/**
 * @brief Convert a tamper class to a stable evidence token.
 *
 * @param tamper_class Tamper class value.
 *
 * @return Static token, or "unknown" for invalid values.
 */
const char *pqcp_deployment_tamper_class_str(
	enum pqcp_deployment_tamper_class tamper_class);

/**
 * @brief Return true for classes mutating the line text itself.
 *
 * PQCP_DEPLOYMENT_TAMPER_NONE, _DUPLICATE, and _OMIT leave the line text
 * unchanged; the matrix runner realizes them by feeding the line zero, one,
 * or two times instead.
 *
 * @param tamper_class Tamper class value.
 *
 * @return True when the class rewrites line bytes.
 */
bool pqcp_deployment_tamper_class_mutates_line(
	enum pqcp_deployment_tamper_class tamper_class);

/**
 * @brief Apply one deterministic mutation to a key=value marker line.
 *
 * For line-mutating classes the output is guaranteed to differ from the
 * input. For PQCP_DEPLOYMENT_TAMPER_NONE, _DUPLICATE, and _OMIT the line is
 * copied unchanged and the record reports applied=false.
 *
 * @param tamper_class Mutation class to apply.
 * @param seed Deterministic seed selecting positions and replacement bytes.
 * @param field_key Field key for DIGEST_FLIP, SCORE_INFLATE, and FIELD_STRIP
 *                  (for example "seal_digest" or "score"); ignored and may be
 *                  NULL for the other classes.
 * @param line Input marker line (no newline).
 * @param out Output buffer for the mutated line.
 * @param out_size Output buffer capacity in bytes.
 * @param record Output mutation description. Must not be NULL.
 *
 * @retval 0 on success.
 * @retval -EINVAL on NULL inputs or an unknown class.
 * @retval -ENOENT when the targeted field is absent from the line.
 * @retval -ENOSPC when the output buffer is too small.
 */
int pqcp_deployment_tamper_apply(
	enum pqcp_deployment_tamper_class tamper_class,
	uint32_t seed,
	const char *field_key,
	const char *line,
	char *out, size_t out_size,
	struct pqcp_deployment_tamper_record *record);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_TAMPER_ENGINE_H_ */
