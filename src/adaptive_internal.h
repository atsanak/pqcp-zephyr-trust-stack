/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 */

#ifndef PQCP_ADAPTIVE_INTERNAL_H_
#define PQCP_ADAPTIVE_INTERNAL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/adaptive_control.h>

bool pqcp_adaptive_internal_id_valid(const char *value);
void pqcp_adaptive_internal_set_text(
	char *destination, size_t capacity, const char *source);
uint32_t pqcp_adaptive_internal_clamp_u32(
	uint32_t value, uint32_t minimum, uint32_t maximum);
uint64_t pqcp_adaptive_internal_clamp_u64(
	uint64_t value, uint64_t minimum, uint64_t maximum);
uint32_t pqcp_adaptive_internal_percent(
	uint64_t numerator, uint64_t denominator);
uint32_t pqcp_adaptive_internal_permille(
	uint64_t numerator, uint64_t denominator);
uint32_t pqcp_adaptive_internal_bit_count(uint32_t value);
uint64_t pqcp_adaptive_internal_saturating_add_u64(
	uint64_t left, uint64_t right);
uint64_t pqcp_adaptive_internal_saturating_mul_u64(
	uint64_t left, uint64_t right);
uint64_t pqcp_adaptive_internal_abs_i64(int64_t value);
int pqcp_adaptive_internal_digest_profile(
	const struct pqcp_adaptive_profile *profile,
	struct pqcp_deployment_evidence_digest *digest);
int pqcp_adaptive_internal_digest_event(
	const struct pqcp_adaptive_event *event,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U]);
int pqcp_adaptive_internal_digest_registry(
	const struct pqcp_adaptive_profile_registry *registry,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U]);
int pqcp_adaptive_internal_digest_control(
	const struct pqcp_adaptive_control_plane *control,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U]);
bool pqcp_adaptive_internal_profile_valid(
	const struct pqcp_adaptive_profile *profile);
bool pqcp_adaptive_internal_policy_valid(
	const struct pqcp_adaptive_policy *policy);
bool pqcp_adaptive_internal_status_valid(enum pqcp_adaptive_status status);
bool pqcp_adaptive_internal_pressure_valid(
	enum pqcp_adaptive_pressure pressure);
bool pqcp_adaptive_internal_threat_valid(
	enum pqcp_adaptive_threat_level level);
uint32_t pqcp_adaptive_internal_operation_for_session(
	enum pqcp_adaptive_session_kind kind);
uint32_t pqcp_adaptive_internal_profile_security_strength(
	const struct pqcp_adaptive_profile *profile);
int pqcp_adaptive_internal_compare_profile_ids(
	const struct pqcp_adaptive_profile *left,
	const struct pqcp_adaptive_profile *right);

#endif /* PQCP_ADAPTIVE_INTERNAL_H_ */
