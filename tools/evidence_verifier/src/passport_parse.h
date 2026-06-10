/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Passport marker line -> struct reconstruction (host side).
 *
 * The passport replay verifier is struct-based; this is the host-side line
 * adapter shared by the verifier CLI and the evidence fuzzer. Field grammar
 * matches the firmware emitters: space-separated key=value tokens, keys
 * anchored at start-of-line or after a space. Digest recomputation stays in
 * the firmware .c file.
 */

#ifndef PQCP_EVIDENCE_VERIFIER_PASSPORT_PARSE_H_
#define PQCP_EVIDENCE_VERIFIER_PASSPORT_PARSE_H_

#include <pqcp_zephyr/deployment_assurance_passport.h>

int parse_passport_marker(
	const char *line,
	struct pqcp_deployment_assurance_passport *passport);

#endif /* PQCP_EVIDENCE_VERIFIER_PASSPORT_PARSE_H_ */
