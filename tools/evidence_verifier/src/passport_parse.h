/*
 * SPDX-License-Identifier: MIT
 *
 * Passport marker line -> struct reconstruction (host side).
 *
 * Compatibility adapter retained for hosted consumers that still reconstruct
 * the passport structure directly. New verifier and fuzzer paths use the
 * firmware replay ingest state machine so parsing remains single-source.
 */

#ifndef PQCP_EVIDENCE_VERIFIER_PASSPORT_PARSE_H_
#define PQCP_EVIDENCE_VERIFIER_PASSPORT_PARSE_H_

#include <pqcp_zephyr/deployment_assurance_passport.h>

int parse_passport_marker(
	const char *line,
	struct pqcp_deployment_assurance_passport *passport);

#endif /* PQCP_EVIDENCE_VERIFIER_PASSPORT_PARSE_H_ */
