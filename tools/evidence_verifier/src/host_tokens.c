/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Stable marker token tables for the host evidence verifier.
 *
 * The replay verifier translation units reference these token functions for
 * marker emission. On firmware they live in the generator modules
 * (deployment_release_gate.c, deployment_evidence_verdict.c, ...), which
 * carry heavy upstream link dependencies that have no place in a host CLI.
 * The token strings are part of the stable marker contract documented in the
 * public headers, so this file restates only the contract tables; all
 * parsing and digest logic stays single-source in the firmware .c files.
 */

#include <pqcp_zephyr/deployment_assurance_passport.h>

const char *pqcp_deployment_release_gate_profile_str(
	enum pqcp_deployment_release_gate_profile profile)
{
	switch (profile) {
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE:
		return "prototype";
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER:
		return "paper";
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT:
		return "product";
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER:
		return "partner";
	default:
		return "unknown";
	}
}

const char *pqcp_deployment_evidence_verdict_status_str(
	enum pqcp_deployment_evidence_verdict_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

const char *pqcp_deployment_evidence_verdict_audit_status_str(
	enum pqcp_deployment_evidence_verdict_audit_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

const char *pqcp_deployment_evidence_seal_status_str(
	enum pqcp_deployment_evidence_seal_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

const char *pqcp_deployment_assurance_passport_status_str(
	enum pqcp_deployment_assurance_passport_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}
