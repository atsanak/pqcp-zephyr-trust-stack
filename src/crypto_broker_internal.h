/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 */

#ifndef PQCP_CRYPTO_BROKER_INTERNAL_H_
#define PQCP_CRYPTO_BROKER_INTERNAL_H_

#include <pqcp_zephyr/crypto_broker.h>

#define PQCP_CRYPTO_BROKER_RECEIPT_BODY_MAX_BYTES 384U
#define PQCP_CRYPTO_BROKER_REQUEST_HEADER_BYTES 224U

bool pqcp_crypto_broker_internal_secure_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length);
bool pqcp_crypto_broker_internal_all_zero(
	const uint8_t *value,
	size_t length);
uint32_t pqcp_crypto_broker_internal_next_generation(
	uint32_t *generation);
int pqcp_crypto_broker_internal_copy_id(
	char *destination,
	size_t capacity,
	const char *source);
int pqcp_crypto_broker_internal_principal_index(
	const struct pqcp_crypto_broker *broker,
	const char *principal_id);
int pqcp_crypto_broker_internal_grant_index(
	const struct pqcp_crypto_broker *broker,
	uint32_t grant_id);
int pqcp_crypto_broker_internal_capability_index(
	const struct pqcp_crypto_broker *broker,
	const uint8_t token[PQCP_CRYPTO_BROKER_TOKEN_BYTES]);
int pqcp_crypto_broker_internal_transaction_index(
	const struct pqcp_crypto_broker *broker,
	uint32_t principal_index,
	const uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES]);
int pqcp_crypto_broker_internal_free_principal(
	const struct pqcp_crypto_broker *broker);
int pqcp_crypto_broker_internal_free_grant(
	const struct pqcp_crypto_broker *broker);
int pqcp_crypto_broker_internal_free_capability(
	const struct pqcp_crypto_broker *broker);
int pqcp_crypto_broker_internal_free_transaction(
	const struct pqcp_crypto_broker *broker,
	uint64_t now_ms);

int pqcp_crypto_broker_internal_request_digest(
	const struct pqcp_crypto_broker_request *request,
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES]);
uint64_t pqcp_crypto_broker_internal_cost(
	const struct pqcp_crypto_broker_request *request);
int pqcp_crypto_broker_internal_validate_request(
	const struct pqcp_crypto_broker_request *request);
int pqcp_crypto_broker_internal_validate_quota(
	const struct pqcp_crypto_broker_quota *quota);
int pqcp_crypto_broker_internal_validate_grant_policy(
	const struct pqcp_crypto_broker_grant_policy *policy);
void pqcp_crypto_broker_internal_refresh_window(
	struct pqcp_crypto_broker_principal *principal,
	uint64_t now_ms);
int pqcp_crypto_broker_internal_reserve_quota(
	struct pqcp_crypto_broker_principal *principal,
	const struct pqcp_crypto_broker_request *request,
	uint64_t cost_units,
	uint64_t now_ms);
void pqcp_crypto_broker_internal_complete_quota(
	struct pqcp_crypto_broker_principal *principal,
	size_t output_length,
	bool cancelled);

int pqcp_crypto_broker_internal_dispatch(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	const struct pqcp_crypto_broker_authorization *authorization,
	struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response);
int pqcp_crypto_broker_internal_create_receipt(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	const struct pqcp_crypto_broker_authorization *authorization,
	struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response);
size_t pqcp_crypto_broker_internal_receipt_body(
	const struct pqcp_crypto_broker_receipt *receipt,
	uint8_t output[PQCP_CRYPTO_BROKER_RECEIPT_BODY_MAX_BYTES]);
int pqcp_crypto_broker_internal_copy_transaction_response(
	const struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response);
void pqcp_crypto_broker_internal_destroy_response_keys(
	struct pqcp_crypto_broker *broker,
	struct pqcp_crypto_broker_response *response);

#endif /* PQCP_CRYPTO_BROKER_INTERNAL_H_ */
