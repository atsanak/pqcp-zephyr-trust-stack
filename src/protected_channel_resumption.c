/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Authenticated, replay-bounded protected-channel resumption tickets.
 */

#include <errno.h>
#include <string.h>

#include <psa/crypto.h>

#include <pqcp_zephyr/protected_channel_operations.h>

#include "runtime_internal.h"

#define TICKET_MAGIC 0x50515254U
#define TICKET_HEADER_BYTES 40U
#define TICKET_CLAIMS_BYTES 192U
#define TICKET_AAD_BYTES 24U

static int import_ticket_key(
	const uint8_t secret[PQCP_CHANNEL_RESUMPTION_SECRET_BYTES],
	uint32_t usage,
	psa_key_id_t *key_id)
{
	psa_key_attributes_t attributes =
		PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(
		&attributes,
		PQCP_CHANNEL_RESUMPTION_SECRET_BYTES * 8U);
	psa_set_key_usage_flags(&attributes, usage);
	psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
	status = psa_import_key(
		&attributes, secret,
		PQCP_CHANNEL_RESUMPTION_SECRET_BYTES,
		key_id);
	psa_reset_key_attributes(&attributes);
	return status == PSA_SUCCESS ? 0 : -EIO;
}

static void claims_encode(
	const struct pqcp_channel_resumption_claims *claims,
	uint8_t output[TICKET_CLAIMS_BYTES])
{
	size_t profile_length;

	memset(output, 0, TICKET_CLAIMS_BYTES);
	pqcp_runtime_internal_write_u32(
		output, claims->schema_version);
	pqcp_runtime_internal_write_u64(
		output + 4U, claims->ticket_id);
	pqcp_runtime_internal_write_u64(
		output + 12U, claims->issued_at_ms);
	pqcp_runtime_internal_write_u64(
		output + 20U, claims->expires_at_ms);
	pqcp_runtime_internal_write_u64(
		output + 28U, claims->original_session_id);
	pqcp_runtime_internal_write_u64(
		output + 36U, claims->channel_epoch);
	pqcp_runtime_internal_write_u32(
		output + 44U, claims->mlkem_level);
	pqcp_runtime_internal_write_u32(
		output + 48U, claims->mldsa_level);
	pqcp_runtime_internal_write_u32(
		output + 52U, claims->flags);
	profile_length = strnlen(
		claims->profile_id,
		sizeof(claims->profile_id));
	output[56U] = (uint8_t)profile_length;
	memcpy(output + 57U, claims->profile_id,
	       profile_length);
	memcpy(output + 128U,
	       claims->peer_identity_digest,
	       sizeof(claims->peer_identity_digest));
	memcpy(output + 160U,
	       claims->transcript_digest,
	       sizeof(claims->transcript_digest));
}

static int claims_decode(
	const uint8_t input[TICKET_CLAIMS_BYTES],
	struct pqcp_channel_resumption_claims *claims)
{
	uint8_t profile_length;

	memset(claims, 0, sizeof(*claims));
	claims->schema_version =
		pqcp_runtime_internal_read_u32(input);
	claims->ticket_id =
		pqcp_runtime_internal_read_u64(input + 4U);
	claims->issued_at_ms =
		pqcp_runtime_internal_read_u64(input + 12U);
	claims->expires_at_ms =
		pqcp_runtime_internal_read_u64(input + 20U);
	claims->original_session_id =
		pqcp_runtime_internal_read_u64(input + 28U);
	claims->channel_epoch =
		pqcp_runtime_internal_read_u64(input + 36U);
	claims->mlkem_level =
		pqcp_runtime_internal_read_u32(input + 44U);
	claims->mldsa_level =
		pqcp_runtime_internal_read_u32(input + 48U);
	claims->flags =
		pqcp_runtime_internal_read_u32(input + 52U);
	profile_length = input[56U];
	if (profile_length == 0U ||
	    profile_length >=
		    sizeof(claims->profile_id)) {
		return -EBADMSG;
	}
	memcpy(claims->profile_id, input + 57U,
	       profile_length);
	claims->profile_id[profile_length] = '\0';
	memcpy(claims->peer_identity_digest,
	       input + 128U,
	       sizeof(claims->peer_identity_digest));
	memcpy(claims->transcript_digest,
	       input + 160U,
	       sizeof(claims->transcript_digest));
	if (claims->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    claims->ticket_id == 0U ||
	    claims->issued_at_ms == 0U ||
	    claims->expires_at_ms <=
		    claims->issued_at_ms ||
	    claims->original_session_id == 0U ||
	    claims->channel_epoch == 0U) {
		return -EBADMSG;
	}
	return 0;
}

static void ticket_aad(
	uint64_t ticket_id,
	uint64_t expires_at_ms,
	uint8_t aad[TICKET_AAD_BYTES])
{
	pqcp_runtime_internal_write_u32(aad, TICKET_MAGIC);
	pqcp_runtime_internal_write_u32(
		aad + 4U,
		PQCP_CHANNEL_OPERATION_SCHEMA_VERSION);
	pqcp_runtime_internal_write_u64(
		aad + 8U, ticket_id);
	pqcp_runtime_internal_write_u64(
		aad + 16U, expires_at_ms);
}

static int ticket_header_encode(
	uint64_t ticket_id,
	uint64_t expires_at_ms,
	const uint8_t nonce[
		PQCP_CHANNEL_RESUMPTION_NONCE_BYTES],
	uint8_t output[TICKET_HEADER_BYTES])
{
	if (ticket_id == 0U || expires_at_ms == 0U ||
	    nonce == NULL || output == NULL) {
		return -EINVAL;
	}
	memset(output, 0, TICKET_HEADER_BYTES);
	pqcp_runtime_internal_write_u32(output, TICKET_MAGIC);
	pqcp_runtime_internal_write_u32(
		output + 4U,
		PQCP_CHANNEL_OPERATION_SCHEMA_VERSION);
	pqcp_runtime_internal_write_u64(
		output + 8U, ticket_id);
	pqcp_runtime_internal_write_u64(
		output + 16U, expires_at_ms);
	memcpy(output + 24U, nonce,
	       PQCP_CHANNEL_RESUMPTION_NONCE_BYTES);
	return 0;
}

static int replay_find(
	const struct pqcp_channel_resumption_store *store,
	uint64_t ticket_id)
{
	for (size_t index = 0U;
	     index < store->replay_capacity; ++index) {
		if (store->replay_entries[index].occupied &&
		    store->replay_entries[index].ticket_id ==
			    ticket_id) {
			return (int)index;
		}
	}
	return -1;
}

static void replay_record(
	struct pqcp_channel_resumption_store *store,
	uint64_t ticket_id,
	uint64_t now_ms)
{
	struct pqcp_channel_ticket_replay_entry *entry =
		&store->replay_entries[store->next_replay_slot];

	entry->ticket_id = ticket_id;
	entry->accepted_at_ms = now_ms;
	entry->occupied = true;
	store->next_replay_slot =
		(store->next_replay_slot + 1U) %
		store->replay_capacity;
}

int pqcp_channel_resumption_store_init(
	struct pqcp_channel_resumption_store *store,
	const uint8_t secret[PQCP_CHANNEL_RESUMPTION_SECRET_BYTES],
	struct pqcp_channel_ticket_replay_entry *replay_entries,
	size_t replay_capacity)
{
	uint8_t accumulator = 0U;

	if (store == NULL || secret == NULL ||
	    replay_entries == NULL || replay_capacity == 0U) {
		return -EINVAL;
	}
	for (size_t index = 0U;
	     index < PQCP_CHANNEL_RESUMPTION_SECRET_BYTES;
	     ++index) {
		accumulator |= secret[index];
	}
	if (accumulator == 0U) {
		return -EKEYREJECTED;
	}
	memset(replay_entries, 0,
	       replay_capacity * sizeof(*replay_entries));
	memset(store, 0, sizeof(*store));
	memcpy(store->secret, secret, sizeof(store->secret));
	store->replay_entries = replay_entries;
	store->replay_capacity = replay_capacity;
	store->next_ticket_id = 1U;
	k_mutex_init(&store->lock);
	store->initialized = true;
	return 0;
}

int pqcp_channel_resumption_issue(
	struct pqcp_channel_resumption_store *store,
	const struct pqcp_channel *channel,
	const uint8_t peer_identity_digest[PQCP_CHANNEL_HASH_BYTES],
	uint64_t now_ms,
	uint64_t lifetime_ms,
	struct pqcp_channel_resumption_ticket *ticket)
{
	struct pqcp_channel_resumption_claims claims;
	uint8_t plaintext[TICKET_CLAIMS_BYTES];
	uint8_t nonce[
		PQCP_CHANNEL_RESUMPTION_NONCE_BYTES];
	uint8_t aad[TICKET_AAD_BYTES];
	psa_key_id_t key_id = 0U;
	size_t produced = 0U;
	psa_status_t status;
	int ret;

	if (store == NULL || !store->initialized ||
	    channel == NULL || !channel->established ||
	    !channel->keys.traffic_keys_ready ||
	    peer_identity_digest == NULL || now_ms == 0U ||
	    lifetime_ms == 0U || ticket == NULL ||
	    UINT64_MAX - now_ms < lifetime_ms) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&store->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	memset(&claims, 0, sizeof(claims));
	claims.schema_version =
		PQCP_CHANNEL_OPERATION_SCHEMA_VERSION;
	claims.ticket_id = store->next_ticket_id++;
	claims.issued_at_ms = now_ms;
	claims.expires_at_ms = now_ms + lifetime_ms;
	claims.original_session_id =
		channel->config.session_id;
	claims.channel_epoch =
		channel->send_sequence +
		channel->receive_sequence + 1U;
	claims.mlkem_level = channel->config.mlkem_level;
	claims.mldsa_level = channel->config.mldsa_level;
	claims.flags =
		channel->config.require_mutual_authentication ?
			BIT(0) : 0U;
	ret = pqcp_runtime_internal_copy_text(
		claims.profile_id, sizeof(claims.profile_id),
		channel->config.profile_id);
	if (ret == 0) {
		memcpy(claims.peer_identity_digest,
		       peer_identity_digest,
		       sizeof(claims.peer_identity_digest));
		ret = pqcp_channel_transcript_digest(
			&channel->transcript,
			claims.transcript_digest);
	}
	if (ret == 0) {
		claims_encode(&claims, plaintext);
		status = psa_generate_random(
			nonce, sizeof(nonce));
		ret = status == PSA_SUCCESS ? 0 : -EIO;
	}
	if (ret == 0) {
		ticket_aad(
			claims.ticket_id,
			claims.expires_at_ms, aad);
		ret = import_ticket_key(
			store->secret,
			PSA_KEY_USAGE_ENCRYPT, &key_id);
	}
	if (ret == 0) {
		memset(ticket, 0, sizeof(*ticket));
		ret = ticket_header_encode(
			claims.ticket_id,
			claims.expires_at_ms, nonce,
			ticket->bytes);
	}
	if (ret == 0) {
		status = psa_aead_encrypt(
			key_id, PSA_ALG_GCM,
			nonce, sizeof(nonce),
			aad, sizeof(aad),
			plaintext, sizeof(plaintext),
			ticket->bytes + TICKET_HEADER_BYTES,
			sizeof(ticket->bytes) -
				TICKET_HEADER_BYTES,
			&produced);
		ret = status == PSA_SUCCESS ? 0 : -EIO;
	}
	if (ret == 0 &&
	    produced !=
		    TICKET_CLAIMS_BYTES +
			    PQCP_CHANNEL_RESUMPTION_TAG_BYTES) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ticket->length =
			TICKET_HEADER_BYTES + produced;
		ticket->ticket_id = claims.ticket_id;
		ticket->expires_at_ms = claims.expires_at_ms;
		store->issued++;
	} else {
		pqcp_runtime_secure_zero(
			ticket, sizeof(*ticket));
	}
	if (key_id != 0U) {
		(void)psa_destroy_key(key_id);
	}
	pqcp_runtime_secure_zero(plaintext, sizeof(plaintext));
	pqcp_runtime_secure_zero(nonce, sizeof(nonce));
	pqcp_runtime_secure_zero(aad, sizeof(aad));
	pqcp_runtime_secure_zero(&claims, sizeof(claims));
	(void)k_mutex_unlock(&store->lock);
	return ret;
}

int pqcp_channel_resumption_accept(
	struct pqcp_channel_resumption_store *store,
	const struct pqcp_channel_resumption_ticket *ticket,
	uint64_t now_ms,
	struct pqcp_channel_resumption_claims *claims)
{
	uint8_t plaintext[TICKET_CLAIMS_BYTES];
	uint8_t nonce[
		PQCP_CHANNEL_RESUMPTION_NONCE_BYTES];
	uint8_t aad[TICKET_AAD_BYTES];
	psa_key_id_t key_id = 0U;
	uint64_t encoded_ticket_id;
	uint64_t encoded_expiry;
	size_t produced = 0U;
	psa_status_t status;
	int ret;

	if (store == NULL || !store->initialized ||
	    ticket == NULL ||
	    ticket->length !=
		    TICKET_HEADER_BYTES +
			    TICKET_CLAIMS_BYTES +
			    PQCP_CHANNEL_RESUMPTION_TAG_BYTES ||
	    now_ms == 0U || claims == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&store->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (pqcp_runtime_internal_read_u32(ticket->bytes) !=
		    TICKET_MAGIC ||
	    pqcp_runtime_internal_read_u32(
		    ticket->bytes + 4U) !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION) {
		ret = -EBADMSG;
		goto cleanup;
	}
	encoded_ticket_id =
		pqcp_runtime_internal_read_u64(
			ticket->bytes + 8U);
	encoded_expiry =
		pqcp_runtime_internal_read_u64(
			ticket->bytes + 16U);
	if (encoded_ticket_id == 0U ||
	    encoded_expiry <= now_ms ||
	    ticket->ticket_id != encoded_ticket_id ||
	    ticket->expires_at_ms != encoded_expiry) {
		ret = encoded_expiry <= now_ms ?
			-ETIMEDOUT : -EBADMSG;
		goto cleanup;
	}
	if (replay_find(store, encoded_ticket_id) >= 0) {
		ret = -EALREADY;
		goto cleanup;
	}
	memcpy(nonce, ticket->bytes + 24U,
	       sizeof(nonce));
	ticket_aad(encoded_ticket_id, encoded_expiry, aad);
	ret = import_ticket_key(
		store->secret, PSA_KEY_USAGE_DECRYPT, &key_id);
	if (ret != 0) {
		goto cleanup;
	}
	status = psa_aead_decrypt(
		key_id, PSA_ALG_GCM,
		nonce, sizeof(nonce),
		aad, sizeof(aad),
		ticket->bytes + TICKET_HEADER_BYTES,
		ticket->length - TICKET_HEADER_BYTES,
		plaintext, sizeof(plaintext), &produced);
	ret = status == PSA_SUCCESS ? 0 : -EKEYREJECTED;
	if (ret == 0 && produced != sizeof(plaintext)) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = claims_decode(plaintext, claims);
	}
	if (ret == 0 &&
	    (claims->ticket_id != encoded_ticket_id ||
	     claims->expires_at_ms != encoded_expiry ||
	     claims->expires_at_ms <= now_ms)) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		replay_record(store, encoded_ticket_id, now_ms);
		store->accepted++;
	}

cleanup:
	if (ret != 0) {
		store->rejected++;
		pqcp_runtime_secure_zero(claims, sizeof(*claims));
	}
	if (key_id != 0U) {
		(void)psa_destroy_key(key_id);
	}
	pqcp_runtime_secure_zero(plaintext, sizeof(plaintext));
	pqcp_runtime_secure_zero(nonce, sizeof(nonce));
	pqcp_runtime_secure_zero(aad, sizeof(aad));
	(void)k_mutex_unlock(&store->lock);
	return ret;
}

int pqcp_channel_resumption_store_audit(
	struct pqcp_channel_resumption_store *store)
{
	uint8_t accumulator = 0U;
	int ret;

	if (store == NULL || !store->initialized ||
	    store->replay_entries == NULL ||
	    store->replay_capacity == 0U ||
	    store->next_replay_slot >=
		    store->replay_capacity ||
	    store->next_ticket_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&store->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < sizeof(store->secret); ++index) {
		accumulator |= store->secret[index];
	}
	if (accumulator == 0U) {
		ret = -EKEYREJECTED;
	}
	for (size_t left = 0U;
	     ret == 0 && left < store->replay_capacity;
	     ++left) {
		const struct pqcp_channel_ticket_replay_entry *entry =
			&store->replay_entries[left];

		if (!entry->occupied) {
			continue;
		}
		if (entry->ticket_id == 0U ||
		    entry->accepted_at_ms == 0U) {
			ret = -EBADMSG;
			break;
		}
		for (size_t right = left + 1U;
		     right < store->replay_capacity; ++right) {
			if (store->replay_entries[right].occupied &&
			    store->replay_entries[right].ticket_id ==
				    entry->ticket_id) {
				ret = -EBADMSG;
				break;
			}
		}
	}
	(void)k_mutex_unlock(&store->lock);
	return ret;
}
