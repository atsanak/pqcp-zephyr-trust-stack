/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Exporter-bound ML-KEM and ML-DSA channel handshake.
 *
 * The outer mbedTLS connection remains a standard TLS connection. This state
 * machine is an application protocol running inside TLS; it does not register
 * or claim a TLS PQC ciphersuite.
 */

#include <errno.h>
#include <string.h>

#include <psa/crypto.h>
#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/protected_channel.h>

#include "protected_channel_internal.h"
#include "runtime_internal.h"

#define PQCP_CHANNEL_AUTH_DOMAIN "PQCP channel auth v1"
#define PQCP_CHANNEL_AUTH_MESSAGE_BYTES 160U

static bool role_valid(enum pqcp_channel_role role)
{
	return role == PQCP_CHANNEL_ROLE_CLIENT ||
	       role == PQCP_CHANNEL_ROLE_SERVER;
}

static bool level_pair_valid(
	uint32_t mlkem_level,
	uint32_t mldsa_level)
{
	return pqcp_runtime_internal_level_valid(
		       PQCP_RUNTIME_KEY_MLKEM_KEYPAIR,
		       mlkem_level) &&
	       pqcp_runtime_internal_level_valid(
		       PQCP_RUNTIME_KEY_MLDSA_KEYPAIR,
		       mldsa_level);
}

static bool config_valid(
	const struct pqcp_channel_config *config)
{
	if (config == NULL ||
	    config->schema_version !=
		    PQCP_CHANNEL_SCHEMA_VERSION ||
	    !role_valid(config->role) ||
	    config->session_id == 0U ||
	    !level_pair_valid(
		    config->mlkem_level,
		    config->mldsa_level) ||
	    config->timeout_ms == 0U ||
	    config->max_payload_bytes == 0U ||
	    config->max_payload_bytes >
		    PQCP_CHANNEL_MAX_PAYLOAD_BYTES ||
	    !pqcp_runtime_key_handle_is_valid(
		    &config->local_identity) ||
	    config->local_identity.family !=
		    PQCP_RUNTIME_KEY_MLDSA_KEYPAIR ||
	    config->local_identity.level !=
		    config->mldsa_level ||
	    config->peer_identity_public_length !=
		    pqcp_mldsa_pk_size(
			    (pqcp_mldsa_level_t)
				    config->mldsa_level) ||
	    !pqcp_runtime_internal_text_valid(
		    config->profile_id,
		    sizeof(config->profile_id))) {
		return false;
	}
	return true;
}

static bool transport_valid(
	const struct pqcp_channel_transport *transport)
{
	return transport != NULL &&
	       transport->context != NULL &&
	       transport->send != NULL &&
	       transport->receive != NULL &&
	       transport->export_keying_material != NULL &&
	       transport->close != NULL;
}

const char *pqcp_channel_state_str(
	enum pqcp_channel_state state)
{
	switch (state) {
	case PQCP_CHANNEL_STATE_IDLE:
		return "IDLE";
	case PQCP_CHANNEL_STATE_TLS_READY:
		return "TLS_READY";
	case PQCP_CHANNEL_STATE_HELLO_SENT:
		return "HELLO_SENT";
	case PQCP_CHANNEL_STATE_HELLO_RECEIVED:
		return "HELLO_RECEIVED";
	case PQCP_CHANNEL_STATE_PROFILE_SELECTED:
		return "PROFILE_SELECTED";
	case PQCP_CHANNEL_STATE_KEM_EXCHANGED:
		return "KEM_EXCHANGED";
	case PQCP_CHANNEL_STATE_AUTHENTICATED:
		return "AUTHENTICATED";
	case PQCP_CHANNEL_STATE_FINISHED:
		return "FINISHED";
	case PQCP_CHANNEL_STATE_ESTABLISHED:
		return "ESTABLISHED";
	case PQCP_CHANNEL_STATE_CLOSING:
		return "CLOSING";
	case PQCP_CHANNEL_STATE_CLOSED:
		return "CLOSED";
	case PQCP_CHANNEL_STATE_FAILED:
		return "FAILED";
	default:
		return "UNKNOWN";
	}
}

const char *pqcp_channel_alert_str(
	enum pqcp_channel_alert alert)
{
	switch (alert) {
	case PQCP_CHANNEL_ALERT_NONE:
		return "none";
	case PQCP_CHANNEL_ALERT_BAD_FRAME:
		return "bad_frame";
	case PQCP_CHANNEL_ALERT_UNSUPPORTED_VERSION:
		return "unsupported_version";
	case PQCP_CHANNEL_ALERT_UNSUPPORTED_PROFILE:
		return "unsupported_profile";
	case PQCP_CHANNEL_ALERT_REPLAY:
		return "replay";
	case PQCP_CHANNEL_ALERT_SEQUENCE:
		return "sequence";
	case PQCP_CHANNEL_ALERT_AUTHENTICATION:
		return "authentication";
	case PQCP_CHANNEL_ALERT_FINISHED:
		return "finished";
	case PQCP_CHANNEL_ALERT_KEY_DERIVATION:
		return "key_derivation";
	case PQCP_CHANNEL_ALERT_INTERNAL:
		return "internal";
	case PQCP_CHANNEL_ALERT_TIMEOUT:
		return "timeout";
	default:
		return "unknown";
	}
}

int pqcp_channel_init(
	struct pqcp_channel *channel,
	const struct pqcp_channel_config *config,
	const struct pqcp_channel_transport *transport,
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_key_store *key_store)
{
	psa_status_t status;

	if (channel == NULL || !config_valid(config) ||
	    !transport_valid(transport) ||
	    executor == NULL || key_store == NULL ||
	    executor->key_store != key_store) {
		return -EINVAL;
	}
	memset(channel, 0, sizeof(*channel));
	channel->schema_version =
		PQCP_CHANNEL_SCHEMA_VERSION;
	channel->config = *config;
	channel->transport = *transport;
	channel->executor = executor;
	channel->key_store = key_store;
	channel->state = PQCP_CHANNEL_STATE_TLS_READY;
	channel->last_alert = PQCP_CHANNEL_ALERT_NONE;
	channel->handshake_started_ms =
		pqcp_runtime_internal_now_ms();
	if (pqcp_channel_transcript_init(
		    &channel->transcript) != 0 ||
	    pqcp_channel_replay_reset(
		    &channel->inbound_replay) != 0) {
		return -EIO;
	}
	status = psa_generate_random(
		channel->local_nonce,
		sizeof(channel->local_nonce));
	if (status != PSA_SUCCESS) {
		pqcp_runtime_secure_zero(
			channel, sizeof(*channel));
		return -EIO;
	}
	return 0;
}

int pqcp_channel_internal_create_public_key(
	struct pqcp_channel *channel,
	enum pqcp_runtime_key_family family,
	uint32_t level,
	const uint8_t *public_key,
	size_t public_key_length,
	const char *label,
	struct pqcp_runtime_key_handle *handle)
{
	struct pqcp_runtime_key_request request = {
		.family = family,
		.level = level,
		.usage =
			(family == PQCP_RUNTIME_KEY_MLKEM_PUBLIC ?
			 PQCP_RUNTIME_USAGE_ENCAPSULATE :
			 PQCP_RUNTIME_USAGE_VERIFY) |
			PQCP_RUNTIME_USAGE_EXPORT_PUBLIC |
			PQCP_RUNTIME_USAGE_DESTROY,
		.now_ms = pqcp_runtime_internal_now_ms(),
		.expires_at_ms =
			pqcp_runtime_internal_now_ms() +
			channel->config.timeout_ms * 2U,
		.owner = "channel",
		.label = label,
		.persistent = false,
		.exportable_public = true,
	};

	return pqcp_runtime_key_store_create(
		channel->key_store, &request,
		public_key, public_key_length,
		NULL, 0U, handle);
}

static int send_hello(
	struct pqcp_channel *channel,
	enum pqcp_channel_frame_type type)
{
	int ret = pqcp_channel_internal_encode_hello(
		channel, channel->local_nonce,
		channel->work_buffer);

	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_internal_send_frame(
		channel, type, 0U,
		channel->work_buffer,
		PQCP_CHANNEL_HELLO_BYTES, true);
	pqcp_runtime_secure_zero(
		channel->work_buffer,
		PQCP_CHANNEL_HELLO_BYTES);
	if (ret == 0) {
		channel->state = PQCP_CHANNEL_STATE_HELLO_SENT;
	}
	return ret;
}

static int receive_hello(
	struct pqcp_channel *channel,
	enum pqcp_channel_frame_type type)
{
	struct pqcp_channel_frame_header header;
	const uint8_t *payload = NULL;
	size_t payload_length = 0U;
	uint32_t mlkem_level;
	uint32_t mldsa_level;
	uint32_t flags;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	int ret;

	ret = pqcp_channel_internal_receive_frame(
		channel, type, &header, &payload,
		&payload_length, true);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_internal_decode_hello(
		payload, payload_length, &mlkem_level,
		&mldsa_level, &flags, channel->peer_nonce,
		profile_id);
	if (ret != 0) {
		return ret;
	}
	if (mlkem_level != channel->config.mlkem_level ||
	    mldsa_level != channel->config.mldsa_level ||
	    strcmp(profile_id, channel->config.profile_id) != 0) {
		return -ENOTSUP;
	}
	if (((flags & PQCP_CHANNEL_FLAG_MUTUAL_AUTH) != 0U) !=
	    channel->config.require_mutual_authentication) {
		return -EPROTO;
	}
	channel->state = PQCP_CHANNEL_STATE_HELLO_RECEIVED;
	return 0;
}

static int create_kem_keypair(
	struct pqcp_channel *channel)
{
	struct pqcp_runtime_job job;

	memset(&job, 0, sizeof(job));
	job.schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	job.job_id = channel->config.session_id ^ UINT64_C(0x4b454d01);
	job.session_id = channel->config.session_id;
	job.type = PQCP_RUNTIME_JOB_MLKEM_KEYGEN;
	job.priority = PQCP_RUNTIME_PRIORITY_CRITICAL;
	job.status = PQCP_RUNTIME_STATUS_IDLE;
	job.flags =
		PQCP_RUNTIME_JOB_FLAG_SYNCHRONOUS |
		PQCP_RUNTIME_JOB_FLAG_ZERO_OUTPUT_ON_FAILURE |
		PQCP_RUNTIME_JOB_FLAG_RECORD_ADAPTIVE_OBSERVATION;
	job.level = channel->config.mlkem_level;
	job.deadline_ms =
		pqcp_runtime_internal_now_ms() +
		channel->config.timeout_ms;
	job.key_request.family =
		PQCP_RUNTIME_KEY_MLKEM_KEYPAIR;
	job.key_request.level = channel->config.mlkem_level;
	job.key_request.usage =
		PQCP_RUNTIME_USAGE_ENCAPSULATE |
		PQCP_RUNTIME_USAGE_DECAPSULATE |
		PQCP_RUNTIME_USAGE_EXPORT_PUBLIC |
		PQCP_RUNTIME_USAGE_DESTROY;
	job.key_request.now_ms =
		pqcp_runtime_internal_now_ms();
	job.key_request.expires_at_ms =
		job.deadline_ms + channel->config.timeout_ms;
	job.key_request.owner = "channel";
	job.key_request.label = "ephemeral-kem";
	job.key_request.exportable_public = true;
	(void)pqcp_runtime_internal_copy_text(
		job.profile_id, sizeof(job.profile_id),
		channel->config.profile_id);
	int ret = pqcp_runtime_executor_submit(
		channel->executor, &job);

	if (ret == 0) {
		channel->ephemeral_kem_key = job.primary_key;
	}
	return ret;
}

static int server_send_kem_public_key(
	struct pqcp_channel *channel)
{
	size_t public_length = 0U;
	int ret = create_kem_keypair(channel);

	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_key_store_export_public(
		channel->key_store,
		&channel->ephemeral_kem_key,
		channel->work_buffer,
		sizeof(channel->work_buffer),
		&public_length);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_internal_send_frame(
		channel, PQCP_CHANNEL_FRAME_KEM_PUBLIC_KEY,
		0U, channel->work_buffer, public_length, true);
	pqcp_runtime_secure_zero(
		channel->work_buffer, public_length);
	return ret;
}

static int client_receive_and_encapsulate(
	struct pqcp_channel *channel)
{
	struct pqcp_channel_frame_header header;
	const uint8_t *public_key = NULL;
	size_t public_key_length = 0U;
	struct pqcp_runtime_key_handle public_handle;
	struct pqcp_runtime_job job;
	int ret;

	ret = pqcp_channel_internal_receive_frame(
		channel, PQCP_CHANNEL_FRAME_KEM_PUBLIC_KEY,
		&header, &public_key, &public_key_length, true);
	if (ret != 0) {
		return ret;
	}
	if (public_key_length !=
	    pqcp_mlkem_pk_size(
		    (pqcp_mlkem_level_t)
			    channel->config.mlkem_level)) {
		return -EMSGSIZE;
	}
	ret = pqcp_channel_internal_create_public_key(
		channel, PQCP_RUNTIME_KEY_MLKEM_PUBLIC,
		channel->config.mlkem_level,
		public_key, public_key_length,
		"peer-kem", &public_handle);
	if (ret != 0) {
		return ret;
	}
	memset(&job, 0, sizeof(job));
	job.schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	job.job_id =
		channel->config.session_id ^ UINT64_C(0x4b454d02);
	job.session_id = channel->config.session_id;
	job.type = PQCP_RUNTIME_JOB_MLKEM_ENCAPSULATE;
	job.priority = PQCP_RUNTIME_PRIORITY_CRITICAL;
	job.status = PQCP_RUNTIME_STATUS_IDLE;
	job.flags =
		PQCP_RUNTIME_JOB_FLAG_SYNCHRONOUS |
		PQCP_RUNTIME_JOB_FLAG_ZERO_OUTPUT_ON_FAILURE |
		PQCP_RUNTIME_JOB_FLAG_RECORD_ADAPTIVE_OBSERVATION;
	job.level = channel->config.mlkem_level;
	job.deadline_ms =
		pqcp_runtime_internal_now_ms() +
		channel->config.timeout_ms;
	job.primary_key = public_handle;
	job.output = channel->work_buffer;
	job.output_capacity = sizeof(channel->work_buffer);
	(void)pqcp_runtime_internal_copy_text(
		job.profile_id, sizeof(job.profile_id),
		channel->config.profile_id);
	ret = pqcp_runtime_executor_submit(
		channel->executor, &job);
	(void)pqcp_runtime_key_store_destroy(
		channel->key_store, &public_handle);
	if (ret != 0) {
		return ret;
	}
	channel->ephemeral_kem_key = job.secondary_key;
	ret = pqcp_channel_internal_send_frame(
		channel, PQCP_CHANNEL_FRAME_KEM_CIPHERTEXT,
		0U, channel->work_buffer,
		job.output_length, true);
	pqcp_runtime_secure_zero(
		channel->work_buffer, job.output_length);
	if (ret == 0) {
		channel->state =
			PQCP_CHANNEL_STATE_KEM_EXCHANGED;
	}
	return ret;
}

static int server_receive_and_decapsulate(
	struct pqcp_channel *channel)
{
	struct pqcp_channel_frame_header header;
	const uint8_t *ciphertext = NULL;
	size_t ciphertext_length = 0U;
	struct pqcp_runtime_key_handle keypair =
		channel->ephemeral_kem_key;
	struct pqcp_runtime_job job;
	int ret;

	ret = pqcp_channel_internal_receive_frame(
		channel, PQCP_CHANNEL_FRAME_KEM_CIPHERTEXT,
		&header, &ciphertext, &ciphertext_length, true);
	if (ret != 0) {
		return ret;
	}
	if (ciphertext_length !=
	    pqcp_mlkem_ct_size(
		    (pqcp_mlkem_level_t)
			    channel->config.mlkem_level)) {
		return -EMSGSIZE;
	}
	memset(&job, 0, sizeof(job));
	job.schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	job.job_id =
		channel->config.session_id ^ UINT64_C(0x4b454d03);
	job.session_id = channel->config.session_id;
	job.type = PQCP_RUNTIME_JOB_MLKEM_DECAPSULATE;
	job.priority = PQCP_RUNTIME_PRIORITY_CRITICAL;
	job.status = PQCP_RUNTIME_STATUS_IDLE;
	job.flags =
		PQCP_RUNTIME_JOB_FLAG_SYNCHRONOUS |
		PQCP_RUNTIME_JOB_FLAG_ZERO_OUTPUT_ON_FAILURE |
		PQCP_RUNTIME_JOB_FLAG_RECORD_ADAPTIVE_OBSERVATION;
	job.level = channel->config.mlkem_level;
	job.deadline_ms =
		pqcp_runtime_internal_now_ms() +
		channel->config.timeout_ms;
	job.primary_key = keypair;
	job.input = ciphertext;
	job.input_length = ciphertext_length;
	(void)pqcp_runtime_internal_copy_text(
		job.profile_id, sizeof(job.profile_id),
		channel->config.profile_id);
	ret = pqcp_runtime_executor_submit(
		channel->executor, &job);
	if (ret != 0) {
		return ret;
	}
	channel->ephemeral_kem_key = job.secondary_key;
	(void)pqcp_runtime_key_store_destroy(
		channel->key_store, &keypair);
	channel->state = PQCP_CHANNEL_STATE_KEM_EXCHANGED;
	return 0;
}

static int build_auth_message(
	struct pqcp_channel *channel,
	enum pqcp_channel_role signer,
	uint8_t output[PQCP_CHANNEL_AUTH_MESSAGE_BYTES],
	size_t *output_length)
{
	uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES];
	size_t offset = 0U;
	const size_t domain_length =
		sizeof(PQCP_CHANNEL_AUTH_DOMAIN) - 1U;
	const size_t profile_length = strnlen(
		channel->config.profile_id,
		sizeof(channel->config.profile_id));
	int ret;

	ret = pqcp_channel_transcript_digest(
		&channel->transcript, transcript_hash);
	if (ret != 0) {
		return ret;
	}
	memset(output, 0, PQCP_CHANNEL_AUTH_MESSAGE_BYTES);
	memcpy(output + offset,
	       PQCP_CHANNEL_AUTH_DOMAIN, domain_length);
	offset += domain_length;
	output[offset++] = (uint8_t)signer;
	pqcp_runtime_internal_write_u64(
		output + offset, channel->config.session_id);
	offset += 8U;
	pqcp_runtime_internal_write_u32(
		output + offset, channel->config.mlkem_level);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		output + offset, channel->config.mldsa_level);
	offset += 4U;
	memcpy(output + offset, channel->keys.exporter,
	       PQCP_CHANNEL_EXPORTER_BYTES);
	offset += PQCP_CHANNEL_EXPORTER_BYTES;
	memcpy(output + offset, transcript_hash,
	       sizeof(transcript_hash));
	offset += sizeof(transcript_hash);
	output[offset++] = (uint8_t)profile_length;
	memcpy(output + offset,
	       channel->config.profile_id, profile_length);
	offset += profile_length;
	*output_length = offset;
	pqcp_runtime_secure_zero(
		transcript_hash, sizeof(transcript_hash));
	return 0;
}

static int sign_auth(
	struct pqcp_channel *channel,
	enum pqcp_channel_role signer,
	uint8_t *signature,
	size_t signature_capacity,
	size_t *signature_length)
{
	uint8_t auth_message[PQCP_CHANNEL_AUTH_MESSAGE_BYTES];
	struct pqcp_runtime_job job;
	size_t auth_length = 0U;
	int ret;

	ret = build_auth_message(
		channel, signer, auth_message,
		&auth_length);
	if (ret != 0) {
		return ret;
	}
	memset(&job, 0, sizeof(job));
	job.schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	job.job_id =
		channel->config.session_id ^
		(signer == PQCP_CHANNEL_ROLE_SERVER ?
		 UINT64_C(0x41555448) :
		 UINT64_C(0x41555449));
	job.session_id = channel->config.session_id;
	job.type = PQCP_RUNTIME_JOB_MLDSA_SIGN;
	job.priority = PQCP_RUNTIME_PRIORITY_CRITICAL;
	job.status = PQCP_RUNTIME_STATUS_IDLE;
	job.flags =
		PQCP_RUNTIME_JOB_FLAG_SYNCHRONOUS |
		PQCP_RUNTIME_JOB_FLAG_ZERO_OUTPUT_ON_FAILURE |
		PQCP_RUNTIME_JOB_FLAG_RECORD_ADAPTIVE_OBSERVATION;
	job.level = channel->config.mldsa_level;
	job.deadline_ms =
		pqcp_runtime_internal_now_ms() +
		channel->config.timeout_ms;
	job.primary_key = channel->config.local_identity;
	job.input = auth_message;
	job.input_length = auth_length;
	job.context = (const uint8_t *)"pqcp-channel-v1";
	job.context_length = 15U;
	job.output = signature;
	job.output_capacity = signature_capacity;
	(void)pqcp_runtime_internal_copy_text(
		job.profile_id, sizeof(job.profile_id),
		channel->config.profile_id);
	ret = pqcp_runtime_executor_submit(
		channel->executor, &job);
	pqcp_runtime_secure_zero(
		auth_message, sizeof(auth_message));
	if (ret == 0) {
		*signature_length = job.output_length;
	}
	return ret;
}

static int verify_auth(
	struct pqcp_channel *channel,
	enum pqcp_channel_role signer,
	const uint8_t *signature,
	size_t signature_length)
{
	struct pqcp_runtime_key_handle peer_handle;
	struct pqcp_runtime_job job;
	size_t auth_length = 0U;
	int ret;

	ret = build_auth_message(
		channel, signer, channel->work_buffer,
		&auth_length);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_internal_create_public_key(
		channel, PQCP_RUNTIME_KEY_MLDSA_PUBLIC,
		channel->config.mldsa_level,
		channel->config.peer_identity_public,
		channel->config.peer_identity_public_length,
		"peer-identity", &peer_handle);
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			channel->work_buffer, auth_length);
		return ret;
	}
	memset(&job, 0, sizeof(job));
	job.schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	job.job_id =
		channel->config.session_id ^
		(signer == PQCP_CHANNEL_ROLE_SERVER ?
		 UINT64_C(0x56455253) :
		 UINT64_C(0x56455243));
	job.session_id = channel->config.session_id;
	job.type = PQCP_RUNTIME_JOB_MLDSA_VERIFY;
	job.priority = PQCP_RUNTIME_PRIORITY_CRITICAL;
	job.status = PQCP_RUNTIME_STATUS_IDLE;
	job.flags =
		PQCP_RUNTIME_JOB_FLAG_SYNCHRONOUS |
		PQCP_RUNTIME_JOB_FLAG_RECORD_ADAPTIVE_OBSERVATION;
	job.level = channel->config.mldsa_level;
	job.deadline_ms =
		pqcp_runtime_internal_now_ms() +
		channel->config.timeout_ms;
	job.primary_key = peer_handle;
	job.input = channel->work_buffer;
	job.input_length = auth_length;
	job.aux_input = signature;
	job.aux_input_length = signature_length;
	job.context = (const uint8_t *)"pqcp-channel-v1";
	job.context_length = 15U;
	(void)pqcp_runtime_internal_copy_text(
		job.profile_id, sizeof(job.profile_id),
		channel->config.profile_id);
	ret = pqcp_runtime_executor_submit(
		channel->executor, &job);
	(void)pqcp_runtime_key_store_destroy(
		channel->key_store, &peer_handle);
	pqcp_runtime_secure_zero(
		channel->work_buffer, auth_length);
	return ret;
}

static int send_auth(
	struct pqcp_channel *channel,
	enum pqcp_channel_role signer,
	enum pqcp_channel_frame_type type)
{
	size_t signature_length = 0U;
	int ret = sign_auth(
		channel, signer, channel->work_buffer,
		sizeof(channel->work_buffer),
		&signature_length);

	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_internal_send_frame(
		channel, type, 0U,
		channel->work_buffer,
		signature_length, true);
	pqcp_runtime_secure_zero(
		channel->work_buffer, signature_length);
	if (ret == 0) {
		channel->local_authenticated = true;
	}
	return ret;
}

static int receive_auth(
	struct pqcp_channel *channel,
	enum pqcp_channel_role signer,
	enum pqcp_channel_frame_type type)
{
	struct pqcp_channel_frame_header header;
	const uint8_t *signature = NULL;
	size_t signature_length = 0U;
	size_t frame_length;
	int ret;

	ret = pqcp_channel_internal_receive_frame(
		channel, type, &header, &signature,
		&signature_length, false);
	if (ret != 0) {
		return ret;
	}
	if (signature_length !=
	    pqcp_mldsa_sig_size(
		    (pqcp_mldsa_level_t)
			    channel->config.mldsa_level)) {
		return -EMSGSIZE;
	}
	ret = verify_auth(
		channel, signer, signature, signature_length);
	if (ret != 0) {
		return ret;
	}
	frame_length = PQCP_CHANNEL_FRAME_HEADER_BYTES +
		       signature_length;
	ret = pqcp_channel_transcript_update(
		&channel->transcript,
		channel->rx_frame, frame_length);
	if (ret == 0) {
		channel->peer_authenticated = true;
	}
	return ret;
}

static int send_finished(
	struct pqcp_channel *channel,
	enum pqcp_channel_role sender)
{
	uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES];
	uint8_t finished[PQCP_CHANNEL_FINISHED_BYTES];
	int ret;

	ret = pqcp_channel_transcript_digest(
		&channel->transcript, transcript_hash);
	if (ret == 0) {
		ret = pqcp_channel_internal_finished(
			channel, sender, transcript_hash, finished);
	}
	if (ret == 0) {
		ret = pqcp_channel_internal_send_frame(
			channel, PQCP_CHANNEL_FRAME_FINISHED,
			(uint32_t)sender, finished,
			sizeof(finished), true);
	}
	pqcp_runtime_secure_zero(
		transcript_hash, sizeof(transcript_hash));
	pqcp_runtime_secure_zero(finished, sizeof(finished));
	return ret;
}

static int receive_finished(
	struct pqcp_channel *channel,
	enum pqcp_channel_role sender)
{
	struct pqcp_channel_frame_header header;
	const uint8_t *received = NULL;
	size_t received_length = 0U;
	uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES];
	uint8_t expected[PQCP_CHANNEL_FINISHED_BYTES] = { 0 };
	int ret;

	ret = pqcp_channel_internal_receive_frame(
		channel, PQCP_CHANNEL_FRAME_FINISHED,
		&header, &received, &received_length, false);
	if (ret != 0) {
		return ret;
	}
	if (header.flags != (uint32_t)sender ||
	    received_length != PQCP_CHANNEL_FINISHED_BYTES) {
		return -EBADMSG;
	}
	ret = pqcp_channel_transcript_digest(
		&channel->transcript, transcript_hash);
	if (ret == 0) {
		ret = pqcp_channel_internal_finished(
			channel, sender, transcript_hash, expected);
	}
	if (ret == 0 &&
	    memcmp(received, expected, sizeof(expected)) != 0) {
		ret = -EKEYREJECTED;
	}
	if (ret == 0) {
		const size_t frame_length =
			PQCP_CHANNEL_FRAME_HEADER_BYTES +
			received_length;

		ret = pqcp_channel_transcript_update(
			&channel->transcript,
			channel->rx_frame, frame_length);
	}
	pqcp_runtime_secure_zero(
		transcript_hash, sizeof(transcript_hash));
	pqcp_runtime_secure_zero(expected, sizeof(expected));
	return ret;
}

static int client_handshake(
	struct pqcp_channel *channel)
{
	int ret;

	ret = send_hello(
		channel, PQCP_CHANNEL_FRAME_CLIENT_HELLO);
	if (ret == 0) {
		ret = receive_hello(
			channel, PQCP_CHANNEL_FRAME_SERVER_HELLO);
	}
	if (ret == 0) {
		channel->state =
			PQCP_CHANNEL_STATE_PROFILE_SELECTED;
		ret = pqcp_channel_internal_export(channel);
	}
	if (ret == 0) {
		ret = client_receive_and_encapsulate(channel);
	}
	if (ret == 0) {
		ret = receive_auth(
			channel, PQCP_CHANNEL_ROLE_SERVER,
			PQCP_CHANNEL_FRAME_SERVER_AUTH);
	}
	if (ret == 0 &&
	    channel->config.require_mutual_authentication) {
		ret = send_auth(
			channel, PQCP_CHANNEL_ROLE_CLIENT,
			PQCP_CHANNEL_FRAME_CLIENT_AUTH);
	}
	if (ret == 0) {
		channel->state =
			PQCP_CHANNEL_STATE_AUTHENTICATED;
		ret = pqcp_channel_internal_derive_keys(channel);
	}
	if (ret == 0) {
		ret = receive_finished(
			channel, PQCP_CHANNEL_ROLE_SERVER);
	}
	if (ret == 0) {
		ret = send_finished(
			channel, PQCP_CHANNEL_ROLE_CLIENT);
	}
	return ret;
}

static int server_handshake(
	struct pqcp_channel *channel)
{
	int ret;

	ret = receive_hello(
		channel, PQCP_CHANNEL_FRAME_CLIENT_HELLO);
	if (ret == 0) {
		ret = send_hello(
			channel, PQCP_CHANNEL_FRAME_SERVER_HELLO);
	}
	if (ret == 0) {
		channel->state =
			PQCP_CHANNEL_STATE_PROFILE_SELECTED;
		ret = pqcp_channel_internal_export(channel);
	}
	if (ret == 0) {
		ret = server_send_kem_public_key(channel);
	}
	if (ret == 0) {
		ret = server_receive_and_decapsulate(channel);
	}
	if (ret == 0) {
		ret = send_auth(
			channel, PQCP_CHANNEL_ROLE_SERVER,
			PQCP_CHANNEL_FRAME_SERVER_AUTH);
	}
	if (ret == 0 &&
	    channel->config.require_mutual_authentication) {
		ret = receive_auth(
			channel, PQCP_CHANNEL_ROLE_CLIENT,
			PQCP_CHANNEL_FRAME_CLIENT_AUTH);
	}
	if (ret == 0) {
		channel->state =
			PQCP_CHANNEL_STATE_AUTHENTICATED;
		ret = pqcp_channel_internal_derive_keys(channel);
	}
	if (ret == 0) {
		ret = send_finished(
			channel, PQCP_CHANNEL_ROLE_SERVER);
	}
	if (ret == 0) {
		ret = receive_finished(
			channel, PQCP_CHANNEL_ROLE_CLIENT);
	}
	return ret;
}

static enum pqcp_channel_alert alert_for_error(int error)
{
	switch (error) {
	case -ETIMEDOUT:
		return PQCP_CHANNEL_ALERT_TIMEOUT;
	case -EALREADY:
		return PQCP_CHANNEL_ALERT_REPLAY;
	case -ERANGE:
		return PQCP_CHANNEL_ALERT_SEQUENCE;
	case -ENOTSUP:
		return PQCP_CHANNEL_ALERT_UNSUPPORTED_PROFILE;
	case -EKEYREJECTED:
	case -EBADMSG:
		return PQCP_CHANNEL_ALERT_AUTHENTICATION;
	default:
		return PQCP_CHANNEL_ALERT_INTERNAL;
	}
}

int pqcp_channel_handshake(struct pqcp_channel *channel)
{
	int ret;

	if (channel == NULL ||
	    channel->schema_version !=
		    PQCP_CHANNEL_SCHEMA_VERSION ||
	    channel->state != PQCP_CHANNEL_STATE_TLS_READY) {
		return -EINVAL;
	}
	ret = channel->config.role == PQCP_CHANNEL_ROLE_CLIENT ?
		client_handshake(channel) :
		server_handshake(channel);
	if (ret != 0) {
		return pqcp_channel_internal_fail(
			channel, alert_for_error(ret), ret);
	}
	channel->state = PQCP_CHANNEL_STATE_FINISHED;
	channel->handshake_completed_ms =
		pqcp_runtime_internal_now_ms();
	channel->established = true;
	channel->state = PQCP_CHANNEL_STATE_ESTABLISHED;
	return 0;
}

int pqcp_channel_internal_send_application(
	struct pqcp_channel *channel,
	const uint8_t *plaintext,
	size_t plaintext_length,
	bool allow_blocked)
{
	size_t ciphertext_length = 0U;
	int ret;

	if (channel == NULL || !channel->established ||
	    channel->state != PQCP_CHANNEL_STATE_ESTABLISHED ||
	    (!allow_blocked &&
	     channel->application_send_blocked) ||
	    (plaintext == NULL && plaintext_length != 0U) ||
	    plaintext_length >
		    channel->config.max_payload_bytes) {
		return channel != NULL &&
			       channel->application_send_blocked &&
			       !allow_blocked ?
			       -EBUSY : -EINVAL;
	}
	ret = pqcp_channel_internal_encrypt_record(
		channel, plaintext, plaintext_length,
		channel->work_buffer,
		sizeof(channel->work_buffer),
		&ciphertext_length);
	if (ret == 0) {
		ret = pqcp_channel_internal_send_frame(
			channel, PQCP_CHANNEL_FRAME_APPLICATION,
			0U, channel->work_buffer,
			ciphertext_length, false);
	}
	pqcp_runtime_secure_zero(
		channel->work_buffer, ciphertext_length);
	/* Even control records may have been partially transmitted. Never retry
	 * with the same sequence/nonce after an uncertain transport failure.
	 */
	if (ret != 0) {
		return pqcp_channel_internal_fail(
			channel, alert_for_error(ret), ret);
	}
	channel->application_bytes_sent += plaintext_length;
	return 0;
}

int pqcp_channel_send(
	struct pqcp_channel *channel,
	const uint8_t *plaintext,
	size_t plaintext_length)
{
	return pqcp_channel_internal_send_application(
		channel, plaintext, plaintext_length, false);
}

int pqcp_channel_receive(
	struct pqcp_channel *channel,
	uint8_t *plaintext,
	size_t plaintext_capacity,
	size_t *plaintext_length)
{
	struct pqcp_channel_frame_header header;
	const uint8_t *ciphertext = NULL;
	size_t ciphertext_length = 0U;
	int ret;

	if (channel == NULL || !channel->established ||
	    channel->state != PQCP_CHANNEL_STATE_ESTABLISHED ||
	    plaintext == NULL || plaintext_length == NULL) {
		return -EINVAL;
	}
	*plaintext_length = 0U;
	pqcp_runtime_secure_zero(plaintext, plaintext_capacity);
	ret = pqcp_channel_internal_receive_frame(
		channel, PQCP_CHANNEL_FRAME_APPLICATION,
		&header, &ciphertext, &ciphertext_length, false);
	if (ret == 0) {
		ret = pqcp_channel_internal_decrypt_record(
			channel, header.sequence,
			ciphertext, ciphertext_length,
			plaintext, plaintext_capacity,
			plaintext_length);
	}
	if (ret != 0) {
		*plaintext_length = 0U;
		pqcp_runtime_secure_zero(plaintext, plaintext_capacity);
		return pqcp_channel_internal_fail(
			channel, alert_for_error(ret), ret);
	}
	channel->application_bytes_received +=
		*plaintext_length;
	return 0;
}

int pqcp_channel_close(struct pqcp_channel *channel)
{
	int ret = 0;
	int cleanup_ret;

	if (channel == NULL ||
	    channel->schema_version !=
		    PQCP_CHANNEL_SCHEMA_VERSION) {
		return -EINVAL;
	}
	if (channel->state == PQCP_CHANNEL_STATE_CLOSED) {
		return 0;
	}
	channel->state = PQCP_CHANNEL_STATE_CLOSING;
	if (channel->established) {
		ret = pqcp_channel_internal_send_frame(
			channel, PQCP_CHANNEL_FRAME_CLOSE,
			0U, NULL, 0U, false);
	}
	cleanup_ret = pqcp_channel_internal_discard_keys(channel);
	if (cleanup_ret != 0) {
		ret = cleanup_ret;
	}
	if (channel->transport.close != NULL) {
		int close_ret = channel->transport.close(
			channel->transport.context);

		if (ret == 0) {
			ret = close_ret;
		}
	}
	channel->state = cleanup_ret == 0 ? PQCP_CHANNEL_STATE_CLOSED :
		PQCP_CHANNEL_STATE_FAILED;
	return ret;
}

int pqcp_channel_audit(const struct pqcp_channel *channel)
{
	bool peer_authentication_required;
	bool local_authentication_required;

	if (channel == NULL ||
	    channel->schema_version !=
		    PQCP_CHANNEL_SCHEMA_VERSION ||
	    !config_valid(&channel->config) ||
	    !transport_valid(&channel->transport) ||
	    channel->executor == NULL ||
	    channel->key_store == NULL ||
	    channel->send_sequence != channel->frames_sent ||
	    channel->receive_sequence !=
		    channel->frames_received ||
	    channel->transcript.schema_version !=
		    PQCP_CHANNEL_SCHEMA_VERSION ||
	    !channel->transcript.initialized) {
		return -EINVAL;
	}
	peer_authentication_required =
		channel->config.role == PQCP_CHANNEL_ROLE_CLIENT ||
		channel->config.require_mutual_authentication;
	local_authentication_required =
		channel->config.role == PQCP_CHANNEL_ROLE_SERVER ||
		channel->config.require_mutual_authentication;
	if (channel->established &&
	    (channel->state !=
		     PQCP_CHANNEL_STATE_ESTABLISHED ||
	     !channel->keys.traffic_keys_ready ||
	     !pqcp_runtime_key_handle_is_valid(
		     &channel->keys.client_write_key) ||
	     !pqcp_runtime_key_handle_is_valid(
		     &channel->keys.server_write_key) ||
	     (peer_authentication_required &&
	      !channel->peer_authenticated) ||
	     (local_authentication_required &&
	      !channel->local_authenticated) ||
	     channel->handshake_completed_ms <
		     channel->handshake_started_ms)) {
		return -EBADMSG;
	}
	if (channel->state == PQCP_CHANNEL_STATE_FAILED &&
	    channel->last_alert == PQCP_CHANNEL_ALERT_NONE) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_channel_emit(const struct pqcp_channel *channel)
{
	uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES];
	char transcript_hex[PQCP_RUNTIME_DIGEST_HEX_CHARS + 1U];
	int ret = pqcp_channel_audit(channel);

	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_transcript_digest(
		&channel->transcript, transcript_hash);
	if (ret == 0) {
		ret = pqcp_runtime_internal_hex(
			transcript_hash, sizeof(transcript_hash),
			transcript_hex, sizeof(transcript_hex));
	}
	if (ret != 0) {
		return ret;
	}
	printk("PQCP_PROTECTED_CHANNEL schema=%u status=%s role=%s session=%llu profile=%s mlkem=%u mldsa=%u peer_authenticated=%u mutual=%u frames_sent=%llu frames_received=%llu app_sent=%llu app_received=%llu failures=%u alert=%s transcript=%s\n",
	       channel->schema_version,
	       pqcp_channel_state_str(channel->state),
	       channel->config.role == PQCP_CHANNEL_ROLE_CLIENT ?
		       "client" : "server",
	       (unsigned long long)channel->config.session_id,
	       channel->config.profile_id,
	       channel->config.mlkem_level,
	       channel->config.mldsa_level,
	       channel->peer_authenticated ? 1U : 0U,
	       channel->config.require_mutual_authentication ? 1U : 0U,
	       (unsigned long long)channel->frames_sent,
	       (unsigned long long)channel->frames_received,
	       (unsigned long long)channel->application_bytes_sent,
	       (unsigned long long)channel->application_bytes_received,
	       channel->failure_count,
	       pqcp_channel_alert_str(channel->last_alert),
	       transcript_hex);
	pqcp_runtime_secure_zero(
		transcript_hash, sizeof(transcript_hash));
	return 0;
}
