/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Dual-slot runtime checkpoints containing references and measurements only.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_operations.h>

#include "runtime_internal.h"

#define CHECKPOINT_SECTION_SESSIONS 1U
#define CHECKPOINT_SECTION_PROFILES 2U
#define CHECKPOINT_SECTION_KEYS 3U
#define CHECKPOINT_SECTION_IDENTITIES 4U
#define CHECKPOINT_SECTION_TRAILER 0xffffU
#define CHECKPOINT_SESSION_BYTES 128U
#define CHECKPOINT_PROFILE_BYTES 128U
#define CHECKPOINT_KEY_BYTES 96U
#define CHECKPOINT_IDENTITY_BYTES 128U

struct checkpoint_writer {
	uint8_t *buffer;
	size_t capacity;
	size_t offset;
	int error;
};

static void writer_bytes(
	struct checkpoint_writer *writer,
	const void *value,
	size_t length)
{
	if (writer->error != 0) {
		return;
	}
	if (value == NULL || writer->offset > writer->capacity ||
	    length > writer->capacity - writer->offset) {
		writer->error = -ENOSPC;
		return;
	}
	memcpy(writer->buffer + writer->offset, value, length);
	writer->offset += length;
}

static void writer_zero(
	struct checkpoint_writer *writer,
	size_t length)
{
	if (writer->error != 0) {
		return;
	}
	if (writer->offset > writer->capacity ||
	    length > writer->capacity - writer->offset) {
		writer->error = -ENOSPC;
		return;
	}
	memset(writer->buffer + writer->offset, 0, length);
	writer->offset += length;
}

static void writer_u16(
	struct checkpoint_writer *writer,
	uint16_t value)
{
	uint8_t bytes[2];

	pqcp_runtime_internal_write_u16(bytes, value);
	writer_bytes(writer, bytes, sizeof(bytes));
}

static void writer_u32(
	struct checkpoint_writer *writer,
	uint32_t value)
{
	uint8_t bytes[4];

	pqcp_runtime_internal_write_u32(bytes, value);
	writer_bytes(writer, bytes, sizeof(bytes));
}

static void writer_u64(
	struct checkpoint_writer *writer,
	uint64_t value)
{
	uint8_t bytes[8];

	pqcp_runtime_internal_write_u64(bytes, value);
	writer_bytes(writer, bytes, sizeof(bytes));
}

static void writer_text(
	struct checkpoint_writer *writer,
	const char *text,
	size_t capacity)
{
	size_t length;

	if (text == NULL ||
	    !pqcp_runtime_internal_text_valid(text, capacity)) {
		writer->error = -EINVAL;
		return;
	}
	length = strlen(text);
	writer_u16(writer, (uint16_t)length);
	writer_bytes(writer, text, length);
}

static int header_encode(
	const struct pqcp_runtime_checkpoint_header *header,
	uint8_t output[PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES])
{
	if (header == NULL || output == NULL ||
	    header->magic != PQCP_RUNTIME_CHECKPOINT_MAGIC ||
	    header->format_version !=
		    PQCP_RUNTIME_CHECKPOINT_FORMAT_VERSION ||
	    header->header_bytes !=
		    PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES) {
		return -EINVAL;
	}
	memset(output, 0, PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES);
	pqcp_runtime_internal_write_u32(output, header->magic);
	pqcp_runtime_internal_write_u16(
		output + 4U, header->format_version);
	pqcp_runtime_internal_write_u16(
		output + 6U, header->header_bytes);
	pqcp_runtime_internal_write_u32(
		output + 8U, header->payload_bytes);
	pqcp_runtime_internal_write_u32(
		output + 12U, header->flags);
	pqcp_runtime_internal_write_u64(
		output + 16U, header->generation);
	pqcp_runtime_internal_write_u64(
		output + 24U, header->created_at_ms);
	pqcp_runtime_internal_write_u64(
		output + 32U, header->runtime_epoch);
	pqcp_runtime_internal_write_u32(
		output + 40U, header->session_count);
	pqcp_runtime_internal_write_u32(
		output + 44U, header->profile_count);
	pqcp_runtime_internal_write_u32(
		output + 48U, header->key_reference_count);
	pqcp_runtime_internal_write_u32(
		output + 52U, header->identity_count);
	memcpy(output + 56U, header->previous_digest,
	       sizeof(header->previous_digest));
	memcpy(output + 88U, header->payload_digest,
	       sizeof(header->payload_digest));
	return 0;
}

static int header_decode(
	const uint8_t input[PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES],
	struct pqcp_runtime_checkpoint_header *header)
{
	if (input == NULL || header == NULL) {
		return -EINVAL;
	}
	memset(header, 0, sizeof(*header));
	header->magic = pqcp_runtime_internal_read_u32(input);
	header->format_version =
		pqcp_runtime_internal_read_u16(input + 4U);
	header->header_bytes =
		pqcp_runtime_internal_read_u16(input + 6U);
	header->payload_bytes =
		pqcp_runtime_internal_read_u32(input + 8U);
	header->flags =
		pqcp_runtime_internal_read_u32(input + 12U);
	header->generation =
		pqcp_runtime_internal_read_u64(input + 16U);
	header->created_at_ms =
		pqcp_runtime_internal_read_u64(input + 24U);
	header->runtime_epoch =
		pqcp_runtime_internal_read_u64(input + 32U);
	header->session_count =
		pqcp_runtime_internal_read_u32(input + 40U);
	header->profile_count =
		pqcp_runtime_internal_read_u32(input + 44U);
	header->key_reference_count =
		pqcp_runtime_internal_read_u32(input + 48U);
	header->identity_count =
		pqcp_runtime_internal_read_u32(input + 52U);
	memcpy(header->previous_digest, input + 56U,
	       sizeof(header->previous_digest));
	memcpy(header->payload_digest, input + 88U,
	       sizeof(header->payload_digest));
	if (header->magic != PQCP_RUNTIME_CHECKPOINT_MAGIC ||
	    header->format_version !=
		    PQCP_RUNTIME_CHECKPOINT_FORMAT_VERSION ||
	    header->header_bytes !=
		    PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES ||
	    header->generation == 0U ||
	    header->created_at_ms == 0U) {
		return -EBADMSG;
	}
	return 0;
}

static void write_section_header(
	struct checkpoint_writer *writer,
	uint16_t type,
	uint16_t record_bytes,
	uint32_t record_count)
{
	writer_u16(writer, type);
	writer_u16(writer, record_bytes);
	writer_u32(writer, record_count);
}

static void write_key_handle(
	struct checkpoint_writer *writer,
	const struct pqcp_runtime_key_handle *handle)
{
	writer_u32(writer, handle->slot);
	writer_u32(writer, handle->generation);
	writer_u32(writer, (uint32_t)handle->family);
	writer_u32(writer, handle->level);
	writer_u32(writer, (uint32_t)handle->backend);
}

static void write_session(
	struct checkpoint_writer *writer,
	const struct pqcp_runtime_session *session)
{
	const size_t start = writer->offset;

	writer_u32(writer, session->schema_version);
	writer_u64(writer, session->session_id);
	writer_text(writer, session->profile_id,
		    sizeof(session->profile_id));
	writer_u32(writer, session->mlkem_level);
	writer_u32(writer, session->mldsa_level);
	writer_u64(writer, session->opened_at_ms);
	writer_u64(writer, session->expires_at_ms);
	writer_u64(writer, session->jobs_submitted);
	writer_u64(writer, session->jobs_completed);
	writer_u64(writer, session->failures);
	write_key_handle(writer, &session->kem_key);
	write_key_handle(writer, &session->signing_key);
	writer_u32(
		writer,
		(session->active ? BIT(0) : 0U) |
		(session->draining ? BIT(1) : 0U) |
		(session->protected_channel ? BIT(2) : 0U));
	if (writer->error == 0 &&
	    writer->offset - start < CHECKPOINT_SESSION_BYTES) {
		writer_zero(
			writer,
			CHECKPOINT_SESSION_BYTES -
				(writer->offset - start));
	}
}

static void write_profile(
	struct checkpoint_writer *writer,
	const struct pqcp_runtime_profile_state *profile)
{
	const size_t start = writer->offset;

	writer_u32(writer, profile->schema_version);
	writer_text(writer, profile->profile_id,
		    sizeof(profile->profile_id));
	writer_u32(writer, (uint32_t)profile->latency_source);
	writer_u32(writer, (uint32_t)profile->cycles_source);
	writer_u32(writer, (uint32_t)profile->memory_source);
	writer_u32(writer, (uint32_t)profile->energy_source);
	writer_u32(writer, profile->observation_count);
	writer_u32(writer, profile->successful_observations);
	writer_u32(writer, profile->failed_observations);
	writer_u64(writer, profile->latency_ewma_us);
	writer_u64(writer, profile->cycles_ewma);
	writer_u64(writer, profile->stack_high_watermark);
	writer_u64(writer, profile->workspace_high_watermark);
	writer_u64(writer, profile->last_observed_at_ms);
	if (writer->error == 0 &&
	    writer->offset - start < CHECKPOINT_PROFILE_BYTES) {
		writer_zero(
			writer,
			CHECKPOINT_PROFILE_BYTES -
				(writer->offset - start));
	}
}

static void write_key_reference(
	struct checkpoint_writer *writer,
	const struct pqcp_runtime_volatile_slot *slot)
{
	const size_t start = writer->offset;
	uint8_t public_digest[PQCP_RUNTIME_DIGEST_BYTES];

	memset(public_digest, 0, sizeof(public_digest));
	if (slot->public_length != 0U) {
		if (pqcp_runtime_internal_sha256(
			    slot->public_data, slot->public_length,
			    public_digest) != 0) {
			writer->error = -EIO;
			return;
		}
	}
	writer_u32(writer, slot->metadata.schema_version);
	write_key_handle(writer, &slot->metadata.handle);
	writer_u32(writer, slot->metadata.usage);
	writer_u64(writer, slot->metadata.created_at_ms);
	writer_u64(writer, slot->metadata.expires_at_ms);
	writer_u64(writer, slot->metadata.last_used_at_ms);
	writer_u32(writer, slot->metadata.use_count);
	writer_u32(writer, slot->references);
	writer_u32(writer, (uint32_t)slot->public_length);
	writer_u32(writer, (uint32_t)slot->secret_length);
	writer_bytes(writer, public_digest, sizeof(public_digest));
	if (writer->error == 0 &&
	    writer->offset - start < CHECKPOINT_KEY_BYTES) {
		writer_zero(
			writer,
			CHECKPOINT_KEY_BYTES -
				(writer->offset - start));
	}
}

static void write_identity(
	struct checkpoint_writer *writer,
	const struct pqcp_runtime_identity *identity)
{
	const size_t start = writer->offset;

	writer_u32(writer, identity->schema_version);
	writer_text(writer, identity->identity_id,
		    sizeof(identity->identity_id));
	writer_u32(writer, identity->mldsa_level);
	write_key_handle(writer, &identity->local_key);
	writer_u32(writer,
		   (uint32_t)identity->peer_public_key_length);
	writer_bytes(writer, identity->fingerprint,
		     sizeof(identity->fingerprint));
	writer_u64(writer, identity->created_at_ms);
	writer_u64(writer, identity->expires_at_ms);
	writer_u32(writer, identity->use_count);
	writer_u32(
		writer,
		(identity->active ? BIT(0) : 0U) |
		(identity->local ? BIT(1) : 0U) |
		(identity->trusted ? BIT(2) : 0U) |
		(identity->rotation_pending ? BIT(3) : 0U));
	if (writer->error == 0 &&
	    writer->offset - start < CHECKPOINT_IDENTITY_BYTES) {
		writer_zero(
			writer,
			CHECKPOINT_IDENTITY_BYTES -
				(writer->offset - start));
	}
}

static uint32_t count_active_sessions(
	const struct pqcp_runtime_service *service)
{
	uint32_t count = 0U;

	for (size_t index = 0U;
	     index < service->sessions.capacity; ++index) {
		if (service->sessions.sessions[index].active) {
			count++;
		}
	}
	return count;
}

static uint32_t count_profiles(
	const struct pqcp_runtime_service *service)
{
	uint32_t count = 0U;

	for (size_t index = 0U;
	     index < service->executor.profile_state_capacity;
	     ++index) {
		if (service->executor.profile_states[index].
			    schema_version ==
		    PQCP_RUNTIME_SCHEMA_VERSION) {
			count++;
		}
	}
	return count;
}

static uint32_t count_key_references(
	const struct pqcp_runtime_service *service)
{
	uint32_t count = 0U;

	if (service->key_store.backend !=
	    PQCP_RUNTIME_KEY_BACKEND_VOLATILE) {
		return service->key_store.active_count;
	}
	for (size_t index = 0U;
	     index < service->volatile_context.slot_count; ++index) {
			if (service->volatile_context.slots[index].
				    metadata.active) {
			count++;
		}
	}
	return count;
}

static uint32_t count_identities(
	const struct pqcp_runtime_service *service)
{
	uint32_t count = 0U;

	for (size_t index = 0U;
	     index < service->identities.capacity; ++index) {
		if (service->identities.identities[index].active) {
			count++;
		}
	}
	return count;
}

static int write_payload(
	struct checkpoint_writer *writer,
	const struct pqcp_runtime_service *service,
	const struct pqcp_runtime_checkpoint_header *header)
{
	write_section_header(
		writer, CHECKPOINT_SECTION_SESSIONS,
		CHECKPOINT_SESSION_BYTES, header->session_count);
	for (size_t index = 0U;
	     index < service->sessions.capacity; ++index) {
		const struct pqcp_runtime_session *session =
			&service->sessions.sessions[index];

		if (session->active) {
			write_session(writer, session);
		}
	}
	write_section_header(
		writer, CHECKPOINT_SECTION_PROFILES,
		CHECKPOINT_PROFILE_BYTES, header->profile_count);
	for (size_t index = 0U;
	     index < service->executor.profile_state_capacity;
	     ++index) {
		const struct pqcp_runtime_profile_state *profile =
			&service->executor.profile_states[index];

		if (profile->schema_version ==
		    PQCP_RUNTIME_SCHEMA_VERSION) {
			write_profile(writer, profile);
		}
	}
	write_section_header(
		writer, CHECKPOINT_SECTION_KEYS,
		CHECKPOINT_KEY_BYTES,
		header->key_reference_count);
	if (service->key_store.backend ==
	    PQCP_RUNTIME_KEY_BACKEND_VOLATILE) {
		for (size_t index = 0U;
		     index < service->volatile_context.slot_count;
		     ++index) {
			const struct pqcp_runtime_volatile_slot *slot =
				&service->volatile_context.slots[index];

				if (slot->metadata.active) {
				write_key_reference(writer, slot);
			}
		}
	}
	write_section_header(
		writer, CHECKPOINT_SECTION_IDENTITIES,
		CHECKPOINT_IDENTITY_BYTES, header->identity_count);
	for (size_t index = 0U;
	     index < service->identities.capacity; ++index) {
		const struct pqcp_runtime_identity *identity =
			&service->identities.identities[index];

		if (identity->active) {
			write_identity(writer, identity);
		}
	}
	write_section_header(
		writer, CHECKPOINT_SECTION_TRAILER, 0U, 0U);
	return writer->error;
}

int pqcp_runtime_checkpoint_store_init(
	struct pqcp_runtime_checkpoint_store *store,
	struct pqcp_runtime_checkpoint_slot *slots,
	size_t slot_count)
{
	if (store == NULL || slots == NULL || slot_count < 2U) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < slot_count; ++index) {
		if (slots[index].buffer == NULL ||
		    slots[index].capacity <
			    PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES +
				    8U) {
			return -EINVAL;
		}
		slots[index].length = 0U;
		slots[index].generation = 0U;
		slots[index].valid = false;
		memset(slots[index].buffer, 0,
		       slots[index].capacity);
	}
	memset(store, 0, sizeof(*store));
	store->slots = slots;
	store->slot_count = slot_count;
	store->next_generation = 1U;
	k_mutex_init(&store->lock);
	store->initialized = true;
	return 0;
}

int pqcp_runtime_checkpoint_write(
	struct pqcp_runtime_checkpoint_store *store,
	const struct pqcp_runtime_service *service,
	uint64_t now_ms,
	uint64_t runtime_epoch,
	uint32_t flags,
	struct pqcp_runtime_checkpoint_header *header)
{
	struct pqcp_runtime_checkpoint_slot *slot;
	struct pqcp_runtime_checkpoint_header prepared;
	struct checkpoint_writer writer;
	uint8_t encoded[PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES];
	uint8_t payload_digest[PQCP_RUNTIME_DIGEST_BYTES];
	size_t target;
	int ret;

	if (store == NULL || !store->initialized ||
	    service == NULL || !service->initialized ||
	    now_ms == 0U || runtime_epoch == 0U ||
	    header == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&store->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	target = (store->active_slot + 1U) % store->slot_count;
	slot = &store->slots[target];
	memset(slot->buffer, 0, slot->capacity);
	memset(&prepared, 0, sizeof(prepared));
	prepared.magic = PQCP_RUNTIME_CHECKPOINT_MAGIC;
	prepared.format_version =
		PQCP_RUNTIME_CHECKPOINT_FORMAT_VERSION;
	prepared.header_bytes =
		PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES;
	prepared.flags = flags;
	prepared.generation = store->next_generation++;
	prepared.created_at_ms = now_ms;
	prepared.runtime_epoch = runtime_epoch;
	prepared.session_count = count_active_sessions(service);
	prepared.profile_count = count_profiles(service);
	prepared.key_reference_count =
		count_key_references(service);
	prepared.identity_count = count_identities(service);
	memcpy(prepared.previous_digest, store->chain_head,
	       sizeof(prepared.previous_digest));
	writer.buffer = slot->buffer;
	writer.capacity = slot->capacity;
	writer.offset = PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES;
	writer.error = 0;
	ret = write_payload(&writer, service, &prepared);
	if (ret == 0) {
		prepared.payload_bytes =
			(uint32_t)(writer.offset -
				   PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES);
		ret = pqcp_runtime_internal_sha256(
			slot->buffer +
				PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES,
			prepared.payload_bytes, payload_digest);
	}
	if (ret == 0) {
		memcpy(prepared.payload_digest, payload_digest,
		       sizeof(prepared.payload_digest));
		ret = header_encode(&prepared, encoded);
	}
	if (ret == 0) {
		memcpy(slot->buffer, encoded, sizeof(encoded));
		slot->length = writer.offset;
		slot->generation = prepared.generation;
		slot->valid = true;
		store->active_slot = target;
		memcpy(store->chain_head, payload_digest,
		       sizeof(store->chain_head));
		*header = prepared;
	} else {
		memset(slot->buffer, 0, slot->capacity);
		slot->length = 0U;
		slot->generation = 0U;
		slot->valid = false;
	}
	(void)k_mutex_unlock(&store->lock);
	return ret;
}

int pqcp_runtime_checkpoint_read(
	struct pqcp_runtime_checkpoint_store *store,
	uint64_t generation,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length,
	struct pqcp_runtime_checkpoint_header *header)
{
	int ret;

	if (store == NULL || !store->initialized ||
	    generation == 0U || output == NULL ||
	    output_length == NULL || header == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&store->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < store->slot_count; ++index) {
		const struct pqcp_runtime_checkpoint_slot *slot =
			&store->slots[index];

		if (!slot->valid ||
		    slot->generation != generation) {
			continue;
		}
		if (output_capacity < slot->length) {
			(void)k_mutex_unlock(&store->lock);
			return -ENOSPC;
		}
		ret = pqcp_runtime_checkpoint_verify(
			slot->buffer, slot->length, header);
		if (ret == 0) {
			memcpy(output, slot->buffer, slot->length);
			*output_length = slot->length;
		}
		(void)k_mutex_unlock(&store->lock);
		return ret;
	}
	(void)k_mutex_unlock(&store->lock);
	return -ENOENT;
}

int pqcp_runtime_checkpoint_verify(
	const uint8_t *checkpoint,
	size_t checkpoint_length,
	struct pqcp_runtime_checkpoint_header *header)
{
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES];
	int ret;

	if (checkpoint == NULL ||
	    checkpoint_length <
		    PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES ||
	    header == NULL) {
		return -EINVAL;
	}
	ret = header_decode(checkpoint, header);
	if (ret != 0) {
		return ret;
	}
	if (header->payload_bytes !=
	    checkpoint_length -
		    PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES) {
		return -EBADMSG;
	}
	ret = pqcp_runtime_internal_sha256(
		checkpoint +
			PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES,
		header->payload_bytes, digest);
	if (ret != 0) {
		return ret;
	}
	if (memcmp(digest, header->payload_digest,
		   sizeof(digest)) != 0) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_runtime_checkpoint_store_audit(
	struct pqcp_runtime_checkpoint_store *store)
{
	uint64_t highest_generation = 0U;
	size_t valid_count = 0U;
	int ret;

	if (store == NULL || !store->initialized ||
	    store->slots == NULL || store->slot_count < 2U ||
	    store->active_slot >= store->slot_count ||
	    store->next_generation == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&store->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < store->slot_count; ++index) {
		const struct pqcp_runtime_checkpoint_slot *slot =
			&store->slots[index];
		struct pqcp_runtime_checkpoint_header header;

		if (!slot->valid) {
			if (slot->length != 0U ||
			    slot->generation != 0U) {
				ret = -EBADMSG;
				break;
			}
			continue;
		}
		if (slot->length >
			    slot->capacity ||
		    slot->generation == 0U ||
		    pqcp_runtime_checkpoint_verify(
			    slot->buffer, slot->length,
			    &header) != 0 ||
		    header.generation != slot->generation) {
			ret = -EBADMSG;
			break;
		}
		valid_count++;
		if (slot->generation > highest_generation) {
			highest_generation = slot->generation;
		}
	}
	if (ret == 0 && valid_count != 0U) {
		const struct pqcp_runtime_checkpoint_slot *active =
			&store->slots[store->active_slot];

		if (!active->valid ||
		    active->generation != highest_generation ||
		    store->next_generation <= highest_generation) {
			ret = -EBADMSG;
		}
	}
	(void)k_mutex_unlock(&store->lock);
	return ret;
}
