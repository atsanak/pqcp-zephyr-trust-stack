/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Append-only hash-chained deployment evidence trail.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_evidence_trail.h>

static bool text_present(const char *value)
{
	return value != NULL && value[0] != '\0';
}

static bool text_marker_safe(const char *value)
{
	if (!text_present(value)) {
		return false;
	}
	for (const char *p = value; *p != '\0'; ++p) {
		if (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') {
			return false;
		}
	}

	return true;
}

static bool profile_valid(enum pqcp_deployment_release_gate_profile profile)
{
	return profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER;
}

static bool trail_status_valid(
	enum pqcp_deployment_evidence_trail_status status)
{
	return status == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_PASS ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARN ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_FAIL;
}

static bool stage_valid(enum pqcp_deployment_evidence_trail_stage stage)
{
	return (uint32_t)stage < PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_COUNT;
}

static bool is_lower_hex_len(const char *value, size_t expected_len)
{
	if (value == NULL || strlen(value) != expected_len) {
		return false;
	}
	for (size_t i = 0U; i < expected_len; ++i) {
		const char c = value[i];

		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
			return false;
		}
	}

	return true;
}

static bool nonce_valid(const char *value)
{
	return is_lower_hex_len(value,
				PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS);
}

static bool digest_valid(const char *value)
{
	return is_lower_hex_len(
		value, PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS);
}

static void set_text(char *dst, size_t dst_size, const char *src)
{
	if (dst == NULL || dst_size == 0U) {
		return;
	}
	(void)snprintk(dst, dst_size, "%s", src != NULL ? src : "");
}

/* ------------------------------------------------------------------ */
/* Trail link digest                                                   */
/* ------------------------------------------------------------------ */

static void digest_init(uint64_t digest[4])
{
	digest[0] = 0xe7037ed1a0b428dbULL;
	digest[1] = 0x8ebc6af09c88c6e3ULL;
	digest[2] = 0x9e3779b97f4a7c15ULL;
	digest[3] = 0x589965cc75374cc3ULL;
}

static uint64_t rotl64(uint64_t value, uint32_t bits)
{
	return (value << bits) | (value >> (64U - bits));
}

static void digest_update_byte(uint64_t digest[4], uint8_t value)
{
	digest[0] ^= (uint64_t)value + 0x100000001b3ULL;
	digest[0] *= 0x100000001b3ULL;
	digest[1] += digest[0] ^ ((uint64_t)value << 9U);
	digest[1] = rotl64(digest[1], 21U) * 0x9e3779b185ebca87ULL;
	digest[2] ^= digest[1] + digest[0] + 0x94d049bb133111ebULL;
	digest[2] = rotl64(digest[2], 33U);
	digest[3] += digest[2] ^ (digest[1] >> 15U);
	digest[3] = rotl64(digest[3], 45U);
}

static void digest_update_u32(uint64_t digest[4], uint32_t value)
{
	for (uint32_t shift = 0U; shift < 32U; shift += 8U) {
		digest_update_byte(digest, (uint8_t)(value >> shift));
	}
}

static void digest_update_text(uint64_t digest[4], const char *value)
{
	if (value == NULL) {
		value = "";
	}
	for (const char *p = value; *p != '\0'; ++p) {
		digest_update_byte(digest, (uint8_t)*p);
	}
	digest_update_byte(digest, (uint8_t)'|');
}

static void digest_to_hex(
	const uint64_t digest[4],
	char out[PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U])
{
	(void)snprintk(
		out,
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U,
		"%016llx%016llx%016llx%016llx",
		(unsigned long long)digest[0],
		(unsigned long long)digest[1],
		(unsigned long long)digest[2],
		(unsigned long long)digest[3]);
}

/*
 * Genesis link: binds the chain identity so two trails from different
 * sessions can never share link digests even for identical stage digests.
 */
static void compute_genesis_link(
	enum pqcp_deployment_release_gate_profile profile,
	const char *top_candidate_id,
	const char *nonce_hex,
	char out[PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U])
{
	uint64_t digest[4];

	digest_init(digest);
	digest_update_u32(digest,
			  PQCP_DEPLOYMENT_EVIDENCE_TRAIL_SCHEMA_VERSION);
	digest_update_text(digest, "genesis");
	digest_update_u32(digest, (uint32_t)profile);
	digest_update_text(digest, top_candidate_id);
	digest_update_text(digest, nonce_hex);
	digest_to_hex(digest, out);
}

static void compute_entry_link(
	const char *previous_link_hex,
	uint32_t sequence,
	enum pqcp_deployment_evidence_trail_stage stage,
	const char *digest_hex,
	char out[PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U])
{
	uint64_t digest[4];

	digest_init(digest);
	digest_update_u32(digest,
			  PQCP_DEPLOYMENT_EVIDENCE_TRAIL_SCHEMA_VERSION);
	digest_update_text(digest, "link");
	digest_update_text(digest, previous_link_hex);
	digest_update_u32(digest, sequence);
	digest_update_text(digest,
			   pqcp_deployment_evidence_trail_stage_str(stage));
	digest_update_text(digest, digest_hex);
	digest_to_hex(digest, out);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

const char *pqcp_deployment_evidence_trail_status_str(
	enum pqcp_deployment_evidence_trail_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

const char *pqcp_deployment_evidence_trail_stage_str(
	enum pqcp_deployment_evidence_trail_stage stage)
{
	switch (stage) {
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_VERDICT:
		return "verdict";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_SEAL:
		return "seal";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_SEAL_AUDIT:
		return "seal_audit";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_PASSPORT:
		return "passport";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_TAMPER_MATRIX:
		return "tamper_matrix";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_CUSTOM:
		return "custom";
	default:
		return "unknown";
	}
}

int pqcp_deployment_evidence_trail_default_policy(
	struct pqcp_deployment_evidence_trail_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}

	memset(policy, 0, sizeof(*policy));
	policy->min_entries = 3U;
	policy->required_stage_mask =
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_BIT(
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_VERDICT) |
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_BIT(
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_SEAL) |
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_BIT(
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_PASSPORT);
	policy->min_entries_blocks = true;

	return 0;
}

int pqcp_deployment_evidence_trail_init(
	struct pqcp_deployment_evidence_trail *trail,
	enum pqcp_deployment_release_gate_profile profile,
	const char *top_candidate_id,
	const char *nonce_hex)
{
	if (trail == NULL || !profile_valid(profile) ||
	    !text_marker_safe(top_candidate_id) ||
	    strlen(top_candidate_id) >= PQCP_DEPLOYMENT_ID_MAX_CHARS ||
	    !nonce_valid(nonce_hex)) {
		return -EINVAL;
	}

	memset(trail, 0, sizeof(*trail));
	trail->schema_version = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_SCHEMA_VERSION;
	trail->status = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_FAIL;
	trail->profile = profile;
	set_text(trail->top_candidate_id, sizeof(trail->top_candidate_id),
		 top_candidate_id);
	set_text(trail->nonce_hex, sizeof(trail->nonce_hex), nonce_hex);
	compute_genesis_link(profile, trail->top_candidate_id,
			     trail->nonce_hex, trail->head_digest_hex);

	return 0;
}

int pqcp_deployment_evidence_trail_append(
	struct pqcp_deployment_evidence_trail *trail,
	struct pqcp_deployment_evidence_trail_entry *entries,
	size_t max_entries,
	enum pqcp_deployment_evidence_trail_stage stage,
	const char *digest_hex)
{
	struct pqcp_deployment_evidence_trail_entry *entry;

	if (trail == NULL || entries == NULL ||
	    trail->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_SCHEMA_VERSION ||
	    !stage_valid(stage) || !digest_valid(digest_hex)) {
		return -EINVAL;
	}
	if (trail->entry_count >= PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES ||
	    (size_t)trail->entry_count >= max_entries) {
		return -ENOSPC;
	}

	entry = &entries[trail->entry_count];
	memset(entry, 0, sizeof(*entry));
	entry->schema_version = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_SCHEMA_VERSION;
	entry->sequence = trail->entry_count;
	entry->stage = stage;
	set_text(entry->digest_hex, sizeof(entry->digest_hex), digest_hex);
	compute_entry_link(trail->head_digest_hex, entry->sequence, stage,
			   entry->digest_hex, entry->link_digest_hex);

	set_text(trail->head_digest_hex, sizeof(trail->head_digest_hex),
		 entry->link_digest_hex);
	trail->observed_stage_mask |=
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_BIT(stage);
	trail->entry_count++;

	return 0;
}

int pqcp_deployment_evidence_trail_finish(
	struct pqcp_deployment_evidence_trail *trail,
	const struct pqcp_deployment_evidence_trail_policy *policy)
{
	if (trail == NULL ||
	    trail->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_SCHEMA_VERSION) {
		return -EINVAL;
	}
	if (policy == NULL ||
	    policy->min_entries >
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES ||
	    (policy->required_stage_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_KNOWN_MASK) != 0U) {
		trail->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_INVALID_INPUT;
		trail->status = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_FAIL;
		return -EINVAL;
	}

	trail->error_mask = 0U;
	trail->warning_mask = 0U;
	trail->required_stage_mask = policy->required_stage_mask;

	if (trail->entry_count == 0U) {
		trail->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_NO_ENTRIES;
	}
	if (trail->entry_count < policy->min_entries) {
		if (policy->min_entries_blocks) {
			trail->error_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_MIN_ENTRIES;
		} else {
			trail->warning_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARNING_LOW_ENTRY_COUNT;
		}
	}
	if ((trail->observed_stage_mask & policy->required_stage_mask) !=
	    policy->required_stage_mask) {
		trail->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_MISSING_STAGE;
	}
	if ((trail->observed_stage_mask &
	     PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_BIT(
		     PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_CUSTOM)) != 0U) {
		trail->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARNING_CUSTOM_STAGE;
	}

	if (trail->error_mask != 0U) {
		trail->status = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_FAIL;
	} else if (trail->warning_mask != 0U) {
		trail->status = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARN;
	} else {
		trail->status = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_PASS;
	}

	return trail->status == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_FAIL ?
		-EBADMSG : 0;
}

int pqcp_deployment_evidence_trail_entry_emit(
	const struct pqcp_deployment_evidence_trail_entry *entry)
{
	if (entry == NULL ||
	    entry->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_SCHEMA_VERSION ||
	    entry->sequence >= PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES ||
	    !stage_valid(entry->stage) ||
	    !digest_valid(entry->digest_hex) ||
	    !digest_valid(entry->link_digest_hex)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ENTRY schema=%u seq=%u stage=%s digest=%s link=%s\n",
	       entry->schema_version,
	       entry->sequence,
	       pqcp_deployment_evidence_trail_stage_str(entry->stage),
	       entry->digest_hex,
	       entry->link_digest_hex);

	return 0;
}

int pqcp_deployment_evidence_trail_emit(
	const struct pqcp_deployment_evidence_trail *trail)
{
	if (trail == NULL ||
	    trail->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_SCHEMA_VERSION ||
	    !trail_status_valid(trail->status) ||
	    !profile_valid(trail->profile) ||
	    (trail->error_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_KNOWN_MASK) != 0U ||
	    (trail->warning_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARNING_KNOWN_MASK) != 0U ||
	    trail->entry_count > PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES ||
	    (trail->observed_stage_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_KNOWN_MASK) != 0U ||
	    (trail->required_stage_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_KNOWN_MASK) != 0U ||
	    !text_present(trail->top_candidate_id) ||
	    !nonce_valid(trail->nonce_hex) ||
	    !digest_valid(trail->head_digest_hex)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_EVIDENCE_TRAIL schema=%u profile=%s status=%s errors=0x%08x warnings=0x%08x entries=%u required_stages=0x%02x observed_stages=0x%02x top=%s nonce=%s head_digest=%s\n",
	       trail->schema_version,
	       pqcp_deployment_release_gate_profile_str(trail->profile),
	       pqcp_deployment_evidence_trail_status_str(trail->status),
	       trail->error_mask,
	       trail->warning_mask,
	       trail->entry_count,
	       trail->required_stage_mask,
	       trail->observed_stage_mask,
	       trail->top_candidate_id,
	       trail->nonce_hex,
	       trail->head_digest_hex);

	return trail->status == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_FAIL ?
		-EBADMSG : 0;
}
