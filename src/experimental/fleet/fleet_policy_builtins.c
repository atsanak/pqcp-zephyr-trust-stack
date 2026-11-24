/*
 * SPDX-License-Identifier: MIT
 *
 * Portable fleet-policy built-ins.
 *
 * The standard library is selected by passing descriptors == NULL and
 * descriptor_count == 0 to pqcp_fleet_policy_builtin_registry_init().
 * Standard built-in identifiers are stable ABI values in the range 1..16.
 * Custom descriptor tables remain supported.
 *
 * Stateful built-ins share the caller-provided builtin-state scratch buffer.
 * The buffer is self-describing, contains no pointers, and is accessed through
 * memcpy so callers do not need to provide stronger-than-byte alignment.
 */

#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_policy_vm.h>

#define BUILTIN_SECURE_BOOT UINT32_C(1)
#define BUILTIN_MEASUREMENT UINT32_C(2)
#define BUILTIN_CREDENTIAL_FRESHNESS UINT32_C(3)
#define BUILTIN_CHANNEL_IDENTITY UINT32_C(4)
#define BUILTIN_ENTROPY_TIME_QUALITY UINT32_C(5)
#define BUILTIN_NOT_REVOKED_OR_LOCKED UINT32_C(6)
#define BUILTIN_SEMVER_EPOCH UINT32_C(7)
#define BUILTIN_CAPABILITY_SETS UINT32_C(8)
#define BUILTIN_MAINTENANCE_WINDOW UINT32_C(9)
#define BUILTIN_COHORT UINT32_C(10)
#define BUILTIN_RISK_BAND UINT32_C(11)
#define BUILTIN_SLIDING_RATE UINT32_C(12)
#define BUILTIN_FIXED_RATE UINT32_C(13)
#define BUILTIN_TOKEN_RATE UINT32_C(14)
#define BUILTIN_REPLAY_FRESHNESS UINT32_C(15)
#define BUILTIN_MIGRATION_UPDATE UINT32_C(16)
#define BUILTIN_DEPENDENCY_QUORUM UINT32_C(17)
#define BUILTIN_REQUIRED_CLAIMS UINT32_C(18)

#define BUILTIN_KNOWN_FLAGS \
	(PQCP_FLEET_POLICY_BUILTIN_DETERMINISTIC | \
	 PQCP_FLEET_POLICY_BUILTIN_PURE)

#define BUILTIN_STATE_MAGIC UINT32_C(0x50464253)
#define BUILTIN_STATE_VERSION UINT16_C(1)
#define BUILTIN_HOST_ABI_VERSION UINT32_C(1)
#define BUILTIN_SEMVER_MAX_BYTES UINT32_C(96)

struct builtin_rate_sample {
	uint64_t timestamp;
	uint64_t cost;
};

/*
 * Persistent state header stored at the front of builtin_state.scratch.
 * Sliding-window samples immediately follow this header.
 */
struct builtin_scratch_header {
	uint32_t magic;
	uint16_t version;
	uint16_t reserved;

	uint32_t sliding_head;
	uint32_t sliding_count;
	uint64_t sliding_total;
	uint64_t sliding_window;
	uint64_t sliding_limit;
	uint8_t sliding_initialized;
	uint8_t sliding_reserved[7];

	uint64_t fixed_started;
	uint64_t fixed_used;
	uint64_t fixed_window;
	uint64_t fixed_limit;
	uint8_t fixed_initialized;
	uint8_t fixed_reserved[7];

	uint64_t token_last;
	uint64_t token_available;
	uint64_t token_capacity;
	uint64_t token_refill;
	uint64_t token_period;
	uint8_t token_initialized;
	uint8_t token_reserved[7];

	uint64_t replay_sequence;
	uint8_t replay_initialized;
	uint8_t replay_reserved[7];
};

/*
 * application_context for BUILTIN_COHORT is expected to begin with this
 * stable view. Keeping the view private avoids coupling the built-ins to an
 * application-specific cohort implementation.
 */
typedef int (*builtin_cohort_callback)(
	void *context,
	const uint8_t *device_digest,
	uint32_t device_digest_length,
	const uint8_t *policy_digest,
	uint32_t policy_digest_length,
	uint32_t *cohort_basis_points);

struct builtin_host_view {
	uint32_t abi_version;
	uint32_t size;
	void *context;
	builtin_cohort_callback cohort;
};

struct semver_view {
	const uint8_t *data;
	uint32_t length;
	uint32_t offset;
	uint64_t core[3];
	bool has_prerelease;
	uint32_t prerelease_offset;
	uint32_t prerelease_length;
};

static bool value_type_valid(uint32_t type)
{
	return type >= PQCP_FLEET_POLICY_VALUE_I64 &&
	       type <= PQCP_FLEET_POLICY_VALUE_DIGEST;
}

static bool value_valid(const struct pqcp_fleet_policy_value *value)
{
	if (value == NULL || value->reserved != 0U ||
	    !value_type_valid(value->type)) {
		return false;
	}
	if (value->type == PQCP_FLEET_POLICY_VALUE_BYTES ||
	    value->type == PQCP_FLEET_POLICY_VALUE_DIGEST) {
		if (value->as.bytes.length != 0U &&
		    value->as.bytes.data == NULL) {
			return false;
		}
		if (value->type == PQCP_FLEET_POLICY_VALUE_DIGEST &&
		    value->as.bytes.length !=
			    PQCP_FLEET_POLICY_DIGEST_BYTES) {
			return false;
		}
	}
	return true;
}

static void result_bool(
	struct pqcp_fleet_policy_value *result, bool value)
{
	memset(result, 0, sizeof(*result));
	result->type = PQCP_FLEET_POLICY_VALUE_BOOL;
	result->as.boolean = value;
}

static void result_u64(
	struct pqcp_fleet_policy_value *result, uint64_t value)
{
	memset(result, 0, sizeof(*result));
	result->type = PQCP_FLEET_POLICY_VALUE_U64;
	result->as.u64 = value;
}

static int require_call(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	uint32_t expected_count,
	struct pqcp_fleet_policy_value *result)
{
	(void)context;

	if (state == NULL || arguments == NULL || result == NULL ||
	    argument_count != expected_count) {
		return PQCP_FLEET_POLICY_ERR_INVALID_ARGUMENT;
	}
	for (uint32_t index = 0U; index < argument_count; ++index) {
		if (!value_valid(&arguments[index])) {
			return PQCP_FLEET_POLICY_ERR_TYPE;
		}
	}
	return PQCP_FLEET_POLICY_OK;
}

static bool bytes_equal(
	const struct pqcp_fleet_policy_bytes *left,
	const struct pqcp_fleet_policy_bytes *right)
{
	uint8_t difference = 0U;

	if (left->length != right->length) {
		return false;
	}
	for (uint32_t index = 0U; index < left->length; ++index) {
		difference |= left->data[index] ^ right->data[index];
	}
	return difference == 0U;
}

static int builtin_secure_boot(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	int status = require_call(
		context, state, arguments, argument_count, 2U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	result_bool(result, arguments[0].as.boolean &&
			    arguments[1].as.boolean);
	return PQCP_FLEET_POLICY_OK;
}

static int builtin_measurement(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	int status = require_call(
		context, state, arguments, argument_count, 3U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	result_bool(result,
		    arguments[2].as.boolean &&
		    bytes_equal(&arguments[0].as.bytes,
				&arguments[1].as.bytes));
	return PQCP_FLEET_POLICY_OK;
}

static int builtin_credential_freshness(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	uint64_t now;
	uint64_t issued;
	uint64_t expires;
	uint64_t maximum_age;
	bool fresh = false;
	int status = require_call(
		context, state, arguments, argument_count, 4U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	now = arguments[0].as.u64;
	issued = arguments[1].as.u64;
	expires = arguments[2].as.u64;
	maximum_age = arguments[3].as.u64;

	if (maximum_age != 0U && issued <= now && now < expires &&
	    issued < expires && now - issued <= maximum_age) {
		fresh = true;
	}
	result_bool(result, fresh);
	return PQCP_FLEET_POLICY_OK;
}

static int builtin_channel_identity(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	int status = require_call(
		context, state, arguments, argument_count, 4U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	result_bool(result,
		    arguments[0].as.boolean &&
		    arguments[1].as.boolean &&
		    bytes_equal(&arguments[2].as.bytes,
				&arguments[3].as.bytes));
	return PQCP_FLEET_POLICY_OK;
}

static int builtin_entropy_time_quality(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	int status = require_call(
		context, state, arguments, argument_count, 6U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	result_bool(result,
		    arguments[0].as.u64 >= arguments[1].as.u64 &&
		    arguments[2].as.u64 >= arguments[3].as.u64 &&
		    arguments[4].as.u64 <= arguments[5].as.u64);
	return PQCP_FLEET_POLICY_OK;
}

static int builtin_not_revoked_or_locked(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	int status = require_call(
		context, state, arguments, argument_count, 2U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	result_bool(result, !arguments[0].as.boolean &&
			    !arguments[1].as.boolean);
	return PQCP_FLEET_POLICY_OK;
}

static bool ascii_digit(uint8_t value)
{
	return value >= (uint8_t)'0' && value <= (uint8_t)'9';
}

static bool ascii_alpha(uint8_t value)
{
	return (value >= (uint8_t)'a' && value <= (uint8_t)'z') ||
	       (value >= (uint8_t)'A' && value <= (uint8_t)'Z');
}

static bool semver_identifier_char(uint8_t value)
{
	return ascii_digit(value) || ascii_alpha(value) ||
	       value == (uint8_t)'-';
}

static int semver_parse_number(
	struct semver_view *view, uint64_t *number)
{
	uint32_t start = view->offset;
	uint64_t value = 0U;

	if (start >= view->length ||
	    !ascii_digit(view->data[start])) {
		return PQCP_FLEET_POLICY_ERR_TYPE;
	}
	if (view->data[start] == (uint8_t)'0' &&
	    start + 1U < view->length &&
	    ascii_digit(view->data[start + 1U])) {
		return PQCP_FLEET_POLICY_ERR_TYPE;
	}
	while (view->offset < view->length &&
	       ascii_digit(view->data[view->offset])) {
		uint64_t digit =
			(uint64_t)(view->data[view->offset] -
				   (uint8_t)'0');

		if (value > (UINT64_MAX - digit) / 10U) {
			return PQCP_FLEET_POLICY_ERR_OVERFLOW;
		}
		value = value * 10U + digit;
		view->offset++;
	}
	*number = value;
	return PQCP_FLEET_POLICY_OK;
}

static int semver_validate_identifiers(
	const uint8_t *data, uint32_t length,
	bool reject_numeric_leading_zero)
{
	uint32_t offset = 0U;

	if (length == 0U) {
		return PQCP_FLEET_POLICY_ERR_TYPE;
	}
	while (offset < length) {
		uint32_t start = offset;
		bool numeric = true;

		while (offset < length && data[offset] != (uint8_t)'.') {
			if (!semver_identifier_char(data[offset])) {
				return PQCP_FLEET_POLICY_ERR_TYPE;
			}
			if (!ascii_digit(data[offset])) {
				numeric = false;
			}
			offset++;
		}
		if (offset == start) {
			return PQCP_FLEET_POLICY_ERR_TYPE;
		}
		if (reject_numeric_leading_zero && numeric &&
		    offset - start > 1U &&
		    data[start] == (uint8_t)'0') {
			return PQCP_FLEET_POLICY_ERR_TYPE;
		}
		if (offset < length) {
			offset++;
			if (offset == length) {
				return PQCP_FLEET_POLICY_ERR_TYPE;
			}
		}
	}
	return PQCP_FLEET_POLICY_OK;
}

static int semver_parse(
	const struct pqcp_fleet_policy_bytes *bytes,
	struct semver_view *view)
{
	int status;

	if (bytes == NULL || view == NULL || bytes->data == NULL ||
	    bytes->length == 0U ||
	    bytes->length > BUILTIN_SEMVER_MAX_BYTES) {
		return PQCP_FLEET_POLICY_ERR_TYPE;
	}
	memset(view, 0, sizeof(*view));
	view->data = bytes->data;
	view->length = bytes->length;

	for (uint32_t index = 0U; index < 3U; ++index) {
		status = semver_parse_number(view, &view->core[index]);
		if (status != PQCP_FLEET_POLICY_OK) {
			return status;
		}
		if (index < 2U) {
			if (view->offset >= view->length ||
			    view->data[view->offset] != (uint8_t)'.') {
				return PQCP_FLEET_POLICY_ERR_TYPE;
			}
			view->offset++;
		}
	}
	if (view->offset < view->length &&
	    view->data[view->offset] == (uint8_t)'-') {
		uint32_t start = ++view->offset;

		while (view->offset < view->length &&
		       view->data[view->offset] != (uint8_t)'+') {
			view->offset++;
		}
		view->has_prerelease = true;
		view->prerelease_offset = start;
		view->prerelease_length = view->offset - start;
		status = semver_validate_identifiers(
			view->data + start,
			view->prerelease_length, true);
		if (status != PQCP_FLEET_POLICY_OK) {
			return status;
		}
	}
	if (view->offset < view->length &&
	    view->data[view->offset] == (uint8_t)'+') {
		uint32_t start = ++view->offset;

		view->offset = view->length;
		status = semver_validate_identifiers(
			view->data + start,
			view->length - start, false);
		if (status != PQCP_FLEET_POLICY_OK) {
			return status;
		}
	}
	return view->offset == view->length ?
		PQCP_FLEET_POLICY_OK : PQCP_FLEET_POLICY_ERR_TYPE;
}

static int byte_slice_compare(
	const uint8_t *left, uint32_t left_length,
	const uint8_t *right, uint32_t right_length)
{
	uint32_t common = left_length < right_length ?
		left_length : right_length;

	for (uint32_t index = 0U; index < common; ++index) {
		if (left[index] < right[index]) {
			return -1;
		}
		if (left[index] > right[index]) {
			return 1;
		}
	}
	if (left_length < right_length) {
		return -1;
	}
	if (left_length > right_length) {
		return 1;
	}
	return 0;
}

static bool identifier_numeric(
	const uint8_t *data, uint32_t length)
{
	for (uint32_t index = 0U; index < length; ++index) {
		if (!ascii_digit(data[index])) {
			return false;
		}
	}
	return true;
}

static int semver_prerelease_compare(
	const struct semver_view *left,
	const struct semver_view *right)
{
	uint32_t left_offset = left->prerelease_offset;
	uint32_t right_offset = right->prerelease_offset;
	uint32_t left_end = left_offset + left->prerelease_length;
	uint32_t right_end = right_offset + right->prerelease_length;

	while (left_offset < left_end && right_offset < right_end) {
		uint32_t left_start = left_offset;
		uint32_t right_start = right_offset;
		uint32_t left_length;
		uint32_t right_length;
		bool left_numeric;
		bool right_numeric;
		int comparison;

		while (left_offset < left_end &&
		       left->data[left_offset] != (uint8_t)'.') {
			left_offset++;
		}
		while (right_offset < right_end &&
		       right->data[right_offset] != (uint8_t)'.') {
			right_offset++;
		}
		left_length = left_offset - left_start;
		right_length = right_offset - right_start;
		left_numeric = identifier_numeric(
			left->data + left_start, left_length);
		right_numeric = identifier_numeric(
			right->data + right_start, right_length);

		if (left_numeric != right_numeric) {
			return left_numeric ? -1 : 1;
		}
		if (left_numeric && left_length != right_length) {
			return left_length < right_length ? -1 : 1;
		}
		comparison = byte_slice_compare(
			left->data + left_start, left_length,
			right->data + right_start, right_length);
		if (comparison != 0) {
			return comparison;
		}
		if (left_offset < left_end) {
			left_offset++;
		}
		if (right_offset < right_end) {
			right_offset++;
		}
	}
	if (left_offset < left_end) {
		return 1;
	}
	if (right_offset < right_end) {
		return -1;
	}
	return 0;
}

static int semver_compare(
	const struct pqcp_fleet_policy_bytes *left_bytes,
	const struct pqcp_fleet_policy_bytes *right_bytes,
	int *comparison)
{
	struct semver_view left;
	struct semver_view right;
	int status = semver_parse(left_bytes, &left);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	status = semver_parse(right_bytes, &right);
	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	for (uint32_t index = 0U; index < 3U; ++index) {
		if (left.core[index] < right.core[index]) {
			*comparison = -1;
			return PQCP_FLEET_POLICY_OK;
		}
		if (left.core[index] > right.core[index]) {
			*comparison = 1;
			return PQCP_FLEET_POLICY_OK;
		}
	}
	if (left.has_prerelease != right.has_prerelease) {
		*comparison = left.has_prerelease ? -1 : 1;
		return PQCP_FLEET_POLICY_OK;
	}
	*comparison = left.has_prerelease ?
		semver_prerelease_compare(&left, &right) : 0;
	return PQCP_FLEET_POLICY_OK;
}

static int builtin_semver_epoch(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	int comparison;
	int status = require_call(
		context, state, arguments, argument_count, 4U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	result_bool(result, false);
	status = semver_compare(
		&arguments[0].as.bytes, &arguments[1].as.bytes,
		&comparison);
	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	result_bool(result,
		    comparison >= 0 &&
		    arguments[2].as.u64 >= arguments[3].as.u64);
	return PQCP_FLEET_POLICY_OK;
}

static int builtin_capability_sets(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	uint64_t observed;
	uint64_t required;
	uint64_t forbidden;
	int status = require_call(
		context, state, arguments, argument_count, 3U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	observed = arguments[0].as.u64;
	required = arguments[1].as.u64;
	forbidden = arguments[2].as.u64;
	result_bool(result,
		    (required & forbidden) == 0U &&
		    (observed & required) == required &&
		    (observed & forbidden) == 0U);
	return PQCP_FLEET_POLICY_OK;
}

static int builtin_maintenance_window(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	uint64_t now;
	uint64_t starts;
	uint64_t duration;
	uint64_t period;
	bool inside = false;
	int status = require_call(
		context, state, arguments, argument_count, 4U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	now = arguments[0].as.u64;
	starts = arguments[1].as.u64;
	duration = arguments[2].as.u64;
	period = arguments[3].as.u64;

	if (duration == 0U || now < starts) {
		result_bool(result, false);
		return PQCP_FLEET_POLICY_OK;
	}
	if (period == 0U) {
		inside = duration <= UINT64_MAX - starts &&
			 now < starts + duration;
	} else if (duration <= period) {
		inside = (now - starts) % period < duration;
	}
	result_bool(result, inside);
	return PQCP_FLEET_POLICY_OK;
}

static int builtin_cohort(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	const struct builtin_host_view *host;
	const void *host_context;
	uint32_t cohort = 0U;
	uint64_t threshold;
	int status = require_call(
		context, state, arguments, argument_count, 3U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	result_bool(result, false);
	if (context == NULL) {
		return PQCP_FLEET_POLICY_ERR_BUILTIN;
	}
	host_context = context->registry_context != NULL ?
		context->registry_context : context->application_context;
	if (host_context == NULL) {
		return PQCP_FLEET_POLICY_ERR_BUILTIN;
	}
	host = (const struct builtin_host_view *)host_context;
	if (host->abi_version != BUILTIN_HOST_ABI_VERSION ||
	    host->size < sizeof(*host) || host->cohort == NULL) {
		return PQCP_FLEET_POLICY_ERR_BUILTIN;
	}
	threshold = arguments[2].as.u64;
	if (threshold > PQCP_FLEET_POLICY_BASIS_POINTS) {
		return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
	}
	status = host->cohort(
		host->context,
		arguments[0].as.bytes.data,
		arguments[0].as.bytes.length,
		arguments[1].as.bytes.data,
		arguments[1].as.bytes.length,
		&cohort);
	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	if (cohort >= PQCP_FLEET_POLICY_BASIS_POINTS) {
		return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
	}
	result_bool(result, (uint64_t)cohort < threshold);
	return PQCP_FLEET_POLICY_OK;
}

static int builtin_risk_band(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	uint64_t score;
	uint64_t low;
	uint64_t elevated;
	uint64_t high;
	uint64_t band;
	int status = require_call(
		context, state, arguments, argument_count, 4U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	score = arguments[0].as.u64;
	low = arguments[1].as.u64;
	elevated = arguments[2].as.u64;
	high = arguments[3].as.u64;
	if (low > elevated || elevated > high) {
		return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
	}
	band = score <= low ? 0U :
		(score <= elevated ? 1U : (score <= high ? 2U : 3U));
	result_u64(result, band);
	return PQCP_FLEET_POLICY_OK;
}

static int scratch_load(
	struct pqcp_fleet_policy_builtin_state *state,
	struct builtin_scratch_header *header,
	size_t *sample_capacity)
{
	if (state->scratch == NULL ||
	    state->scratch_capacity < sizeof(*header)) {
		return PQCP_FLEET_POLICY_ERR_CAPACITY;
	}
	memcpy(header, state->scratch, sizeof(*header));
	if (header->magic == 0U && header->version == 0U) {
		memset(header, 0, sizeof(*header));
		header->magic = BUILTIN_STATE_MAGIC;
		header->version = BUILTIN_STATE_VERSION;
		memcpy(state->scratch, header, sizeof(*header));
	}
	if (header->magic != BUILTIN_STATE_MAGIC ||
	    header->version != BUILTIN_STATE_VERSION ||
	    header->reserved != 0U) {
		return PQCP_FLEET_POLICY_ERR_STATE;
	}
	*sample_capacity =
		(state->scratch_capacity - sizeof(*header)) /
		sizeof(struct builtin_rate_sample);
	if ((size_t)header->sliding_count > *sample_capacity ||
	    (size_t)header->sliding_head >=
		    (*sample_capacity == 0U ? 1U : *sample_capacity)) {
		return PQCP_FLEET_POLICY_ERR_STATE;
	}
	if ((header->sliding_initialized != 0U &&
	     header->sliding_total > header->sliding_limit) ||
	    (header->fixed_initialized != 0U &&
	     header->fixed_used > header->fixed_limit) ||
	    (header->token_initialized != 0U &&
	     header->token_available > header->token_capacity)) {
		return PQCP_FLEET_POLICY_ERR_STATE;
	}
	return PQCP_FLEET_POLICY_OK;
}

static void scratch_store(
	struct pqcp_fleet_policy_builtin_state *state,
	const struct builtin_scratch_header *header)
{
	memcpy(state->scratch, header, sizeof(*header));
}

static size_t sample_offset(size_t index)
{
	return sizeof(struct builtin_scratch_header) +
	       index * sizeof(struct builtin_rate_sample);
}

static void sample_load(
	const struct pqcp_fleet_policy_builtin_state *state,
	size_t index,
	struct builtin_rate_sample *sample)
{
	const uint8_t *bytes = (const uint8_t *)state->scratch;

	memcpy(sample, bytes + sample_offset(index), sizeof(*sample));
}

static void sample_store(
	struct pqcp_fleet_policy_builtin_state *state,
	size_t index,
	const struct builtin_rate_sample *sample)
{
	uint8_t *bytes = (uint8_t *)state->scratch;

	memcpy(bytes + sample_offset(index), sample, sizeof(*sample));
}

static int builtin_sliding_rate(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	struct builtin_scratch_header header;
	struct builtin_rate_sample sample;
	size_t capacity;
	uint64_t now;
	uint64_t window;
	uint64_t limit;
	uint64_t cost;
	int status = require_call(
		context, state, arguments, argument_count, 4U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	result_bool(result, false);
	now = arguments[0].as.u64;
	window = arguments[1].as.u64;
	limit = arguments[2].as.u64;
	cost = arguments[3].as.u64;
	if (window == 0U || limit == 0U || cost == 0U) {
		return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
	}
	status = scratch_load(state, &header, &capacity);
	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	if (capacity == 0U) {
		return PQCP_FLEET_POLICY_ERR_CAPACITY;
	}
	if (header.sliding_initialized == 0U) {
		header.sliding_window = window;
		header.sliding_limit = limit;
		header.sliding_initialized = 1U;
	} else if (header.sliding_window != window ||
		   header.sliding_limit != limit) {
		return PQCP_FLEET_POLICY_ERR_STATE;
	}

	while (header.sliding_count != 0U) {
		sample_load(state, header.sliding_head, &sample);
		if (now < sample.timestamp) {
			return PQCP_FLEET_POLICY_ERR_STATE;
		}
		if (now - sample.timestamp < window) {
			break;
		}
		if (sample.cost > header.sliding_total) {
			return PQCP_FLEET_POLICY_ERR_STATE;
		}
		header.sliding_total -= sample.cost;
		header.sliding_head =
			(header.sliding_head + 1U) % (uint32_t)capacity;
		header.sliding_count--;
	}
	if (cost > limit ||
	    header.sliding_total > limit - cost) {
		scratch_store(state, &header);
		return PQCP_FLEET_POLICY_OK;
	}
	if ((size_t)header.sliding_count == capacity) {
		scratch_store(state, &header);
		return PQCP_FLEET_POLICY_ERR_CAPACITY;
	}
	sample.timestamp = now;
	sample.cost = cost;
	sample_store(
		state,
		(header.sliding_head + header.sliding_count) %
			(uint32_t)capacity,
		&sample);
	header.sliding_count++;
	header.sliding_total += cost;
	scratch_store(state, &header);
	result_bool(result, true);
	return PQCP_FLEET_POLICY_OK;
}

static int builtin_fixed_rate(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	struct builtin_scratch_header header;
	size_t capacity;
	uint64_t now;
	uint64_t window;
	uint64_t limit;
	uint64_t cost;
	uint64_t elapsed;
	int status = require_call(
		context, state, arguments, argument_count, 4U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	result_bool(result, false);
	now = arguments[0].as.u64;
	window = arguments[1].as.u64;
	limit = arguments[2].as.u64;
	cost = arguments[3].as.u64;
	if (window == 0U || limit == 0U || cost == 0U) {
		return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
	}
	status = scratch_load(state, &header, &capacity);
	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	(void)capacity;
	if (header.fixed_initialized == 0U) {
		header.fixed_started = now;
		header.fixed_window = window;
		header.fixed_limit = limit;
		header.fixed_initialized = 1U;
	} else if (header.fixed_window != window ||
		   header.fixed_limit != limit) {
		return PQCP_FLEET_POLICY_ERR_STATE;
	}
	if (now < header.fixed_started) {
		return PQCP_FLEET_POLICY_ERR_STATE;
	}
	elapsed = now - header.fixed_started;
	if (elapsed >= window) {
		uint64_t advance = (elapsed / window) * window;

		header.fixed_started += advance;
		header.fixed_used = 0U;
	}
	if (cost <= limit &&
	    header.fixed_used <= limit - cost) {
		header.fixed_used += cost;
		result_bool(result, true);
	}
	scratch_store(state, &header);
	return PQCP_FLEET_POLICY_OK;
}

static int builtin_token_rate(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	struct builtin_scratch_header header;
	size_t sample_capacity;
	uint64_t now;
	uint64_t capacity;
	uint64_t refill;
	uint64_t period;
	uint64_t cost;
	int status = require_call(
		context, state, arguments, argument_count, 5U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	result_bool(result, false);
	now = arguments[0].as.u64;
	capacity = arguments[1].as.u64;
	refill = arguments[2].as.u64;
	period = arguments[3].as.u64;
	cost = arguments[4].as.u64;
	if (capacity == 0U || refill == 0U ||
	    period == 0U || cost == 0U) {
		return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
	}
	status = scratch_load(state, &header, &sample_capacity);
	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	(void)sample_capacity;
	if (header.token_initialized == 0U) {
		header.token_last = now;
		header.token_available = capacity;
		header.token_capacity = capacity;
		header.token_refill = refill;
		header.token_period = period;
		header.token_initialized = 1U;
	} else if (header.token_capacity != capacity ||
		   header.token_refill != refill ||
		   header.token_period != period) {
		return PQCP_FLEET_POLICY_ERR_STATE;
	}
	if (now < header.token_last) {
		return PQCP_FLEET_POLICY_ERR_STATE;
	}
	if (now - header.token_last >= period) {
		uint64_t periods =
			(now - header.token_last) / period;
		uint64_t room =
			capacity - header.token_available;

		if (periods > room / refill) {
			header.token_available = capacity;
		} else {
			header.token_available += periods * refill;
		}
		header.token_last += periods * period;
	}
	if (cost <= header.token_available) {
		header.token_available -= cost;
		result_bool(result, true);
	}
	scratch_store(state, &header);
	return PQCP_FLEET_POLICY_OK;
}

static int builtin_replay_freshness(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	struct builtin_scratch_header header;
	size_t sample_capacity;
	uint64_t sequence;
	uint64_t issued;
	uint64_t now;
	uint64_t maximum_age;
	uint64_t future_skew;
	bool time_fresh;
	int status = require_call(
		context, state, arguments, argument_count, 5U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	result_bool(result, false);
	sequence = arguments[0].as.u64;
	issued = arguments[1].as.u64;
	now = arguments[2].as.u64;
	maximum_age = arguments[3].as.u64;
	future_skew = arguments[4].as.u64;
	if (maximum_age == 0U) {
		return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
	}
	time_fresh = issued <= now ?
		now - issued <= maximum_age :
		issued - now <= future_skew;
	if (!time_fresh) {
		return PQCP_FLEET_POLICY_OK;
	}
	status = scratch_load(state, &header, &sample_capacity);
	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	(void)sample_capacity;
	if (header.replay_initialized != 0U &&
	    sequence <= header.replay_sequence) {
		return PQCP_FLEET_POLICY_OK;
	}
	header.replay_sequence = sequence;
	header.replay_initialized = 1U;
	scratch_store(state, &header);
	result_bool(result, true);
	return PQCP_FLEET_POLICY_OK;
}

static int builtin_migration_update(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	int comparison;
	int status = require_call(
		context, state, arguments, argument_count, 5U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	result_bool(result, false);
	status = semver_compare(
		&arguments[1].as.bytes,
		&arguments[0].as.bytes, &comparison);
	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	if (comparison < 0 ||
	    arguments[3].as.u64 < arguments[2].as.u64) {
		return PQCP_FLEET_POLICY_OK;
	}
	result_bool(result,
		    arguments[4].as.boolean ||
		    comparison > 0 ||
		    arguments[3].as.u64 > arguments[2].as.u64);
	return PQCP_FLEET_POLICY_OK;
}

static uint32_t popcount_u64(uint64_t value)
{
	uint32_t count = 0U;

	while (value != 0U) {
		value &= value - 1U;
		count++;
	}
	return count;
}

static int builtin_dependency_quorum(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	uint64_t healthy;
	uint64_t required;
	uint64_t quorum;
	uint32_t required_count;
	int status = require_call(
		context, state, arguments, argument_count, 3U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	healthy = arguments[0].as.u64;
	required = arguments[1].as.u64;
	quorum = arguments[2].as.u64;
	required_count = popcount_u64(required);
	if (required == 0U || quorum == 0U ||
	    quorum > required_count) {
		return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
	}
	result_bool(result,
		    popcount_u64(healthy & required) >= quorum);
	return PQCP_FLEET_POLICY_OK;
}

static uint32_t read_u32_be(const uint8_t *input)
{
	return ((uint32_t)input[0] << 24) |
	       ((uint32_t)input[1] << 16) |
	       ((uint32_t)input[2] << 8) |
	       (uint32_t)input[3];
}

static int builtin_required_claims(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result)
{
	const struct pqcp_fleet_policy_bytes *claim_ids;
	struct pqcp_fleet_policy_value claim;
	int status = require_call(
		context, state, arguments, argument_count, 1U, result);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	result_bool(result, false);
	if (context == NULL || context->claims == NULL ||
	    context->claims->load == NULL) {
		return PQCP_FLEET_POLICY_OK;
	}
	claim_ids = &arguments[0].as.bytes;
	if (claim_ids->data == NULL || claim_ids->length == 0U ||
	    claim_ids->length % 4U != 0U) {
		return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
	}
	for (uint32_t offset = 0U;
	     offset < claim_ids->length; offset += 4U) {
		uint32_t claim_id =
			read_u32_be(claim_ids->data + offset);

		if (claim_id == 0U) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		memset(&claim, 0, sizeof(claim));
		status = context->claims->load(
			context->claims->context, claim_id, &claim);
		if (status != PQCP_FLEET_POLICY_OK ||
		    !value_valid(&claim)) {
			return PQCP_FLEET_POLICY_OK;
		}
	}
	result_bool(result, true);
	return PQCP_FLEET_POLICY_OK;
}

#define TYPES8(a, b, c, d, e, f, g, h) \
	{ (a), (b), (c), (d), (e), (f), (g), (h) }

static const struct pqcp_fleet_policy_builtin_descriptor
standard_builtins[] = {
	{
		.builtin_id = BUILTIN_SECURE_BOOT,
		.flags = BUILTIN_KNOWN_FLAGS,
		.argument_count = 2U,
		.result_type = PQCP_FLEET_POLICY_VALUE_BOOL,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_BOOL,
			PQCP_FLEET_POLICY_VALUE_BOOL, 0U, 0U,
			0U, 0U, 0U, 0U),
		.invoke = builtin_secure_boot,
	},
	{
		.builtin_id = BUILTIN_MEASUREMENT,
		.flags = BUILTIN_KNOWN_FLAGS,
		.argument_count = 3U,
		.result_type = PQCP_FLEET_POLICY_VALUE_BOOL,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_DIGEST,
			PQCP_FLEET_POLICY_VALUE_DIGEST,
			PQCP_FLEET_POLICY_VALUE_BOOL, 0U,
			0U, 0U, 0U, 0U),
		.invoke = builtin_measurement,
	},
	{
		.builtin_id = BUILTIN_CREDENTIAL_FRESHNESS,
		.flags = BUILTIN_KNOWN_FLAGS,
		.argument_count = 4U,
		.result_type = PQCP_FLEET_POLICY_VALUE_BOOL,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			0U, 0U, 0U, 0U),
		.invoke = builtin_credential_freshness,
	},
	{
		.builtin_id = BUILTIN_CHANNEL_IDENTITY,
		.flags = BUILTIN_KNOWN_FLAGS,
		.argument_count = 4U,
		.result_type = PQCP_FLEET_POLICY_VALUE_BOOL,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_BOOL,
			PQCP_FLEET_POLICY_VALUE_BOOL,
			PQCP_FLEET_POLICY_VALUE_DIGEST,
			PQCP_FLEET_POLICY_VALUE_DIGEST,
			0U, 0U, 0U, 0U),
		.invoke = builtin_channel_identity,
	},
	{
		.builtin_id = BUILTIN_ENTROPY_TIME_QUALITY,
		.flags = BUILTIN_KNOWN_FLAGS,
		.argument_count = 6U,
		.result_type = PQCP_FLEET_POLICY_VALUE_BOOL,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64, 0U, 0U),
		.invoke = builtin_entropy_time_quality,
	},
	{
		.builtin_id = BUILTIN_NOT_REVOKED_OR_LOCKED,
		.flags = BUILTIN_KNOWN_FLAGS,
		.argument_count = 2U,
		.result_type = PQCP_FLEET_POLICY_VALUE_BOOL,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_BOOL,
			PQCP_FLEET_POLICY_VALUE_BOOL, 0U, 0U,
			0U, 0U, 0U, 0U),
		.invoke = builtin_not_revoked_or_locked,
	},
	{
		.builtin_id = BUILTIN_SEMVER_EPOCH,
		.flags = BUILTIN_KNOWN_FLAGS,
		.argument_count = 4U,
		.result_type = PQCP_FLEET_POLICY_VALUE_BOOL,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_BYTES,
			PQCP_FLEET_POLICY_VALUE_BYTES,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			0U, 0U, 0U, 0U),
		.invoke = builtin_semver_epoch,
	},
	{
		.builtin_id = BUILTIN_CAPABILITY_SETS,
		.flags = BUILTIN_KNOWN_FLAGS,
		.argument_count = 3U,
		.result_type = PQCP_FLEET_POLICY_VALUE_BOOL,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64, 0U,
			0U, 0U, 0U, 0U),
		.invoke = builtin_capability_sets,
	},
	{
		.builtin_id = BUILTIN_MAINTENANCE_WINDOW,
		.flags = BUILTIN_KNOWN_FLAGS,
		.argument_count = 4U,
		.result_type = PQCP_FLEET_POLICY_VALUE_BOOL,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			0U, 0U, 0U, 0U),
		.invoke = builtin_maintenance_window,
	},
	{
		.builtin_id = BUILTIN_COHORT,
		.flags = PQCP_FLEET_POLICY_BUILTIN_DETERMINISTIC,
		.argument_count = 3U,
		.result_type = PQCP_FLEET_POLICY_VALUE_BOOL,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_DIGEST,
			PQCP_FLEET_POLICY_VALUE_DIGEST,
			PQCP_FLEET_POLICY_VALUE_U64, 0U,
			0U, 0U, 0U, 0U),
		.invoke = builtin_cohort,
	},
	{
		.builtin_id = BUILTIN_RISK_BAND,
		.flags = BUILTIN_KNOWN_FLAGS,
		.argument_count = 4U,
		.result_type = PQCP_FLEET_POLICY_VALUE_U64,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			0U, 0U, 0U, 0U),
		.invoke = builtin_risk_band,
	},
	{
		.builtin_id = BUILTIN_SLIDING_RATE,
		.flags = PQCP_FLEET_POLICY_BUILTIN_DETERMINISTIC,
		.argument_count = 4U,
		.result_type = PQCP_FLEET_POLICY_VALUE_BOOL,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			0U, 0U, 0U, 0U),
		.invoke = builtin_sliding_rate,
	},
	{
		.builtin_id = BUILTIN_FIXED_RATE,
		.flags = PQCP_FLEET_POLICY_BUILTIN_DETERMINISTIC,
		.argument_count = 4U,
		.result_type = PQCP_FLEET_POLICY_VALUE_BOOL,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			0U, 0U, 0U, 0U),
		.invoke = builtin_fixed_rate,
	},
	{
		.builtin_id = BUILTIN_TOKEN_RATE,
		.flags = PQCP_FLEET_POLICY_BUILTIN_DETERMINISTIC,
		.argument_count = 5U,
		.result_type = PQCP_FLEET_POLICY_VALUE_BOOL,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			0U, 0U, 0U),
		.invoke = builtin_token_rate,
	},
	{
		.builtin_id = BUILTIN_REPLAY_FRESHNESS,
		.flags = PQCP_FLEET_POLICY_BUILTIN_DETERMINISTIC,
		.argument_count = 5U,
		.result_type = PQCP_FLEET_POLICY_VALUE_BOOL,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			0U, 0U, 0U),
		.invoke = builtin_replay_freshness,
	},
	{
		.builtin_id = BUILTIN_MIGRATION_UPDATE,
		.flags = BUILTIN_KNOWN_FLAGS,
		.argument_count = 5U,
		.result_type = PQCP_FLEET_POLICY_VALUE_BOOL,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_BYTES,
			PQCP_FLEET_POLICY_VALUE_BYTES,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_BOOL,
			0U, 0U, 0U),
		.invoke = builtin_migration_update,
	},
	{
		.builtin_id = BUILTIN_DEPENDENCY_QUORUM,
		.flags = BUILTIN_KNOWN_FLAGS,
		.argument_count = 3U,
		.result_type = PQCP_FLEET_POLICY_VALUE_BOOL,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64,
			PQCP_FLEET_POLICY_VALUE_U64, 0U,
			0U, 0U, 0U, 0U),
		.invoke = builtin_dependency_quorum,
	},
	{
		.builtin_id = BUILTIN_REQUIRED_CLAIMS,
		.flags = PQCP_FLEET_POLICY_BUILTIN_DETERMINISTIC,
		.argument_count = 1U,
		.result_type = PQCP_FLEET_POLICY_VALUE_BOOL,
		.argument_types = TYPES8(
			PQCP_FLEET_POLICY_VALUE_BYTES, 0U, 0U, 0U,
			0U, 0U, 0U, 0U),
		.invoke = builtin_required_claims,
	},
};

static bool descriptor_valid(
	const struct pqcp_fleet_policy_builtin_descriptor *descriptor)
{
	if (descriptor == NULL || descriptor->builtin_id == 0U ||
	    descriptor->reserved != 0U ||
	    descriptor->argument_count >
		    PQCP_FLEET_POLICY_MAX_BUILTIN_ARGS ||
	    !value_type_valid(descriptor->result_type) ||
	    (descriptor->flags & ~BUILTIN_KNOWN_FLAGS) != 0U ||
	    descriptor->invoke == NULL) {
		return false;
	}
	for (uint32_t index = 0U;
	     index < PQCP_FLEET_POLICY_MAX_BUILTIN_ARGS; ++index) {
		if (index < descriptor->argument_count) {
			if (!value_type_valid(
				    descriptor->argument_types[index])) {
				return false;
			}
		} else if (descriptor->argument_types[index] != 0U) {
			return false;
		}
	}
	return true;
}

int pqcp_fleet_policy_builtin_registry_init(
	struct pqcp_fleet_policy_builtin_registry *registry,
	const struct pqcp_fleet_policy_builtin_descriptor *descriptors,
	size_t descriptor_count,
	void *context)
{
	if (registry == NULL ||
	    ((descriptors == NULL) != (descriptor_count == 0U))) {
		return PQCP_FLEET_POLICY_ERR_INVALID_ARGUMENT;
	}
	if (descriptors == NULL) {
		descriptors = standard_builtins;
		descriptor_count =
			sizeof(standard_builtins) /
			sizeof(standard_builtins[0]);
	}
	for (size_t index = 0U; index < descriptor_count; ++index) {
		if (!descriptor_valid(&descriptors[index]) ||
		    (index != 0U &&
		     descriptors[index - 1U].builtin_id >=
			     descriptors[index].builtin_id)) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
	}
	registry->descriptors = descriptors;
	registry->descriptor_count = descriptor_count;
	registry->context = context;
	return PQCP_FLEET_POLICY_OK;
}

const struct pqcp_fleet_policy_builtin_descriptor *
pqcp_fleet_policy_builtin_find(
	const struct pqcp_fleet_policy_builtin_registry *registry,
	uint32_t builtin_id)
{
	size_t low = 0U;
	size_t high;

	if (registry == NULL || registry->descriptors == NULL ||
	    registry->descriptor_count == 0U || builtin_id == 0U) {
		return NULL;
	}
	high = registry->descriptor_count;
	while (low < high) {
		size_t middle = low + (high - low) / 2U;
		uint32_t candidate =
			registry->descriptors[middle].builtin_id;

		if (candidate < builtin_id) {
			low = middle + 1U;
		} else {
			high = middle;
		}
	}
	if (low < registry->descriptor_count &&
	    registry->descriptors[low].builtin_id == builtin_id) {
		return &registry->descriptors[low];
	}
	return NULL;
}

void pqcp_fleet_policy_builtin_state_reset(
	struct pqcp_fleet_policy_builtin_state *state,
	void *scratch,
	size_t scratch_capacity)
{
	if (state == NULL) {
		return;
	}
	memset(state, 0, sizeof(*state));
	state->scratch = scratch;
	state->scratch_capacity = scratch_capacity;
	if (scratch != NULL && scratch_capacity != 0U) {
		memset(scratch, 0, scratch_capacity);
	}
}
