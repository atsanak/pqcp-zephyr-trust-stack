/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <string.h>
#include <psa/crypto.h>
#include <zephyr/sys/printk.h>
#include <pqcp_zephyr/runtime_journal.h>

static struct pqcp_runtime_journal journal;
static uint8_t scratch[1024];
static struct pqcp_runtime_session saved[1];
static struct pqcp_runtime_profile_state profiles[1];
static struct pqcp_runtime_session recovered[1];
static struct pqcp_runtime_profile_state recovered_profiles[1];
static struct pqcp_runtime_volatile_slot key_slots[2];
static struct pqcp_runtime_key_store keys;
static struct pqcp_runtime_volatile_context key_context;

/* Demo binding only. Applications supply their measured firmware/profile hash.
 * Reserve this partition exclusively; the sample never automatically formats
 * corrupt or incompatible existing data.
 */
static const uint8_t binding[32] = {0x50U, 0x51U, 0x4aU, 1U};

static int run_demo(void)
{
	const struct flash_area *area;
	struct pqcp_runtime_journal_flash flash;
	struct pqcp_runtime_journal_io io;
	struct pqcp_runtime_executor executor = {
		.profile_states = recovered_profiles, .profile_state_capacity = 1U,
	};
	struct pqcp_runtime_session_manager manager = {.sessions = recovered, .capacity = 1U};
	struct pqcp_runtime_controller controller = {
		.initialized = true, .executor = &executor, .sessions = &manager,
		.key_store = &keys,
	};
	struct pqcp_runtime_snapshot_info info;
	int ret = psa_crypto_init() == PSA_SUCCESS ? 0 : -EIO;

	if (ret != 0) {
		return ret;
	}
	ret = flash_area_open(PARTITION_ID(storage_partition), &area);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_journal_flash_io(&flash, area, &io);
	if (ret == 0) {
		ret = pqcp_runtime_journal_open(&journal, &io, 2048U, binding,
			0U, scratch, sizeof(scratch));
	}
	if (ret == 0 && !journal.has_snapshot) {
		saved[0].schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
		saved[0].session_id = 1U;
		saved[0].active = true;
		saved[0].mlkem_level = 768U;
		saved[0].mldsa_level = 65U;
		strcpy(saved[0].profile_id, "hybrid768-65-runtime");
		ret = pqcp_runtime_journal_save(&journal, saved, 1U, profiles, 1U);
	}
	if (ret == 0) {
		/* Lose all runtime journal state; reopen from partition contents. */
		memset(&journal, 0, sizeof(journal));
		memset(scratch, 0, sizeof(scratch));
		ret = pqcp_runtime_journal_open(&journal, &io, 2048U, binding,
			0U, scratch, sizeof(scratch));
	}
	if (ret == 0) {
		ret = pqcp_runtime_volatile_store_init(&keys, &key_context, key_slots, 2U);
	}
	if (ret == 0) {
		ret = pqcp_runtime_journal_restore(&journal, &controller, &info, 100U);
	}
	if (ret == 0 && (manager.active_count != 1U || !recovered[0].draining ||
	    controller.accepting_sessions)) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		printk("PQCP_RUNTIME_RECOVERY status=PASS generation=%llu sessions=%u mode=flash_reopen secrets=not_persisted\n",
			(unsigned long long)journal.generation, (unsigned int)manager.active_count);
	}
	flash_area_close(area);
	return ret;
}

int main(void)
{
	int ret = run_demo();

	if (ret != 0) {
		printk("PQCP_RUNTIME_RECOVERY status=FAIL error=%d\n", ret);
	}
	return ret;
}
