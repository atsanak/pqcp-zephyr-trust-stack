/* SPDX-License-Identifier: MIT */
#ifndef PQCP_RUNTIME_JOURNAL_H_
#define PQCP_RUNTIME_JOURNAL_H_

#include <pqcp_zephyr/runtime_control.h>

#define PQCP_RUNTIME_JOURNAL_HEADER_BYTES 128U
#define PQCP_RUNTIME_JOURNAL_COMMIT_BYTES 32U
#define PQCP_RUNTIME_JOURNAL_MAX_ALIGNMENT 32U

/* Callbacks are synchronous, partition-relative and return zero or -errno.
 * sync must make preceding writes durable before returning success. Each slot
 * must occupy independent erase units. The caller exclusively owns this region.
 */
struct pqcp_runtime_journal_io {
	void *context;
	int (*read)(void *context, size_t offset, void *buffer, size_t length);
	int (*write)(void *context, size_t offset, const void *buffer, size_t length);
	int (*erase)(void *context, size_t offset, size_t length);
	int (*sync)(void *context);
	size_t region_bytes;
	size_t erase_bytes;
	size_t write_bytes;
};

struct pqcp_runtime_journal {
	struct pqcp_runtime_journal_io io;
	uint8_t binding[PQCP_RUNTIME_DIGEST_BYTES];
	uint8_t *scratch;
	size_t scratch_capacity;
	size_t slot_bytes;
	size_t snapshot_bytes;
	uint64_t generation;
	uint64_t minimum_generation;
	unsigned int active_slot;
	struct k_mutex lock;
	bool ready;
	bool has_snapshot;
};

/* Reopen without erasing flash. binding identifies the firmware/profile build;
 * minimum_generation comes from a caller's trusted rollback policy (zero allows
 * all generations). Hashes detect corruption, not malicious forgery. This is
 * NOT authenticated or hardware-backed anti-rollback storage. Scratch and input
 * arrays must remain exclusive and unmodified during calls. No keys or record
 * counters are persisted; only runtime_snapshot_write metadata is accepted.
 */
int pqcp_runtime_journal_open(struct pqcp_runtime_journal *journal,
	const struct pqcp_runtime_journal_io *io, size_t slot_bytes,
	const uint8_t binding[PQCP_RUNTIME_DIGEST_BYTES],
	uint64_t minimum_generation, uint8_t *scratch, size_t scratch_capacity);

/* Failed/uncertain I/O invalidates the instance. Reopen it before retrying:
 * a commit may have reached flash even if the final sync returned an error.
 */
int pqcp_runtime_journal_save(struct pqcp_runtime_journal *journal,
	const struct pqcp_runtime_session *sessions, size_t session_capacity,
	const struct pqcp_runtime_profile_state *profiles, size_t profile_capacity);

/* Fresh read and full integrity check before touching runtime state. Existing
 * recovery rules drain recovered sessions and reject unavailable key handles.
 * -ENOENT from key reconciliation means a fresh handshake is required. Restore
 * is an offline operation: stop the worker and exclude other runtime callers.
 */
int pqcp_runtime_journal_restore(struct pqcp_runtime_journal *journal,
	struct pqcp_runtime_controller *controller,
	struct pqcp_runtime_snapshot_info *info, uint64_t now_ms);

#if defined(CONFIG_PQCP_RUNTIME_JOURNAL_FLASH)
#include <zephyr/storage/flash_map.h>
struct pqcp_runtime_journal_flash {
	const struct flash_area *area;
};
/* Partition is borrowed and must outlive the journal; only uniform erase-page
 * areas with 0xff erased contents and write units <=32 bytes are supported.
 */
int pqcp_runtime_journal_flash_io(struct pqcp_runtime_journal_flash *context,
	const struct flash_area *area, struct pqcp_runtime_journal_io *io);
#endif

#endif
