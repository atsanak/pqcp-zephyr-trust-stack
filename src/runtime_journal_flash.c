/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <zephyr/drivers/flash.h>
#include <pqcp_zephyr/runtime_journal.h>

/* Keep the callback ABI shared with mutable storage backends. */
// cppcheck-suppress constParameterCallback
static int area_read(void *opaque, size_t offset, void *buffer, size_t length)
{
	const struct pqcp_runtime_journal_flash *context = opaque;
	return flash_area_read(context->area, (off_t)offset, buffer, length);
}

// cppcheck-suppress constParameterCallback
static int area_write(void *opaque, size_t offset, const void *buffer, size_t length)
{
	const struct pqcp_runtime_journal_flash *context = opaque;
	return flash_area_write(context->area, (off_t)offset, buffer, length);
}

// cppcheck-suppress constParameterCallback
static int area_erase(void *opaque, size_t offset, size_t length)
{
	const struct pqcp_runtime_journal_flash *context = opaque;
	return flash_area_erase(context->area, (off_t)offset, length);
}

static int area_sync(void *opaque)
{
	ARG_UNUSED(opaque);
	/* Zephyr flash operations complete synchronously. */
	return 0;
}

int pqcp_runtime_journal_flash_io(struct pqcp_runtime_journal_flash *context,
	const struct flash_area *area, struct pqcp_runtime_journal_io *io)
{
	struct flash_pages_info page;
	const struct flash_parameters *parameters;
	size_t erase_bytes;
	int ret;

	if (context == NULL || area == NULL || io == NULL ||
	    !device_is_ready(area->fa_dev)) {
		return -EINVAL;
	}
	parameters = flash_get_parameters(area->fa_dev);
	if (parameters->erase_value != 0xffU || parameters->write_block_size == 0U ||
	    parameters->write_block_size > PQCP_RUNTIME_JOURNAL_MAX_ALIGNMENT) {
		return -ENOTSUP;
	}
	ret = flash_get_page_info_by_offs(area->fa_dev, area->fa_off, &page);
	if (ret != 0 || page.start_offset != area->fa_off || page.size == 0U) {
		return -EINVAL;
	}
	erase_bytes = page.size;
	if (area->fa_size % erase_bytes != 0U) {
		return -EINVAL;
	}
	for (size_t offset = 0U; offset < area->fa_size; offset += erase_bytes) {
		ret = flash_get_page_info_by_offs(area->fa_dev, area->fa_off + offset, &page);
		if (ret != 0 || page.size != erase_bytes || page.start_offset != area->fa_off + offset) {
			return -ENOTSUP;
		}
	}
	context->area = area;
	*io = (struct pqcp_runtime_journal_io) {
		.context = context, .read = area_read, .write = area_write,
		.erase = area_erase, .sync = area_sync,
		.region_bytes = area->fa_size, .erase_bytes = erase_bytes,
		.write_bytes = parameters->write_block_size,
	};
	return 0;
}
