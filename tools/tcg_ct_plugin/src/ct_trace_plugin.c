/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * pqcp_ct_trace - QEMU TCG plugin that records, for every region bracketed
 * by two marker addresses, a fingerprint of what the executing image
 * revealed on four observation channels:
 *
 *   h_pc    the sequence of executed instruction addresses   (control flow)
 *   h_addr  the sequence of guest data addresses, exact      (memory access)
 *   h_line  the same addresses at 64-byte line granularity   (cache lines)
 *   h_div   the dividend registers (rdx:rax) of every x86 div/idiv
 *                                                    (variable-latency ops)
 *
 * Each channel is an FNV-1a-64 hash over a 64-bit stream. Two regions that
 * ran with different secrets are indistinguishable on a channel exactly when
 * their hashes are equal. The runner compares regions relationally.
 *
 * Output, one line per completed region:
 *   PQCP_CT_TRACE region=<n> label=<tag> insns=<n> loads=<n> stores=<n>
 *       ndiv=<n> h_pc=<hex16> h_addr=<hex16> h_line=<hex16> h_div=<hex16>
 *
 * label is the value of rdi at the begin marker (the first C argument), so
 * the firmware can name regions (valid / corrupt ciphertext, ...).
 *
 * This is relational leakage testing in an emulated whole-system image. It
 * is NOT a constant-time proof and models no microarchitecture.
 */

#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define FNV_OFFSET 0xcbf29ce484222325ULL
#define FNV_PRIME 0x100000001b3ULL

static uint64_t begin_addr;
static uint64_t end_addr;
static FILE *out_file;

static int counting;
static uint64_t region_index;
static uint64_t label;
static uint64_t insns, loads, stores, ndiv;
static uint64_t h_pc, h_addr, h_line, h_div;

static struct qemu_plugin_register *reg_rax;
static struct qemu_plugin_register *reg_rdx;
static struct qemu_plugin_register *reg_rdi;

static inline uint64_t mix(uint64_t h, uint64_t v)
{
	for (int i = 0; i < 8; ++i) {
		h ^= (v >> (8 * i)) & 0xffU;
		h *= FNV_PRIME;
	}
	return h;
}

static void reset_region(void)
{
	insns = loads = stores = ndiv = 0U;
	h_pc = h_addr = h_line = h_div = FNV_OFFSET;
}

/*
 * One scratch buffer for the whole run. The QEMU host binary exports no glib
 * symbols, so the plugin links glib itself (GLIB_LIBS in the Makefile).
 */
static GByteArray *scratch;

static uint64_t read_reg(struct qemu_plugin_register *reg)
{
	uint64_t value = 0U;

	if (scratch == NULL) {
		scratch = g_byte_array_new();
	}
	scratch->len = 0U;
	if (reg != NULL && qemu_plugin_read_register(reg, scratch) > 0 &&
	    scratch->len >= 8U) {
		memcpy(&value, scratch->data, 8U);
	}
	return value;
}

static void emit_region(void)
{
	if (out_file != NULL) {
		fprintf(out_file,
			"PQCP_CT_TRACE region=%" PRIu64 " label=%" PRIu64
			" insns=%" PRIu64 " loads=%" PRIu64 " stores=%" PRIu64
			" ndiv=%" PRIu64 " h_pc=%016" PRIx64
			" h_addr=%016" PRIx64 " h_line=%016" PRIx64
			" h_div=%016" PRIx64 "\n",
			region_index, label, insns, loads, stores, ndiv,
			h_pc, h_addr, h_line, h_div);
		fflush(out_file);
	}
	region_index++;
}

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
	GArray *regs = qemu_plugin_get_registers();

	(void)id;
	(void)vcpu_index;
	for (guint i = 0U; regs != NULL && i < regs->len; ++i) {
		qemu_plugin_reg_descriptor *d =
			&g_array_index(regs, qemu_plugin_reg_descriptor, i);

		if (strcmp(d->name, "rax") == 0) {
			reg_rax = d->handle;
		} else if (strcmp(d->name, "rdx") == 0) {
			reg_rdx = d->handle;
		} else if (strcmp(d->name, "rdi") == 0) {
			reg_rdi = d->handle;
		}
	}
	if (regs != NULL) {
		g_array_free(regs, TRUE);
	}
}

/* Plain instruction: needs only the address. */
static void insn_exec(unsigned int cpu_index, void *udata)
{
	const uint64_t vaddr = (uint64_t)(uintptr_t)udata;

	(void)cpu_index;
	if (vaddr == end_addr) {
		if (counting) {
			counting = 0;
			emit_region();
		}
		return;
	}
	if (counting) {
		insns++;
		h_pc = mix(h_pc, vaddr);
	}
}

/* Region begin: also latches the label from the first argument register. */
static void insn_exec_begin(unsigned int cpu_index, void *udata)
{
	(void)cpu_index;
	(void)udata;
	reset_region();
	label = read_reg(reg_rdi);
	counting = 1;
}

/* div/idiv: record the dividend. */
static void insn_exec_div(unsigned int cpu_index, void *udata)
{
	insn_exec(cpu_index, udata);
	if (counting) {
		const uint64_t lo = read_reg(reg_rax);
		const uint64_t hi = read_reg(reg_rdx);

		ndiv++;
		h_div = mix(mix(h_div, lo), hi);
	}
}

static void mem_access(unsigned int cpu_index, qemu_plugin_meminfo_t info,
		       uint64_t vaddr, void *udata)
{
	(void)cpu_index;
	(void)udata;
	if (!counting) {
		return;
	}
	if (qemu_plugin_mem_is_store(info)) {
		stores++;
	} else {
		loads++;
	}
	h_addr = mix(h_addr, vaddr);
	h_line = mix(h_line, vaddr >> 6);
}

/*
 * x86 DIV/IDIV are opcode F6/F7 with ModRM.reg = 6 (DIV) or 7 (IDIV). The
 * mnemonic is not used: the SDK's QEMU is built without a disassembler, so
 * qemu_plugin_insn_disas() cannot be relied on. Legacy prefixes and REX are
 * skipped first.
 */
static int insn_is_div(struct qemu_plugin_insn *insn)
{
	uint8_t buf[16];
	size_t len = qemu_plugin_insn_data(insn, buf, sizeof(buf));
	size_t i = 0U;

	while (i < len) {
		const uint8_t b = buf[i];

		if (b == 0x66U || b == 0x67U || b == 0xF2U || b == 0xF3U ||
		    b == 0x2EU || b == 0x36U || b == 0x3EU || b == 0x26U ||
		    b == 0x64U || b == 0x65U || (b >= 0x40U && b <= 0x4FU)) {
			i++;
			continue;
		}
		break;
	}
	if (i + 1U >= len || (buf[i] != 0xF6U && buf[i] != 0xF7U)) {
		return 0;
	}
	{
		const unsigned int reg = (buf[i + 1U] >> 3) & 7U;

		return reg == 6U || reg == 7U;
	}
}

static void tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
	const size_t n = qemu_plugin_tb_n_insns(tb);

	(void)id;
	for (size_t i = 0U; i < n; ++i) {
		struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
		const uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
		void *ud = (void *)(uintptr_t)vaddr;
		const int divide = insn_is_div(insn);

		if (vaddr == begin_addr) {
			/* Begin must read rdi at the instruction itself. */
			qemu_plugin_register_vcpu_insn_exec_cb(
				insn, insn_exec_begin, QEMU_PLUGIN_CB_R_REGS,
				ud);
		} else if (divide) {
			qemu_plugin_register_vcpu_insn_exec_cb(
				insn, insn_exec_div, QEMU_PLUGIN_CB_R_REGS,
				ud);
		} else {
			qemu_plugin_register_vcpu_insn_exec_cb(
				insn, insn_exec, QEMU_PLUGIN_CB_NO_REGS, ud);
		}
		qemu_plugin_register_vcpu_mem_cb(insn, mem_access,
						 QEMU_PLUGIN_CB_NO_REGS,
						 QEMU_PLUGIN_MEM_RW, NULL);
	}
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
	(void)id;
	(void)p;
	if (out_file != NULL) {
		fprintf(out_file, "PQCP_CT_TRACE done regions=%" PRIu64 "\n",
			region_index);
		fflush(out_file);
		if (out_file != stderr) {
			(void)fclose(out_file);
		}
		out_file = NULL;
	}
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
					   const qemu_info_t *info,
					   int argc, char **argv)
{
	const char *outfile_path = NULL;

	(void)info;
	for (int i = 0; i < argc; ++i) {
		if (strncmp(argv[i], "begin=", 6) == 0) {
			begin_addr = strtoull(argv[i] + 6, NULL, 0);
		} else if (strncmp(argv[i], "end=", 4) == 0) {
			end_addr = strtoull(argv[i] + 4, NULL, 0);
		} else if (strncmp(argv[i], "outfile=", 8) == 0) {
			outfile_path = argv[i] + 8;
		}
	}
	if (begin_addr == 0U || end_addr == 0U) {
		fprintf(stderr,
			"pqcp_ct_trace: begin= and end= are required\n");
		return -1;
	}
	out_file = outfile_path != NULL ? fopen(outfile_path, "w") : stderr;
	if (out_file == NULL) {
		fprintf(stderr, "pqcp_ct_trace: cannot open %s\n",
			outfile_path);
		return -1;
	}
	reset_region();
	qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
	qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans);
	qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
	return 0;
}
