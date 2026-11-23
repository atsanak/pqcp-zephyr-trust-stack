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
 * Optional event=<addr> (declassification-aware mode): every execution of the
 * event marker closes a segment and emits
 *   PQCP_CT_SEG region=<n> seq=<k> site=<rdi> len=<rsi> cls=<rdx> insns=...
 *       h_pc=... h_addr=... h_line=... h_div=...
 * for the trace since the previous event (or the region begin). A final
 * segment with site=0 closes each region. scripts/ct_trace_analysis.py
 * compares segments of executions that agree on every declassified value so
 * far (relational noninterference modulo declassification).
 *
 * Cortex-M (target "arm") operand-latency channel: Thumb-2 UDIV/SDIV and the
 * long multiplies UMULL/SMULL/UMLAL/SMLAL have operand-dependent latency on
 * Cortex-M3 (ARM DDI 0337, instruction timing). For every such instruction
 * executed inside a region the plugin accumulates, per instruction address,
 * the operand pair three ways and emits one line per site at region end:
 *   PQCP_CT_VLAT region=<n> pc=<hex> kind=<k> n=<count> h_op=<hex16>
 *       h_cls=<hex16> h_doc=<hex16> h_cm=<hex16>
 *   h_op   exact operand values (identity: any latency function of the
 *          operands is a function of this)
 *   h_cls  operand bit-lengths (a magnitude / leading-zero latency model)
 *   h_doc  the documented M3 long-multiply predicate: are both operands
 *          below 65536 (div: same as h_cls)
 *   h_cm   the CMEmu latency class (ct_latency_models.h): half-word
 *          non-zero patterns for long multiplies, cycle formula for divides
 * kind: 1 UDIV 2 SDIV 3 UMULL 4 SMULL 5 UMLAL 6 SMLAL. Registers are r0..r12,
 * sp and lr, and the marker arguments are r0..r2. Marker addresses are masked to even.
 * No cycle model: operands are recorded, latency is not simulated.
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

#include "ct_latency_models.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define FNV_OFFSET 0xcbf29ce484222325ULL
#define FNV_PRIME 0x100000001b3ULL

static uint64_t begin_addr;
static uint64_t end_addr;
static uint64_t event_addr; /* optional declassification event marker */
static FILE *out_file;

static int counting;
static uint64_t region_index;
static uint64_t label;
static uint64_t insns, loads, stores, ndiv;
static uint64_t h_pc, h_addr, h_line, h_div;

/* Per-segment accumulators (only meaningful when event_addr is set). A
 * segment is the trace between two declassification events inside a region.
 */
static uint64_t seg_index;
static uint64_t sg_insns, sg_loads, sg_stores, sg_ndiv;
static uint64_t sg_pc, sg_addr, sg_line, sg_div;
/* Cortex-M per-segment latency streams: div bit-lengths, long-multiply
 * predicate, exact operands; each mixed with the instruction address. */
static uint64_t sg_vdiv, sg_vmul, sg_vop, sg_vcm, sg_nvl;

static int is_arm;
static struct qemu_plugin_register *arm_regs[15]; /* r0..r12, sp, lr */

#define VLAT_SITES 512U
struct vlat_site {
	uint64_t pc;
	uint64_t n;
	uint64_t h_op, h_cls, h_doc, h_cm;
	uint32_t kind;
	int used;
};
static struct vlat_site vsites[VLAT_SITES];
static unsigned int vsite_order[VLAT_SITES];
static unsigned int vsite_count;

struct vlat_insn {
	uint64_t pc;
	uint8_t kind;
	uint8_t ra, rb;
};

static struct qemu_plugin_register *reg_rax;
static struct qemu_plugin_register *reg_rdx;
static struct qemu_plugin_register *reg_rdi;
static struct qemu_plugin_register *reg_rsi;

static inline uint64_t mix(uint64_t h, uint64_t v)
{
	for (int i = 0; i < 8; ++i) {
		h ^= (v >> (8 * i)) & 0xffU;
		h *= FNV_PRIME;
	}
	return h;
}

static void reset_vlat(void)
{
	for (unsigned int i = 0U; i < vsite_count; ++i) {
		vsites[vsite_order[i]].used = 0;
	}
	vsite_count = 0U;
}

static void reset_region(void)
{
	reset_vlat();
	insns = loads = stores = ndiv = 0U;
	h_pc = h_addr = h_line = h_div = FNV_OFFSET;
	seg_index = 0U;
	sg_insns = sg_loads = sg_stores = sg_ndiv = 0U;
	sg_pc = sg_addr = sg_line = sg_div = FNV_OFFSET;
	sg_vdiv = sg_vmul = sg_vop = sg_vcm = FNV_OFFSET;
	sg_nvl = 0U;
}

static void reset_segment(void)
{
	sg_insns = sg_loads = sg_stores = sg_ndiv = 0U;
	sg_pc = sg_addr = sg_line = sg_div = FNV_OFFSET;
	sg_vdiv = sg_vmul = sg_vop = sg_vcm = FNV_OFFSET;
	sg_nvl = 0U;
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
	    scratch->len >= 4U) {
		memcpy(&value, scratch->data,
		       scratch->len >= 8U ? 8U : scratch->len);
	}
	return value;
}

static void emit_segment(uint64_t site, uint64_t len, uint64_t cls)
{
	if (out_file != NULL) {
		char vlat[192] = "";

		if (is_arm) {
			snprintf(vlat, sizeof(vlat),
				 " nvl=%" PRIu64 " h_vdiv=%016" PRIx64
				 " h_vmul=%016" PRIx64 " h_vop=%016" PRIx64
				 " h_vcm=%016" PRIx64,
				 sg_nvl, sg_vdiv, sg_vmul, sg_vop, sg_vcm);
		}
		fprintf(out_file,
			"PQCP_CT_SEG region=%" PRIu64 " seq=%" PRIu64
			" site=%" PRIu64 " len=%" PRIu64 " cls=%" PRIu64
			" insns=%" PRIu64 " loads=%" PRIu64 " stores=%" PRIu64
			" ndiv=%" PRIu64 " h_pc=%016" PRIx64
			" h_addr=%016" PRIx64 " h_line=%016" PRIx64
			" h_div=%016" PRIx64 "%s\n",
			region_index, seg_index, site, len, cls, sg_insns,
			sg_loads, sg_stores, sg_ndiv, sg_pc, sg_addr, sg_line,
			sg_div, vlat);
		fflush(out_file);
	}
	seg_index++;
	reset_segment();
}

static void emit_region(void)
{
	if (event_addr != 0U) {
		/* Tail segment: trace after the last event, site 0. */
		emit_segment(0U, 0U, 0U);
	}
	for (unsigned int i = 0U; out_file != NULL && i < vsite_count; ++i) {
		const struct vlat_site *v = &vsites[vsite_order[i]];

		fprintf(out_file,
			"PQCP_CT_VLAT region=%" PRIu64 " pc=%" PRIx64
			" kind=%u n=%" PRIu64 " h_op=%016" PRIx64
			" h_cls=%016" PRIx64 " h_doc=%016" PRIx64
			" h_cm=%016" PRIx64 "\n",
			region_index, v->pc, v->kind, v->n, v->h_op, v->h_cls,
			v->h_doc, v->h_cm);
	}
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

		if (is_arm) {
			unsigned int n;

			if (strcmp(d->name, "sp") == 0) {
				arm_regs[13] = d->handle;
			} else if (strcmp(d->name, "lr") == 0) {
				arm_regs[14] = d->handle;
			}
			if (d->name[0] == 'r' && d->name[1] >= '0' &&
			    d->name[1] <= '9') {
				n = (unsigned int)atoi(d->name + 1);
				if (n < 13U) {
					arm_regs[n] = d->handle;
				}
				if (n == 0U) {
					reg_rdi = d->handle;
				} else if (n == 1U) {
					reg_rsi = d->handle;
				} else if (n == 2U) {
					reg_rdx = d->handle;
				}
			}
			continue;
		}
		if (strcmp(d->name, "rax") == 0) {
			reg_rax = d->handle;
		} else if (strcmp(d->name, "rdx") == 0) {
			reg_rdx = d->handle;
		} else if (strcmp(d->name, "rdi") == 0) {
			reg_rdi = d->handle;
		} else if (strcmp(d->name, "rsi") == 0) {
			reg_rsi = d->handle;
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
		sg_insns++;
		sg_pc = mix(sg_pc, vaddr);
	}
}

/*
 * Declassification event: closes the current segment. Arguments are the
 * first three C arguments, 32 bits each (rdi/r0 = site, rsi/r1 = length,
 * rdx/r2 = value class).
 */
static void insn_exec_event(unsigned int cpu_index, void *udata)
{
	(void)cpu_index;
	(void)udata;
	if (counting) {
		const uint64_t site = read_reg(reg_rdi) & 0xffffffffU;
		const uint64_t len = read_reg(reg_rsi) & 0xffffffffU;
		const uint64_t cls = read_reg(reg_rdx) & 0xffffffffU;

		emit_segment(site, len, cls);
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
		sg_ndiv++;
		sg_div = mix(mix(sg_div, lo), hi);
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
	if (qemu_plugin_mem_is_store(info)) {
		sg_stores++;
	} else {
		sg_loads++;
	}
	sg_addr = mix(sg_addr, vaddr);
	sg_line = mix(sg_line, vaddr >> 6);
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

static unsigned int bitlen(uint64_t v)
{
	unsigned int n = 0U;

	while (v != 0U) {
		n++;
		v >>= 1;
	}
	return n;
}

static uint64_t magnitude(uint32_t v, int is_signed)
{
	if (is_signed && (v & 0x80000000U) != 0U) {
		return (uint64_t)(0x100000000ULL - v);
	}
	return v;
}

static struct vlat_site *vlat_lookup(uint64_t pc, uint32_t kind)
{
	unsigned int slot = (unsigned int)((pc >> 1) * 2654435761U) %
			    VLAT_SITES;

	for (unsigned int probe = 0U; probe < VLAT_SITES; ++probe) {
		struct vlat_site *v = &vsites[slot];

		if (!v->used) {
			v->used = 1;
			v->pc = pc;
			v->kind = kind;
			v->n = 0U;
			v->h_op = v->h_cls = v->h_doc = v->h_cm = FNV_OFFSET;
			vsite_order[vsite_count++] = slot;
			return v;
		}
		if (v->pc == pc) {
			return v;
		}
		slot = (slot + 1U) % VLAT_SITES;
	}
	return NULL;
}

/* Cortex-M variable-latency instruction: record the operand pair. */
static void insn_exec_vlat(unsigned int cpu_index, void *udata)
{
	const struct vlat_insn *vi = udata;

	insn_exec(cpu_index, (void *)(uintptr_t)vi->pc);
	if (counting && vsite_count < VLAT_SITES - 1U) {
		const uint32_t a = (uint32_t)read_reg(arm_regs[vi->ra]);
		const uint32_t b = (uint32_t)read_reg(arm_regs[vi->rb]);
		const int sgn = vi->kind == 2U || vi->kind == 4U ||
				vi->kind == 6U;
		const uint64_t ma = magnitude(a, sgn);
		const uint64_t mb = magnitude(b, sgn);
		struct vlat_site *v = vlat_lookup(vi->pc, vi->kind);

		const uint32_t cm = ctlm_cmemu_class(vi->kind, a, b);

		sg_nvl++;
		sg_vop = mix(mix(mix(sg_vop, vi->pc), a), b);
		sg_vcm = mix(mix(sg_vcm, vi->pc), cm);
		if (vi->kind <= 2U) {
			sg_vdiv = mix(mix(mix(sg_vdiv, vi->pc), bitlen(ma)),
				      bitlen(mb));
		} else {
			sg_vmul = mix(mix(sg_vmul, vi->pc),
				      (ma < 65536U) * 2U + (mb < 65536U));
		}
		if (v != NULL) {
			v->n++;
			v->h_op = mix(mix(v->h_op, a), b);
			v->h_cls = mix(mix(v->h_cls, bitlen(ma)), bitlen(mb));
			v->h_cm = mix(v->h_cm, cm);
			if (vi->kind >= 3U) {
				v->h_doc = mix(v->h_doc,
					       (ma < 65536U) * 2U +
						       (mb < 65536U));
			} else {
				v->h_doc = mix(mix(v->h_doc, bitlen(ma)),
					       bitlen(mb));
			}
		}
	}
}

/*
 * Thumb-2 32-bit encodings (ARM DDI 0403, A7.7):
 *   UDIV  FBB0+Rn | F0F0 | Rd<<8 | Rm        SDIV  FB90+Rn | F0F0 ...
 *   SMULL FB80+Rn | RdLo<<12 RdHi<<8 0000 Rm UMULL FBA0+Rn | same
 *   SMLAL FBC0+Rn | RdLo<<12 RdHi<<8 0000 Rm UMLAL FBE0+Rn | same
 * qemu_plugin_insn_data returns the halfwords in memory (little-endian)
 * order. Returns 0 when the instruction is not one of these.
 */
static int arm_vlat_decode(struct qemu_plugin_insn *insn,
			   struct vlat_insn *out)
{
	uint8_t buf[8];
	const size_t len = qemu_plugin_insn_data(insn, buf, sizeof(buf));
	uint16_t hw1, hw2;

	if (len != 4U) {
		return 0;
	}
	hw1 = (uint16_t)(buf[0] | (buf[1] << 8));
	hw2 = (uint16_t)(buf[2] | (buf[3] << 8));
	out->ra = hw1 & 0xFU;
	out->rb = hw2 & 0xFU;
	if ((hw1 & 0xFFF0U) == 0xFBB0U && (hw2 & 0xF0F0U) == 0xF0F0U) {
		out->kind = 1U;
	} else if ((hw1 & 0xFFF0U) == 0xFB90U &&
		   (hw2 & 0xF0F0U) == 0xF0F0U) {
		out->kind = 2U;
	} else if ((hw2 & 0x00F0U) == 0x0000U &&
		   (hw1 & 0xFFF0U) == 0xFBA0U) {
		out->kind = 3U;
	} else if ((hw2 & 0x00F0U) == 0x0000U &&
		   (hw1 & 0xFFF0U) == 0xFB80U) {
		out->kind = 4U;
	} else if ((hw2 & 0x00F0U) == 0x0000U &&
		   (hw1 & 0xFFF0U) == 0xFBE0U) {
		out->kind = 5U;
	} else if ((hw2 & 0x00F0U) == 0x0000U &&
		   (hw1 & 0xFFF0U) == 0xFBC0U) {
		out->kind = 6U;
	} else {
		return 0;
	}
	return out->ra < 15U && out->rb < 15U;
}

static void tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
	const size_t n = qemu_plugin_tb_n_insns(tb);

	(void)id;
	for (size_t i = 0U; i < n; ++i) {
		struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
		const uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
		void *ud = (void *)(uintptr_t)vaddr;
		const int divide = is_arm ? 0 : insn_is_div(insn);
		struct vlat_insn vtmp;

		if (vaddr == begin_addr) {
			/* Begin must read rdi at the instruction itself. */
			qemu_plugin_register_vcpu_insn_exec_cb(
				insn, insn_exec_begin, QEMU_PLUGIN_CB_R_REGS,
				ud);
		} else if (event_addr != 0U && vaddr == event_addr) {
			/* Event args must be read at the instruction itself. */
			qemu_plugin_register_vcpu_insn_exec_cb(
				insn, insn_exec_event, QEMU_PLUGIN_CB_R_REGS,
				ud);
		} else if (is_arm && arm_vlat_decode(insn, &vtmp)) {
			struct vlat_insn *vi = g_new(struct vlat_insn, 1);

			*vi = vtmp;
			vi->pc = vaddr;
			qemu_plugin_register_vcpu_insn_exec_cb(
				insn, insn_exec_vlat, QEMU_PLUGIN_CB_R_REGS,
				vi);
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

	is_arm = info != NULL && info->target_name != NULL &&
		 strcmp(info->target_name, "arm") == 0;
	for (int i = 0; i < argc; ++i) {
		if (strncmp(argv[i], "begin=", 6) == 0) {
			begin_addr = strtoull(argv[i] + 6, NULL, 0);
		} else if (strncmp(argv[i], "end=", 4) == 0) {
			end_addr = strtoull(argv[i] + 4, NULL, 0);
		} else if (strncmp(argv[i], "event=", 6) == 0) {
			event_addr = strtoull(argv[i] + 6, NULL, 0);
		} else if (strncmp(argv[i], "outfile=", 8) == 0) {
			outfile_path = argv[i] + 8;
		}
	}
	if (is_arm) {
		/* Thumb function symbols carry bit 0; instruction addresses
		 * are even. */
		begin_addr &= ~1ULL;
		end_addr &= ~1ULL;
		event_addr &= ~1ULL;
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
