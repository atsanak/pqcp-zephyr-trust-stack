/* SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation */
/*
 * Cortex-M3 operand-dependent latency models, pure C (no QEMU dependency) so
 * the same code is compiled into the TCG plugin and into the host cross-check
 * of scripts/ct_latency_models.py.
 *
 * CMEMU model: the rules published for CMEmu (a cycle-exact Cortex-M3 r2p1
 * model derived from timing measurements, MSWiM 2025), re-implemented here
 * from the description. No CMEmu code is used. A third party's measurement of
 * one chip revision; not validated against silicon in this repository.
 *
 *   long multiplies  latency depends on which 16-bit halves of each operand
 *                    are non-zero; the signed forms also on operand signs.
 *   divides          2 cycles if either operand is zero, 3 if the dividend
 *                    has fewer significant bits than the divisor, otherwise
 *                    5 + (bitlen difference) / 4; SDIV works on magnitudes
 *                    with two negative-divisor corrections.
 *
 * kind: 1 UDIV, 2 SDIV, 3 UMULL, 4 SMULL, 5 UMLAL, 6 SMLAL. `a` is Rn and `b`
 * is Rm. The class is an opaque small integer: equal classes mean equal
 * modelled latency. Multiplies return (hi_cycles << 8) | lo_cycles.
 */
#ifndef CT_LATENCY_MODELS_H
#define CT_LATENCY_MODELS_H

#include <stdint.h>

static inline int ctlm_msb(uint32_t v) /* index of the highest set bit */
{
	int n = -1;

	while (v != 0U) {
		n++;
		v >>= 1;
	}
	return n;
}

static inline uint32_t ctlm_pair(uint32_t hi, uint32_t lo)
{
	return (hi << 8) | lo;
}

static inline uint32_t ctlm_cmemu_umull(uint32_t a, uint32_t b)
{
	const int ah = (a & 0xFFFF0000U) != 0U, al = (a & 0xFFFFU) != 0U;
	const int bh = (b & 0xFFFF0000U) != 0U, bl = (b & 0xFFFFU) != 0U;

	if ((!bh && !bl) || (!ah && !al) || (!ah && al && !bh && bl) ||
	    (ah && !al && bh && !bl)) {
		return ctlm_pair(2U, 1U);
	}
	if (ah && al && bh && bl) {
		return ctlm_pair(4U, 3U);
	}
	return ctlm_pair(3U, 2U);
}

static inline uint32_t ctlm_cmemu_smull(uint32_t a, uint32_t b)
{
	const int ah = (a & 0xFFFF0000U) != 0U, al = (a & 0xFFFFU) != 0U;
	const int bh = (b & 0xFFFF0000U) != 0U, bl = (b & 0xFFFFU) != 0U;
	const int neg = (a >> 31) != 0U || (b >> 31) != 0U;
	const int bneg = (b >> 31) != 0U;

	if ((!bh && !bl) || (!ah && !al)) {
		return ctlm_pair(2U, 1U);
	}
	if ((!ah && al && !bh && bl) || (ah && !al && bh && !bl)) {
		return neg ? ctlm_pair(3U, 2U) : ctlm_pair(2U, 1U);
	}
	if (ah && al && bh && !bl) {
		return neg ? ctlm_pair(4U, 3U) : ctlm_pair(3U, 2U);
	}
	if (ah && !al && bh && bl) {
		return ctlm_pair(3U, 2U);
	}
	if (ah && al && bh && bl) {
		return ctlm_pair(4U, 3U);
	}
	return bneg ? ctlm_pair(4U, 3U) : ctlm_pair(3U, 2U);
}

static inline uint32_t ctlm_cmemu_umlal(uint32_t a, uint32_t b)
{
	const int ah = (a & 0xFFFF0000U) != 0U, al = (a & 0xFFFFU) != 0U;
	const int bh = (b & 0xFFFF0000U) != 0U, bl = (b & 0xFFFFU) != 0U;

	if ((!bh && !bl) || (!ah && !al) || (!ah && al && !bh && bl)) {
		return ctlm_pair(2U, 1U);
	}
	if ((ah && !al && bh && !bl) || (ah && !al && !bh && bl) ||
	    (ah && al && !bh && bl) || (!ah && al && bh && !bl) ||
	    (!ah && al && bh && bl)) {
		return ctlm_pair(4U, 3U);
	}
	if ((ah && al && bh && !bl) || (ah && !al && bh && bl)) {
		return ctlm_pair(5U, 4U);
	}
	return ctlm_pair(6U, 5U);
}

static inline uint32_t ctlm_cmemu_smlal(uint32_t a, uint32_t b)
{
	const int ah = (a & 0xFFFF0000U) != 0U, al = (a & 0xFFFFU) != 0U;
	const int bh = (b & 0xFFFF0000U) != 0U, bl = (b & 0xFFFFU) != 0U;
	const int neg = (a >> 31) != 0U || (b >> 31) != 0U;
	const int bneg = (b >> 31) != 0U;

	if ((!bh && !bl) || (!ah && !al) || (!ah && al && !bh && bl)) {
		return ctlm_pair(2U, 1U);
	}
	if (ah && !al && bh && !bl) {
		return neg ? ctlm_pair(5U, 4U) : ctlm_pair(4U, 3U);
	}
	if (ah && al && bh && !bl) {
		return neg ? ctlm_pair(6U, 5U) : ctlm_pair(5U, 4U);
	}
	if (ah && !al && bh && bl) {
		return ctlm_pair(5U, 4U);
	}
	if (ah && al && bh && bl) {
		return ctlm_pair(6U, 5U);
	}
	return bneg ? ctlm_pair(5U, 4U) : ctlm_pair(4U, 3U);
}

static inline uint32_t ctlm_cmemu_udiv(uint32_t a, uint32_t b)
{
	uint32_t t;

	if (a == 0U || b == 0U) {
		t = 2U;
	} else if (ctlm_msb(a) < ctlm_msb(b)) {
		t = 3U;
	} else {
		t = (uint32_t)(ctlm_msb(a) - ctlm_msb(b)) / 4U + 5U;
	}
	return t - 1U;
}

static inline uint32_t ctlm_cmemu_sdiv(uint32_t a, uint32_t b)
{
	uint32_t t, rn, rm;
	int bneg, diff, pow2;

	if (a == 0U || b == 0U) {
		return 2U - 1U;
	}
	rn = ((int32_t)a < 0) ? (0U - a) : a; /* wrapping abs */
	bneg = (int32_t)b < 0;
	rm = bneg ? (0U - b) : b;
	pow2 = (rm & (rm - 1U)) == 0U;
	diff = ctlm_msb(rn) - ctlm_msb(rm);
	if (bneg && pow2 && rn != 0x80000000U) {
		diff += 1;
	} else if (bneg && !pow2 && rn == 0x80000000U) {
		diff -= 1;
	}
	t = diff < 0 ? 3U : (uint32_t)diff / 4U + 5U;
	return t - 1U;
}

static inline uint32_t ctlm_cmemu_class(unsigned int kind, uint32_t a,
					uint32_t b)
{
	switch (kind) {
	case 1U:
		return ctlm_cmemu_udiv(a, b);
	case 2U:
		return ctlm_cmemu_sdiv(a, b);
	case 3U:
		return ctlm_cmemu_umull(a, b);
	case 4U:
		return ctlm_cmemu_smull(a, b);
	case 5U:
		return ctlm_cmemu_umlal(a, b);
	default:
		return ctlm_cmemu_smlal(a, b);
	}
}

#endif /* CT_LATENCY_MODELS_H */
