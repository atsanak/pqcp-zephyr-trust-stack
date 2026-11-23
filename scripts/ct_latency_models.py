#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Reference implementation of the Cortex-M3 latency models, and the host
cross-check against the C classifier compiled into the TCG plugin
(tools/tcg_ct_plugin/src/ct_latency_models.h).

`documented`  ARM DDI 0337 as used by claims 13-15: a long multiply finishes
              early when both operands are below 65536; divides follow
              operand bit lengths.
`cmemu`       the rules published for CMEmu (MSWiM 2025), re-implemented from
              the description (no CMEmu code is used): long multiplies depend
              on which 16-bit halves of each operand are non-zero (and, for
              signed forms, on signs); divides take 2 cycles if either operand
              is zero, 3 if the dividend is shorter than the divisor, else
              5 + bitlen-difference // 4.

kind: 1 UDIV, 2 SDIV, 3 UMULL, 4 SMULL, 5 UMLAL, 6 SMLAL; a = Rn, b = Rm.

    python3 scripts/ct_latency_models.py --crosscheck
"""

import argparse
import random
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
HEADER_DIR = SCRIPT_DIR.parent / "tools" / "tcg_ct_plugin" / "src"
MASK = 0xFFFFFFFF
DIV_KINDS = (1, 2)

# (hi cycles, lo cycles) per (a_hi, a_lo, b_hi, b_lo) halves-nonzero pattern.
_U = {}
_UL = {}
for _ah in (0, 1):
    for _al in (0, 1):
        for _bh in (0, 1):
            for _bl in (0, 1):
                _k = (_ah, _al, _bh, _bl)
                a_zero, b_zero = not (_ah or _al), not (_bh or _bl)
                # UMULL
                if (b_zero or a_zero or _k in ((0, 1, 0, 1), (1, 0, 1, 0))):
                    _U[_k] = (2, 1)
                elif _k == (1, 1, 1, 1):
                    _U[_k] = (4, 3)
                else:
                    _U[_k] = (3, 2)
                # UMLAL
                if b_zero or a_zero or _k == (0, 1, 0, 1):
                    _UL[_k] = (2, 1)
                elif _k == (1, 1, 1, 1):
                    _UL[_k] = (6, 5)
                elif _k in ((1, 1, 1, 0), (1, 0, 1, 1)):
                    _UL[_k] = (5, 4)
                else:
                    _UL[_k] = (4, 3)


def _halves(a: int, b: int) -> tuple:
    return (int(a & 0xFFFF0000 != 0), int(a & 0xFFFF != 0),
            int(b & 0xFFFF0000 != 0), int(b & 0xFFFF != 0))


def _neg(v: int) -> bool:
    return bool(v & 0x80000000)


def _signed_mull(k: tuple, a: int, b: int, accumulate: bool) -> tuple:
    ah, al, bh, bl = k
    neg = _neg(a) or _neg(b)
    base = 2 if not accumulate else 4   # smull / smlal (hi cycles)
    if not (bh or bl) or not (ah or al):
        return (2, 1)
    if accumulate and k == (0, 1, 0, 1):
        return (2, 1)
    if k in ((0, 1, 0, 1), (1, 0, 1, 0)):
        if accumulate:
            hi = 5 if neg else 4
        else:
            hi = 3 if neg else 2
        return (hi, hi - 1)
    if k == (1, 1, 1, 0):
        hi = (base + 2 if neg else base + 1)
        return (hi, hi - 1)
    if k == (1, 0, 1, 1):
        hi = base + 1
        return (hi, hi - 1)
    if k == (1, 1, 1, 1):
        hi = base + 2
        return (hi, hi - 1)
    if accumulate:
        hi = 5 if _neg(b) else 4
    else:
        hi = 4 if _neg(b) else 3
    return (hi, hi - 1)


def _msb(v: int) -> int:
    return v.bit_length() - 1


def _udiv(a: int, b: int) -> int:
    if a == 0 or b == 0:
        t = 2
    elif _msb(a) < _msb(b):
        t = 3
    else:
        t = (_msb(a) - _msb(b)) // 4 + 5
    return t - 1


def _sdiv(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 1
    sa = a - (1 << 32) if _neg(a) else a
    rn = (-sa) & MASK if sa < 0 else a
    b_neg = _neg(b)
    rm = ((-(b - (1 << 32))) & MASK) if b_neg else b
    pow2 = rm & (rm - 1) == 0
    diff = _msb(rn) - _msb(rm)
    if b_neg and pow2 and rn != 0x80000000:
        diff += 1
    elif b_neg and not pow2 and rn == 0x80000000:
        diff -= 1
    return (3 if diff < 0 else diff // 4 + 5) - 1


def cmemu_class(kind: int, a: int, b: int) -> int:
    a &= MASK
    b &= MASK
    if kind == 1:
        return _udiv(a, b)
    if kind == 2:
        return _sdiv(a, b)
    k = _halves(a, b)
    if kind == 3:
        pair = _U[k]
    elif kind == 5:
        pair = _UL[k]
    elif kind == 4:
        pair = _signed_mull(k, a, b, accumulate=False)
    else:
        pair = _signed_mull(k, a, b, accumulate=True)
    return (pair[0] << 8) | pair[1]


def documented_class(kind: int, a: int, b: int) -> int:
    """The class the plugin's h_cls / h_doc hashes encode."""
    def mag(v: int, signed: bool) -> int:
        v &= MASK
        return (1 << 32) - v if signed and _neg(v) else v

    signed = kind in (2, 4, 6)
    ma, mb = mag(a, signed), mag(b, signed)
    if kind in DIV_KINDS:
        return (ma.bit_length() << 8) | mb.bit_length()
    return int(ma < 65536) * 2 + int(mb < 65536)


HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include "ct_latency_models.h"
int main(void) {
  unsigned k, a, b;
  while (scanf("%u %x %x", &k, &a, &b) == 3)
    printf("%u\n", ctlm_cmemu_class(k, a, b));
  return 0;
}
"""


def operand_pairs(n_random: int, seed: int = 1) -> list:
    rng = random.Random(seed)
    edge = [0, 1, 2, 3, 0xFFFF, 0x10000, 0x10001, 0x7FFF, 0x8000, 0xFFFF0000,
            0x80000000, 0x80000001, 0xFFFFFFFF, 0xFFFFFFFE, 0x7FFFFFFF,
            0x00FF0000, 0x0000FF00, 0x9D7DC000, 58728449, 8380417,
            (-8380417) & MASK, 41978, 0x80008000]
    pairs = [(a, b) for a in edge for b in edge]
    for _ in range(n_random):
        shift_a, shift_b = rng.randrange(32), rng.randrange(32)
        pairs.append((rng.getrandbits(32) >> shift_a,
                      rng.getrandbits(32) >> shift_b))
        if rng.random() < 0.3:      # zero/half-zero patterns matter most
            pairs.append((rng.choice([0, 0xFFFF, 0xFFFF0000]) &
                          rng.getrandbits(32), rng.getrandbits(32)))
    return pairs


def crosscheck(n_random: int = 40000) -> int:
    pairs = operand_pairs(n_random)
    lines = [f"{k} {a:x} {b:x}" for k in range(1, 7) for a, b in pairs]
    with tempfile.TemporaryDirectory(prefix="pqcp-ctlm-") as tmp:
        src = Path(tmp) / "h.c"
        exe = Path(tmp) / "h"
        src.write_text(HARNESS, encoding="utf-8")
        subprocess.run(["cc", "-O2", "-Wall", "-Werror", f"-I{HEADER_DIR}",
                        "-o", str(exe), str(src)], check=True)
        out = subprocess.run([str(exe)], input="\n".join(lines) + "\n",
                             capture_output=True, text=True, check=True)
    got = [int(x) for x in out.stdout.split()]
    if len(got) != len(lines):
        print(f"FAIL harness produced {len(got)} of {len(lines)} lines")
        return 1
    for line, value in zip(lines, got):
        k, a, b = line.split()
        want = cmemu_class(int(k), int(a, 16), int(b, 16))
        if want != value:
            print(f"FAIL kind={k} a={a} b={b} python={want} c={value}")
            return 1
    print(f"PQCP_CT_LATENCY_MODEL_CROSSCHECK PASS cases={len(lines)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--crosscheck", action="store_true")
    args = parser.parse_args()
    if args.crosscheck:
        return crosscheck()
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
