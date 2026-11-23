#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Opt-in operand-offset repair for the ML-KEM compress_d10 multiply.

Claim 16 found that the multiply-and-shift `(uint64_t)u * 2642263040` in
mlk_scalar_compress_d10 is constant under the documented Cortex-M3 rule but
one cycle faster for u == 0 under the CMEmu model (a zero operand is the
fast case). The repair offsets the operand so both 16-bit halves are always
non-zero and removes the offset from the 64-bit product afterwards:

    ub = u + 0x10001            # hi = 1, lo = u + 1 in [1, 3329]: never zero
    d0 = ub * C - 0x10001 * C   # identical value, constant latency class

An empty asm statement keeps the compiler from folding the offset away. Cost:
one add and one 64-bit subtract per coefficient, not a 16x16 split. A private
copy of mlkem-native is patched (the vendored tree is never edited).

    python3 scripts/mlkem_fixed_latency.py --apply DEST | --check | --selftest
"""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

import ct_latency_models as lm  # noqa: E402
import ct_leak_rediscovery as base  # noqa: E402

PATH = "ext/mlkem-native/mlkem/src/compress.h"
Q = 3329
# (name, constant, output mask): ML-KEM-512/768 use d10, ML-KEM-1024 uses d11.
VARIANTS = (("d10", 2642263040, 0x3FF), ("d11", 5284526080, 0x7FF))


def _old(const: int) -> str:
    return f"  uint64_t d0 = (uint64_t)u * {const};\n"


def _new(const: int) -> str:
    return f"""  /* PQCP operand-offset patch (scripts/mlkem_fixed_latency.py): both 16-bit
   * halves of ub are always non-zero, so the multiply latency does not
   * depend on u == 0. The asm keeps the compiler from folding it away. */
  uint32_t ub = (uint32_t)u + 0x10001u;
  uint64_t d0;
  __asm__("" : "+r"(ub));
  d0 = (uint64_t)ub * {const} - (uint64_t)0x10001u * {const};
"""


COPY_PATHS = base.COPY_PATHS


def check(root: Path = MODULE_PATH) -> list[str]:
    text = (root / PATH).read_text(encoding="utf-8")
    return [f"STALE {PATH}: {name} anchor matched {text.count(_old(c))}x"
            for name, c, _ in VARIANTS if text.count(_old(c)) != 1]


def apply(tree: Path) -> None:
    target = tree / PATH
    text = target.read_text(encoding="utf-8")
    for name, const, _ in VARIANTS:
        if text.count(_old(const)) != 1:
            raise RuntimeError(f"stale {name} anchor in {PATH}")
        text = text.replace(_old(const), _new(const), 1)
    target.write_text(text, encoding="utf-8")


def materialise(dest: Path) -> Path:
    base.build_base(dest, COPY_PATHS)
    apply(dest)
    return dest


C_TEST = r"""
#include <stdint.h>
#include <stdio.h>
#define MAKE(NAME, C, MASK) \
static uint16_t ref_##NAME(int16_t u) { \
  uint64_t d0 = (uint64_t)u * C; d0 = (d0 + ((uint64_t)1u << 32)) >> 33; \
  return d0 & MASK; } \
static uint16_t fix_##NAME(int16_t u) { \
  uint32_t ub = (uint32_t)u + 0x10001u; uint64_t d0; \
  __asm__("" : "+r"(ub)); \
  d0 = (uint64_t)ub * C - (uint64_t)0x10001u * C; \
  d0 = (d0 + ((uint64_t)1u << 32)) >> 33; return d0 & MASK; }
MAKE(d10, 2642263040, 0x3FF)
MAKE(d11, 5284526080, 0x7FF)
int main(void) {
  for (int u = 0; u < 3329; ++u) {
    if (ref_d10((int16_t)u) != fix_d10((int16_t)u)) { printf("FAIL d10 %d\n", u); return 1; }
    if (ref_d11((int16_t)u) != fix_d11((int16_t)u)) { printf("FAIL d11 %d\n", u); return 1; }
  }
  printf("OK\n");
  return 0;
}
"""


def selftest() -> int:
    # 1. exhaustive value equivalence over the whole input domain, both
    #    variants (d10 for ML-KEM-512/768, d11 for ML-KEM-1024).
    with tempfile.TemporaryDirectory(prefix="pqcp-mlkemfix-") as tmp:
        src, exe = Path(tmp) / "t.c", Path(tmp) / "t"
        src.write_text(C_TEST, encoding="utf-8")
        subprocess.run(["cc", "-O2", "-o", str(exe), str(src)], check=True)
        out = subprocess.run([str(exe)], capture_output=True, text=True)
    if out.stdout.strip() != "OK":
        print("FAIL value equivalence", out.stdout)
        return 1
    # 2. exhaustive latency check. The multiplier operand is the low 32 bits
    #    of the constant (the compiler folds the 33rd bit into a shift).
    stock_all, fixed_all = [], []
    for name, const, _ in VARIANTS:
        c32 = const & 0xFFFFFFFF
        stock = {lm.cmemu_class(3, u, c32) for u in range(Q)}
        fixed = {lm.cmemu_class(3, u + 0x10001, c32) for u in range(Q)}
        doc = {lm.documented_class(3, u + 0x10001, c32) for u in range(Q)}
        if len(stock) < 2 or len(fixed) != 1 or len(doc) != 1:
            print(f"FAIL latency classes {name} stock={len(stock)} "
                  f"fixed={len(fixed)} documented_fixed={len(doc)}")
            return 1
        stock_all.append(len(stock))
        fixed_all.append(len(fixed))
    print(f"PQCP_MLKEM_FIXED_LATENCY_SELFTEST PASS domain={Q} "
          f"stock_cmemu_classes={min(stock_all)} fixed_cmemu_classes=1 "
          f"variants={len(VARIANTS)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--apply", type=Path, metavar="DEST")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.check:
        problems = check()
        for p in problems:
            print(f"[fixed-latency] {p}")
        print(f"PQCP_MLKEM_FIXED_LATENCY_ANCHORS "
              f"{'FAIL' if problems else 'PASS'}")
        return 1 if problems else 0
    if args.selftest:
        return selftest()
    if args.apply:
        print(materialise(args.apply))
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
