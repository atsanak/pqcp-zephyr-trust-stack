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
OLD = "  uint64_t d0 = (uint64_t)u * 2642263040;\n"
NEW = """  /* PQCP operand-offset patch (scripts/mlkem_fixed_latency.py): both 16-bit
   * halves of ub are always non-zero, so the multiply latency does not
   * depend on u == 0. The asm keeps the compiler from folding it away. */
  uint32_t ub = (uint32_t)u + 0x10001u;
  uint64_t d0;
  __asm__("" : "+r"(ub));
  d0 = (uint64_t)ub * 2642263040 - (uint64_t)0x10001u * 2642263040;
"""
COPY_PATHS = base.COPY_PATHS
Q = 3329
C = 2642263040


def check(root: Path = MODULE_PATH) -> list[str]:
    n = (root / PATH).read_text(encoding="utf-8").count(OLD)
    return [] if n == 1 else [f"STALE {PATH}: anchor matched {n}x"]


def apply(tree: Path) -> None:
    target = tree / PATH
    text = target.read_text(encoding="utf-8")
    if text.count(OLD) != 1:
        raise RuntimeError(f"stale anchor in {PATH}")
    target.write_text(text.replace(OLD, NEW, 1), encoding="utf-8")


def materialise(dest: Path) -> Path:
    base.build_base(dest, COPY_PATHS)
    apply(dest)
    return dest


C_TEST = r"""
#include <stdint.h>
#include <stdio.h>
static uint16_t ref(int16_t u) {
  uint64_t d0 = (uint64_t)u * 2642263040;
  d0 = (d0 + ((uint64_t)1u << 32)) >> 33;
  return d0 & 0x3FF;
}
static uint16_t fixed(int16_t u) {
  uint32_t ub = (uint32_t)u + 0x10001u;
  uint64_t d0;
  __asm__("" : "+r"(ub));
  d0 = (uint64_t)ub * 2642263040 - (uint64_t)0x10001u * 2642263040;
  d0 = (d0 + ((uint64_t)1u << 32)) >> 33;
  return d0 & 0x3FF;
}
int main(void) {
  for (int u = 0; u < 3329; ++u)
    if (ref((int16_t)u) != fixed((int16_t)u)) { printf("FAIL %d\n", u); return 1; }
  printf("OK\n");
  return 0;
}
"""


def selftest() -> int:
    # 1. exhaustive value equivalence over the whole input domain.
    with tempfile.TemporaryDirectory(prefix="pqcp-mlkemfix-") as tmp:
        src, exe = Path(tmp) / "t.c", Path(tmp) / "t"
        src.write_text(C_TEST, encoding="utf-8")
        subprocess.run(["cc", "-O2", "-o", str(exe), str(src)], check=True)
        out = subprocess.run([str(exe)], capture_output=True, text=True)
    if out.stdout.strip() != "OK":
        print("FAIL value equivalence", out.stdout)
        return 1
    # 2. exhaustive latency check: the repaired operand has ONE latency class
    #    under both models over the whole domain, the stock operand does not.
    stock = {lm.cmemu_class(3, u, C) for u in range(Q)}
    fixed = {lm.cmemu_class(3, u + 0x10001, C) for u in range(Q)}
    doc_fixed = {lm.documented_class(3, u + 0x10001, C) for u in range(Q)}
    if len(stock) < 2 or len(fixed) != 1 or len(doc_fixed) != 1:
        print(f"FAIL latency classes stock={len(stock)} fixed={len(fixed)} "
              f"documented_fixed={len(doc_fixed)}")
        return 1
    print(f"PQCP_MLKEM_FIXED_LATENCY_SELFTEST PASS domain={Q} "
          f"stock_cmemu_classes={len(stock)} fixed_cmemu_classes=1")
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
