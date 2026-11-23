#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Opt-in fixed-latency multiplication patch for mldsa-native on Cortex-M3.

Claim 14 found that the stock ML-DSA-65 signing image multiplies
secret-dependent 32-bit operands with SMULL, whose latency on a Cortex-M3
depends on operand size (ARM DDI 0337). This module is the mitigation: every
signed 32x32 -> 64 product in the Montgomery path is replaced by a helper
built from four 16x16 partial products computed with the 32-bit MUL, which is
single-cycle on Cortex-M3/M4 (and constant-time on every Cortex-M, including
the 32-cycle small-multiplier option of M0/M0+), plus shifts and adds.
The technique is not new: Greconici, Kannwischer and Sprenkels (ePrint
2020/1278) already observed that smull/smlal are not constant time on the
M3 and ship a constant-time M3 Dilithium. The vendored tree is
never edited: `apply()` patches a private copy, the same way the leak
rediscovery tests do, and the copy is built with
`-DZEPHYR_EXTRA_MODULES=<copy>`.

    python3 scripts/mldsa_fixed_latency.py --apply DEST   # materialise a copy
    python3 scripts/mldsa_fixed_latency.py --check        # anchors still match
    python3 scripts/mldsa_fixed_latency.py --selftest     # host equivalence

Every replacement is an exact-match anchor and must match once, so a vendor
update that moves the code fails loudly instead of silently un-mitigating.
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

import ct_leak_rediscovery as base  # noqa: E402

SRC = "ext/mldsa-native/mldsa/src/"
COPY_PATHS = tuple(p if p != "tests/ztest_ct_trace" else
                   "tests/ztest_ct_trace_mldsa" for p in base.COPY_PATHS)

HELPER = """\
/* PQCP fixed-latency patch (scripts/mldsa_fixed_latency.py).
 * Signed 32x32 -> 64 product from four 16x16 partial products. Every
 * multiply is a 32-bit MUL (constant-time on all Cortex-M cores), so the
 * latency no longer depends on the operand magnitudes the way SMULL does on a
 * Cortex-M3. Shifts and adds are data-independent. */
#define PQCP_FIXED_LATENCY_MUL 1
static MLD_INLINE int64_t pqcp_smul32x32(int32_t a, int32_t b)
{
  const uint32_t al = (uint32_t)a & 0xFFFFu;
  const uint32_t bl = (uint32_t)b & 0xFFFFu;
  const int32_t ah = a >> 16;
  const int32_t bh = b >> 16;
  const uint32_t ll = al * bl;
  const int32_t lh = (int32_t)al * bh;
  const int32_t hl = ah * (int32_t)bl;
  const int32_t hh = ah * bh;
  const uint64_t mid = (uint64_t)((int64_t)lh + (int64_t)hl);
  return (int64_t)(((uint64_t)(int64_t)hh << 32) + (mid << 16) +
                   (uint64_t)ll);
}

"""

# (path, exact old text, new text); every `old` must match exactly once.
PATCHES = (
    (SRC + "reduce.h",
     "/*************************************************\n"
     " * Name:        mld_montgomery_reduce\n",
     HELPER +
     "/*************************************************\n"
     " * Name:        mld_montgomery_reduce\n"),
    (SRC + "reduce.h",
     "  r = a - (int64_t)t * MLDSA_Q;",
     "  r = a - pqcp_smul32x32(t, MLDSA_Q);"),
    (SRC + "poly.c",
     "  return mld_montgomery_reduce((int64_t)a * (int64_t)b);",
     "  return mld_montgomery_reduce(pqcp_smul32x32(a, b));"),
    (SRC + "poly.c",
     "  return mld_montgomery_reduce((int64_t)a * f);",
     "  return mld_montgomery_reduce(pqcp_smul32x32(a, f));"),
    (SRC + "poly.c",
     "c->coeffs[i] = mld_montgomery_reduce((int64_t)a->coeffs[i] * "
     "b->coeffs[i]);",
     "c->coeffs[i] = mld_montgomery_reduce(\n"
     "        pqcp_smul32x32(a->coeffs[i], b->coeffs[i]));"),
    (SRC + "polyvec.c",
     "      t += (int64_t)u->vec[j].coeffs[i] * v->vec[j].coeffs[i];",
     "      t += pqcp_smul32x32(u->vec[j].coeffs[i], v->vec[j].coeffs[i]);"),
)


def check(root: Path = MODULE_PATH) -> list[str]:
    problems = []
    for path, old, _ in PATCHES:
        text = (root / path).read_text(encoding="utf-8")
        n = text.count(old)
        if n != 1:
            problems.append(f"STALE {path}: anchor matched {n}x: "
                            f"{old.strip().splitlines()[0][:60]}")
    return problems


def apply(tree: Path) -> None:
    """Patch an already-copied module tree in place."""
    for path, old, new in PATCHES:
        target = tree / path
        text = target.read_text(encoding="utf-8")
        if text.count(old) != 1:
            raise RuntimeError(f"stale anchor in {path}")
        target.write_text(text.replace(old, new, 1), encoding="utf-8")


def materialise(dest: Path) -> Path:
    base.build_base(dest, COPY_PATHS)
    apply(dest)
    return dest


SELFTEST_C = r"""
#include <stdint.h>
#include <stdio.h>
#define MLD_INLINE static inline
%(helper)s
static uint64_t s = 88172645463325252ull;
static uint32_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17;
                            return (uint32_t)(s >> 16); }
int main(void) {
  static const int32_t edge[] = {0, 1, -1, 2, -2, 65535, 65536, -65535,
    -65536, 32767, 32768, -32768, -32769, 8380417, -8380417, 4190208,
    -4190208, 58728449, INT32_MAX, INT32_MIN, INT32_MAX - 1, INT32_MIN + 1,
    0x7FFF0000, (int32_t)0x80008000, 0x00010001, 0x12345678};
  uint64_t n = 0;
  for (unsigned i = 0; i < sizeof edge / sizeof *edge; ++i)
    for (unsigned j = 0; j < sizeof edge / sizeof *edge; ++j, ++n)
      if (pqcp_smul32x32(edge[i], edge[j]) !=
          (int64_t)edge[i] * (int64_t)edge[j]) {
        printf("FAIL edge %%d %%d\n", edge[i], edge[j]); return 1; }
  for (uint32_t k = 0; k < 20000000u; ++k, ++n) {
    int32_t a = (int32_t)(rnd() ^ (rnd() << 16));
    int32_t b = (int32_t)(rnd() ^ (rnd() << 16));
    if (k & 1u) a >>= (k >> 1) %% 31u;
    if (k & 2u) b >>= (k >> 3) %% 31u;
    if (pqcp_smul32x32(a, b) != (int64_t)a * (int64_t)b) {
      printf("FAIL rand %%d %%d\n", a, b); return 1; }
  }
  printf("PQCP_MLDSA_FIXED_MUL_SELFTEST PASS products=%%llu\n",
         (unsigned long long)n);
  return 0;
}
"""


def selftest() -> int:
    helper = HELPER.replace("static MLD_INLINE", "static inline")
    with tempfile.TemporaryDirectory(prefix="pqcp-fixedmul-") as tmp:
        src = Path(tmp) / "t.c"
        src.write_text(SELFTEST_C % {"helper": helper}, encoding="utf-8")
        exe = Path(tmp) / "t"
        subprocess.run(["cc", "-O2", "-fsanitize=undefined",
                        "-fno-sanitize-recover=undefined", "-o", str(exe),
                        str(src)], check=True)
        out = subprocess.run([str(exe)], capture_output=True, text=True)
    print(out.stdout.strip() or out.stderr.strip())
    return out.returncode


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
        print(f"PQCP_MLDSA_FIXED_MUL_ANCHORS "
              f"{'FAIL' if problems else 'PASS'} patches={len(PATCHES)}")
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
