#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Does the number of ML-DSA signing attempts depend on the secret key?

Host build of the real mldsa-native (ML-DSA-65, deterministic signing) from a
private patched copy that exports the attempt counter. For K keys and M
messages per key it records the per-key attempt histogram, then tests the
histograms for homogeneity (chi-square) and the per-key mean attempt count for
correlation with key statistics (sum of |s1|, |s2|, |t0| coefficients).
Hypotheses and the theory-based prediction are registered in
docs/ct-latency-model-sensitivity.md.

    python3 scripts/mldsa_rejection_study.py --keys 200 --messages 5000
    python3 scripts/mldsa_rejection_study.py --selftest
"""

import argparse
import math
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MODULE = SCRIPT_DIR.parent
SRC = MODULE / "ext" / "mldsa-native"
BINS = 40                     # attempt counts >= BINS-1 share the last bin
SIGN_C = "mldsa/src/sign.c"
ANCHOR = "    nonce++;\n    if (ret == 0)"
PATCHED = "    nonce++;\n    pqcp_attempts = nonce;\n    if (ret == 0)"
EXTERN = "volatile unsigned int pqcp_attempts;\n"

DRIVER = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mldsa_native.h"
extern volatile unsigned int pqcp_attempts;
/* Unused: only the deterministic internal entry points are called. */
int randombytes(uint8_t *out, size_t outlen) { memset(out, 0, outlen); return 0; }
static uint64_t st;
static uint64_t rnd64(void) { st ^= st << 13; st ^= st >> 7; st ^= st << 17; return st; }
int main(int argc, char **argv) {
  unsigned keys = (unsigned)atoi(argv[1]), msgs = (unsigned)atoi(argv[2]);
  unsigned long long seed0 = strtoull(argv[3], 0, 10);
  const char *skfile = argv[4];
  static uint8_t pk[MLDSA_PUBLICKEYBYTES(65)], sk[MLDSA_SECRETKEYBYTES(65)];
  static uint8_t sig[MLDSA_BYTES(65)];
  uint8_t seed[32], rnd[32] = {0}, msg[32];
  FILE *fsk = fopen(skfile, "wb");
  for (unsigned k = 0; k < keys; ++k) {
    st = seed0 * 2654435761ULL + k * 0x9E3779B97F4A7C15ULL + 1;
    for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)(rnd64() >> 24);
    if (mldsa_keypair_internal(pk, sk, seed)) return 2;
    fwrite(sk, 1, sizeof(sk), fsk);
    unsigned hist[%(bins)d] = {0};
    for (unsigned m = 0; m < msgs; ++m) {
      for (int i = 0; i < 32; ++i) msg[i] = (uint8_t)(rnd64() >> 17);
      size_t siglen = 0;
      if (mldsa_signature_internal(sig, &siglen, msg, 32, NULL, 0, rnd, sk, 0)) return 3;
      unsigned a = pqcp_attempts; if (a >= %(bins)d) a = %(bins)d - 1;
      hist[a]++;
    }
    printf("K %%u", k);
    for (int b = 0; b < %(bins)d; ++b) printf(" %%u", hist[b]);
    printf("\n");
  }
  fclose(fsk);
  return 0;
}
""" % {"bins": BINS}


def chi2_sf(x: float, k: int) -> float:
    """Survival function of the chi-square distribution (regularised upper
    incomplete gamma, series / continued fraction, no SciPy)."""
    if x <= 0:
        return 1.0
    a, z = k / 2.0, x / 2.0
    if z < a + 1.0:
        term = total = 1.0 / a
        n = a
        for _ in range(10000):
            n += 1.0
            term *= z / n
            total += term
            if abs(term) < abs(total) * 1e-15:
                break
        p = total * math.exp(-z + a * math.log(z) - math.lgamma(a))
        return max(0.0, 1.0 - p)
    tiny = 1e-300
    b = z + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 10000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        d = tiny if abs(d) < tiny else d
        c = b + an / c
        c = tiny if abs(c) < tiny else c
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    return min(1.0, math.exp(-z + a * math.log(z) - math.lgamma(a)) * h)


def homogeneity(hists: list[list[int]]) -> tuple[float, int, float]:
    """Chi-square test that every row has the same distribution. Columns with
    an expected count below 5 are merged into their neighbour."""
    cols = len(hists[0])
    totals = [sum(h[c] for h in hists) for c in range(cols)]
    rows = [sum(h) for h in hists]
    grand = sum(rows)
    # merge sparse columns (right to left)
    groups, cur = [], []
    for c in range(cols - 1, -1, -1):
        cur.append(c)
        if min(rows) * sum(totals[x] for x in cur) / grand >= 5.0:
            groups.append(cur)
            cur = []
    if cur:
        if groups:
            groups[-1].extend(cur)
        else:
            groups.append(cur)
    chi2 = 0.0
    for g in groups:
        tg = sum(totals[c] for c in g)
        for h, r in zip(hists, rows):
            expected = r * tg / grand
            if expected > 0:
                obs = sum(h[c] for c in g)
                chi2 += (obs - expected) ** 2 / expected
    dof = (len(groups) - 1) * (len(hists) - 1)
    return chi2, dof, chi2_sf(chi2, dof) if dof > 0 else 1.0


def pearson(xs: list[float], ys: list[float]) -> float:
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    syy = sum((y - my) ** 2 for y in ys)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    return sxy / math.sqrt(sxx * syy) if sxx > 0 and syy > 0 else 0.0


def unpack(sk: bytes) -> dict:
    """ML-DSA-65 secret key: rho(32) K(32) tr(64) s1(5x128) s2(6x128) t0(6x416);
    eta = 4: 4-bit coefficients (eta - v); t0: 13-bit (2^12 - v)."""
    off = 128
    s1 = sk[off:off + 5 * 128]
    s2 = sk[off + 5 * 128:off + 11 * 128]
    t0 = sk[off + 11 * 128:off + 11 * 128 + 6 * 416]
    l1 = lambda data: sum(  # noqa: E731
        abs(4 - (b & 15)) + abs(4 - (b >> 4)) for b in data)
    bits = int.from_bytes(t0, "little")
    t0l1 = sum(abs(4096 - ((bits >> (13 * i)) & 0x1FFF))
               for i in range(len(t0) * 8 // 13))
    return {"s1": l1(s1), "s2": l1(s2), "t0": t0l1}


def build(tmp: Path) -> Path:
    copy = tmp / "mldsa-native"
    shutil.copytree(SRC / "mldsa", copy / "mldsa", symlinks=True)
    sign = copy / SIGN_C
    text = sign.read_text(encoding="utf-8")
    if text.count(ANCHOR) != 1:
        raise RuntimeError("stale attempt-counter anchor")
    sign.write_text(EXTERN + text.replace(ANCHOR, PATCHED, 1),
                    encoding="utf-8")
    (tmp / "driver.c").write_text(DRIVER, encoding="utf-8")
    exe = tmp / "study"
    subprocess.run(
        ["cc", "-O2", "-DMLD_CONFIG_PARAMETER_SET=65",
         "-DMLD_CONFIG_NAMESPACE_PREFIX=mldsa",
         f"-I{copy / 'mldsa'}", str(copy / "mldsa" / "mldsa_native.c"),
         str(tmp / "driver.c"), "-o", str(exe)], check=True)
    return exe


def run(keys: int, msgs: int, seed: int) -> int:
    with tempfile.TemporaryDirectory(prefix="pqcp-reject-") as t:
        tmp = Path(t)
        exe = build(tmp)
        out = subprocess.run([str(exe), str(keys), str(msgs), str(seed),
                              str(tmp / "sk.bin")], capture_output=True,
                             text=True, check=True).stdout
        sks = (tmp / "sk.bin").read_bytes()
    hists = [[int(x) for x in line.split()[2:]] for line in out.splitlines()]
    sk_len = len(sks) // keys
    stats = [unpack(sks[i * sk_len:(i + 1) * sk_len]) for i in range(keys)]
    means = [sum(a * c for a, c in enumerate(h)) / max(sum(h), 1)
             for h in hists]
    pooled = sum(means) / len(means)
    chi2, dof, p = homogeneity(hists)
    se = math.sqrt(sum((m - pooled) ** 2 for m in means) / (len(means) - 1))
    rs = {k: pearson([s[k] for s in stats], means) for k in ("s1", "s2", "t0")}
    verdict = "DEPENDENT" if p < 1e-3 else "CONSISTENT_WITH_INDEPENDENT"
    print(f"PQCP_MLDSA_REJECTION_STUDY {verdict} keys={keys} msgs={msgs} "
          f"pooled_mean={pooled:.4f} key_mean_sd={se:.4f} "
          f"relative_sd={se / pooled:.5f} chi2={chi2:.1f} dof={dof} "
          f"p={p:.4g} r_s1={rs['s1']:.3f} r_s2={rs['s2']:.3f} "
          f"r_t0={rs['t0']:.3f}")
    return 0


def selftest() -> int:
    rng = random.Random(7)
    # same-distribution rows must not reject; clearly different rows must.
    same = [[0] * 12 for _ in range(30)]
    for h in same:
        for _ in range(4000):
            h[min(int(rng.expovariate(0.5)), 11)] += 1
    _, _, p_same = homogeneity(same)
    diff = [row[:] for row in same]
    for _ in range(4000):
        diff[0][min(int(rng.expovariate(0.2)), 11)] += 1
    _, _, p_diff = homogeneity(diff)
    ok = (p_same > 1e-3 and p_diff < 1e-6 and
          abs(chi2_sf(10.0, 4) - 0.04043) < 1e-4 and
          # even dof has a closed form: e^{-x/2} * sum_{i<k/2} (x/2)^i / i!
          abs(chi2_sf(50.0, 30) - math.exp(-25.0) * sum(
              25.0 ** i / math.factorial(i) for i in range(15))) < 1e-12 and
          abs(pearson([1, 2, 3, 4], [2, 4, 6, 9]) - 0.99438) < 1e-4)
    print(f"PQCP_MLDSA_REJECTION_SELFTEST {'PASS' if ok else 'FAIL'} "
          f"p_same={p_same:.3g} p_diff={p_diff:.3g}")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--keys", type=int, default=200)
    ap.add_argument("--messages", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return run(args.keys, args.messages, args.seed)


if __name__ == "__main__":
    sys.exit(main())
