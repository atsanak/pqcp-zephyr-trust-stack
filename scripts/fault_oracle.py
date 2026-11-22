#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Classify a faulted run by what it means cryptographically.

Observations come from tests/ztest_fault_oracle:
  PQCP_FAULT_OBS name=<scenario> rc=<int> out=<hex>   (one per scenario)
  PQCP_FAULT_DONE

The golden (unfaulted) observations define the expected behaviour. A faulted
run is classified, in priority order:

  KEM_FO_BYPASS      a corrupted ciphertext decapsulated to the genuine
                     shared secret: the Fujisaki-Okamoto check was defeated
  SIG_VERIFY_BYPASS  a tampered signature or message was ACCEPTED
  DETECTED_RUNTIME   a runtime countermeasure (CONFIG_PQCP_FAULT_CANARY /
                     DUPLICATE) returned PQCP_*_ERR_FAULT_DETECTED
  FAIL_SAFE          a genuine input was rejected or errored: denial of
                     service, but nothing forged was accepted
  CORRUPT            some other deviation from the golden observations
  NO_EFFECT          identical to golden
  HARNESS_ERROR      the injection itself failed (stub, memory write); never
                     counted as NO_EFFECT, and a campaign with any fails
  DETECTED_BOOT      the power-on self-test (CONFIG_PQCP_KAT_BOOT_VERIFY)
                     caught the fault and halted before the workload ran
  CRASH / TIMEOUT    no DONE line (reset, panic, hang)

KEM_FO_BYPASS and SIG_VERIFY_BYPASS are the exploitable classes.
"""

import re
from dataclasses import dataclass

OBS_RE = re.compile(
    r"^PQCP_FAULT_OBS name=(\w+) rc=(-?\d+) out=([0-9a-f]*)$", re.M)
EXPLOITABLE = ("KEM_FO_BYPASS", "SIG_VERIFY_BYPASS")
CLASSES = ("NO_EFFECT", "FAIL_SAFE", "DETECTED_BOOT", "DETECTED_RUNTIME",
           "CORRUPT", "CRASH",
           "TIMEOUT", "HARNESS_ERROR",
           *EXPLOITABLE)
FAULT_DETECTED_RC = (-6, -7)  # PQCP_MLKEM/MLDSA_ERR_FAULT_DETECTED
KEM_BAD = ("KEM_CORRUPT1", "KEM_CORRUPT2")
DSA_BAD = ("DSA_BADSIG1", "DSA_BADSIG2", "DSA_BADMSG")
SCENARIOS = ("KEM_VALID", *KEM_BAD, "DSA_VALID", *DSA_BAD)


@dataclass(frozen=True)
class Obs:
    rc: int
    out: str


def parse(text: str) -> tuple[dict, bool]:
    """(observations by scenario, saw the DONE line)."""
    observed = {m.group(1): Obs(int(m.group(2)), m.group(3))
                for m in OBS_RE.finditer(text)}
    return observed, "PQCP_FAULT_DONE" in text


def validate_golden(golden: dict) -> list[str]:
    problems = [f"golden run lacks {s}" for s in SCENARIOS
                if s not in golden]
    if problems:
        return problems
    if golden["KEM_VALID"].rc != 0:
        problems.append("golden KEM_VALID failed")
    for s in KEM_BAD:
        if golden[s].out == golden["KEM_VALID"].out:
            problems.append(f"golden {s} equals the genuine key")
    if golden["DSA_VALID"].rc != 0:
        problems.append("golden DSA_VALID was rejected")
    for s in DSA_BAD:
        if golden[s].rc == 0:
            problems.append(f"golden {s} was accepted")
    return problems


def classify(golden: dict, text: str, *, timed_out: bool = False) -> str:
    observed, done = parse(text)
    if "PQCP_FAULT_HARNESS_ERROR" in text:
        return "HARNESS_ERROR"
    if "PQCP_KAT_BOOT_VERIFY FAIL" in text:
        return "DETECTED_BOOT"
    if not done:
        return "TIMEOUT" if timed_out else "CRASH"
    if any(s not in observed for s in SCENARIOS):
        return "CORRUPT"
    for s in KEM_BAD:
        if observed[s].rc == 0 and \
                observed[s].out == golden["KEM_VALID"].out:
            return "KEM_FO_BYPASS"
    for s in DSA_BAD:
        if observed[s].rc == 0:
            return "SIG_VERIFY_BYPASS"
    if all(observed[s] == golden[s] for s in SCENARIOS):
        return "NO_EFFECT"
    if any(observed[s].rc in FAULT_DETECTED_RC for s in SCENARIOS):
        return "DETECTED_RUNTIME"
    if observed["KEM_VALID"].rc != 0 or observed["DSA_VALID"].rc != 0:
        return "FAIL_SAFE"
    return "CORRUPT"
