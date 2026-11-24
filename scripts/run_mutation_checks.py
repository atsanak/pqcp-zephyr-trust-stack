#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation-test the host evidence verifier's security checks.

Passing tests only prove the checks accept good evidence. This proves the
tests would NOTICE if a check were removed: each mutant weakens exactly one
security decision (a digest comparison, a cross-layer binding, the
signature check, duplicate-marker detection) in a private copy of the
verifier sources, rebuilds, and runs scripts/test_evidence_verifier.py.

  killed    the test suite failed -> the check is genuinely guarded
  SURVIVED  the suite still passed -> a test gap: a real regression of
            that check would ship unnoticed
  STALE     the mutation pattern no longer matches exactly once -> the
            mutant list has rotted and must be updated
  allowed   survived, but with a written reason: either redundant by design
            (a second check enforces the same predicate, so only removing
            BOTH is observable; a combined mutant covers that) or a
            documented fixture gap. Allowed survivors are counted in the
            PASS marker so they stay visible.

Mutants weaken (never merely invert) checks: inversion is caught by any
test, whereas silently accepting forged evidence is the failure that
matters. Exits nonzero on any survivor or stale mutant. Runs entirely on
temporary copies; the working tree is never modified.
"""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent.parent

COPY_PATHS = (
    "include",
    "tools/evidence_verifier",
    "tools/evidence_register",
    "scripts/test_evidence_verifier.py",
    "scripts/run_transparent_appraisal.py",
    "scripts/rfc9162_reference.py",
    "scripts/local_workflow.py",
    "ext/mldsa-native/mldsa",
)
REPLAY_SOURCES = (
    "src/evidence/deployment_evidence_verdict_replay.c",
    "src/evidence/deployment_evidence_seal_replay.c",
    "src/evidence/deployment_assurance_passport_replay.c",
    "src/evidence/deployment_evidence_trail_replay.c",
    "src/evidence/deployment_tamper_matrix_replay.c",
    # RFC 9162 transparency code shared by the verifier and register tool.
    "src/experimental/fleet/fleet_cbor_map.c",
    "src/experimental/fleet/fleet_transparency_merkle.c",
    "src/experimental/fleet/fleet_transparency_log.c",
    "src/experimental/fleet/fleet_transparency_proof.c",
    "src/experimental/fleet/fleet_transparency_checkpoint.c",
)

# Test suites a mutant can be judged by. Receipt/consistency checks are only
# exercised end to end by the transparent appraisal driver (C verifier versus
# the independent python reference, forgery list), so those mutants select it.
SUITES = {
    "verifier": "scripts/test_evidence_verifier.py",
    "appraisal": "scripts/run_transparent_appraisal.py",
}


@dataclass(frozen=True)
class Mutant:
    name: str
    path: str
    pattern: str
    replacement: str
    # Additional (path, pattern, replacement) edits applied together.
    extra: tuple = ()
    # Non-empty: a survivor is acceptable, for this stated reason.
    allowance: str = ""
    # Key of SUITES: which suite must notice this mutant.
    suite: str = "verifier"


def digest_check_disabled(name: str, path: str, expr: str) -> Mutant:
    return Mutant(
        name=name, path=path,
        pattern=r"if \(strcmp\(recomputed, " + re.escape(expr) + r"\) != 0\) \{",
        replacement="if (0 && strcmp(recomputed, " + expr + ") != 0) {")


def binding_disabled(name: str, expr_regex: str) -> Mutant:
    return Mutant(name=name, path="tools/evidence_verifier/src/main.c",
                  pattern=expr_regex, replacement="1")


MUTANTS = (
    digest_check_disabled(
        "verdict replay: digest recomputation check removed",
        "src/evidence/deployment_evidence_verdict_replay.c",
        "verdict->verdict_digest_hex"),
    digest_check_disabled(
        "seal replay: digest recomputation check removed",
        "src/evidence/deployment_evidence_seal_replay.c", "seal->seal_digest_hex"),
    digest_check_disabled(
        "passport replay: digest recomputation check removed",
        "src/evidence/deployment_assurance_passport_replay.c",
        "passport->passport_digest_hex"),
    digest_check_disabled(
        "trail replay: hash-chain link check removed",
        "src/evidence/deployment_evidence_trail_replay.c", "entry->link_digest_hex"),
    digest_check_disabled(
        "tamper matrix replay: matrix digest check removed",
        "src/evidence/deployment_tamper_matrix_replay.c", "report->matrix_digest_hex"),
    Mutant(
        "verdict replay: duplicate-marker detection removed",
        "src/evidence/deployment_evidence_verdict_replay.c",
        r"if \(\(state->marker_mask &\s*"
        r"PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_MARKER_VERDICT\) != 0U\) \{",
        "if (0) {"),
    binding_disabled(
        "host: verdict->seal digest binding removed",
        r"strcmp\(summary->seal\.verdict_digest_hex,\s*"
        r"summary->verdict\.computed_digest_hex\) == 0"),
    binding_disabled(
        "host: seal->passport digest binding removed",
        r"strcmp\(passport_state\.passport\.seal_digest_hex,\s*"
        r"summary->seal\.computed_digest_hex\) == 0"),
    binding_disabled(
        "host: passport->tamper-matrix binding removed",
        r"strcmp\(summary->tamper\.passport_digest_hex,\s*"
        r"summary->passport\.computed_digest_hex\) == 0"),
    Mutant(
        "host: verdict->trail identity binding removed",
        "tools/evidence_verifier/src/main.c",
        r"strcmp\(summary->trail\.top_candidate_id,\s*"
        r"summary->verdict\.top_candidate_id\) == 0 &&",
        "1 &&",
        allowance=("fixture gap: needs a second device run with a different "
                   "top candidate or nonce; both fixtures share identity, "
                   "and forging identity in one marker breaks that "
                   "marker's own digest instead")),
    Mutant(
        "host: signature->passport digest binding removed",
        "tools/evidence_verifier/src/main.c",
        r"strcmp\(sig_capture\.passport_digest_hex,\s*"
        r"summary->passport\.computed_digest_hex\) == 0",
        "1",
        allowance=("redundant by design: signature_capture_verify repeats "
                   "the same comparison; see the combined mutant below")),
    Mutant(
        "signature: capture/passport digest comparison removed",
        "tools/evidence_verifier/src/signature_check.c",
        r"strcmp\(capture->passport_digest_hex, passport_digest_hex\) != 0",
        "0",
        allowance=("redundant by design: the host binding repeats the same "
                   "comparison; see the combined mutant below")),
    Mutant(
        "signature: BOTH digest comparisons removed (splice would verify)",
        "tools/evidence_verifier/src/main.c",
        r"strcmp\(sig_capture\.passport_digest_hex,\s*"
        r"summary->passport\.computed_digest_hex\) == 0",
        "1",
        extra=(("tools/evidence_verifier/src/signature_check.c",
                r"strcmp\(capture->passport_digest_hex, "
                r"passport_digest_hex\) != 0", "0"),)),
    Mutant(
        "signature: ML-DSA verification result ignored",
        "tools/evidence_verifier/src/signature_check.c",
        r"return ret == 0 \? 0 : -EBADMSG;",
        "(void)ret; return 0;"),
    # Receipt / consistency verification: judged by the transparent appraisal
    # driver (C verifier versus the independent python reference).
    Mutant(
        "receipt: tree_size binding to the signed checkpoint removed",
        "tools/evidence_verifier/src/receipt_verify.c",
        r"if \(receipt->tree_size != receipt->checkpoint.tree_size\) \{",
        "if (0) {", suite="appraisal"),
    Mutant(
        "receipt: checkpoint ML-DSA signature result ignored",
        "tools/evidence_verifier/src/receipt_verify.c",
        r"if \(pqcp_fleet_transparency_checkpoint_verify\(&fleet, &hash,\s*"
        r"&sigops\) != 0\) \{",
        "if (0) {", suite="appraisal"),
    Mutant(
        "receipt: log_id binding to the pinned log key removed",
        "tools/evidence_verifier/src/receipt_verify.c",
        r"if \(memcmp\(checkpoint->log_id, ctx.key_id, 32U\) != 0 \|\|\s*"
        r"memcmp\(checkpoint->signer_key_id, ctx.key_id, 32U\) != 0\) \{",
        "if (0) {", suite="appraisal"),
    Mutant(
        "consistency: equivocation detection removed",
        "tools/evidence_verifier/src/receipt_verify.c",
        r"if \(\(o->tree_size == n->tree_size &&\s*"
        r"memcmp\(o->root, n->root, 32U\) != 0\) \|\|\s*"
        r"\(o->sequence == n->sequence &&\s*"
        r"\(o->tree_size != n->tree_size \|\|\s*"
        r"memcmp\(o->root, n->root, 32U\) != 0\)\)\) \{",
        "if (0) {", suite="appraisal"),
    Mutant(
        "consistency: rollback sequence check removed",
        "tools/evidence_verifier/src/receipt_verify.c",
        r"if \(n->sequence <= o->sequence \|\| n->tree_size < o->tree_size\) \{",
        "if (n->tree_size < o->tree_size) {", suite="appraisal"),
)


def build_base(destination: Path) -> None:
    for relative in COPY_PATHS + REPLAY_SOURCES:
        source = MODULE_ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copy2(source, target)


def run_suite(tree: Path, suite: str = "verifier") -> subprocess.CompletedProcess:
    command = [sys.executable, str(tree / SUITES[suite])]
    if suite == "appraisal":
        # Own build/work directory beside the mutant tree (never inside it,
        # so copies of the base tree carry no stale build); a small sweep keeps
        # the run short (the fixed forgery list is what kills the mutants).
        command += ["--output-dir",
                    str(tree.parent / (tree.name + "-appraisal-work")),
                    "--sweep-flips", "4"]
    return subprocess.run(command, capture_output=True, text=True, cwd=tree)


def apply_edit(tree: Path, path: str, pattern: str,
               replacement: str) -> str | None:
    target = tree / path
    text = target.read_text(encoding="utf-8")
    matches = re.findall(pattern, text, flags=re.S)
    if len(matches) != 1:
        return f"{path}: pattern matched {len(matches)} times"
    target.write_text(
        re.sub(pattern, lambda _m: replacement, text, count=1, flags=re.S),
        encoding="utf-8")
    return None


def evaluate(base: Path, mutant: Mutant, scratch: Path, index: int) -> tuple:
    tree = scratch / f"mutant-{index}"
    shutil.copytree(base, tree)
    edits = ((mutant.path, mutant.pattern, mutant.replacement),
             *mutant.extra)
    for path, pattern, replacement in edits:
        problem = apply_edit(tree, path, pattern, replacement)
        if problem:
            return mutant, "STALE", problem
    result = run_suite(tree, mutant.suite)
    if result.returncode != 0:
        return mutant, "killed", ""
    if mutant.allowance:
        return mutant, "allowed", mutant.allowance
    return mutant, "SURVIVED", "test suite still passed"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="pqcp-mutation-") as tmp:
        scratch = Path(tmp)
        base = scratch / "base"
        build_base(base)

        for suite in sorted({"verifier"} | {m.suite for m in MUTANTS}):
            print(f"[mutation] baseline: unmutated {suite} suite must pass")
            baseline = run_suite(base, suite)
            if baseline.returncode != 0:
                print(baseline.stdout + baseline.stderr)
                print(f"[mutation] FAIL: baseline {suite} suite does not pass")
                return 1

        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            outcomes = list(pool.map(
                lambda item: evaluate(base, item[1], scratch, item[0]),
                enumerate(MUTANTS)))

    killed = 0
    allowed = 0
    problems = []
    for mutant, status, note in outcomes:
        suffix = f" ({note})" if note else ""
        print(f"[mutation] {status:8s} {mutant.name}{suffix}")
        if status == "killed":
            killed += 1
        elif status == "allowed":
            allowed += 1
        else:
            problems.append(mutant.name)

    if problems:
        print(f"[mutation] FAIL: {len(problems)} of {len(MUTANTS)} mutant(s) "
              "not killed; add a test that exercises each")
        return 1
    print(f"PQCP_MUTATION PASS mutants={len(MUTANTS)} killed={killed} "
          f"allowed_survivors={allowed}")
    print("[mutation] PASS: every weakened security check was caught "
          "(allowed survivors are documented above)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
