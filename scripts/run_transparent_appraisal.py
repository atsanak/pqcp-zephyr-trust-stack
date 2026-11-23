#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""End-to-end transparent appraisal receipt driver (differential + forgeries).

Orchestrates the whole transparent-appraisal path with no Zephyr tooling:

1. build tools/evidence_verifier and tools/evidence_register (cmake),
2. replay the committed device transcripts (tools/evidence_verifier/testdata,
   signed fixture included) into appraisal statements,
3. register them in deterministic RFC 9162 logs (fixed seeds, fixed
   timestamps), cut ML-DSA-65-signed checkpoints, receipts and consistency
   proofs,
4. verify EVERY case with the C verifier (pqcp-evidence-verify) AND with the
   independently written stdlib verifier scripts/rfc9162_reference.py and
   require agreement on accept/reject (the differential),
5. run a forgery list, each of which must be REJECTED by the C verifier with
   the expected reason (and by python with the comparable reason where python
   can check it), plus one positive control per forgery class so a verifier
   that rejects everything cannot pass.

Python has no ML-DSA, so it reports the checkpoint signature as "delegated".
Cases whose only defect is a flipped signature byte therefore require the C
verifier to reject and python to ACCEPT-with-signature-delegated; they are
excluded from the differential count and reported separately.

Orchestration only: every verification decision is made by the C verifier or
the python reference; this script compares them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from local_workflow import clean_env, run_command  # noqa: E402

TESTDATA = MODULE_PATH / "tools" / "evidence_verifier" / "testdata"
REFERENCE = SCRIPT_DIR / "rfc9162_reference.py"
CKPT_PREFIX = b"PQCP-FLEET-TRANSPARENCY-CHECKPOINT-V1"
DEFAULT_SEED = 20260101
DEFAULT_SWEEP_FLIPS = 48
BASE_TIMESTAMP_MS = 1_700_000_000_000

KNOWN_PY_FAULTS = ("skip-root-binding", "skip-tree-size-binding",
                   "no-leaf-prefix", "skip-equivocation", "skip-rollback")

# For the randomized bit-flip sweep: C reason -> python reasons that are an
# acceptable counterpart. C checks the signature before anything structural
# and python never can, so for a flip inside a signed checkpoint field python
# reports the broken transcript_digest instead (bad_checkpoint).
COMPAT = {
    "malformed": {"malformed", "bad_statement", "bad_checkpoint"},
    "log_id_mismatch": {"log_id_mismatch", "bad_checkpoint"},
    "bad_signature": {"bad_checkpoint"},
    "tree_size_mismatch": {"tree_size_mismatch"},
    "inclusion_proof_invalid": {"inclusion_proof_invalid", "bad_statement"},
    "statement_malformed": {"bad_statement"},
    "equivocation": {"equivocation"},
    "rollback": {"rollback"},
    "consistency_proof_invalid": {"consistency_proof_invalid"},
}


# ---------------------------------------------------------------------------
# Minimal CBOR walker / encoder (offsets for surgical edits, never decisions)
# ---------------------------------------------------------------------------

class CborWalkError(ValueError):
    pass


@dataclass
class Item:
    major: int
    arg: int
    start: int
    hdr_end: int
    end: int
    items: list = field(default_factory=list)   # array children
    pairs: list = field(default_factory=list)   # map (key_item, value_item)

    def get(self, key: int) -> "Item":
        for k, v in self.pairs:
            if k.major == 0 and k.arg == key:
                return v
        raise KeyError(key)


def cbor_walk(data: bytes, pos: int = 0) -> Item:
    """Parse one item of the restricted profile; absolute offsets."""
    if pos >= len(data):
        raise CborWalkError("truncated")
    start = pos
    ib = data[pos]
    major, ai = ib >> 5, ib & 0x1F
    pos += 1
    if ai < 24:
        arg = ai
    elif 24 <= ai <= 27:
        width = 1 << (ai - 24)
        if pos + width > len(data):
            raise CborWalkError("truncated argument")
        arg = int.from_bytes(data[pos:pos + width], "big")
        pos += width
    else:
        raise CborWalkError("unsupported additional info")
    item = Item(major, arg, start, pos, pos)
    if major in (0,):
        return item
    if major in (2, 3):
        if pos + arg > len(data):
            raise CborWalkError("truncated string")
        item.end = pos + arg
        return item
    if major == 4:
        for _ in range(arg):
            child = cbor_walk(data, pos)
            item.items.append(child)
            pos = child.end
        item.end = pos
        return item
    if major == 5:
        for _ in range(arg):
            key = cbor_walk(data, pos)
            val = cbor_walk(data, key.end)
            item.pairs.append((key, val))
            pos = val.end
        item.end = pos
        return item
    if major == 7:
        return item
    raise CborWalkError("unsupported major type %d" % major)


def cbor_head(major: int, arg: int) -> bytes:
    if arg < 24:
        return bytes([(major << 5) | arg])
    if arg < 1 << 8:
        return bytes([(major << 5) | 24, arg])
    if arg < 1 << 16:
        return bytes([(major << 5) | 25]) + arg.to_bytes(2, "big")
    if arg < 1 << 32:
        return bytes([(major << 5) | 26]) + arg.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + arg.to_bytes(8, "big")


def cbor_uint(n: int) -> bytes:
    return cbor_head(0, n)


def cbor_bstr(b: bytes) -> bytes:
    return cbor_head(2, len(b)) + b


def cbor_text(s: str) -> bytes:
    raw = s.encode("ascii")
    return cbor_head(3, len(raw)) + raw


def cbor_array(encoded_items: list[bytes]) -> bytes:
    return cbor_head(4, len(encoded_items)) + b"".join(encoded_items)


def noncanonical_uint(n: int) -> bytes:
    """A wider-than-necessary head for n (< 256): 0x18 nn."""
    if not 0 <= n < 256:
        raise ValueError("only small values supported")
    return bytes([0x18, n])


def flip_bit(data: bytes, bit_index: int) -> bytes:
    out = bytearray(data)
    out[bit_index >> 3] ^= 1 << (bit_index & 7)
    return bytes(out)


def flip_in(data: bytes, span: tuple[int, int], byte_offset: int = 0,
            bit: int = 0) -> bytes:
    """Flip one bit inside [span) at byte_offset from the span start."""
    start, end = span
    pos = start + byte_offset
    if not start <= pos < end:
        raise ValueError("offset outside span")
    return flip_bit(data, pos * 8 + bit)


def replace_span(data: bytes, span: tuple[int, int], new: bytes) -> bytes:
    return data[:span[0]] + new + data[span[1]:]


def whole(item: Item) -> tuple[int, int]:
    return item.start, item.end


def payload(item: Item) -> tuple[int, int]:
    return item.hdr_end, item.end


def last_byte_span(item: Item) -> tuple[int, int]:
    """The final byte of an item's encoding: the low bits of a uint."""
    return item.end - 1, item.end


def read_uint(item: Item) -> int:
    if item.major != 0:
        raise CborWalkError("not a uint")
    return item.arg


def checkpoint_signed_bytes(ckpt: bytes) -> bytes:
    root = cbor_walk(ckpt)
    return (CKPT_PREFIX
            + read_uint(root.get(1)).to_bytes(4, "big")
            + ckpt[slice(*payload(root.get(5)))]
            + read_uint(root.get(2)).to_bytes(8, "big")
            + ckpt[slice(*payload(root.get(6)))]
            + read_uint(root.get(3)).to_bytes(8, "big")
            + read_uint(root.get(4)).to_bytes(8, "big")
            + ckpt[slice(*payload(root.get(7)))])


def redigest_checkpoint(ckpt: bytes) -> bytes:
    """Recompute transcript_digest after an edit (the signature stays stale).

    The digest is a public SHA-256, so a forger can always do this; only the
    ML-DSA signature stops the result.
    """
    digest = hashlib.sha256(checkpoint_signed_bytes(ckpt)).digest()
    return replace_span(ckpt, payload(cbor_walk(ckpt).get(8)), digest)


def receipt_parts(data: bytes) -> dict:
    root = cbor_walk(data)
    path_item = root.get(4)
    return {
        "root": root,
        "statement": root.get(1),
        "leaf_index": root.get(2),
        "tree_size": root.get(3),
        "path": path_item.items,
        "ckpt": root.get(5),
    }


def consistency_parts(data: bytes) -> dict:
    root = cbor_walk(data)
    return {
        "root": root,
        "old_size": root.get(1),
        "new_size": root.get(2),
        "nodes": root.get(3).items,
        "old": root.get(4),
        "new": root.get(5),
    }


def encode_consistency(old_size: int, new_size: int, nodes: list[bytes],
                       old_ckpt: bytes, new_ckpt: bytes) -> bytes:
    return (cbor_head(5, 5)
            + cbor_uint(1) + cbor_uint(old_size)
            + cbor_uint(2) + cbor_uint(new_size)
            + cbor_uint(3) + cbor_array([cbor_bstr(n) for n in nodes])
            + cbor_uint(4) + old_ckpt
            + cbor_uint(5) + new_ckpt)


# ---------------------------------------------------------------------------
# Verifier invocation and output parsing
# ---------------------------------------------------------------------------

@dataclass
class Outcome:
    accepted: bool
    reason: str            # "ok" when accepted
    returncode: int
    signature: str = ""    # python only: "delegated"
    error: str = ""        # unparseable output / crash
    raw: str = ""

    def describe(self) -> str:
        if self.error:
            return "error(%s)" % self.error
        return "accept" if self.accepted else "reject:" + self.reason


def parse_c_output(stdout: str, returncode: int, kind: str) -> Outcome:
    marker = ("PQCP_APPRAISAL_RECEIPT " if kind == "receipt"
              else "PQCP_APPRAISAL_CONSISTENCY ")
    lines = [ln for ln in stdout.splitlines() if ln.startswith(marker)]
    if len(lines) != 1:
        return Outcome(False, "", returncode,
                       error="expected exactly one %s line, got %d"
                       % (marker.strip(), len(lines)), raw=stdout)
    fields = lines[0][len(marker):].split()
    verdict = fields[0] if fields else ""
    if verdict == "PASS":
        if returncode != 0:
            return Outcome(False, "", returncode,
                           error="PASS marker with exit %d" % returncode,
                           raw=stdout)
        return Outcome(True, "ok", returncode, raw=stdout)
    if verdict == "REJECT":
        reason = ""
        for f in fields[1:]:
            if f.startswith("reason="):
                reason = f[len("reason="):]
        if returncode != 1 or not reason:
            return Outcome(False, "", returncode,
                           error="REJECT marker with exit %d reason=%r"
                           % (returncode, reason), raw=stdout)
        return Outcome(False, reason, returncode, raw=stdout)
    return Outcome(False, "", returncode, error="unknown verdict %r" % verdict,
                   raw=stdout)


def parse_py_output(stdout: str, returncode: int) -> Outcome:
    try:
        verdict = json.loads(stdout)
        accepted = bool(verdict["accepted"])
        reason = str(verdict["reason"])
        signature = str(verdict.get("signature", ""))
    except (ValueError, KeyError, TypeError) as exc:
        return Outcome(False, "", returncode,
                       error="python output not JSON verdict: %s" % exc,
                       raw=stdout)
    if accepted != (returncode == 0):
        return Outcome(False, reason, returncode, signature,
                       error="accepted=%s but exit %d" % (accepted, returncode),
                       raw=stdout)
    return Outcome(accepted, reason, returncode, signature, raw=stdout)


@dataclass
class Tools:
    verifier: Path
    register: Path
    env: dict
    reference: Path = REFERENCE
    python_faults: tuple = ()

    def run(self, cmd: list, cwd: Path | None = None) -> subprocess.CompletedProcess:
        return subprocess.run([str(c) for c in cmd], cwd=cwd, env=self.env,
                              capture_output=True, text=True, timeout=300)


# ---------------------------------------------------------------------------
# Cases and judging
# ---------------------------------------------------------------------------

@dataclass
class Case:
    name: str
    klass: str
    kind: str                          # "receipt" | "consistency"
    role: str                          # control | forgery | matrix | sweep
    path: Path
    log_pk: Path
    transcript: Path | None = None
    c_flags: tuple = ()
    use_vbin: bool = False             # pass --verifier-bin to both verifiers
    expect_verdict: str | None = None  # python --expect-verdict
    c_expect: str | None = None        # None = must accept
    py_expect: str | None = None       # None = must accept
    scope: str = "merkle"              # merkle | delegated
    compat: bool = False               # sweep: judge via COMPAT table
    sig_region: bool = False           # sweep: flip inside the signature


@dataclass
class CaseResult:
    case: Case
    c: Outcome
    p: Outcome
    problems: list
    in_differential: bool
    agree: bool

    @property
    def ok(self) -> bool:
        return not self.problems


def run_c(tools: Tools, case: Case) -> Outcome:
    if case.kind == "receipt":
        cmd = [tools.verifier, "--receipt", case.path, "--log-pk", case.log_pk]
        if case.use_vbin:
            cmd += ["--verifier-bin", tools.verifier]
        cmd += list(case.c_flags) + [case.transcript]
    else:
        cmd = [tools.verifier, "--consistency", case.path,
               "--log-pk", case.log_pk]
    proc = tools.run(cmd)
    return parse_c_output(proc.stdout, proc.returncode, case.kind)


def run_py(tools: Tools, case: Case) -> Outcome:
    cmd = [sys.executable, tools.reference]
    if case.kind == "receipt":
        cmd += ["--receipt", case.path, "--log-pk", case.log_pk,
                "--transcript", case.transcript]
        if case.use_vbin:
            cmd += ["--verifier-bin", tools.verifier]
        if case.expect_verdict:
            cmd += ["--expect-verdict", case.expect_verdict]
    else:
        cmd += ["--consistency", case.path, "--log-pk", case.log_pk]
    for fault in tools.python_faults:
        cmd += ["--inject-fault", fault]
    proc = tools.run(cmd)
    return parse_py_output(proc.stdout, proc.returncode)


def expectation_problem(who: str, got: Outcome, expect: str | None) -> str:
    if got.error:
        return "%s error: %s" % (who, got.error)
    if expect is None:
        if not got.accepted:
            return "%s rejected (%s) but acceptance was expected" % (
                who, got.reason)
        return ""
    if got.accepted:
        return "%s ACCEPTED but reject:%s was expected" % (who, expect)
    if got.reason != expect:
        return "%s reason %s, expected %s" % (who, got.reason, expect)
    return ""


def judge(case: Case, c: Outcome, p: Outcome) -> CaseResult:
    problems = []
    sig_only = case.scope == "delegated" or case.sig_region
    if case.compat:
        if c.error:
            problems.append("C error: " + c.error)
        elif c.accepted:
            problems.append("C ACCEPTED a forged file")
        elif case.sig_region:
            if c.reason != "bad_signature":
                problems.append("C reason %s, expected bad_signature"
                                % c.reason)
        if p.error:
            problems.append("python error: " + p.error)
        elif case.sig_region:
            if not p.accepted or p.signature != "delegated":
                problems.append("python should accept with signature "
                                "delegated, got %s" % p.describe())
        elif not c.error and not c.accepted:
            if p.accepted:
                problems.append("python ACCEPTED but C rejected (%s)"
                                % c.reason)
            elif p.reason not in COMPAT.get(c.reason, set()):
                problems.append("python reason %s not comparable with C %s"
                                % (p.reason, c.reason))
    else:
        for who, got, expect in (("C", c, case.c_expect),
                                 ("python", p, case.py_expect)):
            problem = expectation_problem(who, got, expect)
            if problem:
                problems.append(problem)
        if case.scope == "delegated" and not p.error and p.accepted \
                and p.signature != "delegated":
            problems.append("python accepted without reporting the "
                            "signature as delegated")
    agree = (not c.error and not p.error and c.accepted == p.accepted)
    in_diff = not sig_only
    if in_diff and not agree and not c.error and not p.error:
        problems.append("DISAGREEMENT: C %s vs python %s"
                        % (c.describe(), p.describe()))
    return CaseResult(case, c, p, problems, in_diff, agree)


def evaluate_case(tools: Tools, case: Case) -> CaseResult:
    return judge(case, run_c(tools, case), run_py(tools, case))


def evaluate_all(tools: Tools, cases: list[Case],
                 jobs: int | None = None) -> list[CaseResult]:
    workers = jobs or min(8, os.cpu_count() or 2)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda c: evaluate_case(tools, c), cases))


# ---------------------------------------------------------------------------
# Summary and final marker
# ---------------------------------------------------------------------------

@dataclass
class Summary:
    differential_agree: int
    differential_total: int
    forgeries_rejected: int
    forgeries_total: int
    controls_ok: int
    controls_total: int
    delegated_cases: int
    consistency_ok: bool
    failures: list
    disagreements: list

    @property
    def passed(self) -> bool:
        return (not self.failures and self.consistency_ok
                and self.differential_agree == self.differential_total
                and self.forgeries_rejected == self.forgeries_total
                and self.controls_ok == self.controls_total
                and self.forgeries_total > 0 and self.controls_total > 0)


CONSISTENCY_CONTROL = "consistency/honest-append-only"


def summarize(results: list[CaseResult]) -> Summary:
    diff = [r for r in results if r.in_differential]
    forgeries = [r for r in results if r.case.role in ("forgery", "sweep")]
    controls = [r for r in results if r.case.role == "control"]
    consistency_ok = any(
        r.case.name == CONSISTENCY_CONTROL and r.ok
        and r.c.accepted and "consistency=ok" in r.c.raw
        for r in results)
    return Summary(
        differential_agree=sum(1 for r in diff if r.agree),
        differential_total=len(diff),
        forgeries_rejected=sum(1 for r in forgeries if r.ok),
        forgeries_total=len(forgeries),
        controls_ok=sum(1 for r in controls if r.ok),
        controls_total=len(controls),
        delegated_cases=sum(1 for r in results if not r.in_differential),
        consistency_ok=consistency_ok,
        failures=[r for r in results if not r.ok],
        disagreements=[r for r in diff if not r.agree],
    )


def format_marker(s: Summary) -> str:
    if s.passed:
        return ("PQCP_APPRAISAL_RECEIPT PASS consistency=ok "
                "differential_agree=%d/%d forgeries_rejected=%d/%d "
                "controls=%d/%d" % (
                    s.differential_agree, s.differential_total,
                    s.forgeries_rejected, s.forgeries_total,
                    s.controls_ok, s.controls_total))
    return ("PQCP_APPRAISAL_RECEIPT FAIL consistency=%s "
            "differential_agree=%d/%d forgeries_rejected=%d/%d "
            "controls=%d/%d" % (
                "ok" if s.consistency_ok else "missing",
                s.differential_agree, s.differential_total,
                s.forgeries_rejected, s.forgeries_total,
                s.controls_ok, s.controls_total))


# ---------------------------------------------------------------------------
# Fixture construction
# ---------------------------------------------------------------------------

def build_tools(build_root: Path, env: dict) -> tuple[Path, Path]:
    """cmake-build both host tools (same pattern as run_evidence_chain_replay)."""
    outputs = []
    for name, binary in (("evidence_verifier", "pqcp-evidence-verify"),
                         ("evidence_register", "pqcp-evidence-register")):
        build_dir = build_root / ("build-" + name)
        run_command(["cmake", "-S", str(MODULE_PATH / "tools" / name),
                     "-B", str(build_dir), "-DCMAKE_BUILD_TYPE=Release"],
                    cwd=MODULE_PATH, env=env, timeout=120)
        run_command(["cmake", "--build", str(build_dir), "--parallel"],
                    cwd=MODULE_PATH, env=env, timeout=600)
        exe = build_dir / binary
        if not exe.exists():
            raise RuntimeError("%s was not produced" % binary)
        outputs.append(exe)
    return outputs[0], outputs[1]


class FixtureError(RuntimeError):
    pass


def must(proc: subprocess.CompletedProcess, what: str,
         ok_codes: tuple = (0,)) -> str:
    if proc.returncode not in ok_codes:
        raise FixtureError("%s failed (exit %d): %s" % (
            what, proc.returncode, (proc.stdout + proc.stderr)[-400:]))
    return proc.stdout


def seed_bytes(seed: int, label: str) -> bytes:
    return hashlib.sha256(
        ("pqcp-appraisal-demo-%s-%d" % (label, seed)).encode()).digest()


@dataclass
class Log:
    """A registered log directory plus its signing identity."""
    name: str
    directory: Path
    seed_file: Path
    pk: Path
    count: int = 0


class Fixtures:
    """Builds deterministic statements, logs, checkpoints, receipts."""

    def __init__(self, tools: Tools, work: Path, seed: int):
        self.t = tools
        self.work = work
        self.seed = seed
        work.mkdir(parents=True, exist_ok=True)
        self.keys = {}
        for label in ("log1", "log2"):
            seed_file = work / (label + ".seed")
            seed_file.write_bytes(seed_bytes(seed, label))
            pk = work / (label + ".pk")
            must(tools.run([tools.register, "keygen", "--seed-file",
                            seed_file, "--pk-out", pk]), "keygen " + label)
            self.keys[label] = (seed_file, pk)

    # -- transcripts and statements ---------------------------------------

    def emit_statement(self, name: str, transcript: Path, flags=(),
                       vbin: Path | None = None) -> Path:
        out = self.work / (name + ".stmt")
        cmd = [self.t.verifier, "--emit-statement", out,
               "--verifier-bin", vbin or self.t.verifier, *flags, transcript]
        stdout = must(self.t.run(cmd), "emit " + name, ok_codes=(0, 1))
        if "PQCP_APPRAISAL_STATEMENT written" not in stdout:
            raise FixtureError("no statement written for " + name)
        return out

    # -- logs -------------------------------------------------------------

    def new_log(self, name: str, key: str, statements: list[Path]) -> Log:
        seed_file, pk = self.keys[key]
        log = Log(name, self.work / ("log-" + name), seed_file, pk)
        for stmt in statements:
            must(self.t.run([self.t.register, "register", "--log-dir",
                             log.directory, "--log-pk", pk,
                             "--statement", stmt]), "register " + name)
            log.count += 1
        return log

    def checkpoint(self, log: Log, tag: str, size: int, sequence: int) -> Path:
        out = self.work / ("ckpt-%s-%s.cbor" % (log.name, tag))
        must(self.t.run([
            self.t.register, "checkpoint", "--log-dir", log.directory,
            "--seed-file", log.seed_file, "--sequence", sequence,
            "--timestamp-ms", BASE_TIMESTAMP_MS + sequence * 1000,
            "--tree-size", size, "--out", out]), "checkpoint " + tag)
        return out

    def receipt(self, log: Log, ckpt: Path, leaf: int, tag: str,
                allow_mismatch: bool = False) -> Path:
        out = self.work / ("receipt-%s-%s.cbor" % (log.name, tag))
        cmd = [self.t.register, "receipt", "--log-dir", log.directory,
               "--checkpoint", ckpt, "--leaf-index", leaf, "--out", out]
        if allow_mismatch:
            cmd.append("--allow-mismatch")
        must(self.t.run(cmd), "receipt " + tag)
        return out

    def consistency(self, log: Log, old: Path, new: Path, tag: str,
                    allow_mismatch: bool = False) -> Path:
        out = self.work / ("consistency-%s-%s.cbor" % (log.name, tag))
        cmd = [self.t.register, "prove-consistency", "--log-dir",
               log.directory, "--old-checkpoint", old, "--new-checkpoint",
               new, "--out", out]
        if allow_mismatch:
            cmd.append("--allow-mismatch")
        must(self.t.run(cmd), "consistency " + tag)
        return out

    def write(self, name: str, data: bytes) -> Path:
        path = self.work / name
        path.write_bytes(data)
        return path


# Leaves of the main log: (label, transcript key, extra C flags)
LEAF_TRANSCRIPT = ("qemu", "full", "signed", "tampered", "full", "tampered")
LEAF_FLAGS = ((), (), ("--require-signature",), (), (), ())


def build_cases(fx: Fixtures, sweep_flips: int, seed: int) -> list[Case]:
    """Create all fixtures and the full case list."""
    t = fx.t
    work = fx.work
    pk1 = fx.keys["log1"][1]
    pk2 = fx.keys["log2"][1]
    transcripts = {
        "qemu": TESTDATA / "advisor_qemu_transcript.log",
        "full": TESTDATA / "advisor_full_chain_transcript.log",
        "signed": TESTDATA / "signed_passport_transcript.log",
    }
    full_text = transcripts["full"].read_bytes()
    marker = b"verdict_digest="
    if full_text.count(marker) < 1:
        raise FixtureError("full-chain fixture lacks verdict_digest=")
    transcripts["tampered"] = fx.write(
        "full_tampered.log", full_text.replace(marker, marker + b"0", 1))
    transcripts["noise"] = fx.write(
        "full_noise.log", full_text + b"# appended non-marker line\n")

    # Statements. s4 is produced by a "different verifier build" (the
    # register binary stands in for any other executable).
    stmts = [
        fx.emit_statement("s0", transcripts["qemu"]),
        fx.emit_statement("s1", transcripts["full"]),
        fx.emit_statement("s2", transcripts["signed"],
                          flags=("--require-signature",)),
        fx.emit_statement("s3", transcripts["tampered"]),
        fx.emit_statement("s4", transcripts["full"], vbin=t.register),
    ]
    s3_bytes = stmts[3].read_bytes()
    verdict_item = cbor_walk(s3_bytes).get(5)
    if s3_bytes[slice(*payload(verdict_item))] != b"REJECT":
        raise FixtureError("tampered transcript did not replay to REJECT")
    forged_bytes = replace_span(s3_bytes, whole(verdict_item),
                                cbor_text("CHAIN OK"))
    stmts.append(fx.write("s5.stmt", forged_bytes))
    s3alt = fx.emit_statement("s3alt", transcripts["tampered"],
                              vbin=t.register)

    main = fx.new_log("main", "log1", stmts)
    fork = fx.new_log("fork", "log1", stmts[:3] + [s3alt] + stmts[4:])
    rewritten = fx.new_log("rewrite", "log1",
                           [stmts[1], stmts[2], stmts[3], stmts[4], stmts[5],
                            stmts[0]])
    other = fx.new_log("otherkey", "log2", stmts)

    cases: list[Case] = []

    def add(name, klass, kind, role, path, pk, tr=None, flags=(), vbin=False,
            expect_verdict=None, c_expect=None, py_expect=None,
            scope="merkle", compat=False, sig_region=False):
        cases.append(Case(name, klass, kind, role, path, pk, tr, tuple(flags),
                          vbin, expect_verdict, c_expect, py_expect, scope,
                          compat, sig_region))

    # -- checkpoints -------------------------------------------------------
    per_size = {k: fx.checkpoint(main, "m%d" % k, k, 10 + k)
                for k in range(1, 7)}
    a3 = fx.checkpoint(main, "a3", 3, 1)
    b6 = fx.checkpoint(main, "b6", 6, 2)
    c6 = fx.checkpoint(main, "c6", 6, 3)             # same tree, newer seq
    a3_seq2 = fx.checkpoint(main, "a3s2", 3, 2)
    a3_hiseq = fx.checkpoint(main, "a3hi", 3, 5)
    f6 = fx.checkpoint(fork, "f6", 6, 3)             # forked tree, same key
    w6 = fx.checkpoint(rewritten, "w6", 6, 3)        # history rewrite
    k6 = fx.checkpoint(other, "k6", 6, 1)            # other log key

    # -- differential matrix: every (checkpoint size, leaf) receipt --------
    for k in range(1, 7):
        for i in range(k):
            if i == 5:
                continue        # forged-verdict leaf: python has no replay
            r = fx.receipt(main, per_size[k], i, "m%d-%d" % (k, i))
            add("matrix/size%d-leaf%d" % (k, i), "matrix", "receipt",
                "matrix", r, pk1, transcripts[LEAF_TRANSCRIPT[i]],
                LEAF_FLAGS[i])

    # -- class: receipt field bit flips (base: leaf 2 of the size-6 tree) --
    base_path = fx.receipt(main, per_size[6], 2, "base")
    base = base_path.read_bytes()
    parts = receipt_parts(base)
    tr_sig = transcripts["signed"]
    sig_flags = ("--require-signature",)

    def receipt_case(name, klass, data, c_expect, py_expect, role="forgery",
                     pk=pk1, tr=tr_sig, flags=sig_flags, **kw):
        path = fx.write(name.replace("/", "_") + ".cbor", data)
        add(name, klass, "receipt", role, path, pk, tr, flags,
            c_expect=c_expect, py_expect=py_expect, **kw)

    receipt_case("flip/control", "flip", base, None, None, role="control")
    stmt_inner = cbor_walk(base, parts["statement"].hdr_end)
    receipt_case("flip/statement-verifier-hash", "flip",
                 flip_in(base, payload(stmt_inner.get(6)), 5, 3),
                 "inclusion_proof_invalid", "inclusion_proof_invalid")
    receipt_case("flip/statement-transcript-hash", "flip",
                 flip_in(base, payload(stmt_inner.get(8)), 11, 6),
                 "inclusion_proof_invalid", "inclusion_proof_invalid")
    receipt_case("flip/statement-verdict-text", "flip",
                 flip_in(base, payload(stmt_inner.get(5)), 0, 0),
                 "inclusion_proof_invalid", "bad_statement")
    for n, node in enumerate(parts["path"]):
        receipt_case("flip/path-node-%d" % n, "flip",
                     flip_in(base, payload(node), 7 * n + 1, n),
                     "inclusion_proof_invalid", "inclusion_proof_invalid")
    receipt_case("flip/leaf-index", "flip",
                 flip_in(base, last_byte_span(parts["leaf_index"])),
                 "inclusion_proof_invalid", "inclusion_proof_invalid")
    receipt_case("flip/receipt-tree-size", "flip",
                 flip_in(base, last_byte_span(parts["tree_size"])),
                 "tree_size_mismatch", "tree_size_mismatch")
    ck = cbor_walk(base, parts["ckpt"].start)
    receipt_case("flip/checkpoint-root", "flip",
                 flip_in(base, payload(ck.get(6)), 3, 2),
                 "bad_signature", "bad_checkpoint")
    receipt_case("flip/checkpoint-tree-size", "flip",
                 flip_in(base, last_byte_span(ck.get(2))),
                 "bad_signature", "bad_checkpoint")
    receipt_case("flip/checkpoint-log-id", "flip",
                 flip_in(base, payload(ck.get(5)), 9, 5),
                 "log_id_mismatch", "bad_checkpoint")
    # Root swapped and the (public) digest recomputed: only the ML-DSA
    # signature, or python's root binding, stops these.
    ckpt_bytes = base[parts["ckpt"].start:parts["ckpt"].end]
    ck_local = cbor_walk(ckpt_bytes)
    swapped_root = redigest_checkpoint(
        flip_in(ckpt_bytes, payload(ck_local.get(6)), 0, 0))
    receipt_case("flip/checkpoint-root-redigested", "flip",
                 replace_span(base, whole(parts["ckpt"]), swapped_root),
                 "bad_signature", "inclusion_proof_invalid")
    resized = redigest_checkpoint(
        flip_in(ckpt_bytes, last_byte_span(ck_local.get(2))))
    receipt_case("flip/checkpoint-tree-size-redigested", "flip",
                 replace_span(base, whole(parts["ckpt"]), resized),
                 "bad_signature", "tree_size_mismatch")
    receipt_case("flip/checkpoint-signature", "flip",
                 flip_in(base, payload(ck.get(9)), 1500, 4),
                 "bad_signature", None, scope="delegated")

    # -- class: wrong log key ---------------------------------------------
    rk = fx.receipt(other, k6, 2, "k6-2")
    receipt_case("key/control", "key", rk.read_bytes(), None, None,
                 role="control", pk=pk2)
    receipt_case("key/receipt-under-other-pinned-key", "key", base,
                 "log_id_mismatch", "log_id_mismatch", pk=pk2)
    receipt_case("key/other-log-receipt-under-pinned-key", "key",
                 rk.read_bytes(), "log_id_mismatch", "log_id_mismatch")

    # -- class: stale (older signed) checkpoint with a newer claimed size --
    r3 = fx.receipt(main, per_size[3], 2, "m3-2")
    receipt_case("stale/control", "stale", r3.read_bytes(), None, None,
                 role="control")
    old_ckpt_bytes = per_size[3].read_bytes()
    stale = replace_span(base, whole(parts["ckpt"]), old_ckpt_bytes)
    receipt_case("stale/older-checkpoint-newer-size-claimed", "stale", stale,
                 "tree_size_mismatch", "tree_size_mismatch")
    stale_p = receipt_parts(stale)
    patched = replace_span(stale, whole(stale_p["tree_size"]), cbor_uint(3))
    receipt_case("stale/older-checkpoint-size-patched", "stale", patched,
                 "inclusion_proof_invalid", "inclusion_proof_invalid")

    # -- class: cross-fork receipt (valid signed root, wrong tree) ---------
    rf = fx.receipt(fork, f6, 3, "f6-3")
    t_tamp = transcripts["tampered"]
    receipt_case("fork-receipt/control", "fork-receipt", rf.read_bytes(),
                 None, None, role="control", tr=t_tamp, flags=())
    rf_bytes = rf.read_bytes()
    rf_parts = receipt_parts(rf_bytes)
    swapped = replace_span(rf_bytes, whole(rf_parts["ckpt"]),
                           per_size[6].read_bytes())
    receipt_case("fork-receipt/proof-from-fork-checkpoint-from-main",
                 "fork-receipt", swapped, "inclusion_proof_invalid",
                 "inclusion_proof_invalid", tr=t_tamp, flags=())

    # -- class: forged / foreign verdict -----------------------------------
    r1 = fx.receipt(main, per_size[6], 1, "m6-1")
    r3x = fx.receipt(main, per_size[6], 3, "m6-3")
    r4 = fx.receipt(main, per_size[6], 4, "m6-4")
    r5 = fx.receipt(main, per_size[6], 5, "m6-5")
    add("verdict/control", "verdict", "receipt", "control", r1, pk1,
        transcripts["full"], (), True, expect_verdict="CHAIN OK")
    add("verdict/reject-receipt-control", "verdict", "receipt", "control",
        r3x, pk1, t_tamp, (), True, expect_verdict="REJECT")
    r3x_bytes = r3x.read_bytes()
    r3x_parts = receipt_parts(r3x_bytes)
    s3_item = cbor_walk(r3x_bytes, r3x_parts["statement"].hdr_end)
    forged_in_receipt = replace_span(
        r3x_bytes, whole(r3x_parts["statement"]),
        cbor_bstr(replace_span(
            r3x_bytes[slice(*payload(r3x_parts["statement"]))],
            (s3_item.get(5).start - r3x_parts["statement"].hdr_end,
             s3_item.get(5).end - r3x_parts["statement"].hdr_end),
            cbor_text("CHAIN OK"))))
    receipt_case("verdict/statement-edited-reject-to-ok", "verdict",
                 forged_in_receipt, "inclusion_proof_invalid",
                 "inclusion_proof_invalid", tr=t_tamp, flags=(), vbin=True)
    add("verdict/registered-forged-verdict", "verdict", "receipt", "forgery",
        r5, pk1, t_tamp, (), True, expect_verdict="REJECT",
        c_expect="verdict_mismatch", py_expect="statement_mismatch")
    add("verdict/other-verifier-build", "verdict", "receipt", "forgery",
        r4, pk1, transcripts["full"], (), True,
        c_expect="verifier_hash_mismatch", py_expect="statement_mismatch")

    # -- class: tampered transcript ----------------------------------------
    add("transcript/control", "transcript", "receipt", "control", r1, pk1,
        transcripts["full"], (), False)
    add("transcript/appended-noise", "transcript", "receipt", "forgery", r1,
        pk1, transcripts["noise"], (), False,
        c_expect="transcript_hash_mismatch", py_expect="statement_mismatch")
    add("transcript/digest-tampered", "transcript", "receipt", "forgery", r1,
        pk1, t_tamp, (), False, c_expect=TAMPER_C_REASON,
        py_expect="statement_mismatch")

    # -- class: malformed CBOR ----------------------------------------------
    receipt_case("malformed/control", "malformed", base, None, None,
                 role="control")
    receipt_case("malformed/truncated-last-byte", "malformed", base[:-1],
                 "malformed", "malformed")
    receipt_case("malformed/truncated-mid-statement", "malformed",
                 base[:60], "malformed", "malformed")
    receipt_case("malformed/trailing-byte", "malformed", base + b"\x00",
                 "malformed", "malformed")
    receipt_case("malformed/noncanonical-leaf-index", "malformed",
                 replace_span(base, whole(parts["leaf_index"]),
                              noncanonical_uint(read_uint(
                                  parts["leaf_index"]))),
                 "malformed", "malformed")
    receipt_case("malformed/noncanonical-checkpoint-sequence", "malformed",
                 replace_span(base, whole(ck.get(4)),
                              noncanonical_uint(read_uint(ck.get(4)))),
                 "malformed", "malformed")

    # -- consistency classes -------------------------------------------------
    honest = fx.consistency(main, a3, b6, "honest")
    add(CONSISTENCY_CONTROL, "rewrite", "consistency", "control", honest, pk1)
    same_tree = fx.consistency(main, b6, c6, "same-tree")
    add("fork/control-same-tree-resigned", "fork", "consistency", "control",
        same_tree, pk1)
    advance = fx.consistency(main, per_size[3], per_size[6], "advance")
    add("rollback/control-advance", "rollback", "consistency", "control",
        advance, pk1)

    # equivocation (the headline negative): both signatures valid
    eq_same_size = fx.consistency(fork, b6, f6, "eq-size", True)
    add("fork/same-size-different-root", "fork", "consistency", "forgery",
        eq_same_size, pk1, c_expect="equivocation", py_expect="equivocation")
    eq_same_seq = fx.consistency(main, a3_seq2, b6, "eq-seq")
    add("fork/same-sequence-different-size", "fork", "consistency",
        "forgery", eq_same_seq, pk1, c_expect="equivocation",
        py_expect="equivocation")

    # history rewrite: entry 0 removed and re-appended
    rewrite = fx.consistency(rewritten, a3, w6, "rewrite", True)
    add("rewrite/entry-0-removed-and-reappended", "rewrite", "consistency",
        "forgery", rewrite, pk1, c_expect="consistency_proof_invalid",
        py_expect="consistency_proof_invalid")
    hp = consistency_parts(honest.read_bytes())
    hbytes = honest.read_bytes()
    add("rewrite/proof-node-flipped", "rewrite", "consistency", "forgery",
        fx.write("consistency_flip_node.cbor",
                 flip_in(hbytes, payload(hp["nodes"][0]), 4, 1)),
        pk1, c_expect="consistency_proof_invalid",
        py_expect="consistency_proof_invalid")
    old_ck = cbor_walk(hbytes, hp["old"].start)
    new_ck = cbor_walk(hbytes, hp["new"].start)
    add("rewrite/old-root-flipped", "rewrite", "consistency", "forgery",
        fx.write("consistency_flip_oldroot.cbor",
                 flip_in(hbytes, payload(old_ck.get(6)), 2, 3)),
        pk1, c_expect="bad_signature", py_expect="bad_checkpoint")
    new_ck_bytes = hbytes[hp["new"].start:hp["new"].end]
    new_local = cbor_walk(new_ck_bytes)
    new_redigested = redigest_checkpoint(
        flip_in(new_ck_bytes, payload(new_local.get(6)), 6, 4))
    add("rewrite/new-root-redigested", "rewrite", "consistency", "forgery",
        fx.write("consistency_new_redigested.cbor",
                 replace_span(hbytes, whole(hp["new"]), new_redigested)),
        pk1, c_expect="bad_signature", py_expect="consistency_proof_invalid")
    add("rewrite/new-signature-flipped", "rewrite", "consistency", "forgery",
        fx.write("consistency_flip_newsig.cbor",
                 flip_in(hbytes, payload(new_ck.get(9)), 900, 7)),
        pk1, c_expect="bad_signature", py_expect=None, scope="delegated")
    add("rewrite/wrong-pinned-key", "rewrite", "consistency", "forgery",
        honest, pk2, c_expect="log_id_mismatch",
        py_expect="log_id_mismatch")

    # rollback
    rb_seq = fx.consistency(main, a3_hiseq, b6, "rb-seq", True)
    add("rollback/sequence-decreases", "rollback", "consistency", "forgery",
        rb_seq, pk1, c_expect="rollback", py_expect="rollback")
    shrink = encode_consistency(
        6, 3, [], per_size[6].read_bytes(),
        fx.checkpoint(main, "m3x", 3, 30).read_bytes())
    add("rollback/tree-shrinks", "rollback", "consistency", "forgery",
        fx.write("consistency_shrink.cbor", shrink), pk1,
        c_expect="rollback", py_expect="rollback")
    identical = encode_consistency(6, 6, [], b6.read_bytes(),
                                   b6.read_bytes())
    add("rollback/identical-checkpoint-replayed", "rollback", "consistency",
        "forgery", fx.write("consistency_identical.cbor", identical), pk1,
        c_expect="rollback", py_expect="rollback")

    # malformed consistency files
    add("malformed/consistency-truncated", "malformed", "consistency",
        "forgery", fx.write("consistency_trunc.cbor", hbytes[:-1]), pk1,
        c_expect="malformed", py_expect="malformed")
    add("malformed/consistency-trailing", "malformed", "consistency",
        "forgery", fx.write("consistency_trail.cbor", hbytes + b"\x00"), pk1,
        c_expect="malformed", py_expect="malformed")
    add("malformed/consistency-noncanonical-size", "malformed",
        "consistency", "forgery",
        fx.write("consistency_noncanon.cbor",
                 replace_span(hbytes, whole(hp["old_size"]),
                              noncanonical_uint(read_uint(hp["old_size"])))),
        pk1, c_expect="malformed", py_expect="malformed")
    add("malformed/consistency-size-field-mismatch", "malformed",
        "consistency", "forgery",
        fx.write("consistency_sizefield.cbor",
                 flip_in(hbytes, last_byte_span(hp["old_size"]))),
        pk1, c_expect="malformed", py_expect="malformed")

    # -- deterministic randomized single-bit sweeps --------------------------
    rng = random.Random(seed)
    sweeps = (
        ("receipt", base, tr_sig, sig_flags,
         whole_sig_span(base, parts["ckpt"].start)),
        ("consistency", hbytes, None, (),
         whole_sig_span(hbytes, hp["new"].start)),
    )
    for kind, data, tr, flags, sig_span in sweeps:
        sig_spans = [sig_span]
        if kind == "consistency":
            sig_spans.append(whole_sig_span(hbytes, hp["old"].start))
        in_sig = lambda byte: any(s <= byte < e for s, e in sig_spans)  # noqa: E731
        plain = [b for b in range(len(data) * 8) if not in_sig(b >> 3)]
        sig_bits = [b for b in range(len(data) * 8) if in_sig(b >> 3)]
        picked = [(b, False) for b in rng.sample(plain, sweep_flips)]
        picked += [(b, True) for b in rng.sample(
            sig_bits, max(1, sweep_flips // 6))]
        for n, (bit, is_sig) in enumerate(picked):
            path = fx.write("sweep_%s_%03d.cbor" % (kind, n),
                            flip_bit(data, bit))
            add("sweep/%s-%03d-bit%d" % (kind, n, bit), "sweep", kind,
                "sweep", path, pk1, tr, flags, compat=True,
                sig_region=is_sig)
    return cases


# Receipt replay order in the C verifier hashes the transcript before the
# per-layer comparisons, so any transcript edit is reported as a transcript
# hash mismatch. Pinned from the observed, deterministic result.
TAMPER_C_REASON = "transcript_hash_mismatch"


def whole_sig_span(data: bytes, ckpt_start: int) -> tuple[int, int]:
    ck = cbor_walk(data, ckpt_start)
    return payload(ck.get(9))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(results: list[CaseResult], summary: Summary,
                 verbose: bool) -> None:
    by_class: dict[str, list[CaseResult]] = {}
    for r in results:
        by_class.setdefault(r.case.klass, []).append(r)
    for klass in sorted(by_class):
        rs = by_class[klass]
        bad = [r for r in rs if not r.ok]
        print("[appraisal] %-12s %3d cases, %d failed" % (
            klass, len(rs), len(bad)))
    if verbose:
        for r in results:
            print("[appraisal]   %s %-14s %-55s C=%-34s py=%s" % (
                "ok  " if r.ok else "FAIL", r.case.role, r.case.name,
                r.c.describe(), r.p.describe()))
    for r in summary.failures:
        print("[appraisal] FAIL %s (%s)" % (r.case.name, r.case.role))
        for problem in r.problems:
            print("[appraisal]      " + problem)
    print("[appraisal] delegated (C-only, python reports signature "
          "delegated): %d cases excluded from the differential"
          % summary.delegated_cases)


def write_json(path: Path, results: list[CaseResult],
               summary: Summary) -> None:
    doc = {
        "schema_version": 1,
        "differential_agree": summary.differential_agree,
        "differential_total": summary.differential_total,
        "forgeries_rejected": summary.forgeries_rejected,
        "forgeries_total": summary.forgeries_total,
        "controls_ok": summary.controls_ok,
        "controls_total": summary.controls_total,
        "delegated_cases": summary.delegated_cases,
        "cases": [{
            "name": r.case.name, "class": r.case.klass, "role": r.case.role,
            "c": r.c.describe(), "python": r.p.describe(), "ok": r.ok,
            "problems": r.problems} for r in results],
    }
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--output-dir", type=Path, default=None,
                        help="work/build directory (default: "
                             "build-transparent-appraisal)")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED,
                        help="deterministic seed for keys and bit sweeps")
    parser.add_argument("--sweep-flips", type=int, default=DEFAULT_SWEEP_FLIPS,
                        help="random single-bit flips per file kind")
    parser.add_argument("--python-fault", action="append", default=[],
                        choices=KNOWN_PY_FAULTS,
                        help="TEST ONLY: break the python verifier; the "
                             "driver must then detect the disagreement")
    parser.add_argument("--verbose", action="store_true",
                        help="print every case")
    parser.add_argument("--jobs", type=int, default=None)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    env = clean_env()
    output_dir = args.output_dir or (MODULE_PATH / "build-transparent-appraisal")
    output_dir.mkdir(parents=True, exist_ok=True)

    print("[appraisal] building host tools")
    verifier, register = build_tools(output_dir, env)
    tools = Tools(verifier, register, env,
                  python_faults=tuple(args.python_fault))
    if args.python_fault:
        print("[appraisal] python verifier FAULT INJECTED: "
              + ", ".join(args.python_fault))

    print("[appraisal] building deterministic fixtures (seed %d)" % args.seed)
    work = output_dir / "fixtures"
    if work.exists():
        shutil.rmtree(work)
    fx = Fixtures(tools, work, args.seed)
    cases = build_cases(fx, args.sweep_flips, args.seed)
    print("[appraisal] evaluating %d cases with C and python" % len(cases))
    results = evaluate_all(tools, cases, args.jobs)
    summary = summarize(results)
    print_report(results, summary, args.verbose)
    write_json(output_dir / "appraisal_summary.json", results, summary)
    print(format_marker(summary))
    return 0 if summary.passed else 1


if __name__ == "__main__":
    sys.exit(main())
