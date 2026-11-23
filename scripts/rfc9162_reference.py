#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent RFC 9162 reference verifier for transparent appraisal receipts.

Standard library only (hashlib, json, argparse, random, ...). It deliberately
shares NO code with the C verifier or with any other repository script: the
Merkle algorithms below are written from RFC 9162 sections 2.1.1, 2.1.3 and
2.1.4, and the CBOR decoder is a minimal strict deterministic-CBOR reader.

Wire formats: docs/transparent-appraisal-format.md.

What this verifier checks
  * strict deterministic CBOR (no trailing bytes, shortest-form heads, no
    indefinite lengths, ascending unique integer map keys, no tags/floats)
  * statement schema, leaf hash H(0x00 || statement) recomputed
  * checkpoint fields: schema_version, sequence != 0, log_id == signer_key_id,
    transcript_digest == SHA-256(signed_bytes), empty-tree root
  * optional pinned log public key: length and log_id == SHA-256(pk)
  * receipt.tree_size == checkpoint.tree_size, inclusion proof (RFC 9162
    2.1.3.2) recomputed root == checkpoint.root
  * consistency proof (2.1.4.2) against both checkpoint roots
  * equivocation: same size with different roots, or same sequence with a
    different (size, root)

What it does NOT check: the ML-DSA-65 checkpoint signature. There is no
stdlib ML-DSA, so every verdict reports signature="delegated"; the C verifier
owns signature verification. An accept from this tool therefore means
"structure and Merkle math are valid", never "authentic".

Exit codes: 0 accept; 1 self-test failure; 2 usage; 3 I/O error; otherwise one
distinct code per reject reason (REASON_EXIT below).
"""

import argparse
import hashlib
import json
import os
import random
import sys

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DIGEST = 32
MAX_PROOF_NODES = 65
LOG_PK_BYTES = 1952
SIG_BYTES = 3309
STATEMENT_MAGIC = "pqcp-appraisal/1"
CKPT_PREFIX = b"PQCP-FLEET-TRANSPARENCY-CHECKPOINT-V1"
VERDICTS = ("CHAIN OK", "REJECT")
MAX_DEPTH = 16

REASON_EXIT = {
    "ok": 0,
    "selftest_failed": 1,
    "usage": 2,
    "io_error": 3,
    "malformed": 10,
    "bad_statement": 11,
    "bad_checkpoint": 12,
    "log_id_mismatch": 13,
    "tree_size_mismatch": 14,
    "inclusion_proof_invalid": 15,
    "statement_mismatch": 16,
    "equivocation": 17,
    "rollback": 18,
    "consistency_proof_invalid": 19,
    "bad_log_pk": 20,
    # Never produced here; reserved so the C and Python code spaces align.
    "bad_signature": 21,
}

# Test-only fault injection, used to prove the negative suite is sensitive and
# by the differential driver to confirm it detects a disagreeing verifier.
FAULTS = set()
KNOWN_FAULTS = ("skip-root-binding", "skip-tree-size-binding",
                "no-leaf-prefix", "skip-equivocation", "skip-rollback")


def sha256(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


class Reject(Exception):
    def __init__(self, reason, detail=""):
        Exception.__init__(self, "%s: %s" % (reason, detail))
        self.reason = reason
        self.detail = detail


# ---------------------------------------------------------------------------
# Strict deterministic CBOR (decoder + encoder for tests)
# ---------------------------------------------------------------------------

class CborError(Exception):
    pass


def _read_head(data, pos):
    """Return (major, argument_or_None, new_pos). None means simple value ai."""
    if pos >= len(data):
        raise CborError("truncated head")
    ib = data[pos]
    major, ai = ib >> 5, ib & 0x1f
    pos += 1
    if ai < 24:
        return major, ai, pos
    if ai == 31:
        raise CborError("indefinite length")
    if ai > 27:
        raise CborError("reserved additional info")
    width = 1 << (ai - 24)
    if pos + width > len(data):
        raise CborError("truncated argument")
    val = int.from_bytes(data[pos:pos + width], "big")
    minimum = {24: 24, 25: 1 << 8, 26: 1 << 16, 27: 1 << 32}[ai]
    if val < minimum:
        raise CborError("non-canonical integer head")
    return major, val, pos + width


def _decode(data, pos, depth):
    if depth > MAX_DEPTH:
        raise CborError("nesting too deep")
    start = pos
    if pos >= len(data):
        raise CborError("truncated item")
    major = data[pos] >> 5
    if major == 7:
        b = data[pos]
        if b == 0xf4:
            return False, pos + 1
        if b == 0xf5:
            return True, pos + 1
        if b == 0xf6:
            return None, pos + 1
        raise CborError("unsupported simple/float value 0x%02x" % b)
    major, arg, pos = _read_head(data, pos)
    if major == 0:
        return arg, pos
    if major in (1, 6):
        raise CborError("negative integers and tags are not permitted")
    remaining = len(data) - pos
    if major in (2, 3):
        if arg > remaining:
            raise CborError("truncated string")
        raw = bytes(data[pos:pos + arg])
        pos += arg
        if major == 2:
            return raw, pos
        try:
            return raw.decode("utf-8"), pos
        except UnicodeDecodeError:
            raise CborError("invalid UTF-8 text")
    if major == 4:
        if arg > remaining:
            raise CborError("array count exceeds input")
        out = []
        for _ in range(arg):
            item, pos = _decode(data, pos, depth + 1)
            out.append(item)
        return out, pos
    if major == 5:
        if arg > remaining:
            raise CborError("map count exceeds input")
        out = {}
        last = -1
        for _ in range(arg):
            if pos >= len(data) or (data[pos] >> 5) != 0:
                raise CborError("map key is not an unsigned integer")
            key, pos = _decode(data, pos, depth + 1)
            if key <= last:
                raise CborError("map keys not strictly ascending")
            last = key
            val, pos = _decode(data, pos, depth + 1)
            out[key] = val
        return out, pos
    raise CborError("unreachable major type %d at %d" % (major, start))


def cbor_decode(data):
    """Decode exactly one canonical item; trailing bytes are an error."""
    data = bytes(data)
    item, pos = _decode(data, 0, 0)
    if pos != len(data):
        raise CborError("%d trailing byte(s)" % (len(data) - pos))
    return item


def _enc_head(major, arg):
    if arg < 24:
        return bytes([(major << 5) | arg])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if arg < (1 << (8 * width)):
            return bytes([(major << 5) | ai]) + arg.to_bytes(width, "big")
    raise ValueError("integer too large")


def cbor_encode(obj):
    if obj is True:
        return b"\xf5"
    if obj is False:
        return b"\xf4"
    if obj is None:
        return b"\xf6"
    if isinstance(obj, int):
        return _enc_head(0, obj)
    if isinstance(obj, (bytes, bytearray)):
        return _enc_head(2, len(obj)) + bytes(obj)
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _enc_head(3, len(raw)) + raw
    if isinstance(obj, list):
        return _enc_head(4, len(obj)) + b"".join(cbor_encode(x) for x in obj)
    if isinstance(obj, dict):
        return _enc_head(5, len(obj)) + b"".join(
            cbor_encode(k) + cbor_encode(obj[k]) for k in sorted(obj))
    raise TypeError("cannot encode %r" % type(obj))


# ---------------------------------------------------------------------------
# RFC 9162 Merkle algorithms
# ---------------------------------------------------------------------------

EMPTY_ROOT = sha256(b"")


def leaf_hash(entry):
    if "no-leaf-prefix" in FAULTS:
        return sha256(entry)
    return sha256(b"\x00", entry)


def node_hash(left, right):
    return sha256(b"\x01", left, right)


def _split(n):
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_tree_hash(entries):
    """RFC 9162 2.1.1 MTH over raw entries (recursive definition)."""
    n = len(entries)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaf_hash(entries[0])
    k = _split(n)
    return node_hash(merkle_tree_hash(entries[:k]), merkle_tree_hash(entries[k:]))


def verify_inclusion(leaf_h, leaf_index, tree_size, path, root):
    """RFC 9162 2.1.3.2. Returns (ok, recomputed_root_or_None)."""
    if leaf_index >= tree_size:
        return False, None
    fn, sn = leaf_index, tree_size - 1
    r = leaf_h
    for p in path:
        if sn == 0:
            return False, None
        if (fn & 1) == 1 or fn == sn:
            r = node_hash(p, r)
            if (fn & 1) == 0:
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return (sn == 0), r


def verify_consistency(first, second, first_hash, second_hash, proof):
    """RFC 9162 2.1.4.2. Returns True when proof links the two roots."""
    if first > second:
        return False
    if first == second:
        return len(proof) == 0 and first_hash == second_hash
    if first == 0:
        # Not covered by 2.1.4.2 (which requires 0 < first); the file format
        # fixes this case: zero nodes and the old root is H("").
        return len(proof) == 0 and first_hash == EMPTY_ROOT
    path = list(proof)
    if first & (first - 1) == 0:
        path.insert(0, first_hash)
    if not path:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if (fn & 1) == 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if (fn & 1) == 0:
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_hash and sr == second_hash


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

def _is_int(x):
    return type(x) is int


def _is_hex64(s):
    return (isinstance(s, str) and len(s) == 64
            and all(c in "0123456789abcdef" for c in s))


def _is_b32(b):
    return isinstance(b, bytes) and len(b) == DIGEST


def _keys(m, expected, what, reason="malformed"):
    if not isinstance(m, dict) or sorted(m) != list(expected):
        raise Reject(reason, "%s: wrong map shape" % what)


def parse_statement(raw):
    try:
        m = cbor_decode(raw)
    except CborError as e:
        raise Reject("bad_statement", "statement CBOR: %s" % e)
    _keys(m, range(1, 9), "statement", "bad_statement")
    if m[1] != STATEMENT_MAGIC or not isinstance(m[1], str):
        raise Reject("bad_statement", "statement magic")
    if not _is_hex64(m[2]):
        raise Reject("bad_statement", "passport_digest not 64 lowercase hex")
    if m[3] is not None and not _is_b32(m[3]):
        raise Reject("bad_statement", "device_pk_hash not bstr(32)/null")
    if not (m[4] == "" or _is_hex64(m[4])):
        raise Reject("bad_statement", "trail_head not hex64 or empty")
    if not isinstance(m[5], str) or m[5] not in VERDICTS:
        raise Reject("bad_statement", "verdict")
    if not _is_b32(m[6]):
        raise Reject("bad_statement", "verifier_sha256")
    if type(m[7]) is not bool:
        raise Reject("bad_statement", "signature_verified not bool")
    if not _is_b32(m[8]):
        raise Reject("bad_statement", "transcript_sha256")
    return m


def checkpoint_signed_bytes(c):
    return (CKPT_PREFIX
            + c[1].to_bytes(4, "big") + c[5]
            + c[2].to_bytes(8, "big") + c[6]
            + c[3].to_bytes(8, "big") + c[4].to_bytes(8, "big")
            + c[7])


def parse_checkpoint(m):
    """Schema + field checks (everything except the delegated signature)."""
    _keys(m, range(1, 10), "checkpoint")
    for k in (1, 2, 3, 4):
        if not _is_int(m[k]):
            raise Reject("malformed", "checkpoint key %d not uint" % k)
    if m[1] >= 1 << 32 or m[2] >= 1 << 64 or m[3] >= 1 << 64 or m[4] >= 1 << 64:
        raise Reject("malformed", "checkpoint integer out of range")
    for k in (5, 6, 7, 8):
        if not _is_b32(m[k]):
            raise Reject("malformed", "checkpoint key %d not bstr(32)" % k)
    if not isinstance(m[9], bytes) or len(m[9]) != SIG_BYTES:
        raise Reject("malformed", "checkpoint signature length")
    # Semantic field checks (precede the delegated signature step).
    if m[1] != 1:
        raise Reject("bad_checkpoint", "schema_version != 1")
    if m[4] == 0:
        raise Reject("bad_checkpoint", "sequence == 0")
    if m[5] != m[7]:
        raise Reject("bad_checkpoint", "log_id != signer_key_id")
    if sha256(checkpoint_signed_bytes(m)) != m[8]:
        raise Reject("bad_checkpoint", "transcript_digest != SHA-256(signed_bytes)")
    if m[2] == 0 and m[6] != EMPTY_ROOT:
        raise Reject("bad_checkpoint", "tree_size 0 with non-empty root")
    return {"schema_version": m[1], "tree_size": m[2], "timestamp_ms": m[3],
            "sequence": m[4], "log_id": m[5], "root": m[6],
            "signer_key_id": m[7], "transcript_digest": m[8], "signature": m[9]}


def check_log_pk(ckpt, log_pk):
    if log_pk is None:
        return "not_pinned"
    if len(log_pk) != LOG_PK_BYTES:
        raise Reject("bad_log_pk", "pinned key is %d bytes, want %d"
                     % (len(log_pk), LOG_PK_BYTES))
    if sha256(log_pk) != ckpt["log_id"]:
        raise Reject("log_id_mismatch", "log_id != SHA-256(pinned log pk)")
    return "ok"


def _path_nodes(arr, what):
    if not isinstance(arr, list) or len(arr) > MAX_PROOF_NODES:
        raise Reject("malformed", "%s: not an array of <= %d nodes"
                     % (what, MAX_PROOF_NODES))
    for n in arr:
        if not _is_b32(n):
            raise Reject("malformed", "%s: node not bstr(32)" % what)
    return arr


def _decode_file(data, shape, what):
    try:
        m = cbor_decode(data)
    except CborError as e:
        raise Reject("malformed", "%s: %s" % (what, e))
    _keys(m, shape, what)
    return m


# ---------------------------------------------------------------------------
# Verification entry points. Each returns a verdict dict; never raises Reject.
# ---------------------------------------------------------------------------

def _verdict(mode, checks, reject=None, extra=None):
    reason = reject.reason if reject else "ok"
    v = {
        "accepted": reject is None,
        "reason": reason,
        "exit_code": REASON_EXIT[reason],
        "mode": mode,
        "signature": "delegated",
        "checks": checks,
    }
    if reject is not None and reject.detail:
        v["detail"] = reject.detail
    if FAULTS:
        v["faults_injected"] = sorted(FAULTS)
    if extra:
        v.update(extra)
    return v


def verify_receipt(data, log_pk=None, transcript_sha256=None,
                   verifier_sha256=None, expect_verdict=None):
    checks = {"cbor": "pending", "statement": "pending", "checkpoint": "pending",
              "log_pk_binding": "pending", "tree_size_binding": "pending",
              "leaf_hash": "pending", "inclusion": "pending",
              "root_binding": "pending", "expectations": "pending",
              "signature": "delegated"}
    extra = {}
    try:
        m = _decode_file(data, range(1, 6), "receipt")
        if not isinstance(m[1], bytes) or not _is_int(m[2]) or not _is_int(m[3]):
            raise Reject("malformed", "receipt field types")
        path = _path_nodes(m[4], "receipt path")
        checks["cbor"] = "ok"
        stmt = parse_statement(m[1])
        checks["statement"] = "ok"
        ck = parse_checkpoint(m[5])
        checks["checkpoint"] = "ok"
        checks["log_pk_binding"] = check_log_pk(ck, log_pk)
        if m[3] != ck["tree_size"] and "skip-tree-size-binding" not in FAULTS:
            checks["tree_size_binding"] = "fail"
            raise Reject("tree_size_mismatch", "receipt %d vs checkpoint %d"
                         % (m[3], ck["tree_size"]))
        checks["tree_size_binding"] = "ok"
        lh = leaf_hash(m[1])
        checks["leaf_hash"] = "recomputed"
        extra["leaf_hash"] = lh.hex()
        ok, root = verify_inclusion(lh, m[2], m[3], path, None)
        if not ok:
            checks["inclusion"] = "fail"
            raise Reject("inclusion_proof_invalid", "path does not terminate "
                         "at the tree top (index %d, size %d, %d nodes)"
                         % (m[2], m[3], len(path)))
        checks["inclusion"] = "ok"
        if root != ck["root"] and "skip-root-binding" not in FAULTS:
            checks["root_binding"] = "fail"
            raise Reject("inclusion_proof_invalid",
                         "recomputed root != checkpoint.root")
        checks["root_binding"] = "ok"
        extra["root"] = ck["root"].hex()
        extra["verdict"] = stmt[5]
        if transcript_sha256 is not None and stmt[8] != transcript_sha256:
            checks["expectations"] = "fail"
            raise Reject("statement_mismatch", "transcript_sha256")
        if verifier_sha256 is not None and stmt[6] != verifier_sha256:
            checks["expectations"] = "fail"
            raise Reject("statement_mismatch", "verifier_sha256")
        if expect_verdict is not None and stmt[5] != expect_verdict:
            checks["expectations"] = "fail"
            raise Reject("statement_mismatch", "verdict is %r" % stmt[5])
        checks["expectations"] = "ok"
        return _verdict("receipt", checks, None, extra)
    except Reject as r:
        return _verdict("receipt", checks, r, extra)


def _detect_equivocation(a, b):
    """a, b: parsed checkpoints of the same log. Returns description or None."""
    if "skip-equivocation" in FAULTS:
        return None
    if a["tree_size"] == b["tree_size"] and a["root"] != b["root"]:
        return "same tree_size %d, different roots" % a["tree_size"]
    if a["sequence"] == b["sequence"] and (
            a["tree_size"] != b["tree_size"] or a["root"] != b["root"]):
        return "same sequence %d, different (tree_size, root)" % a["sequence"]
    return None


def _same_log(a, b):
    return a["log_id"] == b["log_id"] and a["signer_key_id"] == b["signer_key_id"]


def verify_consistency_file(data, log_pk=None):
    checks = {"cbor": "pending", "checkpoints": "pending",
              "size_binding": "pending", "log_pk_binding": "pending",
              "same_log": "pending", "equivocation": "pending",
              "rollback": "pending", "consistency_proof": "pending",
              "signature": "delegated"}
    extra = {}
    try:
        m = _decode_file(data, range(1, 6), "consistency")
        if not _is_int(m[1]) or not _is_int(m[2]):
            raise Reject("malformed", "consistency sizes not uint")
        proof = _path_nodes(m[3], "consistency proof")
        checks["cbor"] = "ok"
        old = parse_checkpoint(m[4])
        new = parse_checkpoint(m[5])
        checks["checkpoints"] = "ok"
        if m[1] != old["tree_size"] or m[2] != new["tree_size"]:
            checks["size_binding"] = "fail"
            raise Reject("malformed", "size field does not match checkpoint")
        checks["size_binding"] = "ok"
        if not _same_log(old, new):
            checks["same_log"] = "fail"
            raise Reject("log_id_mismatch", "checkpoints name different logs")
        checks["same_log"] = "ok"
        checks["log_pk_binding"] = check_log_pk(old, log_pk)
        eq = _detect_equivocation(old, new)
        if eq:
            checks["equivocation"] = "fail"
            raise Reject("equivocation", eq)
        checks["equivocation"] = "ok"
        if (new["sequence"] <= old["sequence"]
                or new["tree_size"] < old["tree_size"]) \
                and "skip-rollback" not in FAULTS:
            checks["rollback"] = "fail"
            raise Reject("rollback", "new sequence/size does not advance")
        checks["rollback"] = "ok"
        if not verify_consistency(old["tree_size"], new["tree_size"],
                                  old["root"], new["root"], proof):
            checks["consistency_proof"] = "fail"
            raise Reject("consistency_proof_invalid",
                         "proof does not link the two signed roots")
        checks["consistency_proof"] = "ok"
        extra["old_size"], extra["new_size"] = old["tree_size"], new["tree_size"]
        return _verdict("consistency", checks, None, extra)
    except Reject as r:
        return _verdict("consistency", checks, r, extra)


def _extract_checkpoints(data):
    """Pull every checkpoint out of a bare checkpoint, receipt or consistency file."""
    m = cbor_decode(data)
    if isinstance(m, dict) and sorted(m) == list(range(1, 10)):
        return [m]
    if isinstance(m, dict) and sorted(m) == list(range(1, 6)):
        if isinstance(m.get(5), dict) and isinstance(m.get(4), list):
            return [m[5]]                       # receipt
        if isinstance(m.get(4), dict) and isinstance(m.get(5), dict):
            return [m[4], m[5]]                 # consistency
    raise CborError("not a checkpoint, receipt or consistency file")


def verify_equivocation(data_a, data_b, log_pk=None):
    """Compare every checkpoint in file A with every checkpoint in file B.

    accepted == True means NO equivocation was found. A fork is a reject with
    reason "equivocation" (the pair is the evidence).
    """
    checks = {"cbor": "pending", "checkpoints": "pending", "same_log": "pending",
              "log_pk_binding": "pending", "equivocation": "pending",
              "signature": "delegated"}
    extra = {}
    try:
        try:
            ra = _extract_checkpoints(data_a)
            rb = _extract_checkpoints(data_b)
        except CborError as e:
            raise Reject("malformed", str(e))
        checks["cbor"] = "ok"
        pa = [parse_checkpoint(c) for c in ra]
        pb = [parse_checkpoint(c) for c in rb]
        checks["checkpoints"] = "ok"
        checks["log_pk_binding"] = "not_pinned"
        if log_pk is not None:
            for c in pa + pb:
                checks["log_pk_binding"] = check_log_pk(c, log_pk)
        for a in pa:
            for b in pb:
                if not _same_log(a, b):
                    checks["same_log"] = "fail"
                    raise Reject("log_id_mismatch", "checkpoints name different logs")
        checks["same_log"] = "ok"
        for a in pa:
            for b in pb:
                eq = _detect_equivocation(a, b)
                if eq:
                    checks["equivocation"] = "fail"
                    extra["evidence"] = {
                        "a": {"tree_size": a["tree_size"], "sequence": a["sequence"],
                              "root": a["root"].hex()},
                        "b": {"tree_size": b["tree_size"], "sequence": b["sequence"],
                              "root": b["root"].hex()}}
                    raise Reject("equivocation", eq)
        checks["equivocation"] = "ok"
        return _verdict("equivocation", checks, None, extra)
    except Reject as r:
        return _verdict("equivocation", checks, r, extra)


# ---------------------------------------------------------------------------
# Self-test (also the only place proof GENERATORS live; they follow RFC 9162
# 2.1.3.1 PATH and 2.1.4.1 PROOF/SUBPROOF, independently of the verifiers)
# ---------------------------------------------------------------------------

def gen_path(m, entries):
    n = len(entries)
    if n == 1:
        return []
    k = _split(n)
    if m < k:
        return gen_path(m, entries[:k]) + [merkle_tree_hash(entries[k:])]
    return gen_path(m - k, entries[k:]) + [merkle_tree_hash(entries[:k])]


def gen_consistency(m, entries):
    def sub(m, d, b):
        n = len(d)
        if m == n:
            return [] if b else [merkle_tree_hash(d)]
        k = _split(n)
        if m <= k:
            return sub(m, d[:k], b) + [merkle_tree_hash(d[k:])]
        return sub(m - k, d[k:], False) + [merkle_tree_hash(d[:k])]
    if m == 0 or m == len(entries):
        return []
    return sub(m, entries, True)


def _iterative_root(entries):
    """Independent second tree-hash: stack/merge formulation (RFC 6962 style)."""
    stack = []          # (height, hash)
    for e in entries:
        cur = (0, leaf_hash(e))
        while stack and stack[-1][0] == cur[0]:
            top = stack.pop()
            cur = (cur[0] + 1, node_hash(top[1], cur[1]))
        stack.append(cur)
    if not stack:
        return EMPTY_ROOT
    h = stack.pop()[1]
    while stack:
        h = node_hash(stack.pop()[1], h)
    return h


# Public CT / RFC 6962 reference tree (also exercised by tests/ztest_fleet_
# transparency): leaf 0 is the empty string.
RFC_LEAVES = [
    b"", b"\x00", b"\x10", b"\x20\x21", b"\x30\x31",
    b"\x40\x41\x42\x43", bytes(range(0x50, 0x58)), bytes(range(0x60, 0x70)),
]
RFC_ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]
RFC_EMPTY_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class _T:
    """Tiny assertion counter."""

    def __init__(self):
        self.n = 0
        self.failures = []

    def ok(self, cond, msg):
        self.n += 1
        if not cond:
            self.failures.append(msg)


def _stream(seed, n):
    out = b""
    c = 0
    while len(out) < n:
        out += sha256(seed, c.to_bytes(4, "big"))
        c += 1
    return out[:n]


def _make_statement(i, verdict="CHAIN OK", vhash=None):
    return cbor_encode({
        1: STATEMENT_MAGIC,
        2: sha256(b"passport", bytes([i])).hex(),
        3: sha256(b"devpk", bytes([i])) if i % 3 else None,
        4: sha256(b"trail", bytes([i])).hex() if i % 4 else "",
        5: verdict,
        6: vhash if vhash is not None else sha256(b"verifier-binary"),
        7: bool(i % 3),
        8: sha256(b"transcript", bytes([i])),
    })


class _Log:
    """Synthetic log with fake (undetectable-here) signatures."""

    def __init__(self, tag=b"A", n=0):
        self.pk = _stream(b"pk" + tag, LOG_PK_BYTES)
        self.log_id = sha256(self.pk)
        self.tag = tag
        self.entries = []
        for i in range(n):
            self.append()

    def append(self, entry=None):
        self.entries.append(entry if entry is not None
                            else _make_statement(len(self.entries)))

    def checkpoint(self, size, seq, ts=1700000000000, root=None, log_id=None,
                   signer=None):
        lid = log_id if log_id is not None else self.log_id
        r = root if root is not None else merkle_tree_hash(self.entries[:size])
        c = {1: 1, 2: size, 3: ts, 4: seq, 5: lid, 6: r,
             7: signer if signer is not None else lid}
        c[8] = sha256(checkpoint_signed_bytes(c))
        c[9] = _stream(b"sig" + self.tag + size.to_bytes(8, "big")
                       + seq.to_bytes(8, "big") + r, SIG_BYTES)
        return c

    def receipt(self, idx, size, ckpt=None, seq=None):
        ck = ckpt if ckpt is not None else self.checkpoint(size, seq or size)
        return {1: self.entries[idx], 2: idx, 3: size,
                4: gen_path(idx, self.entries[:size]), 5: ck}

    def consistency(self, old, new, seq_old=None, seq_new=None):
        return {1: old, 2: new, 3: gen_consistency(old, self.entries[:new]),
                4: self.checkpoint(old, seq_old or old),
                5: self.checkpoint(new, seq_new or new)}


def _merkle_selftest(t, max_n):
    # 1. RFC 6962 / CT reference vectors, two independent tree-hash routines.
    t.ok(EMPTY_ROOT.hex() == RFC_EMPTY_ROOT, "empty root")
    for n in range(1, 9):
        a = merkle_tree_hash(RFC_LEAVES[:n]).hex()
        b = _iterative_root(RFC_LEAVES[:n]).hex()
        t.ok(a == RFC_ROOTS[n - 1], "RFC root n=%d recursive got %s" % (n, a))
        t.ok(b == RFC_ROOTS[n - 1], "RFC root n=%d iterative got %s" % (n, b))
    t.ok(merkle_tree_hash(RFC_LEAVES[:7]).hex() ==
         "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
         "7-leaf root")
    # Known 8-leaf inclusion proof for leaf 0 (CT reference): sibling hashes are
    # leaf1 hash, MTH(leaf2,leaf3), MTH(leaf4..7).
    p = gen_path(0, RFC_LEAVES)
    t.ok(p[0] == leaf_hash(RFC_LEAVES[1]), "rfc path[0]")
    t.ok(p[1] == node_hash(leaf_hash(RFC_LEAVES[2]), leaf_hash(RFC_LEAVES[3])),
         "rfc path[1]")
    t.ok(p[2] == merkle_tree_hash(RFC_LEAVES[4:8]), "rfc path[2]")

    # 2. Exhaustive inclusion/consistency for every size/index up to max_n.
    entries = [b"entry-%d" % i + bytes([i]) * (i % 5) for i in range(max_n)]
    roots = [merkle_tree_hash(entries[:n]) for n in range(max_n + 1)]
    for n in range(1, max_n + 1):
        t.ok(roots[n] == _iterative_root(entries[:n]), "iter root %d" % n)
    n_incl = n_cons = 0
    for n in range(1, max_n + 1):
        for i in range(n):
            path = gen_path(i, entries[:n])
            lh = leaf_hash(entries[i])
            ok, r = verify_inclusion(lh, i, n, path, None)
            t.ok(ok and r == roots[n], "inclusion good n=%d i=%d" % (n, i))
            n_incl += 1
            # Wrong index / size / short / long / empty paths must all fail.
            for j in range(n):
                if j != i:
                    ok, r = verify_inclusion(lh, j, n, path, None)
                    t.ok(not (ok and r == roots[n]),
                         "wrong index accepted n=%d i=%d j=%d" % (n, i, j))
            for n2 in (n - 1, n + 1, 2 * n):
                if n2 >= 1:
                    # The path alone does not bind the size (same recomputed
                    # value is expected for a prefix-equivalent path); what
                    # must never happen is acceptance against the TRUE root
                    # of the claimed size.
                    ok, r = verify_inclusion(lh, i, n2, path, None)
                    true_root = (roots[n2] if n2 <= max_n else
                                 merkle_tree_hash([b"pad%d" % k for k in range(n2)]))
                    t.ok(not (ok and r == true_root),
                         "wrong size accepted n=%d i=%d n2=%d" % (n, i, n2))
            if path:
                ok, r = verify_inclusion(lh, i, n, path[:-1], None)
                t.ok(not (ok and r == roots[n]), "short path n=%d i=%d" % (n, i))
            ok, r = verify_inclusion(lh, i, n, path + [path[0] if path else lh], None)
            t.ok(not (ok and r == roots[n]), "long path n=%d i=%d" % (n, i))
    for old in range(0, max_n + 1):
        for new in range(max(old, 0), max_n + 1):
            if new == 0:
                continue
            proof = gen_consistency(old, entries[:new])
            t.ok(verify_consistency(old, new, roots[old], roots[new], proof),
                 "consistency good %d->%d" % (old, new))
            n_cons += 1
            if old < new:
                # Any other old size / roots must fail.
                if old > 0:  # the empty tree is consistent with any root
                    t.ok(not verify_consistency(old, new, roots[old],
                                                sha256(roots[new]), proof),
                         "cons bad new root %d->%d" % (old, new))
                t.ok(not verify_consistency(old, new, sha256(roots[old]),
                                            roots[new], proof),
                     "cons bad old root %d->%d" % (old, new))
                if proof:
                    t.ok(not verify_consistency(old, new, roots[old], roots[new],
                                                proof[:-1]),
                         "cons short %d->%d" % (old, new))
                t.ok(not verify_consistency(old, new, roots[old], roots[new],
                                            proof + [roots[old]]),
                     "cons long %d->%d" % (old, new))
            if new > 0 and old != new:
                t.ok(not verify_consistency(new, old, roots[new], roots[old], proof),
                     "cons reversed %d->%d" % (old, new))
    return n_incl, n_cons


def _bitflip_proofs(t, rng, full_up_to=12, max_n=40):
    """Every single bit flip in leaf hash, each path node, each root fails."""
    flips = 0
    entries = [b"flip-%d" % i for i in range(max_n)]
    for n in range(1, max_n + 1):
        sample = (range(n) if n <= full_up_to
                  else sorted(rng.sample(range(n), 2)))
        root = merkle_tree_hash(entries[:n])
        for i in sample:
            path = gen_path(i, entries[:n])
            lh = leaf_hash(entries[i])
            targets = [("leaf", None)] + [("node", k) for k in range(len(path))] \
                + [("root", None)]
            for kind, k in targets:
                bits = range(256) if n <= full_up_to else rng.sample(range(256), 16)
                for bit in bits:
                    def flip(b):
                        x = bytearray(b)
                        x[bit // 8] ^= 1 << (bit % 8)
                        return bytes(x)
                    l2, p2, r2 = lh, list(path), root
                    if kind == "leaf":
                        l2 = flip(lh)
                    elif kind == "node":
                        p2[k] = flip(path[k])
                    else:
                        r2 = flip(root)
                    ok, got = verify_inclusion(l2, i, n, p2, None)
                    t.ok(not (ok and got == r2), "bitflip accepted n=%d i=%d %s"
                         % (n, i, kind))
                    flips += 1
    # Consistency proof node / root bit flips.
    for old in range(1, 21):
        for new in range(old + 1, 21):
            proof = gen_consistency(old, entries[:new])
            ro, rn = merkle_tree_hash(entries[:old]), merkle_tree_hash(entries[:new])
            for k in range(len(proof)):
                for bit in rng.sample(range(256), 4):
                    p2 = list(proof)
                    x = bytearray(p2[k])
                    x[bit // 8] ^= 1 << (bit % 8)
                    p2[k] = bytes(x)
                    t.ok(not verify_consistency(old, new, ro, rn, p2),
                         "cons bitflip accepted %d->%d node %d" % (old, new, k))
                    flips += 1
    return flips


def _flip_bit(data, bit):
    b = bytearray(data)
    b[bit // 8] ^= 1 << (bit % 8)
    return bytes(b)


def _file_selftest(t, rng, exhaustive_bits=True):
    """Receipt/consistency file level: positives, semantic negatives, CBOR rules,
    and every single bit flip of the file bytes."""
    counts = {"file_bitflips": 0, "sig_region_bitflips_delegated": 0,
              "truncations": 0}
    log = _Log(b"A", 40)
    log2 = _Log(b"B", 40)
    enc = cbor_encode

    def rcv(m, **kw):
        return verify_receipt(enc(m) if not isinstance(m, bytes) else m, **kw)

    def cons(m, **kw):
        return verify_consistency_file(enc(m) if not isinstance(m, bytes) else m, **kw)

    def expect(v, reason, msg):
        t.ok(v["reason"] == reason and v["accepted"] == (reason == "ok"),
             "%s: expected %s got %s (%s)" % (msg, reason, v["reason"],
                                              v.get("detail", "")))

    # ---- receipt positives (one per interesting tree shape) ----
    for size, idx in ((1, 0), (2, 1), (7, 3), (8, 7), (13, 12), (40, 0), (40, 39)):
        expect(rcv(log.receipt(idx, size), log_pk=log.pk), "ok",
               "receipt positive %d/%d" % (idx, size))
    expect(rcv(log.receipt(3, 7)), "ok", "receipt positive, pk not pinned")
    good = log.receipt(3, 7)
    gv = rcv(good)
    t.ok(gv["signature"] == "delegated" and gv["checks"]["signature"] == "delegated",
         "signature reported delegated")
    # Expectations.
    st = parse_statement(good[1])
    expect(rcv(good, transcript_sha256=st[8], verifier_sha256=st[6],
               expect_verdict="CHAIN OK"), "ok", "expectations positive")
    expect(rcv(good, transcript_sha256=b"\x00" * 32), "statement_mismatch",
           "tampered transcript")
    expect(rcv(good, verifier_sha256=b"\x00" * 32), "statement_mismatch",
           "different verifier hash")
    expect(rcv(good, expect_verdict="REJECT"), "statement_mismatch", "verdict expect")

    # ---- receipt semantic negatives ----
    expect(rcv(log.receipt(3, 7), log_pk=log2.pk), "log_id_mismatch",
           "receipt under different log key")
    expect(rcv(log.receipt(3, 7), log_pk=log.pk[:-1]), "bad_log_pk", "short pk")
    bad = log.receipt(3, 7, ckpt=log.checkpoint(7, 7, log_id=log2.log_id,
                                        signer=log.log_id))
    expect(rcv(bad), "bad_checkpoint", "log_id != signer_key_id")
    bad = log.receipt(3, 7, ckpt=log.checkpoint(7, 7, signer=log2.log_id))
    expect(rcv(bad), "bad_checkpoint", "signer_key_id differs from log_id")
    # Older signed checkpoint while claiming the newer size.
    old_ck = log.checkpoint(5, 5)
    r = log.receipt(3, 7, ckpt=old_ck)
    expect(rcv(r), "tree_size_mismatch", "newer size vs older checkpoint")
    # Path for 7 but receipt tree_size rewritten to old size to match checkpoint.
    r = log.receipt(3, 7, ckpt=old_ck)
    r[3] = 5
    expect(rcv(r), "inclusion_proof_invalid", "old checkpoint, path for newer tree")
    # Checkpoint root swapped for the older root but digest recomputed.
    r = log.receipt(3, 7, ckpt=log.checkpoint(7, 7, root=merkle_tree_hash(log.entries[:5])))
    expect(rcv(r), "inclusion_proof_invalid", "root swapped, same size")
    # Statement edited: REJECT -> CHAIN OK, different verifier hash.
    log3 = _Log(b"C", 7)
    log3.entries[3] = _make_statement(3, verdict="REJECT")
    ck_rej = log3.checkpoint(7, 7)
    forged = log3.receipt(3, 7, ckpt=ck_rej)
    forged[1] = _make_statement(3, verdict="CHAIN OK")
    expect(rcv(forged), "inclusion_proof_invalid", "verdict forged")
    forged[1] = _make_statement(3, verdict="REJECT", vhash=sha256(b"other-bin"))
    expect(rcv(forged), "inclusion_proof_invalid", "verifier hash forged")
    # Index out of range / wrong index.
    r = log.receipt(3, 7)
    r[2] = 7
    expect(rcv(r), "inclusion_proof_invalid", "leaf_index == tree_size")
    r[2] = 4
    expect(rcv(r), "inclusion_proof_invalid", "wrong leaf_index")
    # Statement schema negatives.
    for label, mut in (("magic", lambda s: s.update({1: "pqcp-appraisal/2"})),
                       ("verdict", lambda s: s.update({5: "CHAIN_OK"})),
                       ("upper hex", lambda s: s.update({2: s[2].upper()})),
                       ("sigverified int", lambda s: s.update({7: 1})),
                       ("extra key", lambda s: s.update({9: 1})),
                       ("missing key", lambda s: s.pop(8))):
        s = cbor_decode(log.entries[3])
        mut(s)
        lg = _Log(b"S", 7)
        lg.entries[3] = enc(s)
        expect(rcv(lg.receipt(3, 7)), "bad_statement", "statement %s" % label)
    # Bad checkpoint fields.
    for label, tweak in (("schema_version", {1: 2}), ("sequence zero", {4: 0})):
        ck = log.checkpoint(7, 7)
        ck.update(tweak)
        ck[8] = sha256(checkpoint_signed_bytes(ck))
        expect(rcv(log.receipt(3, 7, ckpt=ck)), "bad_checkpoint", label)
    ck = log.checkpoint(7, 7)
    ck[8] = sha256(b"wrong")
    expect(rcv(log.receipt(3, 7, ckpt=ck)), "bad_checkpoint", "transcript_digest")
    ck = log.checkpoint(7, 7)
    ck[9] = ck[9][:-1]
    expect(rcv(log.receipt(3, 7, ckpt=ck)), "malformed", "signature length")
    ck = log.checkpoint(0, 1, root=sha256(b"x"))
    # size-0 non-empty root; receipt cannot be valid either way.
    expect(rcv(log.receipt(0, 1, ckpt=ck)), "bad_checkpoint", "size 0 root")
    # Path longer than the 65-node bound.
    r = log.receipt(3, 7)
    r[4] = [sha256(b"n")] * 66
    expect(rcv(r), "malformed", "66 path nodes")

    # ---- CBOR strictness on a receipt ----
    base = enc(log.receipt(3, 7))
    expect(rcv(base), "ok", "base receipt")
    expect(rcv(base + b"\x00"), "malformed", "trailing byte")
    for cut in range(len(base)):
        v = rcv(base[:cut])
        t.ok(not v["accepted"] and v["reason"] == "malformed",
             "truncation at %d: %s" % (cut, v["reason"]))
        counts["truncations"] += 1
    # Non-canonical heads: rewrite leaf_index 3 (0x03) as 0x18 0x03 and the map
    # head, a text length, etc.
    r5 = bytes([0xa5])
    t.ok(base[0] == 0xa5, "receipt head byte")
    off = len(r5) + len(enc(1)) + len(enc(log.entries[3]))  # after key1+value
    t.ok(base[off:off + 2] == enc(2) + enc(3), "locate leaf_index")
    nc = base[:off + 1] + b"\x18\x03" + base[off + 2:]
    expect(rcv(nc), "malformed", "non-canonical int 0x18 0x03")
    nc = base[:off + 1] + b"\x19\x00\x03" + base[off + 2:]
    expect(rcv(nc), "malformed", "non-canonical int 0x19")
    nc = b"\xb8\x05" + base[1:]
    expect(rcv(nc), "malformed", "non-canonical map length")
    nc = base[:off + 1] + b"\x1b" + (3).to_bytes(8, "big") + base[off + 2:]
    expect(rcv(nc), "malformed", "non-canonical int 0x1b")
    # Indefinite lengths.
    expect(rcv(b"\xbf" + base[1:] + b"\xff"), "malformed", "indefinite map")
    expect(rcv(base.replace(enc(log.entries[3]), b"\x5f\x41\x00\xff", 1)),
           "malformed", "indefinite bstr")
    # Map key order / duplicates / unknown / wrong count.
    items = [(1, log.entries[3]), (2, 3), (3, 7), (4, gen_path(3, log.entries[:7])),
             (5, log.checkpoint(7, 7))]

    def raw_map(pairs):
        return enc_head5(len(pairs)) + b"".join(enc(k) + enc(v) for k, v in pairs)

    def enc_head5(n):
        return bytes([0xa0 | n])
    expect(rcv(raw_map(items)), "ok", "raw map rebuild")
    expect(rcv(raw_map([items[1], items[0]] + items[2:])), "malformed", "keys out of order")
    expect(rcv(raw_map(items[:1] + items[:1] + items[2:])), "malformed", "duplicate key")
    expect(rcv(raw_map(items[:4])), "malformed", "missing key 5")
    expect(rcv(raw_map(items + [(6, 0)])), "malformed", "unknown key 6")
    # Negative int, tag, float, wrong simple, text key.
    expect(rcv(base[:off + 1] + b"\x20" + base[off + 2:]), "malformed", "negative int")
    expect(rcv(base[:off + 1] + b"\xc0\x03" + base[off + 2:]), "malformed", "tag")
    expect(rcv(base[:off + 1] + b"\xfb" + b"\x00" * 8 + base[off + 2:]),
           "malformed", "float64")
    expect(rcv(base[:off + 1] + b"\xf7" + base[off + 2:]), "malformed", "undefined")
    expect(rcv(base[:off + 1] + b"\xf8\x20" + base[off + 2:]), "malformed", "simple 32")
    expect(rcv(b""), "malformed", "empty input")
    expect(rcv(b"\xff"), "malformed", "break byte")

    # ---- consistency positives ----
    for old, new in ((1, 2), (3, 7), (4, 8), (5, 40), (8, 16), (1, 40), (39, 40)):
        expect(cons(log.consistency(old, new), log_pk=log.pk), "ok",
               "consistency positive %d->%d" % (old, new))
    expect(cons(log.consistency(5, 5, 5, 6)), "ok", "equal size, equal root, seq advances")

    # ---- consistency semantic negatives ----
    c = log.consistency(3, 7)
    expect(cons(c, log_pk=log2.pk), "log_id_mismatch", "consistency under other pk")
    # Different logs in old/new.
    c = log.consistency(3, 7)
    c[5] = log2.checkpoint(7, 7)
    expect(cons(c), "log_id_mismatch", "old/new name different logs")
    # Equivocation: same size, different root, both internally valid.
    fork = _Log(b"A", 40)
    fork.entries[6] = b"forged-entry-6"
    c = {1: 7, 2: 7, 3: [], 4: log.checkpoint(7, 7), 5: fork.checkpoint(7, 8)}
    t.ok(c[4][6] != c[5][6], "fork roots differ")
    expect(cons(c), "equivocation", "same size, different roots")
    # Same sequence, different size/root.
    c = {1: 5, 2: 7, 3: gen_consistency(5, log.entries[:7]),
         4: log.checkpoint(5, 9), 5: log.checkpoint(7, 9)}
    expect(cons(c), "equivocation", "same sequence, different size")
    # Rollback: new.sequence <= old.sequence, and size shrink.
    expect(cons(log.consistency(3, 7, 9, 8)), "rollback", "sequence goes backwards")
    expect(cons(log.consistency(3, 7, 9, 9)), "equivocation", "equal sequence, new tree")
    c = {1: 7, 2: 3, 3: [], 4: log.checkpoint(7, 1), 5: log.checkpoint(3, 2)}
    expect(cons(c), "rollback", "tree size shrinks")
    # Rewrite of history: entry 0 replaced in the "new" log; proof taken from the
    # rewritten log against honest old root.
    hist = _Log(b"A", 40)
    hist.entries[0] = b"rewritten-0"
    c = {1: 3, 2: 7, 3: gen_consistency(3, hist.entries[:7]),
         4: log.checkpoint(3, 3), 5: hist.checkpoint(7, 7)}
    expect(cons(c), "consistency_proof_invalid", "history rewritten (entry 0)")
    # Entry 0 removed and re-appended at the end.
    hist = _Log(b"A", 0)
    hist.entries = log.entries[1:7] + [log.entries[0]]
    c = {1: 3, 2: 7, 3: gen_consistency(3, hist.entries[:7]),
         4: log.checkpoint(3, 3), 5: hist.checkpoint(7, 7)}
    expect(cons(c), "consistency_proof_invalid", "entry 0 removed and re-appended")
    # Empty proof where one is needed; wrong proof; size fields.
    c = log.consistency(3, 7)
    c[3] = []
    expect(cons(c), "consistency_proof_invalid", "missing proof nodes")
    c = log.consistency(3, 7)
    c[1] = 4
    expect(cons(c), "malformed", "old_size field != old checkpoint")
    c = log.consistency(3, 7)
    c[2] = 8
    expect(cons(c), "malformed", "new_size field != new checkpoint")
    c = log.consistency(3, 7)
    c[3] = [sha256(b"n")] * 66
    expect(cons(c), "malformed", "66 consistency nodes")
    cb = enc(log.consistency(3, 7))
    expect(cons(cb + b"\x00"), "malformed", "consistency trailing byte")
    for cut in range(0, len(cb), 7):
        t.ok(cons(cb[:cut])["reason"] == "malformed", "consistency truncation %d" % cut)
        counts["truncations"] += 1
    # old_size 0: empty proof and H("") old root.
    zero_old = {1: 0, 2: 7, 3: [], 4: log.checkpoint(0, 1, root=EMPTY_ROOT),
                5: log.checkpoint(7, 2)}
    expect(cons(zero_old), "ok", "old_size 0 accepted")
    zero_old[4] = log.checkpoint(0, 1, root=EMPTY_ROOT)
    zero_old[3] = [sha256(b"x")]
    expect(cons(zero_old), "consistency_proof_invalid", "old_size 0 with nodes")

    # ---- equivocation mode ----
    a = enc(log.receipt(3, 7))
    b = enc(fork.receipt(3, 7, ckpt=fork.checkpoint(7, 8)))
    ev = verify_equivocation(a, b)
    expect(ev, "equivocation", "equivocation pair detected (receipts)")
    t.ok("evidence" in ev, "equivocation evidence attached")
    expect(verify_equivocation(a, enc(log.receipt(5, 7))), "ok", "same checkpoint, no fork")
    expect(verify_equivocation(a, enc(log.consistency(3, 9))), "ok",
           "honest later checkpoint, no fork")
    expect(verify_equivocation(a, enc(log2.receipt(3, 7))), "log_id_mismatch",
           "different logs are not a fork")
    expect(verify_equivocation(a, enc(log.checkpoint(7, 7))), "ok", "bare checkpoint")
    expect(verify_equivocation(a, b"\xa1\x01\x01"), "malformed", "equivocation garbage")

    # ---- single bit flips over whole files ----
    def sweep(blob, verifier, label, sig_spans):
        accepted_outside = []
        for bit in range(len(blob) * 8):
            byte = bit // 8
            v = verifier(_flip_bit(blob, bit))
            in_sig = any(s <= byte < e for s, e in sig_spans)
            counts["file_bitflips"] += 1
            if in_sig:
                counts["sig_region_bitflips_delegated"] += 1
                continue
            if v["accepted"]:
                accepted_outside.append(bit)
        t.ok(not accepted_outside,
             "%s: %d bit flips accepted outside signature, first at bit %s"
             % (label, len(accepted_outside), accepted_outside[:3]))
    if exhaustive_bits:
        for size, idx in ((7, 3), (40, 17)):
            blob = enc(log.receipt(idx, size))
            sig = log.checkpoint(size, size)[9]
            s0 = blob.find(sig)
            t.ok(s0 > 0 and blob.count(sig) == 1, "locate sig in receipt")
            sweep(blob, lambda x: verify_receipt(x), "receipt %d/%d" % (idx, size),
                  [(s0, s0 + len(sig))])
        blob = enc(log.consistency(5, 13))
        sigs = [log.checkpoint(5, 5)[9], log.checkpoint(13, 13)[9]]
        spans = []
        for sg in sigs:
            s0 = blob.find(sg)
            t.ok(s0 > 0, "locate sig in consistency")
            spans.append((s0, s0 + len(sg)))
        sweep(blob, lambda x: verify_consistency_file(x), "consistency 5->13", spans)
    return counts


def _cli_selftest(t):
    """Exit-code table is injective and covers every reason."""
    codes = list(REASON_EXIT.values())
    t.ok(len(codes) == len(set(codes)), "distinct exit codes")


def _fault_sensitivity(t):
    """Each injected fault must make at least one semantic negative pass wrongly."""
    killed = {}
    for fault in KNOWN_FAULTS:
        FAULTS.clear()
        FAULTS.add(fault)
        sub = _T()
        try:
            _merkle_selftest(sub, 8)  # fixed RFC vectors catch hash-domain faults
            _file_selftest(sub, random.Random(1), exhaustive_bits=False)
        finally:
            FAULTS.clear()
        killed[fault] = bool(sub.failures)
        t.ok(killed[fault], "fault %s not detected by negative suite" % fault)
    return killed


def run_self_test(seed=20260101, max_n=40, quick=False):
    FAULTS.clear()
    rng = random.Random(seed)
    t = _T()
    n_incl, n_cons = _merkle_selftest(t, max_n)
    flips = _bitflip_proofs(t, rng, max_n=max_n)
    counts = _file_selftest(t, rng, exhaustive_bits=not quick)
    _cli_selftest(t)
    killed = _fault_sensitivity(t)
    # Strict-CBOR unit checks.
    for label, blob in (("uint8 long form", b"\x18\x05"),
                        ("uint16 short value", b"\x19\x00\xff"),
                        ("uint32 short value", b"\x1a\x00\x00\xff\xff"),
                        ("uint64 short value", b"\x1b\x00\x00\x00\x00\xff\xff\xff\xff"),
                        ("reserved ai 28", b"\x1c"), ("indefinite array", b"\x9f\xff"),
                        ("indefinite text", b"\x7f\xff"), ("bstr truncated", b"\x42\x00"),
                        ("array count too big", b"\x9b\xff\xff\xff\xff\xff\xff\xff\xff"),
                        ("text invalid utf8", b"\x62\xc3\x28"),
                        ("text overlong", b"\x62\xc0\x80"),
                        ("map text key", b"\xa1\x61a\x01"),
                        ("map equal keys", b"\xa2\x01\x01\x01\x02"),
                        ("tag", b"\xc1\x01"), ("float16", b"\xf9\x00\x00"),
                        ("break", b"\xff"), ("trailing", b"\x01\x01"),
                        ("depth bomb", b"\x81" * 40 + b"\x00")):
        try:
            cbor_decode(blob)
            t.ok(False, "cbor accepted: %s" % label)
        except CborError:
            t.ok(True, label)
    for obj in (0, 23, 24, 255, 256, 65535, 65536, 2 ** 32 - 1, 2 ** 32, 2 ** 64 - 1,
                b"", b"x" * 300, "", "abc", [], [1, [2]], {1: None, 2: True, 3: False},
                {1: b"a" * 70000}):
        t.ok(cbor_decode(cbor_encode(obj)) == obj, "cbor round trip %r" % (str(obj)[:20],))
    return {
        "passed": not t.failures, "assertions": t.n, "failures": t.failures[:20],
        "inclusion_proofs_checked": n_incl, "consistency_proofs_checked": n_cons,
        "proof_bitflips_rejected": flips, "mutant_faults_detected": killed,
        **counts,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise Reject("io_error", "%s: %s" % (path, e.strerror))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Independent RFC 9162 verifier for appraisal receipts "
                    "(ML-DSA signature is 'delegated' to the C verifier).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--receipt", metavar="R.cbor")
    g.add_argument("--consistency", metavar="C.cbor")
    g.add_argument("--equivocation", nargs=2, metavar=("A.cbor", "B.cbor"),
                   help="files may be bare checkpoints, receipts or consistency files")
    g.add_argument("--self-test", action="store_true")
    ap.add_argument("--log-pk", metavar="P", help="pinned raw 1952-byte log public key")
    ap.add_argument("--transcript", metavar="T",
                    help="receipt mode: require statement.transcript_sha256 == sha256(file)")
    ap.add_argument("--verifier-bin", metavar="B",
                    help="receipt mode: require statement.verifier_sha256 == sha256(file)")
    ap.add_argument("--expect-verdict", choices=VERDICTS)
    ap.add_argument("--inject-fault", choices=KNOWN_FAULTS, action="append", default=[],
                    help="TEST ONLY: deliberately break one invariant")
    ap.add_argument("--quick", action="store_true",
                    help="self-test: skip exhaustive whole-file bit flips")
    ap.add_argument("--seed", type=int, default=20260101)
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return REASON_EXIT["usage"] if e.code else 0

    FAULTS.update(args.inject_fault)
    if args.self_test:
        res = run_self_test(seed=args.seed, quick=args.quick)
        print(json.dumps(res, indent=2, sort_keys=True))
        print("RFC9162_REFERENCE SELFTEST %s assertions=%d"
              % ("PASS" if res["passed"] else "FAIL", res["assertions"]))
        return 0 if res["passed"] else REASON_EXIT["selftest_failed"]
    try:
        pk = _read(args.log_pk) if args.log_pk else None
        if args.receipt:
            ts = sha256(_read(args.transcript)) if args.transcript else None
            vb = sha256(_read(args.verifier_bin)) if args.verifier_bin else None
            v = verify_receipt(_read(args.receipt), pk, ts, vb, args.expect_verdict)
        elif args.consistency:
            v = verify_consistency_file(_read(args.consistency), pk)
        else:
            v = verify_equivocation(_read(args.equivocation[0]),
                                    _read(args.equivocation[1]), pk)
    except Reject as r:
        v = _verdict("io", {"signature": "delegated"}, r)
    print(json.dumps(v, indent=2, sort_keys=True))
    return v["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
