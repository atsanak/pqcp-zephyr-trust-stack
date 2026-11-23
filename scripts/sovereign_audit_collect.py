#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify signed sovereign audit CBOR v1 and atomically journal receipts.

A receipt authenticates the transmitted projection, not source completeness or
persistence. Stream pins and the public key must be provisioned out of band.
"""
import argparse
import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

MAX_WIRE = 4 * 1024 * 1024
MAX_ITEMS = 100000
DOMAIN = b"PQCP-SOVEREIGN-AUDIT-BATCH-V1"

class Invalid(ValueError):
    pass

class Reader:
    def __init__(self, data):
        self.data, self.pos, self.items = data, 0, 0

    def read(self, depth=0):
        self.items += 1
        if depth > 8 or self.items > MAX_ITEMS or self.pos >= len(self.data):
            raise Invalid("CBOR limit or truncated input")
        first = self.data[self.pos]
        self.pos += 1
        major, ai = first >> 5, first & 31
        if major == 7:
            if ai in (20, 21):
                return ai == 21
            raise Invalid("unsupported CBOR primitive")
        if ai < 24:
            n = ai
        elif ai in (24, 25, 26, 27):
            size = 1 << (ai - 24)
            if self.pos + size > len(self.data):
                raise Invalid("truncated CBOR argument")
            n = int.from_bytes(self.data[self.pos:self.pos + size], 'big')
            self.pos += size
            if n < (24 if size == 1 else 1 << (8 * (size // 2))):
                raise Invalid("noncanonical CBOR argument")
        else:
            raise Invalid("indefinite or reserved CBOR")
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major in (2, 3):
            if n > MAX_WIRE or self.pos + n > len(self.data):
                raise Invalid("truncated or oversized CBOR string")
            raw = self.data[self.pos:self.pos + n]
            self.pos += n
            if major == 2:
                return raw
            try:
                return raw.decode('utf-8')
            except UnicodeDecodeError as exc:
                raise Invalid("invalid UTF-8") from exc
        if major == 4:
            if n > MAX_ITEMS:
                raise Invalid("oversized array")
            return [self.read(depth + 1) for _ in range(n)]
        if major == 5:
            if n > MAX_ITEMS:
                raise Invalid("oversized map")
            result = {}
            last = 0
            for _ in range(n):
                key = self.read(depth + 1)
                if type(key) is not int or key <= last:
                    raise Invalid("map keys must be ascending positive integers")
                last = key
                result[key] = self.read(depth + 1)
            return result
        raise Invalid("unsupported CBOR type")

def uint(v):
    return type(v) is int and 0 <= v <= 0xffffffffffffffff

def shape(v, count):
    return type(v) is dict and list(v) == list(range(1, count + 1))

def text(v, limit):
    return type(v) is str and len(v) < limit and all(32 <= ord(ch) <= 126 for ch in v)

def blob(v, size):
    return type(v) is bytes and len(v) == size

def validate_event(e, tenant):
    if not shape(e, 31) or e[1] != 1 or any(not uint(e[k]) for k in list(range(1, 10)) + list(range(12, 18))):
        raise Invalid("invalid event fields")
    if (not 0 < e[2] <= 0xffffffff or not e[3] or not e[4] or e[5] < e[4]
        or (e[6] and e[6] <= e[4]) or not 1 <= e[12] <= 9 or not 1 <= e[13] <= 26
        or e[14] > 5 or e[15] > 6 or e[16] > 6 or e[17] & ~255):
        raise Invalid("invalid event metadata")
    t = e[11]
    if (not blob(e[10], 16) or not shape(t, 5) or not text(t[1], 48) or t[1] != tenant
        or not text(t[2], 48) or not uint(t[3]) or not uint(t[4]) or t[3] != e[8] or t[4] != e[9] or not blob(t[5], 32)):
        raise Invalid("invalid event tenant")
    if type(e[18]) is not int or not -(1 << 31) <= e[18] < (1 << 31):
        raise Invalid("invalid event result")
    if any(not text(e[k], size) for k, size in zip(range(19, 24), (48, 64, 96, 48, 128))):
        raise Invalid("invalid event text")
    if any(not blob(e[k], 32) for k in range(24, 31)) or type(e[31]) is not list or len(e[31]) > 12:
        raise Invalid("invalid event digests or attributes")
    for a in e[31]:
        if not shape(a, 4) or not text(a[1], 40) or not uint(a[2]) or not uint(a[3]) or a[3] & ~7 or not a[1] or any(not (ch.isascii() and (ch.isalnum() or ch in "_.-")) for ch in a[1]):
            raise Invalid("invalid attribute")
        v, kind = a[4], a[2]
        valid = (kind == 0 and uint(v) or kind == 1 and type(v) is int and -(1 << 63) <= v < (1 << 63)
                 or kind == 2 and type(v) is bool or kind == 3 and text(v, 96) or kind == 4 and blob(v, 32))
        if not valid:
            raise Invalid("invalid attribute value")
    if any(a[1] >= b[1] for a, b in zip(e[31], e[31][1:])):
        raise Invalid("attributes not ordered")

def validate_pins(db, stream, tenant, cursor, epoch, first):
    if (not db or db == ':memory:' or not stream or not text(tenant, 48) or not tenant
        or not uint(cursor) or not cursor or not uint(epoch) or not epoch or not uint(first) or not first):
        raise Invalid("invalid durable database or stream pins")

def decode_batch(wire):
    if not 0 < len(wire) <= MAX_WIRE:
        raise Invalid("invalid wire length")
    # The outer map header must be the canonical single-byte 19-field map.
    if wire[0] != 0xb3:
        raise Invalid("invalid batch map")
    reader = Reader(wire)
    reader.pos = 1
    batch = {}
    body_end = None
    for expected in range(1, 20):
        field_key = reader.read(1)
        if type(field_key) is not int or field_key != expected:
            raise Invalid("invalid batch key")
        batch[expected] = reader.read(1)
        if expected == 16:
            body_end = reader.pos
    if reader.pos != len(wire):
        raise Invalid("trailing bytes")
    digest = hashlib.sha256(DOMAIN + b'\xb0' + wire[1:body_end]).digest()
    if digest != batch[17]:
        raise Invalid("batch digest mismatch")
    return batch

def verify_wire(wire, public_key, verifier, tenant, cursor, epoch):
    if len(public_key) != 1952:
        raise Invalid("invalid public key length")
    batch = decode_batch(wire)
    if (any(not uint(batch[k]) for k in list(range(1, 11)) + [18]) or batch[1] != 1
        or batch[2] != cursor or batch[3] == 0 or batch[4] != epoch
        or batch[5] == 0 or batch[6] < batch[5] or batch[7] < batch[6]
        or batch[7] == 0xffffffffffffffff
        or batch[8] == 0 or batch[9] != 0 or batch[10] > 3 or batch[11] != tenant
        or not text(batch[11], 48) or any(not blob(batch[k], 32) for k in range(12, 16))
        or type(batch[16]) is not list or len(batch[16]) != batch[8]
        or not blob(batch[17], 32) or batch[18] != 1 or not blob(batch[19], 3309)):
        raise Invalid("invalid batch fields or pins")
    for event in batch[16]:
        validate_event(event, tenant)
    seq = [event[3] for event in batch[16]]
    if seq[0] != batch[5] or seq[-1] != batch[6] or any(a >= b for a, b in zip(seq, seq[1:])):
        raise Invalid("invalid event sequence")
    try:
        result = subprocess.run(
            [str(verifier)], input=public_key + batch[17] + batch[19],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Invalid("signature helper failed") from exc
    if result.returncode != 0:
        raise Invalid("signature verification failed")
    return batch

def collect(db, stream, tenant, cursor, epoch, first, public_key, wire, batch):
    validate_pins(db, stream, tenant, cursor, epoch, first)
    db_path = Path(db).resolve()
    con = sqlite3.connect(db_path, isolation_level=None, timeout=30)
    try:
        con.execute('PRAGMA synchronous=FULL')
        con.execute('BEGIN IMMEDIATE')
        con.execute("""CREATE TABLE IF NOT EXISTS streams (
            id TEXT PRIMARY KEY, tenant TEXT NOT NULL, cursor TEXT NOT NULL,
            epoch TEXT NOT NULL, first TEXT NOT NULL, key BLOB NOT NULL,
            high TEXT NOT NULL, created TEXT NOT NULL, digest BLOB NOT NULL
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS receipts (
            stream TEXT NOT NULL, digest BLOB NOT NULL, wire BLOB NOT NULL,
            first TEXT NOT NULL, last TEXT NOT NULL, PRIMARY KEY (stream, digest),
            FOREIGN KEY (stream) REFERENCES streams(id)
        )""")
        row = con.execute(
            'SELECT tenant,cursor,epoch,first,key,high,created,digest FROM streams WHERE id=?',
            (stream,),
        ).fetchone()
        pins = (tenant, str(cursor), str(epoch), str(first), public_key)
        if row is None:
            if batch[14] != bytes(32) or batch[5] < first:
                raise Invalid("invalid genesis or sequence floor")
            con.execute(
                'INSERT INTO streams VALUES (?,?,?,?,?,?,?,?,?)',
                (stream, *pins, str(batch[7]), str(batch[3]), batch[17]),
            )
        else:
            if row[:5] != pins:
                raise Invalid("stream pin mismatch")
            saved = con.execute(
                'SELECT wire,first,last FROM receipts WHERE stream=? AND digest=?',
                (stream, row[7]),
            ).fetchone()
            if saved is None:
                raise Invalid("inconsistent journal")
            prior = decode_batch(saved[0])
            if (prior[17] != row[7]
                or str(prior[7]) != row[5] or str(prior[3]) != row[6]
                or str(prior[5]) != saved[1] or str(prior[6]) != saved[2]):
                raise Invalid("inconsistent journal")
            if batch[17] == row[7]:
                if saved[0] != wire:
                    raise Invalid("digest collision or inconsistent journal")
                con.execute('COMMIT')
                return
            if (batch[14] != row[7] or batch[5] <= int(row[5])
                or batch[7] <= int(row[5]) or batch[3] < int(row[6])):
                raise Invalid("replay, fork, or nonmonotonic scan")
            con.execute(
                'UPDATE streams SET high=?, created=?, digest=? WHERE id=?',
                (str(batch[7]), str(batch[3]), batch[17], stream),
            )
        con.execute(
            'INSERT INTO receipts VALUES (?,?,?,?,?)',
            (stream, batch[17], wire, str(batch[5]), str(batch[6])),
        )
        con.execute('COMMIT')
    finally:
        con.close()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--database', required=True)
    p.add_argument('--stream-id', required=True)
    p.add_argument('--tenant', required=True)
    p.add_argument('--cursor', required=True, type=int)
    p.add_argument('--policy-epoch', required=True, type=int)
    p.add_argument('--first-sequence', required=True, type=int)
    p.add_argument('--public-key', required=True, type=Path)
    p.add_argument('--verifier', required=True, type=Path)
    p.add_argument('wire', type=Path)
    args = p.parse_args()
    try:
        validate_pins(
            args.database, args.stream_id, args.tenant, args.cursor,
            args.policy_epoch, args.first_sequence,
        )
        with args.wire.open('rb') as f:
            wire = f.read(MAX_WIRE + 1)
        with args.public_key.open('rb') as f:
            public_key = f.read(1953)
        batch = verify_wire(
            wire, public_key, args.verifier.resolve(), args.tenant,
            args.cursor, args.policy_epoch,
        )
        collect(
            args.database, args.stream_id, args.tenant, args.cursor,
            args.policy_epoch, args.first_sequence, public_key, wire, batch,
        )
        print(json.dumps({
            'first_sequence': batch[5], 'last_sequence': batch[6],
            'batch_digest': batch[17].hex(),
        }), flush=True)
    except (Invalid, OSError, sqlite3.Error) as exc:
        print(f'collector: {exc}', file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
