#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Exercise the host collector with real firmware-produced signed CBOR."""
import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import sovereign_audit_collect as collector

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / 'scripts/testdata/sovereign_audit_collect'

# The subprocess exits after the real SQLite update, before inserting a receipt.
CRASH_INJECTION = '''
import os, runpy, sqlite3, sys
original_connect = sqlite3.connect
class CrashConnection(sqlite3.Connection):
    def execute(self, sql, *args):
        result = super().execute(sql, *args)
        if sql.startswith("UPDATE streams SET"):
            os._exit(73)
        return result
def connect(*args, **kwargs):
    return original_connect(*args, factory=CrashConnection, **kwargs)
sqlite3.connect = connect
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
'''


class FirmwareConformance(unittest.TestCase):
    def test_signed_chain_and_restarts(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            build = tmp / 'build'
            subprocess.run(
                ['cmake', '-S', str(ROOT / 'tools/evidence_verifier'), '-B', str(build)],
                check=True, stdout=subprocess.DEVNULL,
            )
            subprocess.run(
                ['cmake', '--build', str(build), '--target', 'pqcp-sovereign-signature-verify'],
                check=True, stdout=subprocess.DEVNULL,
            )
            db = tmp / 'journal.db'
            base = [
                sys.executable, str(ROOT / 'scripts/sovereign_audit_collect.py'),
                '--database', str(db), '--stream-id', 'demo', '--tenant', 'tenant-a',
                '--cursor', '1', '--policy-epoch', '7', '--first-sequence', '1',
                '--public-key', str(FIXTURES / 'public-key.bin'),
                '--verifier', str(build / 'pqcp-sovereign-signature-verify'),
            ]

            def run(path, args=base):
                return subprocess.run(args + [str(path)], capture_output=True, text=True)

            batches = [FIXTURES / f'batch-{i}.cbor' for i in range(1, 4)]
            first = run(batches[0])
            self.assertEqual(first.returncode, 0, first.stderr)
            retry = run(batches[0])
            self.assertEqual(retry.returncode, 0, retry.stderr)
            self.assertEqual(json.loads(first.stdout), json.loads(retry.stdout))
            with sqlite3.connect(db) as con:
                before = con.execute('SELECT high FROM streams').fetchone()

            crash = subprocess.run(
                [sys.executable, '-c', CRASH_INJECTION, *base[1:], str(batches[1])],
                capture_output=True, text=True,
            )
            self.assertEqual(crash.returncode, 73, crash.stderr)
            self.assertEqual(crash.stdout, '')
            with sqlite3.connect(db) as con:
                self.assertEqual(con.execute('SELECT high FROM streams').fetchone(), before)
                self.assertEqual(con.execute('SELECT count(*) FROM receipts').fetchone()[0], 1)

            second = run(batches[1])
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertNotEqual(run(batches[0]).returncode, 0)

            # Damage a previously accepted projection without changing its stored
            # receipt metadata. A subsequent intake must stop at the damaged head.
            head_wire = batches[1].read_bytes()
            damaged_head = head_wire.replace(b'redacted', b'sedacted', 1)
            self.assertNotEqual(damaged_head, head_wire)
            with sqlite3.connect(db) as con:
                con.execute('UPDATE receipts SET wire=? WHERE wire=?', (damaged_head, head_wire))
            stopped = run(batches[2])
            self.assertNotEqual(stopped.returncode, 0)
            self.assertIn('batch digest mismatch', stopped.stderr)
            self.assertEqual(stopped.stdout, '')
            with sqlite3.connect(db) as con:
                con.execute('UPDATE receipts SET wire=? WHERE wire=?', (head_wire, damaged_head))

            tampered = tmp / 'tampered.cbor'
            altered = bytearray(batches[2].read_bytes())
            altered[-1] ^= 1
            tampered.write_bytes(altered)
            self.assertNotEqual(run(tampered).returncode, 0)

            # Change a printable source field while retaining the same schema and pins.
            body = bytearray(batches[2].read_bytes())
            source_offset = body.index(b'redacted')
            body[source_offset] = ord('s')
            tampered.write_bytes(body)
            changed = run(tampered)
            self.assertNotEqual(changed.returncode, 0)
            self.assertIn('batch digest mismatch', changed.stderr)

            original = batches[2].read_bytes()
            reader = collector.Reader(original)
            reader.pos = 1
            body_end = None
            for index in range(1, 20):
                reader.read()
                reader.read()
                if index == 16:
                    body_end = reader.pos
            digest = hashlib.sha256(collector.DOMAIN + b'\xb0' + original[1:body_end]).digest()
            changed_digest = bytearray(original)
            digest_offset = original.index(digest, body_end)
            changed_digest[digest_offset] ^= 1
            tampered.write_bytes(changed_digest)
            self.assertNotEqual(run(tampered).returncode, 0)

            wrong_key = tmp / 'wrong-key.bin'
            public_key = bytearray((FIXTURES / 'public-key.bin').read_bytes())
            public_key[0] ^= 1
            wrong_key.write_bytes(public_key)
            wrong_key_args = base.copy()
            wrong_key_args[wrong_key_args.index(str(FIXTURES / 'public-key.bin'))] = str(wrong_key)
            self.assertNotEqual(run(batches[2], wrong_key_args).returncode, 0)
            wrong = base.copy()
            wrong[wrong.index('tenant-a')] = 'tenant-b'
            self.assertNotEqual(run(batches[2], wrong).returncode, 0)
            third = run(batches[2])
            self.assertEqual(third.returncode, 0, third.stderr)
            self.assertEqual(run(batches[2]).stdout, third.stdout)
            with sqlite3.connect(db) as con:
                self.assertEqual(con.execute('SELECT count(*) FROM receipts').fetchone()[0], 3)


if __name__ == '__main__':
    unittest.main()
