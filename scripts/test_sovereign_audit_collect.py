#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Parser and transactional collector regression tests."""
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import sovereign_audit_collect as c

class CollectorTests(unittest.TestCase):
    def test_canonical_parser(self):
        for data in (b'\x18\x01', b'\x9f\xff', b'\xa2\x01\x00\x01\x00', b'\xfa\x00\x00\x00\x00', b'\x62\xff\xff'):
            with self.subTest(data=data), self.assertRaises(c.Invalid):
                c.Reader(data).read()
        self.assertEqual(c.Reader(b'\xa2\x01\x01\x02\xf5').read(), {1: 1, 2: True})

    def test_transaction_replay_and_recovery(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / 'journal.db')
            key = b'k' * 1952
            one = {3: 10, 5: 2, 6: 3, 7: 5, 14: bytes(32), 17: b'a' * 32}
            two = {3: 10, 5: 8, 6: 8, 7: 9, 14: b'a' * 32, 17: b'b' * 32}
            def put(batch, wire, **kwargs):
                c.collect(db, 'stream', kwargs.get('tenant', 'tenant'), 1, 7, 1, key, wire, batch)
            def wire(batch):
                def enc(v):
                    if isinstance(v, int):
                        return bytes([v]) if v < 24 else bytes([24, v])
                    if isinstance(v, bytes):
                        return bytes([0x58, len(v)]) + v
                    raise AssertionError(v)
                fields = {k: batch.get(k, 0) for k in range(1, 20)}
                body = b''.join(enc(k) + enc(fields[k]) for k in range(1, 17))
                fields[17] = batch[17] = hashlib.sha256(c.DOMAIN + b'\xb0' + body).digest()
                return b'\xb3' + b''.join(enc(k) + enc(v) for k, v in fields.items())
            one_wire = wire(one)
            two[14] = one[17]
            two_wire = wire(two)
            put(one, one_wire)
            put(one, one_wire)  # a lost acknowledgement is safe to retry
            with self.assertRaises(c.Invalid): put(one, b'changed')
            with self.assertRaises(c.Invalid): put(two, two_wire, tenant='wrong')
            with self.assertRaises(c.Invalid): put(dict(two, **{}) | {5: 5}, b'two')
            with self.assertRaises(c.Invalid): put(two | {14: bytes(32)}, b'two')
            # Simulate interruption after the high-water update but before receipt insertion.
            original = sqlite3.connect
            class Connection(sqlite3.Connection):
                def execute(self, sql, *args):
                    if sql.startswith('INSERT INTO receipts'):
                        raise sqlite3.OperationalError('simulated crash')
                    return super().execute(sql, *args)
            with patch.object(c.sqlite3, 'connect', side_effect=lambda *a, **kw: original(*a, factory=Connection, **kw)):
                with self.assertRaises(sqlite3.OperationalError): put(two, two_wire)
            with original(db) as con:
                self.assertEqual(con.execute('SELECT high FROM streams').fetchone()[0], '5')
                self.assertEqual(con.execute('SELECT count(*) FROM receipts').fetchone()[0], 1)
            put(two, two_wire)
            put(two, two_wire)
            with self.assertRaises(c.Invalid): put(one, one_wire)
            with original(db) as con:
                self.assertEqual(con.execute('SELECT high FROM streams').fetchone()[0], '9')
                self.assertEqual(con.execute('SELECT count(*) FROM receipts').fetchone()[0], 2)

if __name__ == '__main__':
    unittest.main()
