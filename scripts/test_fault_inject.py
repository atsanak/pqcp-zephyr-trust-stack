#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for fault_inject: byte arithmetic and ELF mapping on synthetic data."""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fault_inject as fi  # noqa: E402


def make_elf32(code: bytes, vaddr: int = 0x100000, off: int = 0x1000) -> bytes:
    image = bytearray(off + len(code))
    image[:4] = b"\x7fELF"
    image[4] = 1
    struct.pack_into("<I", image, 0x1C, 52)
    struct.pack_into("<HH", image, 0x2A, 32, 1)
    struct.pack_into("<IIIII", image, 52, 1, off, vaddr, vaddr, len(code))
    image[off:] = code
    return bytes(image)


class Jcc(unittest.TestCase):
    def test_short_jcc_inverts_low_bit(self):
        self.assertEqual(fi.invert_condition(bytes([0x74, 0x05])),
                         bytes([0x75, 0x05]))   # je -> jne
        self.assertEqual(fi.invert_condition(bytes([0x7F, 0x00])),
                         bytes([0x7E, 0x00]))   # jg -> jle

    def test_near_jcc_setcc_cmov_and_prefixes(self):
        self.assertEqual(fi.invert_condition(bytes([0x0F, 0x84, 1, 0, 0, 0])),
                         bytes([0x0F, 0x85, 1, 0, 0, 0]))
        self.assertEqual(fi.invert_condition(bytes([0x0F, 0x94, 0xC0])),
                         bytes([0x0F, 0x95, 0xC0]))        # sete -> setne
        self.assertEqual(fi.invert_condition(bytes([0x48, 0x0F, 0x44, 0xC1])),
                         bytes([0x48, 0x0F, 0x45, 0xC1]))  # cmove -> cmovne

    def test_non_branches_are_left_alone(self):
        for raw in (bytes([0x90]), bytes([0xC3]), bytes([0x89, 0xE5]),
                    bytes([0xE9, 0, 0, 0, 0]), bytes([0xEB, 0x02])):
            self.assertIsNone(fi.invert_condition(raw), raw)

    def test_inversion_is_an_involution(self):
        raw = bytes([0x0F, 0x8C, 9, 0, 0, 0])
        self.assertEqual(fi.invert_condition(fi.invert_condition(raw)), raw)


class Sites(unittest.TestCase):
    def test_faults_cover_skip_everywhere_and_jcc_where_applicable(self):
        insns = [fi.Insn(0x10, bytes([0x55]), "push"),
                 fi.Insn(0x11, bytes([0x74, 0x02]), "je")]
        faults = fi.faults_for("f", insns)
        self.assertEqual([(f.addr, f.model) for f in faults],
                         [(0x10, "SKIP"), (0x11, "SKIP"), (0x11, "JCC_INV")])
        self.assertEqual(faults[1].new, bytes([0x90, 0x90]))
        self.assertEqual(faults[0].ident, "f+10:SKIP")
        based = fi.faults_for("f", insns, base=0x8)
        self.assertEqual(based[0].ident, "f+8:SKIP")     # offset, not address


class Patching(unittest.TestCase):
    CODE = bytes([0x55, 0x74, 0x02, 0xC3])

    def test_patch_lands_at_the_mapped_offset(self):
        image = make_elf32(self.CODE)
        fault = fi.Fault("f", 0x100001, "JCC_INV", bytes([0x74, 0x02]),
                         bytes([0x75, 0x02]), "je")
        patched = fi.apply_fault(image, fault)
        self.assertEqual(patched[0x1001:0x1003], bytes([0x75, 0x02]))
        self.assertEqual(patched[:0x1001], image[:0x1001])
        self.assertEqual(patched[0x1003:], image[0x1003:])

    def test_mismatched_expected_bytes_are_refused(self):
        image = make_elf32(self.CODE)
        wrong = fi.Fault("f", 0x100001, "SKIP", bytes([0x75, 0x02]),
                         bytes([0x90, 0x90]), "x")
        with self.assertRaises(ValueError):
            fi.apply_fault(image, wrong)

    def test_unmapped_address_is_refused(self):
        image = make_elf32(self.CODE)
        far = fi.Fault("f", 0x200000, "SKIP", b"\x00", b"\x90", "x")
        with self.assertRaises(ValueError):
            fi.apply_fault(image, far)

    def test_identity_patch_is_a_noop(self):
        image = make_elf32(self.CODE)
        same = fi.Fault("f", 0x100000, "SKIP", bytes([0x55]),
                        bytes([0x55]), "push")
        self.assertEqual(fi.apply_fault(image, same), image)


if __name__ == "__main__":
    unittest.main()
