#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ct_static_scan as scan
import ct_trace_analysis as cta
import run_ct_compiler_matrix as matrix
import generate_assurance_ledger as ledger


ARM = """
00001000 <mlk_compress>:
    1000: umullne.w r0, r1, r2, r3
    1004: udiv     r0, r1, r2
    1008: bne.n    1000 <mlk_compress>
    100a: bhs.w    1000 <mlk_compress>
    100c: cbnz     r0, 1000 <mlk_compress>
    100e: itte     ne
    1010: bl       1200 <pqcp_wrapper>
    1014: b.w      1000 <mlk_compress>
00001200 <pqcp_wrapper>:
    1200: sdiv     r0, r1, r2
    1204: bx       lr
00001300 <kernel_helper>:
    1300: udiv     r1, r2, r3
"""

X86 = """
0000000000001010 <PQCP_MLKEM_NATIVE_FOO>:
    1010: idivq    %rcx
    1012: div      %r8
    1014: jmpq     1000
    1016: bnd jmp  1000
    1018: jne      1000
    101a: jrcxz    1000
    101c: loopne   1000
    101e: cmovne   %rax,%rdx
    1020: setnz    %al
0000000000002000 <pqcp_other>:
    2000: ret
"""


class StaticScanTests(unittest.TestCase):
    def test_arm_inventory(self):
        inv = scan.inventory_functions(scan.parse_disassembly(ARM), "cortex-m3")
        self.assertEqual(inv["vlat"], {
            0x1000: ("mlk_compress", "umull"),
            0x1004: ("mlk_compress", "udiv"),
            0x1200: ("pqcp_wrapper", "sdiv"),
        })
        self.assertEqual(inv["branches"], {"mlk_compress": 3, "pqcp_wrapper": 0})
        self.assertEqual(inv["predicated"], {"mlk_compress": 1, "pqcp_wrapper": 0})
        self.assertEqual(scan.project_counts(inv), {"pqcp_wrapper": {"branches": 0, "vlat": 1}})

    def test_x86_inventory(self):
        inv = scan.inventory_functions(scan.parse_disassembly(X86), "x86_64")
        fn = "PQCP_MLKEM_NATIVE_FOO"
        self.assertEqual(inv["vlat"], {0x1010: (fn, "idivq"), 0x1012: (fn, "div")})
        self.assertEqual(inv["branches"], {fn: 3, "pqcp_other": 0})
        self.assertEqual(inv["predicated"], {fn: 2, "pqcp_other": 0})

    def test_cross_validation_requires_address_and_kind(self):
        inv = scan.inventory_functions(scan.parse_disassembly(ARM), "cortex-m3")
        observed = cta.VlatAnalysis(
            regions=3, sites={0x1000: 3, 0x1004: 2, 0x1300: 1},
            fail_sites=[(0x1000, 3, "model"), (0x1300, 1, "model")],
            candidate_sites=[(0x1004, 2)], base_clean=True, kinds_seen={},
        )
        result = scan.cross_validate(inv, observed)
        self.assertEqual(result["executed"], 1)
        self.assertEqual(result["dynamic_only_pcs"], [0x1300])
        self.assertEqual(result["kind_mismatches"], [0x1004])
        self.assertEqual(result["secret_varying"], 3)
        self.assertEqual(result["precision"], 1 / 3)
        self.assertEqual(result["recall"], 1 / 3)
        self.assertTrue(scan.format_xval("cortex-m3", result).endswith("status=FAIL"))

    def test_empty_denominator_is_undefined(self):
        inv = scan.inventory_functions({}, "cortex-m3")
        observed = cta.VlatAnalysis(3, {}, [], [], True, {})
        result = scan.cross_validate(inv, observed)
        self.assertIsNone(result["recall"])
        self.assertIsNone(result["precision"])

    def test_ratchet_rejects_growth_and_new_functions(self):
        baseline = {"pqcp_a": {"branches": 4, "vlat": 1}}
        clean = {"pqcp_a": {"branches": 3, "vlat": 0}}
        self.assertEqual(scan.ratchet(clean, baseline), [])
        self.assertEqual(scan.ratchet({}, baseline), [])
        self.assertEqual(scan.ratchet({
            "pqcp_a": {"branches": 5, "vlat": 2},
            "pqcp_b": {"branches": 0, "vlat": 0},
        }, baseline), [
            "pqcp_a: branches grew from 4 to 5",
            "pqcp_a: vlat grew from 1 to 2",
            "pqcp_b: missing baseline entry",
        ])


class CompilerMatrixTests(unittest.TestCase):
    def test_effective_flags_across_all_mlkem_c_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            build = Path(tmp)
            path = build / "compile_commands.json"
            sources = [
                {"file": f"/repo/ext/mlkem-native/{unit}.c",
                 "command": f"ccache /sdk/x86_64-zephyr-elf-gcc -O2 -Os -flto=auto -c {unit}.c"}
                for unit in ("kem", "sha3")
            ]
            sources.append({"file": "/repo/kernel/a.c", "command": "cc -O0 -c a.c"})
            path.write_text(json.dumps(sources), encoding="utf-8")
            with patch.object(matrix.subprocess, "run") as run:
                run.return_value.stdout = "GCC 12\n"
                actual = matrix.verify_compile_commands(build, matrix.VARIANTS["gcc-Os-lto"])
            self.assertEqual(actual["translation_units"], 2)
            self.assertEqual(actual["opt"], "-Os")
            for suffix in (" -O3", " -fno-lto"):
                path.write_text(json.dumps([sources[0], {
                    **sources[1], "command": sources[1]["command"] + suffix,
                }]), encoding="utf-8")
                with self.assertRaises(matrix.ConfigMismatch):
                    matrix.verify_compile_commands(build, matrix.VARIANTS["gcc-Os-lto"])

    def test_lto_comparison_uses_source_location(self):
        site = {"kind": "umull", "pc": "0x10",
                "source": [{"location": "ext/mlkem-native/project/compress.h:20"}]}
        baseline = {"target": "cortex-m3", "variant": "gcc-Os", "expected_lto": False,
                    "workload_digest": "0x0", "secret_sites": [site],
                    "divergent_channels": []}
        lto = {**baseline, "variant": "gcc-Os-lto", "expected_lto": True,
               "secret_sites": [{**site, "pc": "0x20"}, {
                   **site, "pc": "0x24", "source": [{"location": "src/kem.c:42"}],
               }], "divergent_channels": ["pc"]}
        comparison, = matrix.compare_lto([baseline, lto])
        self.assertEqual(comparison["additional_sites"], ["umull@src/kem.c:42"])
        self.assertEqual(comparison["additional_channels"], ["pc"])


class StudyLedgerTests(unittest.TestCase):
    def test_static_evidence_requires_both_markers_and_no_misses(self):
        static = ("PQCP_CT_STATIC_XVAL target=cortex-m3 static_vlat=1 executed=1 "
                  "dynamic_only=0 kind_mismatches=0 secret_varying=1 precision=1.000 "
                  "recall=1.000 static_branches=111 predicated=7 status=PASS\n")
        ratchet = "PQCP_CT_STATIC_RATCHET target=cortex-m3 functions=12 status=PASS\n"
        self.assertIsNone(ledger._ct_static_result(static + ratchet)[0])
        for body in (static, ratchet, static + static + ratchet,
                     static.replace("dynamic_only=0", "dynamic_only=1") + ratchet,
                     static + ratchet.replace("status=PASS", "status=FAIL")):
            self.assertIsNotNone(ledger._ct_static_result(body)[0])

    def test_compiler_evidence_accounts_for_all_cells_and_effective_flags(self):
        cells = []
        for target in matrix.TARGETS:
            for name, variant in matrix.VARIANTS.items():
                cell = {"target": target, "variant": name, "cc": variant.compiler,
                        "opt": variant.opt, "lto": variant.lto, "instructions": [100],
                        "status": "CLEAN", "recall": 1.0 if target == "cortex-m3" else None}
                if variant.compiler == "clang" and target == "x86_64":
                    cell = {"target": target, "variant": name, "status": "BUILD_FAIL"}
                cells.append(matrix.format_cell(cell))
        summary = ("PQCP_CT_COMPILER_MATRIX cells=16 clean=13 candidate=0 fail=0 "
                   "build_fail=3 config_mismatch=0 digests=1 status=PASS")
        body = "\n".join([*cells, summary])
        self.assertIsNone(ledger._ct_matrix_result(body)[0])
        for invalid in (
            "\n".join([*cells[:-1], summary]),
            "\n".join([*cells[:-1], cells[0], summary]),
            body.replace("opt=-Os", "opt=-Oz", 1),
            body.replace("recall=1.000", "recall=0.990", 1),
            body.replace("build_fail=3", "build_fail=2", 1),
            body.replace("digests=1", "digests=2", 1),
        ):
            self.assertIsNotNone(ledger._ct_matrix_result(invalid)[0])


if __name__ == "__main__":
    unittest.main()
