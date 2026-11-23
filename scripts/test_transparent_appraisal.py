#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for scripts/run_transparent_appraisal.py.

Pure helper tests (CBOR spans, output parsing, judging, counting, marker
text) plus an integration class that builds the two host tools and proves the
driver both passes on a healthy pair of verifiers and DETECTS a deliberately
broken python verifier (rfc9162_reference.py --inject-fault).
"""

import contextlib
import hashlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_transparent_appraisal as ta  # noqa: E402


def make_checkpoint(tree_size=6, sequence=2, root=None, sig=None) -> bytes:
    """A syntactically valid checkpoint with a correct transcript_digest."""
    log_id = hashlib.sha256(b"pk").digest()
    root = root or hashlib.sha256(b"root").digest()
    fields = (ta.CKPT_PREFIX + (1).to_bytes(4, "big") + log_id
              + tree_size.to_bytes(8, "big") + root
              + (1700000000000).to_bytes(8, "big")
              + sequence.to_bytes(8, "big") + log_id)
    digest = hashlib.sha256(fields).digest()
    sig = sig or bytes(range(256)) * 12 + bytes(237)
    assert len(sig) == 3309
    return (ta.cbor_head(5, 9)
            + ta.cbor_uint(1) + ta.cbor_uint(1)
            + ta.cbor_uint(2) + ta.cbor_uint(tree_size)
            + ta.cbor_uint(3) + ta.cbor_uint(1700000000000)
            + ta.cbor_uint(4) + ta.cbor_uint(sequence)
            + ta.cbor_uint(5) + ta.cbor_bstr(log_id)
            + ta.cbor_uint(6) + ta.cbor_bstr(root)
            + ta.cbor_uint(7) + ta.cbor_bstr(log_id)
            + ta.cbor_uint(8) + ta.cbor_bstr(digest)
            + ta.cbor_uint(9) + ta.cbor_bstr(sig))


def make_receipt(path_nodes=2) -> bytes:
    statement = ta.cbor_head(5, 1) + ta.cbor_uint(1) + ta.cbor_text("x")
    return (ta.cbor_head(5, 5)
            + ta.cbor_uint(1) + ta.cbor_bstr(statement)
            + ta.cbor_uint(2) + ta.cbor_uint(1)
            + ta.cbor_uint(3) + ta.cbor_uint(6)
            + ta.cbor_uint(4) + ta.cbor_array(
                [ta.cbor_bstr(bytes([n]) * 32) for n in range(path_nodes)])
            + ta.cbor_uint(5) + make_checkpoint())


class CborHelpers(unittest.TestCase):
    def test_walk_receipt_spans(self) -> None:
        data = make_receipt()
        parts = ta.receipt_parts(data)
        self.assertEqual(ta.read_uint(parts["leaf_index"]), 1)
        self.assertEqual(ta.read_uint(parts["tree_size"]), 6)
        self.assertEqual(len(parts["path"]), 2)
        self.assertEqual(data[slice(*ta.payload(parts["path"][1]))],
                         bytes([1]) * 32)
        self.assertEqual(parts["ckpt"].end, len(data))

    def test_walk_rejects_truncation_and_unsupported_types(self) -> None:
        with self.assertRaises(ta.CborWalkError):
            ta.cbor_walk(make_receipt()[:-1])
        with self.assertRaises(ta.CborWalkError):
            ta.cbor_walk(b"\x1f")
        with self.assertRaises(ta.CborWalkError):
            ta.cbor_walk(b"\xc0\x00")          # tag

    def test_head_round_trip_shortest_form(self) -> None:
        for n in (0, 23, 24, 255, 256, 65535, 65536, 2 ** 32 - 1, 2 ** 32):
            item = ta.cbor_walk(ta.cbor_uint(n))
            self.assertEqual(item.arg, n)
        self.assertEqual(ta.cbor_uint(23), b"\x17")
        self.assertEqual(ta.cbor_uint(24), b"\x18\x18")

    def test_flip_in_changes_exactly_one_bit(self) -> None:
        data = make_receipt()
        parts = ta.receipt_parts(data)
        flipped = ta.flip_in(data, ta.payload(parts["path"][0]), 3, 5)
        diff = [i for i in range(len(data)) if data[i] != flipped[i]]
        self.assertEqual(len(diff), 1)
        self.assertEqual(data[diff[0]] ^ flipped[diff[0]], 1 << 5)
        with self.assertRaises(ValueError):
            ta.flip_in(data, (0, 2), 5)

    def test_noncanonical_uint_is_longer_but_same_value(self) -> None:
        wide = ta.noncanonical_uint(1)
        self.assertEqual(wide, b"\x18\x01")
        self.assertEqual(ta.cbor_walk(wide).arg, 1)
        self.assertGreater(len(wide), len(ta.cbor_uint(1)))
        with self.assertRaises(ValueError):
            ta.noncanonical_uint(300)

    def test_redigest_is_idempotent_and_tracks_edits(self) -> None:
        ckpt = make_checkpoint()
        self.assertEqual(ta.redigest_checkpoint(ckpt), ckpt)
        item = ta.cbor_walk(ckpt)
        edited = ta.flip_in(ckpt, ta.payload(item.get(6)), 0, 0)
        self.assertNotEqual(edited, ckpt)
        fixed = ta.redigest_checkpoint(edited)
        self.assertNotEqual(fixed, edited)
        self.assertEqual(ta.redigest_checkpoint(fixed), fixed)
        # Signature bytes are untouched by the redigest.
        self.assertEqual(
            fixed[slice(*ta.payload(ta.cbor_walk(fixed).get(9)))],
            ckpt[slice(*ta.payload(item.get(9)))])

    def test_encode_consistency_round_trips_through_the_walker(self) -> None:
        old, new = make_checkpoint(3, 1), make_checkpoint(6, 2)
        blob = ta.encode_consistency(3, 6, [b"\x07" * 32], old, new)
        parts = ta.consistency_parts(blob)
        self.assertEqual(ta.read_uint(parts["old_size"]), 3)
        self.assertEqual(ta.read_uint(parts["new_size"]), 6)
        self.assertEqual(len(parts["nodes"]), 1)
        self.assertEqual(blob[parts["old"].start:parts["old"].end], old)
        self.assertEqual(blob[parts["new"].start:parts["new"].end], new)


class OutputParsing(unittest.TestCase):
    def test_c_pass_and_reject(self) -> None:
        ok = ta.parse_c_output(
            "noise\nPQCP_APPRAISAL_RECEIPT PASS leaf_index=1 tree_size=2\n",
            0, "receipt")
        self.assertTrue(ok.accepted)
        bad = ta.parse_c_output(
            "PQCP_APPRAISAL_RECEIPT REJECT reason=bad_signature\n", 1,
            "receipt")
        self.assertFalse(bad.accepted)
        self.assertEqual(bad.reason, "bad_signature")

    def test_c_consistency_marker_is_not_a_receipt_marker(self) -> None:
        out = ta.parse_c_output(
            "PQCP_APPRAISAL_CONSISTENCY PASS consistency=ok old_size=3 "
            "new_size=6\n", 0, "receipt")
        self.assertTrue(out.error)
        self.assertTrue(ta.parse_c_output(
            "PQCP_APPRAISAL_CONSISTENCY PASS consistency=ok\n", 0,
            "consistency").accepted)

    def test_c_inconsistent_marker_and_exit_code_is_an_error(self) -> None:
        self.assertTrue(ta.parse_c_output(
            "PQCP_APPRAISAL_RECEIPT PASS x=1\n", 1, "receipt").error)
        self.assertTrue(ta.parse_c_output(
            "PQCP_APPRAISAL_RECEIPT REJECT reason=malformed\n", 0,
            "receipt").error)
        self.assertTrue(ta.parse_c_output("", 2, "receipt").error)
        self.assertTrue(ta.parse_c_output(
            "PQCP_APPRAISAL_RECEIPT PASS a\nPQCP_APPRAISAL_RECEIPT PASS b\n",
            0, "receipt").error)

    def test_python_verdict_json(self) -> None:
        ok = ta.parse_py_output(
            '{"accepted": true, "reason": "ok", "signature": "delegated"}',
            0)
        self.assertTrue(ok.accepted)
        self.assertEqual(ok.signature, "delegated")
        rej = ta.parse_py_output(
            '{"accepted": false, "reason": "rollback", '
            '"signature": "delegated"}', 18)
        self.assertEqual((rej.accepted, rej.reason), (False, "rollback"))
        self.assertTrue(ta.parse_py_output("Traceback", 1).error)
        self.assertTrue(ta.parse_py_output(
            '{"accepted": true, "reason": "ok"}', 3).error)


def outcome(accepted, reason="ok", signature="delegated"):
    return ta.Outcome(accepted, "ok" if accepted else reason,
                      0 if accepted else 1, signature)


def make_case(**kw) -> ta.Case:
    defaults = dict(name="n", klass="k", kind="receipt", role="forgery",
                    path=Path("p"), log_pk=Path("k"), transcript=Path("t"))
    defaults.update(kw)
    return ta.Case(**defaults)


class Judging(unittest.TestCase):
    def test_matching_reject_reasons_pass(self) -> None:
        case = make_case(c_expect="rollback", py_expect="rollback",
                         kind="consistency")
        res = ta.judge(case, outcome(False, "rollback"),
                       outcome(False, "rollback"))
        self.assertTrue(res.ok)
        self.assertTrue(res.agree)
        self.assertTrue(res.in_differential)

    def test_disagreement_is_reported(self) -> None:
        case = make_case(c_expect="rollback", py_expect="rollback")
        res = ta.judge(case, outcome(False, "rollback"), outcome(True))
        self.assertFalse(res.ok)
        self.assertFalse(res.agree)
        self.assertTrue(any("DISAGREEMENT" in p for p in res.problems))

    def test_c_accepting_a_forgery_fails_even_if_python_agrees(self) -> None:
        case = make_case(c_expect="bad_signature", py_expect=None)
        res = ta.judge(case, outcome(True), outcome(True))
        self.assertFalse(res.ok)
        self.assertTrue(any("ACCEPTED" in p for p in res.problems))

    def test_reason_mismatch_fails_without_accept_disagreement(self) -> None:
        case = make_case(c_expect="equivocation", py_expect="equivocation")
        res = ta.judge(case, outcome(False, "equivocation"),
                       outcome(False, "consistency_proof_invalid"))
        self.assertTrue(res.agree)
        self.assertFalse(res.ok)

    def test_control_must_be_accepted_by_both(self) -> None:
        case = make_case(role="control")
        self.assertTrue(ta.judge(case, outcome(True), outcome(True)).ok)
        self.assertFalse(ta.judge(case, outcome(False, "malformed"),
                                  outcome(True)).ok)

    def test_signature_only_case_is_outside_the_differential(self) -> None:
        case = make_case(c_expect="bad_signature", py_expect=None,
                         scope="delegated")
        res = ta.judge(case, outcome(False, "bad_signature"), outcome(True))
        self.assertTrue(res.ok)
        self.assertFalse(res.in_differential)
        # Python rejecting is a defect here: it cannot see the signature.
        bad = ta.judge(case, outcome(False, "bad_signature"),
                       outcome(False, "bad_checkpoint"))
        self.assertFalse(bad.ok)

    def test_sweep_reason_must_be_comparable(self) -> None:
        case = make_case(role="sweep", compat=True)
        good = ta.judge(case, outcome(False, "bad_signature"),
                        outcome(False, "bad_checkpoint"))
        self.assertTrue(good.ok)
        wrong = ta.judge(case, outcome(False, "bad_signature"),
                         outcome(False, "rollback"))
        self.assertFalse(wrong.ok)
        accepted = ta.judge(case, outcome(False, "malformed"), outcome(True))
        self.assertFalse(accepted.ok)

    def test_sweep_signature_flip_needs_c_bad_signature_python_accept(
            self) -> None:
        case = make_case(role="sweep", compat=True, sig_region=True)
        self.assertTrue(ta.judge(case, outcome(False, "bad_signature"),
                                 outcome(True)).ok)
        self.assertFalse(ta.judge(case, outcome(False, "malformed"),
                                  outcome(True)).ok)

    def test_tool_errors_are_failures_not_agreement(self) -> None:
        case = make_case(role="control")
        broken = ta.Outcome(False, "", 2, error="no marker")
        res = ta.judge(case, broken, outcome(True))
        self.assertFalse(res.ok)
        self.assertFalse(res.agree)


class Counting(unittest.TestCase):
    def results(self, spec) -> list:
        out = []
        for name, role, ok, in_diff, agree in spec:
            case = make_case(name=name, role=role)
            out.append(ta.CaseResult(case, outcome(True), outcome(True),
                                     [] if ok else ["x"], in_diff, agree))
        return out

    def test_counts_and_marker_on_success(self) -> None:
        results = self.results([
            (ta.CONSISTENCY_CONTROL, "control", True, True, True),
            ("c2", "control", True, True, True),
            ("f1", "forgery", True, True, True),
            ("f2", "sweep", True, False, False),
            ("m1", "matrix", True, True, True),
        ])
        results[0].c.raw = "PQCP_APPRAISAL_CONSISTENCY PASS consistency=ok\n"
        summary = ta.summarize(results)
        self.assertEqual((summary.differential_agree,
                          summary.differential_total), (4, 4))
        self.assertEqual((summary.forgeries_rejected,
                          summary.forgeries_total), (2, 2))
        self.assertEqual((summary.controls_ok, summary.controls_total),
                         (2, 2))
        self.assertEqual(summary.delegated_cases, 1)
        self.assertTrue(summary.passed)
        self.assertEqual(
            ta.format_marker(summary),
            "PQCP_APPRAISAL_RECEIPT PASS consistency=ok "
            "differential_agree=4/4 forgeries_rejected=2/2 controls=2/2")

    def test_failure_blocks_the_pass_marker(self) -> None:
        results = self.results([
            (ta.CONSISTENCY_CONTROL, "control", True, True, True),
            ("f1", "forgery", False, True, False),
        ])
        results[0].c.raw = "consistency=ok"
        summary = ta.summarize(results)
        self.assertFalse(summary.passed)
        self.assertEqual(len(summary.disagreements), 1)
        marker = ta.format_marker(summary)
        self.assertIn("FAIL", marker)
        self.assertNotIn("PASS", marker)

    def test_missing_consistency_control_blocks_pass(self) -> None:
        results = self.results([("c1", "control", True, True, True),
                                ("f1", "forgery", True, True, True)])
        self.assertFalse(ta.summarize(results).consistency_ok)
        self.assertFalse(ta.summarize(results).passed)

    def test_empty_case_lists_cannot_pass(self) -> None:
        self.assertFalse(ta.summarize([]).passed)

    def test_compat_table_covers_every_c_reason_used_by_sweeps(self) -> None:
        for reason in ("malformed", "log_id_mismatch", "bad_signature",
                       "tree_size_mismatch", "inclusion_proof_invalid",
                       "equivocation", "rollback",
                       "consistency_proof_invalid"):
            self.assertIn(reason, ta.COMPAT)


class Integration(unittest.TestCase):
    """Builds the real tools; proves the driver detects a broken verifier."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="pqcp-appraisal-test-")
        cls.out = Path(cls.tmp.name)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cls.rc_clean = ta.main(["--output-dir", str(cls.out),
                                    "--sweep-flips", "6"])
        cls.clean_output = buf.getvalue()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def run_faulty(self, fault: str) -> tuple[int, str]:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = ta.main(["--output-dir", str(self.out), "--sweep-flips",
                          "6", "--python-fault", fault])
        return rc, buf.getvalue()

    def test_healthy_pair_passes_with_exact_marker_shape(self) -> None:
        self.assertEqual(self.rc_clean, 0, self.clean_output)
        marker = [ln for ln in self.clean_output.splitlines()
                  if ln.startswith("PQCP_APPRAISAL_RECEIPT")]
        self.assertEqual(len(marker), 1)
        self.assertRegex(
            marker[0],
            r"^PQCP_APPRAISAL_RECEIPT PASS consistency=ok "
            r"differential_agree=(\d+)/\1 forgeries_rejected=(\d+)/\2 "
            r"controls=(\d+)/\3$")

    def test_broken_python_rollback_check_is_detected(self) -> None:
        rc, out = self.run_faulty("skip-rollback")
        self.assertNotEqual(rc, 0)
        self.assertIn("DISAGREEMENT", out)
        self.assertIn("rollback/identical-checkpoint-replayed", out)
        self.assertIn("PQCP_APPRAISAL_RECEIPT FAIL", out)
        self.assertNotIn("PQCP_APPRAISAL_RECEIPT PASS", out)

    def test_broken_python_root_binding_is_detected(self) -> None:
        rc, out = self.run_faulty("skip-root-binding")
        self.assertNotEqual(rc, 0)
        self.assertIn("DISAGREEMENT: C reject:inclusion_proof_invalid "
                      "vs python accept", out)

    def test_broken_python_leaf_prefix_is_detected_on_good_receipts(
            self) -> None:
        rc, out = self.run_faulty("no-leaf-prefix")
        self.assertNotEqual(rc, 0)
        self.assertIn("DISAGREEMENT: C accept vs python reject", out)

    def test_broken_python_equivocation_check_changes_the_reason(
            self) -> None:
        rc, out = self.run_faulty("skip-equivocation")
        self.assertNotEqual(rc, 0)
        self.assertIn("fork/same-size-different-root", out)


if __name__ == "__main__":
    unittest.main()
