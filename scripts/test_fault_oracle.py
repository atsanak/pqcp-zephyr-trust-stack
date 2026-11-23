#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for fault_oracle: every class, plus a reject-everything control."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fault_oracle as fo  # noqa: E402

GOOD, REJ1, REJ2 = "aa" * 32, "bb" * 32, "cc" * 32
GOLDEN_ROWS = {
    "KEM_VALID": (0, GOOD), "KEM_CORRUPT1": (0, REJ1),
    "KEM_CORRUPT2": (0, REJ2), "DSA_VALID": (0, ""),
    "DSA_BADSIG1": (-3, ""), "DSA_BADSIG2": (-3, ""), "DSA_BADMSG": (-3, ""),
}


def render(rows=None, done=True):
    rows = {**GOLDEN_ROWS, **(rows or {})}
    text = "".join(f"PQCP_FAULT_OBS name={n} rc={rc} out={out}\n"
                   for n, (rc, out) in rows.items())
    return text + ("PQCP_FAULT_DONE\n" if done else "")


GOLDEN = fo.parse(render())[0]


class Oracle(unittest.TestCase):
    def test_golden_is_valid_and_no_effect(self):
        self.assertEqual(fo.validate_golden(GOLDEN), [])
        self.assertEqual(fo.classify(GOLDEN, render()), "NO_EFFECT")

    def test_fo_bypass_when_corrupt_ciphertext_yields_the_genuine_key(self):
        text = render({"KEM_CORRUPT1": (0, GOOD)})
        self.assertEqual(fo.classify(GOLDEN, text), "KEM_FO_BYPASS")

    def test_a_different_wrong_key_is_corruption_not_bypass(self):
        text = render({"KEM_CORRUPT1": (0, "dd" * 32)})
        self.assertEqual(fo.classify(GOLDEN, text), "CORRUPT")

    def test_signature_bypass_for_each_tamper_scenario(self):
        for scenario in fo.DSA_BAD:
            text = render({scenario: (0, "")})
            self.assertEqual(fo.classify(GOLDEN, text), "SIG_VERIFY_BYPASS")

    def test_valid_input_rejected_is_fail_safe(self):
        self.assertEqual(
            fo.classify(GOLDEN, render({"DSA_VALID": (-3, "")})), "FAIL_SAFE")
        self.assertEqual(
            fo.classify(GOLDEN, render({"KEM_VALID": (-1, GOOD)})),
            "FAIL_SAFE")

    def test_exploitable_outranks_fail_safe(self):
        text = render({"DSA_VALID": (-3, ""), "DSA_BADSIG1": (0, "")})
        self.assertEqual(fo.classify(GOLDEN, text), "SIG_VERIFY_BYPASS")

    def test_missing_done_is_crash_or_timeout(self):
        self.assertEqual(fo.classify(GOLDEN, render(done=False)), "CRASH")
        self.assertEqual(
            fo.classify(GOLDEN, render(done=False), timed_out=True),
            "TIMEOUT")

    def test_boot_self_test_detection_outranks_everything(self):
        text = "PQCP_KAT_BOOT_VERIFY FAIL rc=-5\n" + render(done=False)
        self.assertEqual(fo.classify(GOLDEN, text), "DETECTED_BOOT")
        both = "PQCP_KAT_BOOT_VERIFY FAIL rc=-5\n" + render(
            {"DSA_BADSIG1": (0, "")})
        self.assertEqual(fo.classify(GOLDEN, both), "DETECTED_BOOT")
        self.assertNotIn("DETECTED_BOOT", fo.EXPLOITABLE)

    def test_runtime_detection_is_not_exploitable_and_outranks_fail_safe(self):
        text = render({"KEM_CORRUPT1": (-6, "00" * 32)})
        self.assertEqual(fo.classify(GOLDEN, text), "DETECTED_RUNTIME")
        text = render({"DSA_BADSIG1": (-7, ""), "DSA_VALID": (-7, "")})
        self.assertEqual(fo.classify(GOLDEN, text), "DETECTED_RUNTIME")
        self.assertNotIn("DETECTED_RUNTIME", fo.EXPLOITABLE)

    def test_exploitable_outranks_runtime_detection(self):
        # One scenario bypassed while another was detected: still exploitable.
        text = render({"KEM_CORRUPT1": (0, GOOD), "DSA_BADSIG2": (-7, "")})
        self.assertEqual(fo.classify(GOLDEN, text), "KEM_FO_BYPASS")

    def test_harness_errors_are_never_no_effect(self):
        text = render() + "PQCP_FAULT_HARNESS_ERROR cannot write\n"
        self.assertEqual(fo.classify(GOLDEN, text), "HARNESS_ERROR")
        self.assertNotIn("HARNESS_ERROR", fo.EXPLOITABLE)

    def test_missing_scenario_is_corrupt(self):
        text = render().replace("DSA_BADMSG", "DSA_X")
        self.assertEqual(fo.classify(GOLDEN, text), "CORRUPT")

    def test_bad_golden_is_reported(self):
        bad = fo.parse(render({"DSA_BADSIG1": (0, "")}))[0]
        self.assertTrue(fo.validate_golden(bad))
        self.assertTrue(fo.validate_golden({}))

    def test_control_not_everything_is_exploitable(self):
        # A classifier that flags every deviation as exploitable would fail
        # these two: benign deviations must stay non-exploitable.
        for text in (render({"KEM_CORRUPT2": (0, "ee" * 32)}),
                     render({"DSA_VALID": (-9, "")})):
            self.assertNotIn(fo.classify(GOLDEN, text), fo.EXPLOITABLE)


if __name__ == "__main__":
    unittest.main()
