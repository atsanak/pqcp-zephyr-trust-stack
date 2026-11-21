#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Tests for the fault gate's marker parsing and verdicts."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_fault_gate as g  # noqa: E402

BASE = {"min_sites": 300, "boot_exploitable_min": 1,
        "boot_negative_exploitable_max": 0}


def marker(variant, kem=0, sig=0, det=100, sites=388, ok=6, controls=6):
    return (f"PQCP_FAULT_CAMPAIGN variant={variant} sites={sites} "
            f"kem_fo_bypass={kem} sig_verify_bypass={sig} "
            f"detected_boot={det} fail_safe=1 corrupt=2 no_effect=100 "
            f"crash=100 timeout=2 controls_ok={ok}/{controls}")


def results(boot, neg):
    return {"boot": g.parse_marker(boot), "boot-negative": g.parse_marker(neg)}


class Gate(unittest.TestCase):
    def test_parse(self):
        r = g.parse_marker(marker("boot", kem=3, sig=5))
        self.assertEqual((r["kem"], r["sig"], r["exploitable"]), (3, 5, 8))
        self.assertIsNone(g.parse_marker("nothing here"))

    def test_pass_when_boot_has_sites_and_negative_has_none(self):
        problems, line = g.judge(results(
            marker("boot", kem=3, sig=5, det=111),
            marker("boot-negative", det=121)), BASE)
        self.assertEqual(problems, [])
        self.assertIn("PQCP_FAULT_GATE PASS", line)
        self.assertIn("exploitable_boot=8 exploitable_boot_negative=0", line)

    def test_fail_if_a_site_survives_negative_vectors(self):
        problems, line = g.judge(results(
            marker("boot", kem=3, sig=5, det=111),
            marker("boot-negative", sig=1, det=121)), BASE)
        self.assertTrue(problems)
        self.assertIn("FAIL", line)

    def test_fail_if_campaign_is_insensitive(self):
        problems, _ = g.judge(results(
            marker("boot", det=111), marker("boot-negative", det=121)), BASE)
        self.assertTrue(any("not sensitive" in p for p in problems))

    def test_fail_on_uncalibrated_or_small_campaigns(self):
        for kw in ({"ok": 5}, {"controls": 0, "ok": 0}, {"sites": 10}):
            r = results(marker("boot", kem=1, det=1, **kw),
                        marker("boot-negative", det=9))
            problems, line = g.judge(r, BASE)
            self.assertTrue(problems, kw)
            self.assertIn("FAIL", line)

    def test_fail_if_negative_vectors_add_no_detection(self):
        problems, _ = g.judge(results(
            marker("boot", kem=1, det=50),
            marker("boot-negative", det=50)), BASE)
        self.assertTrue(problems)


if __name__ == "__main__":
    unittest.main()
