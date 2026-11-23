#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Adversarial tests for the fault-timing gate's verdicts."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_fault_timing_gate as g  # noqa: E402

BASE = {"min_sites": 300, "base_postboot_min": 1, "base_transient_min": 1,
        "hardened_postboot_max": 0, "hardened_transient_max": 0}


def marker(variant, timing, sites=900, kem=0, sig=0, harness=0, ok=6,
           controls=6, esites=0):
    return (f"PQCP_FAULT_CAMPAIGN variant={variant} sites={sites} "
            f"kem_fo_bypass={kem} sig_verify_bypass={sig} detected_boot=0 "
            f"detected_runtime=5 fail_safe=1 corrupt=2 no_effect=100 "
            f"crash=100 timeout=2 harness_error={harness} "
            f"controls_ok={ok}/{controls} timing={timing} "
            f"exploitable_sites={esites}")


def good():
    return {
        ("boot-negative", "post-boot"):
            g.parse_marker(marker("boot-negative", "post-boot", kem=3, sig=6,
                                  esites=9)),
        ("hardened", "post-boot"): g.parse_marker(marker("hardened", "post-boot")),
        ("boot-negative", "transient"):
            g.parse_marker(marker("boot-negative", "transient", kem=5,
                                  sig=17, esites=9)),
        ("hardened", "transient"): g.parse_marker(marker("hardened", "transient")),
    }


class Gate(unittest.TestCase):
    def test_pass(self):
        problems, line = g.judge(good(), BASE)
        self.assertEqual(problems, [])
        self.assertIn("PQCP_FAULT_TIMING_GATE PASS", line)
        self.assertIn("base_postboot=9 base_transient=9 hardened_postboot=0 "
                      "hardened_transient=0", line)

    def test_parse_requires_the_whole_marker(self):
        self.assertIsNone(g.parse_marker("PQCP_FAULT_CAMPAIGN variant=x"))
        r = g.parse_marker(marker("hardened", "transient", esites=2))
        self.assertEqual((r["timing"], r["exploitable_sites"]), ("transient", 2))

    def test_fails_if_a_site_survives_on_the_hardened_image(self):
        for timing in ("post-boot", "transient"):
            r = good()
            r[("hardened", timing)] = g.parse_marker(
                marker("hardened", timing, kem=1, esites=1))
            problems, line = g.judge(r, BASE)
            self.assertTrue(problems, timing)
            self.assertIn("FAIL", line)

    def test_fails_if_the_campaign_is_insensitive(self):
        for timing in ("post-boot", "transient"):
            r = good()
            r[("boot-negative", timing)] = g.parse_marker(
                marker("boot-negative", timing, esites=0))
            problems, _ = g.judge(r, BASE)
            self.assertTrue(any("not sensitive" in p for p in problems))

    def test_fails_on_calibration_or_harness_or_size_problems(self):
        for kw in ({"ok": 5}, {"controls": 0, "ok": 0}, {"harness": 1},
                   {"sites": 50}):
            r = good()
            r[("hardened", "transient")] = g.parse_marker(
                marker("hardened", "transient", **kw))
            problems, line = g.judge(r, BASE)
            self.assertTrue(problems, kw)
            self.assertIn("FAIL", line)

    def test_fails_on_a_missing_or_misattributed_cell(self):
        r = good()
        del r[("hardened", "transient")]
        self.assertTrue(g.judge(r, BASE)[0])
        r = good()
        r[("hardened", "transient")] = g.parse_marker(
            marker("hardened", "post-boot"))
        self.assertTrue(g.judge(r, BASE)[0])


if __name__ == "__main__":
    unittest.main()
