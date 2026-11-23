#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import shutil
import unittest

import ct_latency_models as lm


def pair(hi, lo):
    return (hi << 8) | lo


class CmemuModel(unittest.TestCase):
    def test_umull_zero_operand_is_fastest(self):
        self.assertEqual(lm.cmemu_class(3, 0, 0x9D7DC000), pair(2, 1))
        self.assertEqual(lm.cmemu_class(3, 5, 0), pair(2, 1))

    def test_umull_small_times_two_half_constant_is_slower(self):
        # The ML-KEM compress_d10 shape: u < 65536 times 0x9D7DC000.
        self.assertEqual(lm.cmemu_class(3, 1234, 0x9D7DC000), pair(3, 2))
        self.assertNotEqual(lm.cmemu_class(3, 0, 0x9D7DC000),
                            lm.cmemu_class(3, 1234, 0x9D7DC000))

    def test_documented_model_cannot_see_that_difference(self):
        self.assertEqual(lm.documented_class(3, 0, 0x9D7DC000),
                         lm.documented_class(3, 1234, 0x9D7DC000))

    def test_all_halves_nonzero_is_slowest(self):
        self.assertEqual(lm.cmemu_class(3, 0x10001, 0x10001), pair(4, 3))
        self.assertEqual(lm.cmemu_class(5, 0x10001, 0x10001), pair(6, 5))

    def test_smull_sign_matters(self):
        self.assertNotEqual(lm.cmemu_class(4, 0x10000, 0x10000),
                            lm.cmemu_class(4, 0xFFFF0000, 0x10000))

    def test_division_zero_and_shorter_dividend(self):
        self.assertEqual(lm.cmemu_class(1, 0, 7), 1)
        self.assertEqual(lm.cmemu_class(1, 3, 100), 2)
        self.assertEqual(lm.cmemu_class(1, 1 << 20, 1), 5 + 20 // 4 - 1)

    def test_sdiv_negative_power_of_two_correction(self):
        # 0x40 / -8: magnitude difference 3 is bumped to 4 by the correction.
        self.assertEqual(lm.cmemu_class(2, 0x40, (-8) & lm.MASK),
                         lm.cmemu_class(2, 0x40, 8) + 1)

    def test_c_classifier_matches_the_python_reference(self):
        if shutil.which("cc") is None:
            self.skipTest("no C compiler")
        self.assertEqual(lm.crosscheck(n_random=3000), 0)


if __name__ == "__main__":
    unittest.main()
