import unittest
from unittest import TestCase

import gflags
from verify_perf import VerifyPerf


class TestVerify(TestCase):
    """Tests misc.py verifies function."""

    def setUp(self) -> None:
        self.verifier = VerifyPerf()
        gflags.FLAGS.verifies_perf = True

    def test_verify__with_zero_threshold(self):
        """Test passes when expected rate, actual rate and threshold are all zero."""
        self.verifier.verify(metric="failure rate", is_update=False, actual=0.0, expected=0.0)
        self.assertTrue(self.verifier.is_success())

    def test_verify__with_zero_threshold_non_zero_actual_result(self):
        """Test passes when expected rate is zero but actual rate is not."""
        self.verifier.verify(metric="failure rate", is_update=True, actual=5.0, expected=0.0)
        self.assertFalse(self.verifier.is_success())

    def test_verify__fails_when_positive_actual_rate_larger_than_positive_expected_rate(self):
        """Test fails when positive delta between actual rate and expected rate exceeds positive threshold."""
        self.verifier.verify(metric="latency", is_update=False, actual=200, expected=100)
        self.assertFalse(self.verifier.is_success())

    def test_verify__fails_when_negative_actual_rate_and_positive_expected_rate(self):
        """Test fails when negative delta between actual rate and expected rate exceeds negative threshold."""
        self.verifier.verify(metric="latency", is_update=True, actual=-150, expected=100)
        self.assertTrue(self.verifier.is_success())

    def test_verify__fails_when_negative_actual_rate_greater_than_negative_expected_rate(self):
        """Test fails when delta between actual rate and expected rate exceeds threshold."""
        self.verifier.verify(metric="latency", is_update=True, actual=-50, expected=-100)
        self.assertTrue(self.verifier.is_success())


if __name__ == "__main__":
    unittest.main()
