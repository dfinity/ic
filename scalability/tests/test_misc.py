import unittest
from unittest import TestCase

from misc import verify


class TestVerify(TestCase):
    """Tests misc.py verifies function."""

    def test_verify__with_zero_threshold_and_expected_succeeds(self):
        """Test passes when expected rate, actual rate and threshold are all zero."""
        result = verify(metric="failure rate", is_update=False, actual=0.0, expected=0.0, threshold=0.0)
        self.assertEqual(result, 0)

    def test_verify__fails_when_positive_delta_is_larger_than_postive_threshold(self):
        """Test fails when positive delta between actual rate and expected rate exceeds positive threshold."""
        result = verify(metric="latency", is_update=False, actual=200, expected=100, threshold=0.1)
        self.assertEqual(result, 1)

    def test_verify__fails_when_negative_delta_is_smaller_than_negative_threshold(self):
        """Test fails when negative delta between actual rate and expected rate exceeds negative threshold."""
        result = verify(metric="latency", is_update=True, actual=50, expected=100, threshold=-0.01)
        self.assertEqual(result, 1)

    def test_verify__fails_when_negative_delta_and_positive_threshold(self):
        """Test fails when delta between actual rate and expected rate exceeds threshold."""
        result = verify(metric="latency", is_update=True, actual=50, expected=100, threshold=0.01)
        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
