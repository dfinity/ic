"""Tests for the proposal payload parsing in ci/scripts/repro-check."""

import importlib.machinery
import importlib.util
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_loader(
    "repro_check", importlib.machinery.SourceFileLoader("repro_check", str(Path(__file__).parent / "repro-check"))
)
repro_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(repro_check)

SHA = "a" * 64


class ParseProposalPayloadTest(unittest.TestCase):
    def test_hostos_payload_without_launch_measurements(self):
        payload = {
            "hostos_version_to_elect": "7360f8f35bda2e4754bb7f2258d6852feec268e8",
            "hostos_versions_to_unelect": ["deadbeef"],
            "release_package_sha256_hex": SHA,
            "release_package_urls": ["https://example.com/update-img.tar.zst"],
        }

        git_hash, guest_os_hash, guest_os_measurements, host_os_hash = repro_check.parse_proposal_payload(payload, 1)

        self.assertEqual(git_hash, "7360f8f35bda2e4754bb7f2258d6852feec268e8")
        self.assertIsNone(guest_os_hash)
        self.assertIsNone(guest_os_measurements)
        self.assertEqual(host_os_hash, SHA)

    def test_guestos_payload_converts_measurements_to_bytes(self):
        payload = {
            "replica_version_to_elect": "7360f8f35bda2e4754bb7f2258d6852feec268e8",
            "replica_versions_to_unelect": [],
            "release_package_sha256_hex": SHA,
            "release_package_urls": ["https://example.com/update-img.tar.zst"],
            "guest_launch_measurements": {"guest_launch_measurements": [{"measurement": "0a0b"}]},
        }

        git_hash, guest_os_hash, guest_os_measurements, host_os_hash = repro_check.parse_proposal_payload(payload, 1)

        self.assertEqual(git_hash, "7360f8f35bda2e4754bb7f2258d6852feec268e8")
        self.assertEqual(guest_os_hash, SHA)
        self.assertEqual(guest_os_measurements, {"guest_launch_measurements": [{"measurement": [10, 11]}]})
        self.assertIsNone(host_os_hash)

    def test_payload_without_elected_version(self):
        with self.assertRaises(repro_check.VerificationError):
            repro_check.parse_proposal_payload({"release_package_sha256_hex": SHA}, 1)


if __name__ == "__main__":
    unittest.main()
