"""Tests for the proposal handling in ci/scripts/repro-check."""

import hashlib
import importlib.machinery
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_spec = importlib.util.spec_from_loader(
    "repro_check", importlib.machinery.SourceFileLoader("repro_check", str(Path(__file__).parent / "repro-check"))
)
repro_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(repro_check)

GIT_HASH = "7360f8f35bda2e4754bb7f2258d6852feec268e8"
SHA = "a" * 64
# Launch measurements as the dashboard API returns them, i.e. with hex measurements.
MEASUREMENTS = {"guest_launch_measurements": [{"measurement": "0a0b", "metadata": {}}]}


def sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def to_byte_measurements(measurements: dict) -> dict:
    """The byte format used both in the proposal and in the published launch-measurements.json."""
    return {
        "guest_launch_measurements": [
            {**m, "measurement": list(bytes.fromhex(m["measurement"]))}
            for m in measurements["guest_launch_measurements"]
        ]
    }


def cdn_url(os_type: str, subdir: str, filename: str) -> str:
    return f"https://download.dfinity.systems/ic/{GIT_HASH}/{os_type}/{subdir}/{filename}"


GUEST_OS_IMG = cdn_url("guest-os", "update-img", "update-img.tar.zst")
HOST_OS_IMG = cdn_url("host-os", "update-img", "update-img.tar.zst")
SETUP_OS_IMG = cdn_url("setup-os", "disk-img", "disk-img.tar.zst")
RECOVERY_IMG = cdn_url("guest-os", "update-img-recovery", "update-img.tar.zst")
MEASUREMENTS_URL = cdn_url("guest-os", "update-img", "launch-measurements.json")


def fake_cdn() -> dict[str, bytes]:
    """Contents served for every URL a full `repro-check -p <id>` run downloads."""
    cdn = {}
    for os_type, subdir, artifact in [
        ("guest-os", "update-img", "update-img.tar.zst"),
        ("host-os", "update-img", "update-img.tar.zst"),
        ("setup-os", "disk-img", "disk-img.tar.zst"),
        ("guest-os", "update-img-recovery", "update-img.tar.zst"),
    ]:
        content = f"{os_type}/{subdir} image".encode()
        cdn[cdn_url(os_type, subdir, artifact)] = content
        cdn[cdn_url(os_type, subdir, "SHA256SUMS")] = f"{sha256_hex(content)}  {artifact}\n".encode()
    cdn[MEASUREMENTS_URL] = json.dumps(to_byte_measurements(MEASUREMENTS)).encode()
    return cdn


class FakeResponse:
    """Stands in for the urlopen() response carrying the proposal JSON."""

    def __init__(self, content: bytes):
        self.status = 200
        self.headers = {"Content-Length": str(len(content))}
        self._content = content

    def read(self, *args) -> bytes:
        content, self._content = self._content, b""
        return content

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args) -> None:
        return None


class ParseProposalPayloadTest(unittest.TestCase):
    def test_hostos_payload_without_launch_measurements(self):
        payload = {
            "hostos_version_to_elect": GIT_HASH,
            "hostos_versions_to_unelect": ["deadbeef"],
            "release_package_sha256_hex": SHA,
            "release_package_urls": ["https://example.com/update-img.tar.zst"],
        }

        git_hash, guest_os_hash, guest_os_measurements, host_os_hash = repro_check.parse_proposal_payload(payload, 1)

        self.assertEqual(git_hash, GIT_HASH)
        self.assertIsNone(guest_os_hash)
        self.assertIsNone(guest_os_measurements)
        self.assertEqual(host_os_hash, SHA)

    def test_guestos_payload_converts_measurements_to_bytes(self):
        payload = {
            "replica_version_to_elect": GIT_HASH,
            "replica_versions_to_unelect": [],
            "release_package_sha256_hex": SHA,
            "release_package_urls": ["https://example.com/update-img.tar.zst"],
            "guest_launch_measurements": MEASUREMENTS,
        }

        git_hash, guest_os_hash, guest_os_measurements, host_os_hash = repro_check.parse_proposal_payload(payload, 1)

        self.assertEqual(git_hash, GIT_HASH)
        self.assertEqual(guest_os_hash, SHA)
        self.assertEqual(guest_os_measurements, to_byte_measurements(MEASUREMENTS))
        self.assertIsNone(host_os_hash)

    def test_payload_without_elected_version(self):
        with self.assertRaises(repro_check.VerificationError):
            repro_check.parse_proposal_payload({"release_package_sha256_hex": SHA}, 1)


class RunTest(unittest.TestCase):
    """
    Drives run() for an election proposal end to end, with only the network and the local
    build stubbed out, so the whole verification path is exercised offline.
    """

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp_dir, True)
        self.addCleanup(mock.patch.stopall)
        self.cdn = fake_cdn()

    def build_verifier(self, payload: dict) -> "repro_check.ReproducibilityVerifier":
        verifier = repro_check.ReproducibilityVerifier(
            verify_guestos=True,
            verify_hostos=True,
            verify_setupos=True,
            verify_recovery=True,
            proposal_id="143816",
            git_commit="",
            download_source_mode="systems",
            base_cache_dir=self.tmp_dir / "cache",
            clean_base_cache_dir=False,
            keep_temp=False,
        )
        self.addCleanup(verifier.download_executor.shutdown)

        proposal = json.dumps({"payload": payload}).encode()
        mock.patch.object(repro_check.urllib.request, "urlopen", lambda req: FakeResponse(proposal)).start()
        mock.patch.object(repro_check, "fetch_url_to_file", self.fake_fetch).start()
        mock.patch.object(verifier, "check_environment").start()
        mock.patch.object(verifier, "build_locally", self.fake_build).start()
        return verifier

    def fake_fetch(self, url: str, dest_path: Path) -> Path:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_bytes(self.cdn[url])
        return dest_path

    def fake_build(self, storage: "repro_check.Dirs") -> None:
        """Writes local artifacts that are byte-identical to the CDN ones."""
        for local, url in [
            ("guestos/update/update-img.tar.zst", GUEST_OS_IMG),
            ("guestos/update/launch-measurements.json", MEASUREMENTS_URL),
            ("hostos/update/update-img.tar.zst", HOST_OS_IMG),
            ("setupos/disk-img.tar.zst", SETUP_OS_IMG),
            ("guestos/update-img-recovery/update-img.tar.zst", RECOVERY_IMG),
        ]:
            dest = storage.dev_out / local
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(self.cdn[url])

    def guestos_payload(self, measurements: dict) -> dict:
        return {
            "replica_version_to_elect": GIT_HASH,
            "replica_versions_to_unelect": [],
            "release_package_sha256_hex": sha256_hex(self.cdn[GUEST_OS_IMG]),
            "release_package_urls": [GUEST_OS_IMG],
            "guest_launch_measurements": measurements,
        }

    def test_hostos_proposal_run(self):
        """A HostOS proposal carries no launch measurements; the run must not trip over that."""
        verifier = self.build_verifier(
            {
                "hostos_version_to_elect": GIT_HASH,
                "hostos_versions_to_unelect": ["deadbeef"],
                "release_package_sha256_hex": sha256_hex(self.cdn[HOST_OS_IMG]),
                "release_package_urls": [HOST_OS_IMG],
            }
        )

        verifier.run()

        self.assertEqual(verifier.git_hash, GIT_HASH)

    def test_guestos_proposal_run(self):
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))

        verifier.run()

        self.assertEqual(verifier.git_hash, GIT_HASH)

    def test_guestos_proposal_run_detects_measurement_mismatch(self):
        """The GuestOS run must still compare the measurements it does carry."""
        mismatched = {"guest_launch_measurements": [{"measurement": "ffff", "metadata": {}}]}
        verifier = self.build_verifier(self.guestos_payload(mismatched))

        with self.assertRaises(repro_check.VerificationError):
            verifier.run()


if __name__ == "__main__":
    unittest.main()
