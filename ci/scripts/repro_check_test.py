"""Tests for the proposal handling and the local-build verification in ci/scripts/repro-check."""

import gzip
import hashlib
import http.client
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import tarfile
import tempfile
import unittest
import urllib.error
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

RELEASE_WORKFLOW, RELEASE_REF = "dfinity/ic/.github/workflows/release-testing.yml", "refs/heads/rc--2026-09-15_03-29"
MASTER_WORKFLOW, MASTER_REF = "dfinity/ic/.github/workflows/ci-kickoff.yml", "refs/heads/master"


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

CDN_DIRS = [
    ("guest-os", "update-img", "update-img.tar.zst"),
    ("host-os", "update-img", "update-img.tar.zst"),
    ("setup-os", "disk-img", "disk-img.tar.zst"),
    ("guest-os", "update-img-recovery", "update-img.tar.zst"),
]


def sums_body(entries: dict[str, bytes]) -> bytes:
    """A SHA256SUMS file in the CDN's own format: one space between hash and name."""
    return "".join(f"{sha256_hex(content)} {name}\n" for name, content in entries.items()).encode()


def fake_cdn(domain: str = "download.dfinity.systems") -> dict[str, bytes]:
    """Contents served for every URL a full `repro-check -p <id>` run downloads."""
    cdn = {}
    measurements = json.dumps(to_byte_measurements(MEASUREMENTS)).encode()
    for os_type, subdir, artifact in CDN_DIRS:
        content = f"{os_type}/{subdir} image".encode()
        base = f"https://{domain}/ic/{GIT_HASH}/{os_type}/{subdir}"
        cdn[f"{base}/{artifact}"] = content
        entries = {artifact: content}
        if (os_type, subdir) == ("guest-os", "update-img"):
            cdn[f"{base}/launch-measurements.json"] = measurements
            entries["launch-measurements.json"] = measurements
        cdn[f"{base}/SHA256SUMS"] = sums_body(entries)
    return cdn


def gh_entry(
    subjects: dict[str, str],
    workflow: str = RELEASE_WORKFLOW,
    ref: str = RELEASE_REF,
    run: str = "https://github.com/dfinity/ic/actions/runs/1",
) -> dict:
    """One entry of `gh attestation verify --format json`, with the key paths the policy reads."""
    return {
        "verificationResult": {
            "signature": {
                "certificate": {
                    "buildConfigURI": f"https://github.com/{workflow}@{ref}",
                    "sourceRepositoryRef": ref,
                    "runInvocationURI": run,
                }
            },
            "statement": {"subject": [{"name": name, "digest": {"sha256": d}} for name, d in subjects.items()]},
        }
    }


class FakeResponse:
    """Stands in for the urlopen() response carrying the proposal JSON."""

    def __init__(self, content: bytes, headers: dict | None = None):
        self.status = 200
        self.headers = {"Content-Length": str(len(content)), **(headers or {})}
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
    Drives run() for an election proposal end to end, with only the network, the gh CLI and the
    local build stubbed out, so the whole verification path is exercised offline.
    """

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp_dir, True)
        self.addCleanup(mock.patch.stopall)
        # A failed run sets the module-level interrupt flag; do not leak that into the next test.
        self.addCleanup(setattr, repro_check, "interrupted", False)
        self.cdn = fake_cdn()
        # Local artifacts (keyed by their path below dev_out) that should differ from the CDN ones.
        self.local_overrides: dict[str, bytes] = {}
        # The storage the fake build was given, to inspect after the run.
        self.build_storage: repro_check.Dirs | None = None
        self.build_ran = False
        # Attestation stubs: what fetch_attestation_bundles / run_gh_attestation_verify do.
        self.bundles_error: Exception | None = None
        # Digests for which GitHub holds no attestation.
        self.unattested_digests: set[str] = set()
        self.gh_error: Exception | None = None
        self.entries_for: dict[str, list[dict]] = {}
        self.fetch_calls: list[str] = []
        self.gh_calls: list[str] = []
        self.ensure_gh_error: Exception | None = None

    def build_verifier(
        self,
        payload: dict,
        *,
        proposal_id: str = "143816",
        git_commit: str = "",
        skip: bool = False,
        download_source: str = "systems",
    ) -> "repro_check.ReproducibilityVerifier":
        verifier = repro_check.ReproducibilityVerifier(
            verify_guestos=True,
            verify_hostos=True,
            verify_setupos=True,
            verify_recovery=True,
            proposal_id=proposal_id,
            git_commit=git_commit,
            download_source_mode=download_source,
            base_cache_dir=self.tmp_dir / "cache",
            clean_base_cache_dir=False,
            keep_temp=False,
            skip_attestation_check=skip,
        )
        self.addCleanup(verifier.download_executor.shutdown)

        proposal = json.dumps({"payload": payload}).encode()
        mock.patch.object(
            repro_check.urllib.request, "urlopen", lambda req, timeout=None: FakeResponse(proposal)
        ).start()
        mock.patch.object(repro_check, "fetch_url_to_file", self.fake_fetch).start()
        mock.patch.object(repro_check, "fetch_url_validator", self.fake_validator).start()
        mock.patch.object(repro_check, "fetch_attestation_bundles", self.fake_fetch_bundles).start()
        mock.patch.object(repro_check, "run_gh_attestation_verify", self.fake_gh_verify).start()
        mock.patch.object(verifier, "ensure_gh", self.fake_ensure_gh).start()
        mock.patch.object(verifier, "check_environment").start()
        mock.patch.object(verifier, "build_locally", self.fake_build).start()
        return verifier

    def fake_ensure_gh(self, dirs: "repro_check.Dirs") -> Path:
        if self.ensure_gh_error is not None:
            raise self.ensure_gh_error
        return Path("/usr/bin/gh")

    def fake_fetch_bundles(self, digest: str) -> list[dict]:
        self.fetch_calls.append(digest)
        if self.bundles_error is not None:
            raise self.bundles_error
        if digest in self.unattested_digests:
            raise repro_check.VerificationError("GitHub holds no build-provenance attestation")
        return [{"stub": digest}]

    def fake_gh_verify(self, gh, sums_file, bundle_file, commit, config_dir) -> list[dict]:
        digest = repro_check.compute_sha256(sums_file)
        self.gh_calls.append(digest)
        if self.gh_error is not None:
            raise self.gh_error
        if digest in self.entries_for:
            return self.entries_for[digest]
        return [gh_entry(self.subjects_for(digest))]

    def subjects_for(self, digest: str) -> dict[str, str]:
        """The subject the CDN directory serving these bytes must be attested under."""
        for url, content in self.cdn.items():
            if url.endswith("/SHA256SUMS") and sha256_hex(content) == digest:
                return {url.split("://", 1)[1].split("/", 1)[1]: digest}
        raise AssertionError(f"no SHA256SUMS in the fake CDN has digest {digest}")

    def fake_fetch(self, url: str, dest_path: Path) -> Path:
        if url not in self.cdn:
            # What fetch_url_to_file raises for a 404, so that the exit-2 path is exercised as is.
            raise RuntimeError(f"Could not download {url} -> {dest_path}. Error: HTTP Error 404: Not Found")
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_bytes(self.cdn[url])
        return dest_path

    def fake_validator(self, url: str) -> dict[str, str] | None:
        """An ETag that tracks the content, so mutating self.cdn models a CDN substitution."""
        content = self.cdn.get(url)
        return {"ETag": f'"{sha256_hex(content)}"'} if content is not None else None

    def fake_build(self, storage: "repro_check.Dirs") -> None:
        """Writes local artifacts that are byte-identical to the CDN ones, except for those in local_overrides."""
        self.build_storage = storage
        self.build_ran = True
        for local, url in [
            ("guestos/update/update-img.tar.zst", GUEST_OS_IMG),
            ("guestos/update/launch-measurements.json", MEASUREMENTS_URL),
            ("hostos/update/update-img.tar.zst", HOST_OS_IMG),
            ("setupos/disk-img.tar.zst", SETUP_OS_IMG),
            ("guestos/update-img-recovery/update-img.tar.zst", RECOVERY_IMG),
        ]:
            dest = storage.dev_out / local
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(self.local_overrides.get(local, self.cdn[url]))

    def guestos_payload(self, measurements: dict) -> dict:
        return {
            "replica_version_to_elect": GIT_HASH,
            "replica_versions_to_unelect": [],
            "release_package_sha256_hex": sha256_hex(self.cdn[GUEST_OS_IMG]),
            "release_package_urls": [GUEST_OS_IMG],
            "guest_launch_measurements": measurements,
        }

    def sums_digest(self, os_type: str, subdir: str) -> str:
        return sha256_hex(self.cdn[cdn_url(os_type, subdir, "SHA256SUMS")])

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
        # Every CDN directory's SHA256SUMS was attested, and each distinct file only once.
        self.assertEqual(len(self.gh_calls), 4)
        self.assertEqual(sorted(self.fetch_calls), sorted(self.gh_calls))

    def test_guestos_proposal_run_detects_measurement_mismatch(self):
        """The GuestOS run must still compare the measurements it does carry."""
        mismatched = {"guest_launch_measurements": [{"measurement": "ffff", "metadata": {}}]}
        verifier = self.build_verifier(self.guestos_payload(mismatched))

        with self.assertRaises(repro_check.VerificationError):
            verifier.run()

    def test_guestos_proposal_run_detects_local_build_mismatch(self):
        """
        Locally built artifacts that differ from the CDN ones must fail the run, and the run must
        report every mismatch rather than stop at the first one.
        """
        mismatched = {"guest_launch_measurements": [{"measurement": "ffff", "metadata": {}}]}
        self.local_overrides = {
            "guestos/update/update-img.tar.zst": b"locally built guest-os image",
            "guestos/update/launch-measurements.json": json.dumps(to_byte_measurements(mismatched)).encode(),
            "setupos/disk-img.tar.zst": b"locally built setup-os image",
        }
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))

        with self.assertLogs(repro_check.logger, level="INFO") as logs, self.assertRaises(
            repro_check.VerificationError
        ) as raised:
            verifier.run()

        self.assertEqual(
            str(raised.exception),
            "The locally built artifacts do not match the remote CDN artifacts for: "
            "GuestOS update image, GuestOS launch measurements, SetupOS disk image.\n"
            "The build provenance of the CDN checksum files was confirmed, and the artifacts compared here "
            "match them, so they are what CI built for this commit: this is a reproducibility problem in the "
            "build, not a substituted artifact.",
        )
        # The artifacts after the first mismatch were still compared, and they matched.
        self.assertTrue(any("Verification successful for HostOS!" in line for line in logs.output), logs.output)
        self.assertTrue(
            any("Verification successful for Recovery-GuestOS!" in line for line in logs.output), logs.output
        )
        # A failed run must not leave the downloaded and built images behind.
        self.assertFalse(self.build_storage.tmp_dir.exists())

    # ---- attestation policy -------------------------------------------------

    def test_commit_mode_accepts_a_master_build(self):
        verifier = self.build_verifier({}, proposal_id="", git_commit=GIT_HASH)
        self.entries_for = {
            self.sums_digest(os_type, subdir): [
                gh_entry(
                    {f"ic/{GIT_HASH}/{os_type}/{subdir}/SHA256SUMS": self.sums_digest(os_type, subdir)},
                    workflow=MASTER_WORKFLOW,
                    ref=MASTER_REF,
                )
            ]
            for os_type, subdir, _ in CDN_DIRS
        }

        verifier.run()

        self.assertTrue(self.build_ran)

    def test_proposal_mode_rejects_a_master_only_build(self):
        """An elected version must come from a release build, not from a master run."""
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        self.entries_for = {
            self.sums_digest(os_type, subdir): [
                gh_entry(
                    {f"ic/{GIT_HASH}/{os_type}/{subdir}/SHA256SUMS": self.sums_digest(os_type, subdir)},
                    workflow=MASTER_WORKFLOW,
                    ref=MASTER_REF,
                )
            ]
            for os_type, subdir, _ in CDN_DIRS
        }

        with self.assertRaises(repro_check.VerificationError) as raised:
            verifier.run()

        self.assertIn("unexpected pipeline", str(raised.exception))
        # The build must not have been started for a substituted artifact.
        self.assertFalse(self.build_ran)

    def test_proposal_mode_accepts_the_release_entry_of_a_two_entry_list(self):
        """An rc commit that is also on master carries both attestations; the rc one must be found."""
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        self.entries_for = {
            self.sums_digest(os_type, subdir): [
                gh_entry(
                    {f"ic/{GIT_HASH}/{os_type}/{subdir}/SHA256SUMS": self.sums_digest(os_type, subdir)},
                    workflow=MASTER_WORKFLOW,
                    ref=MASTER_REF,
                ),
                gh_entry({f"ic/{GIT_HASH}/{os_type}/{subdir}/SHA256SUMS": self.sums_digest(os_type, subdir)}),
            ]
            for os_type, subdir, _ in CDN_DIRS
        }

        verifier.run()

        self.assertTrue(self.build_ran)

    def test_skip_flag_makes_no_attestation_calls_and_warns(self):
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS), skip=True)

        with self.assertLogs(repro_check.logger, level="WARNING") as logs:
            verifier.run()

        self.assertEqual(self.fetch_calls, [])
        self.assertEqual(self.gh_calls, [])
        self.assertTrue(any("--skip-attestation-check" in line for line in logs.output), logs.output)
        # Warned once when skipping and once more at the end of the run.
        self.assertEqual(sum("--skip-attestation-check" in line for line in logs.output), 2)

    def test_dry_run_bootstraps_gh_but_does_not_verify(self):
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        ensure_gh_calls = []
        verifier.ensure_gh = lambda dirs: ensure_gh_calls.append(dirs) or Path("/usr/bin/gh")

        verifier.run(dry_run=True)

        self.assertEqual(len(ensure_gh_calls), 1)
        self.assertEqual(self.fetch_calls, [])

    def test_tampered_launch_measurements_fail_against_the_attested_sums(self):
        """launch-measurements.json is only as trustworthy as its line in the attested SHA256SUMS."""
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        self.cdn[MEASUREMENTS_URL] = json.dumps(to_byte_measurements(MEASUREMENTS)).encode() + b" "

        with self.assertRaises(repro_check.VerificationError) as raised:
            verifier.run()

        self.assertIn("launch-measurements.json", str(raised.exception))

    def test_sums_without_a_measurements_line_fails(self):
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        url = cdn_url("guest-os", "update-img", "SHA256SUMS")
        self.cdn[url] = sums_body({"update-img.tar.zst": self.cdn[GUEST_OS_IMG]})

        with self.assertRaises(repro_check.VerificationError) as raised:
            verifier.run()

        self.assertIn("Couldn't find launch-measurements.json", str(raised.exception))

    def test_divergent_bytes_on_the_second_cdn_are_verified_separately(self):
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS), download_source="both")
        network = fake_cdn("download.dfinity.network")
        # Make the second CDN's host-os SHA256SUMS differ, so it cannot ride on the memo.
        host_url = "https://download.dfinity.network/ic/%s/host-os/update-img/SHA256SUMS" % GIT_HASH
        network[host_url] = network[host_url] + b"\n"
        self.cdn.update(network)

        verifier.run()

        # 4 directories on the first CDN + the one directory whose bytes differ on the second; the
        # other three ride on the memo rather than costing another API call.
        self.assertEqual(len(self.gh_calls), 5)
        self.assertEqual(len(set(self.gh_calls)), 5)

    def test_the_first_unverifiable_directory_stops_the_run(self):
        """
        Nothing after the first attestation that cannot be obtained is looked up, and the build
        never starts: fail-first hides nothing, because nothing continues.
        """
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        guest_digest = self.sums_digest("guest-os", "update-img")
        host_digest = self.sums_digest("host-os", "update-img")
        self.unattested_digests = {guest_digest}
        # host-os is attested as some OTHER directory's SHA256SUMS: a cross-directory substitution
        # that a run continuing past guest-os would report; this one stops before it.
        self.entries_for = {host_digest: [gh_entry({f"ic/{GIT_HASH}/setup-os/disk-img/SHA256SUMS": host_digest})]}

        with self.assertRaises(repro_check.VerificationError) as raised:
            verifier.run()

        self.assertIn("guest-os/update-img/SHA256SUMS", str(raised.exception))
        self.assertIn("no build-provenance attestation", str(raised.exception))
        self.assertEqual(self.fetch_calls, [guest_digest])
        self.assertEqual(self.gh_calls, [])
        self.assertFalse(self.build_ran)

    def test_an_unreadable_gh_shape_aborts_the_run(self):
        """A gh output this script cannot read stops the run, without claiming substitution."""
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        guest_digest = self.sums_digest("guest-os", "update-img")
        self.entries_for = {guest_digest: [{"someShapeThisScriptCannotRead": {}}]}

        with self.assertRaises(repro_check.VerificationError) as raised:
            verifier.run()

        self.assertIn("guest-os/update-img/SHA256SUMS", str(raised.exception))
        self.assertIn("unrecognised", str(raised.exception))
        self.assertNotIn("substitution", str(raised.exception))
        self.assertFalse(self.build_ran)

    def test_github_tokens_are_dropped_before_the_build_runs(self):
        """
        build_locally() executes the commit's own ci/container/build-ic.sh with this environment;
        verifying a commit must not hand that commit's build scripts a GitHub credential.
        """
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        seen = {}
        real_build = self.fake_build

        def build(storage):
            seen["GH_TOKEN"] = os.environ.get("GH_TOKEN")
            seen["GITHUB_TOKEN"] = os.environ.get("GITHUB_TOKEN")
            return real_build(storage)

        mock.patch.object(verifier, "build_locally", build).start()
        with mock.patch.dict(os.environ, {"GH_TOKEN": "secret", "GITHUB_TOKEN": "also-secret"}):
            verifier.run()

        self.assertIsNone(seen["GH_TOKEN"])
        self.assertIsNone(seen["GITHUB_TOKEN"])

    def test_tokens_are_dropped_even_when_the_preflight_aborts(self):
        """The finally is the only thing between a credential and the build, on every path."""
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        verifier.ensure_gh = mock.Mock(side_effect=repro_check.VerificationError("no gh"))

        with mock.patch.dict(os.environ, {"GH_TOKEN": "secret"}):
            with self.assertRaises(repro_check.VerificationError):
                verifier.run()
            self.assertNotIn("GH_TOKEN", os.environ)

    def test_sha256sums_are_fetched_fresh_rather_than_from_the_cache(self):
        """
        A cached SHA256SUMS would make a rerun re-verify the previous run's bytes and report
        success even if the CDN had started serving something else since.
        """
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        cached = []
        mock.patch.object(
            verifier, "cached_download", lambda url, target, os_type: cached.append(url) or self.fake_fetch(url, target)
        ).start()

        verifier.run()

        self.assertTrue(cached, "the images should still come from the cache")
        self.assertFalse([url for url in cached if url.endswith("/SHA256SUMS")], cached)

    def test_skip_flag_still_drops_the_github_tokens(self):
        """The documented escape hatch must not be the one way to leak a token to the build."""
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS), skip=True)
        seen = {}
        real_build = self.fake_build
        mock.patch.object(
            verifier,
            "build_locally",
            lambda storage: seen.update(tok=os.environ.get("GH_TOKEN")) or real_build(storage),
        ).start()

        with mock.patch.dict(os.environ, {"GH_TOKEN": "secret"}):
            verifier.run()

        self.assertIsNone(seen["tok"])

    def test_launch_measurements_are_fetched_fresh_rather_than_from_the_cache(self):
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        cached = []
        mock.patch.object(
            verifier, "cached_download", lambda url, target, os_type: cached.append(url) or self.fake_fetch(url, target)
        ).start()

        verifier.run()

        self.assertFalse([url for url in cached if url.endswith("/launch-measurements.json")], cached)

    def test_a_substituted_image_is_detected_although_the_image_is_cached(self):
        """
        The attack the cache would otherwise hide: an attacker who cannot forge the attestation
        leaves SHA256SUMS alone and swaps only the image. A rerun with a warm cache must notice
        that the CDN no longer serves what was cached, rather than re-verifying the old bytes.
        """
        cache_dir = self.tmp_dir / "cache"
        first = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        first.run()
        self.assertTrue(self.build_ran)
        mock.patch.stopall()

        # The CDN now serves a different GuestOS image; SHA256SUMS is untouched, as it is attested.
        self.cdn[GUEST_OS_IMG] = b"substituted guest-os image"
        self.build_ran = False
        second = repro_check.ReproducibilityVerifier(
            verify_guestos=True,
            verify_hostos=False,
            verify_setupos=False,
            verify_recovery=False,
            proposal_id="143816",
            git_commit="",
            download_source_mode="systems",
            base_cache_dir=cache_dir,
            clean_base_cache_dir=False,
            keep_temp=False,
        )
        self.addCleanup(second.download_executor.shutdown)
        proposal = json.dumps({"payload": self.guestos_payload(MEASUREMENTS)}).encode()
        mock.patch.object(
            repro_check.urllib.request, "urlopen", lambda req, timeout=None: FakeResponse(proposal)
        ).start()
        mock.patch.object(repro_check, "fetch_url_to_file", self.fake_fetch).start()
        mock.patch.object(repro_check, "fetch_url_validator", self.fake_validator).start()
        mock.patch.object(repro_check, "fetch_attestation_bundles", self.fake_fetch_bundles).start()
        mock.patch.object(repro_check, "run_gh_attestation_verify", self.fake_gh_verify).start()
        mock.patch.object(second, "ensure_gh", self.fake_ensure_gh).start()
        mock.patch.object(second, "check_environment").start()
        mock.patch.object(second, "build_locally", self.fake_build).start()

        # The re-downloaded image no longer matches the (genuine, attested) SHA256SUMS.
        with self.assertRaises(repro_check.VerificationError) as raised:
            second.run()

        self.assertIn("doesn't match the CDN sha256 sum", str(raised.exception))

    def test_a_cached_image_is_downloaded_again_when_the_head_fails(self):
        """A cached image the CDN cannot revalidate is a miss, not a reuse with a warning."""
        first = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        first.run()
        mock.patch.stopall()
        self.build_ran = False

        fetched: list[str] = []
        real_fetch = self.fake_fetch

        def fetch(url, dest):
            fetched.append(url)
            return real_fetch(url, dest)

        second = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        mock.patch.object(repro_check, "fetch_url_to_file", fetch).start()
        mock.patch.object(repro_check, "fetch_url_validator", lambda url: None).start()

        with self.assertNoLogs(repro_check.logger, level="WARNING"):
            second.run()

        self.assertIn(GUEST_OS_IMG, fetched)
        self.assertTrue(self.build_ran)

    def test_a_transport_fault_in_the_attestation_api_aborts_cleanly(self):
        """
        http.client.HTTPException is neither OSError nor ValueError and urllib re-raises it
        unwrapped: the abort must be a VerificationError with a message, not a traceback.
        """
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        self.bundles_error = http.client.IncompleteRead(b"partial")

        self.assert_aborts_before_the_build(verifier, "IncompleteRead")

    def test_an_unexpected_exception_in_the_preflight_becomes_a_verification_error(self):
        """attestation_preflight promises that only VerificationError and RuntimeError leave it."""
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        verifier.ensure_gh = mock.Mock(side_effect=http.client.BadStatusLine("garbage"))

        self.assert_aborts_before_the_build(verifier, "BadStatusLine")

    def test_a_download_failure_still_stops_the_run_as_a_download_failure(self):
        """The backstop must not rewrap a CDN checksum file that cannot be fetched: that is exit 2."""
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        del self.cdn[cdn_url("guest-os", "update-img", "SHA256SUMS")]

        with self.assertRaises(RuntimeError) as raised:
            verifier.run()

        self.assertNotIsInstance(raised.exception, repro_check.VerificationError)
        self.assertIn("Could not download", str(raised.exception))
        self.assertFalse(self.build_ran)

    # ---- the abort path: none of these may start the build ------------------

    def assert_aborts_before_the_build(self, verifier, needle: str, *, dry_run: bool = False):
        with self.assertRaises(repro_check.VerificationError) as raised:
            verifier.run(dry_run=dry_run)
        message = str(raised.exception)
        self.assertIn(needle, message)
        self.assertFalse(self.build_ran)
        # The moment an attestation is missing is exactly when the bypass must not be suggested.
        self.assertNotIn("--skip-attestation-check", message)
        return raised.exception

    def test_a_missing_attestation_aborts_before_the_build(self):
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        self.bundles_error = repro_check.VerificationError("GitHub holds no build-provenance attestation")

        self.assert_aborts_before_the_build(verifier, "no build-provenance attestation")
        self.assertEqual(len(self.fetch_calls), 1)
        self.assertEqual(self.gh_calls, [])

    def test_no_image_is_downloaded_when_the_preflight_aborts(self):
        """
        storage() joins the executor on the way out, so an image in flight when the check fails
        would hold the exit for as long as the download takes: the images are queued only once the
        check has passed, and only the checksum files are fetched before it.
        """
        fetched: list[str] = []
        real_fetch = self.fake_fetch

        def fetch(url, dest):
            fetched.append(url)
            return real_fetch(url, dest)

        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        mock.patch.object(repro_check, "fetch_url_to_file", fetch).start()
        self.bundles_error = repro_check.VerificationError("GitHub holds no build-provenance attestation")

        self.assert_aborts_before_the_build(verifier, "no build-provenance attestation")
        self.assertTrue(any(url.endswith("/SHA256SUMS") for url in fetched), fetched)
        self.assertEqual([url for url in fetched if not url.endswith("/SHA256SUMS")], [])

    def test_the_abort_for_a_missing_attestation_does_not_name_the_bypass(self):
        """The advice text, and the abort built from it, must both stay silent on the bypass."""
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        self.bundles_error = repro_check.VerificationError(
            "GitHub holds no build-provenance attestation covering sha256:x.\n" + repro_check.NO_ATTESTATION_ADVICE
        )

        self.assert_aborts_before_the_build(verifier, "substituted checksum file")
        self.assertNotIn("--skip-attestation-check", repro_check.NO_ATTESTATION_ADVICE)

    def test_a_mismatch_with_the_check_skipped_is_not_put_down_to_the_build(self):
        """
        With the check skipped the run cannot tell a reproducibility problem from a substituted
        artifact, and its mismatch report must say so, naming the flag that caused it.
        """
        self.local_overrides = {"guestos/update/update-img.tar.zst": b"what CI actually built"}
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS), skip=True)

        with self.assertRaises(repro_check.VerificationError) as raised:
            verifier.run()

        self.assertIn("was NOT verified, because --skip-attestation-check was given", str(raised.exception))
        self.assertNotIn("reproducibility problem in the build, not", str(raised.exception))
        self.assertTrue(self.build_ran)

    def test_a_rate_limited_api_aborts_before_the_build(self):
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        self.bundles_error = repro_check.VerificationError("the GitHub API rate limit is exhausted")

        self.assert_aborts_before_the_build(verifier, "rate limit is exhausted")

    def test_an_unreachable_api_aborts_before_the_build(self):
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        self.bundles_error = repro_check.VerificationError("could not reach the GitHub attestations API")

        self.assert_aborts_before_the_build(verifier, "could not reach the GitHub attestations API")

    def test_a_failing_gh_bootstrap_aborts_before_any_lookup(self):
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        verifier.ensure_gh = mock.Mock(side_effect=repro_check.VerificationError("could not download gh"))

        self.assert_aborts_before_the_build(verifier, "could not download gh")
        self.assertEqual(self.fetch_calls, [])

    def test_a_failing_gh_bootstrap_fails_the_dry_run_too(self):
        """The bootstrap is all of the attestation check a PR's dry run rehearses; a broken pin must fail the PR."""
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        verifier.ensure_gh = mock.Mock(side_effect=repro_check.VerificationError("could not download gh"))

        self.assert_aborts_before_the_build(verifier, "could not download gh", dry_run=True)
        self.assertEqual(self.fetch_calls, [])

    def test_an_unusable_git_hash_aborts_before_the_build(self):
        verifier = self.build_verifier({}, proposal_id="", git_commit=GIT_HASH)
        verifier.git_hash = "abc"
        mock.patch.object(verifier, "decide_git_hash").start()
        # The CDN is keyed on the real hash; serve the same bytes for the truncated one.
        self.cdn.update({url.replace(GIT_HASH, "abc"): body for url, body in self.cdn.items()})

        self.assert_aborts_before_the_build(verifier, "not a 40-character git commit id")
        self.assertEqual(self.fetch_calls, [])


class BuildPipelineNameTest(unittest.TestCase):
    """The ref in a Build Config URI contains slashes, so a naive basename yields the ref."""

    def test_strips_the_ref_before_taking_the_basename(self):
        for ref in ("refs/heads/rc--2026-09-19_03-27", "refs/heads/master", "refs/heads/hotfix-a268b428"):
            with self.subTest(ref=ref):
                uri = f"https://github.com/{RELEASE_WORKFLOW}@{ref}"
                self.assertEqual(repro_check.build_pipeline_name(uri), "release-testing.yml")

    def test_tolerates_a_missing_uri(self):
        self.assertEqual(repro_check.build_pipeline_name(None), "<unknown pipeline>")


class SelectAttestedEntryTest(unittest.TestCase):
    SUBJECT = f"ic/{GIT_HASH}/guest-os/update-img/SHA256SUMS"
    DIGEST = "b" * 64
    RELEASE_ONLY = (repro_check.RELEASE_BUILD,)
    BOTH = (repro_check.RELEASE_BUILD, repro_check.MASTER_BUILD)

    def select(self, entries, accepted=None, subject=None, digest=None):
        return repro_check.select_attested_entry(
            entries, subject or self.SUBJECT, digest or self.DIGEST, accepted or self.BOTH
        )

    def entry(self, **kwargs):
        return gh_entry({self.SUBJECT: self.DIGEST}, **kwargs)

    def test_accepts_a_release_build_in_both_modes(self):
        self.assertIsNotNone(self.select([self.entry()], self.RELEASE_ONLY))
        self.assertIsNotNone(self.select([self.entry()], self.BOTH))

    def test_accepts_a_master_build_only_in_commit_mode(self):
        master = self.entry(workflow=MASTER_WORKFLOW, ref=MASTER_REF)
        self.assertIsNotNone(self.select([master], self.BOTH))
        with self.assertRaises(repro_check.VerificationError):
            self.select([master], self.RELEASE_ONLY)

    def test_accepts_a_hotfix_ref(self):
        self.assertIsNotNone(self.select([self.entry(ref="refs/heads/hotfix-a268b428")], self.RELEASE_ONLY))

    def test_rejects_another_directorys_sums_with_the_same_digest(self):
        other = gh_entry({f"ic/{GIT_HASH}/host-os/update-img/SHA256SUMS": self.DIGEST})
        with self.assertRaises(repro_check.VerificationError):
            self.select([other])

    def test_rejects_a_flipped_digest(self):
        with self.assertRaises(repro_check.VerificationError):
            self.select([self.entry()], digest="c" + self.DIGEST[1:])

    def test_rejects_a_lookalike_workflow(self):
        lookalike = self.entry(workflow="dfinity/ic/.github/workflows/ci-kickoff-manual.yml", ref=MASTER_REF)
        with self.assertRaises(repro_check.VerificationError):
            self.select([lookalike])

    def test_rejects_unaccepted_refs(self):
        for ref in ("refs/pull/1/merge", "refs/heads/master-2", "refs/heads/rc--x/y", "refs/heads/dev-gh-x"):
            with self.subTest(ref=ref), self.assertRaises(repro_check.VerificationError):
                self.select([self.entry(ref=ref)])

    def test_rejects_pins_split_across_two_entries(self):
        """The pipeline, the ref and the subject must all hold on ONE attestation."""
        right_pipeline_wrong_subject = gh_entry({f"ic/{GIT_HASH}/host-os/update-img/SHA256SUMS": self.DIGEST})
        right_subject_wrong_pipeline = self.entry(
            workflow="dfinity/ic/.github/workflows/ci-kickoff-manual.yml", ref=MASTER_REF
        )
        with self.assertRaises(repro_check.VerificationError):
            self.select([right_pipeline_wrong_subject, right_subject_wrong_pipeline])

    def test_missing_subject_keys_never_match(self):
        entry = self.entry()
        entry["verificationResult"]["statement"]["subject"] = [{"name": self.SUBJECT}]
        with self.assertRaises(repro_check.VerificationError):
            self.select([entry])

    def test_an_unrecognised_json_shape_aborts_without_claiming_substitution(self):
        """A gh output this script cannot read is our problem, and must not read as evidence."""
        with self.assertRaises(repro_check.VerificationError) as raised:
            self.select([{"someNewShape": {}}])

        self.assertIn("unrecognised", str(raised.exception))
        self.assertNotIn("substitution", str(raised.exception))

    def test_malformed_entries_never_crash(self):
        """Shape surprises must abort as a VerificationError, not raise AttributeError."""
        for entries in (
            [None],
            ["nope"],
            [{"verificationResult": "oops"}],
            [{"verificationResult": {"signature": "oops"}}],
            [{"verificationResult": {"signature": {"certificate": "oops"}}}],
        ):
            with self.subTest(entries=entries), self.assertRaises(repro_check.VerificationError):
                self.select(entries)

    def test_malformed_subjects_never_crash(self):
        entry = self.entry()
        entry["verificationResult"]["statement"]["subject"] = ["nope", None, {"digest": "oops"}]
        with self.assertRaises(repro_check.VerificationError):
            self.select([entry])

    def test_a_partially_recognised_shape_still_hard_fails(self):
        entry = self.entry()
        del entry["verificationResult"]["signature"]["certificate"]["buildConfigURI"]
        with self.assertRaises(repro_check.VerificationError):
            self.select([entry])


class FetchAttestationBundlesTest(unittest.TestCase):
    DIGEST = "d" * 64
    URL = f"https://api.github.com/repos/dfinity/ic/attestations/sha256:{'d' * 64}?per_page=100"

    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(repro_check.time, "sleep").start()
        mock.patch.dict(os.environ, {}, clear=True).start()
        self.requests: list[urllib.request.Request] = []

    def serve(self, *responses):
        """Patches urlopen to return/raise the given responses in order, recording the requests."""
        queue = list(responses)

        def fake_urlopen(request, timeout=None):
            self.requests.append(request)
            item = queue.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        mock.patch.object(repro_check.urllib.request, "urlopen", fake_urlopen).start()

    def page(self, bundles, link: str | None = None):
        body = json.dumps({"attestations": [{"bundle": b} for b in bundles]}).encode()
        return FakeResponse(body, {"Link": link} if link else {})

    def http_error(self, code: int, headers: dict | None = None):
        return urllib.error.HTTPError(self.URL, code, "nope", headers or {}, None)

    def test_requests_the_public_endpoint_anonymously(self):
        self.serve(self.page([{"a": 1}]))

        self.assertEqual(repro_check.fetch_attestation_bundles(self.DIGEST), [{"a": 1}])

        request = self.requests[0]
        self.assertEqual(request.full_url, self.URL)
        self.assertEqual(request.get_header("Accept"), "application/vnd.github+json")
        self.assertEqual(request.get_header("X-github-api-version"), "2022-11-28")
        self.assertIsNone(request.get_header("Authorization"))

    def test_uses_a_token_when_one_is_set(self):
        os.environ["GH_TOKEN"] = "secret"
        self.serve(self.page([{"a": 1}]))

        repro_check.fetch_attestation_bundles(self.DIGEST)

        self.assertEqual(self.requests[0].get_header("Authorization"), "Bearer secret")

    def test_404_means_no_attestation(self):
        self.serve(self.http_error(404))

        with self.assertRaises(repro_check.VerificationError) as raised:
            repro_check.fetch_attestation_bundles(self.DIGEST)

        self.assertIn("holds no build-provenance attestation", str(raised.exception))
        self.assertIn(repro_check.NO_ATTESTATION_ADVICE, str(raised.exception))
        self.assertNotIn("--skip-attestation-check", str(raised.exception))

    def test_an_empty_list_means_no_attestation(self):
        self.serve(self.page([]))

        with self.assertRaises(repro_check.VerificationError) as raised:
            repro_check.fetch_attestation_bundles(self.DIGEST)

        self.assertIn("holds no build-provenance attestation", str(raised.exception))

    def test_retries_a_server_error(self):
        self.serve(self.http_error(503), self.page([{"a": 1}]))

        self.assertEqual(repro_check.fetch_attestation_bundles(self.DIGEST), [{"a": 1}])

    def test_gives_up_after_three_network_errors(self):
        err = urllib.error.URLError("no route to host")
        self.serve(err, err, err)

        with self.assertRaises(repro_check.VerificationError) as raised:
            repro_check.fetch_attestation_bundles(self.DIGEST)

        self.assertIn("could not reach", str(raised.exception))

    def test_exhausted_rate_limit_names_gh_token_and_is_not_retried(self):
        self.serve(self.http_error(403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1700000000"}))

        with self.assertRaises(repro_check.VerificationError) as raised:
            repro_check.fetch_attestation_bundles(self.DIGEST)

        self.assertIn("GH_TOKEN", str(raised.exception))
        self.assertEqual(len(self.requests), 1)

    def test_a_rejected_token_is_retried_anonymously(self):
        os.environ["GITHUB_TOKEN"] = "wrong-repo"
        self.serve(self.http_error(401), self.page([{"a": 1}]))

        with self.assertLogs(repro_check.logger, level="WARNING") as logs:
            self.assertEqual(repro_check.fetch_attestation_bundles(self.DIGEST), [{"a": 1}])

        self.assertTrue(any("GITHUB_TOKEN" in line for line in logs.output), logs.output)
        self.assertIsNone(self.requests[1].get_header("Authorization"))

    def test_a_404_after_the_first_page_is_reported_rather_than_truncating(self):
        """A cursor GitHub no longer honours must not pass as a complete but shorter list."""
        nxt = f'<{self.URL}&after=cursor>; rel="next"'
        self.serve(self.page([{"a": 1}], link=nxt), self.http_error(404))

        with self.assertRaises(repro_check.VerificationError) as raised:
            repro_check.fetch_attestation_bundles(self.DIGEST)

        self.assertIn("HTTP 404", str(raised.exception))

    def test_a_non_list_attestations_field_aborts(self):
        self.serve(FakeResponse(json.dumps({"attestations": 5}).encode()))

        with self.assertRaises(repro_check.VerificationError) as raised:
            repro_check.fetch_attestation_bundles(self.DIGEST)

        self.assertIn("attestations API", str(raised.exception))

    def test_follows_the_next_cursor(self):
        nxt = f'<{self.URL}&after=cursor>; rel="next", <{self.URL}>; rel="last"'
        self.serve(self.page([{"a": 1}], link=nxt), self.page([{"b": 2}]))

        self.assertEqual(repro_check.fetch_attestation_bundles(self.DIGEST), [{"a": 1}, {"b": 2}])
        self.assertEqual(self.requests[1].full_url, f"{self.URL}&after=cursor")

    def test_caps_the_number_of_pages(self):
        """An insider minting attestations must not be able to make this page forever."""
        link = f'<{self.URL}&after=x>; rel="next"'
        self.serve(*[self.page([{"a": 1}], link=link) for _ in range(repro_check.ATTESTATION_MAX_PAGES)])

        with self.assertRaises(repro_check.VerificationError) as raised:
            repro_check.fetch_attestation_bundles(self.DIGEST)

        self.assertIn("refusing to page through them", str(raised.exception))


class EnsureGhTest(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp_dir, True)
        self.addCleanup(mock.patch.stopall)
        self.verifier = repro_check.ReproducibilityVerifier(
            verify_guestos=True,
            verify_hostos=False,
            verify_setupos=False,
            verify_recovery=False,
            proposal_id="",
            git_commit=GIT_HASH,
            download_source_mode="systems",
            base_cache_dir=self.tmp_dir / "cache",
            clean_base_cache_dir=False,
            keep_temp=False,
        )
        self.addCleanup(self.verifier.download_executor.shutdown)
        self.verifier.git_hash = GIT_HASH
        self.verifier.init_cache()
        self.dirs = repro_check.Dirs(
            self.tmp_dir / "tmp", self.tmp_dir / "out", self.tmp_dir, self.tmp_dir, self.tmp_dir
        )
        self.dirs.tmp_dir.mkdir(parents=True, exist_ok=True)

    def test_parse_gh_version(self):
        self.assertEqual(repro_check.parse_gh_version("gh version 2.98.0 (2026-08-20)"), (2, 98, 0))
        self.assertEqual(repro_check.parse_gh_version("gh version 2.4.0+dfsg1 (2022-03-23)"), (2, 4, 0))
        self.assertIsNone(repro_check.parse_gh_version("gh version DEV"))
        self.assertIsNone(repro_check.parse_gh_version("bash: gh: command not found"))
        self.assertIsNone(repro_check.parse_gh_version(""))

    def make_tarball(self, gh_script: bytes) -> bytes:
        """A tar.gz shaped like the gh release: the binary we want, plus a decoy beside it."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for name, content in [
                (repro_check.GH_CLI_TAR_MEMBER, gh_script),
                (f"gh_{repro_check.GH_CLI_VERSION}_linux_amd64/LICENSE", b"decoy"),
            ]:
                info = tarfile.TarInfo(name)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
        return gzip.compress(buf.getvalue())

    def stub_download(self, payload: bytes):
        def fake_cached_download(url, target_file, os_type):
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_bytes(payload)
            cache_dir = self.verifier.cache_for_this_hash / "github.com" / os_type
            cache_dir.mkdir(parents=True, exist_ok=True)
            (cache_dir / target_file.name).write_bytes(payload)
            return target_file

        mock.patch.object(self.verifier, "cached_download", fake_cached_download).start()

    def test_downloads_extracts_and_smoke_tests_the_pinned_gh(self):
        payload = self.make_tarball(b'#!/bin/sh\necho "gh version 2.98.0 (2026-08-20)"\n')
        self.stub_download(payload)
        mock.patch.object(repro_check, "GH_CLI_SHA256", sha256_hex(payload)).start()

        gh_path = self.verifier.ensure_gh(self.dirs)

        self.assertEqual(gh_path, self.dirs.tmp_dir / "gh")
        self.assertTrue(os.access(gh_path, os.X_OK))
        # Only the member we asked for was written out.
        self.assertFalse((self.dirs.tmp_dir / f"gh_{repro_check.GH_CLI_VERSION}_linux_amd64").exists())
        version = repro_check.parse_gh_version(self.verifier.gh_version_output(str(gh_path), self.dirs.tmp_dir / "cfg"))
        self.assertEqual(version, (2, 98, 0))

    def test_never_uses_a_gh_from_path(self):
        """One gh, the one the messages and the JSON handling were validated against."""
        payload = self.make_tarball(b'#!/bin/sh\necho "gh version 2.98.0 (2026-08-20)"\n')
        self.stub_download(payload)
        mock.patch.object(repro_check, "GH_CLI_SHA256", sha256_hex(payload)).start()
        which = mock.patch.object(repro_check.shutil, "which", mock.Mock(return_value="/usr/bin/gh")).start()

        self.assertEqual(self.verifier.ensure_gh(self.dirs), self.dirs.tmp_dir / "gh")
        which.assert_not_called()

    def test_a_tarball_failing_the_pin_is_rejected_and_uncached(self):
        payload = self.make_tarball(b"#!/bin/sh\ntrue\n")
        self.stub_download(payload)  # GH_CLI_SHA256 deliberately NOT patched.

        with self.assertRaises(repro_check.VerificationError) as raised:
            self.verifier.ensure_gh(self.dirs)

        self.assertIn("pinned sha256", str(raised.exception))
        self.assertFalse((self.dirs.tmp_dir / "gh").exists())
        self.assertFalse((self.verifier.cache_for_this_hash / "github.com" / "tools" / "gh_cli.tar.gz").exists())

    def test_an_unrunnable_gh_aborts(self):
        payload = self.make_tarball(b"not an executable")
        self.stub_download(payload)
        mock.patch.object(repro_check, "GH_CLI_SHA256", sha256_hex(payload)).start()

        with self.assertRaises(repro_check.VerificationError) as raised:
            self.verifier.ensure_gh(self.dirs)

        self.assertIn("does not run", str(raised.exception))


class FetchUrlValidatorTest(unittest.TestCase):
    """
    Only a strong ETag confirms a cached copy. Content-Length and Last-Modified cannot tell a
    same-sized replacement within the same second apart, and a weak ETag promises only semantic
    equivalence, so without a strong ETag there is no validator and the copy is downloaded again.
    """

    ETAG = '"98545880a7fb2e166110260376c9a202-78"'
    MODIFIED = "Fri, 18 Sep 2026 15:50:01 GMT"

    def setUp(self):
        self.addCleanup(mock.patch.stopall)

    def head(self, headers: dict[str, str]) -> dict[str, str] | None:
        mock.patch.object(
            repro_check.urllib.request, "urlopen", lambda req, timeout=None: FakeResponse(b"", headers)
        ).start()
        return repro_check.fetch_url_validator("https://cdn/img")

    def test_a_strong_etag_is_recorded_with_the_size_and_the_modification_time(self):
        validator = self.head({"ETag": self.ETAG, "Last-Modified": self.MODIFIED})
        self.assertEqual(validator, {"ETag": self.ETAG, "Last-Modified": self.MODIFIED, "Content-Length": "0"})

    def test_a_weak_etag_is_no_validator(self):
        self.assertIsNone(self.head({"ETag": 'W/"abc"', "Last-Modified": self.MODIFIED}))

    def test_size_and_modification_time_alone_are_no_validator(self):
        self.assertIsNone(self.head({"Last-Modified": self.MODIFIED}))


class CacheRevalidationTest(unittest.TestCase):
    """A cached image is reused only when the CDN confirms it still serves the same bytes."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp_dir, True)
        self.addCleanup(mock.patch.stopall)
        self.verifier = repro_check.ReproducibilityVerifier(
            verify_guestos=True,
            verify_hostos=False,
            verify_setupos=False,
            verify_recovery=False,
            proposal_id="",
            git_commit=GIT_HASH,
            download_source_mode="systems",
            base_cache_dir=self.tmp_dir / "cache",
            clean_base_cache_dir=False,
            keep_temp=False,
        )
        self.addCleanup(self.verifier.download_executor.shutdown)
        self.cache_file = self.tmp_dir / "img"
        self.cache_file.write_bytes(b"cached image")

    def stub_validator(self, value):
        mock.patch.object(repro_check, "fetch_url_validator", mock.Mock(return_value=value)).start()

    def test_a_matching_validator_reuses_the_cache(self):
        self.stub_validator({"ETag": '"a"'})
        self.verifier.write_cache_validator(self.cache_file, {"ETag": '"a"'})

        self.assertTrue(self.verifier.cached_copy_is_current("https://cdn/img", self.cache_file))

    def test_a_changed_validator_forces_a_redownload(self):
        self.stub_validator({"ETag": '"a"'})
        self.verifier.write_cache_validator(self.cache_file, {"ETag": '"a"'})
        self.stub_validator({"ETag": '"b"'})

        with self.assertLogs(repro_check.logger, level="WARNING") as logs:
            self.assertFalse(self.verifier.cached_copy_is_current("https://cdn/img", self.cache_file))

        self.assertTrue(any("no longer serves" in line for line in logs.output), logs.output)

    def test_a_cache_without_a_record_is_a_miss(self):
        """Cached by an older version of this script: downloaded again, once."""
        self.stub_validator({"ETag": '"a"'})

        self.assertFalse(self.verifier.cached_copy_is_current("https://cdn/img", self.cache_file))

    def test_an_unreachable_head_is_a_miss(self):
        self.verifier.write_cache_validator(self.cache_file, {"ETag": '"a"'})
        self.stub_validator(None)

        self.assertFalse(self.verifier.cached_copy_is_current("https://cdn/img", self.cache_file))

    def cache_path(self, url: str, os_type: str) -> Path:
        """Where cached_download keeps the file for a URL."""
        self.verifier.git_hash = GIT_HASH
        self.verifier.init_cache()
        netloc = url.split("://", 1)[1].split("/", 1)[0]
        return self.verifier.cache_for_this_hash / netloc / os_type / url.rsplit("/", 1)[1]

    def download(self, url: str = "https://cdn/img", os_type: str = "guest-os") -> Path:
        return self.verifier.cached_download(url, self.tmp_dir / "out" / url.rsplit("/", 1)[1], os_type)

    def test_a_record_without_a_strong_etag_is_a_miss(self):
        """Recorded by a version of this script that also accepted weaker validators."""
        weak = {"Last-Modified": "Fri, 18 Sep 2026 15:50:01 GMT", "Content-Length": "12"}
        self.verifier.write_cache_validator(self.cache_file, weak)
        self.stub_validator(weak)

        with self.assertNoLogs(repro_check.logger, level="WARNING"):
            self.assertFalse(self.verifier.cached_copy_is_current("https://cdn/img", self.cache_file))

    def test_the_validator_is_sampled_before_the_download_and_recorded_after_it(self):
        """
        Sampled after the GET it could describe an object the CDN began serving during the
        download, blessing bytes this run never had. Recorded before the GET it would outlive a
        failed one (next test).
        """
        record = self.verifier.validator_path(self.cache_path("https://cdn/img", "guest-os"))
        order = []
        mock.patch.object(
            repro_check, "fetch_url_validator", lambda url: order.append("head") or {"ETag": '"a"'}
        ).start()

        def get(url, dest):
            order.append("get" if not record.exists() else "get, with the record already written")
            dest.write_bytes(b"x")
            return dest

        mock.patch.object(repro_check, "fetch_url_to_file", get).start()

        self.download()

        self.assertEqual(order, ["head", "get"])
        self.assertEqual(json.loads(record.read_text()), {"ETag": '"a"'})

    def test_a_failed_redownload_leaves_neither_the_stale_bytes_nor_a_record_behind(self):
        """
        The CDN changed and the replacement download failed. The previous bytes must not stay in
        the cache under the CDN's new validator (the next run would take them for current), nor
        without one (a stale copy must not be what a later run compares against).
        """
        cache_file = self.cache_path("https://cdn/img", "guest-os")
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_bytes(b"previous image")
        self.stub_validator({"ETag": '"a"'})
        self.verifier.write_cache_validator(cache_file, {"ETag": '"a"'})
        self.stub_validator({"ETag": '"b"'})
        mock.patch.object(
            repro_check, "fetch_url_to_file", mock.Mock(side_effect=RuntimeError("connection reset"))
        ).start()

        with self.assertRaises(RuntimeError):
            self.download()

        self.assertFalse(cache_file.exists())
        self.assertFalse(self.verifier.validator_path(cache_file).exists())

    def test_a_download_without_a_validator_drops_the_previous_record(self):
        """An old record next to new bytes would turn the next run's HEAD comparison into noise."""
        cache_file = self.cache_path("https://cdn/img", "guest-os")
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_bytes(b"")  # An empty cached file counts as a miss.
        self.verifier.write_cache_validator(cache_file, {"ETag": '"a"'})
        self.stub_validator(None)

        def get(url, dest):
            dest.write_bytes(b"x")
            return dest

        mock.patch.object(repro_check, "fetch_url_to_file", get).start()

        self.download()

        self.assertEqual(cache_file.read_bytes(), b"x")
        self.assertFalse(self.verifier.validator_path(cache_file).exists())


class GhArgvTest(unittest.TestCase):
    """The gh invocation is positional and load-bearing; pin it so a reorder cannot slip through."""

    def test_exact_argv(self):
        argv = repro_check.gh_attestation_verify_argv(
            Path("/tmp/gh"), Path("/tmp/SHA256SUMS"), Path("/tmp/bundles.jsonl"), GIT_HASH
        )

        self.assertEqual(
            argv,
            [
                "/tmp/gh",
                "attestation",
                "verify",
                "/tmp/SHA256SUMS",
                "--repo",
                "dfinity/ic",
                "--bundle",
                "/tmp/bundles.jsonl",
                "--signer-workflow",
                "dfinity/ic/.github/workflows/ci-main.yml",
                "--source-digest",
                GIT_HASH,
                "--format",
                "json",
            ],
        )

    def test_never_denies_self_hosted_runners(self):
        """The release builds run on self-hosted runners; the flag would reject every attestation."""
        argv = repro_check.gh_attestation_verify_argv(Path("gh"), Path("s"), Path("b"), GIT_HASH)
        self.assertNotIn("--deny-self-hosted-runners", argv)

    def test_gh_env_drops_credentials_and_isolates_the_config(self):
        caller = {
            "GH_TOKEN": "t",
            "GITHUB_TOKEN": "u",
            # GH_HOST would point the verification at a GitHub Enterprise instance, where these
            # attestations do not exist, turning a benign environment into a hard failure.
            "GH_HOST": "github.example.com",
            "GH_ENTERPRISE_TOKEN": "v",
            "GITHUB_ENTERPRISE_TOKEN": "w",
            "PATH": "/bin",
            "HTTPS_PROXY": "http://proxy:3128",
            "SSL_CERT_FILE": "/etc/ssl/certs/ca.pem",
        }
        with mock.patch.dict(os.environ, caller, clear=True):
            env = repro_check.gh_env(Path("/tmp/cfg"))

        for leaked in ("GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"):
            self.assertNotIn(leaked, env)
        self.assertEqual(env["GH_CONFIG_DIR"], "/tmp/cfg")
        # Proxy and CA settings must survive: without them gh cannot reach Sigstore at all.
        self.assertEqual(env["PATH"], "/bin")
        self.assertEqual(env["HTTPS_PROXY"], "http://proxy:3128")
        self.assertEqual(env["SSL_CERT_FILE"], "/etc/ssl/certs/ca.pem")


class RunGhAttestationVerifyTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp_dir, True)
        self.sums = self.tmp_dir / "SHA256SUMS"
        self.sums.write_bytes(b"sums")

    def stub_run(self, returncode: int, stdout: str = "", stderr: str = ""):
        completed = mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)
        return mock.patch.object(repro_check.subprocess, "run", mock.Mock(return_value=completed)).start()

    def verify(self):
        return repro_check.run_gh_attestation_verify(
            Path("gh"), self.sums, self.tmp_dir / "b.jsonl", GIT_HASH, self.tmp_dir / "cfg"
        )

    def test_gh_runs_with_the_sanitised_environment_and_a_timeout(self):
        """Nothing else asserts that the env gh_env() builds actually reaches the subprocess."""
        run = self.stub_run(0, stdout="[]")
        with mock.patch.dict(os.environ, {"GH_TOKEN": "t", "GH_HOST": "github.example.com"}):
            self.verify()

        env = run.call_args.kwargs["env"]
        self.assertNotIn("GH_TOKEN", env)
        self.assertNotIn("GH_HOST", env)
        self.assertEqual(env["GH_CONFIG_DIR"], str(self.tmp_dir / "cfg"))
        self.assertIsNotNone(run.call_args.kwargs["timeout"])

    def test_parses_stdout(self):
        self.stub_run(0, stdout=json.dumps([{"verificationResult": {}}]))
        self.assertEqual(self.verify(), [{"verificationResult": {}}])

    # The stderr strings below are verbatim output of the pinned gh 2.98.0, captured by running it
    # against the real rc bundles of 2967c1cc9b, and kept as documentation of what a verifier will
    # see: a wrong --source-digest, a tampered file or a non-matching signer, a Sigstore setup
    # failure, an empty bundle. Every one of them aborts, and the message quotes gh and gives both
    # readings, since gh has no exit code separating "failed to verify" from "could not be set up".

    def test_a_non_zero_exit_aborts_with_ghs_own_words(self):
        cases = [
            (
                "\x1b[31mError: expected SourceRepositoryDigest to be "
                "0000000000000000000000000000000000000000, got 2967c1cc9ba88fd85f196a09d05ea941bbabe830\x1b[0m"
            ),
            'Error: verifying with issuer "sigstore.dev"',
            "error creating Sigstore verifier: no valid Sigstore verifiers could be initialized",
            "Error: bundle content could not be parsed: provided bundle file is empty",
        ]
        for stderr in cases:
            with self.subTest(stderr=stderr):
                self.stub_run(1, stderr=stderr)

                with self.assertRaises(repro_check.VerificationError) as raised:
                    self.verify()

                message = str(raised.exception)
                self.assertIn(repro_check.sanitize_output(stderr), message)
                self.assertNotIn("\x1b", message)
                # Both readings, for the reader to match against gh's words.
                self.assertIn("Sigstore verifiers could be initialized", message)
                self.assertIn("SourceRepositoryDigest", message)
                self.assertNotIn("--skip-attestation-check", message)

    def test_a_gh_that_cannot_be_executed_aborts(self):
        mock.patch.object(repro_check.subprocess, "run", mock.Mock(side_effect=OSError("noexec"))).start()

        with self.assertRaises(repro_check.VerificationError) as raised:
            self.verify()

        self.assertIn("could not run", str(raised.exception))

    def test_unparseable_output_aborts(self):
        self.stub_run(0, stdout="not json")

        with self.assertRaises(repro_check.VerificationError):
            self.verify()

    def test_a_non_list_or_non_object_shape_aborts(self):
        for stdout in ('{"verificationResult": {}}', "[null]", '["nope"]', "[1]"):
            with self.subTest(stdout=stdout):
                self.stub_run(0, stdout=stdout)
                with self.assertRaises(repro_check.VerificationError):
                    self.verify()


class NetworkTimeoutTest(unittest.TestCase):
    """
    Every urlopen must be bounded. Without a timeout a connection that is accepted and then
    stalls hangs the run forever instead of failing it.
    """

    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp_dir, True)
        self.timeouts = []

        def fake_urlopen(req, timeout=None):
            self.timeouts.append(timeout)
            return FakeResponse(b'{"payload": {}}')

        mock.patch.object(repro_check.urllib.request, "urlopen", fake_urlopen).start()

    def test_downloads_are_bounded(self):
        repro_check.fetch_url_to_file("https://example.com/x", self.tmp_dir / "x")
        self.assertEqual(self.timeouts, [repro_check.NETWORK_TIMEOUT_SECONDS])

    def test_the_validator_head_is_bounded(self):
        repro_check.fetch_url_validator("https://example.com/x")
        self.assertEqual(self.timeouts, [repro_check.NETWORK_TIMEOUT_SECONDS])

    def test_the_attestations_api_is_bounded(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            try:
                repro_check.fetch_attestation_bundles("e" * 64)
            except repro_check.VerificationError:
                pass
        self.assertEqual(self.timeouts, [repro_check.NETWORK_TIMEOUT_SECONDS])

    def test_a_stalled_download_of_gh_aborts_rather_than_hangs(self):
        """A timeout during the gh bootstrap must fail the run, not hang it."""
        verifier = repro_check.ReproducibilityVerifier(
            verify_guestos=True,
            verify_hostos=False,
            verify_setupos=False,
            verify_recovery=False,
            proposal_id="",
            git_commit=GIT_HASH,
            download_source_mode="systems",
            base_cache_dir=self.tmp_dir / "cache",
            clean_base_cache_dir=False,
            keep_temp=False,
        )
        self.addCleanup(verifier.download_executor.shutdown)
        verifier.git_hash = GIT_HASH
        verifier.init_cache()
        dirs = repro_check.Dirs(self.tmp_dir, self.tmp_dir, self.tmp_dir, self.tmp_dir, self.tmp_dir)
        mock.patch.object(repro_check, "fetch_url_to_file", mock.Mock(side_effect=RuntimeError("timed out"))).start()

        with self.assertRaises(repro_check.VerificationError) as raised:
            verifier.ensure_gh(dirs)

        self.assertIn("timed out", str(raised.exception))


class MainExitCodeTest(unittest.TestCase):
    """An attestation that cannot be obtained exits like a mismatch; a download failure as before."""

    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp_dir, True)
        argv = ["repro-check", "-c", GIT_HASH, "--cache-dir", str(self.tmp_dir)]
        mock.patch.object(repro_check.sys, "argv", argv).start()
        # conventional_logging replaces the root handlers, which would silence the test runner.
        mock.patch.object(repro_check, "conventional_logging").start()

    def exit_code_for(self, error: Exception) -> int:
        mock.patch.object(repro_check.ReproducibilityVerifier, "run", mock.Mock(side_effect=error)).start()
        with self.assertRaises(SystemExit) as raised:
            repro_check.main()
        return raised.exception.code

    def test_an_unobtainable_attestation_exits_1_like_a_mismatch(self):
        self.assertEqual(self.exit_code_for(repro_check.VerificationError("GitHub holds no attestation")), 1)

    def test_a_download_failure_exits_2(self):
        self.assertEqual(self.exit_code_for(RuntimeError("Could not download")), 2)


class InterruptedDownloadTest(unittest.TestCase):
    """An interrupted multi-GB download must abort rather than return a bogus path."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp_dir, True)
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(setattr, repro_check, "interrupted", False)

    def test_raises_once_interrupted(self):
        class SlowResponse(FakeResponse):
            """
            Yields the body in chunks, tripping the interrupt on the first one.

            Finite on purpose: a stub that returns forever would make a regression of the
            interrupt check hang the suite instead of failing it by name.
            """

            def read(self, *args):
                repro_check.interrupted = True
                chunk, self._content = self._content[:1024], self._content[1024:]
                return chunk

        mock.patch.object(
            repro_check.urllib.request, "urlopen", lambda req, timeout=None: SlowResponse(b"x" * 4096)
        ).start()

        with self.assertRaises(RuntimeError) as raised:
            repro_check.fetch_url_to_file("https://example.com/img", self.tmp_dir / "img")

        self.assertIn("interrupted", str(raised.exception))
        self.assertFalse((self.tmp_dir / "img").exists())
        self.assertFalse((self.tmp_dir / "img.part").exists())


if __name__ == "__main__":
    unittest.main()
