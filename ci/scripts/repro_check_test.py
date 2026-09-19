"""Tests for the proposal handling and the local-build verification in ci/scripts/repro-check."""

import gzip
import hashlib
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
        # Digests for which GitHub holds no attestation, to test per-directory degradation.
        self.unavailable_digests: set[str] = set()
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
        mock.patch.object(repro_check.urllib.request, "urlopen", lambda req: FakeResponse(proposal)).start()
        mock.patch.object(repro_check, "fetch_url_to_file", self.fake_fetch).start()
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
        if digest in self.unavailable_digests:
            raise repro_check.AttestationUnavailable("GitHub holds no build-provenance attestation")
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
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_bytes(self.cdn[url])
        return dest_path

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
            "GuestOS update image, GuestOS launch measurements, SetupOS disk image",
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
        # The multi-hour build must not have been started for a substituted artifact.
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

    def test_one_unattested_directory_does_not_hide_a_substitution_in_the_next(self):
        """
        A 404 on one directory must not abort the loop: the remaining directories still have to be
        checked, or an attacker could mask a substitution by making an earlier lookup fail.
        """
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        guest_digest = self.sums_digest("guest-os", "update-img")
        host_digest = self.sums_digest("host-os", "update-img")
        self.unavailable_digests = {guest_digest}
        # host-os is attested as some OTHER directory's SHA256SUMS: a cross-directory substitution.
        self.entries_for = {host_digest: [gh_entry({f"ic/{GIT_HASH}/setup-os/disk-img/SHA256SUMS": host_digest})]}

        with self.assertRaises(repro_check.VerificationError) as raised:
            verifier.run()

        self.assertIn("host-os/update-img/SHA256SUMS", str(raised.exception))
        self.assertFalse(self.build_ran)

    def test_an_unreadable_gh_shape_degrades_only_that_directory(self):
        """
        select_attested_entry's AttestationUnavailable must be handled per directory too, or an
        unrecognised gh shape on one directory would hide a substitution on the next.
        """
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        guest_digest = self.sums_digest("guest-os", "update-img")
        host_digest = self.sums_digest("host-os", "update-img")
        self.entries_for = {
            guest_digest: [{"someShapeThisScriptCannotRead": {}}],
            host_digest: [gh_entry({f"ic/{GIT_HASH}/setup-os/disk-img/SHA256SUMS": host_digest})],
        }

        with self.assertRaises(repro_check.VerificationError) as raised:
            verifier.run()

        self.assertIn("host-os/update-img/SHA256SUMS", str(raised.exception))
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

    def test_tokens_are_dropped_even_when_the_preflight_warns(self):
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        verifier.ensure_gh = mock.Mock(side_effect=repro_check.AttestationUnavailable("no gh"))

        with mock.patch.dict(os.environ, {"GH_TOKEN": "secret"}):
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

    # ---- the warn path: none of these may fail the run ----------------------

    def assert_warns_and_completes(self, verifier, needle: str):
        with self.assertLogs(repro_check.logger, level="WARNING") as logs:
            # Deliberately not assertRaises: an AttestationUnavailable escaping run() must fail.
            verifier.run()
        self.assertTrue(self.build_ran)
        self.assertTrue(any(needle in line for line in logs.output), logs.output)

    def test_missing_attestation_only_warns(self):
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        self.bundles_error = repro_check.AttestationUnavailable("GitHub holds no build-provenance attestation")

        self.assert_warns_and_completes(verifier, "no build-provenance attestation")

    def test_rate_limited_api_only_warns(self):
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        self.bundles_error = repro_check.AttestationUnavailable("the GitHub API rate limit is exhausted")

        self.assert_warns_and_completes(verifier, "rate limit is exhausted")

    def test_unreachable_api_only_warns(self):
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        self.bundles_error = repro_check.AttestationUnavailable("could not reach the GitHub attestations API")

        self.assert_warns_and_completes(verifier, "could not reach the GitHub attestations API")

    def test_failing_gh_bootstrap_only_warns(self):
        """
        Regression guard: ensure_gh runs outside verify_cdn_attestations, so its warn path must be
        caught by the same handler rather than escaping as an uncaught exception.
        """
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        verifier.ensure_gh = mock.Mock(side_effect=repro_check.AttestationUnavailable("could not download gh"))

        self.assert_warns_and_completes(verifier, "could not download gh")
        self.assertEqual(self.fetch_calls, [])

    def test_failing_gh_bootstrap_only_warns_in_dry_run(self):
        verifier = self.build_verifier(self.guestos_payload(MEASUREMENTS))
        verifier.ensure_gh = mock.Mock(side_effect=repro_check.AttestationUnavailable("could not download gh"))

        with self.assertLogs(repro_check.logger, level="WARNING") as logs:
            verifier.run(dry_run=True)

        self.assertTrue(self.build_ran)
        self.assertTrue(any("could not download gh" in line for line in logs.output), logs.output)

    def test_unusable_git_hash_only_warns(self):
        verifier = self.build_verifier({}, proposal_id="", git_commit=GIT_HASH)
        verifier.git_hash = "abc"
        mock.patch.object(verifier, "decide_git_hash").start()
        # The CDN is keyed on the real hash; serve the same bytes for the truncated one.
        self.cdn.update({url.replace(GIT_HASH, "abc"): body for url, body in self.cdn.items()})

        self.assert_warns_and_completes(verifier, "not a 40-character git commit id")
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

    def test_an_unrecognised_json_shape_is_unavailable_not_evidence(self):
        """A gh output this script cannot read is our problem, not evidence of substitution."""
        with self.assertRaises(repro_check.AttestationUnavailable):
            self.select([{"someNewShape": {}}])

    def test_malformed_entries_never_crash(self):
        """Shape surprises must land in the AttestationUnavailable branch, not raise AttributeError."""
        for entries in (
            [None],
            ["nope"],
            [{"verificationResult": "oops"}],
            [{"verificationResult": {"signature": "oops"}}],
            [{"verificationResult": {"signature": {"certificate": "oops"}}}],
        ):
            with self.subTest(entries=entries), self.assertRaises(repro_check.AttestationUnavailable):
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

    def test_404_is_unavailable_not_a_verification_error(self):
        self.serve(self.http_error(404))

        with self.assertRaises(repro_check.AttestationUnavailable):
            repro_check.fetch_attestation_bundles(self.DIGEST)

    def test_empty_list_is_unavailable(self):
        self.serve(self.page([]))

        with self.assertRaises(repro_check.AttestationUnavailable):
            repro_check.fetch_attestation_bundles(self.DIGEST)

    def test_retries_a_server_error(self):
        self.serve(self.http_error(503), self.page([{"a": 1}]))

        self.assertEqual(repro_check.fetch_attestation_bundles(self.DIGEST), [{"a": 1}])

    def test_gives_up_after_three_network_errors(self):
        err = urllib.error.URLError("no route to host")
        self.serve(err, err, err)

        with self.assertRaises(repro_check.AttestationUnavailable) as raised:
            repro_check.fetch_attestation_bundles(self.DIGEST)

        self.assertIn("could not reach", str(raised.exception))

    def test_exhausted_rate_limit_names_gh_token_and_is_not_retried(self):
        self.serve(self.http_error(403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1700000000"}))

        with self.assertRaises(repro_check.AttestationUnavailable) as raised:
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

    def test_follows_the_next_cursor(self):
        nxt = f'<{self.URL}&after=cursor>; rel="next", <{self.URL}>; rel="last"'
        self.serve(self.page([{"a": 1}], link=nxt), self.page([{"b": 2}]))

        self.assertEqual(repro_check.fetch_attestation_bundles(self.DIGEST), [{"a": 1}, {"b": 2}])
        self.assertEqual(self.requests[1].full_url, f"{self.URL}&after=cursor")

    def test_caps_the_number_of_pages(self):
        """An insider minting attestations must not be able to make this page forever."""
        link = f'<{self.URL}&after=x>; rel="next"'
        self.serve(*[self.page([{"a": 1}], link=link) for _ in range(repro_check.ATTESTATION_MAX_PAGES)])

        with self.assertRaises(repro_check.AttestationUnavailable) as raised:
            repro_check.fetch_attestation_bundles(self.DIGEST)

        self.assertIn("refusing to page through them", str(raised.exception))

    def test_unavailable_is_not_a_verification_error(self):
        """The warn/fail split must not regress into 'everything fails' or 'everything warns'."""
        self.assertFalse(issubclass(repro_check.AttestationUnavailable, repro_check.VerificationError))
        self.assertFalse(issubclass(repro_check.AttestationUnavailable, RuntimeError))


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

    def test_min_version_is_the_first_release_with_source_digest(self):
        self.assertEqual(repro_check.GH_CLI_MIN_VERSION, (2, 68, 0))

    def test_parse_gh_version(self):
        self.assertEqual(repro_check.parse_gh_version("gh version 2.98.0 (2026-08-20)"), (2, 98, 0))
        self.assertEqual(repro_check.parse_gh_version("gh version 2.4.0+dfsg1 (2022-03-23)"), (2, 4, 0))
        self.assertIsNone(repro_check.parse_gh_version("gh version DEV"))
        self.assertIsNone(repro_check.parse_gh_version("bash: gh: command not found"))
        self.assertIsNone(repro_check.parse_gh_version(""))

    def use_path_gh(self, path: str | None, version_output: str = ""):
        mock.patch.object(repro_check.shutil, "which", lambda name: path).start()
        mock.patch.object(self.verifier, "gh_version_output", lambda gh: version_output).start()
        return mock.patch.object(self.verifier, "download_gh", mock.Mock(return_value=Path("/downloaded/gh"))).start()

    def test_uses_a_recent_path_gh(self):
        for version in ("2.98.0", "2.68.0"):
            with self.subTest(version=version):
                download = self.use_path_gh("/usr/bin/gh", f"gh version {version} (2026-01-01)")
                self.assertEqual(self.verifier.ensure_gh(self.dirs), Path("/usr/bin/gh"))
                download.assert_not_called()

    def test_downloads_when_the_path_gh_is_unusable(self):
        cases = [
            (None, ""),
            ("/usr/bin/gh", "gh version 2.67.0 (2026-01-01)"),
            ("/usr/bin/gh", "gh version 2.4.0+dfsg1 (2022-03-23)"),
            ("/usr/bin/gh", "gh version DEV"),
            ("/snap/bin/gh", "gh version 2.98.0 (2026-08-20)"),
        ]
        for path, output in cases:
            with self.subTest(path=path, output=output):
                download = self.use_path_gh(path, output)
                self.assertEqual(self.verifier.ensure_gh(self.dirs), Path("/downloaded/gh"))
                download.assert_called_once()

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

        gh_path = self.verifier.download_gh(self.dirs)

        self.assertEqual(gh_path, self.dirs.tmp_dir / "gh")
        self.assertTrue(os.access(gh_path, os.X_OK))
        # Only the member we asked for was written out.
        self.assertFalse((self.dirs.tmp_dir / f"gh_{repro_check.GH_CLI_VERSION}_linux_amd64").exists())
        self.assertEqual(repro_check.parse_gh_version(self.verifier.gh_version_output(str(gh_path))), (2, 98, 0))

    def test_a_tarball_failing_the_pin_is_rejected_and_uncached(self):
        payload = self.make_tarball(b"#!/bin/sh\ntrue\n")
        self.stub_download(payload)  # GH_CLI_SHA256 deliberately NOT patched.

        with self.assertRaises(repro_check.AttestationUnavailable) as raised:
            self.verifier.download_gh(self.dirs)

        self.assertIn("pinned sha256", str(raised.exception))
        self.assertFalse((self.dirs.tmp_dir / "gh").exists())
        self.assertFalse((self.verifier.cache_for_this_hash / "github.com" / "tools" / "gh_cli.tar.gz").exists())

    def test_an_unrunnable_gh_is_unavailable_not_evidence(self):
        payload = self.make_tarball(b"not an executable")
        self.stub_download(payload)
        mock.patch.object(repro_check, "GH_CLI_SHA256", sha256_hex(payload)).start()

        with self.assertRaises(repro_check.AttestationUnavailable) as raised:
            self.verifier.download_gh(self.dirs)

        self.assertIn("does not run", str(raised.exception))


class GhVerifyRetryTest(unittest.TestCase):
    """
    The evidence markers are calibrated against the pinned gh, but a PATH gh may be any release
    >= 2.68. An unclassifiable failure from an unpinned gh must be redone with the pinned one, or
    a real mismatch would silently degrade to a warning.
    """

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
        self.dirs = repro_check.Dirs(self.tmp_dir, self.tmp_dir, self.tmp_dir, self.tmp_dir, self.tmp_dir)
        self.calls = []

    def stub_verify(self, *outcomes):
        queue = list(outcomes)

        def verify(gh, sums_file, bundle_file, commit, config_dir):
            self.calls.append(str(gh))
            outcome = queue.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        mock.patch.object(repro_check, "run_gh_attestation_verify", verify).start()

    def call(self):
        return self.verifier.gh_verify(self.dirs, self.tmp_dir / "s", self.tmp_dir / "b", self.tmp_dir / "cfg")

    def test_an_unpinned_gh_that_cannot_be_classified_is_redone_with_the_pinned_one(self):
        self.verifier.gh, self.verifier.gh_is_pinned = Path("/usr/bin/gh"), False
        self.stub_verify(
            repro_check.AttestationUnavailable("unrecognised failure"),
            repro_check.VerificationError("expected SourceRepositoryDigest to be ..."),
        )
        mock.patch.object(self.verifier, "download_gh", mock.Mock(return_value=Path("/tmp/pinned/gh"))).start()

        with self.assertRaises(repro_check.VerificationError):
            self.call()

        self.assertEqual(self.calls, ["/usr/bin/gh", "/tmp/pinned/gh"])
        self.assertTrue(self.verifier.gh_is_pinned)

    def test_the_pinned_gh_is_not_retried(self):
        self.verifier.gh, self.verifier.gh_is_pinned = Path("/tmp/pinned/gh"), True
        self.stub_verify(repro_check.AttestationUnavailable("sigstore is down"))
        download = mock.patch.object(self.verifier, "download_gh", mock.Mock()).start()

        with self.assertRaises(repro_check.AttestationUnavailable):
            self.call()

        self.assertEqual(len(self.calls), 1)
        download.assert_not_called()

    def test_a_verification_error_from_an_unpinned_gh_is_not_retried(self):
        """It was classified as evidence; re-running would only cost a download."""
        self.verifier.gh, self.verifier.gh_is_pinned = Path("/usr/bin/gh"), False
        self.stub_verify(repro_check.VerificationError("verifying with issuer"))
        download = mock.patch.object(self.verifier, "download_gh", mock.Mock()).start()

        with self.assertRaises(repro_check.VerificationError):
            self.call()

        self.assertEqual(len(self.calls), 1)
        download.assert_not_called()


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
        mock.patch.object(repro_check.subprocess, "run", mock.Mock(return_value=completed)).start()

    def verify(self):
        return repro_check.run_gh_attestation_verify(
            Path("gh"), self.sums, self.tmp_dir / "b.jsonl", GIT_HASH, self.tmp_dir / "cfg"
        )

    def test_parses_stdout(self):
        self.stub_run(0, stdout=json.dumps([{"verificationResult": {}}]))
        self.assertEqual(self.verify(), [{"verificationResult": {}}])

    # The stderr strings below are verbatim output of the pinned gh 2.98.0, captured by running it
    # against the real rc bundles of 2967c1cc9b. Do not paraphrase them: an earlier version of this
    # test invented plausible-looking text, which kept the suite green while every real Sigstore
    # outage hard-failed. Re-capture them when bumping GH_CLI_VERSION.

    def test_a_wrong_source_digest_is_evidence(self):
        """The message gh prints when the bytes are attested, but for a different commit."""
        self.stub_run(
            1,
            stderr=(
                "\x1b[31mError: expected SourceRepositoryDigest to be "
                "0000000000000000000000000000000000000000, got 2967c1cc9ba88fd85f196a09d05ea941bbabe830\x1b[0m"
            ),
        )

        with self.assertRaises(repro_check.VerificationError) as raised:
            self.verify()

        self.assertIn("expected SourceRepositoryDigest to be", str(raised.exception))
        self.assertNotIn("\x1b", str(raised.exception))

    def test_a_failed_signature_check_is_evidence(self):
        """The message gh prints when the file was tampered with, or no bundle carries the signer."""
        self.stub_run(1, stderr='Error: verifying with issuer "sigstore.dev"')

        with self.assertRaises(repro_check.VerificationError):
            self.verify()

    def test_a_sigstore_init_failure_is_unavailable_not_evidence(self):
        """No bundle was ever examined: tuf-repo-cdn.sigstore.dev is unreachable, or its cache is."""
        self.stub_run(1, stderr="error creating Sigstore verifier: no valid Sigstore verifiers could be initialized")

        with self.assertRaises(repro_check.AttestationUnavailable):
            self.verify()

    def test_an_unrecognised_gh_failure_defaults_to_unavailable(self):
        """
        The default has to be "not evidence": the local build still catches a substitution, so a gh
        message this script does not know must not block the run.
        """
        self.stub_run(1, stderr="Error: bundle content could not be parsed: provided bundle file is empty")

        with self.assertRaises(repro_check.AttestationUnavailable):
            self.verify()

    def test_unparseable_output_is_unavailable(self):
        self.stub_run(0, stdout="not json")

        with self.assertRaises(repro_check.AttestationUnavailable):
            self.verify()

    def test_a_non_list_or_non_object_shape_is_unavailable(self):
        for stdout in ('{"verificationResult": {}}', "[null]", '["nope"]', "[1]"):
            with self.subTest(stdout=stdout):
                self.stub_run(0, stdout=stdout)
                with self.assertRaises(repro_check.AttestationUnavailable):
                    self.verify()


class InterruptedDownloadTest(unittest.TestCase):
    """An interrupted multi-GB download must abort rather than return a bogus path."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp_dir, True)
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(setattr, repro_check, "interrupted", False)

    def test_raises_once_interrupted(self):
        class SlowResponse(FakeResponse):
            def read(self, *args):
                repro_check.interrupted = True
                return b"x" * 1024

        mock.patch.object(repro_check.urllib.request, "urlopen", lambda req: SlowResponse(b"x" * 4096)).start()

        with self.assertRaises(RuntimeError) as raised:
            repro_check.fetch_url_to_file("https://example.com/img", self.tmp_dir / "img")

        self.assertIn("interrupted", str(raised.exception))
        self.assertFalse((self.tmp_dir / "img").exists())
        self.assertFalse((self.tmp_dir / "img.part").exists())


if __name__ == "__main__":
    unittest.main()
