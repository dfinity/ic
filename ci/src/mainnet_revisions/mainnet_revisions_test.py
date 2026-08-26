"""
Tests for the validation of the values written to mainnet-icos-revisions.json.

The version and the hashes come from the public dashboard API and from CDN-served
SHA256SUMS files, and the PR that records them is auto-approved and auto-merged. They
are interpolated into download URLs by //bazel:mainnet-icos-*.bzl, so a value that is
not exactly a commit id / sha256 / plain name must be rejected here, before it can
reach a PR (F-051).

Also tests VersionArtifactSums, the choke point that verifies CDN-served SHA256SUMS
against the build's provenance attestation before any hash is recorded (finding
3618194): attested for public commits (hard requirement), CDN fallback with a loud
warning only for versions whose commit is not public yet.
"""

import hashlib
import io
import logging
import subprocess
import urllib.error
import urllib.request

import mainnet_revisions
import pytest
from mainnet_revisions import (
    VersionArtifactSums,
    VersionInfo,
    check_elected_hash_against_build,
    get_binary_hashes,
    parse_sha256sums,
)

VERSION = "79c01052b5f7f49d3cf53d04d696cb2893294cd3"
HASH = "5e67e60caf8b71d79f6f2300ceb2461086d9d763cabc5656175307c13a4410e2"
BINARIES = {
    "canister_sandbox": "2a2e8891dc8837b02b1bf00972b71e5e8393fc5334ac611638071bc151b37cfc",
    "ic-replay": "6fc9e9b24e74690964357ac1681d4dcfac1c7907af6fbdd4d24a45e986d56ee5",
}


def version_info(**overrides) -> VersionInfo:
    fields = dict(
        version=VERSION,
        hash=HASH,
        dev_hash=HASH,
        launch_measurements={"guest_launch_measurements": []},
        dev_measurements={"guest_launch_measurements": []},
        setupos_hash=HASH,
        setupos_dev_hash=HASH,
        binaries=dict(BINARIES),
    )
    fields.update(overrides)
    return VersionInfo(**fields)


def test_accepts_real_values():
    assert version_info().version == VERSION


def test_accepts_arbitrary_launch_measurements():
    # Not validated on purpose: arbitrary JSON by design, and not interpolated into a
    # URL or a file name.
    assert version_info(launch_measurements={"whatever": [1, 2, 3]}).version == VERSION


@pytest.mark.parametrize(
    "overrides",
    [
        # A version that escapes the pinned CDN prefix, or selects another artifact.
        pytest.param({"version": "../../../../evil/guest-os/update-img"}, id="traversing version"),
        pytest.param({"version": VERSION.upper()}, id="uppercase version"),
        pytest.param({"version": VERSION[:-1]}, id="short version"),
        pytest.param({"version": None}, id="missing version"),
        pytest.param({"version": 79}, id="non-string version"),
        # The empty string makes repository_ctx.download skip verification.
        pytest.param({"hash": ""}, id="empty hash"),
        pytest.param({"dev_hash": "not-a-hash"}, id="malformed dev_hash"),
        pytest.param({"setupos_hash": None}, id="missing setupos_hash"),
        pytest.param({"setupos_dev_hash": HASH.upper()}, id="uppercase setupos_dev_hash"),
        pytest.param({"binaries": {"../../../evil/ic-replay": HASH}}, id="traversing binary name"),
        pytest.param({"binaries": {'ic-replay"]) load("@evil//:evil.bzl", "evil")': HASH}}, id="injecting binary name"),
        pytest.param({"binaries": {"ic-replay": ""}}, id="empty binary hash"),
        pytest.param({"binaries": ["ic-replay"]}, id="non-dict binaries"),
    ],
)
def test_rejects_poisoned_values(overrides):
    with pytest.raises(ValueError):
        version_info(**overrides)


def test_parse_sha256sums_single_space():
    # The CDN SHA256SUMS files produced by the artifact_bundle rule use a single
    # space between hash and filename (unlike sha256sum's two spaces).
    assert parse_sha256sums(f"{HASH} update-img.tar.zst\n") == {"update-img.tar.zst": HASH}
    assert parse_sha256sums(f"{HASH}  update-img.tar.zst\n") == {"update-img.tar.zst": HASH}


ATTESTATION_FAILED = subprocess.CalledProcessError(1, "gh attestation verify")


def sums_with(monkeypatch, *, attested=None, cdn=None, public=True):
    """
    A VersionArtifactSums whose collaborators are stubbed out.

    `attested`: {subdir: {filename: hash}} served by the (verified) attested path,
    or None to make attestation verification fail. `cdn`: the same, served by the
    unverified CDN fallback. `public`: whether the commit exists in dfinity/ic.
    """

    def fake_attested(version, subdir):
        assert version == VERSION
        if attested is None:
            raise ATTESTATION_FAILED
        return dict(attested[subdir])

    def fake_cdn(url):
        assert url.startswith(f"{mainnet_revisions.CDN_BASE_URL}/ic/{VERSION}/")
        subdir = url.removeprefix(f"{mainnet_revisions.CDN_BASE_URL}/ic/{VERSION}/").removesuffix("/SHA256SUMS")
        assert cdn is not None, "unexpected CDN fallback"
        return dict(cdn[subdir])

    monkeypatch.setattr(mainnet_revisions, "fetch_attested_sha256sums", fake_attested)
    monkeypatch.setattr(mainnet_revisions, "download_sha256sums", fake_cdn)
    monkeypatch.setattr(mainnet_revisions, "commit_is_public", lambda version: public)
    return VersionArtifactSums(VERSION)


def test_attested_sums_are_used(monkeypatch):
    sums = sums_with(monkeypatch, attested={"canisters": {"a.wasm.gz": HASH}})
    assert sums.file_sha256("canisters", "a.wasm.gz") == HASH
    assert sums.attested is True


def test_missing_sums_entry_raises(monkeypatch):
    sums = sums_with(monkeypatch, attested={"canisters": {}})
    with pytest.raises(Exception, match="No sha256 for a.wasm.gz"):
        sums.file_sha256("canisters", "a.wasm.gz")


def test_public_commit_without_attestation_hard_fails(monkeypatch):
    # An unattested public commit must never fall back to CDN-served hashes:
    # the operator backfills the attestation by re-running release-testing.
    sums = sums_with(monkeypatch, attested=None, cdn={"canisters": {"a.wasm.gz": HASH}}, public=True)
    with pytest.raises(Exception, match="Refusing to record CDN-served hashes"):
        sums.file_sha256("canisters", "a.wasm.gz")


def test_private_commit_falls_back_with_warning(monkeypatch, caplog):
    # An undisclosed security patch (commit not in the public repo) keeps the
    # pre-attestation behavior, loudly.
    sums = sums_with(monkeypatch, attested=None, cdn={"canisters": {"a.wasm.gz": HASH}}, public=False)
    with caplog.at_level(logging.WARNING, logger="logger"):
        assert sums.file_sha256("canisters", "a.wasm.gz") == HASH
    assert any("UNVERIFIED" in r.message for r in caplog.records)
    assert sums.attested is False


def test_no_fallback_once_attested(monkeypatch):
    # If one directory of a build verified, a verification failure on another
    # directory of the same build is an error, never a CDN fallback.
    state = {"calls": 0}

    def flaky_attested(version, subdir):
        state["calls"] += 1
        if state["calls"] > 1:
            raise ATTESTATION_FAILED
        return {"a.wasm.gz": HASH}

    monkeypatch.setattr(mainnet_revisions, "fetch_attested_sha256sums", flaky_attested)
    monkeypatch.setattr(mainnet_revisions, "commit_is_public", lambda version: False)
    sums = VersionArtifactSums(VERSION)
    assert sums.file_sha256("canisters", "a.wasm.gz") == HASH
    with pytest.raises(subprocess.CalledProcessError):
        sums.file_sha256("binaries/x86_64-linux", "ic-replay.gz")


def test_verified_json_accepts_matching_bytes(monkeypatch):
    payload = b'{"guest_launch_measurements": []}'
    sums = sums_with(
        monkeypatch, attested={"guest-os/update-img": {"launch-measurements.json": hashlib.sha256(payload).hexdigest()}}
    )
    monkeypatch.setattr(mainnet_revisions, "download_bytes", lambda url: payload)
    assert sums.verified_json("guest-os/update-img", "launch-measurements.json") == {"guest_launch_measurements": []}


def test_verified_json_rejects_tampered_bytes(monkeypatch):
    # The house-style negative test: content differing in a single byte from the
    # recorded hash must be rejected before it is parsed.
    payload = b'{"guest_launch_measurements": []}'
    sums = sums_with(
        monkeypatch, attested={"guest-os/update-img": {"launch-measurements.json": hashlib.sha256(payload).hexdigest()}}
    )
    monkeypatch.setattr(mainnet_revisions, "download_bytes", lambda url: payload[:-1] + b" ")
    with pytest.raises(Exception, match="does not match its SHA256SUMS entry"):
        sums.verified_json("guest-os/update-img", "launch-measurements.json")


def test_elected_hash_must_match_build(monkeypatch):
    built = dict(BINARIES)
    sums = sums_with(monkeypatch, attested={"guest-os/update-img": {"update-img.tar.zst": HASH}})
    check_elected_hash_against_build(sums, "guest-os", HASH)
    with pytest.raises(Exception, match="does not match the build-time hash"):
        check_elected_hash_against_build(sums, "guest-os", HASH[:-1] + "0")
    assert built == BINARIES  # sums_with must not mutate its inputs


def test_get_binary_hashes_requires_every_binary(monkeypatch):
    complete = {f"{name}.gz": HASH for name in mainnet_revisions.MAINNET_BINARIES}
    sums = sums_with(monkeypatch, attested={"binaries/x86_64-linux": complete})
    assert get_binary_hashes(sums) == {name: HASH for name in mainnet_revisions.MAINNET_BINARIES}

    incomplete = dict(complete)
    del incomplete["ic-replay.gz"]
    sums = sums_with(monkeypatch, attested={"binaries/x86_64-linux": incomplete})
    with pytest.raises(Exception, match="No sha256 for ic-replay"):
        get_binary_hashes(sums)


def http_error(code: int, body: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://api.github.com/x", code, "err", {}, io.BytesIO(body.encode()))


def test_commit_is_public(monkeypatch):
    # The commits endpoint answers 422 "No commit found for SHA" (not 404) for a
    # well-formed absent sha; only that exact answer means "not public". Other
    # errors -- including other 422s (validation failures, throttling) -- must
    # raise, because the answer gates whether unverified CDN data may be recorded.
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def urlopen_returning(result):
        def fake(req, timeout):
            if isinstance(result, Exception):
                raise result
            return result

        return fake

    monkeypatch.setattr(urllib.request, "urlopen", urlopen_returning(FakeResponse()))
    assert mainnet_revisions.commit_is_public(VERSION) is True

    monkeypatch.setattr(
        urllib.request, "urlopen", urlopen_returning(http_error(422, '{"message":"No commit found for SHA: x"}'))
    )
    assert mainnet_revisions.commit_is_public(VERSION) is False

    monkeypatch.setattr(
        urllib.request, "urlopen", urlopen_returning(http_error(422, '{"message":"Validation Failed"}'))
    )
    with pytest.raises(urllib.error.HTTPError):
        mainnet_revisions.commit_is_public(VERSION)

    monkeypatch.setattr(urllib.request, "urlopen", urlopen_returning(http_error(403, '{"message":"rate limited"}')))
    with pytest.raises(urllib.error.HTTPError):
        mainnet_revisions.commit_is_public(VERSION)
