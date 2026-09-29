"""
Tests for the validation of the values written to mainnet-icos-revisions.json.

The version and the hashes come from the public dashboard API and from CDN-served
SHA256SUMS files, and the PR that records them is auto-approved and auto-merged. They
are interpolated into download URLs by //bazel:mainnet-icos-*.bzl, so a value that is
not exactly a commit id / sha256 / plain name must be rejected here, before it can
reach a PR (F-051).

Also tests VersionArtifactSums, the choke point that verifies CDN-served SHA256SUMS
against the build's provenance attestation before any hash is recorded:
attested for public commits (hard requirement), CDN fallback with a loud
warning only for versions whose commit is not public yet. Fallback records carry
the "attestation_pending" marker so they are re-verified -- and rewritten,
without the marker -- on the first run after their commit is disclosed.

Finally tests the verification of mainnet-canister-revisions.json: test canister
pins that sync-with-released-nervous-system-wasms computes from CDN downloads are
only recorded when the build's attested SHA256SUMS agrees (F-008).
"""

import hashlib
import io
import json
import logging
import pathlib
import re
import subprocess
import urllib.error
import urllib.request

import mainnet_revisions
import pytest
from mainnet_revisions import (
    VersionArtifactSums,
    VersionInfo,
    check_elected_update_img_hash_against_build,
    get_binary_hashes,
    is_record_up_to_date,
    parse_sha256sums,
    version_record,
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
        attestation_pending=False,
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
        # Anything but a bool would end up verbatim in the auto-merged JSON.
        pytest.param({"attestation_pending": "true"}, id="non-bool attestation_pending"),
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


def test_fetch_attested_sums_positional_contract(monkeypatch):
    # ci/scripts/fetch-attested-sums.sh takes its five arguments positionally, so
    # a rename or reorder on either side cannot be caught by the interpreter: it
    # would verify against the wrong pipeline or the wrong ref regex and still
    # exit 0. Pin the exact argv this module must produce.
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["check"] = kwargs.get("check")
        pathlib.Path(cmd[5]).write_text(f"{HASH}  update-img.tar.zst\n", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert mainnet_revisions.fetch_attested_sha256sums(VERSION, "guest-os/update-img") == {"update-img.tar.zst": HASH}
    # A non-zero exit of the verifier must propagate, never be ignored.
    assert seen["check"] is True
    assert seen["cmd"][:5] == [
        str(mainnet_revisions.FETCH_ATTESTED_SUMS_SCRIPT),
        VERSION,
        "guest-os/update-img",
        # <build-workflow>: the run's top-level workflow, matched against the
        # attestation certificate's Build Config URI. The signer is ci-main.yml.
        "dfinity/ic/.github/workflows/release-testing.yml",
        # <source-ref-regex>: release-qualification branches only.
        r"refs/heads/(rc--|hotfix-)[^/]+",
    ]
    # The out-file is the fifth positional argument.
    assert len(seen["cmd"]) == 6


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
    sums = sums_with(monkeypatch, attested={"guest-os/update-img": {"update-img.tar.zst": HASH}})
    check_elected_update_img_hash_against_build(sums, "guest-os", HASH)
    with pytest.raises(Exception, match="does not match the build-time hash"):
        check_elected_update_img_hash_against_build(sums, "guest-os", HASH[:-1] + "0")


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


def test_version_record_marks_pending_fallback():
    record = version_record(version_info(attestation_pending=True))
    assert record["attestation_pending"] is True
    assert record["version"] == VERSION

    # A verified record must not carry the marker at all, so that a pending
    # record rewritten after disclosure sheds it.
    assert "attestation_pending" not in version_record(version_info())


def test_version_record_field_mapping():
    # version_record() now feeds all three record types, so a swapped mapping
    # would corrupt the auto-merged JSON for every one of them. The one-HASH
    # version_info() fixture cannot see such a swap: assert the full record
    # against a literal, with a distinct sentinel in every field.
    def sha(i: int) -> str:
        return f"{i:064x}"

    info = VersionInfo(
        version=VERSION,
        hash=sha(1),
        dev_hash=sha(2),
        launch_measurements={"guest_launch_measurements": [1]},
        dev_measurements={"guest_launch_measurements": [2]},
        setupos_hash=sha(3),
        setupos_dev_hash=sha(4),
        binaries={"ic-replay": sha(5)},
        attestation_pending=False,
    )
    assert version_record(info) == {
        "version": VERSION,
        "update_img_hash": sha(1),
        "update_img_hash_dev": sha(2),
        "setupos_disk_img_hash": sha(3),
        "setupos_disk_img_hash_dev": sha(4),
        "binaries": {"ic-replay": sha(5)},
        "launch_measurements": {"guest_launch_measurements": [1]},
        "launch_measurements_dev": {"guest_launch_measurements": [2]},
    }


def test_is_record_up_to_date(monkeypatch):
    record = version_record(version_info())

    def forbid_commit_check(version):
        raise AssertionError("records without the marker must not trigger a GitHub API call")

    # Complete records without the marker are up to date without asking GitHub:
    # the check must stay cheap and must keep working for records that predate
    # the attestation rollout.
    monkeypatch.setattr(mainnet_revisions, "commit_is_public", forbid_commit_check)
    assert is_record_up_to_date(record, VERSION) is True
    assert is_record_up_to_date(record, "f" * 40) is False
    assert is_record_up_to_date({}, VERSION) is False
    assert is_record_up_to_date({k: v for k, v in record.items() if k != "binaries"}, VERSION) is False


def test_pending_record_goes_stale_on_disclosure(monkeypatch):
    # An "attestation_pending" record stays up to date only while its commit
    # remains private; disclosure makes it stale so the caller re-verifies.
    pending = version_record(version_info(attestation_pending=True))

    monkeypatch.setattr(mainnet_revisions, "commit_is_public", lambda version: False)
    assert is_record_up_to_date(pending, VERSION) is True

    monkeypatch.setattr(mainnet_revisions, "commit_is_public", lambda version: True)
    assert is_record_up_to_date(pending, VERSION) is False


def test_guestos_info_from_private_commit_is_attestation_pending(monkeypatch):
    measurements = b'{"guest_launch_measurements": []}'
    sums = {
        "guest-os/update-img": {"update-img.tar.zst": HASH},
        "guest-os/update-img-dev": {
            "update-img.tar.zst": HASH,
            "launch-measurements.json": hashlib.sha256(measurements).hexdigest(),
        },
        "setup-os/disk-img": {"disk-img.tar.zst": HASH},
        "setup-os/disk-img-dev": {"disk-img.tar.zst": HASH},
        "binaries/x86_64-linux": {f"{name}.gz": HASH for name in mainnet_revisions.MAINNET_BINARIES},
    }
    payload = {
        "replica_version_to_elect": VERSION,
        "release_package_sha256_hex": HASH,
        "guest_launch_measurements": {"guest_launch_measurements": []},
    }
    monkeypatch.setattr(mainnet_revisions, "download_bytes", lambda url: measurements)

    # sums_with is called for its module-level patches; the instance it returns
    # is unused because guestos_version_info_from_payload builds its own.
    sums_with(monkeypatch, attested=None, cdn=sums, public=False)
    assert mainnet_revisions.guestos_version_info_from_payload(payload).attestation_pending is True

    sums_with(monkeypatch, attested=sums)
    assert mainnet_revisions.guestos_version_info_from_payload(payload).attestation_pending is False


def test_hostos_record_pending_when_either_side_falls_back(monkeypatch):
    # HostOS reuses the GuestOS info collected for the same commit: a fallback
    # on either side must leave the whole record pending re-verification, and
    # only a record with both sides verified may go without the marker.
    hostos_sums = {
        "host-os/update-img": {"update-img.tar.zst": HASH},
        "host-os/update-img-dev": {"update-img.tar.zst": HASH},
    }
    payload = {"hostos_version_to_elect": VERSION, "release_package_sha256_hex": HASH}
    logger = logging.getLogger("logger")

    def hostos_info():
        return mainnet_revisions.hostos_version_info_from_payload(payload, logger)

    # Both sides verified: nothing pending.
    sums_with(monkeypatch, attested=hostos_sums)
    monkeypatch.setattr(mainnet_revisions, "get_replica_version_info", lambda version: version_info())
    assert hostos_info().attestation_pending is False

    # A pending GuestOS side taints the record even though the HostOS sums verified.
    monkeypatch.setattr(
        mainnet_revisions, "get_replica_version_info", lambda version: version_info(attestation_pending=True)
    )
    assert hostos_info().attestation_pending is True

    # A HostOS-side CDN fallback taints it even with a verified GuestOS side.
    sums_with(monkeypatch, attested=None, cdn=hostos_sums, public=False)
    monkeypatch.setattr(mainnet_revisions, "get_replica_version_info", lambda version: version_info())
    assert hostos_info().attestation_pending is True


def test_disclosed_pending_record_is_reverified_and_rewritten(tmp_path, monkeypatch):
    # The cron flow the marker exists for: a record written from unverified CDN
    # sums while the commit was private must be re-collected -- now under
    # mandatory attestation verification -- on the first run after the commit
    # becomes public, and the rewritten record sheds the marker.
    subnet = "some-subnet"
    pending = version_record(version_info(attestation_pending=True))
    path = tmp_path / "revisions.json"
    path.write_text(json.dumps({"guestos": {"subnets": {subnet: pending}}}))

    monkeypatch.setattr(mainnet_revisions, "get_subnet_latest_replica_version", lambda s: VERSION)
    monkeypatch.setattr(mainnet_revisions, "commit_is_public", lambda version: True)
    monkeypatch.setattr(mainnet_revisions, "get_replica_version_info", lambda version: version_info())
    mainnet_revisions.update_saved_subnet_revision(
        tmp_path, logging.getLogger("logger"), pathlib.Path("revisions.json"), subnet
    )

    written = json.loads(path.read_text())["guestos"]["subnets"][subnet]
    assert written == version_record(version_info())
    assert "attestation_pending" not in written


def test_pending_record_is_skipped_while_commit_is_private(tmp_path, monkeypatch):
    subnet = "some-subnet"
    pending = version_record(version_info(attestation_pending=True))
    path = tmp_path / "revisions.json"
    path.write_text(json.dumps({"guestos": {"subnets": {subnet: pending}}}))

    def no_refetch(version):
        raise AssertionError("a pending record must be skipped while its commit stays private")

    monkeypatch.setattr(mainnet_revisions, "get_subnet_latest_replica_version", lambda s: VERSION)
    monkeypatch.setattr(mainnet_revisions, "commit_is_public", lambda version: False)
    monkeypatch.setattr(mainnet_revisions, "get_replica_version_info", no_refetch)
    mainnet_revisions.update_saved_subnet_revision(
        tmp_path, logging.getLogger("logger"), pathlib.Path("revisions.json"), subnet
    )

    assert json.loads(path.read_text())["guestos"]["subnets"][subnet] == pending


def test_fetch_attested_sums_tries_policies_in_order(monkeypatch):
    # Each policy is one (build-workflow, source-ref-regex) pair passed to the
    # script as a whole: a workflow of one policy must never be combined with the
    # ref regex of another.
    seen = []
    succeed_on = {}

    def fake_run(cmd, **kwargs):
        assert kwargs.get("check") is True
        seen.append(tuple(cmd[3:5]))
        if len(seen) != succeed_on["call"]:
            raise ATTESTATION_FAILED
        pathlib.Path(cmd[5]).write_text(f"{HASH} governance-canister.wasm.gz\n", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    policies = mainnet_revisions.NNS_CANISTER_ATTESTATION_POLICIES
    master = ("dfinity/ic/.github/workflows/ci-kickoff.yml", "refs/heads/master")
    release_testing = ("dfinity/ic/.github/workflows/release-testing.yml", r"refs/heads/(rc--|hotfix-)[^/]+")

    # A master build verifies: the release-testing policy is never consulted.
    succeed_on["call"] = 1
    assert mainnet_revisions.fetch_attested_sha256sums(VERSION, "canisters", policies) == {
        "governance-canister.wasm.gz": HASH
    }
    assert seen == [master]

    # A hotfix build verifies under the second policy only.
    seen.clear()
    succeed_on["call"] = 2
    assert mainnet_revisions.fetch_attested_sha256sums(VERSION, "canisters", policies) == {
        "governance-canister.wasm.gz": HASH
    }
    assert seen == [master, release_testing]

    # Nothing verifies: the verifier's failure propagates.
    seen.clear()
    succeed_on["call"] = 0
    with pytest.raises(subprocess.CalledProcessError):
        mainnet_revisions.fetch_attested_sha256sums(VERSION, "canisters", policies)
    assert seen == [master, release_testing]


# The rev currently pinned in mainnet-canister-revisions.json (built before
# #11569, so its attestation is not acceptable) and a later master commit.
OLD_REV = "0c9710598f7ef85692b588a6ec518c8d8bf817ae"
NEW_REV = "34de476a722b3edaa3665ddfeca88d9b400b3fd6"
TEST_HASH = hashlib.sha256(b"governance-canister_test.wasm.gz").hexdigest()
PROD_HASH = hashlib.sha256(b"governance-canister.wasm.gz").hexdigest()


def canisters(rev=OLD_REV, test_sha256=HASH, prod_rev=None, prod_sha256=HASH) -> dict:
    """A canister map as written by sync-with-released-nervous-system-wasms."""
    return {
        "governance": {"rev": prod_rev or rev, "sha256": prod_sha256},
        "governance-canister_test": {"rev": rev, "sha256": test_sha256},
        "nns_dapp_test": {"sha256": HASH, "tag": "proposal-143823"},
        "sns_aggregator_test": {"sha256": HASH, "tag": "proposal-138924-agg"},
    }


NEW = dict(rev=NEW_REV, test_sha256=TEST_HASH, prod_sha256=PROD_HASH)
ATTESTED_NEW = {"governance-canister.wasm.gz": PROD_HASH, "governance-canister_test.wasm.gz": TEST_HASH}


def attestation_with(monkeypatch, *, attested=None, public=True):
    """
    Stub the attestation verifier: `attested` is the verified SHA256SUMS of NEW_REV's
    canisters directory, or None to make verification fail. `public`: whether the
    commit exists in dfinity/ic. Returns the list of fetches made.
    """
    fetches = []

    def fake_attested(version, subdir, policies):
        fetches.append((version, subdir, policies))
        if attested is None:
            raise ATTESTATION_FAILED
        return dict(attested)

    monkeypatch.setattr(mainnet_revisions, "fetch_attested_sha256sums", fake_attested)
    monkeypatch.setattr(mainnet_revisions, "commit_is_public", lambda version: public)
    return fetches


def forbid_attestation_checks(monkeypatch):
    def forbidden(*args, **kwargs):
        # pytest.fail() raises an exception that `pytest.raises(Exception)` cannot swallow.
        pytest.fail("must not be called")

    monkeypatch.setattr(mainnet_revisions, "fetch_attested_sha256sums", forbidden)
    monkeypatch.setattr(mainnet_revisions, "commit_is_public", forbidden)


def test_unchanged_test_pin_is_not_reverified(monkeypatch):
    # The pin recorded today predates #11569 and could not be verified: it must be
    # left alone rather than failing every run.
    forbid_attestation_checks(monkeypatch)
    after = canisters()
    mainnet_revisions.verify_cdn_test_canister_pins(canisters(), after)
    assert after == canisters()


def test_new_test_pin_verified_against_attested_sums(monkeypatch):
    fetches = attestation_with(monkeypatch, attested=ATTESTED_NEW)
    after = canisters(**NEW)
    mainnet_revisions.verify_cdn_test_canister_pins(canisters(), after)
    assert after == canisters(**NEW)
    assert fetches == [(NEW_REV, "canisters", mainnet_revisions.NNS_CANISTER_ATTESTATION_POLICIES)]


def flip_last_hex_digit(sha256: str) -> str:
    return sha256[:-1] + ("0" if sha256[-1] != "0" else "1")


def test_test_pin_not_matching_attested_sums_fails(monkeypatch):
    # The CDN served a different governance-canister_test than the attested build.
    attestation_with(
        monkeypatch, attested={**ATTESTED_NEW, "governance-canister_test.wasm.gz": flip_last_hex_digit(TEST_HASH)}
    )
    with pytest.raises(Exception, match="does not match its build attestation"):
        mainnet_revisions.verify_cdn_test_canister_pins(canisters(), canisters(**NEW))


def test_prod_hash_must_match_attested_sums(monkeypatch):
    # The module deployed on mainnet is not the attested build of the rev it reports.
    attestation_with(
        monkeypatch, attested={**ATTESTED_NEW, "governance-canister.wasm.gz": flip_last_hex_digit(PROD_HASH)}
    )
    with pytest.raises(Exception, match="does not match its build attestation"):
        mainnet_revisions.verify_cdn_test_canister_pins(canisters(), canisters(**NEW))


def test_missing_attested_entry_fails(monkeypatch):
    attestation_with(monkeypatch, attested={"governance-canister.wasm.gz": PROD_HASH})
    with pytest.raises(Exception, match="does not match its build attestation"):
        mainnet_revisions.verify_cdn_test_canister_pins(canisters(), canisters(**NEW))


def test_changed_bytes_at_pinned_rev_fail_without_fetch(monkeypatch):
    # The tool re-hashes the CDN every run: a different hash at the same rev means
    # the CDN now serves different bytes for an immutable artifact.
    forbid_attestation_checks(monkeypatch)
    with pytest.raises(Exception, match="suspect tampering"):
        mainnet_revisions.verify_cdn_test_canister_pins(canisters(), canisters(test_sha256=flip_last_hex_digit(HASH)))


def test_test_and_prod_revs_must_agree(monkeypatch):
    forbid_attestation_checks(monkeypatch)
    with pytest.raises(Exception, match="upgraded while this ran"):
        mainnet_revisions.verify_cdn_test_canister_pins(canisters(), canisters(**NEW, prod_rev=OLD_REV))


def test_public_commit_without_attestation_is_refused(monkeypatch):
    attestation_with(monkeypatch, attested=None, public=True)
    with pytest.raises(Exception, match="Refusing to record"):
        mainnet_revisions.verify_cdn_test_canister_pins(canisters(), canisters(**NEW))


def test_private_commit_keeps_previous_test_pin(monkeypatch, caplog):
    # An undisclosed security patch: nothing unverified is recorded, and the
    # production pin (anchored on chain) still moves on.
    attestation_with(monkeypatch, attested=None, public=False)
    after = canisters(**NEW)
    with caplog.at_level(logging.WARNING, logger="logger"):
        mainnet_revisions.verify_cdn_test_canister_pins(canisters(), after)
    assert after["governance-canister_test"] == canisters()["governance-canister_test"]
    assert after["governance"] == canisters(**NEW)["governance"]
    assert any("is not public" in r.message for r in caplog.records)


@pytest.mark.parametrize(
    "canister_map, error",
    [
        pytest.param(
            {k: v for k, v in canisters(**NEW).items() if k != "governance"},
            "must contain governance-canister_test and governance",
            id="missing production canister",
        ),
        pytest.param(
            {**canisters(**NEW), "governance-canister_test": {"rev": NEW_REV, "sha256": ""}},
            "governance-canister_test sha256 must be a 64-character lowercase hex sha256",
            id="empty sha256",
        ),
        pytest.param(
            {**canisters(**NEW), "governance-canister_test": {"tag": "v1", "sha256": TEST_HASH}},
            "governance-canister_test rev must be a 40-character lowercase hex git commit id",
            id="tag instead of rev",
        ),
    ],
)
def test_malformed_test_pin_is_rejected(monkeypatch, canister_map, error):
    forbid_attestation_checks(monkeypatch)
    with pytest.raises(Exception, match=error):
        mainnet_revisions.verify_cdn_test_canister_pins(canisters(), canister_map)


def test_unclassified_test_canister_fails():
    mainnet_revisions.check_test_canisters_classified(canisters())
    with pytest.raises(Exception, match="new-canister_test"):
        mainnet_revisions.check_test_canisters_classified({**canisters(), "new-canister_test": {}})


def fake_sync_tool(monkeypatch, repo_root: pathlib.Path, proposed: dict):
    """Stub the `bazel run` of sync-with-released-nervous-system-wasms to propose `proposed`."""

    def fake_check_call(cmd, cwd):
        assert cwd == repo_root
        assert cmd[:6] == ["bazel", "run", mainnet_revisions.SYNC_CANISTERS_TOOL, "--", "--output", cmd[5]]
        output = pathlib.Path(cmd[5])
        # `bazel run` executes the tool in its runfiles directory: the path must be
        # absolute, and it must not be (or be next to) the repository file.
        assert output.is_absolute()
        assert repo_root not in output.parents
        output.write_text(mainnet_revisions.dump_canisters_json(proposed), encoding="utf-8")

    monkeypatch.setattr(subprocess, "check_call", fake_check_call)


def test_canisters_file_untouched_when_verification_fails(tmp_path, monkeypatch):
    path = tmp_path / mainnet_revisions.SAVED_VERSIONS_CANISTERS_FILE
    original = mainnet_revisions.dump_canisters_json(canisters())
    path.write_text(original, encoding="utf-8")
    forbid_attestation_checks(monkeypatch)
    fake_sync_tool(monkeypatch, tmp_path, canisters(test_sha256=flip_last_hex_digit(HASH)))

    with pytest.raises(Exception, match="suspect tampering"):
        mainnet_revisions.update_mainnet_revisions_canisters_file(tmp_path, logging.getLogger("logger"))

    # A retry starts from the same state: the unverified result is nowhere in the
    # working tree.
    assert path.read_text(encoding="utf-8") == original
    assert sorted(p.name for p in tmp_path.iterdir()) == [mainnet_revisions.SAVED_VERSIONS_CANISTERS_FILE]


def test_canisters_file_updated_when_verified(tmp_path, monkeypatch):
    path = tmp_path / mainnet_revisions.SAVED_VERSIONS_CANISTERS_FILE
    path.write_text(mainnet_revisions.dump_canisters_json(canisters()), encoding="utf-8")
    attestation_with(monkeypatch, attested=ATTESTED_NEW)
    fake_sync_tool(monkeypatch, tmp_path, canisters(**NEW))

    mainnet_revisions.update_mainnet_revisions_canisters_file(tmp_path, logging.getLogger("logger"))

    assert path.read_text(encoding="utf-8") == mainnet_revisions.dump_canisters_json(canisters(**NEW))
    assert sorted(p.name for p in tmp_path.iterdir()) == [mainnet_revisions.SAVED_VERSIONS_CANISTERS_FILE]


REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]


def test_dump_canisters_json_round_trips_the_repository_file():
    # The installed file must look exactly as if the sync tool had written it.
    contents = (REPO_ROOT / mainnet_revisions.SAVED_VERSIONS_CANISTERS_FILE).read_text(encoding="utf-8")
    assert mainnet_revisions.dump_canisters_json(json.loads(contents)) == contents


def test_test_canister_classification_matches_sync_tool_and_bazel():
    # A test canister added to the sync tool must be classified here, and the file
    # names must be the ones Bazel downloads.
    main_rs = (REPO_ROOT / "rs/nervous_system/tools/sync-with-released-nervous-system-wasms/src/main.rs").read_text(
        encoding="utf-8"
    )
    nns_test_canisters = set(re.findall(r'\(\s*"([^"]+_test)",\s*[A-Z_]+_CANISTER_ID\s*\)', main_rs))
    external_test_canisters = {
        name
        for name, body in re.findall(
            r'\(\s*"([^"]+)",\s*ExternalCanisterInfo\s*\{(.*?)\}\s*,?\s*\)', main_rs, re.DOTALL
        )
        if "test_filename: Some(" in body
    }
    assert nns_test_canisters == set(mainnet_revisions.CDN_TEST_CANISTERS)
    assert external_test_canisters == set(mainnet_revisions.UNANCHORED_TEST_CANISTERS)

    module_bazel = (REPO_ROOT / "MODULE.bazel").read_text(encoding="utf-8")
    for key, (filename, prod_key, prod_filename) in mainnet_revisions.CDN_TEST_CANISTERS.items():
        assert f'"{key}": "{filename}"' in module_bazel
        assert f'"{prod_key}": "{prod_filename}"' in module_bazel
