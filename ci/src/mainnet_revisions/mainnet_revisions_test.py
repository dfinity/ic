"""
Tests for the validation of the values written to mainnet-icos-revisions.json.

The version and the hashes come from the public dashboard API and from CDN-served
SHA256SUMS files, and the PR that records them is auto-approved and auto-merged. They
are interpolated into download URLs by //bazel:mainnet-icos-*.bzl, so a value that is
not exactly a commit id / sha256 / plain name must be rejected here, before it can
reach a PR (F-051).
"""

import pytest
from mainnet_revisions import VersionInfo

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
