import json
import os

import pytest
from bazel_toml_parser import parse_bazel_toml_to_gh_manifest


@pytest.mark.parametrize(
    "filename",
    [
        pytest.param(os.path.join("test_data", "minimal-example.toml.lock")),
        pytest.param(os.path.join("test_data", "real-world-example.toml.lock")),
    ],
)
def test_happy_cases(filename):
    basedir = os.path.dirname(__file__)
    res = parse_bazel_toml_to_gh_manifest(basedir, filename)

    expected = json.loads(open(os.path.join(basedir, f"{filename}.json"), "r").read())
    assert res.to_json() == expected


@pytest.mark.parametrize(
    "filename,expected_error",
    [
        pytest.param(os.path.join("test_data", "error-dup-version.toml.lock"), "multiple occurrences"),
        pytest.param(os.path.join("test_data", "error-unknown-dep.toml.lock"), "not found"),
    ],
)
def test_error_cases(filename, expected_error):
    try:
        parse_bazel_toml_to_gh_manifest(os.path.dirname(__file__), filename)
        assert False
    except RuntimeError as e:
        assert expected_error in str(e)


LOCKFILE = "Cargo.Bazel.toml.lock"

VALID_LOCKFILE_CONTENT = """
[[package]]
name = "some-crate"
version = "1.0.0"
"""


@pytest.mark.parametrize("target_outside_basedir", [pytest.param(False), pytest.param(True)])
def test_rejects_symlinked_lockfile(tmp_path, target_outside_basedir):
    # A fork can commit the lock file as a symlink to any file readable by the CI
    # runner (e.g. the sibling checkout's .git/config). The parser must refuse the
    # symlink instead of dereferencing it, so the target is never read.
    basedir = tmp_path / "pr"
    basedir.mkdir()
    target = (tmp_path if target_outside_basedir else basedir) / "target.toml.lock"
    target.write_text(VALID_LOCKFILE_CONTENT)
    (basedir / LOCKFILE).symlink_to(target)

    # The target parses fine on its own, so the failure below is caused by the
    # symlink and not by the content it points at.
    parse_bazel_toml_to_gh_manifest(str(target.parent), target.name)

    with pytest.raises(RuntimeError, match="symbolic link"):
        parse_bazel_toml_to_gh_manifest(str(basedir), LOCKFILE)


def test_rejects_lockfile_that_is_not_a_regular_file(tmp_path):
    (tmp_path / LOCKFILE).mkdir()

    with pytest.raises(RuntimeError, match="not a regular file"):
        parse_bazel_toml_to_gh_manifest(str(tmp_path), LOCKFILE)
