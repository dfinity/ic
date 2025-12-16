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
    res = parse_bazel_toml_to_gh_manifest(filename)

    expected = json.loads(open(f"{filename}.json", "r").read())
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
        parse_bazel_toml_to_gh_manifest(filename)
        assert False
    except RuntimeError as e:
        assert expected_error in str(e)
