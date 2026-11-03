import json
import os
from unittest.mock import Mock

import integration.github.github_api as github_api
import pytest
from integration.github.github_api import GithubApi
from integration.github.github_dependency_submission import GHSubManifest

LOCKFILE = "Cargo.Bazel.toml.lock"
MASTER_ENV = {
    "GITHUB_REPOSITORY": "dfinity/ic",
    "GITHUB_RUN_ID": "1",
    "GITHUB_REF": "refs/heads/master",
    "GITHUB_SHA": "a" * 40,
    "GITHUB_WORKSPACE": "/workspace",
    "GITHUB_EVENT_NAME": "push",
}
# Under pull_request_target GITHUB_REF is the base branch.
PR_ENV = {
    **MASTER_ENV,
    "GITHUB_EVENT_NAME": "pull_request_target",
    "GITHUB_PR_DIR": "/workspace/pr",
    "GITHUB_PR_SHA": "b" * 40,
}
PR_EVENT = {"pull_request": {"number": 1234}}


@pytest.fixture
def post(monkeypatch):
    for var in list(os.environ):
        if var.startswith("GITHUB_"):
            monkeypatch.delenv(var)
    monkeypatch.setattr(github_api, "GITHUB_TOKEN", "token")
    monkeypatch.setattr(github_api, "parse_bazel_toml_to_gh_manifest", lambda *_: GHSubManifest(LOCKFILE, LOCKFILE, []))
    post = Mock(return_value=Mock(status_code=201))
    monkeypatch.setattr(github_api.requests, "post", post)
    return post


def submit(monkeypatch, tmp_path, env, event):
    if event is not None:
        event_path = tmp_path / "event.json"
        event_path.write_text(json.dumps(event))
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    for var, value in env.items():
        monkeypatch.setenv(var, value)
    GithubApi.submit_dependencies([("/workspace", LOCKFILE)])


def test_master_snapshot_uses_github_ref_and_sha(monkeypatch, tmp_path, post):
    submit(monkeypatch, tmp_path, MASTER_ENV, {"ref": "refs/heads/master"})

    snapshot = post.call_args.kwargs["json"]
    assert snapshot["ref"] == "refs/heads/master"
    assert snapshot["sha"] == "a" * 40


def test_pr_snapshot_is_never_recorded_under_the_base_branch(monkeypatch, tmp_path, post):
    submit(monkeypatch, tmp_path, PR_ENV, PR_EVENT)

    snapshot = post.call_args.kwargs["json"]
    assert snapshot["ref"] == "refs/pull/1234/head"
    assert snapshot["sha"] == "b" * 40


@pytest.mark.parametrize(
    "overrides,event,error,match",
    [
        pytest.param({}, None, KeyError, "GITHUB_EVENT_PATH", id="missing-event"),
        pytest.param({}, {"ref": "refs/heads/master"}, KeyError, "pull_request", id="event-without-pr"),
        pytest.param({}, {"pull_request": {}}, KeyError, "number", id="event-without-number"),
        pytest.param({}, {"pull_request": {"number": 0}}, RuntimeError, "number", id="zero-number"),
        pytest.param({}, {"pull_request": {"number": True}}, RuntimeError, "number", id="bool-number"),
        pytest.param(
            {}, {"pull_request": {"number": "12/../../heads/master"}}, RuntimeError, "number", id="string-number"
        ),
        pytest.param({"GITHUB_PR_SHA": None}, PR_EVENT, KeyError, "GITHUB_PR_SHA", id="only-pr-dir"),
        pytest.param(
            {"GITHUB_PR_DIR": None, "GITHUB_PR_SHA": None}, PR_EVENT, RuntimeError, "must set", id="no-pr-vars"
        ),
    ],
)
def test_incomplete_pr_environment_is_refused(monkeypatch, tmp_path, post, overrides, event, error, match):
    env = {k: v for k, v in {**PR_ENV, **overrides}.items() if v is not None}

    with pytest.raises(error, match=match):
        submit(monkeypatch, tmp_path, env, event)
    post.assert_not_called()
