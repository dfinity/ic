import json
import logging
import os
import traceback
import typing
from parser.bazel_toml_parser import parse_bazel_toml_to_gh_manifest
from time import sleep

import requests
from github import Github
from github.GithubException import GithubException
from integration.github.github_dependency_submission import GHSubDetector, GHSubJob, GHSubRequest
from integration.github.github_workflow_config import GithubWorklow

# Github dataclass has len(token) > 0 assertion, so we set a placeholder
# value and validate against it.
TOKEN_NOT_SET = "token-not-set"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", TOKEN_NOT_SET)
if GITHUB_TOKEN == TOKEN_NOT_SET:
    logging.warning("GITHUB_TOKEN is not set, can not send comments and dependencies to Github")

GITHUB_REPOSITORY = os.environ.get("CI_PROJECT_PATH", "dfinity/ic")
DELTA_HEADER = "*Vulnerable dependency information*"


class GithubApi:
    def __init__(self) -> None:
        self.github = Github(GITHUB_TOKEN)

    def comment_on_github(self, info: typing.List):
        """Add a github comment with dependency delta info."""
        if not info or GITHUB_TOKEN == TOKEN_NOT_SET:
            return

        GITHUB_PR_NUMBER = os.environ.get("CI_MERGE_REQUEST_IID", "")
        if GITHUB_PR_NUMBER is None:
            logging.error("Unable to find the PR number for the current workflow")
            return

        comment_body = f"{DELTA_HEADER}\nThe *dependency-check* job for the MR has new findings. Please update or remove these dependencies or obtain a commit exception from [product security](https://dfinity.slack.com/archives/C01EWN833KN).\n\nThe findings are:\n{info}"

        # Get the current repo
        repo = self.github.get_repo(GITHUB_REPOSITORY)

        # Get the pull request
        pull_request = repo.get_pull(int(GITHUB_PR_NUMBER))

        # Get the comments
        comments = pull_request.get_issue_comments()

        # Check if dependency management comment already exists
        update_comment = False
        for comment in comments:
            if comment.body.startswith(DELTA_HEADER):
                update_comment = True
                break

        if update_comment:
            comment.edit(comment_body)
        else:
            pull_request.create_issue_comment(comment_body)

    def run_workflow(self, workflow: GithubWorklow) -> bool:
        try:
            repo = self.github.get_repo(workflow.value.project)
            base_build_workflow = repo.get_workflow(workflow.value.workflow_name)
            base_build_workflow.create_dispatch(ref="master")
            return True
        except GithubException:
            logging.error(f"Could not run workflow {workflow}.")
            logging.debug(f"Could not run workflow {workflow}.\nReason: {traceback.format_exc()}")
            return False

    @staticmethod
    def submit_dependencies(toml_lock_filenames: typing.List[typing.Tuple[str, str]]) -> None:
        def get_sha_and_ref() -> typing.Tuple[str, str]:
            # A snapshot of a pull request's lock file must never be recorded under
            # the base branch. Under `pull_request_target` GITHUB_REF is the base
            # branch (refs/heads/master), and since the correlator and detector
            # below are shared with the master job, such a snapshot would replace
            # the default branch's dependency graph (and Dependabot alerts) with
            # the PR's untrusted lock file. Record it under the PR's own head ref
            # instead; dependency review compares by commit, so it still works.
            # The PR number comes from the event payload GitHub writes for the
            # run, so workflows on branches cut before this change still work.
            if "GITHUB_PR_DIR" in os.environ or "GITHUB_PR_SHA" in os.environ:
                with open(os.environ["GITHUB_EVENT_PATH"]) as f:
                    pr_number = json.load(f)["pull_request"]["number"]
                if type(pr_number) is not int or pr_number < 1:
                    raise RuntimeError(f"Invalid pull request number in the event payload: {pr_number!r}")
                return os.environ["GITHUB_PR_SHA"], f"refs/pull/{pr_number}/head"
            if os.environ.get("GITHUB_EVENT_NAME", "").startswith("pull_request"):
                raise RuntimeError("Pull request runs must set GITHUB_PR_DIR and GITHUB_PR_SHA")
            return os.environ["GITHUB_SHA"], os.environ["GITHUB_REF"]

        if toml_lock_filenames is None or len(toml_lock_filenames) == 0:
            raise RuntimeError("No toml lock files provided")

        if GITHUB_TOKEN == TOKEN_NOT_SET:
            raise RuntimeError("Dependency submission not possible because GITHUB_TOKEN not set")

        sha, ref = get_sha_and_ref()
        detector = GHSubDetector("bazel-rust-detector", "0.0.1", "https://github.com/dfinity/ic")
        correlator = "Bazel Dependency Submission / bazel-dependency-submission"
        job = GHSubJob(os.environ["GITHUB_RUN_ID"], correlator)

        manifests = []
        for basedir, filepath in toml_lock_filenames:
            manifests.append(parse_bazel_toml_to_gh_manifest(basedir, filepath))

        req = GHSubRequest(0, job, sha, ref, detector, manifests)
        req_json = req.to_json()

        # https://docs.github.com/en/rest/dependency-graph/dependency-submission?apiVersion=2022-11-28#create-a-snapshot-of-dependencies-for-a-repository
        url = f'https://api.github.com/repos/{os.environ['GITHUB_REPOSITORY']}/dependency-graph/snapshots'
        logging.debug(f"Submitting request to {url} with payload: {req_json}")
        last_error = None
        for retry in range(6):
            if retry > 0:
                sleep(2**retry)
            resp = requests.post(url, headers={"Authorization": f"Bearer {GITHUB_TOKEN}"}, json=req_json)
            if resp.status_code == 201:
                return
            error = f"Dependency submission failed with status code {resp.status_code}"
            body = resp.text
            if body is not None and len(body) > 0:
                error += f" and body:\n\n{body}"
            last_error = RuntimeError(error)
        raise last_error
