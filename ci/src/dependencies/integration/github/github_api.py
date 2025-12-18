import logging
import os
import traceback
import typing
from parser.bazel_toml_parser import parse_bazel_toml_to_gh_manifest

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
        def get_sha():
            if "GITHUB_PR_SHA" in os.environ:
                return os.environ["GITHUB_PR_SHA"]
            return os.environ["GITHUB_SHA"]

        if toml_lock_filenames is None or len(toml_lock_filenames) == 0:
            raise RuntimeError("No toml lock files provided")

        if GITHUB_TOKEN == TOKEN_NOT_SET:
            raise RuntimeError("Dependency submission not possible because GITHUB_TOKEN not set")

        detector = GHSubDetector("bazel-rust-detector", "0.0.1", "https://github.com/dfinity/ic")
        job = GHSubJob(os.environ["GITHUB_RUN_ID"], f'{os.environ['GITHUB_WORKFLOW']} / {os.environ['GITHUB_JOB']}')

        manifests = []
        for basedir, filepath in toml_lock_filenames:
            manifests.append(parse_bazel_toml_to_gh_manifest(basedir, filepath))

        req = GHSubRequest(0, job, get_sha(), os.environ["GITHUB_REF"], detector, manifests)

        # https://docs.github.com/en/rest/dependency-graph/dependency-submission?apiVersion=2022-11-28#create-a-snapshot-of-dependencies-for-a-repository
        url = f'https://api.github.com/repos/{os.environ['GITHUB_REPOSITORY']}/dependency-graph/snapshots'
        logging.debug(f"Submitting request to {url} with payload: {req.to_json()}")
        resp = requests.post(url, headers={"Authorization": f"Bearer {GITHUB_TOKEN}"}, json=req.to_json())
        if resp.status_code != 201:
            raise RuntimeError(f"Dependency submission failed with status code {resp.status_code}")
