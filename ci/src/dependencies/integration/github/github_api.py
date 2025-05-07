import json
import logging
import os
import time
import traceback
import typing
import urllib.request

import jwt
from github import Github
from github.GithubException import GithubException
from integration.github.github_workflow_config import GithubWorklow

# Github dataclass has len(token) > 0 assertion, so we set a placeholder
# value and validate against it.
TOKEN_NOT_SET = "token-not-set"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", TOKEN_NOT_SET)
if GITHUB_TOKEN == TOKEN_NOT_SET:
    logging.warning("GITHUB_TOKEN is not set, can not send comments to Github")

GITHUB_REPOSITORY = os.environ.get("CI_PROJECT_PATH", "dfinity/ic")
DELTA_HEADER = "*Vulnerable dependency information*"

GITHUB_APP_CLIENT_ID = os.environ.get("GITHUB_APP_CLIENT_ID")
GITHUB_APP_SIGNING_KEY = os.environ.get("GITHUB_APP_SIGNING_KEY")
if GITHUB_APP_CLIENT_ID is None or GITHUB_APP_SIGNING_KEY is None:
    logging.warning("GITHUB_APP_CLIENT_ID or GITHUB_APP_SIGNING_KEY is not set, can not clone private repos")


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
    def generate_install_token() -> str:
        if GITHUB_APP_CLIENT_ID is None or GITHUB_APP_SIGNING_KEY is None:
            raise RuntimeError("GITHUB_APP_CLIENT_ID or GITHUB_APP_SIGNING_KEY environment variable is not set")

        # see https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app#example-using-python-to-generate-a-jwt
        payload = {
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
            "iss": GITHUB_APP_CLIENT_ID,
        }
        encoded_jwt = jwt.encode(payload, GITHUB_APP_SIGNING_KEY, algorithm="RS256")

        # get install id
        req = urllib.request.Request(
            url="https://api.github.com/app/installations", headers={"Authorization": f"Bearer {encoded_jwt}"}
        )
        http_response = urllib.request.urlopen(req, timeout=30)
        if http_response.code != 200:
            raise RuntimeError(f"Failed to get installation id, received status code: {http_response.getCode()}")
        installs = json.loads(http_response.read())
        if len(installs) != 1:
            raise RuntimeError(f"Failed to get installation id, received {len(installs)} installs")
        install_id = installs[0]["id"]

        # generate install token
        req = urllib.request.Request(
            method="POST",
            url=f"https://api.github.com/app/installations/{install_id}/access_tokens",
            headers={"Authorization": f"Bearer {encoded_jwt}"},
        )
        http_response = urllib.request.urlopen(req, timeout=30)
        if http_response.code != 201:
            raise RuntimeError(
                f"Failed to generate installation token, received status code: {http_response.getCode()}"
            )
        token_data = json.loads(http_response.read())
        return token_data["token"]
