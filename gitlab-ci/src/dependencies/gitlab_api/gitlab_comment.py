import logging
import os
import typing

import gitlab
from scanner.scanner_job_type import ScannerJobType

GITLAB_TOKEN = os.environ.get("GITLAB_API_TOKEN", "")
if GITLAB_TOKEN is None:
    logging.error("GITLAB_API_TOKEN is not set, can not send comments to GitLab")

GITLAB_PROJECT_NAME = os.environ.get("CI_PROJECT_PATH", "dfinity-lab/core/ic")
DELTA_HEADER = "*Vulnerable dependency information*"


class GitlabComment:
    def __init__(self, job_type: ScannerJobType) -> None:
        self.job_type = job_type

    def comment_on_gitlab(self, info: typing.List):
        """Add a gitlab comment with dependency delta info."""
        if not info or not GITLAB_TOKEN:
            return

        comment_body = self._generate_comment_markdown(info)
        glab = gitlab.Gitlab("https://gitlab.com", private_token=GITLAB_TOKEN)
        glab.auth()  # needed for setting glab.user.username (current user)
        glab_repo = glab.projects.get(GITLAB_PROJECT_NAME)
        for merge_req in glab_repo.mergerequests.list(
            state="opened",
            order_by="updated_at",
            source_branch=os.environ["CI_COMMIT_REF_NAME"],
        ):
            comment = None
            for note in merge_req.notes.list():
                if note.author["username"] == glab.user.username and note.body.startswith(DELTA_HEADER):
                    comment = note
                    break
            if comment:
                comment.body = comment_body
                comment.save()
            else:
                merge_req.notes.create({"body": comment_body})

    def _generate_comment_markdown(self, info: typing.List):
        # TODO : prettify
        """Generate dependency delta comment using markdown."""
        body = ""
        if self.job_type == ScannerJobType.MERGE_SCAN:
            body = f"{DELTA_HEADER}\nThe *dependency-check* job for the MR has new findings. Please update or remove these dependencies or obtain a commit exception from [product security](https://dfinity.slack.com/archives/C01EWN833KN).\n\nThe findings are:\n{info}"

        # TODO : This message will be logged in console for now.
        # if self.job_type == ScannerJobType.RELEASE_SCAN:
        #     body = f"{DELTA_HEADER} \n The *dependency-scan-release-cut* job for the release cut has failures. Please update or remove these dependencies or obtain an commit exception from product security. The exception will be on the latest commit on the branch to make sure there aren't any additional changes added before merging.\n The failures are {info}"
        return body
