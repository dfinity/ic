import logging
import os
import traceback
import typing

import gitlab
from gitlab import GitlabPipelinePlayError
from integration.gitlab.gitlab_pipeline_config import GitlabPipeline

GITLAB_TOKEN = os.environ.get("GITLAB_API_TOKEN", "")
if GITLAB_TOKEN is None:
    logging.error("GITLAB_API_TOKEN is not set, can not send comments to GitLab")

GITLAB_PROJECT_NAME = os.environ.get("CI_PROJECT_PATH", "dfinity-lab/public/ic")
DELTA_HEADER = "*Vulnerable dependency information*"


class GitlabApi:
    def __init__(self) -> None:
        self.gitlab = gitlab.Gitlab("https://gitlab.com", private_token=GITLAB_TOKEN)

    def comment_on_gitlab(self, info: typing.List):
        """Add a gitlab comment with dependency delta info."""
        if not info or not GITLAB_TOKEN:
            return

        comment_body = f"{DELTA_HEADER}\nThe *dependency-check* job for the MR has new findings. Please update or remove these dependencies or obtain a commit exception from [product security](https://dfinity.slack.com/archives/C01EWN833KN).\n\nThe findings are:\n{info}"
        glab_repo = self.gitlab.projects.get(GITLAB_PROJECT_NAME)
        self.gitlab.auth()  # needed for setting self.gitlab.user.username (current user)
        for merge_req in glab_repo.mergerequests.list(
            state="opened",
            order_by="updated_at",
            source_branch=os.environ["CI_COMMIT_REF_NAME"],
        ):
            comment = None
            for note in merge_req.notes.list():
                if note.author["username"] == self.gitlab.user.username and note.body.startswith(DELTA_HEADER):
                    comment = note
                    break
            if comment:
                comment.body = comment_body
                comment.save()
            else:
                merge_req.notes.create({"body": comment_body})


    def run_pipeline(self, pipeline: GitlabPipeline) -> bool:
        try:
            glab_repo = self.gitlab.projects.get(pipeline.value.project)
            job = glab_repo.pipelineschedules.get(pipeline.value.pipeline_id)
            job.play()
            return True
        except GitlabPipelinePlayError:
            logging.error(f"Could not run pipeline {pipeline}.")
            logging.debug(f"Could not run pipeline {pipeline}.\nReason: {traceback.format_exc()}")
            return False
