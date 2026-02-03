import os

from model.project import Project
from model.repository import Repository
from model.team import Team

REPO_NAME = os.environ.get("REPO_NAME", "dfinity/ic")


def get_ic_repo_for_rust() -> Repository:
    repo_name = REPO_NAME.replace("dfinity/", "")
    return Repository(
        "ic",
        f"https://github.com/dfinity/{repo_name}",
        [
            Project(
                name="ic",
                path=repo_name,
                owner_by_path={
                    f"{repo_name}/rs/crypto": [Team.CONSENSUS_TEAM],
                    f"{repo_name}/rs/validator": [Team.CONSENSUS_TEAM],
                    f"{repo_name}/rs/canonical_state": [Team.CONSENSUS_TEAM],
                },
            )
        ],
    )


def get_ic_repo_merge_request_base_url() -> str:
    return f"https://github.com/{REPO_NAME}/pull/"


def get_ic_repo_ci_pipeline_base_url() -> str:
    return f"https://github.com/{REPO_NAME}/actions/runs/"


def __test_get_ic_path():
    return REPO_NAME.replace("dfinity/", "")
