import os

from model.project import Project
from model.repository import Repository
from model.team import Team

CI_PROJECT_PATH = os.environ.get("CI_PROJECT_PATH", "dfinity/ic")
GITHUB_REF = os.environ.get("GITHUB_REF", "refs/heads/master")
REPO_NAME = os.environ.get("REPO_NAME", "dfinity/ic")


def is_running_in_ic_repo() -> bool:
    return CI_PROJECT_PATH == "dfinity/ic"


def is_running_on_main_branch() -> bool:
    return GITHUB_REF == "refs/heads/master"


def is_env_for_periodic_job() -> bool:
    return is_running_in_ic_repo() and is_running_on_main_branch()


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
                    f"{repo_name}/rs/crypto": [Team.CRYPTO_TEAM],
                    f"{repo_name}/rs/validator": [Team.CRYPTO_TEAM],
                    f"{repo_name}/rs/canonical_state": [Team.CRYPTO_TEAM],
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
