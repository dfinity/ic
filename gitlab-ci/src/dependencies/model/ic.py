import os

from model.project import Project
from model.repository import Repository
from model.team import Team
from scanner.dependency_scanner import PROJECT_ROOT

IS_PRIVATE = PROJECT_ROOT.name == "ic-private"
CI_PROJECT_PATH = os.environ.get("CI_PROJECT_PATH", "dfinity/ic")
GITHUB_REF = os.environ.get("GITHUB_REF", "refs/heads/master")


def is_running_in_ic_repo() -> bool:
    return CI_PROJECT_PATH == "dfinity/ic"


def is_running_on_main_branch() -> bool:
    return GITHUB_REF == "refs/heads/master"


def is_env_for_periodic_job() -> bool:
    return is_running_in_ic_repo() and is_running_on_main_branch()


def get_ic_repo_for_rust() -> Repository:
    if IS_PRIVATE:
        return Repository("ic", "https://github.com/dfinity/ic-private",
                          [Project(name="ic", path="ic-private", owner_by_path={"ic-private/rs/crypto": [Team.CRYPTO_TEAM], "ic-private/rs/validator": [Team.CRYPTO_TEAM], "ic-private/rs/canonical_state": [Team.CRYPTO_TEAM]})])
    return Repository("ic", "https://github.com/dfinity/ic", [Project(name="ic", path="ic", owner_by_path={"ic/rs/crypto": [Team.CRYPTO_TEAM], "ic/rs/validator": [Team.CRYPTO_TEAM], "ic/rs/canonical_state": [Team.CRYPTO_TEAM]})])


def get_ic_repo_merge_request_base_url() -> str:
    if IS_PRIVATE:
        return "https://github.com/dfinity/ic-private/pull/"
    return "https://github.com/dfinity/ic/pull/"


def get_ic_repo_ci_pipeline_base_url() -> str:
    if IS_PRIVATE:
        return "https://github.com/dfinity/ic-private/actions/runs/"
    return "https://github.com/dfinity/ic/actions/runs/"


def __test_get_ic_path():
    if IS_PRIVATE:
        return "ic-private"
    return "ic"
