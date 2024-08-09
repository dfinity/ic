from typing import List

from model.project import Project
from model.repository import Repository
from model.team import Team
from scanner.dependency_scanner import PROJECT_ROOT

IS_PRIVATE = PROJECT_ROOT.name == "ic-private"


def get_ic_repo_for_rust() -> Repository:
    if IS_PRIVATE:
        return Repository("ic", "https://github.com/dfinity/ic-private",
                          [Project(name="ic", path="ic-private", owner_by_path={"ic-private/rs/crypto": [Team.CRYPTO_TEAM], "ic-private/rs/validator": [Team.CRYPTO_TEAM], "ic-private/rs/canonical_state": [Team.CRYPTO_TEAM]})])
    return Repository("ic", "https://github.com/dfinity/ic", [Project(name="ic", path="ic", owner_by_path={"ic/rs/crypto": [Team.CRYPTO_TEAM], "ic/rs/validator": [Team.CRYPTO_TEAM], "ic/rs/canonical_state": [Team.CRYPTO_TEAM]})])


def get_ic_repo_for_trivy() -> List[Repository]:
    if IS_PRIVATE:
        return [
            Repository(
                "ic",
                "https://github.com/dfinity/ic-private",
                [
                    Project(
                        name="boundary-guestos",
                        path="ic-private/ic-os/boundary-guestos/envs/prod",
                        link="https://github.com/dfinity/ic-private/tree/master-private/ic-os/boundary-guestos/context",
                        owner=Team.BOUNDARY_NODE_TEAM,
                    ),
                    Project(
                        name="guestos",
                        path="ic-private/ic-os/guestos/envs/prod",
                        link="https://github.com/dfinity/ic-private/tree/master-private/ic-os/guestos/context",
                        owner=Team.NODE_TEAM,
                    ),
                ],
            )
        ]

    return [
        Repository(
            "ic",
            "https://github.com/dfinity/ic",
            [
                Project(
                    name="boundary-guestos",
                    path="ic/ic-os/boundary-guestos/envs/prod",
                    link="https://github.com/dfinity/ic/tree/master/ic-os/boundary-guestos/context",
                    owner=Team.BOUNDARY_NODE_TEAM,
                ),
                Project(
                    name="guestos",
                    path="ic/ic-os/guestos/envs/prod",
                    link="https://github.com/dfinity/ic/tree/master/ic-os/guestos/context",
                    owner=Team.NODE_TEAM,
                ),
            ],
        )
    ]


def get_ic_repo_merge_request_base_url() -> str:
    if IS_PRIVATE:
        return "https://github.com/dfinity/ic-private/pull/"
    return "https://github.com/dfinity/ic/pull/"


def get_ic_repo_ci_pipeline_base_url() -> str:
    if IS_PRIVATE:
        return "https://github.com/dfinity/ic-private/actions/runs/"
    return "https://github.com/dfinity/ic/actions/runs/"


def __test_get_ic_path() :
    if IS_PRIVATE:
        return "ic-private"
    return "ic"
