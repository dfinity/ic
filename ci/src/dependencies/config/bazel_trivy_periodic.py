from model.project import Project
from model.repository import Repository
from model.team import Team

REPOS_TO_SCAN = [
    Repository(
        "ic",
        "https://github.com/dfinity/ic",
        [
            Project(
                name="guestos",
                path="ic/ic-os/guestos/envs/prod",
                link="https://github.com/dfinity/ic/tree/master/ic-os/guestos/context",
                owner=Team.NODE_TEAM,
            ),
        ],
    )
]
