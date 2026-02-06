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
                path="tmu-trivy-debug/ic-os/guestos/envs/prod",  # TODO: change to master
                link="https://github.com/dfinity/ic/tree/tmu-trivy-debug/ic-os/guestos/context",  # TODO: change to master
                owner=Team.NODE_TEAM,
            ),
        ],
    )
]
