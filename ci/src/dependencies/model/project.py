import typing
from dataclasses import dataclass, field

from model.finding import Finding
from model.team import Team


@dataclass
class Project:
    """name of the project"""

    name: str
    """relative path to the project from the root of the repository"""
    path: str
    """link to project"""
    link: typing.Optional[str] = None
    """owner of the project"""
    owner: typing.Optional[Team] = None
    """owner(s) for specific path prefixes in the project (for mono repos)"""
    owner_by_path: typing.Dict[str, typing.List[Team]] = field(default_factory=lambda: {})

    def __post_init__(self):
        """Validate field values after initialization"""
        assert self.name is not None and len(self.name) > 0
        assert self.path is not None and len(self.path) > 0
        assert self.link is None or len(self.link) > 0
        assert self.owner_by_path is not None

    def get_owners_for(self, finding: Finding) -> typing.List[Team]:
        owners = {self.owner} if self.owner else set()
        for path_prefix, path_owners in self.owner_by_path.items():
            for proj in finding.projects:
                if proj.startswith(path_prefix):
                    owners.update(path_owners)
                    break
        return list(owners)
