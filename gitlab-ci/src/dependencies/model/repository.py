import typing
from dataclasses import dataclass, field

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

    def __post_init__(self):
        """Validate field values after initialization"""
        assert self.name is not None and len(self.name) > 0
        assert self.path is not None and len(self.path) > 0
        assert self.link is None or len(self.link) > 0


@dataclass
class Repository:
    """name of the repository"""

    name: str
    """github url of the repository"""
    url: str
    """list of Projects in the repository"""
    projects: typing.List[Project] = field(default_factory=list)
    """version of the compilation engine"""
    engine_version: typing.Optional[int] = None

    def __post_init__(self):
        """Validate field values after initialization"""
        assert self.name is not None and len(self.name) > 0
        assert self.url is not None and len(self.url) > 0
        assert isinstance(self.projects, list) and len(self.projects) > 0
        assert self.engine_version is None or self.engine_version > 0

        for project in self.projects:
            assert project.path.startswith(self.name)
