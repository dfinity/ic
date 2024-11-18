import typing
from dataclasses import dataclass, field

from model.project import Project


@dataclass
class Repository:
    """name of the repository"""

    name: str
    """github url of the repository"""
    url: str
    """list of Projects in the repository"""
    projects: typing.List[Project] = field(default_factory=list)
    """version of the compilation engine"""
    engine_version: typing.Optional[str] = None

    def __post_init__(self):
        """Validate field values after initialization"""
        assert self.name is not None and len(self.name) > 0
        assert self.url is not None and len(self.url) > 0
        assert isinstance(self.projects, list) and len(self.projects) > 0
        assert self.engine_version is None or len(self.engine_version) > 0

        for project in self.projects:
            assert project.path.startswith(self.name)
