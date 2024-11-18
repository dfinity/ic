import abc
import os
import pathlib
import typing

from model.dependency import Dependency
from model.finding import Finding
from model.project import Project

PROJECT_ROOT = pathlib.Path(
    os.environ.get("CI_PROJECT_DIR", pathlib.Path(__file__).absolute().parent.parent.parent.parent.parent.parent)
)


class DependencyManager(abc.ABC):
    """Base class for helper classes for different package managers."""

    def __init__(self):
        self.root = PROJECT_ROOT

    @abc.abstractmethod
    def get_scanner_id(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def get_dependency_diff(self) -> typing.List[Dependency]:
        """Return list of dependency diffs for modified packages"""
        raise NotImplementedError

    @abc.abstractmethod
    def get_findings(
        self, repository_name: str, project: Project, engine_version: typing.Optional[str]
    ) -> typing.List[Finding]:
        """Return list of vulnerable dependencies for the given project or the whole repo if no project is specified"""
        raise NotImplementedError

    @abc.abstractmethod
    def get_modified_packages(self) -> typing.List[str]:
        """Return list of modified internal packages"""
        raise NotImplementedError

    @abc.abstractmethod
    def has_dependencies_changed(self) -> typing.Dict[str, bool]:
        """Return true if dependencies have changed in an MR"""
        raise NotImplementedError
