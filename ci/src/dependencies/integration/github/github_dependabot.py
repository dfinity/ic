import typing
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, List

from github.GithubObject import NotSet


@dataclass
class GHDependabotAlertState(Enum):
    AUTO_DISMISSED = auto()
    DISMISSED = auto()
    FIXED = auto()
    OPEN = auto()

    def __repr__(self):
        return self.name


@dataclass
class GHDependabotAlertSeverity(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

    @staticmethod
    def from_str(severity: str) -> "GHDependabotAlertSeverity":
        if severity is None:
            raise RuntimeError("severity cannot be None")
        return GHDependabotAlertSeverity.__members__[severity.upper()]

    def __repr__(self):
        return self.name


@dataclass
class GHDependabotAlertEcosystem(Enum):
    COMPOSER = auto()
    GO = auto()
    MAVEN = auto()
    NPM = auto()
    NUGET = auto()
    PIP = auto()
    PUB = auto()
    RUBYGEMS = auto()
    RUST = auto()

    def __repr__(self):
        return self.name


@dataclass
class GHDependabotSearchQuery:
    owner: str
    repo: str
    state: List[GHDependabotAlertState] = None
    severity: List[GHDependabotAlertSeverity] = None
    ecosystem: List[GHDependabotAlertEcosystem] = None

    def __post_init__(self):
        assert self.owner is not None and len(self.owner) > 0
        assert self.repo is not None and len(self.repo) > 0
        for field in [self.state, self.severity, self.ecosystem]:
            if field is not None:
                assert len(field) == len(set([x.name for x in field]))

    @staticmethod
    def __get_field(field: List[Any]) -> typing.List[typing.Union[str, NotSet]]:
        if field is None or len(field) == 0:
            return [NotSet]
        return [x.name.lower() for x in field]

    def get_states(self) -> typing.List[typing.Union[str, NotSet]]:
        return GHDependabotSearchQuery.__get_field(self.state)

    def get_severities(self) -> typing.List[typing.Union[str, NotSet]]:
        return GHDependabotSearchQuery.__get_field(self.severity)

    def get_ecosystems(self) -> typing.List[typing.Union[str, NotSet]]:
        return GHDependabotSearchQuery.__get_field(self.ecosystem)


@dataclass
class GHDependabotAlert:
    html_url: str
    severity: GHDependabotAlertSeverity

    def __init__(self, html_url: str, severity: str):
        assert html_url is not None and len(html_url) > 0
        assert severity is not None and len(severity) > 0

        self.html_url = html_url
        self.severity = GHDependabotAlertSeverity.from_str(severity)
