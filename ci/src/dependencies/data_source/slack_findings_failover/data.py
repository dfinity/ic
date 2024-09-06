from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from model.finding import Finding

VULNERABILITY_HEADER = "Vulnerability Info"
VULNERABILITY_MSG_AUTHOR = "U047BLM1V42"
VULNERABILITY_MSG_FIXED_REACTION = "fixed"
VULNERABILITY_THRESHOLD_SCORE = 8


class SlackVulnerabilityEventType(Enum):
    VULN_ADDED = 1
    VULN_REMOVED = 2
    VULN_CHANGED = 3
    DEP_ADDED = 4
    DEP_REMOVED = 5


@dataclass
class SlackVulnerabilityEvent:
    type: SlackVulnerabilityEventType
    vulnerability_id: str
    channel_id: str
    finding_id: Optional[Tuple[str, str, str, str]] = None
    added_projects: List[str] = field(default_factory=lambda: [])
    removed_projects: List[str] = field(default_factory=lambda: [])
    updated_fields: Dict[str, str] = field(default_factory=lambda: {})

    @staticmethod
    def vuln_added(vuln_id: str, channel_id: str):
        return SlackVulnerabilityEvent(SlackVulnerabilityEventType.VULN_ADDED, vuln_id, channel_id)

    @staticmethod
    def vuln_removed(vuln_id: str, channel_id: str):
        return SlackVulnerabilityEvent(SlackVulnerabilityEventType.VULN_REMOVED, vuln_id, channel_id)

    @staticmethod
    def vuln_changed(vuln_id: str, channel_id: str, updated_fields: Dict[str, str]):
        return SlackVulnerabilityEvent(SlackVulnerabilityEventType.VULN_CHANGED, vuln_id, channel_id, updated_fields=updated_fields)

    @staticmethod
    def dep_added(vuln_id: str, channel_id: str, finding_id: Tuple[str, str, str, str], added_projects: List[str]):
        return SlackVulnerabilityEvent(SlackVulnerabilityEventType.DEP_ADDED, vuln_id, channel_id, finding_id=finding_id, added_projects=added_projects)

    @staticmethod
    def dep_removed(vuln_id: str, channel_id: str, finding_id: Tuple[str, str, str, str], removed_projects: List[str]):
        return SlackVulnerabilityEvent(SlackVulnerabilityEventType.DEP_REMOVED, vuln_id, channel_id, finding_id=finding_id, removed_projects=removed_projects)


@dataclass
class SlackFinding:
    repository: str
    scanner: str
    dependency_id: str
    dependency_version: str
    projects: List[str]

    @staticmethod
    def from_finding(finding: Finding) -> "SlackFinding":
        return SlackFinding(finding.repository, finding.scanner, finding.vulnerable_dependency.id, finding.vulnerable_dependency.version, sorted(finding.projects))

    def id(self) -> Tuple[str, str, str, str]:
        return self.repository, self.scanner, self.dependency_id, self.dependency_version


@dataclass
class SlackProjectInfo:
    project: str
    channels: Set[str]
    risk_assessors_by_channel: Dict[str, List[str]]
