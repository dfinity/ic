from dataclasses import dataclass
from typing import List
from typing import Optional

from model.dependency import Dependency
from model.security_risk import SecurityRisk
from model.user import User
from model.vulnerability import Vulnerability


@dataclass
class Finding:
    """unique identifier for the repository of the finding"""

    repository: str
    """unique identifier for the scanner that detected the finding"""
    scanner: str
    """information about the vulnerable dependency"""
    vulnerable_dependency: Dependency
    """information about the vulnerabilities of the vulnerable dependency"""
    vulnerabilities: List[Vulnerability]
    """information about the first level dependencies in case vulnerable_dependency is a transitive dependency"""
    first_level_dependencies: List[Dependency]
    """list of projects that use the vulnerable dependency, might be empty if projects are not relevant for the given repository"""
    projects: List[str]
    """users responsible for assessing the risk of the finding"""
    risk_assessor: List[User]
    """current risk assessment, might be None if no risk assessment was done or reassessment is necessary"""
    risk: Optional[SecurityRisk]
    """users responsible for patching the vulnerable dependency, might be empty if no one was assigned yet"""
    patch_responsible: List[User]
    """UTC timestamp of the due date of the finding, if it is in future, releases with the vuln. dep. are allowed, might be None if no date was assigned yet"""
    due_date: Optional[int]
    """highest vulnerability score or -1 if no score could be determined"""
    score: int = -1
    """additional information about the finding in human-readable format, e.g., link to finding"""
    more_info: Optional[str] = None

    def __post_init__(self):
        """Validate field values after initialization"""
        assert self.repository is not None and len(self.repository) > 0
        assert self.scanner is not None and len(self.scanner) > 0
        assert self.vulnerable_dependency is not None
        assert self.vulnerabilities is not None and len(self.vulnerabilities) > 0
        assert self.projects is not None
        assert self.risk_assessor is not None
        assert self.patch_responsible is not None
        assert self.due_date is None or self.due_date >= 0
        assert self.score >= -1
        assert self.more_info is None or len(self.more_info) > 0
