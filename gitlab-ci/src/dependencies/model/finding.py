from dataclasses import dataclass
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

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
    risk: Optional[SecurityRisk] = None
    """users responsible for patching the vulnerable dependency, might be empty if no one was assigned yet"""
    patch_responsible: List[User] = ()
    """UTC timestamp of the due date of the finding, if it is in future, releases with the vuln. dep. are allowed, might be None if no date was assigned yet"""
    due_date: Optional[int] = None
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

    def id(self) -> Tuple[str, str, str, str]:
        return self.repository, self.scanner, self.vulnerable_dependency.id, self.vulnerable_dependency.version

    def has_patch_version(self, other: Optional["Finding"] = None) -> bool:
        """
        If other is not set, returns true if this finding has some patch version,
        if other is set, returns true if this finding has a patch version that the other finding doesn't have
        """
        if other is None:
            for dep in [self.vulnerable_dependency] + self.first_level_dependencies:
                if len(dep.fix_version_for_vulnerability) > 0:
                    return True
            return False

        if self.id() != other.id():
            raise RuntimeError(
                f"the patch versions of the two findings are not comparable, because the ids doesn't match: {self.id()} != {other.id()}"
            )

        fix_version_by_dep_before: Dict[str, Dict[str, List[str]]] = {}
        for dep in [other.vulnerable_dependency] + other.first_level_dependencies:
            fix_version_by_dep_before[dep.id] = dep.fix_version_for_vulnerability

        for dep in [self.vulnerable_dependency] + self.first_level_dependencies:
            for vuln, patch_versions in dep.fix_version_for_vulnerability.items():
                if (
                    dep.id not in fix_version_by_dep_before
                    or vuln not in fix_version_by_dep_before[dep.id]
                    or len(set(patch_versions).difference(fix_version_by_dep_before[dep.id][vuln])) > 0
                ):
                    return True
        return False
