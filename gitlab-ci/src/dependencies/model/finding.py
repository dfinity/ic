from dataclasses import dataclass
from typing import List
from typing import Optional

from model.dependency import Dependency
from model.security_risk import SecurityRisk
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
    """list of projects that use the vulnerable dependency"""
    projects: List[str]
    """unique identifier for the risk assessor of the finding"""
    risk_assessor: str
    """current risk assessment, might be None if no risk assessment was done or reassessment is necessary"""
    risk: Optional[SecurityRisk]
    """unique identifier for the patch responsible, might be None if no one was assigned yet"""
    patch_responsible: Optional[str]
    """UTC timestamp of the due date of the finding, if it is in future, releases with the vuln. dep. are allowed"""
    due_date: int
    """additional information about the finding in human-readable format, e.g., link to finding"""
    more_info: str
    """highest vulnerability score or -1 if no score could be determined"""
    score: int = -1
