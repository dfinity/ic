from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from model.dependency import Dependency
from model.security_risk import SecurityRisk
from model.team import Team
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
    """teams that own the projects listed in the corresponding property, might be empty if unknown"""
    owning_teams: List[Team] = field(default_factory=lambda: [])
    """users responsible for patching the vulnerable dependency, might be empty if no one was assigned yet"""
    patch_responsible: List[User] = field(default_factory=lambda: [])
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
        assert self.owning_teams is not None
        assert self.patch_responsible is not None
        assert self.due_date is None or self.due_date >= 0
        assert self.score >= -1
        assert self.more_info is None or len(self.more_info) > 0

    @staticmethod
    def id_for(
        repository: str, scanner: str, vulnerable_dependency_id: str, vulnerable_dependency_version: str
    ) -> Tuple[str, str, str, str]:
        return repository, scanner, vulnerable_dependency_id, vulnerable_dependency_version

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

    def merge_with(self, other: "Finding"):
        """Merges the other finding into this finding"""

        # first check if the findings can be merged (everything except projects and 1st level deps must be the same)
        if self.repository != other.repository:
            raise RuntimeError(
                f"trying to merge two findings from different repos: {self.repository} and {other.repository}"
            )
        if self.scanner != other.scanner:
            raise RuntimeError(
                f"trying to merge two findings from different scanners: {self.scanner} and {other.scanner}"
            )
        if self.vulnerable_dependency != other.vulnerable_dependency:
            raise RuntimeError(
                f"trying to merge two findings with different vulnerable dep: {self.vulnerable_dependency} and {other.vulnerable_dependency}"
            )
        if self.vulnerabilities != other.vulnerabilities:
            raise RuntimeError(
                f"trying to merge two findings with different vulnerabilities: {self.vulnerabilities} and {other.vulnerabilities}"
            )
        if self.risk_assessor != other.risk_assessor:
            raise RuntimeError(
                f"trying to merge two findings with different risk assessors: {self.risk_assessor} and {other.risk_assessor}"
            )
        if self.risk != other.risk:
            raise RuntimeError(f"trying to merge two findings with different risk: {self.risk} and {other.risk}")
        if self.patch_responsible != other.patch_responsible:
            raise RuntimeError(
                f"trying to merge two findings with different patch responsibles: {self.patch_responsible} and {other.patch_responsible}"
            )
        if self.due_date != other.due_date:
            raise RuntimeError(
                f"trying to merge two findings with different due dates: {self.due_date} and {other.due_date}"
            )
        if self.score != other.score:
            raise RuntimeError(
                f"trying to merge two findings with different risk scores: {self.score} and {other.score}"
            )
        if self.more_info != other.more_info:
            raise RuntimeError(
                f"trying to merge two findings with different infos: {self.more_info} and {other.more_info}"
            )

        for project in other.projects:
            if project not in self.projects:
                self.projects.append(project)
        self.projects.sort()

        dep_by_id_version = {}
        for first_lvl_dep in self.first_level_dependencies:
            dep_by_id_version[first_lvl_dep.id + first_lvl_dep.version] = first_lvl_dep

        for first_lvl_dep in other.first_level_dependencies:
            id_version = first_lvl_dep.id + first_lvl_dep.version
            if id_version in dep_by_id_version:
                if first_lvl_dep != dep_by_id_version[id_version]:
                    raise RuntimeError(
                        f"trying to merge two findings with different 1st level deps: {dep_by_id_version[first_lvl_dep.id]} and {first_lvl_dep}"
                    )
            else:
                self.first_level_dependencies.append(first_lvl_dep)
                dep_by_id_version[id_version] = first_lvl_dep
        self.first_level_dependencies.sort(key=lambda x: x.id)

        for team in other.owning_teams:
            if team not in self.owning_teams:
                self.owning_teams.append(team)
        self.owning_teams.sort()

    def __copy_vulnerability_notes_and_update_risk(self, vulnerabilities: List[Vulnerability], determine_risk_from_vulnerabilities: bool, related_finding_risk: Optional[SecurityRisk] = None):
        if determine_risk_from_vulnerabilities:
            self.risk = SecurityRisk.INFORMATIONAL

        previous_vulnerabilities_by_id = {}
        for prev_vulnerability in vulnerabilities:
            previous_vulnerabilities_by_id[prev_vulnerability.id] = prev_vulnerability
        for cur_vulnerability in self.vulnerabilities:
            if cur_vulnerability.id in previous_vulnerabilities_by_id:
                cur_vulnerability.risk_note = previous_vulnerabilities_by_id[cur_vulnerability.id].risk_note
                if determine_risk_from_vulnerabilities:
                    vulnerability_risk = cur_vulnerability.get_risk()
                    # risk assessment might be only done on finding level and not on vulnerability level => if vulnerability doesn't have a risk, fallback to risk of finding
                    self.risk = SecurityRisk.new_risk_from(self.risk, vulnerability_risk if vulnerability_risk else related_finding_risk)
            else:
                self.risk = None

    def update_risk_and_vulnerabilities_for_same_finding(self, same_finding: 'Finding'):
        if self.id() != same_finding.id():
            raise RuntimeError(f"update_risk_and_vulnerabilities_for_same_finding called with finding with different id {self.id()} != {same_finding.id()}")
        old_vulnerabilities = self.vulnerabilities
        self.vulnerabilities = same_finding.vulnerabilities
        self.__copy_vulnerability_notes_and_update_risk(old_vulnerabilities, False)

    def update_risk_and_vulnerabilities_for_related_findings(self, related_findings: List['Finding']):
        if len(related_findings) == 0:
            return

        vulnerability_ids_with_risk_consistency = set()
        previous_vulnerabilities_by_id = {}
        related_finding_risk = related_findings[0].risk
        for finding in related_findings:
            if self.repository != finding.repository or self.scanner != finding.scanner or self.vulnerable_dependency.id != finding.vulnerable_dependency.id:
                raise RuntimeError(f"update_risk_and_vulnerabilities_for_related_findings called with finding with different id components {self.id()} != {finding.id()}")

            # if all related findings have the same risk, we use this as fallback if a vulnerability doesn't have a risk set
            if finding.risk != related_finding_risk:
                related_finding_risk = None

            for vulnerability in finding.vulnerabilities:
                if vulnerability.id in vulnerability_ids_with_risk_consistency:
                    continue

                if vulnerability.id in previous_vulnerabilities_by_id:
                    # this vul was already seen before
                    other_vulnerability = previous_vulnerabilities_by_id[vulnerability.id]
                    if vulnerability.has_risk_note() and other_vulnerability.has_risk_note():
                        if vulnerability.get_risk() != other_vulnerability.get_risk():
                            # both vul have a risk note set and the risk ratings of those don't match
                            # we remember the vul id to ignore future vul with same id and remove it from storage
                            # this means if self also contains this vul the risk rating will be reset and risk assessment is necessary
                            vulnerability_ids_with_risk_consistency.add(vulnerability.id)
                            del previous_vulnerabilities_by_id[vulnerability.id]
                    elif vulnerability.has_risk_note():
                        # the new vul has a risk note and the stored vul not, so replace the stored vul
                        previous_vulnerabilities_by_id[vulnerability.id] = vulnerability
                else:
                    # first time we see this vul, remember it
                    previous_vulnerabilities_by_id[vulnerability.id] = vulnerability

        self.__copy_vulnerability_notes_and_update_risk(list(previous_vulnerabilities_by_id.values()), True, related_finding_risk)
