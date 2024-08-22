import logging
import os
import traceback
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from data_source.commit_type import CommitType
from data_source.finding_data_source import FindingDataSource
from data_source.finding_data_source_subscriber import FindingDataSourceSubscriber
from jira import JIRA, Comment, Issue
from jira import User as JiraUser
from jira.client import ResultList
from jira.resources import CustomFieldOption
from model.dependency import Dependency
from model.finding import Finding
from model.security_risk import SecurityRisk
from model.team import Team
from model.user import User
from model.vulnerability import Vulnerability
from notification.app_owner_msg_subscriber import AppOwnerMsgSubscriber
from notification.console_logger_app_owner_msg_subscriber import ConsoleLoggerAppOwnerMsgSubscriber

JIRA_SERVER = "https://dfinity.atlassian.net"
JIRA_USER = "vuln-mgmt@dfinity.org"
JIRA_BOARD_KEY = "SCAVM"
JIRA_INCIDENT_RESPONDER_EPIC = "PSEC-885"
JIRA_DEFAULT_RISK_ASSESSORS = [
    User(id="62c2a69a7273faf658f02412", name="Thomas Müller", email="thomas.mueller@dfinity.org"),
    User(id="6151750907ac3c00689d2802", name="Venkkatesh Sekar", email="venkkatesh.sekar@dfinity.org"),
]
JIRA_MERGE_REQUEST_EXCEPTION_TICKET = "SCAVM-2"
JIRA_RELEASE_CANDIDATE_EXCEPTION_TICKET = "SCAVM-3"
JIRA_API_KEY = os.environ.get("JIRA_API_TOKEN", "")
if JIRA_API_KEY is None:
    logging.error("JIRA_API_KEY is not set, can't write to JIRA")
JIRA_FINDING_ISSUE_TYPE = {"id": "10414"}
JIRA_FINDING_TO_CUSTOM_FIELD = {
    "repository": ("customfield_10329", "cf[10329]"),
    "scanner": ("customfield_10330", "cf[10330]"),
    "vulnerable_dependency_id": ("customfield_10331", "cf[10331]"),
    "vulnerable_dependency_version": ("customfield_10332", "cf[10332]"),
    "dependencies": ("customfield_10318", "cf[10318]"),
    "vulnerabilities": ("customfield_10319", "cf[10319]"),
    "patch_versions": ("customfield_10320", "cf[10320]"),
    "projects": ("customfield_10317", "cf[10317]"),
    "risk_assessor": ("customfield_10325", "cf[10325]"),
    "risk": ("customfield_10327", "cf[10327]"),
    "owning_teams": ("customfield_10338", "cf[10338]"),
    "patch_responsible": ("customfield_10326", "cf[10326]"),
    "due_date": ("duedate", "duedate"),
    "score": ("customfield_10328", "cf[10328]"),
}
JIRA_SECURITY_RISK_TO_ID = {
    SecurityRisk.INFORMATIONAL: "10590",
    SecurityRisk.LOW: "10591",
    SecurityRisk.MEDIUM: "10592",
    SecurityRisk.HIGH: "10593",
    SecurityRisk.CRITICAL: "10594",
}
JIRA_OWNER_GROUP_BY_TEAM = {
    Team.NODE_TEAM: {"name": "dept-Node"},
    Team.BOUNDARY_NODE_TEAM: {"name": "dept-Boundary Nodes"},
    Team.TRUST_TEAM: {"name": "dept-Trust"},
    Team.GIX_TEAM: {"name": "dept-GIX"},
    Team.SDK_TEAM: {"name": "dept-SDK"},
    Team.FINANCIAL_INTEGRATIONS_TEAM: {"name": "dept-Financial Integrations"},
    Team.EXECUTION_TEAM: {"name": "dept-Execution"},
    Team.NNS_TEAM: {"name": "dept-NNS"},
    Team.CRYPTO_TEAM: {"name": "dept-Crypto Library"},
}
JIRA_LABEL_PATCH_VULNDEP_PUBLISHED = "patch_published_vulndep"
JIRA_LABEL_PATCH_ALLDEP_PUBLISHED = "patch_published_alldep"
JIRA_VULNERABILITY_TABLE_RISK_NOTE_MIGRATION_LABEL = "MIGRATE_ME"


class JiraFindingDataSource(FindingDataSource):
    jira: JIRA
    subscribers: List[FindingDataSourceSubscriber]
    findings: Dict[Tuple[str, str, str, str], Tuple[Finding, Issue]]
    findings_cached_for_scanner: Set[str]
    deleted_findings_cached: Dict[Tuple[str, str, str], List[Tuple[Finding, Issue]]]
    risk_assessors: List[User]
    app_owner_msg_subscriber: AppOwnerMsgSubscriber

    def __init__(self, subscribers: List[FindingDataSourceSubscriber], app_owner_msg_subscriber: AppOwnerMsgSubscriber = ConsoleLoggerAppOwnerMsgSubscriber(), custom_jira: Optional[JIRA] = None):
        logging.debug(f"JiraFindingDataSource({subscribers},{custom_jira})")
        self.subscribers = subscribers
        self.jira = (
            JIRA(server=JIRA_SERVER, basic_auth=(JIRA_USER, JIRA_API_KEY)) if custom_jira is None else custom_jira
        )
        self.findings = {}
        self.findings_cached_for_scanner = set()
        self.deleted_findings_cached = {}
        self.risk_assessors = []
        self.app_owner_msg_subscriber = app_owner_msg_subscriber

    # Remove the unnecessary text strings from the description of the Linux kernel CNA CVEs
    @staticmethod
    def __filter_linux_kernel_cna_cves(vuln_description: str) -> str:
        filter_strings = [
            "In the Linux kernel, the following vulnerability has been resolved: "
        ]
        for filter_string in filter_strings:
            vuln_description = vuln_description.replace(filter_string, "")
        return vuln_description

    @staticmethod
    def __finding_to_jira_vulnerabilities(vulnerabilities: List[Vulnerability]) -> str:
        vuln_table: str = "||*id*||*name*||*description*||*score*||*risk*||\n"
        for vuln in vulnerabilities:
            vuln_table += f"|{JiraFindingDataSource.__finding_to_jira_escape_wiki_renderer_chars(vuln.id)}|{JiraFindingDataSource.__finding_to_jira_escape_wiki_renderer_chars(vuln.name)}|{JiraFindingDataSource.__finding_to_jira_escape_wiki_renderer_chars(JiraFindingDataSource.__filter_linux_kernel_cna_cves(vuln.description))}|{vuln.score}|{JiraFindingDataSource.__finding_to_jira_escape_wiki_renderer_chars(vuln.risk_note if vuln.risk_note != JIRA_VULNERABILITY_TABLE_RISK_NOTE_MIGRATION_LABEL else ' ', True)}|\n"
        return vuln_table

    @staticmethod
    def __jira_to_finding_vulnerabilities(vulnerability_table: str) -> Optional[List[Vulnerability]]:
        if vulnerability_table is None or len(vulnerability_table) <= 0:
            return None

        # the jira editor removes the trailing newline when the vulnerability table is edited (e.g., because risk notes are added to a vulnerability)
        # if this is the case, we have to add it again so that the following split on "|\n" works as expected
        if not vulnerability_table.endswith("\n"):
            vulnerability_table += "\n"

        res: List[Vulnerability] = []
        vuln_table: List[str] = vulnerability_table.split("|\n")
        if len(vuln_table) <= 1:
            return None

        for row in vuln_table[1:-1]:
            # each row is parsed char by char
            # "|" is treated as column separator unless it appears within square brackets,
            # because in that case it is a link: [link text | http://www.example.com]
            # or a smart link: [http://www.example.com | http://www.example.com | smart-link]
            # nested square brackets are not supported
            parts: List[str] = []
            is_link = False
            parsed = ''
            for c in row:
                if c == '[':
                    if is_link:
                        # nested links are not supported
                        return None
                    else:
                        is_link = True
                        parsed += c
                elif c == ']':
                    is_link = False
                    parsed += c
                elif c == '|':
                    if is_link:
                        parsed += c
                    else:
                        parts.append(parsed)
                        parsed = ''
                else:
                    parsed += c
            parts.append(parsed)

            if len(parts) > 1 and parts[1].startswith('[') and parts[1].endswith(']'):
                # jira has changed the vulnerability id to a wiki markup link, e.g.
                # [https://avd.aquasec.com/nvd/cve-2023-35823|https://avd.aquasec.com/nvd/cve-2023-35823]
                # change it back to https://avd.aquasec.com/nvd/cve-2023-35823
                vuln_id_parts = parts[1].split("|")
                if len(vuln_id_parts) != 2:
                    # unexpected format
                    return None
                parts[1] = vuln_id_parts[0][1:]

            if len(parts) == 5:
                # backwards compatibility for entries that don't have risk column
                res.append(Vulnerability(id=parts[1], name=parts[2], description=parts[3], score=int(parts[4]), risk_note=JIRA_VULNERABILITY_TABLE_RISK_NOTE_MIGRATION_LABEL))
            elif len(parts) == 6:
                res.append(Vulnerability(id=parts[1], name=parts[2], description=parts[3], score=int(parts[4]), risk_note=parts[5]))
            else:
                # unexpected format
                return None
        return res

    @staticmethod
    def __finding_to_jira_projects(projects: List[str]) -> str:
        proj_list: str = ""
        for proj in projects:
            proj_list += f"* {JiraFindingDataSource.__finding_to_jira_escape_wiki_renderer_chars(proj)}\n"
        return proj_list

    @staticmethod
    def __jira_to_finding_projects(projects_list: str) -> Optional[List[str]]:
        if projects_list is None or len(projects_list) <= 0:
            return None

        res: List[str] = []
        projects: List[str] = projects_list.splitlines()
        for row in projects:
            parts: List[str] = row.split(" ", 1)
            if len(parts) == 2:
                res.append(parts[1])
            else:
                return None
        return res

    @staticmethod
    def __finding_to_jira_users(users: List[User]) -> List[Dict[str, str]]:
        res: List[Dict[str, str]] = []
        for user in users:
            res.append({"accountId": user.id})
        return res

    @staticmethod
    def __jira_to_finding_users(users: Optional[List[JiraUser]]) -> List[User]:
        res: List[User] = []
        if users is not None:
            for user in users:
                res.append(
                    User(user.accountId, getattr(user, "displayName", None), getattr(user, "emailAddress", None))
                )
        return res

    @staticmethod
    def __finding_to_jira_risk(risk: Optional[SecurityRisk]) -> Optional[Dict[str, str]]:
        if risk is None:
            return None
        return {"id": JIRA_SECURITY_RISK_TO_ID[risk]}

    @staticmethod
    def __jira_to_finding_risk(risk: Optional[CustomFieldOption]) -> Optional[SecurityRisk]:
        if risk is None:
            return None
        if risk.id == JIRA_SECURITY_RISK_TO_ID[SecurityRisk.INFORMATIONAL]:
            return SecurityRisk.INFORMATIONAL
        if risk.id == JIRA_SECURITY_RISK_TO_ID[SecurityRisk.LOW]:
            return SecurityRisk.LOW
        if risk.id == JIRA_SECURITY_RISK_TO_ID[SecurityRisk.MEDIUM]:
            return SecurityRisk.MEDIUM
        if risk.id == JIRA_SECURITY_RISK_TO_ID[SecurityRisk.HIGH]:
            return SecurityRisk.HIGH
        if risk.id == JIRA_SECURITY_RISK_TO_ID[SecurityRisk.CRITICAL]:
            return SecurityRisk.CRITICAL

    @staticmethod
    def __jira_to_finding_owning_teams(owning_teams: Optional[List[Any]]) -> List[Team]:
        owners = []
        if owning_teams:
            for team_obj in owning_teams:
                team = team_obj.name
                for known_team_key, known_team_val in JIRA_OWNER_GROUP_BY_TEAM.items():
                    if team == known_team_val["name"]:
                        owners.append(known_team_key)
                        break
        owners.sort()
        return owners

    @staticmethod
    def __finding_to_jira_dependencies(dependencies: List[Dependency]) -> str:
        dep_table: str = "||*id*||*name*||*version*||\n"
        for dep in dependencies:
            dep_table += f"|{JiraFindingDataSource.__finding_to_jira_escape_wiki_renderer_chars(dep.id)}|{JiraFindingDataSource.__finding_to_jira_escape_wiki_renderer_chars(dep.name)}|{JiraFindingDataSource.__finding_to_jira_escape_wiki_renderer_chars(dep.version)}|\n"
        return dep_table

    @staticmethod
    def __jira_to_finding_dependencies(dependency_table: str) -> Optional[List[Dependency]]:
        if dependency_table is None or len(dependency_table) <= 0:
            return None

        res: List[Dependency] = []
        dep_table: List[str] = dependency_table.splitlines()
        if len(dep_table) <= 1:
            return None

        dep_table = dep_table[1:]
        for i in range(len(dep_table)):
            parts: List[str] = dep_table[i].split("|")
            if len(parts) == 5:
                dep = {"id": parts[1], "name": parts[2], "version": parts[3], "fix_version_for_vulnerability": {}}
                res.append(Dependency(**dep))
            else:
                return None

        return res

    @staticmethod
    def __finding_to_jira_patch_version_labels(
        dependencies: List[Dependency], vulnerabilities: List[Vulnerability]
    ) -> Tuple[str, List[str]]:
        patch_published_for_all_vulns_main_dep: bool = False
        patch_published_for_all_vulns_dep_ctr: int = 0
        patch_table: str = "||*dep / vuln*||"
        for vuln in vulnerabilities:
            patch_table += f"*{JiraFindingDataSource.__finding_to_jira_escape_wiki_renderer_chars(vuln.name)}*||"
        patch_table += "\n"
        for i in range(len(dependencies)):
            dep: Dependency = dependencies[i]
            patch_published_for_all_vulns: bool = True
            patch_table += f"||*{JiraFindingDataSource.__finding_to_jira_escape_wiki_renderer_chars(dep.name)}*|"
            for vuln in vulnerabilities:
                if vuln.id in dep.fix_version_for_vulnerability:
                    patch_versions: str = ";".join(
                        map(
                            lambda x: x.replace(";", ":"),
                            map(
                                JiraFindingDataSource.__finding_to_jira_escape_wiki_renderer_chars,
                                dep.fix_version_for_vulnerability[vuln.id],
                            ),
                        )
                    )
                    patch_table += f"{patch_versions}|"
                else:
                    patch_table += "|"
                    patch_published_for_all_vulns = False
            patch_table += "\n"
            if patch_published_for_all_vulns:
                patch_published_for_all_vulns_dep_ctr += 1
                if i == 0:
                    patch_published_for_all_vulns_main_dep = True
        labels: List[str] = []
        if patch_published_for_all_vulns_main_dep:
            labels.append(JIRA_LABEL_PATCH_VULNDEP_PUBLISHED)
            if patch_published_for_all_vulns_dep_ctr == len(dependencies):
                labels.append(JIRA_LABEL_PATCH_ALLDEP_PUBLISHED)
        return patch_table, labels

    @staticmethod
    def __jira_to_finding_patch_version(
        patch_table: str, dependencies: List[Dependency], vulnerabilities: List[Vulnerability]
    ) -> bool:
        if patch_table is None or len(patch_table) <= 0:
            return False

        patch_table_rows: List[str] = patch_table.splitlines()
        if len(patch_table_rows) <= 1:
            return False

        patch_table_rows = patch_table_rows[1:]
        for i in range(len(patch_table_rows)):
            parts: List[str] = patch_table_rows[i].split("|")
            if len(parts) == len(vulnerabilities) + 4:
                parts = parts[3:-1]
                for j in range(len(vulnerabilities)):
                    fix_versions: List[str] = parts[j].split(";") if len(parts[j]) > 0 else []
                    if len(fix_versions) > 0:
                        dependencies[i].fix_version_for_vulnerability[vulnerabilities[j].id] = fix_versions
            else:
                for dep in dependencies:
                    dep.fix_version_for_vulnerability = {}
                return False

        return True

    @staticmethod
    def __finding_to_jira_due_date(due_date: Optional[int]) -> Optional[str]:
        if due_date is None:
            return None
        return datetime.utcfromtimestamp(due_date).strftime("%Y-%m-%d")

    @staticmethod
    def __jira_to_finding_due_date(due_date: Optional[str]) -> Optional[int]:
        if due_date is None:
            return None
        return int(datetime.timestamp(datetime.strptime(due_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)))

    @staticmethod
    def __finding_to_jira_escape_wiki_renderer_chars(text: str, pipe_allowed: bool = False) -> str:
        res = ""
        for i in range(len(text)):
            if text[i] == "|" and not pipe_allowed:
                res += ":"
            elif text[i] == "{" and (i == 0 or text[i - 1] != "\\"):
                res += "\\{"
            else:
                res += text[i]
        return res

    @staticmethod
    def __finding_diff_to_jira(finding_old: Optional[Finding], finding_new: Finding) -> Dict[str, Any]:
        res: Dict[str, Any] = {}
        summary_update_needed: bool = False
        dep_update_needed: bool = False
        patch_version_update_needed: bool = False

        if finding_old is None or finding_old.repository != finding_new.repository:
            res[JIRA_FINDING_TO_CUSTOM_FIELD.get("repository")[0]] = finding_new.repository
            summary_update_needed = True
        if finding_old is None or finding_old.scanner != finding_new.scanner:
            res[JIRA_FINDING_TO_CUSTOM_FIELD.get("scanner")[0]] = finding_new.scanner
            summary_update_needed = True
        if finding_old is None or finding_old.vulnerable_dependency != finding_new.vulnerable_dependency:
            res[JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_id")[0]] = finding_new.vulnerable_dependency.id
            res[
                JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_version")[0]
            ] = finding_new.vulnerable_dependency.version
            summary_update_needed = True
            dep_update_needed = True
            patch_version_update_needed = True
        if finding_old is None or finding_old.vulnerabilities != finding_new.vulnerabilities or finding_new.vulnerabilities[0].risk_note == JIRA_VULNERABILITY_TABLE_RISK_NOTE_MIGRATION_LABEL:
            res[
                JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerabilities")[0]
            ] = JiraFindingDataSource.__finding_to_jira_vulnerabilities(finding_new.vulnerabilities)
            patch_version_update_needed = True
        if finding_old is None or finding_old.first_level_dependencies != finding_new.first_level_dependencies:
            dep_update_needed = True
            patch_version_update_needed = True
        if finding_old is None or finding_old.projects != finding_new.projects:
            res[JIRA_FINDING_TO_CUSTOM_FIELD.get("projects")[0]] = JiraFindingDataSource.__finding_to_jira_projects(
                finding_new.projects
            )
        if finding_old is None or finding_old.risk_assessor != finding_new.risk_assessor:
            res[JIRA_FINDING_TO_CUSTOM_FIELD.get("risk_assessor")[0]] = JiraFindingDataSource.__finding_to_jira_users(
                finding_new.risk_assessor
            )
        if finding_old is None or finding_old.risk != finding_new.risk:
            res[JIRA_FINDING_TO_CUSTOM_FIELD.get("risk")[0]] = JiraFindingDataSource.__finding_to_jira_risk(
                finding_new.risk
            )
        if finding_old is None or finding_old.owning_teams != finding_new.owning_teams:
            owning_teams = []
            for team in finding_new.owning_teams:
                owning_teams.append(JIRA_OWNER_GROUP_BY_TEAM[team])
            res[JIRA_FINDING_TO_CUSTOM_FIELD.get("owning_teams")[0]] = owning_teams
        if finding_old is None or finding_old.patch_responsible != finding_new.patch_responsible:
            res[
                JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_responsible")[0]
            ] = JiraFindingDataSource.__finding_to_jira_users(finding_new.patch_responsible)
        if finding_old is None or finding_old.due_date != finding_new.due_date:
            res[JIRA_FINDING_TO_CUSTOM_FIELD.get("due_date")[0]] = JiraFindingDataSource.__finding_to_jira_due_date(
                finding_new.due_date
            )
        if finding_old is None or finding_old.score != finding_new.score:
            res[JIRA_FINDING_TO_CUSTOM_FIELD.get("score")[0]] = None if finding_new.score == -1 else finding_new.score

        if summary_update_needed:
            res[
                "summary"
            ] = f"[{finding_new.repository}][{finding_new.scanner}] Vulnerability in {finding_new.vulnerable_dependency.name} {finding_new.vulnerable_dependency.version}"[
                :100
                ]
        all_deps: List[Dependency] = [finding_new.vulnerable_dependency] + finding_new.first_level_dependencies
        if dep_update_needed:
            res[
                JIRA_FINDING_TO_CUSTOM_FIELD.get("dependencies")[0]
            ] = JiraFindingDataSource.__finding_to_jira_dependencies(all_deps)
        if patch_version_update_needed:
            (
                res[JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_versions")[0]],
                res["labels"],
            ) = JiraFindingDataSource.__finding_to_jira_patch_version_labels(all_deps, finding_new.vulnerabilities)

        if len(res) > 0:
            res["project"] = JIRA_BOARD_KEY
            res["issuetype"] = JIRA_FINDING_ISSUE_TYPE
        return res

    @staticmethod
    def __jira_to_finding(issue: Issue) -> Finding:
        # noinspection PyDictCreation
        res: Dict[str, Any] = {}
        res["repository"] = issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("repository")[0])
        res["scanner"] = issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("scanner")[0])

        all_deps: Optional[List[Dependency]] = JiraFindingDataSource.__jira_to_finding_dependencies(
            issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("dependencies")[0])
        )
        if all_deps is None:
            raise RuntimeError(f"could not parse dependencies for issue {issue.permalink()}")
        else:
            res["vulnerable_dependency"] = all_deps[0]
            # id & version might have been escaped with __finding_to_jira_escape_wiki_renderer_chars, so use unescaped variants
            res["vulnerable_dependency"].id = issue.get_field(
                JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_id")[0]
            )
            res["vulnerable_dependency"].version = issue.get_field(
                JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_version")[0]
            )
            res["first_level_dependencies"] = all_deps[1:]

        vulns: Optional[List[Vulnerability]] = JiraFindingDataSource.__jira_to_finding_vulnerabilities(
            issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerabilities")[0])
        )
        if vulns is None:
            raise RuntimeError(f"could not parse vulnerabilities for issue {issue.permalink()}")
        else:
            res["vulnerabilities"] = vulns

        if not JiraFindingDataSource.__jira_to_finding_patch_version(
            issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_versions")[0]), all_deps, vulns
        ):
            logging.warning(f"could not parse patch table for issue {issue.permalink()}")

        projects: Optional[List[str]] = JiraFindingDataSource.__jira_to_finding_projects(
            issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("projects")[0])
        )
        if projects is None:
            res["projects"] = []
            logging.warning(f"could not parse projects for issue {issue.permalink()}")
        else:
            res["projects"] = projects

        res["risk_assessor"] = JiraFindingDataSource.__jira_to_finding_users(
            issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("risk_assessor")[0])
        )
        res["risk"] = JiraFindingDataSource.__jira_to_finding_risk(
            issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("risk")[0])
        )
        res["owning_teams"] = JiraFindingDataSource.__jira_to_finding_owning_teams(
            issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("owning_teams")[0])
        )
        res["patch_responsible"] = JiraFindingDataSource.__jira_to_finding_users(
            issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_responsible")[0])
        )
        res["due_date"] = JiraFindingDataSource.__jira_to_finding_due_date(
            issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("due_date")[0])
        )
        res["more_info"] = issue.permalink()
        score = issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("score")[0])
        res["score"] = -1 if score is None else int(score)
        finding = Finding(**res)
        return finding

    def __load_findings_for_scanner(self, scanner: str):
        if scanner in self.findings_cached_for_scanner:
            return
        logging.debug(f"__load_findings_for_scanner({scanner})")
        jql_query: str = (
            f'project = "{JIRA_BOARD_KEY}" and '
            f"issuetype = {JIRA_FINDING_ISSUE_TYPE['id']} and "
            f"status = open and "
            f"\"{JIRA_FINDING_TO_CUSTOM_FIELD.get('scanner')[1]}\" ~ \"{scanner}\""
        )
        logging.debug(f"calling jira.search_issues({jql_query})")
        issues: ResultList[Issue] = self.jira.search_issues(jql_str=jql_query, maxResults=False)
        logging.debug(f"received {len(issues)} issue(s) for query ({scanner})")
        for issue in issues:
            finding: Finding = self.__jira_to_finding(issue)
            if finding.id() in self.findings:
                self.findings.clear()
                raise RuntimeError(f"finding with id {finding.id()} exists twice")
            self.findings[finding.id()] = (finding, issue)
        self.findings_cached_for_scanner.add(scanner)

    def get_open_finding(
        self, repository: str, scanner: str, dependency_id: str, dependency_version: str
    ) -> Optional[Finding]:
        logging.debug(f"get_open_finding({repository}, {scanner}, {dependency_id}, {dependency_version})")
        self.__load_findings_for_scanner(scanner)
        finding_id = Finding.id_for(repository, scanner, dependency_id, dependency_version)
        if finding_id in self.findings:
            return deepcopy(self.findings[finding_id][0])
        return None

    def get_open_findings_for_repo_and_scanner(
        self, repository: str, scanner: str
    ) -> Dict[Tuple[str, str, str, str], Finding]:
        logging.debug(f"get_open_findings_for_repo_and_scanner({repository}, {scanner})")
        self.__load_findings_for_scanner(scanner)
        res: Dict[Tuple[str, str, str, str], Finding] = {}
        for finding_and_issue in self.findings.values():
            finding = finding_and_issue[0]
            if finding.repository == repository and finding.scanner == scanner:
                res[finding.id()] = deepcopy(finding)
        return res

    def get_deleted_findings(
        self, repository: str, scanner: str, dependency_id: str
    ) -> List[Finding]:
        cache_key = (repository, scanner, dependency_id)
        if cache_key in self.deleted_findings_cached:
            return deepcopy(list(map(lambda x: x[0], self.deleted_findings_cached[cache_key])))

        logging.debug(f"get_deleted_findings({repository}, {scanner}, {dependency_id})")
        jql_query: str = (
            f'project = "{JIRA_BOARD_KEY}" and '
            f"issuetype = {JIRA_FINDING_ISSUE_TYPE['id']} and "
            f"status != open and "
            f"\"{JIRA_FINDING_TO_CUSTOM_FIELD.get('repository')[1]}\" ~ \"{repository}\" and "
            f"\"{JIRA_FINDING_TO_CUSTOM_FIELD.get('scanner')[1]}\" ~ \"{scanner}\" and "
            f"\"{JIRA_FINDING_TO_CUSTOM_FIELD.get('vulnerable_dependency_id')[1]}\" ~ \"{dependency_id}\" "
            f"ORDER BY created DESC"
        )
        logging.debug(f"calling jira.search_issues({jql_query})")
        issues: ResultList[Issue] = self.jira.search_issues(jql_str=jql_query, maxResults=100)
        logging.debug(f"received {len(issues)} non-open issue(s) for query ({repository}, {scanner}, {dependency_id})")
        result = []
        for issue in issues:
            finding: Finding = self.__jira_to_finding(issue)
            if finding.repository == repository and finding.scanner == scanner and finding.vulnerable_dependency.id == dependency_id:
                result.append((finding, issue))
        self.deleted_findings_cached[cache_key] = result
        return deepcopy(list(map(lambda x: x[0], result)))

    def commit_has_block_exception(self, commit_type: CommitType, commit_hash: str) -> bool:
        logging.debug(f"commit_has_block_exception({commit_type}, {commit_hash})")
        ticket: str = (
            JIRA_MERGE_REQUEST_EXCEPTION_TICKET
            if commit_type == CommitType.MERGE_COMMIT
            else JIRA_RELEASE_CANDIDATE_EXCEPTION_TICKET
        )
        comments: List[Comment] = self.jira.comments(ticket)
        if comments is not None:
            for comment in comments:
                if commit_hash in comment.body:
                    logging.debug(f'found commit hash {commit_hash} in comment "{comment.body}" of ticket {ticket}')
                    return True
        logging.debug(f"did not find commit hash {commit_hash} in comments of ticket {ticket}")
        return False

    @staticmethod
    def __does_exceed_character_limit(finding: Finding, fields_to_update: Dict[str, Any]):
        does_exceed = False
        for field_name, field_value in fields_to_update.items():
            try:
                if len(field_value) > 32700:
                    logging.warning(f"field {field_name} in finding {finding.id()} exceeds character limit with {len(field_value)} characters")
                    does_exceed = True
            except TypeError:
                pass  # some types don't have a length

        return does_exceed

    def create_or_update_open_finding(self, finding: Finding):
        logging.debug(f"create_or_update_open_finding({finding})")
        self.__load_findings_for_scanner(finding.scanner)
        finding_new: Finding = deepcopy(finding)
        if finding.id() in self.findings:
            # update finding if it has changed
            logging.debug(f"calculating diff for finding {finding}")
            finding_old, jira_issue = self.findings[finding.id()]
            fields_to_update = self.__finding_diff_to_jira(finding_old, finding)
            if len(fields_to_update) > 0:
                if self.__does_exceed_character_limit(finding, fields_to_update):
                    # print warning and notify app owners
                    log_msg = f"skipping update of the following finding because some fields exceed character limit: {finding.id()} "
                    logging.warning(log_msg)
                    self.app_owner_msg_subscriber.send_notification_to_app_owners(log_msg)
                else:
                    logging.debug(f"updating finding fields {fields_to_update}")
                    jira_issue.update(fields_to_update)
                    self.findings[finding.id()] = (finding_new, jira_issue)
            else:
                logging.debug(f"no fields were changed for finding {finding}")
            for sub in self.subscribers:
                sub.on_finding_refreshed(deepcopy(finding_old), deepcopy(finding))
        else:
            # create finding
            logging.debug(f"creating finding {finding}")
            fields_to_update = self.__finding_diff_to_jira(None, finding)
            if self.__does_exceed_character_limit(finding, fields_to_update):
                # print warning and notify app owners
                log_msg = f"skipping creation of the following finding because some fields exceed character limit: {finding.id()}"
                logging.warning(log_msg)
                self.app_owner_msg_subscriber.send_notification_to_app_owners(log_msg)
            else:
                logging.debug(f"creating finding fields {fields_to_update}")
                jira_issue = self.jira.create_issue(fields_to_update)
                finding.more_info = jira_issue.permalink()
                self.findings[finding.id()] = (finding_new, jira_issue)
                for sub in self.subscribers:
                    sub.on_finding_created(deepcopy(finding))

    def delete_finding(self, finding: Finding):
        logging.debug(f"delete_finding({finding})")
        self.__load_findings_for_scanner(finding.scanner)

        if finding.id() in self.findings:
            finding_stored, jira_issue = self.findings[finding.id()]
            self.jira.transition_issue(jira_issue.id, "41")
            for sub in self.subscribers:
                sub.on_finding_deleted(finding_stored)

    def link_findings(self, finding_a: Finding, finding_b: Finding):
        logging.debug(f"link_findings({finding_a}, {finding_b})")

        # finding_a might be a deleted finding or an existing finding
        deleted_finding_cache_key = (finding_a.repository, finding_a.scanner, finding_a.vulnerable_dependency.id)
        jira_issue_a = None
        if deleted_finding_cache_key in self.deleted_findings_cached:
            for finding_issue in self.deleted_findings_cached[deleted_finding_cache_key]:
                if finding_issue[0].more_info == finding_a.more_info:
                    jira_issue_a = finding_issue[1]
                    break
        if not jira_issue_a and finding_a.id() in self.findings:
            _, jira_issue_a = self.findings[finding_a.id()]

        # finding_b is always an existing finding
        if jira_issue_a and finding_b.id() in self.findings:
            _, jira_issue_b = self.findings[finding_b.id()]
            self.jira.create_issue_link(type="Relates", inwardIssue=jira_issue_a.key, outwardIssue=jira_issue_b.key)

    def get_risk_assessor(self) -> List[User]:
        logging.debug("get_risk_assessor()")
        if len(self.risk_assessors) > 0:
            return self.risk_assessors

        try:
            incident_responder_tickets: List[Issue] = self.jira.search_issues(
                f'"Epic Link" = {JIRA_INCIDENT_RESPONDER_EPIC} AND status != Done'
            )
            if incident_responder_tickets is None or len(incident_responder_tickets) == 0:
                raise RuntimeError(
                    f"found no open incident responders tickets under epic {JIRA_INCIDENT_RESPONDER_EPIC}"
                )
            incident_responder_ticket_keys: List[str] = [iss.key for iss in incident_responder_tickets]
            assessors: Optional[List[JiraUser]] = list(
                filter(lambda x: x is not None, map(lambda x: x.get_field("assignee"), incident_responder_tickets))
            )
            if assessors is None or len(assessors) == 0:
                raise RuntimeError(f"found no assignees in incident responder tickets {incident_responder_ticket_keys}")
            logging.debug(f"read current risk assessors from tickets {incident_responder_ticket_keys}: {assessors}")
            self.risk_assessors = self.__jira_to_finding_users(assessors)
            return self.risk_assessors
        except RuntimeError:
            logging.error(
                "could not determine risk assessors by ticket\nusing default risk assessors instead"
            )
            logging.debug(
                f"could not determine risk assessors by ticket, reason:\n{traceback.format_exc()}"
            )
            return JIRA_DEFAULT_RISK_ASSESSORS
