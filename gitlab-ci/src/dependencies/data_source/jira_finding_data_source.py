import logging
import os
from copy import deepcopy
from datetime import datetime
from datetime import timezone
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from data_source.commit_type import CommitType
from data_source.finding_data_source import FindingDataSource
from data_source.finding_data_source_subscriber import FindingDataSourceSubscriber
from jira import Comment
from jira import Issue
from jira import JIRA
from jira import User as JiraUser
from jira.client import ResultList
from jira.resources import CustomFieldOption
from model.dependency import Dependency
from model.finding import Finding
from model.security_risk import SecurityRisk
from model.user import User
from model.vulnerability import Vulnerability

JIRA_SERVER = "https://dfinity.atlassian.net"
JIRA_USER = "vuln-mgmt@dfinity.org"
JIRA_BOARD_KEY = "SCAVM"
JIRA_CURRENT_RISK_ASSESSOR_TICKET = "SCAVM-1"
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
JIRA_LABEL_PATCH_VULNDEP_PUBLISHED = "patch_published_vulndep"
JIRA_LABEL_PATCH_ALLDEP_PUBLISHED = "patch_published_alldep"


class JiraFinding(Finding):
    jira_issue_id: str


class JiraFindingDataSource(FindingDataSource):
    jira: JIRA
    subscribers: List[FindingDataSourceSubscriber]
    findings: Dict[str, Tuple[Finding, Issue]] = {}

    def __init__(self, subscribers: List[FindingDataSourceSubscriber], custom_jira: Optional[JIRA] = None):
        logging.debug(f"JiraFindingDataSource({subscribers},{custom_jira})")
        self.subscribers = subscribers
        self.jira = (
            JIRA(server=JIRA_SERVER, basic_auth=(JIRA_USER, JIRA_API_KEY)) if custom_jira is None else custom_jira
        )

    @staticmethod
    def __finding_to_jira_vulnerabilities(vulnerabilities: List[Vulnerability]) -> str:
        vuln_table: str = "||*id*||*name*||*description*||*score*||\n"
        for vuln in vulnerabilities:
            vuln_table += f"|{JiraFindingDataSource.__finding_to_jira_escape_wiki_renderer_chars(vuln.id)}|{JiraFindingDataSource.__finding_to_jira_escape_wiki_renderer_chars(vuln.name)}|{JiraFindingDataSource.__finding_to_jira_escape_wiki_renderer_chars(vuln.description)}|{vuln.score}|\n"
        return vuln_table

    @staticmethod
    def __jira_to_finding_vulnerabilities(vulnerability_table: str) -> Optional[List[Vulnerability]]:
        if vulnerability_table is None or len(vulnerability_table) <= 0:
            return None

        res: List[Vulnerability] = []
        vuln_table: List[str] = vulnerability_table.splitlines()
        if len(vuln_table) <= 1:
            return None

        for row in vuln_table[1:]:
            parts: List[str] = row.split("|")
            if len(parts) == 6:
                res.append(Vulnerability(id=parts[1], name=parts[2], description=parts[3], score=int(parts[4])))
            else:
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
    ) -> (str, List[str]):
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
    def __finding_to_jira_escape_wiki_renderer_chars(text: str) -> str:
        res = ""
        for i in range(len(text)):
            if text[i] == "|":
                res += ":"
            elif text[i] == "{" and (i == 0 or text[i - 1] != "\\"):
                res += "\\{"
            else:
                res += text[i]
        return res

    @staticmethod
    def __finding_diff_to_jira(finding_old: Optional[Finding], finding_new: Finding) -> Dict[str, Any]:
        res: Dict[str, Any] = {"project": JIRA_BOARD_KEY, "issuetype": JIRA_FINDING_ISSUE_TYPE}
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
        if finding_old is None or finding_old.vulnerabilities != finding_new.vulnerabilities:
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
            ] = f"[{finding_new.repository}][{finding_new.scanner}] Vulnerability in {finding_new.vulnerable_dependency.name} {finding_new.vulnerable_dependency.version}"
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

        return res

    @staticmethod
    def __jira_to_finding(issue: Issue) -> JiraFinding:
        res: Dict[str, Any] = {}
        res["repository"] = issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("repository")[0])
        res["scanner"] = issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("scanner")[0])

        all_deps: Optional[List[Dependency]] = JiraFindingDataSource.__jira_to_finding_dependencies(
            issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("dependencies")[0])
        )
        if all_deps is None:
            raise RuntimeError(f"could not parse dependencies for issue {issue.id}")
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
            raise RuntimeError(f"could not parse vulnerabilities for issue {issue.id}")
        else:
            res["vulnerabilities"] = vulns

        if not JiraFindingDataSource.__jira_to_finding_patch_version(
            issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_versions")[0]), all_deps, vulns
        ):
            logging.warning(f"could not parse patch table for issue {issue.id}")

        projects: Optional[List[str]] = JiraFindingDataSource.__jira_to_finding_projects(
            issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("projects")[0])
        )
        if projects is None:
            res["projects"] = []
            logging.warning(f"could not parse projects for issue {issue.id}")
        else:
            res["projects"] = projects

        res["risk_assessor"] = JiraFindingDataSource.__jira_to_finding_users(
            issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("risk_assessor")[0])
        )
        res["risk"] = JiraFindingDataSource.__jira_to_finding_risk(
            issue.get_field(JIRA_FINDING_TO_CUSTOM_FIELD.get("risk")[0])
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
        finding = JiraFinding(**res)
        finding.jira_issue_id = issue.id
        return finding

    def get_open_finding(
        self, repository: str, scanner: str, dependency_id: str, dependency_version: str
    ) -> Optional[Finding]:
        logging.debug(f"get_open_finding({repository}, {scanner}, {dependency_id}, {dependency_version})")
        if '"' in repository or '"' in scanner or '"' in dependency_id or '"' in dependency_version:
            raise RuntimeError(
                f"detected double quotes in query ({repository},{scanner},{dependency_id},{dependency_version})"
            )
        jql_query: str = (
            f'project = "{JIRA_BOARD_KEY}" and '
            f"issuetype = {JIRA_FINDING_ISSUE_TYPE['id']} and "
            f"status = open and "
            f"\"{JIRA_FINDING_TO_CUSTOM_FIELD.get('repository')[1]}\" ~ \"{repository}\" and "
            f"\"{JIRA_FINDING_TO_CUSTOM_FIELD.get('scanner')[1]}\" ~ \"{scanner}\" and "
            f"\"{JIRA_FINDING_TO_CUSTOM_FIELD.get('vulnerable_dependency_id')[1]}\" ~ \"{dependency_id}\" and "
            f"\"{JIRA_FINDING_TO_CUSTOM_FIELD.get('vulnerable_dependency_version')[1]}\" ~ \"{dependency_version}\""
        )
        logging.debug(f"calling jira.search_issues({jql_query})")
        issues: ResultList[Issue] = self.jira.search_issues(jql_query)
        logging.debug(
            f"received {len(issues)} issue(s) for query ({repository},{scanner},{dependency_id},{dependency_version})"
        )
        if len(issues) > 1:
            raise RuntimeError(
                f"got {len(issues)} findings for query ({repository},{scanner},{dependency_id},{dependency_version})"
            )
        elif len(issues) == 1:
            finding: JiraFinding = self.__jira_to_finding(issues[0])
            if (
                finding.repository != repository
                or finding.scanner != scanner
                or finding.vulnerable_dependency.id != dependency_id
                or finding.vulnerable_dependency.version != dependency_version
            ):
                raise RuntimeError(
                    f"finding primary key does not match expected primary key, expected: ({repository},{scanner},{dependency_id},{dependency_version}), actual: ({finding.repository, finding.scanner, finding.vulnerable_dependency.id, finding.vulnerable_dependency.version})"
                )
            self.findings[finding.jira_issue_id] = (finding, issues[0])
            logging.debug(
                f"returning finding {finding} for query ({repository},{scanner},{dependency_id},{dependency_version})"
            )
            return deepcopy(finding)
        return None

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

    def create_or_update_open_finding(self, finding: Finding):
        logging.debug(f"update_open_finding({finding})")
        finding_new: Finding = deepcopy(finding)
        if isinstance(finding, JiraFinding):
            # update finding if it has changed
            logging.debug(f"calculating diff for finding {finding}")
            finding_old, jira_issue = self.findings[finding.jira_issue_id]
            fields_to_update = self.__finding_diff_to_jira(finding_old, finding)
            if len(fields_to_update) > 0:
                logging.debug(f"updating finding fields {fields_to_update}")
                jira_issue.update(fields_to_update)
                self.findings[finding.jira_issue_id] = (finding_new, jira_issue)
                for sub in self.subscribers:
                    sub.on_finding_updated(deepcopy(finding_old), deepcopy(finding))
            else:
                logging.debug(f"no fields were changed for finding {finding}")
        else:
            # create finding
            logging.debug(f"creating finding {finding}")
            fields_to_update = self.__finding_diff_to_jira(None, finding)
            logging.debug(f"creating finding fields {fields_to_update}")
            jira_issue = self.jira.create_issue(fields_to_update)
            finding.__class__ = JiraFinding
            finding.jira_issue_id = jira_issue.id
            finding.more_info = jira_issue.permalink()
            self.findings[jira_issue.id] = (finding_new, jira_issue)
            for sub in self.subscribers:
                sub.on_finding_created(deepcopy(finding))

    def get_risk_assessor(self) -> List[User]:
        logging.debug("get_risk_assessor()")
        assessors: Optional[List[JiraUser]] = self.jira.issue(JIRA_CURRENT_RISK_ASSESSOR_TICKET).get_field(
            JIRA_FINDING_TO_CUSTOM_FIELD.get("risk_assessor")[0]
        )
        if assessors is None or len(assessors) == 0:
            raise RuntimeError(
                f"risk assessor ticket {JIRA_CURRENT_RISK_ASSESSOR_TICKET} does not contain any risk assessors"
            )
        logging.debug(f"read current risk assessors from ticket {JIRA_CURRENT_RISK_ASSESSOR_TICKET}: {assessors}")
        return self.__jira_to_finding_users(assessors)
