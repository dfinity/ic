import datetime
import logging
import os
import pathlib
import shutil
import sys
import traceback
import typing

from data_source.commit_type import CommitType
from data_source.finding_data_source import FindingDataSource
from data_source.findings_failover_data_store import FindingsFailoverDataStore
from integration.github.github_api import GithubApi
from integration.github.github_app import GithubApp
from model.finding import Finding
from model.repository import Repository
from model.security_risk import SecurityRisk
from scanner.manager.dependency_manager import DependencyManager
from scanner.process_executor import ProcessExecutor
from scanner.scanner_job_type import ScannerJobType
from scanner.scanner_subscriber import ScannerSubscriber

PROJECT_ROOT = pathlib.Path(
    os.environ.get("CI_PROJECT_DIR", pathlib.Path(__file__).absolute().parent.parent.parent.parent.parent)
)


class DependencyScanner:
    """generic scanner that performs periodic/merge/release scans with the configured dependency manager"""

    def __init__(
        self,
        dependency_manager: DependencyManager,
        finding_data_source: FindingDataSource,
        scanner_subscribers: typing.List[ScannerSubscriber],
        failover_data_store: typing.Optional[FindingsFailoverDataStore] = None,
        github_app: GithubApp = None,
    ):
        self.subscribers = scanner_subscribers
        self.dependency_manager = dependency_manager
        self.finding_data_source = finding_data_source
        self.failover_data_store = failover_data_store
        self.github_app = github_app
        self.job_id = os.environ.get("CI_PIPELINE_ID", "CI_PIPELINE_ID")
        self.root = PROJECT_ROOT

    def __clone_repository_from_url(self, url: str, path: pathlib.Path):
        environment = {}
        cwd = path

        if self.github_app:
            checkout_url = self.github_app.get_checkout_url(url)
        else:
            checkout_url = url
        command = f"git clone --depth=1 {checkout_url}"
        logging.info(f"Performing git clone {url}")
        _ = ProcessExecutor.execute_command(command, cwd.resolve(), environment, log_command=False)
        return

    def do_periodic_scan(self, repositories: typing.List[Repository]):
        for repository in repositories:
            repo_cloned = False
            repo_top_level_path = self.root.parent / repository.name
            try:
                finding_by_id: typing.Dict[typing.Tuple[str, str, str, str], Finding] = {}
                if repository.name != "ic":
                    # we are cloning an external repository
                    if repo_top_level_path.is_dir():
                        # git clone fails if the directory already exists
                        shutil.rmtree(repo_top_level_path)
                    self.__clone_repository_from_url(repository.url, self.root.parent)
                    repo_cloned = True
                for project in repository.projects:
                    path = self.root.parent / project.path
                    if not path.is_dir():
                        raise RuntimeError(f"path {path} is invalid")
                    logging.info(f"Calling dependency manager for {repository.name} {path} {project.name}")
                    findings_for_project = self.dependency_manager.get_findings(
                        repository.name, project, repository.engine_version
                    )
                    for finding in findings_for_project:
                        for project_owner in project.get_owners_for(finding):
                            if project_owner not in finding.owning_teams:
                                finding.owning_teams.append(project_owner)
                        finding.owning_teams.sort()
                        if finding.id() in finding_by_id:
                            finding_by_id[finding.id()].merge_with(finding)
                        else:
                            finding_by_id[finding.id()] = finding

                existing_findings: typing.Dict[typing.Tuple[str, str, str, str], Finding] = (
                    self.finding_data_source.get_open_findings_for_repo_and_scanner(
                        repository.name, self.dependency_manager.get_scanner_id()
                    )
                )
                current_findings: typing.List[Finding] = list(finding_by_id.values())
                if len(current_findings) > 0:
                    existing_findings_by_vul_dep_id = {}
                    for finding in existing_findings.values():
                        dependency_id = finding.vulnerable_dependency.id
                        if dependency_id not in existing_findings_by_vul_dep_id:
                            existing_findings_by_vul_dep_id[dependency_id] = []
                        existing_findings_by_vul_dep_id[dependency_id].append(finding)

                    failover_findings = []
                    for index, finding in enumerate(current_findings):
                        jira_finding = existing_findings.get(finding.id())
                        if self.failover_data_store and self.failover_data_store.can_handle(current_findings[index]):
                            # the finding is handled by the failover store (because it can't be handled by finding_data_source)
                            failover_findings.append(current_findings[index])
                            if jira_finding:
                                # if there is an existing finding in the finding_data_source we delete it to avoid confusion
                                self.finding_data_source.delete_finding(jira_finding)
                        elif jira_finding:
                            # update vulnerabilities and clear risk if we have new vulnerabilities
                            if jira_finding.vulnerabilities != current_findings[index].vulnerabilities:
                                jira_finding.update_risk_and_vulnerabilities_for_same_finding(current_findings[index])
                            if (
                                jira_finding.first_level_dependencies
                                != current_findings[index].first_level_dependencies
                            ):
                                jira_finding.first_level_dependencies = current_findings[index].first_level_dependencies
                            if jira_finding.projects != current_findings[index].projects:
                                jira_finding.projects = current_findings[index].projects
                            if jira_finding.vulnerable_dependency != current_findings[index].vulnerable_dependency:
                                jira_finding.vulnerable_dependency = current_findings[index].vulnerable_dependency
                            if jira_finding.owning_teams != current_findings[index].owning_teams:
                                # add all owning teams from the current finding to the jira finding
                                # this allows manually adding owning teams in jira
                                for team in current_findings[index].owning_teams:
                                    if team not in jira_finding.owning_teams:
                                        jira_finding.owning_teams.append(team)
                                jira_finding.owning_teams.sort()
                            # max score is already calculated by the dependency manager.
                            jira_finding.score = current_findings[index].score
                            self.finding_data_source.create_or_update_open_finding(jira_finding)
                        else:
                            cur_finding = current_findings[index]
                            cur_finding.risk_assessor = self.finding_data_source.get_risk_assessor()
                            prev_open_findings = (
                                existing_findings_by_vul_dep_id[cur_finding.vulnerable_dependency.id]
                                if cur_finding.vulnerable_dependency.id in existing_findings_by_vul_dep_id
                                else []
                            )
                            prev_deleted_findings = self.finding_data_source.get_deleted_findings(
                                repository.name,
                                self.dependency_manager.get_scanner_id(),
                                cur_finding.vulnerable_dependency.id,
                            )
                            cur_finding.update_risk_and_vulnerabilities_for_related_findings(
                                prev_open_findings + prev_deleted_findings
                            )

                            # rest of the parameters needs to be set by the risk assessor for a new finding.
                            self.finding_data_source.create_or_update_open_finding(cur_finding)
                            for prev_finding in prev_open_findings:
                                self.finding_data_source.link_findings(prev_finding, cur_finding)
                            if len(prev_deleted_findings) > 0:
                                # only link the last created deleted finding to the current finding
                                self.finding_data_source.link_findings(prev_deleted_findings[0], cur_finding)

                    if self.failover_data_store:
                        self.failover_data_store.store_findings(
                            repository.name, self.dependency_manager.get_scanner_id(), failover_findings
                        )

                findings_to_remove = set(existing_findings.keys()).difference(map(lambda x: x.id(), current_findings))
                for key in findings_to_remove:
                    self.finding_data_source.delete_finding(existing_findings[key])
            except Exception as err:
                logging.error(
                    f"{self.dependency_manager.get_scanner_id()} for {repository.name} failed for {self.job_id}."
                )
                logging.debug(
                    f"{self.dependency_manager.get_scanner_id()} for {repository.name} failed for {self.job_id} with error:\n{traceback.format_exc()}"
                )
                for subscriber in self.subscribers:
                    subscriber.on_scan_job_failed(
                        self.dependency_manager.get_scanner_id() + f"_{repository.name}",
                        ScannerJobType.PERIODIC_SCAN,
                        self.job_id,
                        str(err),
                    )
            finally:
                # delete the repo in order to save disk space
                if repo_cloned and repo_top_level_path.is_dir():
                    shutil.rmtree(repo_top_level_path)
        for subscriber in self.subscribers:
            subscriber.on_scan_job_succeeded(
                self.dependency_manager.get_scanner_id(), ScannerJobType.PERIODIC_SCAN, self.job_id
            )

    def do_merge_request_scan(self, repository: Repository):
        should_fail_job = False
        try:
            dependency_changes = self.dependency_manager.has_dependencies_changed()
            if not dependency_changes["cargo_lock_toml"]:
                return

            # There has been updates to the lock files
            modified_packages = self.dependency_manager.get_modified_packages()
            dependency_diff = self.dependency_manager.get_dependency_diff()

            if not dependency_changes["external_crates_bzl"]:
                return

            # developer has added made changes to dependencies.
            findings = self.dependency_manager.get_findings(repository.name, repository.projects[0], None)

            if len(findings) == 0:
                return

            findings_to_flag: typing.List[Finding] = []
            for index, finding in enumerate(findings):
                vulnerable_dependency = finding.vulnerable_dependency
                jira_finding = self.finding_data_source.get_open_finding(
                    repository.name,
                    self.dependency_manager.get_scanner_id(),
                    vulnerable_dependency.id,
                    vulnerable_dependency.version,
                )
                if not jira_finding:
                    findings_to_flag.append(finding)

            if len(findings_to_flag) == 0:
                return

            # There are findings to be reported.
            # check for exception
            # Developers should be notified that they get commit exception only
            git_commit_sha = os.environ.get("CI_COMMIT_SHA", "CI_COMMIT_SHA")
            exception = self.finding_data_source.commit_has_block_exception(CommitType.MERGE_COMMIT, git_commit_sha)

            if exception:
                return

            # At this point it is guaranteed there is new finding and there's no exception granted.
            # The job should be failed and communicated to the developer
            for index, _ in enumerate(findings_to_flag):
                temp_projects = findings_to_flag[index].projects
                findings_to_flag[index].projects = [
                    project for project in temp_projects if project in modified_packages
                ]

                temp_first_level_dependencies = findings_to_flag[index].first_level_dependencies
                findings_to_flag[index].first_level_dependencies = [
                    dep for dep in temp_first_level_dependencies if dep in dependency_diff
                ]

            github_api = GithubApi()
            github_api.comment_on_github(info=findings_to_flag)

            merge_request_id = os.environ.get("CI_MERGE_REQUEST_IID", "CI_MERGE_REQUEST_IID")
            for subscriber in self.subscribers:
                subscriber.on_merge_request_blocked(
                    self.dependency_manager.get_scanner_id(), self.job_id, merge_request_id
                )
            logging.error("There were new findings in the MR and no exceptions were granted.")
            logging.debug(f"There were new findings in the MR and no exceptions were granted. {findings_to_flag}")

            sys.exit(1)
        except Exception as err:
            should_fail_job = True
            logging.error(f"{self.dependency_manager.get_scanner_id()} for {repository.name} failed for {self.job_id}.")
            logging.debug(
                f"{self.dependency_manager.get_scanner_id()} for {repository.name} failed for {self.job_id} with error:\n{traceback.format_exc()}"
            )
            for subscriber in self.subscribers:
                subscriber.on_scan_job_failed(
                    self.dependency_manager.get_scanner_id(), ScannerJobType.MERGE_SCAN, self.job_id, str(err)
                )
        finally:
            if not should_fail_job:
                for subscriber in self.subscribers:
                    subscriber.on_scan_job_succeeded(
                        self.dependency_manager.get_scanner_id(), ScannerJobType.MERGE_SCAN, self.job_id
                    )

    def do_release_scan(self, repository: Repository):
        should_fail_job = False
        try:
            findings = self.dependency_manager.get_findings(repository.name, repository.projects[0], None)
            failures: typing.List = []

            if len(findings) == 0:
                return

            for finding in findings:
                vulnerable_dependency = finding.vulnerable_dependency
                jira_finding = self.finding_data_source.get_open_finding(
                    repository.name,
                    self.dependency_manager.get_scanner_id(),
                    vulnerable_dependency.id,
                    vulnerable_dependency.version,
                )
                if jira_finding:
                    if not jira_finding.risk:
                        failures.append(f"Risk assessment not done for {jira_finding.more_info}")

                    if (jira_finding.risk == SecurityRisk.HIGH or jira_finding.risk == SecurityRisk.CRITICAL) and (
                        not jira_finding.due_date
                        or jira_finding.due_date - int(datetime.datetime.utcnow().timestamp()) < 0
                    ):
                        failures.append(
                            f"Risk for finding {jira_finding.more_info} crosses release threshold and due date for fixing it has passed"
                        )
                else:
                    failures.append(f"New finding has been found {finding}")

            if len(failures) == 0:
                return

            git_commit_sha = os.environ.get("CI_COMMIT_SHA", "CI_COMMIT_SHA")
            exception = self.finding_data_source.commit_has_block_exception(CommitType.RELEASE_COMMIT, git_commit_sha)

            if exception:
                return

            # At this point, there are failures and there is no exceptions
            # Job must be failed
            for subscriber in self.subscribers:
                subscriber.on_release_build_blocked(self.dependency_manager.get_scanner_id(), self.job_id)
            logging.error("Release job failed with failures.")
            logging.info(f"Release job failed with failures : {failures}")

            sys.exit(1)
        except Exception as err:
            should_fail_job = True
            logging.error(f"{self.dependency_manager.get_scanner_id()} for {repository.name} failed for {self.job_id}.")
            logging.debug(
                f"{self.dependency_manager.get_scanner_id()} for {repository.name} failed for {self.job_id} with error:\n{traceback.format_exc()}"
            )
            for subscriber in self.subscribers:
                subscriber.on_scan_job_failed(
                    self.dependency_manager.get_scanner_id(), ScannerJobType.RELEASE_SCAN, self.job_id, str(err)
                )
        finally:
            if not should_fail_job:
                for subscriber in self.subscribers:
                    subscriber.on_scan_job_succeeded(
                        self.dependency_manager.get_scanner_id(), ScannerJobType.RELEASE_SCAN, self.job_id
                    )
