import abc
import datetime
import logging
import os
import sys
import traceback
import typing

from data_source.commit_type import CommitType
from data_source.finding_data_source import FindingDataSource
from model.finding import Finding
from model.security_risk import SecurityRisk
from scanner.dependency_manager import DependencyManager
from scanner.gitlab_comment import GitlabComment
from scanner.scanner_job_type import ScannerJobType
from scanner.scanner_subscriber import ScannerSubscriber


class DependencyScanner(abc.ABC):
    """Base class for helper classes for different scanners"""

    @abc.abstractmethod
    def on_periodic_scan(self):
        """Perform scanner actions for a periodic scan"""
        raise NotImplementedError

    @abc.abstractmethod
    def on_merge_request_scan(self):
        """Perform scanner actions on merge request"""
        raise NotImplementedError

    @abc.abstractmethod
    def on_release_scan(self):
        """Perform scanner actions on release job"""
        raise NotImplementedError


class BazelICScanner(DependencyScanner):
    def __init__(
        self,
        dependency_manager: DependencyManager,
        finding_data_source: FindingDataSource,
        scanner_subscribers: typing.List[ScannerSubscriber],
    ):
        self.subscribers = scanner_subscribers
        self.dependency_manager = dependency_manager
        self.finding_data_source = finding_data_source
        self.scanner = "BAZEL_IC"
        self.repository = "ic"
        self.job_id = os.environ.get("CI_PIPELINE_ID", "CI_PIPELINE_ID")

    def on_merge_request_scan(self):
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
            findings = self.dependency_manager.get_findings(self.repository, self.scanner)

            if len(findings) == 0:
                return

            findings_to_flag: typing.List[Finding] = []
            for index, finding in enumerate(findings):
                vulnerable_dependency = finding.vulnerable_dependency
                jira_finding = self.finding_data_source.get_open_finding(
                    self.repository, self.scanner, vulnerable_dependency.id, vulnerable_dependency.version
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

            # At this point it is guaranteed there's is new finding and there's no exception granted.
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

            gitlab_comment = GitlabComment(job_type=ScannerJobType.MERGE_SCAN)
            gitlab_comment.comment_on_gitlab(info=findings_to_flag)

            merge_request_id = os.environ.get("CI_MERGE_REQUEST_IID", "CI_MERGE_REQUEST_IID")
            for subscriber in self.subscribers:
                subscriber.on_merge_request_blocked(self.job_id, merge_request_id)
            logging.error(f"There were new findings in the MR and no exceptions were granted. {findings_to_flag}")

            sys.exit(1)
        except Exception as err:
            should_fail_job = True
            logging.error(
                f"{self.scanner} for {self.repository} failed for {self.job_id} with error:\n {traceback.format_exc()}"
            )
            for subscriber in self.subscribers:
                subscriber.on_scan_job_failed(ScannerJobType.MERGE_SCAN, self.job_id, str(err))
        finally:
            if not should_fail_job:
                for subscriber in self.subscribers:
                    subscriber.on_scan_job_succeeded(ScannerJobType.MERGE_SCAN, self.job_id)

    def on_periodic_scan(self):
        try:
            findings = self.dependency_manager.get_findings(self.repository, self.scanner)
            if len(findings) > 0:
                for index, finding in enumerate(findings):
                    vulnerable_dependency = finding.vulnerable_dependency
                    jira_finding = self.finding_data_source.get_open_finding(
                        self.repository, self.scanner, vulnerable_dependency.id, vulnerable_dependency.version
                    )
                    if jira_finding:
                        # update vulnerabilities and clear risk if we have new vulnerabilities
                        if jira_finding.vulnerabilities != findings[index].vulnerabilities:
                            jira_finding.vulnerabilities = findings[index].vulnerabilities
                            jira_finding.risk = None
                        if jira_finding.first_level_dependencies != findings[index].first_level_dependencies:
                            jira_finding.first_level_dependencies = findings[index].first_level_dependencies
                        if jira_finding.projects != findings[index].projects:
                            jira_finding.projects = findings[index].projects
                        if jira_finding.vulnerable_dependency != findings[index].vulnerable_dependency:
                            jira_finding.vulnerable_dependency = findings[index].vulnerable_dependency
                        # max score is already calculated by the dependency manager.
                        jira_finding.score = findings[index].score
                        self.finding_data_source.create_or_update_open_finding(jira_finding)
                    else:
                        findings[index].risk_assessor = self.finding_data_source.get_risk_assessor()
                        # rest of the parameters needs to be set by the risk assessor for a new finding.
                        self.finding_data_source.create_or_update_open_finding(findings[index])
            for subscriber in self.subscribers:
                subscriber.on_scan_job_succeeded(ScannerJobType.PERIODIC_SCAN, self.job_id)
        except Exception as err:
            logging.error(
                f"{self.scanner} for {self.repository} failed for {self.job_id} with error:\n{traceback.format_exc()}"
            )
            for subscriber in self.subscribers:
                subscriber.on_scan_job_failed(ScannerJobType.PERIODIC_SCAN, self.job_id, str(err))

    def on_release_scan(self):
        should_fail_job = False
        try:
            findings = self.dependency_manager.get_findings(self.repository, self.scanner)
            failures: typing.List = []

            if len(findings) == 0:
                return

            for finding in findings:
                vulnerable_dependency = finding.vulnerable_dependency
                jira_finding = self.finding_data_source.get_open_finding(
                    self.repository, self.scanner, vulnerable_dependency.id, vulnerable_dependency.version
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
            # TODO : Figure where to comment for gitlab
            # gitlab_comment = GitlabComment(job_type=ScannerJobType.RELEASE_SCAN)
            # gitlab_comment.comment_on_gitlab(info=failures)
            for subscriber in self.subscribers:
                subscriber.on_release_build_blocked(self.job_id)
            logging.error(f"Release job failed with failures : {failures}")

        except Exception as err:
            should_fail_job = True
            logging.error(
                f"{self.scanner} for {self.repository} failed for {self.job_id} with error:\n {traceback.format_exc()}"
            )
            for subscriber in self.subscribers:
                subscriber.on_scan_job_failed(ScannerJobType.RELEASE_SCAN, self.job_id, str(err))
        finally:
            # TODO : for now, the job would log the new findings in the console
            # Once tested enough, we can start failing the jobs
            # TODO : Add a comment on gitlab on the instructions to resolve the MR
            if not should_fail_job:
                for subscriber in self.subscribers:
                    subscriber.on_scan_job_succeeded(ScannerJobType.RELEASE_SCAN, self.job_id)
            # else :
            #     sys.exit(1)
