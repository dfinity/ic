import abc
import logging
import os
import traceback
import typing

from data_source.finding_data_source import FindingDataSource
from scanner.dependency_manager import DependencyManager
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

    def on_merge_request_scan(self):
        raise NotImplementedError

    def on_periodic_scan(self):
        scanner = "BAZEL_IC"
        repository = "ic"
        # TODO : test on CI
        # Is this the right parameter for CI_JOB_ID. Or should I use Pipeline ID?
        job_id = os.environ.get("CI_PIPELINE_ID", "CI_PIPELINE_ID")
        try:
            findings = self.dependency_manager.get_findings(repository, scanner)
            if len(findings) > 0:
                for index, finding in enumerate(findings):
                    vulnerable_dependency = finding.vulnerable_dependency
                    jira_finding = self.finding_data_source.get_open_finding(
                        repository, scanner, vulnerable_dependency.id, vulnerable_dependency.version
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
                subscriber.on_scan_job_succeeded(ScannerJobType.PERIODIC_SCAN, job_id)
        except Exception as err:
            logging.error(f"{scanner} for {repository} failed for {job_id} with error:\n{traceback.format_exc()}")
            for subscriber in self.subscribers:
                subscriber.on_scan_job_failed(ScannerJobType.PERIODIC_SCAN, job_id, str(err))

    def on_release_scan(self):
        raise NotImplementedError
