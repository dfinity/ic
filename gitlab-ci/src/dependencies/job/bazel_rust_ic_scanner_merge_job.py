import logging

from data_source.jira_finding_data_source import JiraFindingDataSource
from notification.notification_config import NotificationConfig
from notification.notification_creator import NotificationCreator
from scanner.dependency_scanner import DependencyScanner
from scanner.manager.bazel_rust_dependency_manager import BazelRustDependencyManager
from scanner.scanner_job_type import ScannerJobType

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    scanner_job = ScannerJobType.MERGE_SCAN
    notify_on_scan_job_succeeded, notify_on_scan_job_failed = {}, {}
    for job_type in ScannerJobType:
        notify_on_scan_job_succeeded[job_type] = False
        notify_on_scan_job_failed[job_type] = job_type == scanner_job
    notify_on_merge_request_blocked: bool = True

    config = NotificationConfig(
        notify_on_merge_request_blocked=notify_on_merge_request_blocked,
        notify_on_scan_job_succeeded=notify_on_scan_job_succeeded,
        notify_on_scan_job_failed=notify_on_scan_job_failed,
    )
    notifier = NotificationCreator(config)
    finding_data_source_subscribers = [notifier]
    scanner_subscribers = [notifier]
    scanner_job = DependencyScanner(
        BazelRustDependencyManager(), JiraFindingDataSource(finding_data_source_subscribers), scanner_subscribers
    )
    scanner_job.do_merge_request_scan("ic")
