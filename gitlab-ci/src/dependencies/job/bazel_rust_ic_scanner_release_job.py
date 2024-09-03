import logging

from data_source.jira_finding_data_source import JiraFindingDataSource
from model.ic import get_ic_repo_ci_pipeline_base_url, get_ic_repo_for_rust, get_ic_repo_merge_request_base_url
from notification.notification_config import NotificationConfig
from notification.notification_creator import NotificationCreator
from scanner.dependency_scanner import DependencyScanner
from scanner.manager.bazel_rust_dependency_manager import BazelRustDependencyManager
from scanner.scanner_job_type import ScannerJobType

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    scanner_job = ScannerJobType.RELEASE_SCAN
    notify_on_scan_job_succeeded, notify_on_scan_job_failed = {}, {}
    for job_type in ScannerJobType:
        notify_on_scan_job_succeeded[job_type] = job_type == scanner_job
        notify_on_scan_job_failed[job_type] = job_type == scanner_job
    notify_on_release_build_blocked: bool = True

    config = NotificationConfig(
        notify_on_release_build_blocked=notify_on_release_build_blocked,
        notify_on_scan_job_succeeded=notify_on_scan_job_succeeded,
        notify_on_scan_job_failed=notify_on_scan_job_failed,
        merge_request_base_url=get_ic_repo_merge_request_base_url(),
        ci_pipeline_base_url=get_ic_repo_ci_pipeline_base_url()
    )
    notifier = NotificationCreator(config)
    finding_data_source_subscribers = [notifier]
    scanner_subscribers = [notifier]
    scanner_job = DependencyScanner(
        BazelRustDependencyManager(), JiraFindingDataSource(finding_data_source_subscribers, app_owner_msg_subscriber=notifier), scanner_subscribers
    )
    scanner_job.do_release_scan(get_ic_repo_for_rust())
