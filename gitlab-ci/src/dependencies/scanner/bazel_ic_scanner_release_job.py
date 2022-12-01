from data_source.console_logger_finding_data_source_subscriber import ConsoleLoggerFindingDataSourceSubscriber
from data_source.jira_finding_data_source import JiraFindingDataSource
from notification.notification_config import NotificationConfig
from notification.slack_notification import SlackNotifier
from scanner.console_logger_scanner_subscriber import ConsoleLoggerScannerSubscriber
from scanner.dependency_manager import Bazel
from scanner.dependency_scanner import BazelICScanner
from scanner.scanner_job_type import ScannerJobType


if __name__ == "__main__":
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
    )
    slack_subscriber = SlackNotifier(config)
    finding_data_source_subscribers = [ConsoleLoggerFindingDataSourceSubscriber(), slack_subscriber]
    scanner_subscribers = [ConsoleLoggerScannerSubscriber(), slack_subscriber]
    scanner_job = BazelICScanner(Bazel(), JiraFindingDataSource(finding_data_source_subscribers), scanner_subscribers)
    scanner_job.on_release_scan()
