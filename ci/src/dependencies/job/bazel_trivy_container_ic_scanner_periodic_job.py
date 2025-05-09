import logging

from config.bazel_trivy_periodic import REPOS_TO_SCAN
from data_source.jira_finding_data_source import JiraFindingDataSource
from data_source.slack_findings_failover_data_store import SlackFindingsFailoverDataStore
from integration.slack.slack_default_notification_handler import SlackDefaultNotificationHandler
from integration.slack.slack_trivy_finding_notification_handler import SlackTrivyFindingNotificationHandler
from model.ic import get_ic_repo_ci_pipeline_base_url, get_ic_repo_merge_request_base_url
from model.log_level import get_log_level
from notification.notification_config import NotificationConfig
from notification.notification_creator import NotificationCreator
from scanner.dependency_scanner import DependencyScanner
from scanner.manager.bazel_trivy_dependency_manager import BazelTrivyContainer
from scanner.scanner_job_type import ScannerJobType


def main():
    logging.basicConfig(level=get_log_level())

    scanner_job = ScannerJobType.PERIODIC_SCAN
    notify_on_scan_job_succeeded, notify_on_scan_job_failed = {}, {}
    for job_type in ScannerJobType:
        notify_on_scan_job_succeeded[job_type] = job_type == scanner_job
        notify_on_scan_job_failed[job_type] = job_type == scanner_job

    notify_on_finding_risk_assessment_needed: bool = True
    notify_on_finding_patch_version_available: bool = True
    notify_on_finding_deleted: bool = True

    config = NotificationConfig(
        notify_on_finding_risk_assessment_needed=notify_on_finding_risk_assessment_needed,
        notify_on_finding_patch_version_available=notify_on_finding_patch_version_available,
        notify_on_finding_deleted=notify_on_finding_deleted,
        notify_on_scan_job_succeeded=notify_on_scan_job_succeeded,
        notify_on_scan_job_failed=notify_on_scan_job_failed,
        merge_request_base_url=get_ic_repo_merge_request_base_url(),
        ci_pipeline_base_url=get_ic_repo_ci_pipeline_base_url(),
        notification_handlers=[SlackTrivyFindingNotificationHandler(), SlackDefaultNotificationHandler()],
    )
    notifier = NotificationCreator(config)
    finding_data_source_subscribers = [notifier]
    scanner_subscribers = [notifier]
    scanner_job = DependencyScanner(
        BazelTrivyContainer(app_owner_msg_subscriber=notifier),
        JiraFindingDataSource(finding_data_source_subscribers, app_owner_msg_subscriber=notifier),
        scanner_subscribers,
        SlackFindingsFailoverDataStore(projects=REPOS_TO_SCAN[0].projects if len(REPOS_TO_SCAN) > 0 else []),
    )
    scanner_job.do_periodic_scan(REPOS_TO_SCAN)


if __name__ == "__main__":
    main()
