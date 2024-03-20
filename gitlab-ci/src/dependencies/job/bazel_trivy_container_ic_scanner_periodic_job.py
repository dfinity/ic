import logging

from data_source.jira_finding_data_source import JiraFindingDataSource
from integration.slack.slack_default_notification_handler import SlackDefaultNotificationHandler
from integration.slack.slack_trivy_finding_notification_handler import SlackTrivyFindingNotificationHandler
from model.project import Project
from model.repository import Repository
from model.team import Team
from notification.notification_config import NotificationConfig
from notification.notification_creator import NotificationCreator
from scanner.dependency_scanner import DependencyScanner
from scanner.manager.bazel_trivy_dependency_manager import BazelTrivyContainer
from scanner.scanner_job_type import ScannerJobType

REPOS_TO_SCAN = [
    Repository(
        "ic",
        "https://gitlab.com/dfinity-lab/public/ic",
        [
            Project(
                name="boundary-guestos",
                path="ic/ic-os/boundary-guestos/envs/prod",
                link="https://gitlab.com/dfinity-lab/public/ic/-/tree/master/ic-os/boundary-guestos/rootfs",
                owner=Team.BOUNDARY_NODE_TEAM,
            ),
            Project(
                name="guestos",
                path="ic/ic-os/guestos/envs/prod",
                link="https://gitlab.com/dfinity-lab/public/ic/-/tree/master/ic-os/guestos/rootfs",
                owner=Team.NODE_TEAM,
            ),
        ],
    )
]

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
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
        notification_handlers=[SlackTrivyFindingNotificationHandler(), SlackDefaultNotificationHandler()]
    )
    notifier = NotificationCreator(config)
    finding_data_source_subscribers = [notifier]
    scanner_subscribers = [notifier]
    scanner_job = DependencyScanner(
        BazelTrivyContainer(app_owner_msg_subscriber=notifier),
        JiraFindingDataSource(finding_data_source_subscribers),
        scanner_subscribers,
    )
    scanner_job.do_periodic_scan(REPOS_TO_SCAN)
