from data_source.console_logger_finding_data_source_subscriber import ConsoleLoggerFindingDataSourceSubscriber
from data_source.jira_finding_data_source import JiraFindingDataSource
from model.project import Project
from model.repository import Repository
from model.team import Team
from notification.notification_config import NotificationConfig
from notification.notification_creator import NotificationCreator
from scanner.console_logger_scanner_subscriber import ConsoleLoggerScannerSubscriber
from scanner.dependency_scanner import DependencyScanner
from scanner.manager.npm_dependency_manager import NPMDependencyManager
from scanner.scanner_job_type import ScannerJobType

DEFAULT_NODE_VERSION = 19

REPOS_TO_SCAN = [
    Repository(
        "ic",
        "https://gitlab.com/dfinity-lab/public/ic",
        [
            Project(
                name="service-worker",
                path="ic/typescript/service-worker",
                owner=Team.TRUST_TEAM,
            )
        ],
        18,
    ),
    Repository(
        "nns-dapp",
        "https://github.com/dfinity/nns-dapp",
        [
            Project(
                name="frontend",
                path="nns-dapp/frontend",
                owner=Team.GIX_TEAM,
            )
        ],
        18,
    ),
    Repository(
        "internet-identity",
        "https://github.com/dfinity/internet-identity",
        [
            Project(
                name="internet-identity",
                path="internet-identity",
                owner=Team.GIX_TEAM,
            )
        ],
        DEFAULT_NODE_VERSION,
    ),
    Repository(
        "ic-js",
        "https://github.com/dfinity/ic-js",
        [
            Project(
                name="ic-js",
                path="ic-js",
                owner=Team.GIX_TEAM,
            )
        ],
        DEFAULT_NODE_VERSION
    ),
    Repository(
        "agent-js",
        "https://github.com/dfinity/agent-js",
        [
            Project(
                name="agent-js",
                path="agent-js",
                owner=Team.SDK_TEAM,
            )
        ],
        16),
    Repository(
        "cycles-wallet",
        "https://github.com/dfinity/cycles-wallet",
        [
            Project(
                name="cycles-wallet",
                path="cycles-wallet",
                owner=Team.SDK_TEAM,
            )
        ],
        DEFAULT_NODE_VERSION,
    ),
    Repository(
        "rosetta-client",
        "https://github.com/dfinity/rosetta-client",
        [
            Project(
                name="rosetta-client",
                path="rosetta-client",
                owner=Team.FINANCIAL_INTEGRATIONS_TEAM,
            )
        ],
        DEFAULT_NODE_VERSION,
    ),
    Repository(
        "hardware-wallet-cli",
        "https://github.com/dfinity/hardware-wallet-cli",
        [
            Project(
                name="hardware-wallet-cli",
                path="hardware-wallet-cli",
                owner=Team.GIX_TEAM,
            )
        ],
        DEFAULT_NODE_VERSION,
    ),
    Repository(
        "gix-components",
        "https://github.com/dfinity/gix-components",
        [
            Project(
                name="gix-components",
                path="gix-components",
                owner=Team.GIX_TEAM,
            )
        ],
        DEFAULT_NODE_VERSION,
    ),
    Repository(
        "ic-docutrack",
        "https://github.com/dfinity/ic-docutrack",
        [
            Project(
                name="frontend",
                path="ic-docutrack/frontend",
                owner=Team.EXECUTION_TEAM,
            )
        ],
        DEFAULT_NODE_VERSION,
    ),
]

if __name__ == "__main__":
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
    )
    notifier = NotificationCreator(config)
    finding_data_source_subscribers = [ConsoleLoggerFindingDataSourceSubscriber(), notifier]
    scanner_subscribers = [ConsoleLoggerScannerSubscriber(), notifier]
    scanner_job = DependencyScanner(
        NPMDependencyManager(), JiraFindingDataSource(finding_data_source_subscribers), scanner_subscribers
    )
    scanner_job.do_periodic_scan(REPOS_TO_SCAN)
