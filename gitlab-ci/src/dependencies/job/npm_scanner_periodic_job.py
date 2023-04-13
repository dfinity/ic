from data_source.console_logger_finding_data_source_subscriber import ConsoleLoggerFindingDataSourceSubscriber
from data_source.jira_finding_data_source import JiraFindingDataSource
from model.repository import Project, Repository
from notification.notification_config import NotificationConfig
from notification.slack_notification import SlackNotifier
from scanner.console_logger_scanner_subscriber import ConsoleLoggerScannerSubscriber
from scanner.dependency_scanner import DependencyScanner
from scanner.manager.npm_dependency_manager import NPMDependencyManager
from scanner.scanner_job_type import ScannerJobType

DEFAULT_NODE_VERSION = 19

REPOS_TO_SCAN = [
    Repository(
        "ic",
        "https://gitlab.com/dfinity-lab/public/ic",
        [Project("service-worker", "ic/typescript/service-worker")],
        17,
    ),
    Repository(
        "nns-dapp",
        "https://github.com/dfinity/nns-dapp",
        [Project("frontend", "nns-dapp/frontend")],
        18,
    ),
    Repository(
        "internet-identity",
        "https://github.com/dfinity/internet-identity",
        [Project("internet-identity", "internet-identity")],
        DEFAULT_NODE_VERSION,
    ),
    Repository("ic-js", "https://github.com/dfinity/ic-js", [Project("ic-js", "ic-js")], DEFAULT_NODE_VERSION),
    Repository("agent-js", "https://github.com/dfinity/agent-js", [Project("agent-js", "agent-js")], 16),
    Repository(
        "cycles-wallet",
        "https://github.com/dfinity/cycles-wallet",
        [Project("cycles-wallet", "cycles-wallet")],
        DEFAULT_NODE_VERSION,
    ),
    Repository(
        "rosetta-client",
        "https://github.com/dfinity/rosetta-client",
        [Project("rosetta-client", "rosetta-client")],
        DEFAULT_NODE_VERSION,
    ),
    Repository(
        "hardware-wallet-cli",
        "https://github.com/dfinity/hardware-wallet-cli",
        [Project("hardware-wallet-cli", "hardware-wallet-cli")],
        DEFAULT_NODE_VERSION,
    ),
    Repository(
        "gix-components",
        "https://github.com/dfinity/gix-components",
        [Project("gix-components", "gix-components")],
        DEFAULT_NODE_VERSION,
    ),
    Repository(
        "ic-docutrack",
        "https://github.com/dfinity/ic-docutrack",
        [Project("frontend", "ic-docutrack/frontend")],
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

    config = NotificationConfig(
        notify_on_finding_risk_assessment_needed=notify_on_finding_risk_assessment_needed,
        notify_on_finding_patch_version_available=notify_on_finding_patch_version_available,
        notify_on_scan_job_succeeded=notify_on_scan_job_succeeded,
        notify_on_scan_job_failed=notify_on_scan_job_failed,
    )
    slack_subscriber = SlackNotifier(config)
    finding_data_source_subscribers = [ConsoleLoggerFindingDataSourceSubscriber(), slack_subscriber]
    scanner_subscribers = [ConsoleLoggerScannerSubscriber(), slack_subscriber]
    scanner_job = DependencyScanner(
        NPMDependencyManager(), JiraFindingDataSource(finding_data_source_subscribers), scanner_subscribers
    )
    scanner_job.do_periodic_scan(REPOS_TO_SCAN)
