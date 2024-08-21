import logging

from data_source.jira_finding_data_source import JiraFindingDataSource
from model.ic import (
    get_ic_repo_ci_pipeline_base_url,
    get_ic_repo_for_rust,
    get_ic_repo_merge_request_base_url,
    is_env_for_periodic_job,
)
from model.project import Project
from model.repository import Repository
from model.team import Team
from notification.notification_config import NotificationConfig
from notification.notification_creator import NotificationCreator
from scanner.dependency_scanner import DependencyScanner
from scanner.manager.bazel_rust_dependency_manager import BazelRustDependencyManager
from scanner.scanner_job_type import ScannerJobType

REPOS_TO_SCAN = [
    Repository("nns-dapp", "https://github.com/dfinity/nns-dapp", [Project(name="nns-dapp", path="nns-dapp", owner=Team.NNS_TEAM)]),
    Repository("internet-identity", "https://github.com/dfinity/internet-identity", [Project(name="internet-identity", path="internet-identity", owner=Team.GIX_TEAM)]),
    Repository("response-verification", "https://github.com/dfinity/response-verification", [Project(name="response-verification", path="response-verification", owner=Team.TRUST_TEAM)]),
    Repository("agent-rs", "https://github.com/dfinity/agent-rs", [Project(name="agent-rs", path="agent-rs", owner=Team.SDK_TEAM)]),
    Repository("ic-canister-sig-creation", "https://github.com/dfinity/ic-canister-sig-creation", [Project(name="ic-canister-sig-creation", path="ic-canister-sig-creation", owner=Team.GIX_TEAM)]),
    Repository("ic-gateway", "https://github.com/dfinity/ic-gateway", [Project(name="ic-gateway", path="ic-gateway", owner=Team.BOUNDARY_NODE_TEAM)]),
]


def main():
    logging.basicConfig(level=logging.WARNING)
    if not is_env_for_periodic_job():
        logging.warning("skipping periodic RUST job because it is run in the wrong environment")
        return

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
        ci_pipeline_base_url=get_ic_repo_ci_pipeline_base_url()
    )
    notifier = NotificationCreator(config)
    finding_data_source_subscribers = [notifier]
    scanner_subscribers = [notifier]
    scanner_job = DependencyScanner(
        BazelRustDependencyManager(), JiraFindingDataSource(finding_data_source_subscribers, app_owner_msg_subscriber=notifier), scanner_subscribers
    )
    scanner_job.do_periodic_scan([get_ic_repo_for_rust()] + REPOS_TO_SCAN)


if __name__ == "__main__":
    main()
