from dataclasses import dataclass, field
from typing import Dict, List

from integration.slack.slack_default_notification_handler import SlackDefaultNotificationHandler
from notification.notification_handler import NotificationHandler
from scanner.scanner_job_type import ScannerJobType


def default_scan_job_settings() -> Dict[ScannerJobType, bool]:
    res = {}
    for job_type in ScannerJobType:
        res[job_type] = False
    return res


@dataclass
class NotificationConfig:
    notify_on_merge_request_blocked: bool = False
    notify_on_release_build_blocked: bool = False
    notify_on_scan_job_succeeded: Dict[ScannerJobType, bool] = field(default_factory=default_scan_job_settings)
    notify_on_scan_job_failed: Dict[ScannerJobType, bool] = field(default_factory=default_scan_job_settings)

    notify_on_finding_risk_assessment_needed: bool = False
    notify_on_finding_patch_version_available: bool = False
    notify_on_finding_deleted: bool = False

    merge_request_base_url: str = "https://github.com/dfinity/ic/pull/"
    ci_pipeline_base_url: str = "https://github.com/dfinity/ic/actions/runs/"

    notification_handlers: List[NotificationHandler] = field(default_factory=lambda: [SlackDefaultNotificationHandler()])

    def __post_init__(self):
        """Validate field values after initialization"""
        for boolean_field in [
            self.notify_on_merge_request_blocked,
            self.notify_on_release_build_blocked,
            self.notify_on_finding_risk_assessment_needed,
            self.notify_on_finding_patch_version_available,
            self.notify_on_finding_deleted,
        ]:
            assert boolean_field is not None
            assert boolean_field is True or boolean_field is False

        for notify_scan_job in [self.notify_on_scan_job_succeeded, self.notify_on_scan_job_failed]:
            assert notify_scan_job is not None
            for job_type in ScannerJobType:
                assert job_type in notify_scan_job
                assert notify_scan_job[job_type] is True or notify_scan_job[job_type] is False

        for str_field in [self.merge_request_base_url, self.ci_pipeline_base_url]:
            assert str_field is not None and len(str_field) > 0

        assert self.notification_handlers is not None
