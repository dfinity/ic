from dataclasses import dataclass

from model.finding import Finding
from scanner.scanner_job_type import ScannerJobType


@dataclass
class NotificationEvent:
    pass

@dataclass
class MRBlockedNotificationEvent(NotificationEvent):
    scanner_id: str
    ci_job_url: str
    merge_request_url: str

    def __post_init__(self):
        """Validate field values after initialization"""
        assert self.scanner_id is not None and len(self.scanner_id) > 0
        assert self.ci_job_url is not None and len(self.ci_job_url) > 0
        assert self.merge_request_url is not None and len(self.merge_request_url) > 0


@dataclass
class ReleaseBlockedNotificationEvent(NotificationEvent):
    scanner_id: str
    ci_job_url: str

    def __post_init__(self):
        """Validate field values after initialization"""
        assert self.scanner_id is not None and len(self.scanner_id) > 0
        assert self.ci_job_url is not None and len(self.ci_job_url) > 0

@dataclass
class ScanJobSucceededNotificationEvent(NotificationEvent):
    scanner_id: str
    job_type: ScannerJobType
    ci_job_url: str

    def __post_init__(self):
        """Validate field values after initialization"""
        assert self.scanner_id is not None and len(self.scanner_id) > 0
        assert self.job_type is not None
        assert self.ci_job_url is not None and len(self.ci_job_url) > 0

@dataclass
class ScanJobFailedNotificationEvent(NotificationEvent):
    scanner_id: str
    job_type: ScannerJobType
    ci_job_url: str
    reason: str

    def __post_init__(self):
        """Validate field values after initialization"""
        assert self.scanner_id is not None and len(self.scanner_id) > 0
        assert self.job_type is not None
        assert self.ci_job_url is not None and len(self.ci_job_url) > 0
        assert self.reason is not None and len(self.reason) > 0

@dataclass
class FindingNotificationEvent(NotificationEvent):
    finding: Finding
    finding_needs_risk_assessment: bool
    finding_has_patch_version: bool
    finding_was_resolved: bool

    def __post_init__(self):
        """Validate field values after initialization"""
        for boolean_field in [
            self.finding_needs_risk_assessment,
            self.finding_has_patch_version,
            self.finding_was_resolved,
        ]:
            assert boolean_field is not None
            assert boolean_field is True or boolean_field is False

        assert self.finding is not None

@dataclass
class AppOwnerNotificationEvent(NotificationEvent):
    message: str

    def __post_init__(self):
        """Validate field values after initialization"""
        assert self.message is not None and len(self.message) > 0
