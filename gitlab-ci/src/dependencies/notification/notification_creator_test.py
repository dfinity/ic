import pytest
from model.dependency import Dependency
from model.finding import Finding
from model.security_risk import SecurityRisk
from model.user import User
from model.vulnerability import Vulnerability
from notification.notification_config import NotificationConfig
from notification.notification_creator import NotificationCreator
from notification.notification_event import (
    AppOwnerNotificationEvent,
    FindingNotificationEvent,
    MRBlockedNotificationEvent,
    NotificationEvent,
    ReleaseBlockedNotificationEvent,
    ScanJobFailedNotificationEvent,
    ScanJobSucceededNotificationEvent,
)
from notification.notification_handler import NotificationHandler
from scanner.scanner_job_type import ScannerJobType

FINDING_WITH_RISK_YES_PATCH_YES = Finding(
    repository="repo",
    scanner="scanner",
    vulnerable_dependency=Dependency("dep_id", "dep_name", "dep_ver", {"vuln_id": ["dep_ver2"]}),
    vulnerabilities=[Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
    first_level_dependencies=[],
    projects=[],
    risk_assessor=[User("user_id1", "user_name1", "user1@mail.com"), User("user_id2", "user_name2", "user2@mail.com")],
    risk=SecurityRisk.INFORMATIONAL,
    more_info="https://dfinity.atlassian.net/browse/SCAVM-5",
)

FINDING_WITH_RISK_YES_PATCH_NO = Finding(
    repository="repo",
    scanner="scanner",
    vulnerable_dependency=Dependency("dep_id", "dep_name", "dep_ver", {}),
    vulnerabilities=[Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
    first_level_dependencies=[],
    projects=[],
    risk_assessor=[User("user_id1", "user_name1", "user1@mail.com"), User("user_id2", "user_name2", "user2@mail.com")],
    risk=SecurityRisk.INFORMATIONAL,
    more_info="https://dfinity.atlassian.net/browse/SCAVM-5",
)

FINDING_WITH_RISK_NO_PATCH_YES = Finding(
    repository="repo",
    scanner="scanner",
    vulnerable_dependency=Dependency("dep_id", "dep_name", "dep_ver", {"vuln_id": ["dep_ver2"]}),
    vulnerabilities=[Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
    first_level_dependencies=[],
    projects=[],
    risk_assessor=[User("user_id1", "user_name1", "user1@mail.com"), User("user_id2", "user_name2", "user2@mail.com")],
    risk=None,
    more_info="https://dfinity.atlassian.net/browse/SCAVM-5",
)

FINDING_WITH_RISK_NO_PATCH_NO = Finding(
    repository="repo",
    scanner="scanner",
    vulnerable_dependency=Dependency("dep_id", "dep_name", "dep_ver", {}),
    vulnerabilities=[Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
    first_level_dependencies=[],
    projects=[],
    risk_assessor=[User("user_id1", "user_name1", "user1@mail.com"), User("user_id2", "user_name2", "user2@mail.com")],
    risk=None,
    more_info="https://dfinity.atlassian.net/browse/SCAVM-5",
)


def test_on_merge_request_blocked_notify_if_enabled():
    handler = MockNotificationHandler()
    config = NotificationConfig(notify_on_merge_request_blocked=True, notification_handlers=[handler])
    notifier = NotificationCreator(config)

    notifier.on_merge_request_blocked("scanner_id", "job_id", "merge_request_id")

    assert len(handler.events) == 1
    event = handler.events[0]
    assert isinstance(event, MRBlockedNotificationEvent)
    assert event.scanner_id == "scanner_id"
    assert event.ci_job_url == f"{config.ci_pipeline_base_url}job_id"
    assert event.merge_request_url == f"{config.merge_request_base_url}merge_request_id"


def test_on_merge_request_blocked_dont_notify_if_disabled():
    handler = MockNotificationHandler()
    config = NotificationConfig(notify_on_merge_request_blocked=False, notification_handlers=[handler])
    notifier = NotificationCreator(config)

    notifier.on_merge_request_blocked("scanner_id", "job_id", "merge_request_id")

    assert len(handler.events) == 0


def test_on_release_build_blocked_notify_if_enabled():
    handler = MockNotificationHandler()
    config = NotificationConfig(notify_on_release_build_blocked=True, notification_handlers=[handler])
    notifier = NotificationCreator(config)

    notifier.on_release_build_blocked("scanner_id", "job_id")

    assert len(handler.events) == 1
    event = handler.events[0]
    assert isinstance(event, ReleaseBlockedNotificationEvent)
    assert event.scanner_id == "scanner_id"
    assert event.ci_job_url == f"{config.ci_pipeline_base_url}job_id"


def test_on_release_build_blocked_dont_notify_if_disabled():
    handler = MockNotificationHandler()
    config = NotificationConfig(notify_on_release_build_blocked=False, notification_handlers=[handler])
    notifier = NotificationCreator(config)

    notifier.on_release_build_blocked("scanner_id", "job_id")

    assert len(handler.events) == 0


@pytest.mark.parametrize(
    "selected_job_type", [ScannerJobType.PERIODIC_SCAN, ScannerJobType.MERGE_SCAN, ScannerJobType.RELEASE_SCAN]
)
def test_on_scan_job_succeeded_notify_if_enabled(selected_job_type):
    handler = MockNotificationHandler()
    notify_on_scan_job_succeeded = {}
    for job_type in ScannerJobType:
        notify_on_scan_job_succeeded[job_type] = job_type == selected_job_type
    config = NotificationConfig(notify_on_scan_job_succeeded=notify_on_scan_job_succeeded, notification_handlers=[handler])
    notifier = NotificationCreator(config)

    notifier.on_scan_job_succeeded("scanner_id", selected_job_type, "job_id")

    assert len(handler.events) == 1
    event = handler.events[0]
    assert isinstance(event, ScanJobSucceededNotificationEvent)
    assert event.scanner_id == "scanner_id"
    assert event.job_type == selected_job_type
    assert event.ci_job_url == f"{config.ci_pipeline_base_url}job_id"


@pytest.mark.parametrize(
    "selected_job_type", [ScannerJobType.PERIODIC_SCAN, ScannerJobType.MERGE_SCAN, ScannerJobType.RELEASE_SCAN]
)
def test_on_scan_job_succeeded_dont_notify_if_disabled(selected_job_type):
    handler = MockNotificationHandler()
    notify_on_scan_job_succeeded = {}
    for job_type in ScannerJobType:
        notify_on_scan_job_succeeded[job_type] = job_type != selected_job_type
    config = NotificationConfig(notify_on_scan_job_succeeded=notify_on_scan_job_succeeded, notification_handlers=[handler])
    notifier = NotificationCreator(config)

    notifier.on_scan_job_succeeded("scanner_id", selected_job_type, "job_id")

    assert len(handler.events) == 0


@pytest.mark.parametrize(
    "selected_job_type", [ScannerJobType.PERIODIC_SCAN, ScannerJobType.MERGE_SCAN, ScannerJobType.RELEASE_SCAN]
)
def test_on_scan_job_failed_notify_if_enabled(selected_job_type):
    handler = MockNotificationHandler()
    notify_on_scan_job_failed = {}
    for job_type in ScannerJobType:
        notify_on_scan_job_failed[job_type] = job_type == selected_job_type
    config = NotificationConfig(notify_on_scan_job_failed=notify_on_scan_job_failed, notification_handlers=[handler])
    notifier = NotificationCreator(config)

    notifier.on_scan_job_failed("scanner_id", selected_job_type, "job_id", "some error reason")

    assert len(handler.events) == 1
    event = handler.events[0]
    assert isinstance(event, ScanJobFailedNotificationEvent)
    assert event.scanner_id == "scanner_id"
    assert event.job_type == selected_job_type
    assert event.ci_job_url == f"{config.ci_pipeline_base_url}job_id"
    assert event.reason == "some error reason"


@pytest.mark.parametrize(
    "selected_job_type", [ScannerJobType.PERIODIC_SCAN, ScannerJobType.MERGE_SCAN, ScannerJobType.RELEASE_SCAN]
)
def test_on_scan_job_failed_dont_notify_if_disabled(selected_job_type):
    handler = MockNotificationHandler()
    notify_on_scan_job_failed = {}
    for job_type in ScannerJobType:
        notify_on_scan_job_failed[job_type] = job_type != selected_job_type
    config = NotificationConfig(notify_on_scan_job_failed=notify_on_scan_job_failed, notification_handlers=[handler])
    notifier = NotificationCreator(config)

    notifier.on_scan_job_failed("scanner_id", selected_job_type, "job_id", "some error reason")

    assert len(handler.events) == 0


@pytest.mark.parametrize(
    "on_create,finding",
    [
        (True, FINDING_WITH_RISK_NO_PATCH_YES),
        (True, FINDING_WITH_RISK_NO_PATCH_NO),
        (False, FINDING_WITH_RISK_NO_PATCH_YES),
        (False, FINDING_WITH_RISK_NO_PATCH_NO),
    ],
)
def test_on_finding_created_notify_if_risk_not_set_if_enabled(on_create, finding):
    handler = MockNotificationHandler()
    config = NotificationConfig(notify_on_finding_risk_assessment_needed=True, notification_handlers=[handler])
    notifier = NotificationCreator(config)

    if on_create:
        notifier.on_finding_created(finding)
    else:
        notifier.on_finding_refreshed(FINDING_WITH_RISK_YES_PATCH_NO, finding)

    assert len(handler.events) == 1
    event = handler.events[0]
    assert isinstance(event, FindingNotificationEvent)
    assert event.finding == finding
    assert event.finding_needs_risk_assessment


@pytest.mark.parametrize(
    "on_create,finding",
    [
        (True, FINDING_WITH_RISK_NO_PATCH_YES),
        (True, FINDING_WITH_RISK_NO_PATCH_NO),
        (False, FINDING_WITH_RISK_NO_PATCH_YES),
        (False, FINDING_WITH_RISK_NO_PATCH_NO),
    ],
)
def test_on_finding_created_or_updated_dont_notify_if_risk_not_set_if_disabled(on_create, finding):
    handler = MockNotificationHandler()
    config = NotificationConfig(notify_on_finding_risk_assessment_needed=False, notification_handlers=[handler])
    notifier = NotificationCreator(config)

    if on_create:
        notifier.on_finding_created(finding)
    else:
        notifier.on_finding_refreshed(FINDING_WITH_RISK_NO_PATCH_NO, finding)

    assert len(handler.events) == 0


@pytest.mark.parametrize(
    "on_create,finding",
    [
        (True, FINDING_WITH_RISK_YES_PATCH_YES),
        (True, FINDING_WITH_RISK_YES_PATCH_NO),
        (False, FINDING_WITH_RISK_YES_PATCH_YES),
        (False, FINDING_WITH_RISK_YES_PATCH_NO),
    ],
)
def test_on_finding_created_or_updated_dont_notify_if_risk_set_if_enabled(on_create, finding):
    handler = MockNotificationHandler()
    config = NotificationConfig(notify_on_finding_risk_assessment_needed=True, notification_handlers=[handler])
    notifier = NotificationCreator(config)

    if on_create:
        notifier.on_finding_created(finding)
    else:
        notifier.on_finding_refreshed(FINDING_WITH_RISK_NO_PATCH_NO, finding)

    assert len(handler.events) == 0


@pytest.mark.parametrize(
    "on_create,finding",
    [
        (True, FINDING_WITH_RISK_NO_PATCH_YES),
        (True, FINDING_WITH_RISK_YES_PATCH_YES),
        (False, FINDING_WITH_RISK_NO_PATCH_YES),
        (False, FINDING_WITH_RISK_YES_PATCH_YES),
    ],
)
def test_on_finding_created_or_updated_notify_if_patch_set_if_enabled(on_create, finding):
    handler = MockNotificationHandler()
    config = NotificationConfig(notify_on_finding_patch_version_available=True, notification_handlers=[handler])
    notifier = NotificationCreator(config)

    if on_create:
        notifier.on_finding_created(finding)
    else:
        notifier.on_finding_refreshed(FINDING_WITH_RISK_NO_PATCH_NO, finding)

    assert len(handler.events) == 1
    event = handler.events[0]
    assert isinstance(event, FindingNotificationEvent)
    assert event.finding == finding
    assert event.finding_has_patch_version


@pytest.mark.parametrize(
    "on_create,finding",
    [
        (True, FINDING_WITH_RISK_NO_PATCH_YES),
        (True, FINDING_WITH_RISK_YES_PATCH_YES),
        (False, FINDING_WITH_RISK_NO_PATCH_YES),
        (False, FINDING_WITH_RISK_YES_PATCH_YES),
    ],
)
def test_on_finding_created_or_updated_dont_notify_if_patch_set_if_disabled(on_create, finding):
    handler = MockNotificationHandler()
    config = NotificationConfig(notify_on_finding_patch_version_available=False, notification_handlers=[handler])
    notifier = NotificationCreator(config)

    if on_create:
        notifier.on_finding_created(finding)
    else:
        notifier.on_finding_refreshed(FINDING_WITH_RISK_NO_PATCH_NO, finding)

    assert len(handler.events) == 0


@pytest.mark.parametrize(
    "on_create,finding",
    [
        (True, FINDING_WITH_RISK_NO_PATCH_NO),
        (True, FINDING_WITH_RISK_YES_PATCH_NO),
        (False, FINDING_WITH_RISK_NO_PATCH_NO),
        (False, FINDING_WITH_RISK_YES_PATCH_NO),
    ],
)
def test_on_finding_created_or_updated_dont_notify_if_patch_not_set_if_enabled(on_create, finding):
    handler = MockNotificationHandler()
    config = NotificationConfig(notify_on_finding_patch_version_available=True, notification_handlers=[handler])
    notifier = NotificationCreator(config)

    if on_create:
        notifier.on_finding_created(finding)
    else:
        notifier.on_finding_refreshed(FINDING_WITH_RISK_NO_PATCH_NO, finding)

    assert len(handler.events) == 0


@pytest.mark.parametrize("finding", [FINDING_WITH_RISK_NO_PATCH_YES, FINDING_WITH_RISK_YES_PATCH_YES])
def test_on_finding_updated_dont_notify_if_patch_already_set_if_enabled(finding):
    handler = MockNotificationHandler()
    config = NotificationConfig(notify_on_finding_patch_version_available=True, notification_handlers=[handler])
    notifier = NotificationCreator(config)

    notifier.on_finding_refreshed(FINDING_WITH_RISK_NO_PATCH_YES, finding)

    assert len(handler.events) == 0


@pytest.mark.parametrize("on_create", [True, False])
def test_on_finding_created_or_updated_notify_if_risk_not_set_and_patch_set_if_enabled(on_create):
    finding = FINDING_WITH_RISK_NO_PATCH_YES
    handler = MockNotificationHandler()
    config = NotificationConfig(
        notify_on_finding_risk_assessment_needed=True, notify_on_finding_patch_version_available=True, notification_handlers=[handler]
    )
    notifier = NotificationCreator(config)

    if on_create:
        notifier.on_finding_created(finding)
    else:
        notifier.on_finding_refreshed(FINDING_WITH_RISK_YES_PATCH_NO, finding)

    assert len(handler.events) == 1
    event = handler.events[0]
    assert isinstance(event, FindingNotificationEvent)
    assert event.finding == finding
    assert event.finding_needs_risk_assessment
    assert event.finding_has_patch_version
    assert not event.finding_was_resolved


def test_on_finding_deleted():
    handler = MockNotificationHandler()
    notifier = NotificationCreator(NotificationConfig(notify_on_finding_deleted=True, notification_handlers=[handler]))

    notifier.on_finding_deleted(FINDING_WITH_RISK_NO_PATCH_YES)

    assert len(handler.events) == 1
    event = handler.events[0]
    assert isinstance(event, FindingNotificationEvent)
    assert event.finding == FINDING_WITH_RISK_NO_PATCH_YES
    assert not event.finding_needs_risk_assessment
    assert not event.finding_has_patch_version
    assert event.finding_was_resolved

def test_on_finding_deleted_dont_notify_if_disabled():
    handler = MockNotificationHandler()
    notifier = NotificationCreator(NotificationConfig(notify_on_finding_deleted=False, notification_handlers=[handler]))

    notifier.on_finding_deleted(FINDING_WITH_RISK_NO_PATCH_YES)

    assert len(handler.events) == 0

def test_send_notification_to_app_owners():
    handler = MockNotificationHandler()
    notifier = NotificationCreator(NotificationConfig(notification_handlers=[handler]))

    notifier.send_notification_to_app_owners("some message")

    assert len(handler.events) == 1
    event = handler.events[0]
    assert isinstance(event, AppOwnerNotificationEvent)
    assert event.message == "some message"

class MockNotificationHandler(NotificationHandler):

    def __init__(self):
        self.events = []

    def can_handle(self, event: NotificationEvent) -> bool:
        return True

    def handle(self, event: NotificationEvent):
        self.events.append(event)
