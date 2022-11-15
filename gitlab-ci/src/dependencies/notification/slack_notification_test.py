from copy import deepcopy
from typing import Dict
from typing import List
from typing import Optional

import pytest
from model.dependency import Dependency
from model.finding import Finding
from model.security_risk import SecurityRisk
from model.user import User
from model.vulnerability import Vulnerability
from notification.notification_config import NotificationConfig
from notification.slack_api import SlackApi
from notification.slack_notification import SlackNotifier
from scanner.scanner_job_type import ScannerJobType


FINDING_WITH_RISK_YES_PATCH_YES = Finding(
    "repo",
    "scanner",
    Dependency("dep_id", "dep_name", "dep_ver", {"vuln_id": ["dep_ver2"]}),
    [Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
    [],
    [],
    [User("user_id1", "user_name1", "user1@mail.com"), User("user_id2", "user_name2", "user2@mail.com")],
    SecurityRisk.INFORMATIONAL,
    [],
    None,
    -1,
    "https://dfinity.atlassian.net/browse/SCAVM-5",
)

FINDING_WITH_RISK_YES_PATCH_NO = Finding(
    "repo",
    "scanner",
    Dependency("dep_id", "dep_name", "dep_ver", {}),
    [Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
    [],
    [],
    [User("user_id1", "user_name1", "user1@mail.com"), User("user_id2", "user_name2", "user2@mail.com")],
    SecurityRisk.INFORMATIONAL,
    [],
    None,
    -1,
    "https://dfinity.atlassian.net/browse/SCAVM-5",
)

FINDING_WITH_RISK_NO_PATCH_YES = Finding(
    "repo",
    "scanner",
    Dependency("dep_id", "dep_name", "dep_ver", {"vuln_id": ["dep_ver2"]}),
    [Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
    [],
    [],
    [User("user_id1", "user_name1", "user1@mail.com"), User("user_id2", "user_name2", "user2@mail.com")],
    None,
    [],
    None,
    -1,
    "https://dfinity.atlassian.net/browse/SCAVM-5",
)

FINDING_WITH_RISK_NO_PATCH_NO = Finding(
    "repo",
    "scanner",
    Dependency("dep_id", "dep_name", "dep_ver", {}),
    [Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
    [],
    [],
    [User("user_id1", "user_name1", "user1@mail.com"), User("user_id2", "user_name2", "user2@mail.com")],
    None,
    [],
    None,
    -1,
    "https://dfinity.atlassian.net/browse/SCAVM-5",
)


def test_on_merge_request_blocked_notify_if_enabled():
    api = MockSlackApi()
    config = NotificationConfig(notify_on_merge_request_blocked=True)
    notifier = SlackNotifier(config, api)

    notifier.on_merge_request_blocked("job_id", "merge_request_id")

    assert len(api.messages) == 1
    assert f"{config.ci_pipeline_base_url}job_id" in api.messages[0]
    assert f"{config.merge_request_base_url}merge_request_id" in api.messages[0]


def test_on_merge_request_blocked_dont_notify_if_disabled():
    api = MockSlackApi()
    config = NotificationConfig(notify_on_merge_request_blocked=False)
    notifier = SlackNotifier(config, api)

    notifier.on_merge_request_blocked("job_id", "merge_request_id")

    assert len(api.messages) == 0


def test_on_release_build_blocked_notify_if_enabled():
    api = MockSlackApi()
    config = NotificationConfig(notify_on_release_build_blocked=True)
    notifier = SlackNotifier(config, api)

    notifier.on_release_build_blocked("job_id")

    assert len(api.messages) == 1
    assert f"{config.ci_pipeline_base_url}job_id" in api.messages[0]
    assert "<!channel>" in api.messages[0]


def test_on_release_build_blocked_dont_notify_if_disabled():
    api = MockSlackApi()
    config = NotificationConfig(notify_on_release_build_blocked=False)
    notifier = SlackNotifier(config, api)

    notifier.on_release_build_blocked("job_id")

    assert len(api.messages) == 0


@pytest.mark.parametrize(
    "selected_job_type", [ScannerJobType.PERIODIC_SCAN, ScannerJobType.MERGE_SCAN, ScannerJobType.RELEASE_SCAN]
)
def test_on_scan_job_succeeded_notify_if_enabled(selected_job_type):
    api = MockSlackApi()
    notify_on_scan_job_succeeded = {}
    for job_type in ScannerJobType:
        notify_on_scan_job_succeeded[job_type] = job_type == selected_job_type
    config = NotificationConfig(notify_on_scan_job_succeeded=notify_on_scan_job_succeeded)
    notifier = SlackNotifier(config, api)

    notifier.on_scan_job_succeeded(selected_job_type, "job_id")

    assert len(api.messages) == 1
    assert "succeeded" in api.messages[0]
    assert selected_job_type.name in api.messages[0]
    assert f"{config.ci_pipeline_base_url}job_id" in api.messages[0]


@pytest.mark.parametrize(
    "selected_job_type", [ScannerJobType.PERIODIC_SCAN, ScannerJobType.MERGE_SCAN, ScannerJobType.RELEASE_SCAN]
)
def test_on_scan_job_succeeded_dont_notify_if_disabled(selected_job_type):
    api = MockSlackApi()
    notify_on_scan_job_succeeded = {}
    for job_type in ScannerJobType:
        notify_on_scan_job_succeeded[job_type] = job_type != selected_job_type
    config = NotificationConfig(notify_on_scan_job_succeeded=notify_on_scan_job_succeeded)
    notifier = SlackNotifier(config, api)

    notifier.on_scan_job_succeeded(selected_job_type, "job_id")

    assert len(api.messages) == 0


@pytest.mark.parametrize(
    "selected_job_type", [ScannerJobType.PERIODIC_SCAN, ScannerJobType.MERGE_SCAN, ScannerJobType.RELEASE_SCAN]
)
def test_on_scan_job_failed_notify_if_enabled(selected_job_type):
    api = MockSlackApi()
    notify_on_scan_job_failed = {}
    for job_type in ScannerJobType:
        notify_on_scan_job_failed[job_type] = job_type == selected_job_type
    config = NotificationConfig(notify_on_scan_job_failed=notify_on_scan_job_failed)
    notifier = SlackNotifier(config, api)

    notifier.on_scan_job_failed(selected_job_type, "job_id", "some error reason")

    assert len(api.messages) == 1
    assert "failed" in api.messages[0]
    assert "some error reason" in api.messages[0]
    assert selected_job_type.name in api.messages[0]
    assert f"{config.ci_pipeline_base_url}job_id" in api.messages[0]


@pytest.mark.parametrize(
    "selected_job_type", [ScannerJobType.PERIODIC_SCAN, ScannerJobType.MERGE_SCAN, ScannerJobType.RELEASE_SCAN]
)
def test_on_scan_job_failed_dont_notify_if_disabled(selected_job_type):
    api = MockSlackApi()
    notify_on_scan_job_failed = {}
    for job_type in ScannerJobType:
        notify_on_scan_job_failed[job_type] = job_type != selected_job_type
    config = NotificationConfig(notify_on_scan_job_failed=notify_on_scan_job_failed)
    notifier = SlackNotifier(config, api)

    notifier.on_scan_job_failed(selected_job_type, "job_id", "some error reason")

    assert len(api.messages) == 0


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
    api = MockSlackApi(finding.risk_assessor)
    config = NotificationConfig(notify_on_finding_risk_assessment_needed=True)
    notifier = SlackNotifier(config, api)

    if on_create:
        notifier.on_finding_created(finding)
    else:
        notifier.on_finding_updated(FINDING_WITH_RISK_YES_PATCH_NO, finding)

    assert len(api.messages) == 1
    assert "risk assessment" in api.messages[0]
    assert finding.more_info in api.messages[0]
    for user in finding.risk_assessor:
        assert f"<@{api.user_to_slack_id[user.id]}>" in api.messages[0]


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
    api = MockSlackApi(finding.risk_assessor)
    config = NotificationConfig(notify_on_finding_risk_assessment_needed=False)
    notifier = SlackNotifier(config, api)

    if on_create:
        notifier.on_finding_created(finding)
    else:
        notifier.on_finding_updated(FINDING_WITH_RISK_NO_PATCH_NO, finding)

    assert len(api.messages) == 0


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
    api = MockSlackApi(finding.risk_assessor)
    config = NotificationConfig(notify_on_finding_risk_assessment_needed=True)
    notifier = SlackNotifier(config, api)

    if on_create:
        notifier.on_finding_created(finding)
    else:
        notifier.on_finding_updated(FINDING_WITH_RISK_NO_PATCH_NO, finding)

    assert len(api.messages) == 0


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
    api = MockSlackApi(finding.risk_assessor)
    config = NotificationConfig(notify_on_finding_patch_version_available=True)
    notifier = SlackNotifier(config, api)

    if on_create:
        notifier.on_finding_created(finding)
    else:
        notifier.on_finding_updated(FINDING_WITH_RISK_NO_PATCH_NO, finding)

    assert len(api.messages) == 1
    assert "patch version" in api.messages[0]
    assert finding.more_info in api.messages[0]
    for user in finding.risk_assessor:
        assert f"<@{api.user_to_slack_id[user.id]}>" in api.messages[0]


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
    api = MockSlackApi(finding.risk_assessor)
    config = NotificationConfig(notify_on_finding_patch_version_available=False)
    notifier = SlackNotifier(config, api)

    if on_create:
        notifier.on_finding_created(finding)
    else:
        notifier.on_finding_updated(FINDING_WITH_RISK_NO_PATCH_NO, finding)

    assert len(api.messages) == 0


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
    api = MockSlackApi(finding.risk_assessor)
    config = NotificationConfig(notify_on_finding_patch_version_available=True)
    notifier = SlackNotifier(config, api)

    if on_create:
        notifier.on_finding_created(finding)
    else:
        notifier.on_finding_updated(FINDING_WITH_RISK_NO_PATCH_NO, finding)

    assert len(api.messages) == 0


@pytest.mark.parametrize("finding", [FINDING_WITH_RISK_NO_PATCH_YES, FINDING_WITH_RISK_YES_PATCH_YES])
def test_on_finding_updated_dont_notify_if_patch_already_set_if_enabled(finding):
    api = MockSlackApi(finding.risk_assessor)
    config = NotificationConfig(notify_on_finding_patch_version_available=True)
    notifier = SlackNotifier(config, api)

    notifier.on_finding_updated(FINDING_WITH_RISK_NO_PATCH_YES, finding)

    assert len(api.messages) == 0


@pytest.mark.parametrize("on_create", [True, False])
def test_on_finding_created_or_updated_notify_if_risk_not_set_and_patch_set_if_enabled(on_create):
    finding = FINDING_WITH_RISK_NO_PATCH_YES
    api = MockSlackApi(finding.risk_assessor)
    config = NotificationConfig(
        notify_on_finding_risk_assessment_needed=True, notify_on_finding_patch_version_available=True
    )
    notifier = SlackNotifier(config, api)

    if on_create:
        notifier.on_finding_created(finding)
    else:
        notifier.on_finding_updated(FINDING_WITH_RISK_YES_PATCH_NO, finding)

    assert len(api.messages) == 1
    assert "risk assessment" in api.messages[0]
    assert "patch version" in api.messages[0]
    assert finding.more_info in api.messages[0]
    for user in finding.risk_assessor:
        assert f"<@{api.user_to_slack_id[user.id]}>" in api.messages[0]


@pytest.mark.parametrize("on_create", [True, False])
def test_on_finding_created_or_updated_notify_with_finding_primary_key_if_more_info_is_missing(on_create):
    finding = deepcopy(FINDING_WITH_RISK_NO_PATCH_NO)
    finding.more_info = None
    api = MockSlackApi(finding.risk_assessor)
    config = NotificationConfig(notify_on_finding_risk_assessment_needed=True)
    notifier = SlackNotifier(config, api)

    if on_create:
        notifier.on_finding_created(finding)
    else:
        notifier.on_finding_updated(FINDING_WITH_RISK_YES_PATCH_NO, finding)

    assert len(api.messages) == 1
    assert (
        f"({finding.repository}, {finding.scanner}, {finding.vulnerable_dependency.id}, {finding.vulnerable_dependency.version})"
        in api.messages[0]
    )


@pytest.mark.parametrize("on_create", [True, False])
def test_on_finding_created_or_updated_notify_channel_if_risk_assessor_is_missing(on_create):
    finding = deepcopy(FINDING_WITH_RISK_NO_PATCH_NO)
    finding.risk_assessor = None
    api = MockSlackApi()
    config = NotificationConfig(notify_on_finding_risk_assessment_needed=True)
    notifier = SlackNotifier(config, api)

    if on_create:
        notifier.on_finding_created(finding)
    else:
        notifier.on_finding_updated(FINDING_WITH_RISK_YES_PATCH_NO, finding)

    assert len(api.messages) == 1
    assert "no risk assessors" in api.messages[0]
    assert "<!channel>" in api.messages[0]


@pytest.mark.parametrize("on_create", [True, False])
def test_on_finding_created_or_updated_notify_channel_if_risk_assessor_ids_are_unknown(on_create):
    finding = FINDING_WITH_RISK_NO_PATCH_NO
    api = MockSlackApi()
    config = NotificationConfig(notify_on_finding_risk_assessment_needed=True)
    notifier = SlackNotifier(config, api)

    if on_create:
        notifier.on_finding_created(finding)
    else:
        notifier.on_finding_updated(FINDING_WITH_RISK_YES_PATCH_NO, finding)

    assert len(api.messages) == 1
    for user in finding.risk_assessor:
        assert user.name in api.messages[0]
    assert "<!channel>" in api.messages[0]


class MockSlackApi(SlackApi):
    messages: List[str]
    user_to_slack_id: Dict[str, str]

    def __init__(self, known_users: List[User] = None):
        super().__init__("", True, "", "")
        self.messages = []
        self.user_to_slack_id = {}
        if known_users is not None:
            for user in known_users:
                self.user_to_slack_id[user.id] = "slack_" + user.id

    def send_message(self, message: str):
        self.messages.append(message)

    def try_get_slack_id(self, user: User) -> Optional[str]:
        return self.user_to_slack_id[user.id] if user.id in self.user_to_slack_id else None
