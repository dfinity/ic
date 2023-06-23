from copy import deepcopy
from typing import Dict, List, Optional

import pytest
from integration.slack.slack_api import SlackApi
from integration.slack.slack_channel_config import SlackChannelConfig
from integration.slack.slack_default_notification_handler import APP_OWNERS, SlackDefaultNotificationHandler
from model.dependency import Dependency
from model.finding import Finding
from model.security_risk import SecurityRisk
from model.user import User
from model.vulnerability import Vulnerability
from notification.notification_event import (
    AppOwnerNotificationEvent,
    FindingNotificationEvent,
    MRBlockedNotificationEvent,
    ReleaseBlockedNotificationEvent,
    ScanJobFailedNotificationEvent,
    ScanJobSucceededNotificationEvent,
)
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


def test_mr_blocked_event():
    api = MockSlackApi()
    handler = SlackDefaultNotificationHandler(slack_api=api)
    event = MRBlockedNotificationEvent(scanner_id="scanner_id", ci_job_url="http://ci.job/123", merge_request_url="http://mr.url/321")

    assert handler.can_handle(event)

    handler.handle(event)

    assert len(api.messages) == 1
    assert "http://ci.job/123" in api.messages[0]
    assert "http://mr.url/321" in api.messages[0]


def test_release_build_blocked_event():
    api = MockSlackApi()
    handler = SlackDefaultNotificationHandler(slack_api=api)
    event = ReleaseBlockedNotificationEvent(scanner_id="scanner_id", ci_job_url="http://ci.job/123")

    assert handler.can_handle(event)

    handler.handle(event)

    assert len(api.messages) == 1
    assert "http://ci.job/123" in api.messages[0]
    assert "<!channel>" in api.messages[0]


@pytest.mark.parametrize(
    "selected_job_type", [ScannerJobType.PERIODIC_SCAN, ScannerJobType.MERGE_SCAN, ScannerJobType.RELEASE_SCAN]
)
def test_scan_job_succeeded_event(selected_job_type):
    api = MockSlackApi()
    handler = SlackDefaultNotificationHandler(slack_api=api)
    event = ScanJobSucceededNotificationEvent(scanner_id="scanner_id", job_type=selected_job_type, ci_job_url="http://ci.job/123")

    assert handler.can_handle(event)

    handler.handle(event)

    assert len(api.messages) == 1
    assert "succeeded" in api.messages[0]
    assert "scanner_id" in api.messages[0]
    assert selected_job_type.name in api.messages[0]
    assert "http://ci.job/123" in api.messages[0]

@pytest.mark.parametrize(
    "selected_job_type", [ScannerJobType.PERIODIC_SCAN, ScannerJobType.MERGE_SCAN, ScannerJobType.RELEASE_SCAN]
)
def test_scan_job_failed_event(selected_job_type):
    api = MockSlackApi()
    handler = SlackDefaultNotificationHandler(slack_api=api)
    event = ScanJobFailedNotificationEvent(scanner_id="scanner_id", job_type=selected_job_type, ci_job_url="http://ci.job/123", reason="some error reason")

    assert handler.can_handle(event)

    handler.handle(event)

    assert len(api.messages) == 1
    assert "failed" in api.messages[0]
    assert "scanner_id" in api.messages[0]
    assert "some error reason" in api.messages[0]
    assert selected_job_type.name in api.messages[0]
    assert "http://ci.job/123" in api.messages[0]
    assert APP_OWNERS in api.messages[0]


def test_finding_needs_risk_assessment_event():
    finding = FINDING_WITH_RISK_NO_PATCH_NO
    api = MockSlackApi(finding.risk_assessor)
    handler = SlackDefaultNotificationHandler(slack_api=api)
    event = FindingNotificationEvent(finding=finding, finding_needs_risk_assessment=True, finding_has_patch_version=False, finding_was_resolved=False)

    assert handler.can_handle(event)

    handler.handle(event)

    assert len(api.messages) == 1
    assert "risk assessment" in api.messages[0]
    assert finding.more_info in api.messages[0]
    for user in finding.risk_assessor:
        assert f"<@{api.user_to_slack_id[user.id]}>" in api.messages[0]

def test_finding_has_patch_version_event():
    finding = FINDING_WITH_RISK_YES_PATCH_YES
    api = MockSlackApi(finding.risk_assessor)
    handler = SlackDefaultNotificationHandler(slack_api=api)
    event = FindingNotificationEvent(finding=finding, finding_needs_risk_assessment=False,
                                     finding_has_patch_version=True, finding_was_resolved=False)

    assert handler.can_handle(event)

    handler.handle(event)

    assert len(api.messages) == 1
    assert "patch version" in api.messages[0]
    assert finding.more_info in api.messages[0]
    for user in finding.risk_assessor:
        assert f"<@{api.user_to_slack_id[user.id]}>" in api.messages[0]

def test_finding_needs_risk_assessment_and_has_patch_version_event():
    finding = FINDING_WITH_RISK_NO_PATCH_YES
    api = MockSlackApi(finding.risk_assessor)
    handler = SlackDefaultNotificationHandler(slack_api=api)
    event = FindingNotificationEvent(finding=finding, finding_needs_risk_assessment=True,
                                     finding_has_patch_version=True, finding_was_resolved=False)

    assert handler.can_handle(event)

    handler.handle(event)

    assert len(api.messages) == 1
    assert "risk assessment" in api.messages[0]
    assert "patch version" in api.messages[0]
    assert finding.more_info in api.messages[0]
    for user in finding.risk_assessor:
        assert f"<@{api.user_to_slack_id[user.id]}>" in api.messages[0]

def test_notify_channel_if_risk_assessor_is_missing():
    finding = deepcopy(FINDING_WITH_RISK_NO_PATCH_NO)
    finding.risk_assessor = None
    api = MockSlackApi()
    handler = SlackDefaultNotificationHandler(slack_api=api)
    event = FindingNotificationEvent(finding=finding, finding_needs_risk_assessment=True, finding_has_patch_version=False, finding_was_resolved=False)

    assert handler.can_handle(event)

    handler.handle(event)

    assert len(api.messages) == 1
    assert "no risk assessors" in api.messages[0]
    assert "<!channel>" in api.messages[0]

def test_notify_channel_if_risk_assessor_ids_are_unknown():
    finding = FINDING_WITH_RISK_NO_PATCH_NO
    api = MockSlackApi()
    handler = SlackDefaultNotificationHandler(slack_api=api)
    event = FindingNotificationEvent(finding=finding, finding_needs_risk_assessment=True, finding_has_patch_version=False, finding_was_resolved=False)

    assert handler.can_handle(event)

    handler.handle(event)

    assert len(api.messages) == 1
    for user in finding.risk_assessor:
        assert user.name in api.messages[0]
    assert "<!channel>" in api.messages[0]


def test_finding_was_resolved_event():
    finding = FINDING_WITH_RISK_NO_PATCH_YES
    api = MockSlackApi()
    handler = SlackDefaultNotificationHandler(slack_api=api)
    event = FindingNotificationEvent(finding=finding, finding_needs_risk_assessment=False, finding_has_patch_version=False, finding_was_resolved=True)

    assert handler.can_handle(event)

    handler.handle(event)

    assert len(api.messages) == 1
    assert FINDING_WITH_RISK_NO_PATCH_YES.more_info in api.messages[0]
    assert "resolved" in api.messages[0]


def test_app_owner_notification_event():
    api = MockSlackApi()
    handler = SlackDefaultNotificationHandler(slack_api=api)
    event = AppOwnerNotificationEvent("some message")

    assert handler.can_handle(event)

    handler.handle(event)

    assert len(api.messages) == 1
    assert APP_OWNERS in api.messages[0]
    assert "some message" in api.messages[0]

class MockSlackApi(SlackApi):
    messages: List[str]
    user_to_slack_id: Dict[str, str]

    def __init__(self, known_users: List[User] = None):
        super().__init__(SlackChannelConfig(channel_id=None, channel="#dont-care"), True, "")
        self.messages = []
        self.user_to_slack_id = {}
        if known_users is not None:
            for user in known_users:
                self.user_to_slack_id[user.id] = "slack_" + user.id

    def send_message(self, message: str):
        self.messages.append(message)

    def try_get_slack_id(self, user: User) -> Optional[str]:
        return self.user_to_slack_id[user.id] if user.id in self.user_to_slack_id else None
