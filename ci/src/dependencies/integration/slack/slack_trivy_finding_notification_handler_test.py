from copy import deepcopy
from typing import Dict, List, Optional
from unittest.mock import Mock

import pytest
from integration.slack.slack_api import SlackApi
from integration.slack.slack_channel_config import SlackChannelConfig
from integration.slack.slack_trivy_finding_notification_handler import (
    SLACK_CHANNEL_CONFIG_BY_TEAM,
    SLACK_TEAM_GROUP_ID,
    SUPPORTED_TEAMS,
    SlackTrivyFindingNotificationHandler,
)
from model.dependency import Dependency
from model.finding import Finding
from model.security_risk import SecurityRisk
from model.user import User
from model.vulnerability import Vulnerability
from notification.notification_event import FindingNotificationEvent
from scanner.manager.bazel_trivy_dependency_manager import TRIVY_SCANNER_ID

FINDING_WITH_RISK_YES_PATCH_YES = Finding(
    repository="repo",
    scanner=TRIVY_SCANNER_ID,
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
    scanner=TRIVY_SCANNER_ID,
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
    scanner=TRIVY_SCANNER_ID,
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
    scanner=TRIVY_SCANNER_ID,
    vulnerable_dependency=Dependency("dep_id", "dep_name", "dep_ver", {}),
    vulnerabilities=[Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
    first_level_dependencies=[],
    projects=[],
    risk_assessor=[User("user_id1", "user_name1", "user1@mail.com"), User("user_id2", "user_name2", "user2@mail.com")],
    risk=None,
    more_info="https://dfinity.atlassian.net/browse/SCAVM-5",
)


def supported_teams_powerset():
    def powerset(seq):
        if len(seq) <= 1:
            yield seq
            yield []
        else:
            for item in powerset(seq[1:]):
                yield [seq[0]] + item
                yield item
    return powerset(list(SUPPORTED_TEAMS))
    #return [[Team.NODE_TEAM], [Team.BOUNDARY_NODE_TEAM], [Team.NODE_TEAM, Team.BOUNDARY_NODE_TEAM]]

@pytest.mark.parametrize(
    "owning_teams", supported_teams_powerset()
)
def test_finding_needs_risk_assessment_event(owning_teams):
    finding = deepcopy(FINDING_WITH_RISK_NO_PATCH_NO)
    finding.owning_teams = owning_teams
    slack_api = MockSlackApi()
    github_handler = Mock()
    github_handler.can_handle.return_value = True
    handler = SlackTrivyFindingNotificationHandler(slack_api=slack_api,github_handler=github_handler)
    event = FindingNotificationEvent(finding=finding, finding_needs_risk_assessment=True, finding_has_patch_version=False, finding_was_resolved=False)

    assert handler.can_handle(event)

    handler.handle(event)

    assert len(slack_api.messages) == len(owning_teams)
    for i in range(len(owning_teams)):
        msg = slack_api.messages[i]
        team = owning_teams[i]
        assert "risk assessment" in msg
        assert finding.more_info in msg
        assert SLACK_TEAM_GROUP_ID[team] in msg
    github_handler.can_handle.assert_not_called()
    github_handler.handle.assert_not_called()


@pytest.mark.parametrize(
    "owning_teams", supported_teams_powerset()
)
def test_finding_has_patch_version_event(owning_teams):
    finding = deepcopy(FINDING_WITH_RISK_YES_PATCH_YES)
    finding.owning_teams = owning_teams
    slack_api = MockSlackApi()
    github_handler = Mock()
    github_handler.can_handle.return_value = True
    handler = SlackTrivyFindingNotificationHandler(slack_api=slack_api,github_handler=github_handler)
    event = FindingNotificationEvent(finding=finding, finding_needs_risk_assessment=False,
                                     finding_has_patch_version=True, finding_was_resolved=False)

    assert handler.can_handle(event)

    handler.handle(event)

    assert len(slack_api.messages) == len(owning_teams)
    for i in range(len(owning_teams)):
        msg = slack_api.messages[i]
        team = owning_teams[i]
        assert "patch version" in msg
        assert finding.more_info in msg
        assert SLACK_TEAM_GROUP_ID[team] in msg
    assert github_handler.can_handle.call_count == len(owning_teams)
    assert github_handler.handle.call_count == len(owning_teams)


@pytest.mark.parametrize(
    "owning_teams", supported_teams_powerset()
)
def test_finding_needs_risk_assessment_and_has_patch_version_event(owning_teams):
    finding = deepcopy(FINDING_WITH_RISK_NO_PATCH_YES)
    finding.owning_teams = owning_teams
    slack_api = MockSlackApi()
    github_handler = Mock()
    github_handler.can_handle.return_value = False
    handler = SlackTrivyFindingNotificationHandler(slack_api=slack_api,github_handler=github_handler)
    event = FindingNotificationEvent(finding=finding, finding_needs_risk_assessment=True,
                                     finding_has_patch_version=True, finding_was_resolved=False)

    assert handler.can_handle(event)

    handler.handle(event)

    assert len(slack_api.messages) == len(owning_teams)
    for i in range(len(owning_teams)):
        msg = slack_api.messages[i]
        team = owning_teams[i]
        assert "risk assessment" in msg
        assert "patch version" in msg
        assert finding.more_info in msg
        assert SLACK_TEAM_GROUP_ID[team] in msg
    assert github_handler.can_handle.call_count == len(owning_teams)
    github_handler.handle.assert_not_called()

@pytest.mark.parametrize(
    "owning_teams", supported_teams_powerset()
)
def test_finding_was_resolved_event(owning_teams):
    finding = deepcopy(FINDING_WITH_RISK_NO_PATCH_YES)
    finding.owning_teams = owning_teams
    slack_api = MockSlackApi()
    github_handler = Mock()
    github_handler.can_handle.return_value = True
    handler = SlackTrivyFindingNotificationHandler(slack_api=slack_api, github_handler=github_handler)
    event = FindingNotificationEvent(finding=finding, finding_needs_risk_assessment=False, finding_has_patch_version=False, finding_was_resolved=True)

    assert handler.can_handle(event)

    handler.handle(event)
    for i in range(len(owning_teams)):
        msg = slack_api.messages[i]
        assert "resolved" in msg
        assert finding.more_info in msg
    github_handler.can_handle.assert_not_called()
    github_handler.handle.assert_not_called()

def test_supported_teams_slack_config_is_complete():
    for team in SUPPORTED_TEAMS:
        assert team in SLACK_CHANNEL_CONFIG_BY_TEAM
        assert team in SLACK_TEAM_GROUP_ID

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
