from copy import deepcopy
from unittest.mock import Mock

from integration.gitlab.gitlab_pipeline_config import GitlabPipeline
from integration.gitlab.gitlab_trivy_finding_notification_handler import GitlabTrivyFindingNotificationHandler
from model.dependency import Dependency
from model.finding import Finding
from model.security_risk import SecurityRisk
from model.user import User
from model.vulnerability import Vulnerability
from notification.notification_event import FindingNotificationEvent
from scanner.manager.bazel_trivy_dependency_manager import TRIVY_SCANNER_ID

FINDING_OS_PACKAGE = Finding(
    repository="repo",
    scanner=TRIVY_SCANNER_ID,
    vulnerable_dependency=Dependency("dep_id", "dep_name", "dep_ver", {"vuln_id": ["dep_ver2"]}),
    vulnerabilities=[Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
    first_level_dependencies=[],
    projects=["OSP: /some/project"],
    risk_assessor=[User("user_id1", "user_name1", "user1@mail.com"), User("user_id2", "user_name2", "user2@mail.com")],
    risk=SecurityRisk.INFORMATIONAL,
    more_info="https://dfinity.atlassian.net/browse/SCAVM-5",
)

FINDING_BINARY = Finding(
    repository="repo",
    scanner=TRIVY_SCANNER_ID,
    vulnerable_dependency=Dependency("dep_id", "dep_name", "dep_ver", {"vuln_id": ["dep_ver2"]}),
    vulnerabilities=[Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
    first_level_dependencies=[],
    projects=["BIN: /some/project"],
    risk_assessor=[User("user_id1", "user_name1", "user1@mail.com"), User("user_id2", "user_name2", "user2@mail.com")],
    risk=SecurityRisk.INFORMATIONAL,
    more_info="https://dfinity.atlassian.net/browse/SCAVM-5",
)

def test_can_handle_trivy_osp_finding_with_patch_available():
    event = FindingNotificationEvent(finding=FINDING_OS_PACKAGE, finding_needs_risk_assessment=False, finding_has_patch_version=True, finding_was_resolved=False)
    handler = GitlabTrivyFindingNotificationHandler(gitlab_api=Mock())

    assert handler.can_handle(event)

def test_can_not_handle_trivy_osp_finding_without_patch():
    event = FindingNotificationEvent(finding=FINDING_OS_PACKAGE, finding_needs_risk_assessment=False, finding_has_patch_version=False, finding_was_resolved=False)
    handler = GitlabTrivyFindingNotificationHandler(gitlab_api=Mock())

    assert not handler.can_handle(event)

def test_can_not_handle_trivy_bin_finding_with_patch_available():
    event = FindingNotificationEvent(finding=FINDING_BINARY, finding_needs_risk_assessment=False, finding_has_patch_version=True, finding_was_resolved=False)
    handler = GitlabTrivyFindingNotificationHandler(gitlab_api=Mock())

    assert not handler.can_handle(event)

def test_can_not_handle_finding_from_different_scanner():
    finding = deepcopy(FINDING_OS_PACKAGE)
    finding.scanner = "OTHER_SCANNER"
    event = FindingNotificationEvent(finding=finding, finding_needs_risk_assessment=False,
                                     finding_has_patch_version=True, finding_was_resolved=False)
    handler = GitlabTrivyFindingNotificationHandler(gitlab_api=Mock())

    assert not handler.can_handle(event)

def test_call_gitlab_api_during_handle():
    api = Mock()
    event = FindingNotificationEvent(finding=FINDING_OS_PACKAGE, finding_needs_risk_assessment=False,
                                     finding_has_patch_version=True, finding_was_resolved=False)
    handler = GitlabTrivyFindingNotificationHandler(gitlab_api=api)

    assert handler.can_handle(event)

    handler.handle(event)

    api.run_pipeline.assert_called_once_with(GitlabPipeline.IC_BUILD_PUSH_BASE_CONTAINER_IMAGES)

def test_call_gitlab_api_only_once():
    api = Mock()
    api.run_pipeline.return_value = True
    event = FindingNotificationEvent(finding=FINDING_OS_PACKAGE, finding_needs_risk_assessment=False,
                                     finding_has_patch_version=True, finding_was_resolved=False)
    handler = GitlabTrivyFindingNotificationHandler(gitlab_api=api)

    assert handler.can_handle(event)

    handler.handle(event)
    handler.handle(event)

    api.run_pipeline.assert_called_once_with(GitlabPipeline.IC_BUILD_PUSH_BASE_CONTAINER_IMAGES)
