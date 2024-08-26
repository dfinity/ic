from copy import deepcopy

from model.dependency import Dependency
from model.finding import Finding
from model.user import User
from model.vulnerability import Vulnerability
from notification.notification_handler import NotificationHandler

FINDING_WITH_MORE_INFO = Finding(
    repository="repo",
    scanner="scanner",
    vulnerable_dependency=Dependency("dep_id", "dep_name", "dep_ver", {"vuln_id": ["dep_ver2"]}),
    vulnerabilities=[Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
    first_level_dependencies=[],
    projects=[],
    risk_assessor=[User("user_id1", "user_name1", "user1@mail.com"), User("user_id2", "user_name2", "user2@mail.com")],
    more_info="https://dfinity.atlassian.net/browse/SCAVM-5",
)
def test_get_finding_info_from_more_info():
    assert NotificationHandler.get_finding_info(FINDING_WITH_MORE_INFO) == FINDING_WITH_MORE_INFO.more_info

def test_get_finding_info_from_primary_key():
    finding = deepcopy(FINDING_WITH_MORE_INFO)
    finding.more_info = None

    assert NotificationHandler.get_finding_info(finding) == f"({finding.repository}, {finding.scanner}, {finding.vulnerable_dependency.id}, {finding.vulnerable_dependency.version})"
