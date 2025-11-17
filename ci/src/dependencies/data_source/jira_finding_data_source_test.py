import random
import re
import string
from unittest.mock import Mock

import pytest
from data_source.commit_type import CommitType
from data_source.jira_finding_data_source import (
    JIRA_BOARD_KEY,
    JIRA_DEFAULT_RISK_ASSESSORS,
    JIRA_FINDING_ISSUE_TYPE,
    JIRA_FINDING_TO_CUSTOM_FIELD,
    JIRA_INCIDENT_RESPONDER_EPIC,
    JIRA_LABEL_PATCH_ALLDEP_PUBLISHED,
    JIRA_LABEL_PATCH_VULNDEP_PUBLISHED,
    JIRA_MERGE_REQUEST_EXCEPTION_TICKET,
    JIRA_OWNER_GROUP_BY_TEAM,
    JIRA_RELEASE_CANDIDATE_EXCEPTION_TICKET,
    JIRA_SECURITY_RISK_TO_ID,
    JiraFindingDataSource,
)
from model.dependency import Dependency
from model.finding import Finding
from model.security_risk import SecurityRisk
from model.team import Team
from model.user import User
from model.vulnerability import Vulnerability


@pytest.fixture
def jira_lib_mock():
    return Mock()


@pytest.fixture
def jira_ds(jira_lib_mock):
    return JiraFindingDataSource([], custom_jira=jira_lib_mock)


def random_string(n):
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))


def test_get_risk_assessor_return_single_user(jira_ds, jira_lib_mock):
    user = Mock()
    user.accountId = "foo"
    user.displayName = "John Doe"
    user.emailAddress = "jd@example.com"
    issue = Mock()
    issue.get_field.return_value = user
    jira_lib_mock.search_issues.return_value = [issue]

    res = jira_ds.get_risk_assessor()

    assert res == [User("foo", "John Doe", "jd@example.com")]
    assert_get_risk_assessor_issue_and_field_called(jira_lib_mock, [issue])


def test_get_risk_assessor_return_two_users(jira_ds, jira_lib_mock):
    user1 = Mock(["accountId" "displayName"])
    user1.accountId = "mickey"
    user1.displayName = "Mickey Mouse"
    user2 = Mock(["accountId" "emailAddress"])
    user2.accountId = "mouse"
    user2.emailAddress = "mouse@example.com"
    issue1 = Mock()
    issue1.get_field.return_value = user1
    issue2 = Mock()
    issue2.get_field.return_value = user2
    jira_lib_mock.search_issues.return_value = [issue1, issue2]

    res = jira_ds.get_risk_assessor()

    assert res == [User("mickey", "Mickey Mouse"), User("mouse", None, "mouse@example.com")]
    assert_get_risk_assessor_issue_and_field_called(jira_lib_mock, [issue1, issue2])


def test_get_risk_assessor_return_default_if_no_users_returned(jira_ds, jira_lib_mock):
    issue = Mock()
    issue.get_field.return_value = None
    jira_lib_mock.search_issues.return_value = [issue]

    res = jira_ds.get_risk_assessor()

    assert res == JIRA_DEFAULT_RISK_ASSESSORS
    assert_get_risk_assessor_issue_and_field_called(jira_lib_mock, [issue])


def test_get_risk_assessor_return_default_if_no_issue_returned(jira_ds, jira_lib_mock):
    jira_lib_mock.search_issues.return_value = None

    res = jira_ds.get_risk_assessor()

    assert res == JIRA_DEFAULT_RISK_ASSESSORS
    assert_get_risk_assessor_issue_and_field_called(jira_lib_mock, None)


def assert_get_risk_assessor_issue_and_field_called(jira_lib_mock, issues):
    jira_lib_mock.search_issues.assert_called_once_with(
        f'"Epic Link" = {JIRA_INCIDENT_RESPONDER_EPIC} AND status != Done'
    )
    if issues is not None:
        for iss in issues:
            iss.get_field.assert_called_once_with("assignee")


@pytest.mark.parametrize("commit_type", [CommitType.MERGE_COMMIT, CommitType.RELEASE_COMMIT])
def test_commit_has_block_exception_return_true_if_one_comment_contains_hash(jira_ds, jira_lib_mock, commit_type):
    comment1 = Mock()
    comment1.body = "this is a comment which unfortunately does not contain a commit hash"
    comment2 = Mock()
    comment2.body = "this comment contains a commit hash 49088f3c3b615f48ee85527d51b6588a98047305 <--- here"
    jira_lib_mock.comments.return_value = [comment1, comment2]

    res = jira_ds.commit_has_block_exception(commit_type, "49088f3c3b615f48ee85527d51b6588a98047305")

    assert res is True
    assert_commit_has_block_exception_comments_called(jira_lib_mock, commit_type)


@pytest.mark.parametrize("commit_type", [CommitType.MERGE_COMMIT, CommitType.RELEASE_COMMIT])
def test_commit_has_block_exception_return_false_if_no_comment_contains_hash(jira_ds, jira_lib_mock, commit_type):
    comment1 = Mock()
    comment1.body = "this is a comment which unfortunately does not contain a commit hash"
    comment2 = Mock()
    comment2.body = "this comment contains a WRONG commit hash 49088f3c3b615f48ee85527d51b6588a98047300 <--- WRONG"
    jira_lib_mock.comments.return_value = [comment1, comment2]

    res = jira_ds.commit_has_block_exception(commit_type, "49088f3c3b615f48ee85527d51b6588a98047305")

    assert res is False
    assert_commit_has_block_exception_comments_called(jira_lib_mock, commit_type)


@pytest.mark.parametrize("commit_type", [CommitType.MERGE_COMMIT, CommitType.RELEASE_COMMIT])
def test_commit_has_block_exception_return_false_if_no_comments_returned(jira_ds, jira_lib_mock, commit_type):
    jira_lib_mock.comments.return_value = None

    res = jira_ds.commit_has_block_exception(commit_type, "49088f3c3b615f48ee85527d51b6588a98047305")

    assert res is False
    assert_commit_has_block_exception_comments_called(jira_lib_mock, commit_type)


def assert_commit_has_block_exception_comments_called(jira_lib_mock, commit_type):
    jira_lib_mock.comments.assert_called_once_with(
        JIRA_MERGE_REQUEST_EXCEPTION_TICKET
        if commit_type == CommitType.MERGE_COMMIT
        else JIRA_RELEASE_CANDIDATE_EXCEPTION_TICKET
    )


def test_get_finding_return_none_or_empty_dict_if_no_issue_found(jira_ds, jira_lib_mock):
    jira_lib_mock.search_issues.return_value = []

    res1 = jira_ds.get_open_finding("repo", "scanner", "dep_id", "dep_ver")
    res2 = jira_ds.get_open_findings_for_repo_and_scanner("repo", "scanner")

    assert res1 is None
    assert res2 == {}
    jira_lib_mock.search_issues.assert_called_once()

    res3 = jira_ds.get_deleted_findings("repo", "scanner", "dep_id")

    assert res3 == []


def test_get_finding_return_issue(jira_ds, jira_lib_mock):
    user1 = Mock(["accountId"])
    user1.accountId = "user1"
    user2 = Mock(["accountId", "displayName", "emailAddress"])
    user2.accountId = "user2"
    user2.displayName = "User 2"
    user2.emailAddress = "user2@dfinity.org"
    user3 = Mock(["accountId", "displayName"])
    user3.accountId = "user3"
    user3.displayName = "User 3"
    risk = Mock()
    risk.id = JIRA_SECURITY_RISK_TO_ID[SecurityRisk.CRITICAL]
    team1 = Mock()
    team1.name = JIRA_OWNER_GROUP_BY_TEAM[Team.OISY_TEAM]["name"]
    team2 = Mock()
    team2.name = JIRA_OWNER_GROUP_BY_TEAM[Team.DEFI_TEAM]["name"]
    issue_data = {
        JIRA_FINDING_TO_CUSTOM_FIELD.get("repository")[0]: "repo",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("scanner")[0]: "scanner",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_id")[0]: "https://crates.io/crates/chrono",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_version")[0]: "0.4.19",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("dependencies")[0]: "||*id*||*name*||*version*||\n"
        "|https://crates.io/crates/chrono|chrono|0.4.19|\n"
        "|https://crates.io/crates/syn|syn|1.0|\n",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerabilities")[0]: "||*id*||*name*||*description*||*score*||*risk*||\n"
        "|https://rustsec.org/advisories/RUSTSEC-2020-0159|RUSTSEC-2020-0159|Potential segfault in localtime_r invocations|-1| |\n"
        "|[https://rustsec.org/advisories/RUSTSEC-2022-0051|https://rustsec.org/advisories/RUSTSEC-2022-0051]|RUSTSEC-2022-0051|Memory corruption in liblz4|100|crit: [look here for more info| https://example.com] or be smart [https://example.com|https://example.com|smart-link]|\n",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_versions")[
            0
        ]: "||*dep / vuln*||RUSTSEC-2020-0159||RUSTSEC-2022-0051||\n"
        "||*chrono*|0.4.20;>=0.5.0||\n"
        "||*syn*||>=1.9.4|\n",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("projects")[0]: "* project A\n" "* project B\n" "* project C\n",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("risk_assessor")[0]: [user1, user2],
        JIRA_FINDING_TO_CUSTOM_FIELD.get("risk")[0]: risk,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("owning_teams")[0]: [team1, team2],
        JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_responsible")[0]: [user3],
        JIRA_FINDING_TO_CUSTOM_FIELD.get("due_date")[0]: "2022-12-24",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("score")[0]: "100",
    }
    issue = Mock()
    issue.get_field.side_effect = lambda x: issue_data[x]
    issue.permalink.return_value = "https://dfinity.atlassian.net/browse/SCAVM-4"
    issue.id = "SCAVM-4"
    jira_lib_mock.search_issues.return_value = [issue]

    res1 = jira_ds.get_open_finding("repo", "scanner", "https://crates.io/crates/chrono", "0.4.19")
    res2 = jira_ds.get_open_findings_for_repo_and_scanner("repo", "scanner")

    assert res1 is not None
    assert res1.repository == "repo"
    assert res1.scanner == "scanner"
    assert res1.vulnerable_dependency.id == "https://crates.io/crates/chrono"
    assert res1.vulnerable_dependency.name == "chrono"
    assert res1.vulnerable_dependency.version == "0.4.19"
    assert len(res1.vulnerable_dependency.fix_version_for_vulnerability) == 1
    assert res1.vulnerable_dependency.fix_version_for_vulnerability[
        "https://rustsec.org/advisories/RUSTSEC-2020-0159"
    ] == ["0.4.20", ">=0.5.0"]
    assert len(res1.vulnerabilities) == 2
    assert res1.vulnerabilities[0].id == "https://rustsec.org/advisories/RUSTSEC-2020-0159"
    assert res1.vulnerabilities[0].name == "RUSTSEC-2020-0159"
    assert res1.vulnerabilities[0].description == "Potential segfault in localtime_r invocations"
    assert res1.vulnerabilities[0].score == -1
    assert res1.vulnerabilities[0].risk_note == " "
    assert res1.vulnerabilities[1].id == "https://rustsec.org/advisories/RUSTSEC-2022-0051"
    assert res1.vulnerabilities[1].name == "RUSTSEC-2022-0051"
    assert res1.vulnerabilities[1].description == "Memory corruption in liblz4"
    assert res1.vulnerabilities[1].score == 100
    assert (
        res1.vulnerabilities[1].risk_note
        == "crit: [look here for more info| https://example.com] or be smart [https://example.com|https://example.com|smart-link]"
    )
    assert len(res1.first_level_dependencies) == 1
    assert res1.first_level_dependencies[0].id == "https://crates.io/crates/syn"
    assert res1.first_level_dependencies[0].name == "syn"
    assert res1.first_level_dependencies[0].version == "1.0"
    assert len(res1.first_level_dependencies[0].fix_version_for_vulnerability) == 1
    assert res1.first_level_dependencies[0].fix_version_for_vulnerability[
        "https://rustsec.org/advisories/RUSTSEC-2022-0051"
    ] == [">=1.9.4"]
    assert res1.projects == ["project A", "project B", "project C"]
    assert res1.risk_assessor == [User(user1.accountId), User(user2.accountId, user2.displayName, user2.emailAddress)]
    assert res1.risk == SecurityRisk.CRITICAL
    assert res1.owning_teams == [Team.OISY_TEAM, Team.DEFI_TEAM]
    assert res1.patch_responsible == [User(user3.accountId, user3.displayName)]
    assert res1.due_date == 1671840000
    assert res1.more_info == "https://dfinity.atlassian.net/browse/SCAVM-4"
    assert res1.score == 100

    assert len(res2) == 1
    assert res2[res1.id()] == res1

    jira_lib_mock.search_issues.assert_called_once()

    res3 = jira_ds.get_deleted_findings("repo", "scanner", "https://crates.io/crates/chrono")

    assert len(res3) == 1
    assert res3[0] == res1


def test_get_open_finding_raise_error_if_two_issues_with_same_id_returned(jira_ds, jira_lib_mock):
    user1 = Mock(["accountId"])
    user1.accountId = "user1"
    issue_data = {
        JIRA_FINDING_TO_CUSTOM_FIELD.get("repository")[0]: "repo",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("scanner")[0]: "scan",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_id")[0]: "id",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_version")[0]: "vers",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("dependencies")[0]: "||*id*||*name*||*version*||\n" "|id|chrono|vers|\n",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerabilities")[0]: "||*id*||*name*||*description*||*score*||\n"
        "|https://rustsec.org/advisories/RUSTSEC-2020-0159|RUSTSEC-2020-0159|desc|-1|\n",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_versions")[0]: "||*dep / vuln*||RUSTSEC-2020-0159||\n"
        "||*chrono*|0.4.20;>=0.5.0||\n",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("projects")[0]: "* project A",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("risk_assessor")[0]: [user1],
        JIRA_FINDING_TO_CUSTOM_FIELD.get("risk")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("owning_teams")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_responsible")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("due_date")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("score")[0]: None,
    }
    issue = Mock()
    issue.get_field.side_effect = lambda x: issue_data[x]
    issue.permalink.return_value = "https://dfinity.atlassian.net/browse/SCAVM-4"
    issue.id = "SCAVM-4"
    jira_lib_mock.search_issues.return_value = [issue, issue]

    with pytest.raises(RuntimeError, match=r"twice"):
        jira_ds.get_open_finding("repo", "scan", "id", "vers")

    with pytest.raises(RuntimeError, match=r"twice"):
        jira_ds.get_open_findings_for_repo_and_scanner("repo", "scan")

    jira_lib_mock.search_issues.assert_called()


def test_get_finding_return_none_if_primary_key_of_finding_not_matching(jira_ds, jira_lib_mock):
    issue_data = {
        JIRA_FINDING_TO_CUSTOM_FIELD.get("repository")[0]: "repo",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("scanner")[0]: "scanner",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_id")[0]: "https://crates.io/crates/chrono",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_version")[0]: "0.4.19",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("scanner")[0]: "scanner",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("dependencies")[0]: "||*id*||*name*||*version*||\n"
        "|https://crates.io/crates/chrono|chrono|0.4.19|\n",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerabilities")[0]: "||*id*||*name*||*description*||*score*||\n"
        "|https://rustsec.org/advisories/RUSTSEC-2020-0159|RUSTSEC-2020-0159|Potential segfault in localtime_r invocations|-1|\n",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_versions")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("projects")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("risk_assessor")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("risk")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("owning_teams")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_responsible")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("due_date")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("score")[0]: None,
    }
    issue = Mock()
    issue.get_field.side_effect = lambda x: issue_data[x]
    issue.permalink.return_value = "https://dfinity.atlassian.net/browse/SCAVM-4"
    jira_lib_mock.search_issues.return_value = [issue]

    res1 = jira_ds.get_open_finding(
        "repo", "scanner", "https://crates.io/crates/chrono", "0.4.191"
    )  # version not matching
    res2 = jira_ds.get_open_findings_for_repo_and_scanner("repo", "scanner")

    assert res1 is None
    assert len(res2) == 1
    jira_lib_mock.search_issues.assert_called_once()

    res3 = jira_ds.get_deleted_findings("repo", "scanner", "https://crates.io/crates/chrono2")

    assert res3 == []


def test_get_finding_raise_error_if_no_dependency_data_available(jira_ds, jira_lib_mock):
    issue_data = {
        JIRA_FINDING_TO_CUSTOM_FIELD.get("repository")[0]: "repo",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("scanner")[0]: "scanner",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("dependencies")[0]: None,
    }
    issue = Mock()
    issue.get_field.side_effect = lambda x: issue_data[x]
    jira_lib_mock.search_issues.return_value = [issue]

    with pytest.raises(RuntimeError, match=r"dependencies"):
        jira_ds.get_open_finding("repo", "scanner", "https://crates.io/crates/chrono", "0.4.19")

    with pytest.raises(RuntimeError, match=r"dependencies"):
        jira_ds.get_open_findings_for_repo_and_scanner("repo", "scanner")

    with pytest.raises(RuntimeError, match=r"dependencies"):
        jira_ds.get_deleted_findings("repo", "scanner", "https://crates.io/crates/chrono")

    jira_lib_mock.search_issues.assert_called()


def test_update_open_finding_create_issue(jira_ds, jira_lib_mock):
    issue = Mock()
    issue.id = "JIRA-ID"
    issue.permalink.return_value = f"https://dfinity.atlassian.net/browse/{issue.id}"
    jira_lib_mock.create_issue.return_value = issue
    finding = Finding(
        "repo1",
        "scan1",
        Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
        [Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
        [Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
        ["foo", "bar", "bear"],
        [User("risk assessor 1")],
        SecurityRisk.MEDIUM,
        [Team.BOUNDARY_NODE_TEAM, Team.DEFI_TEAM, Team.TRUST_TEAM],
        [User("patch responsible 1"), User("patch responsible 2")],
        0,
        42,
    )
    jira_lib_mock.search_issues.return_value = []

    jira_ds.create_or_update_open_finding(finding)

    assert finding.more_info == f"https://dfinity.atlassian.net/browse/{issue.id}"
    jira_lib_mock.create_issue.assert_called_once_with(
        {
            "project": JIRA_BOARD_KEY,
            "issuetype": JIRA_FINDING_ISSUE_TYPE,
            JIRA_FINDING_TO_CUSTOM_FIELD.get("repository")[0]: "repo1",
            JIRA_FINDING_TO_CUSTOM_FIELD.get("scanner")[0]: "scan1",
            JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_id")[0]: "VDID1",
            JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_version")[0]: "1.0",
            JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerabilities")[
                0
            ]: "||*id*||*name*||*description*||*score*||*risk*||\n|VID1|CVE-123|huuughe vuln|100| |\n",
            JIRA_FINDING_TO_CUSTOM_FIELD.get("projects")[0]: "* foo\n* bar\n* bear\n",
            JIRA_FINDING_TO_CUSTOM_FIELD.get("risk_assessor")[0]: [{"accountId": "risk assessor 1"}],
            JIRA_FINDING_TO_CUSTOM_FIELD.get("risk")[0]: {"id": JIRA_SECURITY_RISK_TO_ID[SecurityRisk.MEDIUM]},
            JIRA_FINDING_TO_CUSTOM_FIELD.get("owning_teams")[0]: [
                JIRA_OWNER_GROUP_BY_TEAM[Team.BOUNDARY_NODE_TEAM],
                JIRA_OWNER_GROUP_BY_TEAM[Team.DEFI_TEAM],
                JIRA_OWNER_GROUP_BY_TEAM[Team.TRUST_TEAM],
            ],
            JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_responsible")[0]: [
                {"accountId": "patch responsible 1"},
                {"accountId": "patch responsible 2"},
            ],
            JIRA_FINDING_TO_CUSTOM_FIELD.get("due_date")[0]: "1970-01-01",
            JIRA_FINDING_TO_CUSTOM_FIELD.get("score")[0]: 42,
            "summary": "[repo1][scan1] Vulnerability in chrono 1.0",
            JIRA_FINDING_TO_CUSTOM_FIELD.get("dependencies")[
                0
            ]: "||*id*||*name*||*version*||\n|VDID1|chrono|1.0|\n|VDID2|fl dep|0.1 beta|\n",
            JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_versions")[
                0
            ]: "||*dep / vuln*||*CVE-123*||\n||*chrono*|1.1;2.0|\n||*fl dep*|3.0 alpha|\n",
            "labels": [JIRA_LABEL_PATCH_VULNDEP_PUBLISHED, JIRA_LABEL_PATCH_ALLDEP_PUBLISHED],
        }
    )


def test_create_query_update_finding():
    jira_lib_mock = Mock()
    sub1 = Mock()
    sub2 = Mock()
    jira_ds = JiraFindingDataSource([sub1, sub2], custom_jira=jira_lib_mock)
    InMemoryJira(jira_lib_mock)
    finding_in = Finding(
        "repo1",
        "scan1",
        Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
        [Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
        [Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
        ["foo", "bar", "bear"],
        [User("risk assessor 1")],
        SecurityRisk.MEDIUM,
        [],
        [User("patch responsible 1"), User("patch responsible 2")],
        0,
        42,
    )
    jira_lib_mock.search_issues.return_value = []

    jira_ds.create_or_update_open_finding(finding_in)
    finding_out = jira_ds.get_open_finding("repo1", "scan1", "VDID1", "1.0")

    finding_in.more_info = finding_out.more_info
    assert finding_in == finding_out
    jira_lib_mock.create_issue.assert_called_once()
    sub1.on_finding_created.assert_called_once()
    sub1.on_finding_refreshed.assert_not_called()
    sub2.on_finding_created.assert_called_once()
    sub2.on_finding_refreshed.assert_not_called()

    finding_out.vulnerabilities.append(Vulnerability("VID2", "CVE-456", "CRITICAL VULN o.O"))
    finding_out.risk = None
    finding_out.score = -1
    finding_out.due_date = None

    jira_ds.create_or_update_open_finding(finding_out)
    finding_out2 = jira_ds.get_open_finding("repo1", "scan1", "VDID1", "1.0")

    assert finding_out == finding_out2
    jira_lib_mock.create_issue.assert_called_once()
    sub1.on_finding_created.assert_called_once()
    sub1.on_finding_refreshed.assert_called_once()
    sub2.on_finding_created.assert_called_once()
    sub2.on_finding_refreshed.assert_called_once()


def test_create_finding_special_character_escaping(jira_ds, jira_lib_mock):
    mem = InMemoryJira(jira_lib_mock)
    finding_in = Finding(
        "repo",
        "scanner",
        Dependency("id{code}and|pipe{code}", "{code}name{code}", "ver|sion", {"id{code}": ["123;456", ";789"]}),
        [
            Vulnerability(
                "id{code}",
                "{code}na|me{code}",
                "|description|",
                0,
                "[url with pipe is fine|https://example.com] and{code}",
            )
        ],
        [Dependency("|id|", "{code}name", "ver{code}|sion", {"id{code}": [";321;", "98;7"]})],
        ["proj1{code}", "|proj2", "pr{code}oject3|"],
        [],
        None,
        [],
        [],
        None,
    )
    jira_lib_mock.search_issues.return_value = []

    jira_ds.create_or_update_open_finding(finding_in)

    key = "repo-scanner-id{code}and|pipe{code}-ver|sion"
    assert key in mem.store
    assert mem.store[key][JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_id")[0]] == "id{code}and|pipe{code}"
    assert mem.store[key][JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_version")[0]] == "ver|sion"
    assert (
        mem.store[key][JIRA_FINDING_TO_CUSTOM_FIELD.get("dependencies")[0]]
        == "||*id*||*name*||*version*||\n|id\\{code}and:pipe\\{code}|\\{code}name\\{code}|ver:sion|\n|:id:|\\{code}name|ver\\{code}:sion|\n"
    )
    assert (
        mem.store[key][JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerabilities")[0]]
        == "||*id*||*name*||*description*||*score*||*risk*||\n|id\\{code}|\\{code}na:me\\{code}|:description:|0|[url with pipe is fine|https://example.com] and\\{code}|\n"
    )
    assert (
        mem.store[key][JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_versions")[0]]
        == "||*dep / vuln*||*\\{code}na:me\\{code}*||\n||*\\{code}name\\{code}*|123:456;:789|\n||*\\{code}name*|:321:;98:7|\n"
    )
    assert (
        mem.store[key][JIRA_FINDING_TO_CUSTOM_FIELD.get("projects")[0]]
        == "* proj1\\{code}\n* :proj2\n* pr\\{code}oject3:\n"
    )


def test_dont_create_finding_with_too_long_field(jira_ds, jira_lib_mock):
    mem = InMemoryJira(jira_lib_mock)
    finding_in = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_vers"),
        [Vulnerability("vuln_id", "vuln_name", "vuln_version")],
        [],
        ["project"],
        [],
        None,
        [],
        [],
        None,
    )
    for i in range(1000):
        finding_in.vulnerabilities.append(
            Vulnerability(
                id=random_string(10), name=random_string(10), description=random_string(10), risk_note=random_string(10)
            )
        )
    jira_lib_mock.search_issues.return_value = []

    jira_ds.create_or_update_open_finding(finding_in)

    assert len(mem.store) == 0


def test_dont_update_finding_with_too_long_field(jira_ds, jira_lib_mock):
    issue_data = {
        JIRA_FINDING_TO_CUSTOM_FIELD.get("repository")[0]: "repo",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("scanner")[0]: "scanner",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_id")[0]: "dep_id",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_version")[0]: "dep_vers",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("scanner")[0]: "scanner",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("dependencies")[0]: "||*id*||*name*||*version*||\n"
        "|dep_id|dep_name|dep_vers|\n",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerabilities")[0]: "||*id*||*name*||*description*||*score*||*risk*||\n"
        "|vuln_id|vuln_name|vuln_version|-1| |\n",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_versions")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("projects")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("risk_assessor")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("risk")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("owning_teams")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_responsible")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("due_date")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("score")[0]: None,
    }
    issue = Mock()
    issue.get_field.side_effect = lambda x: issue_data[x]
    issue.permalink.return_value = "https://dfinity.atlassian.net/browse/SCAVM-4"
    jira_lib_mock.search_issues.return_value = [issue]

    finding_in = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_vers"),
        [Vulnerability("vuln_id", "vuln_name", "vuln_version")],
        [],
        [],
        [],
        None,
        [],
        [],
        None,
    )
    for i in range(1000):
        finding_in.vulnerabilities.append(
            Vulnerability(
                id=random_string(10), name=random_string(10), description=random_string(10), risk_note=random_string(10)
            )
        )

    jira_ds.create_or_update_open_finding(finding_in)

    issue.update.assert_not_called()


def test_delete_finding():
    jira_lib_mock = Mock()
    sub = Mock()
    jira_ds = JiraFindingDataSource([sub], custom_jira=jira_lib_mock)
    issue_data = {
        JIRA_FINDING_TO_CUSTOM_FIELD.get("repository")[0]: "repo",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("scanner")[0]: "scanner",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_id")[0]: "https://crates.io/crates/chrono",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_version")[0]: "0.4.19",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("dependencies")[0]: "||*id*||*name*||*version*||\n"
        "|https://crates.io/crates/chrono|chrono|0.4.19|\n",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerabilities")[0]: "||*id*||*name*||*description*||*score*||\n"
        "|vuln_id|vuln_name|vuln_desc|-1|\n",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_versions")[
            0
        ]: "||*dep / vuln*||RUSTSEC-2020-0159||RUSTSEC-2022-0051||\n",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("projects")[0]: "",
        JIRA_FINDING_TO_CUSTOM_FIELD.get("risk_assessor")[0]: [],
        JIRA_FINDING_TO_CUSTOM_FIELD.get("risk")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("owning_teams")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("patch_responsible")[0]: [],
        JIRA_FINDING_TO_CUSTOM_FIELD.get("due_date")[0]: None,
        JIRA_FINDING_TO_CUSTOM_FIELD.get("score")[0]: None,
    }
    issue = Mock()
    issue.get_field.side_effect = lambda x: issue_data[x]
    issue.permalink.return_value = "https://dfinity.atlassian.net/browse/SCAVM-4"
    issue.id = "SCAVM-4"
    jira_lib_mock.search_issues.return_value = [issue]

    jira_ds.delete_finding(
        Finding(
            "repo",
            "scanner",
            Dependency("https://crates.io/crates/chrono", "chrono", "0.4.19"),
            [Vulnerability("a", "b", "c")],
            [],
            [],
            [],
            None,
            [],
            [],
            None,
        )
    )

    jira_lib_mock.transition_issue.assert_called_once_with(issue.id, "41")
    sub.on_finding_deleted.assert_called_once()


def test_owning_team_mapping_complete(jira_ds, jira_lib_mock):
    for team in Team:
        assert team in JIRA_OWNER_GROUP_BY_TEAM


class InMemoryJira:
    def __init__(self, jira_lib_mock):
        self.store = {}
        jira_lib_mock.create_issue.side_effect = lambda x: self.create_issue(x)
        # jira_lib_mock.search_issues.side_effect = lambda x: self.query_issue(x)

    @staticmethod
    def __mock_issue(issue_id, raw_issue):
        issue = Mock()
        issue.id = issue_id
        issue.update.side_effect = lambda x: raw_issue.update(x)
        issue.get_field.side_effect = lambda x: raw_issue[x]
        issue.permalink.return_value = f"https://dfinity.atlassian.net/browse/{issue_id}"
        return issue

    @staticmethod
    def __convert_users(raw_users):
        users = []
        for ru in raw_users:
            u = Mock(["accountId"])
            u.accountId = ru["accountId"]
            users.append(u)
        return users

    @staticmethod
    def __convert_risk(raw_risk):
        if raw_risk is None:
            return None
        risk = Mock()
        risk.id = raw_risk["id"]
        return risk

    def create_issue(self, raw_issue):
        repo = raw_issue[JIRA_FINDING_TO_CUSTOM_FIELD.get("repository")[0]]
        scan = raw_issue[JIRA_FINDING_TO_CUSTOM_FIELD.get("scanner")[0]]
        vdid = raw_issue[JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_id")[0]]
        vdv = raw_issue[JIRA_FINDING_TO_CUSTOM_FIELD.get("vulnerable_dependency_version")[0]]
        issue_id = f"{repo}-{scan}-{vdid}-{vdv}"
        for field in ["risk_assessor", "patch_responsible"]:
            if JIRA_FINDING_TO_CUSTOM_FIELD.get(field)[0] in raw_issue:
                raw_issue[JIRA_FINDING_TO_CUSTOM_FIELD.get(field)[0]] = self.__convert_users(
                    raw_issue[JIRA_FINDING_TO_CUSTOM_FIELD.get(field)[0]]
                )
        if JIRA_FINDING_TO_CUSTOM_FIELD.get("risk")[0] in raw_issue:
            raw_issue[JIRA_FINDING_TO_CUSTOM_FIELD.get("risk")[0]] = self.__convert_risk(
                raw_issue[JIRA_FINDING_TO_CUSTOM_FIELD.get("risk")[0]]
            )
        self.store[issue_id] = raw_issue
        return self.__mock_issue(issue_id, raw_issue)

    def query_issue(self, query):
        match = re.search('~\\s*"([^"]+)".*' * 4, query)
        repo = match.group(1)
        scan = match.group(2)
        vdid = match.group(3)
        vdv = match.group(4)
        issue_id = f"{repo}-{scan}-{vdid}-{vdv}"
        if issue_id in self.store:
            return [self.__mock_issue(issue_id, self.store[issue_id])]
        return []
