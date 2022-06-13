import json
import pathlib

import jira_helper
import pytest

pytestmark = pytest.mark.skip(
    reason="These are integration tests for JIRA which are not necessary to be executed on every CI run"
)

# The current service account only has member access, hence can't delete issues which is needed during teardown of the fixture.
# While running the integration test locally, change access control to administrator for the service account.

jira_helper.JIRA_BOARD_KEY = "VMT"
jira_helper.JIRA_ISSUE_TYPE = "MR Scan"
jira_helper.BRANCH_NAME = "JIRA Test Branch"

TEST_DATA = pathlib.Path(__file__).parent / "test_data"


def test_jira_auth():
    jira = jira_helper.auth()
    assert jira.session()


def test_board_exists():
    jira = jira_helper.auth()
    project = jira.project(jira_helper.JIRA_BOARD_KEY)
    assert project.name == "Vulnerability Management"


def test_issue_type_exists():
    jira = jira_helper.auth()
    issue_type = jira.issue_type_by_name(jira_helper.JIRA_ISSUE_TYPE)
    assert issue_type.name == "MR Scan"


@pytest.fixture(autouse=True)
def delete_test_issues():
    jira = jira_helper.auth()
    issues = jira.search_issues(f'project = "{jira_helper.JIRA_BOARD_KEY}"')
    if issues:
        for issue in issues:
            issue.delete()
    yield
    issues = jira.search_issues(f'project = "{jira_helper.JIRA_BOARD_KEY}"')
    if issues:
        for issue in issues:
            issue.delete()


def test_create_description():
    with open(TEST_DATA / "vulnerability_scan" / "ticket_description.txt", "r") as f:
        expected_data = f.read()

    with open(TEST_DATA / "vulnerability_scan" / "normal.json", "r") as f:
        scan_data = json.load(f)
    assert jira_helper.create_description(scan_data) == expected_data


def test_create_description_on_empty_payloads():
    d1 = jira_helper.create_description({"modified_crates": []})
    d2 = jira_helper.create_description({"vulnerable_crates": []})
    d3 = jira_helper.create_description({"vulnerability_scan": []})
    d4 = jira_helper.create_description({"whitelist_status": []})

    d5 = jira_helper.create_description({})

    assert not d1 and not d2 and not d3 and not d4 and not d5


def test_create_ticket():

    with open(TEST_DATA / "vulnerability_scan" / "normal.json", "r") as f:
        scan_data = json.load(f)

    with open(TEST_DATA / "vulnerability_scan" / "ticket_description.txt", "r") as f:
        expected_data = f.read()

    url = jira_helper.create_ticket(scan_data)
    assert url

    jira = jira_helper.auth()
    issue_no = url.split("/")[-1]
    issue = jira.issue(issue_no)

    assert issue.fields.summary == "JIRA Test Branch MR dependency scan @ 341fd66d039b"
    assert issue.fields.description == expected_data
    assert len(issue.fields.attachment) == 1
    assert issue.fields.attachment[0].filename == "scan.json"
    assert json.loads(issue.fields.attachment[0].get()) == scan_data


def test_check_ticket_true():

    with open(TEST_DATA / "vulnerability_scan" / "normal.json", "r") as f:
        scan_data = json.load(f)

    url = jira_helper.create_ticket(scan_data)
    assert url
    assert jira_helper.check_ticket_exists()


def test_check_ticket_false():

    assert not jira_helper.check_ticket_exists()


def test_update_ticket():

    with open(TEST_DATA / "vulnerability_scan" / "normal.json", "r") as f:
        scan_data = json.load(f)

    url = jira_helper.create_ticket(scan_data)
    assert url

    jira_helper.update_ticket(scan_data)

    jira = jira_helper.auth()
    issue_no = url.split("/")[-1]
    issue = jira.issue(issue_no)

    comments = issue.fields.comment.comments
    assert len(comments) == 1
    assert comments[0].body == jira_helper.create_description(scan_data)
