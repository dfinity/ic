from unittest.mock import Mock, call

import pytest
from data_source.slack_findings_failover.data import (
    VULNERABILITY_MSG_FIXED_REACTION,
    SlackFinding,
    SlackProjectInfo,
    SlackRiskAssessor,
    SlackVulnerabilityEvent,
)
from data_source.slack_findings_failover.scan_result import SlackScanResult
from data_source.slack_findings_failover.vuln_info import SlackVulnerabilityMessageInfo
from data_source.slack_findings_failover.vuln_store import SlackVulnerabilityStore

TEST_SLACK_MSG = "SLACK_MSG"
TEST_SLACK_MSG_ID = "SLACK_MSG_ID"
TEST_SLACK_MSG_PERMALINK = "SLACK_MSG_PERMALINK"

TEST_SLACK_API_SEND_MSG_CALL = call.send_message(message=TEST_SLACK_MSG, is_block_kit_message=True, thread_id=None)


def slack_api_update_msg_call(msg_id):
    return call.update_message(message=TEST_SLACK_MSG, is_block_kit_message=True, message_id=msg_id)


def slack_api_react_msg_call(msg_id):
    return call.add_reaction(reaction=VULNERABILITY_MSG_FIXED_REACTION, message_id=msg_id)


def slack_api_risk_ass_msg_call(msg_id, risk_ass):
    return call.send_message(
        message=f"This finding needs risk assessment from {risk_ass}", is_block_kit_message=False, thread_id=msg_id
    )


@pytest.fixture
def slack_api():
    slack_api = Mock()
    slack_api.send_message.return_value = TEST_SLACK_MSG_ID
    slack_api.get_permalink.return_value = TEST_SLACK_MSG_PERMALINK
    return slack_api


@pytest.fixture
def slack_store(slack_api):
    return SlackVulnerabilityStore({"c1": slack_api, "c2": slack_api})


@pytest.fixture()
def slack_vuln_info():
    svi = Mock()
    svi.vulnerability.id = "vid"
    svi.vulnerability.name = "vname"
    svi.msg_info_by_channel = {
        "c1": SlackVulnerabilityMessageInfo("c1", "m1"),
        "c2": SlackVulnerabilityMessageInfo("c2", "m2"),
    }
    svi.finding_by_id = {("a", "b", "c", "d"): SlackFinding("a", "b", "c", "d", ["p1"])}
    svi.get_slack_msg_for.return_value = TEST_SLACK_MSG
    return svi


@pytest.fixture()
def info_by_project():
    return {
        "p1": SlackProjectInfo(
            "p1",
            {"c1", "c2"},
            {"c1": [SlackRiskAssessor("risk_ass1", True)], "c2": [SlackRiskAssessor("risk_ass2", True)]},
        )
    }


def test_handle_vuln_added_event(slack_store, slack_vuln_info, slack_api):
    events = [SlackVulnerabilityEvent.vuln_added("vid", "c1"), SlackVulnerabilityEvent.vuln_added("vid", "c2")]
    scan_res = {"c1": SlackScanResult(), "c2": SlackScanResult()}

    slack_store.handle_events(events, scan_res, slack_vuln_info, {})

    assert scan_res["c1"].new_vulnerabilities == 1 and scan_res["c2"].new_vulnerabilities == 1
    slack_api.assert_has_calls([TEST_SLACK_API_SEND_MSG_CALL, TEST_SLACK_API_SEND_MSG_CALL])
    assert slack_vuln_info.msg_info_by_channel == {
        "c1": SlackVulnerabilityMessageInfo("c1", TEST_SLACK_MSG_ID),
        "c2": SlackVulnerabilityMessageInfo("c2", TEST_SLACK_MSG_ID),
    }


def test_handle_vuln_removed_event(slack_store, slack_vuln_info, slack_api):
    events = [SlackVulnerabilityEvent.vuln_removed("vid", "c1"), SlackVulnerabilityEvent.vuln_removed("vid", "c2")]
    scan_res = {"c1": SlackScanResult(), "c2": SlackScanResult()}

    slack_store.handle_events(events, scan_res, slack_vuln_info, {})

    assert scan_res["c1"].fixed_vulnerabilities == 1 and scan_res["c2"].fixed_vulnerabilities == 1
    slack_api.assert_has_calls([slack_api_react_msg_call("m1"), slack_api_react_msg_call("m2")])


def test_handle_vuln_changed_event(slack_store, slack_vuln_info, slack_api):
    events = [
        SlackVulnerabilityEvent.vuln_changed("vid", "c1", {"desc": "changed"}),
        SlackVulnerabilityEvent.vuln_changed("vid", "c2", {"desc": "changed"}),
    ]
    scan_res = {"c1": SlackScanResult(), "c2": SlackScanResult()}

    slack_store.handle_events(events, scan_res, slack_vuln_info, {})

    assert scan_res["c1"].changed_vulnerabilities == 1 and scan_res["c2"].changed_vulnerabilities == 1
    slack_api.update_message.assert_any_call(message=TEST_SLACK_MSG, is_block_kit_message=True, message_id="m1")
    slack_api.update_message.assert_any_call(message=TEST_SLACK_MSG, is_block_kit_message=True, message_id="m2")
    slack_api.send_message.assert_called()


def test_handle_dep_added_event(slack_store, slack_vuln_info, slack_api):
    events = [
        SlackVulnerabilityEvent.dep_added("vid", "c1", ("scanner", "repo", "did", "dvers"), ["proj1"]),
        SlackVulnerabilityEvent.dep_added("vid", "c2", ("scanner", "repo", "did", "dvers"), ["proj2"]),
    ]
    scan_res = {"c1": SlackScanResult(), "c2": SlackScanResult()}

    slack_store.handle_events(events, scan_res, slack_vuln_info, {})

    assert scan_res["c1"].added_dependencies[("scanner", "repo", "did", "dvers")] == {"proj1"}
    assert scan_res["c2"].added_dependencies[("scanner", "repo", "did", "dvers")] == {"proj2"}
    slack_api.assert_has_calls([slack_api_update_msg_call("m1"), slack_api_update_msg_call("m2")])


def test_handle_dep_removed_event(slack_store, slack_vuln_info, slack_api):
    events = [
        SlackVulnerabilityEvent.dep_removed("vid", "c1", ("scanner", "repo", "did", "dvers"), ["proj1"]),
        SlackVulnerabilityEvent.dep_removed("vid", "c2", ("scanner", "repo", "did", "dvers"), ["proj2"]),
    ]
    scan_res = {"c1": SlackScanResult(), "c2": SlackScanResult()}

    slack_store.handle_events(events, scan_res, slack_vuln_info, {})

    assert scan_res["c1"].removed_dependencies[("scanner", "repo", "did", "dvers")] == {"proj1"}
    assert scan_res["c2"].removed_dependencies[("scanner", "repo", "did", "dvers")] == {"proj2"}
    slack_api.assert_has_calls([slack_api_update_msg_call("m1"), slack_api_update_msg_call("m2")])


def test_handle_risk_unknown_event(slack_store, slack_vuln_info, slack_api, info_by_project):
    events = [SlackVulnerabilityEvent.risk_unknown("vid", "c1"), SlackVulnerabilityEvent.risk_unknown("vid", "c2")]
    scan_res = {"c1": SlackScanResult(), "c2": SlackScanResult()}

    slack_store.handle_events(events, scan_res, slack_vuln_info, info_by_project)

    assert scan_res["c1"].unrated_vulnerabilities_reminder == {"vname": (TEST_SLACK_MSG_PERMALINK, {"risk_ass1"})}
    assert scan_res["c2"].unrated_vulnerabilities_reminder == {"vname": (TEST_SLACK_MSG_PERMALINK, {"risk_ass2"})}
