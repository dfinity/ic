from unittest.mock import Mock, call

import pytest
from data_source.slack_findings_failover.data import VULNERABILITY_MSG_FIXED_REACTION, SlackVulnerabilityEvent
from data_source.slack_findings_failover.scan_result import SlackScanResult
from data_source.slack_findings_failover.vuln_store import SlackVulnerabilityStore

TEST_SLACK_MSG = "SLACK_MSG"
TEST_SLACK_MSG_ID = "SLACK_MSG_ID"

TEST_SLACK_API_SEND_MSG_CALL = call.send_message(message=TEST_SLACK_MSG, is_block_kit_message=True, thread_id=None)


def slack_api_update_msg_call(msg_id):
    return call.update_message(message=TEST_SLACK_MSG, is_block_kit_message=True, message_id=msg_id)


def slack_api_react_msg_call(msg_id):
    return call.add_reaction(reaction=VULNERABILITY_MSG_FIXED_REACTION, message_id=msg_id)


@pytest.fixture
def slack_api():
    slack_api = Mock()
    slack_api.send_message.return_value = TEST_SLACK_MSG_ID
    return slack_api


@pytest.fixture
def slack_store(slack_api):
    return SlackVulnerabilityStore({"c1": slack_api, "c2": slack_api})


@pytest.fixture()
def slack_vuln_info():
    svi = Mock()
    svi.vulnerability.id = "vid"
    svi.msg_id_by_channel = {"c1": "m1", "c2": "m2"}
    svi.get_slack_msg_for.return_value = TEST_SLACK_MSG
    return svi


def test_handle_vuln_added_event(slack_store, slack_vuln_info, slack_api):
    events = [SlackVulnerabilityEvent.vuln_added("vid", "c1"), SlackVulnerabilityEvent.vuln_added("vid", "c2")]
    scan_res = {"c1": SlackScanResult(), "c2": SlackScanResult()}

    slack_store.handle_events(events, scan_res, slack_vuln_info, {})

    assert scan_res["c1"].new_vulnerabilities == 1 and scan_res["c2"].new_vulnerabilities == 1
    slack_api.assert_has_calls([TEST_SLACK_API_SEND_MSG_CALL, TEST_SLACK_API_SEND_MSG_CALL])
    assert slack_vuln_info.msg_id_by_channel == {"c1": TEST_SLACK_MSG_ID, "c2": TEST_SLACK_MSG_ID}


def test_handle_vuln_removed_event(slack_store, slack_vuln_info, slack_api):
    events = [SlackVulnerabilityEvent.vuln_removed("vid", "c1"), SlackVulnerabilityEvent.vuln_removed("vid", "c2")]
    scan_res = {"c1": SlackScanResult(), "c2": SlackScanResult()}

    slack_store.handle_events(events, scan_res, slack_vuln_info, {})

    assert scan_res["c1"].fixed_vulnerabilities == 1 and scan_res["c2"].fixed_vulnerabilities == 1
    slack_api.assert_has_calls([slack_api_react_msg_call("m1"), slack_api_react_msg_call("m2")])


def test_handle_vuln_changed_event(slack_store, slack_vuln_info, slack_api):
    events = [SlackVulnerabilityEvent.vuln_changed("vid", "c1", {"desc": "changed"}), SlackVulnerabilityEvent.vuln_changed("vid", "c2", {"desc": "changed"})]
    scan_res = {"c1": SlackScanResult(), "c2": SlackScanResult()}

    slack_store.handle_events(events, scan_res, slack_vuln_info, {})

    assert scan_res["c1"].changed_vulnerabilities == 1 and scan_res["c2"].changed_vulnerabilities == 1
    slack_api.update_message.assert_any_call(message=TEST_SLACK_MSG, is_block_kit_message=True, message_id="m1")
    slack_api.update_message.assert_any_call(message=TEST_SLACK_MSG, is_block_kit_message=True, message_id="m2")
    slack_api.send_message.assert_called()


def test_handle_dep_added_event(slack_store, slack_vuln_info, slack_api):
    events = [SlackVulnerabilityEvent.dep_added("vid", "c1", ("scanner", "repo", "did", "dvers"), ["proj1"]), SlackVulnerabilityEvent.dep_added("vid", "c2", ("scanner", "repo", "did", "dvers"), ["proj2"])]
    scan_res = {"c1": SlackScanResult(), "c2": SlackScanResult()}

    slack_store.handle_events(events, scan_res, slack_vuln_info, {})

    assert scan_res["c1"].added_dependencies[("scanner", "repo", "did", "dvers")] == {"proj1"}
    assert scan_res["c2"].added_dependencies[("scanner", "repo", "did", "dvers")] == {"proj2"}
    slack_api.assert_has_calls([slack_api_update_msg_call("m1"), slack_api_update_msg_call("m2")])


def test_handle_dep_removed_event(slack_store, slack_vuln_info, slack_api):
    events = [SlackVulnerabilityEvent.dep_removed("vid", "c1", ("scanner", "repo", "did", "dvers"), ["proj1"]), SlackVulnerabilityEvent.dep_removed("vid", "c2", ("scanner", "repo", "did", "dvers"), ["proj2"])]
    scan_res = {"c1": SlackScanResult(), "c2": SlackScanResult()}

    slack_store.handle_events(events, scan_res, slack_vuln_info, {})

    assert scan_res["c1"].removed_dependencies[("scanner", "repo", "did", "dvers")] == {"proj1"}
    assert scan_res["c2"].removed_dependencies[("scanner", "repo", "did", "dvers")] == {"proj2"}
    slack_api.assert_has_calls([slack_api_update_msg_call("m1"), slack_api_update_msg_call("m2")])
