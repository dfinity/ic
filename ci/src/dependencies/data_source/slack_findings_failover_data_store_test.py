from copy import deepcopy
from typing import Dict, List
from unittest.mock import Mock

from data_source.slack_findings_failover.data import (
    VULNERABILITY_THRESHOLD_SCORE,
    SlackFinding,
    SlackProjectInfo,
    SlackVulnerabilityEvent,
    SlackVulnerabilityEventType,
)
from data_source.slack_findings_failover.scan_result import SlackScanResult
from data_source.slack_findings_failover.vuln_info import SlackVulnerabilityInfo, VulnerabilityInfo
from data_source.slack_findings_failover.vuln_store import SlackVulnerabilityStore
from data_source.slack_findings_failover_data_store import SLACK_CHANNEL_CONFIG_BY_TEAM, SlackFindingsFailoverDataStore
from model.dependency import Dependency
from model.finding import Finding
from model.project import Project
from model.team import Team
from model.vulnerability import Vulnerability


def test_can_handle_finding():
    fo_finding1 = Finding(
        "ic",
        "BAZEL_TRIVY_CS",
        Dependency("linux-libc-dev", "linux-libc-dev", "1.0"),
        [Vulnerability("vid", "vname", "vdesc")],
        [],
        ["ic/proj1", "ic/proj1/subproj/foo"],
        [],
    )
    fo_finding2 = Finding(
        "ic",
        "BAZEL_TRIVY_CS",
        Dependency("linux-modules-0.8.15", "linux-modules-0.8.15", "1.0"),
        [Vulnerability("vid", "vname", "vdesc")],
        [],
        ["ic/proj1", "ic/proj1/subproj/foo"],
        [],
    )

    ds = SlackFindingsFailoverDataStore([Project("ic", "ic/proj1", None, Team.NODE_TEAM)])
    assert ds.can_handle(fo_finding1)
    assert ds.can_handle(fo_finding2)

    ds = SlackFindingsFailoverDataStore(
        [
            Project(
                "ic",
                "ic/proj1",
                None,
                None,
                {"ic/proj1/subproj": [Team.NODE_TEAM], "ic/proj1": [Team.NODE_TEAM]},
            )
        ]
    )
    assert ds.can_handle(fo_finding1)
    assert ds.can_handle(fo_finding2)


def test_can_not_handle_finding():
    finding = Finding(
        "ic",
        "BAZEL_TRIVY_CS",
        Dependency("linux-libc", "linux-libc", "1.0"),
        [Vulnerability("vid", "vname", "vdesc")],
        [],
        ["ic/proj1", "ic/proj1/subproj/foo"],
        [],
    )

    assert not SlackFindingsFailoverDataStore([Project("ic", "ic/proj1", None, Team.NODE_TEAM)]).can_handle(finding)


def test_store_findings():
    v1 = Vulnerability("vid", "vname", "vdesc", 8)
    sf1 = SlackFinding("repo", "scanner", "did", "dvers", ["proj1", "proj2"])
    f1 = Finding("repo", "scanner", Dependency("did", "dname", "dvers"), [v1], [], ["proj1", "proj3"], [])
    v1_events = [
        SlackVulnerabilityEvent.vuln_added("vid", SLACK_CHANNEL_CONFIG_BY_TEAM[Team.NODE_TEAM].channel_id),
        SlackVulnerabilityEvent.vuln_removed("vid", SLACK_CHANNEL_CONFIG_BY_TEAM[Team.NODE_TEAM].channel_id),
        SlackVulnerabilityEvent.dep_added(
            "vid", SLACK_CHANNEL_CONFIG_BY_TEAM[Team.NODE_TEAM].channel_id, f1.id(), ["proj3"]
        ),
        SlackVulnerabilityEvent.dep_removed(
            "vid", SLACK_CHANNEL_CONFIG_BY_TEAM[Team.NODE_TEAM].channel_id, sf1.id(), ["proj2"]
        ),
    ]

    v_old = Vulnerability("vid_old", "vname_old", "vdesc_old", 8)
    sf_old = SlackFinding("repo", "scanner", "did_old", "dvers_old", ["proj3"])
    v_old_events = [
        SlackVulnerabilityEvent.vuln_removed("vid_old", SLACK_CHANNEL_CONFIG_BY_TEAM[Team.NODE_TEAM].channel_id),
        SlackVulnerabilityEvent.dep_removed(
            "vid_old", SLACK_CHANNEL_CONFIG_BY_TEAM[Team.NODE_TEAM].channel_id, sf_old.id(), ["proj3"]
        ),
    ]

    v_new = Vulnerability("vid_new", "vname_new", "vdesc_new", 9)
    f_new = Finding("repo", "scanner", Dependency("did_new", "dname", "dvers_new"), [v_new], [], ["proj1"], [])

    v_below_thresh = Vulnerability("vid_low", "vname_low", "vdesc_low", VULNERABILITY_THRESHOLD_SCORE - 1)
    f_below_thresh = Finding(
        "repo", "scanner", Dependency("did_low", "dname", "dvers_low"), [v_below_thresh], [], ["proj1"], []
    )

    svi1 = Mock()
    svi1.finding_by_id = {sf1.id(): sf1}
    svi1.vulnerability = v1
    svi1.update_with.return_value = v1_events
    svi_old = Mock()
    svi_old.finding_by_id = {sf_old.id(): sf_old}
    svi_old.vulnerability = v_old
    svi_old.get_events_for_remove.return_value = v_old_events

    slack_vuln_by_vuln_id = {v1.id: svi1, v_old.id: svi_old}

    current_findings = [f1, f_new, f_below_thresh]

    projects = [
        Project("proj1", "proj1", None, Team.NODE_TEAM),
        Project("proj2", "proj2", None, Team.NODE_TEAM),
        Project("proj3", "proj3", None, Team.NODE_TEAM),
    ]
    slack_api = Mock()
    loader = Mock()
    loader.load_findings.return_value = slack_vuln_by_vuln_id
    storage = MockSlackStore()
    failover = SlackFindingsFailoverDataStore(projects, slack_api, loader, storage)

    failover.store_findings("repo", "scanner", current_findings)

    assert len(storage.events_by_vuln_id) == 3
    assert storage.events_by_vuln_id[v1.id] == v1_events
    assert storage.events_by_vuln_id[v_old.id] == v_old_events
    assert storage.events_by_vuln_id[v_new.id] == [
        SlackVulnerabilityEvent.vuln_added(v_new.id, SLACK_CHANNEL_CONFIG_BY_TEAM[Team.NODE_TEAM].channel_id),
        SlackVulnerabilityEvent.dep_added(
            v_new.id, SLACK_CHANNEL_CONFIG_BY_TEAM[Team.NODE_TEAM].channel_id, f_new.id(), f_new.projects
        ),
    ]
    assert slack_api.send_message.call_count == 1


def test_filter_findings():
    v1 = Vulnerability("v1id", "v1 name", "V1 desc", 10)
    # filtered because only f1 is affected and ic/proj1 ignores it
    v2 = Vulnerability("v2id", "v2 name", "v2 desc", 10)
    v3 = Vulnerability("v3id", "v3 name", "v3 desc", 10)
    # filtered because of too low score
    v4 = Vulnerability("v4id", "v4 name", "v4 desc", 2)
    # filtered in v1 and v3
    f1 = Finding(
        "ic",
        "BAZEL_TRIVY_CS",
        Dependency("f1id", "f1 name", "1.0"),
        [v1, v2, v4],
        [],
        ["ic/proj1"],
        [],
    )
    # ic/proj1 filtered in v1
    f2 = Finding(
        "ic",
        "BAZEL_TRIVY_CS",
        Dependency("f2id", "f2 name", "2.0"),
        [v1, v3, v4],
        [],
        ["ic/proj1", "ic/proj2"],
        [],
    )
    ignore_list_by_project = {"ic/proj1": {"v1 DES", "v2"}}
    vuln_by_vuln_id = {
        v1.id: VulnerabilityInfo(v1, {f1.id(): deepcopy(f1), f2.id(): deepcopy(f2)}),
        v2.id: VulnerabilityInfo(v2, {f1.id(): deepcopy(f1)}),
        v3.id: VulnerabilityInfo(v3, {f2.id(): deepcopy(f2)}),
    }

    SlackFindingsFailoverDataStore._filter_vulns(vuln_by_vuln_id, ignore_list_by_project)

    assert len(vuln_by_vuln_id) == 2

    assert v1.id in vuln_by_vuln_id
    assert len(vuln_by_vuln_id[v1.id].finding_by_id) == 1
    assert f2.id() in vuln_by_vuln_id[v1.id].finding_by_id
    assert vuln_by_vuln_id[v1.id].finding_by_id[f2.id()].projects == ["ic/proj2"]

    assert v3.id in vuln_by_vuln_id
    assert len(vuln_by_vuln_id[v3.id].finding_by_id) == 1
    assert f2.id() in vuln_by_vuln_id[v3.id].finding_by_id
    assert vuln_by_vuln_id[v3.id].finding_by_id[f2.id()].projects == ["ic/proj1", "ic/proj2"]


class MockSlackStore(SlackVulnerabilityStore):
    def __init__(self):
        self.events_by_vuln_id = {}

    def handle_events(
        self,
        events: List[SlackVulnerabilityEvent],
        scan_result_by_channel: Dict[str, SlackScanResult],
        slack_vuln_info: SlackVulnerabilityInfo,
        info_by_project: Dict[str, SlackProjectInfo],
    ):
        if slack_vuln_info.vulnerability.id in self.events_by_vuln_id:
            raise RuntimeError(f"duplicate vuln id {slack_vuln_info.vulnerability.id}")
        self.events_by_vuln_id[slack_vuln_info.vulnerability.id] = events

        for event in events:
            t = event.type
            if t == SlackVulnerabilityEventType.VULN_ADDED:
                scan_result_by_channel[event.channel_id].new_vulnerabilities += 1
                scan_result_by_channel[event.channel_id].unrated_vulnerabilities += 1
                scan_result_by_channel[event.channel_id].total_vulnerabilities += 1
            elif t == SlackVulnerabilityEventType.VULN_REMOVED:
                scan_result_by_channel[event.channel_id].fixed_vulnerabilities += 1
            elif t == SlackVulnerabilityEventType.VULN_CHANGED:
                scan_result_by_channel[event.channel_id].changed_vulnerabilities += 1
                scan_result_by_channel[event.channel_id].total_vulnerabilities += 1
            elif t == SlackVulnerabilityEventType.VULN_UNCHANGED:
                scan_result_by_channel[event.channel_id].total_vulnerabilities += 1
            elif t == SlackVulnerabilityEventType.DEP_ADDED:
                if event.finding_id not in scan_result_by_channel[event.channel_id].added_dependencies:
                    scan_result_by_channel[event.channel_id].added_dependencies[event.finding_id] = set()
                scan_result_by_channel[event.channel_id].added_dependencies[event.finding_id].update(
                    event.added_projects
                )
            elif t == SlackVulnerabilityEventType.DEP_REMOVED:
                if event.finding_id not in scan_result_by_channel[event.channel_id].removed_dependencies:
                    scan_result_by_channel[event.channel_id].removed_dependencies[event.finding_id] = set()
                scan_result_by_channel[event.channel_id].removed_dependencies[event.finding_id].update(
                    event.removed_projects
                )
            else:
                raise RuntimeError(f"unknown event type: {t}")
