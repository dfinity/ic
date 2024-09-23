from data_source.slack_findings_failover.data import (
    SlackFinding,
    SlackProjectInfo,
    SlackVulnerabilityEvent,
    SlackVulnerabilityEventType,
)
from data_source.slack_findings_failover.vuln_info import SlackVulnerabilityInfo, VulnerabilityInfo
from model.dependency import Dependency
from model.finding import Finding
from model.vulnerability import Vulnerability


def test_from_vuln_info():
    v = Vulnerability("vid", "vname", "vdesc", 8)
    f1 = Finding("repo1", "scanner1", Dependency("did1", "dname1", "dvers1"), [v], [], ["proj11", "proj12"], [])
    f2 = Finding("repo2", "scanner2", Dependency("did2", "dname2", "dvers2"), [v], [], ["proj21"], [])
    vi = VulnerabilityInfo(v, {f1.id(): f1, f2.id(): f2})

    svi = SlackVulnerabilityInfo.from_vuln_info(vi)

    assert svi.vulnerability == v
    assert len(svi.msg_id_by_channel) == 0
    assert svi.finding_by_id[f1.id()].repository == "repo1"
    assert svi.finding_by_id[f1.id()].scanner == "scanner1"
    assert svi.finding_by_id[f1.id()].dependency_id == "did1"
    assert svi.finding_by_id[f1.id()].dependency_version == "dvers1"
    assert svi.finding_by_id[f1.id()].projects == f1.projects

    assert svi.finding_by_id[f2.id()].repository == "repo2"
    assert svi.finding_by_id[f2.id()].scanner == "scanner2"
    assert svi.finding_by_id[f2.id()].dependency_id == "did2"
    assert svi.finding_by_id[f2.id()].dependency_version == "dvers2"
    assert svi.finding_by_id[f2.id()].projects == f2.projects


def test_merge_with():
    v = Vulnerability("vid", "vname", "vdesc", 8)
    sf1 = SlackFinding("repo", "scanner", "did", "dvers", ["proj11", "proj12"])
    sf2 = SlackFinding("repo", "scanner", "did", "dvers", ["proj2"])
    sf3 = SlackFinding("repo", "scanner", "did", "dvers1", ["proj3"])
    svi = SlackVulnerabilityInfo(v, {})

    svi.merge_with({sf1.id(): sf1}, "channel1", "mid1")
    svi.merge_with({sf2.id(): sf2}, "channel2", "mid1")
    svi.merge_with({sf3.id(): sf3}, "channel3", "mid1")

    assert len(svi.msg_id_by_channel) == 3
    assert svi.msg_id_by_channel["channel1"] == "mid1"
    assert svi.msg_id_by_channel["channel2"] == "mid1"

    assert sf1.id() in svi.finding_by_id
    assert svi.finding_by_id[sf1.id()].id() == sf1.id()
    assert svi.finding_by_id[sf1.id()].projects == ["proj11", "proj12", "proj2"]

    assert sf3.id() in svi.finding_by_id
    assert svi.finding_by_id[sf3.id()] == sf3


def test_events_for_add():
    v = Vulnerability("vid", "vname", "vdesc", 8)
    sf1 = SlackFinding("repo1", "scanner", "did", "dvers", ["proj11", "proj12"])
    sf2 = SlackFinding("repo2", "scanner", "did", "dvers", ["proj2"])
    info_by_project = {
        "proj11": SlackProjectInfo("proj11", {"c1"}, {}),
        "proj12": SlackProjectInfo("proj12", {"c1"}, {}),
        "proj2": SlackProjectInfo("proj2", {"c2"}, {})
    }
    svi = SlackVulnerabilityInfo(v, {sf1.id(): sf1, sf2.id(): sf2})
    da1 = SlackVulnerabilityEvent.dep_added(v.id, "c1", sf1.id(), sf1.projects)
    da2 = SlackVulnerabilityEvent.dep_added(v.id, "c2", sf2.id(), sf2.projects)

    events = svi.get_events_for_add(info_by_project)

    assert len(events) == 4
    assert events[0].type == SlackVulnerabilityEventType.VULN_ADDED
    assert events[1].type == SlackVulnerabilityEventType.VULN_ADDED
    assert {events[0].channel_id, events[1].channel_id} == {"c1", "c2"}
    assert events[2] in [da1, da2]
    assert events[2] in [da1, da2]
    assert events[2] != events[3]


def test_events_for_remove():
    v = Vulnerability("vid", "vname", "vdesc", 8)
    sf1 = SlackFinding("repo1", "scanner", "did", "dvers1", ["proj11", "proj12"])
    sf2 = SlackFinding("repo1", "scanner", "did", "dvers2", ["proj2"])
    sf_keep = SlackFinding("repo2", "scanner", "did", "dvers", ["proj3"])
    info_by_project = {
        "proj11": SlackProjectInfo("proj11", {"c1"}, {}),
        "proj12": SlackProjectInfo("proj12", {"c1"}, {}),
        "proj2": SlackProjectInfo("proj2", {"c2"}, {}),
        "proj3": SlackProjectInfo("proj3", {"c2"}, {})
    }
    svi = SlackVulnerabilityInfo(v, {sf1.id(): sf1, sf2.id(): sf2, sf_keep.id(): sf_keep}, {"c1": "msgid1", "c2": "msgid2"})
    dr1 = SlackVulnerabilityEvent.dep_removed(v.id, "c1", sf1.id(), sf1.projects)
    dr2 = SlackVulnerabilityEvent.dep_removed(v.id, "c2", sf2.id(), sf2.projects)

    events = svi.get_events_for_remove(info_by_project, "repo1", "scanner")

    assert len(events) == 3
    assert events[0] == SlackVulnerabilityEvent.vuln_removed(v.id, "c1")
    assert events[1] in [dr1, dr2]
    assert events[1] in [dr1, dr2]
    assert events[1] != events[2]


def test_update_with():
    v = Vulnerability("vid", "vname", "vdesc", 8)
    sf1 = SlackFinding("repo", "scanner", "did", "dvers", ["proj1", "proj2"])

    v_changed = Vulnerability("vid", "vname", "vdesc_changed", 9)
    f1 = Finding("repo", "scanner", Dependency("did", "dname", "dvers"), [v_changed], [], ["proj1", "proj3"], [])
    f_new = Finding("repo", "scanner", Dependency("did_new", "dname", "dvers_new"), [v_changed], [], ["proj1"], [])

    sf_fixed = SlackFinding("repo", "scanner", "did_fixed", "dvers", ["proj2"])

    info_by_project = {
        "proj1": SlackProjectInfo("proj1", {"c1"}, {}),
        "proj2": SlackProjectInfo("proj2", {"c2"}, {}),
        "proj3": SlackProjectInfo("proj3", {"c3"}, {})
    }

    svi = SlackVulnerabilityInfo(v, {sf1.id(): sf1, sf_fixed.id(): sf_fixed}, {"c1": "msgid1", "c2": "msgid2"})
    vi = VulnerabilityInfo(v_changed, {f1.id(): f1, f_new.id(): f_new})

    da1 = SlackVulnerabilityEvent.dep_added("vid", "c1", f_new.id(), ["proj1"])
    da2 = SlackVulnerabilityEvent.dep_added("vid", "c3", f1.id(), ["proj3"])
    dr1 = SlackVulnerabilityEvent.dep_removed("vid", "c2", sf1.id(), ["proj2"])
    dr2 = SlackVulnerabilityEvent.dep_removed("vid", "c2", sf_fixed.id(), ["proj2"])

    events = svi.update_with(vi, info_by_project, "repo", "scanner")

    assert len(events) == 7
    assert events[0] == SlackVulnerabilityEvent.vuln_added("vid", "c3")
    assert events[1] == SlackVulnerabilityEvent.vuln_removed("vid", "c2")
    assert events[2] == SlackVulnerabilityEvent.vuln_changed("vid", "c1", {"Description": "vdesc", "Score": "8"})
    assert events[3] in [da1, da2, dr1]
    assert events[4] in [da1, da2, dr1]
    assert events[5] in [da1, da2, dr1]
    assert events[3] != events[4] and events[4] != events[5] and events[3] != events[5]
    assert events[6] == dr2
