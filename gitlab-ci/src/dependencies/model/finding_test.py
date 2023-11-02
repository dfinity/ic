from copy import deepcopy

import pytest
from model.dependency import Dependency
from model.finding import Finding
from model.security_risk import SecurityRisk
from model.vulnerability import Vulnerability


def test_id():
    finding = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_version"),
        [Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
        [],
        [],
        [],
        None,
        [],
        [],
        None,
    )

    key = finding.id()

    assert len(key) == 4
    assert key[0] == "repo"
    assert key[1] == "scanner"
    assert key[2] == "dep_id"
    assert key[3] == "dep_version"


def test_has_patch_version_return_true_if_vuln_dep_has_patch_and_if_other_none():
    finding = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_version", {"vuln_id": ["patch_version"]}),
        [Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
        [],
        [],
        [],
        None,
        [],
        [],
        None,
    )

    assert finding.has_patch_version()


def test_has_patch_version_return_false_if_vuln_dep_has_no_patch_and_if_other_none():
    finding = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_version"),
        [Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
        [Dependency("1st_lvl_dep_id", "1st_lvl_dep_name", "1st_lvl_dep_version")],
        [],
        [],
        None,
        [],
        [],
        None,
    )

    assert not finding.has_patch_version()


@pytest.mark.parametrize("patch_on_first_level_dep", [True, False])
def test_has_patch_version_return_true_if_patch_was_added(patch_on_first_level_dep):
    finding_before = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_version"),
        [Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
        [Dependency("1st_lvl_dep_id", "1st_lvl_dep_name", "1st_lvl_dep_version")],
        [],
        [],
        None,
        [],
        [],
        None,
    )
    finding_after = deepcopy(finding_before)
    dep = finding_after.first_level_dependencies[0] if patch_on_first_level_dep else finding_after.vulnerable_dependency
    dep.fix_version_for_vulnerability["vuln_id"] = ["patch"]

    assert finding_after.has_patch_version(finding_before)


@pytest.mark.parametrize("patch_on_first_level_dep", [True, False])
def test_has_patch_version_return_true_if_second_patch_was_added(patch_on_first_level_dep):
    finding_before = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_version", {"vuln_id": ["patch_version"]}),
        [Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
        [Dependency("1st_lvl_dep_id", "1st_lvl_dep_name", "1st_lvl_dep_version", {"vuln_id": ["patch_version"]})],
        [],
        [],
        None,
        [],
        [],
        None,
    )
    finding_after = deepcopy(finding_before)
    dep = finding_after.first_level_dependencies[0] if patch_on_first_level_dep else finding_after.vulnerable_dependency
    dep.fix_version_for_vulnerability["vuln_id"].append("another_patch")

    assert finding_after.has_patch_version(finding_before)


@pytest.mark.parametrize("patch_on_first_level_dep", [True, False])
def test_has_patch_version_return_true_if_patch_for_other_vuln_was_added(patch_on_first_level_dep):
    finding_before = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_version", {"vuln_id1": ["patch_version"]}),
        [Vulnerability("vuln_id1", "vuln_name", "vuln_desc"), Vulnerability("vuln_id2", "vuln_name", "vuln_desc")],
        [Dependency("1st_lvl_dep_id", "1st_lvl_dep_name", "1st_lvl_dep_version", {"vuln_id1": ["patch_version"]})],
        [],
        [],
        None,
        [],
        [],
        None,
    )
    finding_after = deepcopy(finding_before)
    dep = finding_after.first_level_dependencies[0] if patch_on_first_level_dep else finding_after.vulnerable_dependency
    dep.fix_version_for_vulnerability["vuln_id2"] = ["patch_for_vuln_id2"]

    assert finding_after.has_patch_version(finding_before)


def test_has_patch_version_return_false_if_patch_version_are_same():
    finding_before = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_version", {"vuln_id": ["patch_version"]}),
        [Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
        [
            Dependency(
                "1st_lvl_dep_id", "1st_lvl_dep_name", "1st_lvl_dep_version", {"vuln_id": ["1st_lvl_patch_version"]}
            )
        ],
        [],
        [],
        None,
        [],
        [],
        None,
    )
    finding_after = deepcopy(finding_before)

    assert not finding_after.has_patch_version(finding_before)


@pytest.mark.parametrize("change_field", ["repository", "scanner", "dep_id", "dep_version"])
def test_has_patch_version_raise_error_if_findings_have_different_ids(change_field):
    finding1 = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_version", {"vuln_id": ["patch_version"]}),
        [Vulnerability("vuln_id", "vuln_name", "vuln_desc")],
        [],
        [],
        [],
        None,
        [],
        [],
        None,
    )
    finding2 = deepcopy(finding1)
    if change_field == "repository":
        finding2.repository += "a"
    elif change_field == "scanner":
        finding2.scanner += "a"
    elif change_field == "dep_id":
        finding2.vulnerable_dependency.id += "a"
    else:
        finding2.vulnerable_dependency.version += "a"

    with pytest.raises(RuntimeError, match=r"ids"):
        finding1.has_patch_version(finding2)


def test_update_risk_and_vulnerabilities_for_same_finding_keep_risk_if_no_new_vul():
    finding1 = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_version"),
        [Vulnerability("v1", "vn1", "vd1"), Vulnerability("v2", "vn2", "vd2")],
        [],
        [],
        [],
        SecurityRisk.MEDIUM,
        [],
        [],
        None,
    )
    finding2 = deepcopy(finding1)
    finding1.vulnerabilities[1].risk_note = "this risk note should be copied"
    # first vul has disappeared
    finding2.vulnerabilities = finding2.vulnerabilities[1:]

    finding1.update_risk_and_vulnerabilities_for_same_finding(finding2)

    assert finding1.risk == SecurityRisk.MEDIUM
    assert len(finding1.vulnerabilities) == 1
    assert finding1.vulnerabilities[0].id == "v2"
    assert finding1.vulnerabilities[0].name == "vn2"
    assert finding1.vulnerabilities[0].description == "vd2"
    assert finding1.vulnerabilities[0].risk_note == "this risk note should be copied"


def test_update_risk_and_vulnerabilities_for_same_finding_reset_risk_if_new_vul_appears():
    finding1 = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_version"),
        [Vulnerability("v1", "vn1", "vd1")],
        [],
        [],
        [],
        SecurityRisk.MEDIUM,
        [],
        [],
        None,
    )
    finding2 = deepcopy(finding1)
    finding1.vulnerabilities[0].risk_note = "this risk note should be copied"
    # new vul is found during scan
    finding2.vulnerabilities.append(Vulnerability("v2", "vn2", "vd2"))

    finding1.update_risk_and_vulnerabilities_for_same_finding(finding2)

    assert finding1.risk is None
    assert len(finding1.vulnerabilities) == 2
    assert finding1.vulnerabilities[0].id == "v1"
    assert finding1.vulnerabilities[0].name == "vn1"
    assert finding1.vulnerabilities[0].description == "vd1"
    assert finding1.vulnerabilities[0].risk_note == "this risk note should be copied"
    assert finding1.vulnerabilities[1].id == "v2"
    assert finding1.vulnerabilities[1].name == "vn2"
    assert finding1.vulnerabilities[1].description == "vd2"
    assert finding1.vulnerabilities[1].risk_note == " "


def test_update_risk_and_vulnerabilities_for_related_findings_set_risk_from_vul():
    related_finding1 = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_version1"),
        [Vulnerability("v1", "vn1", "vd1", -1, "low"), Vulnerability("v2", "vn2", "vd2", -1, "medium"),
         Vulnerability("v3", "vn3", "vd3", -1, "critical")],
        [],
        [],
        [],
        None,
        [],
        [],
        None,
    )
    related_finding2 = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_version2"),
        [Vulnerability("v4", "vn4", "vd4", -1, "high")],
        [],
        [],
        [],
        None,
        [],
        [],
        None,
    )
    finding = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_version3"),
        [Vulnerability("v1", "vn1", "vd1"), Vulnerability("v2", "vn2", "vd2"), Vulnerability("v4", "vn4", "vd4")],
        [],
        [],
        [],
        None,
        [],
        [],
        None,
    )

    finding.update_risk_and_vulnerabilities_for_related_findings([related_finding1, related_finding2])

    assert finding.risk == SecurityRisk.HIGH
    assert len(finding.vulnerabilities) == 3
    assert finding.vulnerabilities[0].risk_note == "low"
    assert finding.vulnerabilities[1].risk_note == "medium"
    assert finding.vulnerabilities[2].risk_note == "high"


def test_update_risk_and_vulnerabilities_for_related_findings_set_risk_from_finding():
    related_finding1 = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_version1"),
        [Vulnerability("v1", "vn1", "vd1"), Vulnerability("v2", "vn2", "vd2")],
        [],
        [],
        [],
        SecurityRisk.LOW,
        [],
        [],
        None,
    )
    finding = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_version2"),
        [Vulnerability("v1", "vn1", "vd1")],
        [],
        [],
        [],
        None,
        [],
        [],
        None,
    )

    finding.update_risk_and_vulnerabilities_for_related_findings([related_finding1])

    assert finding.risk == SecurityRisk.LOW
    assert len(finding.vulnerabilities) == 1
    assert finding.vulnerabilities[0].risk_note == " "



def test_update_risk_and_vulnerabilities_for_related_findings_reset_risk_if_new_vul_appears():
    related_finding1 = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_version1"),
        [Vulnerability("v1", "vn1", "vd1", -1, "might be a lowball")],
        [],
        [],
        [],
        SecurityRisk.LOW,
        [],
        [],
        None,
    )
    finding = Finding(
        "repo",
        "scanner",
        Dependency("dep_id", "dep_name", "dep_version2"),
        [Vulnerability("v1", "vn1", "vd1"), Vulnerability("v2", "vn2", "vd2")],
        [],
        [],
        [],
        None,
        [],
        [],
        None,
    )

    finding.update_risk_and_vulnerabilities_for_related_findings([related_finding1])

    assert finding.risk is None
    assert len(finding.vulnerabilities) == 2
    assert finding.vulnerabilities[0].risk_note == "might be a lowball"
