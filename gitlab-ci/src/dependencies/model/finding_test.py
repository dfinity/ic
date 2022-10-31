from copy import deepcopy

import pytest
from model.dependency import Dependency
from model.finding import Finding
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
