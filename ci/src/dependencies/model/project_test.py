import pytest
from model.dependency import Dependency
from model.finding import Finding
from model.project import Project
from model.team import Team
from model.vulnerability import Vulnerability


@pytest.fixture
def mock_finding():
    return Finding(repository="repo", scanner="scanner", vulnerable_dependency=Dependency(id="depid", name="depname", version="depvers"), vulnerabilities=[Vulnerability(id="vulnid", name="vulnname", description="vulndesc")], first_level_dependencies=[], projects=[], risk_assessor=[])

def test_no_owners(mock_finding):
    project = Project(name="a", path="b")

    owners = project.get_owners_for(mock_finding)

    assert len(owners) == 0

def test_main_owner(mock_finding):
    project = Project(name="a", path="b", owner=Team.CRYPTO_TEAM)

    owners = project.get_owners_for(mock_finding)

    assert len(owners) == 1
    assert owners[0] == Team.CRYPTO_TEAM

def test_sub_owner_exact_matching(mock_finding):
    project = Project(name="a", path="b", owner_by_path={"/matching/prefix": [Team.NODE_TEAM, Team.BOUNDARY_NODE_TEAM]})
    mock_finding.projects.append("/matching/prefix")

    owners = project.get_owners_for(mock_finding)

    assert len(owners) == 2
    assert Team.NODE_TEAM in owners
    assert Team.BOUNDARY_NODE_TEAM in owners

def test_sub_owner_prefix_matching(mock_finding):
    project = Project(name="a", path="b", owner_by_path={"/matching/prefix": [Team.NODE_TEAM, Team.BOUNDARY_NODE_TEAM]})
    mock_finding.projects.append("/matching/prefix/and/some/more/paths")

    owners = project.get_owners_for(mock_finding)

    assert len(owners) == 2
    assert Team.NODE_TEAM in owners
    assert Team.BOUNDARY_NODE_TEAM in owners

def test_sub_owner_not_matching(mock_finding):
    project = Project(name="a", path="b", owner_by_path={"/no/matching/prefix": [Team.NODE_TEAM, Team.BOUNDARY_NODE_TEAM]})
    mock_finding.projects.append("/not/matching/prefix")

    owners = project.get_owners_for(mock_finding)

    assert len(owners) == 0

def test_sub_owner_not_matching_when_project_is_prefix_of_path(mock_finding):
    project = Project(name="a", path="b", owner_by_path={"/not/matching/prefix/too/long": [Team.NODE_TEAM, Team.BOUNDARY_NODE_TEAM]})
    mock_finding.projects.append("/not/matching/prefix")

    owners = project.get_owners_for(mock_finding)

    assert len(owners) == 0

def test_main_owner_and_sub_owner(mock_finding):
    project = Project(name="a", path="b", owner=Team.CRYPTO_TEAM, owner_by_path={"/matching/prefix": [Team.NODE_TEAM, Team.BOUNDARY_NODE_TEAM], "/different/prefix": [Team.GIX_TEAM]})
    mock_finding.projects.append("/not/matching/prefix")
    mock_finding.projects.append("/matching/prefix")

    owners = project.get_owners_for(mock_finding)

    assert len(owners) == 3
    assert Team.CRYPTO_TEAM in owners
    assert Team.NODE_TEAM in owners
    assert Team.CRYPTO_TEAM in owners

def test_owner_deduplication(mock_finding):
    project = Project(name="a", path="b", owner=Team.CRYPTO_TEAM, owner_by_path={"/prefix/a": [Team.TRUST_TEAM, Team.CRYPTO_TEAM], "/prefix/b": [Team.GIX_TEAM, Team.TRUST_TEAM]})
    mock_finding.projects.append("/not/matching/prefix")
    mock_finding.projects.append("/prefix/a/b")
    mock_finding.projects.append("/prefix/b/a")

    owners = project.get_owners_for(mock_finding)

    assert len(owners) == 3
    assert Team.CRYPTO_TEAM in owners
    assert Team.TRUST_TEAM in owners
    assert Team.GIX_TEAM in owners
