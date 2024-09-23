import datetime
import typing
from unittest.mock import Mock, patch

import pytest
from model.dependency import Dependency
from model.finding import Finding
from model.ic import __test_get_ic_path
from model.project import Project
from model.repository import Repository
from model.security_risk import SecurityRisk
from model.team import Team
from model.user import User
from model.vulnerability import Vulnerability
from scanner.dependency_scanner import DependencyScanner
from scanner.manager.bazel_rust_dependency_manager import BazelRustDependencyManager


@pytest.fixture
def jira_lib_mock():
    return Mock()

class FakeBazel(BazelRustDependencyManager):
    def __init__(self, fake_type: int):
        super().__init__()
        self.fake_type = fake_type

    def get_findings(
        self, repository_name: str, project: typing.Optional[Project], engine_version: typing.Optional[int]
    ) -> typing.List[Finding]:
        if self.fake_type == 1:
            return []

        if self.fake_type == 2:
            return [
                Finding(
                    repository=repository_name,
                    scanner=self.get_scanner_id(),
                    vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
                    vulnerabilities=[
                        Vulnerability("VID1", "CVE-123", "huuughe vuln", 100),
                        Vulnerability("VID2", "CVE-456", "other vuln", 50),
                    ],
                    first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
                    projects=["foo", "bar", "bear"],
                    risk_assessor=[],
                    score=100,
                )
            ]

        if self.fake_type == 3:
            return [
                Finding(
                    repository=repository_name,
                    scanner=self.get_scanner_id(),
                    vulnerable_dependency=Dependency(
                        "VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"], "VID2": ["1.1", "2.0"]}
                    ),
                    vulnerabilities=[
                        Vulnerability("VID1", "CVE-123", "huuughe vuln", 100),
                        Vulnerability("VID2", "CVE-456", "CRITICAL VULN o.O", 120),
                    ],
                    first_level_dependencies=[
                        Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]}),
                        Dependency("VDID3", "fal dep", "0.2 beta", {"VID1": ["3.0 alpha"]}),
                    ],
                    projects=["foo", "bar", "bear", "new foo", "new bear"],
                    risk_assessor=[],
                    score=120,
                )
            ]


def test_on_periodic_job_no_findings(jira_lib_mock):
    # No findings
    jira_lib_mock.get_open_findings_for_repo_and_scanner.return_value = {}
    sub1 = Mock()
    sub2 = Mock()
    scanner_job = DependencyScanner(FakeBazel(1), jira_lib_mock, [sub1, sub2])
    repos = [Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())])]

    scanner_job.do_periodic_scan(repos)

    jira_lib_mock.get_open_findings_for_repo_and_scanner.assert_called_once()
    jira_lib_mock.get_open_finding.assert_not_called()
    jira_lib_mock.create_or_update_open_finding.assert_not_called()
    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


def test_on_periodic_job_delete_finding(jira_lib_mock):
    # no findings, 1 present in JIRA
    repos = [Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())])]
    jira_finding = Finding(
        repository=repos[0].name,
        scanner="BAZEL_RUST",
        vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
        vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
        first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
        projects=["foo", "bar", "bear"],
        risk_assessor=[User("mickey", "Mickey Mouse")],
        risk=SecurityRisk.INFORMATIONAL,
        patch_responsible=[],
        due_date=100,
        score=100,
    )
    jira_lib_mock.get_open_findings_for_repo_and_scanner.return_value = {jira_finding.id(): jira_finding}
    scanner_job = DependencyScanner(FakeBazel(1), jira_lib_mock, [])

    scanner_job.do_periodic_scan(repos)

    jira_lib_mock.get_open_findings_for_repo_and_scanner.assert_called_once()
    jira_lib_mock.delete_finding.assert_called_once()
    jira_lib_mock.get_open_finding.assert_not_called()
    jira_lib_mock.create_or_update_open_finding.assert_not_called()


def test_on_periodic_job_one_finding(jira_lib_mock):
    # one finding, not present in JIRA
    jira_lib_mock.get_open_findings_for_repo_and_scanner.return_value = {}
    jira_lib_mock.get_risk_assessor.return_value = [User("mickey", "Mickey Mouse")]
    jira_lib_mock.get_deleted_findings.return_value = []

    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = FakeBazel(2)
    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])

    repository = Repository("ic", "https://github.com/dfinity/ic", [Project(name="ic", path=__test_get_ic_path(), owner=Team.EXECUTION_TEAM)])
    finding = fake_bazel.get_findings(repository.name, repository.projects[0], repository.engine_version)[0]
    finding.risk_assessor = [User("mickey", "Mickey Mouse")]
    finding.owning_teams = [Team.EXECUTION_TEAM]

    scanner_job.do_periodic_scan([repository])

    jira_lib_mock.get_open_findings_for_repo_and_scanner.assert_called_once()
    jira_lib_mock.get_open_finding.assert_not_called()
    jira_lib_mock.get_risk_assessor.assert_called_once()
    jira_lib_mock.get_deleted_findings.assert_called_once()

    jira_lib_mock.create_or_update_open_finding.assert_called_once()
    jira_lib_mock.create_or_update_open_finding.assert_called_once_with(finding)

    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


def test_on_periodic_job_one_finding_in_jira(jira_lib_mock):
    # one finding, present in JIRA
    scanner = "BAZEL_RUST"
    repository = Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())])
    jira_finding = Finding(
        repository=repository.name,
        scanner=scanner,
        vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
        vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
        first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
        projects=["foo", "bar", "bear"],
        risk_assessor=[User("mickey", "Mickey Mouse")],
        risk=SecurityRisk.INFORMATIONAL,
        owning_teams=[Team.GIX_TEAM],
        patch_responsible=[],
        due_date=100,
        score=100,
    )
    jira_lib_mock.get_open_findings_for_repo_and_scanner.return_value = {jira_finding.id(): jira_finding}

    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = FakeBazel(2)
    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])
    repos = [Repository("ic", "https://github.com/dfinity/ic", [Project(name="ic", path=__test_get_ic_path(), owner_by_path={'bear': [Team.NODE_TEAM]})])]

    scanner_job.do_periodic_scan(repos)

    finding = fake_bazel.get_findings(repos[0].name, repos[0].projects[0], repository.engine_version)[0]
    assert jira_finding.vulnerable_dependency == finding.vulnerable_dependency
    assert jira_finding.vulnerabilities == finding.vulnerabilities
    assert jira_finding.first_level_dependencies == finding.first_level_dependencies
    assert jira_finding.projects == finding.projects
    assert jira_finding.risk is None
    assert jira_finding.owning_teams == [Team.NODE_TEAM, Team.GIX_TEAM]
    assert jira_finding.score == finding.score

    jira_lib_mock.get_open_findings_for_repo_and_scanner.assert_called_once()
    jira_lib_mock.get_open_finding.assert_not_called()
    jira_lib_mock.get_risk_assessor.assert_not_called()
    jira_lib_mock.delete_finding.assert_not_called()

    jira_lib_mock.create_or_update_open_finding.assert_called_once()
    jira_lib_mock.create_or_update_open_finding.assert_called_once_with(jira_finding)

    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


def test_on_periodic_job_one_finding_in_jira_transition_to_failover(jira_lib_mock):
    # one finding, present in JIRA
    scanner = "BAZEL_RUST"
    repository = Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())])
    jira_finding = Finding(
        repository=repository.name,
        scanner=scanner,
        vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
        vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
        first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
        projects=["foo", "bar", "bear"],
        risk_assessor=[User("mickey", "Mickey Mouse")],
        risk=SecurityRisk.INFORMATIONAL,
        owning_teams=[Team.GIX_TEAM],
        patch_responsible=[],
        due_date=100,
        score=100,
    )
    jira_lib_mock.get_open_findings_for_repo_and_scanner.return_value = {jira_finding.id(): jira_finding}

    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = FakeBazel(2)
    failover_mock = Mock()
    failover_mock.can_handle.return_value = True

    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2], failover_mock)
    repos = [Repository("ic", "https://github.com/dfinity/ic", [Project(name="ic", path="ic", owner_by_path={'bear': [Team.NODE_TEAM]})])]

    scanner_job.do_periodic_scan(repos)

    expected_finding = fake_bazel.get_findings(repos[0].name, repos[0].projects[0], repository.engine_version)[0]
    expected_finding.owning_teams = [Team.NODE_TEAM]
    jira_lib_mock.get_open_findings_for_repo_and_scanner.assert_called_once()
    jira_lib_mock.get_open_finding.assert_not_called()
    jira_lib_mock.get_risk_assessor.assert_not_called()
    # finding in jira should be deleted
    jira_lib_mock.delete_finding.assert_called_once()

    jira_lib_mock.create_or_update_open_finding.assert_not_called()
    jira_lib_mock.create_or_update_open_finding.assert_not_called()

    # finding should be passed to failover store
    failover_mock.store_findings.assert_called_once_with(repository.name, scanner, [expected_finding])

    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


def test_on_periodic_job_one_finding_in_jira_clear_risk_and_keep_risk_note(jira_lib_mock):
    # one finding, present in JIRA
    repository = Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())])
    fake_bazel = FakeBazel(2)
    jira_finding = fake_bazel.get_findings(repository.name, repository.projects[0], repository.engine_version)[0]
    jira_finding.risk = SecurityRisk.HIGH
    assert len(jira_finding.vulnerabilities) > 1
    # drop vulnerability
    jira_finding.vulnerabilities = jira_finding.vulnerabilities[:1]
    # add risk note
    jira_finding.vulnerabilities[0].risk_note = "please keep me"
    jira_lib_mock.get_open_findings_for_repo_and_scanner.return_value = {jira_finding.id(): jira_finding}

    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [])

    scanner_job.do_periodic_scan([repository])

    assert jira_finding.risk is None
    assert jira_finding.vulnerabilities[0].risk_note == "please keep me"


def test_on_periodic_job_one_finding_in_jira_leave_risk(jira_lib_mock):
    # one finding, present in JIRA
    repository = Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())])
    fake_bazel = FakeBazel(2)
    jira_finding = fake_bazel.get_findings(repository.name, repository.projects[0], repository.engine_version)[0]
    jira_finding.risk = SecurityRisk.HIGH
    # vulnerability disappeared
    jira_finding.vulnerabilities.append(Vulnerability("other", "other vuln", "some desc", 12))
    jira_lib_mock.get_open_findings_for_repo_and_scanner.return_value = {jira_finding.id(): jira_finding}

    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [])

    scanner_job.do_periodic_scan([repository])

    assert jira_finding.risk == SecurityRisk.HIGH


def test_on_periodic_job_set_risk_for_related_finding(jira_lib_mock):
    # one finding, present in JIRA
    repository = Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())])
    fake_bazel = FakeBazel(2)
    jira_finding = fake_bazel.get_findings(repository.name, repository.projects[0], repository.engine_version)[0]
    # different version means the finding is related
    original_version = jira_finding.vulnerable_dependency.version
    jira_finding.vulnerable_dependency.version = "another version for open finding"
    assert original_version != jira_finding.vulnerable_dependency.version
    for vulnerability in jira_finding.vulnerabilities:
        vulnerability.risk_note = "medium"
    jira_lib_mock.get_open_findings_for_repo_and_scanner.return_value = {jira_finding.id(): jira_finding}
    # add another related finding that was already deleted
    jira_finding = fake_bazel.get_findings(repository.name, repository.projects[0], repository.engine_version)[0]
    jira_finding.vulnerable_dependency.version = "another version for deleted finding"
    assert original_version != jira_finding.vulnerable_dependency.version
    for vulnerability in jira_finding.vulnerabilities:
        vulnerability.risk_note = "medium"
    jira_lib_mock.get_deleted_findings.return_value = [jira_finding]

    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [])

    scanner_job.do_periodic_scan([repository])

    jira_finding.vulnerable_dependency.version = original_version
    jira_finding.risk = SecurityRisk.MEDIUM
    jira_finding.risk_assessor = jira_lib_mock.get_risk_assessor()
    jira_lib_mock.create_or_update_open_finding.assert_called_once_with(jira_finding)


def test_on_periodic_job_failure(jira_lib_mock):
    sub1 = Mock()
    sub2 = Mock()

    fake_bazel = Mock()
    fake_bazel.get_findings.side_effect = OSError("Call failed")

    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])
    repos = [Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())])]

    scanner_job.do_periodic_scan(repos)
    sub1.on_scan_job_succeeded.assert_not_called()
    sub2.on_scan_job_succeeded.assert_not_called()
    sub1.on_scan_job_failed.assert_called_once()
    sub2.on_scan_job_failed.assert_called_once()


@patch("scanner.dependency_scanner.DependencyScanner._DependencyScanner__clone_repository_from_url")
@patch("shutil.rmtree")
def test_get_findings_ic_dir(shutil, clone_repo, jira_lib_mock):
    project = Project("ic", __test_get_ic_path())
    repo = Repository("ic", "https://github.com/dfinity/ic", [project])
    fake_bazel = Mock()
    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [])

    scanner_job.do_periodic_scan([repo])

    shutil.assert_not_called()
    clone_repo.assert_not_called()
    fake_bazel.get_findings.assert_called_once_with("ic", project, repo.engine_version)


@patch("scanner.dependency_scanner.DependencyScanner._DependencyScanner__clone_repository_from_url")
@patch("shutil.rmtree")
def test_get_findings_external_dir(shutil, clone_repo, jira_lib_mock):
    with patch("pathlib.Path.is_dir", return_value=True):
        project = Project("cycles-wallet", "cycles-wallet")
        repo = Repository("cycles-wallet", "https://github.com/dfinity/cycles-wallet", [project])
        fake_bazel = Mock()
        scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [])

        scanner_job.do_periodic_scan([repo])

        shutil.assert_called_once()
        clone_repo.assert_called_once_with("https://github.com/dfinity/cycles-wallet", scanner_job.root.parent)
        fake_bazel.get_findings.assert_called_once_with("cycles-wallet", project, repo.engine_version)


def test_on_merge_request_no_changes_to_dependency_files(jira_lib_mock):
    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = Mock()
    fake_bazel.has_dependencies_changed.return_value = {"external_crates_bzl": False, "cargo_lock_toml": False}
    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])

    scanner_job.do_merge_request_scan("ic")
    fake_bazel.get_modified_packages.assert_not_called()
    fake_bazel.get_dependency_diff.assert_not_called()
    fake_bazel.get_findings.assert_not_called()
    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


def test_on_merge_request_changes_to_dependency_files_but_not_external_crates(jira_lib_mock):
    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = Mock()
    fake_bazel.has_dependencies_changed.return_value = {"external_crates_bzl": False, "cargo_lock_toml": True}
    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])

    scanner_job.do_merge_request_scan("ic")
    fake_bazel.get_modified_packages.assert_called_once()
    fake_bazel.get_dependency_diff.assert_called_once()
    fake_bazel.get_findings.assert_not_called()
    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


def test_on_merge_request_changes_no_findings(jira_lib_mock):
    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = Mock()
    fake_bazel.has_dependencies_changed.return_value = {"external_crates_bzl": True, "cargo_lock_toml": True}
    fake_bazel.get_modified_packages.return_value = ["package1", "package2"]
    fake_bazel.get_findings.return_value = []
    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])

    scanner_job.do_merge_request_scan(Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())]))
    fake_bazel.get_modified_packages.assert_called_once()
    fake_bazel.get_dependency_diff.assert_called_once()
    fake_bazel.get_findings.assert_called_once()
    jira_lib_mock.get_open_finding.assert_not_called()
    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


def test_on_merge_request_changes_all_findings_have_jira_findings(jira_lib_mock):
    scanner = "BAZEL_RUST"
    repository = "ic"
    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = Mock()
    fake_bazel.has_dependencies_changed.return_value = {"external_crates_bzl": True, "cargo_lock_toml": True}
    fake_bazel.get_modified_packages.return_value = ["package1", "package2"]
    fake_bazel.get_findings.return_value = [
        Finding(
            repository=repository,
            scanner=scanner,
            vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
            vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
            first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
            projects=["foo", "bar", "bear"],
            risk_assessor=[],
            score=100,
        )
    ]

    jira_finding = Finding(
        repository=repository,
        scanner=scanner,
        vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
        vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
        first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
        projects=["foo", "bar", "bear"],
        risk_assessor=[User("mickey", "Mickey Mouse")],
        risk=SecurityRisk.INFORMATIONAL,
        patch_responsible=[],
        due_date=100,
        score=100,
    )
    jira_lib_mock.get_open_finding.return_value = jira_finding

    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])

    scanner_job.do_merge_request_scan(Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())]))
    fake_bazel.get_modified_packages.assert_called_once()
    fake_bazel.get_dependency_diff.assert_called_once()
    fake_bazel.get_findings.assert_called_once()
    jira_lib_mock.get_open_finding.assert_called_once()
    jira_lib_mock.commit_has_block_exception.assert_not_called()
    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


@patch("integration.github.github_api.GithubApi.comment_on_github")
def test_on_merge_request_changes_with_findings_to_flag_and_commit_exception(github_comment_mock, jira_lib_mock):
    scanner = "BAZEL_RUST"
    repository = "ic"
    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = Mock()
    fake_bazel.has_dependencies_changed.return_value = {"external_crates_bzl": True, "cargo_lock_toml": True}

    fake_bazel.get_modified_packages.return_value = ["package1", "package2"]
    fake_bazel.get_findings.return_value = [
        Finding(
            repository=repository,
            scanner=scanner,
            vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
            vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
            first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
            projects=["foo", "bar", "bear"],
            risk_assessor=[],
            score=100,
        )
    ]
    jira_lib_mock.get_open_finding.return_value = []
    jira_lib_mock.commit_has_block_exception.return_value = "commit string"
    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])

    scanner_job.do_merge_request_scan(Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())]))
    fake_bazel.get_modified_packages.assert_called_once()
    fake_bazel.get_dependency_diff.assert_called_once()
    fake_bazel.get_findings.assert_called_once()
    jira_lib_mock.get_open_finding.assert_called_once()
    jira_lib_mock.commit_has_block_exception.assert_called_once()
    github_comment_mock.assert_not_called()
    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


@patch("integration.github.github_api.GithubApi.comment_on_github")
def test_on_merge_request_changes_with_findings_to_flag_no_commit_exception(github_comment_mock, jira_lib_mock):
    scanner = "BAZEL_RUST"
    repository = "ic"
    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = Mock()
    fake_bazel.has_dependencies_changed.return_value = {"external_crates_bzl": True, "cargo_lock_toml": True}

    fake_bazel.get_modified_packages.return_value = ["foo"]
    fake_bazel.get_dependency_diff.return_value = [Dependency("VDID3", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})]
    fake_bazel.get_findings.return_value = [
        Finding(
            repository=repository,
            scanner=scanner,
            vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
            vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
            first_level_dependencies=[
                Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]}),
                Dependency("VDID3", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]}),
            ],
            projects=["foo", "bar", "bear"],
            risk_assessor=[],
            score=100,
        )
    ]
    jira_lib_mock.get_open_finding.return_value = []
    jira_lib_mock.commit_has_block_exception.return_value = None
    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])

    with pytest.raises(SystemExit) as e:
        scanner_job.do_merge_request_scan(Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())]))
    assert e.type == SystemExit
    assert e.value.code == 1

    fake_bazel.get_modified_packages.assert_called_once()
    fake_bazel.get_dependency_diff.assert_called_once()
    fake_bazel.get_findings.assert_called_once()
    jira_lib_mock.get_open_finding.assert_called_once()
    jira_lib_mock.commit_has_block_exception.assert_called_once()
    finding_to_flag = [
        Finding(
            repository=repository,
            scanner=scanner,
            vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
            vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
            first_level_dependencies=[Dependency("VDID3", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
            projects=["foo"],
            risk_assessor=[],
            score=100,
        )
    ]
    github_comment_mock.assert_called_once_with(info=finding_to_flag)
    sub1.on_merge_request_blocked.assert_called_once()
    sub2.on_merge_request_blocked.assert_called_once()
    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


def test_on_merge_request_job_failed(jira_lib_mock):
    sub1 = Mock()
    sub2 = Mock()

    fake_bazel = Mock()
    fake_bazel.has_dependencies_changed.side_effect = OSError("Call failed")

    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])
    scanner_job.do_merge_request_scan(Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())]))
    sub1.on_scan_job_failed.assert_called_once()
    sub2.on_scan_job_failed.assert_called_once()
    sub1.on_scan_job_succeeded.assert_not_called()
    sub2.on_scan_job_succeeded.assert_not_called()


def test_on_release_scan_no_findings(jira_lib_mock):
    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = Mock()
    fake_bazel.get_findings.return_value = []
    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])

    scanner_job.do_release_scan(Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())]))
    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


def test_on_release_scan_findings_have_jira_findings_with_no_risk(jira_lib_mock):
    scanner = "BAZEL_RUST"
    repository = "ic"

    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = Mock()

    fake_bazel.get_findings.return_value = [
        Finding(
            repository=repository,
            scanner=scanner,
            vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
            vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
            first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
            projects=["foo", "bar", "bear"],
            risk_assessor=[],
            score=100,
        )
    ]

    jira_finding = Finding(
        repository=repository,
        scanner=scanner,
        vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
        vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
        first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
        projects=["foo", "bar", "bear"],
        risk_assessor=[User("mickey", "Mickey Mouse")],
        risk=None,
        patch_responsible=[],
        due_date=100,
        score=100,
    )
    jira_lib_mock.get_open_finding.return_value = jira_finding
    jira_lib_mock.commit_has_block_exception.return_value = None

    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])

    with pytest.raises(SystemExit) as e:
        scanner_job.do_release_scan(Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())]))

    assert e.type == SystemExit
    assert e.value.code == 1
    fake_bazel.get_findings.assert_called_once()
    jira_lib_mock.get_open_finding.assert_called_once()
    jira_lib_mock.commit_has_block_exception.assert_called_once()
    sub1.on_release_build_blocked.assert_called_once()
    sub2.on_release_build_blocked.assert_called_once()
    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


def test_on_release_scan_findings_have_jira_findings_with_no_risk_with_exception(jira_lib_mock):
    scanner = "BAZEL_RUST"
    repository = "ic"

    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = Mock()

    fake_bazel.get_findings.return_value = [
        Finding(
            repository=repository,
            scanner=scanner,
            vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
            vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
            first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
            projects=["foo", "bar", "bear"],
            risk_assessor=[],
            score=100,
        )
    ]

    jira_finding = Finding(
        repository=repository,
        scanner=scanner,
        vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
        vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
        first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
        projects=["foo", "bar", "bear"],
        risk_assessor=[User("mickey", "Mickey Mouse")],
        risk=None,
        patch_responsible=[],
        due_date=100,
        score=100,
    )
    jira_lib_mock.get_open_finding.return_value = jira_finding
    jira_lib_mock.commit_has_block_exception.return_value = "test commit"

    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])

    scanner_job.do_release_scan(Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())]))
    fake_bazel.get_findings.assert_called_once()
    jira_lib_mock.get_open_finding.assert_called_once()
    jira_lib_mock.commit_has_block_exception.assert_called_once()
    sub1.on_release_build_blocked.assert_not_called()
    sub2.on_release_build_blocked.assert_not_called()
    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


def test_on_release_scan_findings_have_jira_findings_with_high_risk_but_no_due_date(jira_lib_mock):
    scanner = "BAZEL_RUST"
    repository = "ic"

    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = Mock()

    fake_bazel.get_findings.return_value = [
        Finding(
            repository=repository,
            scanner=scanner,
            vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
            vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
            first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
            projects=["foo", "bar", "bear"],
            risk_assessor=[],
            score=100,
        )
    ]

    jira_finding = Finding(
        repository=repository,
        scanner=scanner,
        vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
        vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
        first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
        projects=["foo", "bar", "bear"],
        risk_assessor=[User("mickey", "Mickey Mouse")],
        risk=SecurityRisk.CRITICAL,
        patch_responsible=[],
        due_date=None,
        score=100,
    )
    jira_lib_mock.get_open_finding.return_value = jira_finding
    jira_lib_mock.commit_has_block_exception.return_value = None

    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])

    with pytest.raises(SystemExit) as e:
        scanner_job.do_release_scan(Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())]))

    assert e.type == SystemExit
    assert e.value.code == 1
    fake_bazel.get_findings.assert_called_once()
    jira_lib_mock.get_open_finding.assert_called_once()
    jira_lib_mock.commit_has_block_exception.assert_called_once()
    sub1.on_release_build_blocked.assert_called_once()
    sub2.on_release_build_blocked.assert_called_once()
    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


def test_on_release_scan_findings_have_jira_findings_with_high_risk_but_valid_due_date(jira_lib_mock):
    scanner = "BAZEL_RUST"
    repository = "ic"

    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = Mock()

    fake_bazel.get_findings.return_value = [
        Finding(
            repository=repository,
            scanner=scanner,
            vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
            vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
            first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
            projects=["foo", "bar", "bear"],
            risk_assessor=[],
            score=100,
        )
    ]

    jira_finding = Finding(
        repository=repository,
        scanner=scanner,
        vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
        vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
        first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
        projects=["foo", "bar", "bear"],
        risk_assessor=[User("mickey", "Mickey Mouse")],
        risk=SecurityRisk.CRITICAL,
        patch_responsible=[],
        due_date=int(datetime.datetime.utcnow().timestamp()) + 10000,
        score=100,
    )
    jira_lib_mock.get_open_finding.return_value = jira_finding

    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])

    scanner_job.do_release_scan(Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())]))
    fake_bazel.get_findings.assert_called_once()
    jira_lib_mock.get_open_finding.assert_called_once()
    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


def test_on_release_scan_findings_have_jira_findings_with_high_risk_but_expired_due_date(jira_lib_mock):
    scanner = "BAZEL_RUST"
    repository = "ic"

    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = Mock()

    fake_bazel.get_findings.return_value = [
        Finding(
            repository=repository,
            scanner=scanner,
            vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
            vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
            first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
            projects=["foo", "bar", "bear"],
            risk_assessor=[],
            score=100,
        )
    ]

    jira_finding = Finding(
        repository=repository,
        scanner=scanner,
        vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
        vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
        first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
        projects=["foo", "bar", "bear"],
        risk_assessor=[User("mickey", "Mickey Mouse")],
        risk=SecurityRisk.CRITICAL,
        patch_responsible=[],
        due_date=100,
        score=100,
    )
    jira_lib_mock.get_open_finding.return_value = jira_finding
    jira_lib_mock.commit_has_block_exception.return_value = None

    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])

    with pytest.raises(SystemExit) as e:
        scanner_job.do_release_scan(Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())]))

    assert e.type == SystemExit
    assert e.value.code == 1
    fake_bazel.get_findings.assert_called_once()
    jira_lib_mock.get_open_finding.assert_called_once()
    jira_lib_mock.commit_has_block_exception.assert_called_once()
    sub1.on_release_build_blocked.assert_called_once()
    sub2.on_release_build_blocked.assert_called_once()
    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


def test_on_release_scan_findings_have_jira_findings_with_high_risk_but_expired_due_date_with_exception(jira_lib_mock):
    scanner = "BAZEL_RUST"
    repository = "ic"

    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = Mock()

    fake_bazel.get_findings.return_value = [
        Finding(
            repository=repository,
            scanner=scanner,
            vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
            vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
            first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
            projects=["foo", "bar", "bear"],
            risk_assessor=[],
            score=100,
        )
    ]

    jira_finding = Finding(
        repository=repository,
        scanner=scanner,
        vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
        vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
        first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
        projects=["foo", "bar", "bear"],
        risk_assessor=[User("mickey", "Mickey Mouse")],
        risk=SecurityRisk.CRITICAL,
        patch_responsible=[],
        due_date=100,
        score=100,
    )
    jira_lib_mock.get_open_finding.return_value = jira_finding
    jira_lib_mock.commit_has_block_exception.return_value = "test commit"

    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])

    scanner_job.do_release_scan(Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())]))
    fake_bazel.get_findings.assert_called_once()
    jira_lib_mock.get_open_finding.assert_called_once()
    jira_lib_mock.commit_has_block_exception.assert_called_once()
    sub1.on_release_build_blocked.assert_not_called()
    sub2.on_release_build_blocked.assert_not_called()
    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


def test_on_release_scan_new_findings(jira_lib_mock):
    scanner = "BAZEL_RUST"
    repository = "ic"

    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = Mock()

    fake_bazel.get_findings.return_value = [
        Finding(
            repository=repository,
            scanner=scanner,
            vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
            vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
            first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
            projects=["foo", "bar", "bear"],
            risk_assessor=[],
            score=100,
        )
    ]
    jira_lib_mock.get_open_finding.return_value = []
    jira_lib_mock.commit_has_block_exception.return_value = None

    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])

    with pytest.raises(SystemExit) as e:
        scanner_job.do_release_scan(Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())]))

    assert e.type == SystemExit
    assert e.value.code == 1
    fake_bazel.get_findings.assert_called_once()
    jira_lib_mock.get_open_finding.assert_called_once()
    jira_lib_mock.commit_has_block_exception.assert_called_once()
    sub1.on_release_build_blocked.assert_called_once()
    sub2.on_release_build_blocked.assert_called_once()
    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


def test_on_release_scan_new_findings_with_exception(jira_lib_mock):
    scanner = "BAZEL_RUST"
    repository = "ic"

    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = Mock()

    fake_bazel.get_findings.return_value = [
        Finding(
            repository=repository,
            scanner=scanner,
            vulnerable_dependency=Dependency("VDID1", "chrono", "1.0", {"VID1": ["1.1", "2.0"]}),
            vulnerabilities=[Vulnerability("VID1", "CVE-123", "huuughe vuln", 100)],
            first_level_dependencies=[Dependency("VDID2", "fl dep", "0.1 beta", {"VID1": ["3.0 alpha"]})],
            projects=["foo", "bar", "bear"],
            risk_assessor=[],
            score=100,
        )
    ]
    jira_lib_mock.get_open_finding.return_value = []
    jira_lib_mock.commit_has_block_exception.return_value = "test commit"

    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])

    scanner_job.do_release_scan(Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())]))
    fake_bazel.get_findings.assert_called_once()
    jira_lib_mock.get_open_finding.assert_called_once()
    jira_lib_mock.commit_has_block_exception.assert_called_once()
    sub1.on_release_build_blocked.assert_not_called()
    sub2.on_release_build_blocked.assert_not_called()
    sub1.on_scan_job_succeeded.assert_called_once()
    sub2.on_scan_job_succeeded.assert_called_once()
    sub1.on_scan_job_failed.assert_not_called()
    sub2.on_scan_job_failed.assert_not_called()


def test_on_release_scan_job_failed(jira_lib_mock):
    sub1 = Mock()
    sub2 = Mock()
    fake_bazel = Mock()
    fake_bazel.get_findings.side_effect = OSError("Call failed")
    scanner_job = DependencyScanner(fake_bazel, jira_lib_mock, [sub1, sub2])

    scanner_job.do_release_scan(Repository("ic", "https://github.com/dfinity/ic", [Project("ic", __test_get_ic_path())]))
    sub1.on_scan_job_succeeded.assert_not_called()
    sub2.on_scan_job_succeeded.assert_not_called()
    sub1.on_scan_job_failed.assert_called_once()
    sub2.on_scan_job_failed.assert_called_once()
