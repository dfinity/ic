from unittest.mock import Mock

from bazel_trivy_dependency_manager import BazelTrivyContainer
from model.dependency import Dependency
from model.project import Project
from model.vulnerability import Vulnerability


def test_return_no_finding():
    executor = Mock()
    executor.run_trivy_and_parse_data.return_value = {}, {}

    res = BazelTrivyContainer(executor=executor).get_findings("repo", Project(name="proj", path="/some/path"), None)

    assert len(res) == 0


def test_return_os_finding():
    os_finding = {
        "Metadata": {"OS": {"Family": "ubuntu", "Name": "ubuntu 20.04"}},
        "Results": [
            {
                "Class": "os-pkgs",
                "Vulnerabilities": [
                    {
                        "PkgName": "binutils",
                        "InstalledVersion": "1.0",
                        "PrimaryURL": "http://vuln.org/CVE-0815",
                        "VulnerabilityID": "CVE-0815",
                        "Title": "crazy vulnerability",
                        "FixedVersion": "1.1",
                        "CVSS": {"nvd": {"V3Score": 8.5}},
                    },
                    {
                        "PkgName": "binutils",
                        "InstalledVersion": "1.0",
                        "VulnerabilityID": "CVE-123",
                        "CVSS": {"nvd": {"V3Score": 8.6}},
                    },
                    {
                        "PkgName": "binutils-common",
                        "InstalledVersion": "2.0",
                        "PrimaryURL": "http://vuln.org/CVE-0815",
                        "VulnerabilityID": "CVE-0815",
                        "Title": "crazy vulnerability",
                        "FixedVersion": "2.1",
                        "CVSS": {"nvd": {"V3Score": 8.5}},
                    },
                    {
                        "PkgName": "binutils-common",
                        "InstalledVersion": "2.0",
                        "VulnerabilityID": "CVE-123",
                        "CVSS": {"nvd": {"V3Score": 8.6}},
                    },
                    {
                        "PkgName": "linux-modules-5.15.0-76-generic",
                        "InstalledVersion": "5.15.0-76.83~20.04.1",
                        "VulnerabilityID": "CVE-2023-35829",
                        "CVSS": {"nvd": {"V3Score": 7}},
                    },
                ],
            }
        ],
    }
    executor = Mock()
    executor.run_trivy_and_parse_data.return_value = os_finding, {}
    manager = BazelTrivyContainer(executor=executor)

    res = manager.get_findings("repo", Project(name="proj", path="/some/path", link="https://some.link"), None)

    assert len(res) == 2
    assert res[0].repository == "repo"
    assert res[0].scanner == manager.get_scanner_id()
    assert res[0].vulnerable_dependency == Dependency(
        id="binutils",
        name="binutils",
        version="1.0",
        fix_version_for_vulnerability={"http://vuln.org/CVE-0815": ["1.1"]},
    )
    assert res[0].vulnerabilities == [
        Vulnerability(id="CVE-123", name="CVE-123", description="n/a", score=9),
        Vulnerability(id="http://vuln.org/CVE-0815", name="CVE-0815", description="crazy vulnerability", score=8),
    ]
    assert res[0].first_level_dependencies == [
        Dependency(
            id="binutils-common",
            name="binutils-common",
            version="2.0",
            fix_version_for_vulnerability={"http://vuln.org/CVE-0815": ["2.1"]},
        ),
    ]
    assert res[0].projects == ["OSP: /some/path (https://some.link)"]
    assert res[0].risk_assessor == []
    assert res[0].risk is None
    assert res[0].patch_responsible == []
    assert res[0].due_date is None
    assert res[0].score == 9
    assert res[0].more_info is None

    assert res[1].repository == "repo"
    assert res[1].scanner == manager.get_scanner_id()
    assert res[1].vulnerable_dependency == Dependency(
        id="linux-modules-5.15.0",
        name="linux-modules-5.15.0-76-generic",
        version="5.15.0-76.83~20.04.1",
    )
    assert res[1].vulnerabilities == [
        Vulnerability(id="CVE-2023-35829", name="CVE-2023-35829", description="n/a", score=7),
    ]
    assert res[1].first_level_dependencies == []
    assert res[1].projects == ["OSP: /some/path (https://some.link)"]
    assert res[1].risk_assessor == []
    assert res[1].risk is None
    assert res[1].patch_responsible == []
    assert res[1].due_date is None
    assert res[1].score == 7
    assert res[1].more_info is None

def test_return_binary_finding():
    binary_finding = {
        "Results": [
            {
                "Target": "usr/local/bin/node_exporter",
                "Class": "lang-pkgs",
                "Type": "gobinary",
                "Vulnerabilities": [
                    {
                        "PkgName": "github.com/prometheus/client_golang",
                        "InstalledVersion": "1.11.0",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-21698",
                        "VulnerabilityID": "CVE-2022-21698",
                        "Title": "prometheus/client_golang: Denial of service using InstrumentHandlerCounter",
                        "FixedVersion": "1.11.1",
                        "CVSS": {"nvd": {"V3Score": 8}},
                    },
                    {
                        "PkgName": "golang.org/x/crypto",
                        "InstalledVersion": "1.0",
                        "VulnerabilityID": "CVE-2021-43565",
                    },
                ],
            }
        ]
    }
    executor = Mock()
    executor.run_trivy_and_parse_data.return_value = binary_finding, {
        "usr/local/bin/node_exporter": "44f586eee11a2e07fb86afe6d3698925fe4388b7f55abfb29159e7797c87b095"
    }
    manager = BazelTrivyContainer(executor=executor)

    res = manager.get_findings("repo", Project(name="proj", path="/some/path"), None)

    assert len(res) == 1
    assert res[0].repository == "repo"
    assert res[0].scanner == manager.get_scanner_id()
    assert res[0].vulnerable_dependency == Dependency(
        id="usr/local/bin/node_exporter",
        name="node_exporter",
        version="44f586eee11a2e07fb86afe6d3698925fe4388b7f55abfb29159e7797c87b095",
    )
    assert res[0].vulnerabilities == [
        Vulnerability(id="CVE-2021-43565", name="CVE-2021-43565", description="n/a", score=-1),
        Vulnerability(
            id="https://avd.aquasec.com/nvd/cve-2022-21698",
            name="CVE-2022-21698",
            description="prometheus/client_golang: Denial of service using InstrumentHandlerCounter",
            score=8,
        ),
    ]
    assert res[0].first_level_dependencies == [
        Dependency(
            id="github.com/prometheus/client_golang",
            name="github.com/prometheus/client_golang",
            version="1.11.0",
            fix_version_for_vulnerability={
                "https://avd.aquasec.com/nvd/cve-2022-21698": ["1.11.1"],
                "CVE-2021-43565": ["n/a"],
            },
        ),
        Dependency(
            id="golang.org/x/crypto",
            name="golang.org/x/crypto",
            version="1.0",
            fix_version_for_vulnerability={"https://avd.aquasec.com/nvd/cve-2022-21698": ["n/a"]},
        ),
    ]
    assert res[0].projects == ["BIN: /some/path"]
    assert res[0].risk_assessor == []
    assert res[0].risk is None
    assert res[0].patch_responsible == []
    assert res[0].due_date is None
    assert res[0].score == -1
    assert res[0].more_info is None


def test_return_secret_finding():
    secret_finding = {
        "Results": [
            {
                "Target": "etc/ssl/private/ssl-cert-snakeoil.key",
                "Class": "secret",
                "Secrets": [{"RuleID": "private-key", "Title": "Asymmetric Private Key"}],
            }
        ]
    }
    executor = Mock()
    executor.run_trivy_and_parse_data.return_value = secret_finding, {}
    manager = BazelTrivyContainer(executor=executor)

    res = manager.get_findings("repo", Project(name="proj", path="/some/path"), None)

    assert len(res) == 1
    assert res[0].repository == "repo"
    assert res[0].scanner == manager.get_scanner_id()
    assert res[0].vulnerable_dependency == Dependency(
        id="etc/ssl/private/ssl-cert-snakeoil.key", name="ssl-cert-snakeoil.key", version="current"
    )
    assert res[0].vulnerabilities == [
        Vulnerability(id="private-key", name="private-key", description="Asymmetric Private Key", score=-1)
    ]
    assert res[0].first_level_dependencies == []
    assert res[0].projects == ["SEC: /some/path"]
    assert res[0].risk_assessor == []
    assert res[0].risk is None
    assert res[0].patch_responsible == []
    assert res[0].due_date is None
    assert res[0].score == -1
    assert res[0].more_info is None
