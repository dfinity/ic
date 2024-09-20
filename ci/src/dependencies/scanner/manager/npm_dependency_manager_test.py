import pathlib
import typing
from unittest.mock import call, mock_open, patch

import pytest
from model.dependency import Dependency
from model.finding import Finding
from model.ic import __test_get_ic_path
from model.project import Project
from model.vulnerability import Vulnerability
from scanner.manager.npm_dependency_manager import NPMDependencyManager

DEFAULT_NODE_VERSION = "19"


@pytest.fixture
def npm_test():
    return NPMDependencyManager()


@patch("scanner.process_executor.ProcessExecutor.execute_command")
def test_clone_repository_from_url(process_executor_mock, npm_test):
    url = "https://localhost"
    path = pathlib.Path()
    resolved_path = path.resolve()
    npm_test._NPMDependencyManager__clone_repository_from_url(url, path)
    process_executor_mock.assert_called_once_with("git clone --depth=1 https://localhost", resolved_path, {})

def test_npm_check_engine_no_package_json(npm_test):
    path = pathlib.Path()
    assert npm_test._NPMDependencyManager__npm_check_engine("ic", DEFAULT_NODE_VERSION, path) is False

@patch("pathlib.Path.exists", return_value=True)
@patch("builtins.open", new_callable=mock_open, read_data='{"engines":"{}"}')
def test_npm_check_engine_no_engine_version(_fopen_mock, _path_patch, npm_test):
    path = pathlib.Path()
    assert npm_test._NPMDependencyManager__npm_check_engine("ic", DEFAULT_NODE_VERSION, path) is True

@patch("pathlib.Path.exists", return_value=True)
@patch("builtins.open", new_callable=mock_open, read_data='{"engines":{"node":"<19"}}')
def test_npm_check_engine_not_compatible(_fopen_mock, _path_patch, npm_test):
    path = pathlib.Path()
    assert npm_test._NPMDependencyManager__npm_check_engine("ic", DEFAULT_NODE_VERSION, path) is False

@patch("pathlib.Path.exists", return_value=True)
@patch("builtins.open", new_callable=mock_open, read_data='{"engines":{"node":">=19"}}')
def test_npm_check_engine_compatible(_fopen_mock, _path_patch, npm_test):
    path = pathlib.Path()
    assert npm_test._NPMDependencyManager__npm_check_engine("ic", DEFAULT_NODE_VERSION, path) is True

@patch("pathlib.Path.exists", return_value=True)
@patch("builtins.open", new_callable=mock_open, read_data='{"engines":{"node":"<19"}}')
def test_npm_check_engine_not_compatible_throws_runtime_error(_fopen_mock, _path_patch, npm_test):
    with pytest.raises(RuntimeError) as e:
        path = pathlib.Path()
        assert npm_test._NPMDependencyManager__npm_check_engine("ic", DEFAULT_NODE_VERSION, path) is False
        _ = npm_test.get_findings("ic", Project("ic", __test_get_ic_path()), DEFAULT_NODE_VERSION)
        assert "Dependency scan for ic can't be executed due to engine version mismatch" in str(e.value)

@patch("scanner.process_executor.ProcessExecutor.execute_command", return_value="{'key':'value'}")
@patch("json.loads")
@patch("os.environ.get", return_value="/path/to/nvm")
def test_npm_audit_output(_os_mock, json_mock, process_executor_mock, npm_test):
    path = pathlib.Path()
    resolved_path = path.resolve()
    npm_test._NPMDependencyManager__npm_audit_output(DEFAULT_NODE_VERSION, path)
    process_executor_mock.assert_called_once_with(
        "bash -c 'source /path/to/nvm/nvm.sh && nvm use default 19 --silent && npm audit --json'", resolved_path, {}
    )
    json_mock.assert_called_once_with("{'key':'value'}")


@patch("scanner.process_executor.ProcessExecutor.execute_command", return_value="{'key':'value'}")
@patch("json.loads")
@patch("os.environ.get", return_value="/path/to/nvm")
def test_npm_list_output(_os_mock, json_mock, process_executor_mock, npm_test):
    path = pathlib.Path()
    resolved_path = path.resolve()
    npm_test._NPMDependencyManager__npm_list_output(DEFAULT_NODE_VERSION, path)
    process_executor_mock.assert_has_calls(
        [
            call("bash -c 'source /path/to/nvm/nvm.sh && nvm use default 19 --silent && npm ci'", resolved_path, {}),
            call(
                "bash -c 'source /path/to/nvm/nvm.sh && nvm use default 19 --silent && npm list --all --json'",
                resolved_path,
                {},
            ),
        ]
    )
    json_mock.assert_called_once_with("{'key':'value'}")


def test_vulnerability_from_npm_audit(npm_test):
    vulnerability = {
        "source": 1088820,
        "name": "json5",
        "dependency": "json5",
        "title": "Prototype Pollution in JSON5 via Parse Method",
        "url": "https://github.com/advisories/GHSA-9c47-m6qq-7p4h",
        "severity": "high",
        "cwe": ["CWE-1321"],
        "cvss": {"score": 7.1, "vectorString": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:H"},
        "range": "<1.0.2",
    }
    result = npm_test._NPMDependencyManager__vulnerability_from_npm_audit(vulnerability)
    assert isinstance(result, Vulnerability)
    assert result.id == "https://github.com/advisories/GHSA-9c47-m6qq-7p4h"
    assert result.name == "GHSA-9c47-m6qq-7p4h"
    assert result.description == "Prototype Pollution in JSON5 via Parse Method"
    assert result.score == 7


def test_vulnerability_from_npm_audit_no_cvss(npm_test):
    vulnerability = {
        "source": 1088820,
        "name": "json5",
        "dependency": "json5",
        "title": "Prototype Pollution in JSON5 via Parse Method",
        "url": "https://github.com/advisories/GHSA-9c47-m6qq-7p4h",
        "severity": "high",
        "cwe": ["CWE-1321"],
        "range": "<1.0.2",
    }
    result = npm_test._NPMDependencyManager__vulnerability_from_npm_audit(vulnerability)
    assert isinstance(result, Vulnerability)
    assert result.id == "https://github.com/advisories/GHSA-9c47-m6qq-7p4h"
    assert result.name == "GHSA-9c47-m6qq-7p4h"
    assert result.description == "Prototype Pollution in JSON5 via Parse Method"
    assert result.score == -1


def test_get_first_level_dependencies_from_npm_list(npm_test):
    first_level_dependency_tree = {
        "version": "0.1.0",
        "name": "wallet-ui",
        "dependencies": {
            "@dfinity/agent": {
                "version": "0.10.2",
                "resolved": "https://registry.npmjs.org/@dfinity/agent/-/agent-0.10.2.tgz",
                "overridden": False,
                "dependencies": {
                    "@dfinity/candid": {"version": "0.10.2"},
                    "bignumber.js": {
                        "version": "9.0.1",
                        "resolved": "https://registry.npmjs.org/bignumber.js/-/bignumber.js-9.0.1.tgz",
                        "overridden": False,
                    },
                },
            }
        },
    }
    first_level_dependency = npm_test._NPMDependencyManager__get_first_level_dependencies_from_npm_list(
        first_level_dependency_tree, "bignumber.js", ["<10.0.0"]
    )
    assert len(first_level_dependency) == 1
    assert isinstance(first_level_dependency[0], Dependency)
    assert first_level_dependency[0].id == "https://www.npmjs.com/package/@dfinity/agent/v/0.10.2"
    assert first_level_dependency[0].name == "@dfinity/agent"
    assert first_level_dependency[0].version == "0.10.2"


def test_get_first_level_dependencies_from_npm_list_two_results(npm_test):
    first_level_dependency_tree = {
        "version": "0.1.0",
        "name": "wallet-ui",
        "dependencies": {
            "@dfinity/agent": {
                "version": "0.10.2",
                "resolved": "https://registry.npmjs.org/@dfinity/agent/-/agent-0.10.2.tgz",
                "overridden": False,
                "dependencies": {
                    "@dfinity/candid": {"version": "0.10.2"},
                    "bignumber.js": {
                        "version": "9.0.1",
                        "resolved": "https://registry.npmjs.org/bignumber.js/-/bignumber.js-9.0.1.tgz",
                        "overridden": False,
                    },
                },
            },
            "@dfinity/auth-client": {
                "version": "0.10.2",
                "resolved": "https://registry.npmjs.org/@dfinity/auth-client/-/auth-client-0.10.2.tgz",
                "overridden": False,
                "dependencies": {
                    "bignumber.js": {
                        "version": "8.0.1",
                        "resolved": "https://registry.npmjs.org/bignumber.js/-/bignumber.js-9.0.1.tgz",
                        "overridden": False,
                    }
                },
            },
        },
    }
    first_level_dependency = npm_test._NPMDependencyManager__get_first_level_dependencies_from_npm_list(
        first_level_dependency_tree, "bignumber.js", ["<10.0.0"]
    )
    assert len(first_level_dependency) == 2
    assert isinstance(first_level_dependency[0], Dependency)
    assert first_level_dependency[0].id == "https://www.npmjs.com/package/@dfinity/agent/v/0.10.2"
    assert first_level_dependency[0].name == "@dfinity/agent"
    assert first_level_dependency[0].version == "0.10.2"
    assert isinstance(first_level_dependency[1], Dependency)
    assert first_level_dependency[1].id == "https://www.npmjs.com/package/@dfinity/auth-client/v/0.10.2"
    assert first_level_dependency[1].name == "@dfinity/auth-client"
    assert first_level_dependency[1].version == "0.10.2"


def test_get_first_level_dependencies_from_npm_list_no_results(npm_test):
    first_level_dependency_tree = {
        "version": "0.1.0",
        "name": "wallet-ui",
        "dependencies": {
            "@dfinity/agent": {
                "version": "0.10.2",
                "resolved": "https://registry.npmjs.org/@dfinity/agent/-/agent-0.10.2.tgz",
                "overridden": False,
                "dependencies": {
                    "@dfinity/candid": {"version": "0.10.2"},
                    "bignumber.js": {
                        "version": "9.0.1",
                        "resolved": "https://registry.npmjs.org/bignumber.js/-/bignumber.js-9.0.1.tgz",
                        "overridden": False,
                    },
                },
            }
        },
    }
    first_level_dependency = npm_test._NPMDependencyManager__get_first_level_dependencies_from_npm_list(
        first_level_dependency_tree, "package_not_present", ["<10.0.0"]
    )
    assert not first_level_dependency


def test_get_first_level_dependencies_from_npm_list_version_mismatch(npm_test):
    first_level_dependency_tree = {
        "version": "0.1.0",
        "name": "wallet-ui",
        "dependencies": {
            "@dfinity/agent": {
                "version": "0.10.2",
                "resolved": "https://registry.npmjs.org/@dfinity/agent/-/agent-0.10.2.tgz",
                "overridden": False,
                "dependencies": {
                    "@dfinity/candid": {"version": "0.10.2"},
                    "bignumber.js": {
                        "version": "9.0.1",
                        "resolved": "https://registry.npmjs.org/bignumber.js/-/bignumber.js-9.0.1.tgz",
                        "overridden": False,
                    },
                },
            },
            "@dfinity/auth-client": {
                "version": "0.10.2",
                "resolved": "https://registry.npmjs.org/@dfinity/auth-client/-/auth-client-0.10.2.tgz",
                "overridden": False,
                "dependencies": {
                    "bignumber.js": {
                        "version": "10.0.1",
                        "resolved": "https://registry.npmjs.org/bignumber.js/-/bignumber.js-9.0.1.tgz",
                        "overridden": False,
                    }
                },
            },
        },
    }
    first_level_dependency = npm_test._NPMDependencyManager__get_first_level_dependencies_from_npm_list(
        first_level_dependency_tree, "bignumber.js", ["<10.0.0"]
    )
    assert len(first_level_dependency) == 1
    assert isinstance(first_level_dependency[0], Dependency)
    assert first_level_dependency[0].id == "https://www.npmjs.com/package/@dfinity/agent/v/0.10.2"
    assert first_level_dependency[0].name == "@dfinity/agent"
    assert first_level_dependency[0].version == "0.10.2"


def test_get_first_level_dependencies_from_npm_list_default_version_if_missing(npm_test):
    first_level_dependency_tree = {
        "version": "0.1.0",
        "name": "wallet-ui",
        "dependencies": {
            "@dfinity/agent": {
                "resolved": "../../../",
                "overridden": False,
                "dependencies": {
                    "@dfinity/candid": {"version": "0.10.2"},
                    "bignumber.js": {
                        "version": "9.0.1",
                        "resolved": "https://registry.npmjs.org/bignumber.js/-/bignumber.js-9.0.1.tgz",
                        "overridden": False,
                    },
                },
            },
        },
    }
    first_level_dependency = npm_test._NPMDependencyManager__get_first_level_dependencies_from_npm_list(
        first_level_dependency_tree, "bignumber.js", ["<10.0.0"]
    )
    assert len(first_level_dependency) == 1
    assert isinstance(first_level_dependency[0], Dependency)
    assert first_level_dependency[0].id == "https://www.npmjs.com/package/@dfinity/agent/v/0.0.0"
    assert first_level_dependency[0].name == "@dfinity/agent"
    assert first_level_dependency[0].version == "0.0.0"


def test_get_vulnerable_dependency_from_npm_list(npm_test):
    first_level_dependency_tree = {
        "version": "0.1.0",
        "name": "wallet-ui",
        "dependencies": {
            "@dfinity/agent": {
                "version": "0.10.2",
                "resolved": "https://registry.npmjs.org/@dfinity/agent/-/agent-0.10.2.tgz",
                "overridden": False,
                "dependencies": {
                    "@dfinity/candid": {"version": "0.10.2"},
                    "bignumber.js": {
                        "version": "9.0.1",
                        "resolved": "https://registry.npmjs.org/bignumber.js/-/bignumber.js-9.0.1.tgz",
                        "overridden": False,
                    },
                },
            }
        },
    }
    vulnerable_dependency = npm_test._NPMDependencyManager__get_vulnerable_dependency_from_npm_list(
        first_level_dependency_tree, "bignumber.js", "<10.0.0"
    )
    assert len(vulnerable_dependency) == 1
    assert isinstance(vulnerable_dependency[0], Dependency)
    assert vulnerable_dependency[0].id == "https://www.npmjs.com/package/bignumber.js/v/9.0.1"
    assert vulnerable_dependency[0].name == "bignumber.js"
    assert vulnerable_dependency[0].version == "9.0.1"


def test_get_vulnerable_dependency_from_npm_list_two_results(npm_test):
    first_level_dependency_tree = {
        "version": "0.1.0",
        "name": "wallet-ui",
        "dependencies": {
            "@dfinity/agent": {
                "version": "0.10.2",
                "resolved": "https://registry.npmjs.org/@dfinity/agent/-/agent-0.10.2.tgz",
                "overridden": False,
                "dependencies": {
                    "@dfinity/candid": {"version": "0.10.2"},
                    "bignumber.js": {
                        "version": "9.0.1",
                        "resolved": "https://registry.npmjs.org/bignumber.js/-/bignumber.js-9.0.1.tgz",
                        "overridden": False,
                    },
                },
            },
            "@dfinity/auth-client": {
                "version": "0.10.2",
                "resolved": "https://registry.npmjs.org/@dfinity/auth-client/-/auth-client-0.10.2.tgz",
                "overridden": False,
                "dependencies": {
                    "bignumber.js": {
                        "version": "8.0.1",
                        "resolved": "https://registry.npmjs.org/bignumber.js/-/bignumber.js-9.0.1.tgz",
                        "overridden": False,
                    }
                },
            },
        },
    }
    vulnerable_dependency = npm_test._NPMDependencyManager__get_vulnerable_dependency_from_npm_list(
        first_level_dependency_tree, "bignumber.js", "<10.0.0"
    )
    assert len(vulnerable_dependency) == 2
    assert isinstance(vulnerable_dependency[0], Dependency)
    assert vulnerable_dependency[0].id == "https://www.npmjs.com/package/bignumber.js/v/9.0.1"
    assert vulnerable_dependency[0].name == "bignumber.js"
    assert vulnerable_dependency[0].version == "9.0.1"
    assert isinstance(vulnerable_dependency[1], Dependency)
    assert vulnerable_dependency[1].id == "https://www.npmjs.com/package/bignumber.js/v/8.0.1"
    assert vulnerable_dependency[1].name == "bignumber.js"
    assert vulnerable_dependency[1].version == "8.0.1"


def test_get_vulnerable_dependency_from_npm_list_version_mismatch(npm_test):
    first_level_dependency_tree = {
        "version": "0.1.0",
        "name": "wallet-ui",
        "dependencies": {
            "@dfinity/agent": {
                "version": "0.10.2",
                "resolved": "https://registry.npmjs.org/@dfinity/agent/-/agent-0.10.2.tgz",
                "overridden": False,
                "dependencies": {
                    "@dfinity/candid": {"version": "0.10.2"},
                    "bignumber.js": {
                        "version": "9.0.1",
                        "resolved": "https://registry.npmjs.org/bignumber.js/-/bignumber.js-9.0.1.tgz",
                        "overridden": False,
                    },
                },
            },
            "@dfinity/auth-client": {
                "version": "0.10.2",
                "resolved": "https://registry.npmjs.org/@dfinity/auth-client/-/auth-client-0.10.2.tgz",
                "overridden": False,
                "dependencies": {
                    "bignumber.js": {
                        "version": "10.0.1",
                        "resolved": "https://registry.npmjs.org/bignumber.js/-/bignumber.js-9.0.1.tgz",
                        "overridden": False,
                    }
                },
            },
        },
    }
    vulnerable_dependency = npm_test._NPMDependencyManager__get_vulnerable_dependency_from_npm_list(
        first_level_dependency_tree, "bignumber.js", "<10.0.0"
    )
    assert len(vulnerable_dependency) == 1
    assert isinstance(vulnerable_dependency[0], Dependency)
    assert vulnerable_dependency[0].id == "https://www.npmjs.com/package/bignumber.js/v/9.0.1"
    assert vulnerable_dependency[0].name == "bignumber.js"
    assert vulnerable_dependency[0].version == "9.0.1"


def test_get_vulnerable_dependency_from_npm_list_no_vulnerable_dependency(npm_test):
    with pytest.raises(RuntimeError) as e:
        first_level_dependency_tree = {
            "version": "0.1.0",
            "name": "wallet-ui",
            "dependencies": {
                "@dfinity/agent": {
                    "version": "0.10.2",
                    "resolved": "https://registry.npmjs.org/@dfinity/agent/-/agent-0.10.2.tgz",
                    "overridden": False,
                    "dependencies": {"@dfinity/candid": {"version": "0.10.2"}},
                }
            },
        }
        _ = npm_test._NPMDependencyManager__get_vulnerable_dependency_from_npm_list(
            first_level_dependency_tree, "bignumber.js", "<10.0.0"
        )
        assert "nested lookup failed for dependency bignumber.js with error (no dependency)" in str(e.value)


def test_get_vulnerable_dependency_from_npm_list_no_vulnerable_dependency_with_version(npm_test):
    with pytest.raises(RuntimeError) as e:
        first_level_dependency_tree = {
            "version": "0.1.0",
            "name": "wallet-ui",
            "dependencies": {
                "@dfinity/agent": {
                    "version": "0.10.2",
                    "resolved": "https://registry.npmjs.org/@dfinity/agent/-/agent-0.10.2.tgz",
                    "overridden": False,
                    "dependencies": {
                        "@dfinity/candid": {"version": "0.10.2"},
                        "bignumber.js": {
                            "version": "10.0.1",
                            "resolved": "https://registry.npmjs.org/bignumber.js/-/bignumber.js-9.0.1.tgz",
                            "overridden": False,
                        },
                    },
                }
            },
        }
        _ = npm_test._NPMDependencyManager__get_vulnerable_dependency_from_npm_list(
            first_level_dependency_tree, "bignumber.js", "<10.0.0"
        )
        assert "nested lookup failed for dependency bignumber.js with error (no vulnerable versions)" in str(e.value)


class FakeNPM:
    def __init__(self, fake_audit_type: int):
        self.fake_audit_type = fake_audit_type

    def npm_check_engine(self, repository_name: str, engine_version: int, path: pathlib.Path) -> bool:
        return True

    def npm_audit_output(self, engine_version: int, path: pathlib.Path) -> typing.Dict:
        if self.fake_audit_type == 1:
            return {}

        if self.fake_audit_type == 2:
            return {
                "auditReportVersion": 2,
                "vulnerabilities": {
                    "d3-color": {
                        "name": "d3-color",
                        "severity": "high",
                        "isDirect": False,
                        "via": [
                            {
                                "source": 1088594,
                                "name": "d3-color",
                                "dependency": "d3-color",
                                "title": "d3-color vulnerable to ReDoS",
                                "url": "https://github.com/advisories/GHSA-36jr-mh4h-2g58",
                                "severity": "high",
                                "cwe": ["CWE-400"],
                                "cvss": {"score": 0, "vectorString": ""},
                                "range": "<3.1.0",
                            },
                            {
                                "source": 1088594,
                                "name": "d2-color",
                                "dependency": "d2-color",
                                "title": "d2-color vulnerable to ReDoS",
                                "url": "https://github.com/advisories/GHSA-36jr-mh4h-2g57",
                                "severity": "high",
                                "cwe": ["CWE-400"],
                                "cvss": {"score": 0, "vectorString": ""},
                                "range": "<3.1.0",
                            },
                        ],
                        "effects": ["d3-interpolate"],
                        "range": "<3.1.0",
                        "nodes": ["node_modules/d3-color"],
                        "fixAvailable": {"name": "recharts", "version": "2.3.2", "isSemVerMajor": True},
                    }
                },
            }

        if self.fake_audit_type == 3:
            return {
                "auditReportVersion": 2,
                "vulnerabilities": {
                    "d3-color": {
                        "name": "d3-color",
                        "severity": "high",
                        "isDirect": False,
                        "via": [
                            {
                                "source": 1088594,
                                "name": "d3-color",
                                "dependency": "d3-color",
                                "title": "d3-color vulnerable to ReDoS",
                                "url": "https://github.com/advisories/GHSA-36jr-mh4h-2g58",
                                "severity": "high",
                                "cwe": ["CWE-400"],
                                "cvss": {"score": 0, "vectorString": ""},
                                "range": ">3.1.0",
                            }
                        ],
                        "effects": ["d3-interpolate"],
                        "range": "<3.1.0",
                        "nodes": ["node_modules/d3-color"],
                        "fixAvailable": {"name": "recharts", "version": "2.3.2", "isSemVerMajor": True},
                    }
                },
            }

        if self.fake_audit_type == 4:
            return {
                "auditReportVersion": 2,
                "vulnerabilities": {
                    "d3-color": {
                        "name": "d3-color",
                        "severity": "high",
                        "isDirect": False,
                        "via": ["d3-interpolate"],
                        "effects": ["recharts"],
                        "range": "0.1.5 - 3.3.0",
                        "nodes": ["node_modules/d3-color"],
                        "fixAvailable": {"name": "recharts", "version": "2.3.2", "isSemVerMajor": True},
                    }
                },
            }

    def npm_list_output(self, engine_version: int, path: pathlib.Path) -> typing.Dict:
        return {
            "version": "0.1.0",
            "name": "wallet-ui",
            "dependencies": {
                "@dfinity/agent": {
                    "version": "0.10.2",
                    "resolved": "https://registry.npmjs.org/@dfinity/agent/-/agent-0.10.2.tgz",
                    "overridden": False,
                    "dependencies": {
                        "@dfinity/candid": {"version": "0.10.2"},
                        "d3-color": {
                            "version": "2.0.1",
                            "resolved": "https://registry.npmjs.org/bignumber.js/-/bignumber.js-9.0.1.tgz",
                            "overridden": False,
                        },
                    },
                }
            },
        }


def test_findings_helper_no_vulnerabilities(npm_test):
    repository = "ic"
    project = Project("ic", __test_get_ic_path())
    fake_npm = FakeNPM(1)
    npm_test._NPMDependencyManager__npm_audit_output = fake_npm.npm_audit_output
    npm_test._NPMDependencyManager__npm_list_output = fake_npm.npm_list_output
    npm_test._NPMDependencyManager__npm_check_engine = fake_npm.npm_check_engine

    findings = npm_test.get_findings(repository, project, DEFAULT_NODE_VERSION)
    assert not findings


def test_findings_helper_one_finding(npm_test):
    repository = "ic"
    project = Project("ic", __test_get_ic_path())
    fake_npm = FakeNPM(2)
    npm_test._NPMDependencyManager__npm_audit_output = fake_npm.npm_audit_output
    npm_test._NPMDependencyManager__npm_list_output = fake_npm.npm_list_output
    npm_test._NPMDependencyManager__npm_check_engine = fake_npm.npm_check_engine

    findings = npm_test.get_findings(repository, project, DEFAULT_NODE_VERSION)
    assert len(findings) == 1
    assert findings[0] == Finding(
        repository="ic",
        scanner="NPM",
        vulnerable_dependency=Dependency(
            id="https://www.npmjs.com/package/d3-color/v/2.0.1",
            name="d3-color",
            version="2.0.1",
            fix_version_for_vulnerability={},
        ),
        vulnerabilities=[
            Vulnerability(
                id="https://github.com/advisories/GHSA-36jr-mh4h-2g57",
                name="GHSA-36jr-mh4h-2g57",
                description="d2-color vulnerable to ReDoS",
                score=-1,
            ),
            Vulnerability(
                id="https://github.com/advisories/GHSA-36jr-mh4h-2g58",
                name="GHSA-36jr-mh4h-2g58",
                description="d3-color vulnerable to ReDoS",
                score=-1,
            ),
        ],
        first_level_dependencies=[
            Dependency(
                id="https://www.npmjs.com/package/@dfinity/agent/v/0.10.2",
                name="@dfinity/agent",
                version="0.10.2",
                fix_version_for_vulnerability={},
            )
        ],
        projects=["ic"],
        risk_assessor=[],
        risk=None,
        patch_responsible=[],
        due_date=None,
        score=-1,
        more_info=None,
    )


def test_findings_helper_vulnerable_dependency_not_in_range(npm_test):
    repository = "ic"
    project = Project("ic", __test_get_ic_path())
    fake_npm = FakeNPM(3)
    npm_test._NPMDependencyManager__npm_audit_output = fake_npm.npm_audit_output
    npm_test._NPMDependencyManager__npm_list_output = fake_npm.npm_list_output
    npm_test._NPMDependencyManager__npm_check_engine = fake_npm.npm_check_engine

    findings = npm_test.get_findings(repository, project, DEFAULT_NODE_VERSION)
    assert not findings


def test_findings_helper_transitive_vulnerability(npm_test):
    repository = "ic"
    project = Project("ic", __test_get_ic_path())
    fake_npm = FakeNPM(4)
    npm_test._NPMDependencyManager__npm_audit_output = fake_npm.npm_audit_output
    npm_test._NPMDependencyManager__npm_list_output = fake_npm.npm_list_output
    npm_test._NPMDependencyManager__npm_check_engine = fake_npm.npm_check_engine

    findings = npm_test.get_findings(repository, project, DEFAULT_NODE_VERSION)
    assert not findings
