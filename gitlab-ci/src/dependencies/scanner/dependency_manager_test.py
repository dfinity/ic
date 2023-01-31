import pathlib
import typing
from unittest.mock import call
from unittest.mock import patch

import pytest
from model.dependency import Dependency
from model.finding import Finding
from model.repository import Project
from model.repository import Repository
from model.vulnerability import Vulnerability
from scanner.dependency_manager import Bazel
from scanner.dependency_manager import NPM

# Bazel tests


@pytest.fixture
def bazel_test():
    return Bazel()


def test_project_root_bazel(bazel_test):
    assert bazel_test.root.exists()
    assert bazel_test.root.is_dir()
    assert bazel_test.root.name == "ic"


def test_cargo_lock_exists(bazel_test):
    cargo_lock_file = bazel_test.root / "rs" / "Cargo.lock"
    assert cargo_lock_file.exists()


def test_cargo_bazel_lock_exists(bazel_test):
    cargo_bazel_lock_file = bazel_test.root / "Cargo.Bazel.toml.lock"
    assert cargo_bazel_lock_file.exists()


def test_dependency_to_transitive_bazel_string(bazel_test):
    dependency = Dependency(id="random_string", name="chrono", version="0.4.19", fix_version_for_vulnerability={})
    bazel_string = bazel_test._Bazel__dependency_to_transitive_bazel_string(dependency)
    assert bazel_string == "@crate_index__chrono-0.4.19//:*"


def test_transitive_bazel_string_to_dependency_random(bazel_test):
    bazel_string = "@com_google_protobuf_protoc_linux_aarch64//"
    dependency = bazel_test._Bazel__transitive_bazel_string_to_dependency(bazel_string)
    assert dependency is None


def test_transitive_bazel_string_to_dependency(bazel_test):
    bazel_string = "@crate_index__chrono-0.4.19//"
    dependency = bazel_test._Bazel__transitive_bazel_string_to_dependency(bazel_string)
    assert dependency.name == "chrono"
    assert dependency.version == "0.4.19"


def test_transitive_bazel_string_to_dependency_hypenated(bazel_test):
    bazel_string_hypenated_crate = "@crate_index__build-info-common-0.4.19//"
    dependency = bazel_test._Bazel__transitive_bazel_string_to_dependency(bazel_string_hypenated_crate)
    assert dependency.name == "build-info-common"
    assert dependency.version == "0.4.19"


def test_transitive_bazel_string_to_dependency_versioned(bazel_test):
    bazel_string_versioned_crate = "@crate_index__rand_chacha-0.4.19//"
    dependency = bazel_test._Bazel__transitive_bazel_string_to_dependency(bazel_string_versioned_crate)
    assert dependency.name == "rand_chacha"
    assert dependency.version == "0.4.19"


def test_transitive_bazel_string_to_dependency_zstd(bazel_test):
    bazel_string = "@crate_index__zstd-sys-2.0.2-zstd.1.5.2//"
    dependency = bazel_test._Bazel__transitive_bazel_string_to_dependency(bazel_string)
    assert dependency.name == "zstd-sys"
    assert dependency.version == "2.0.2"


def test_dependency_to_direct_bazel_string(bazel_test):
    dependency = Dependency(id="random_string", name="chrono", version="0.4.19", fix_version_for_vulnerability={})
    bazel_string = bazel_test._Bazel__dependency_to_direct_bazel_string(dependency)
    assert bazel_string == "@crate_index//:chrono"


def test_versioned_dependency_to_direct_bazel_string(bazel_test):

    dependency = Dependency(id="random_string", name="rand", version="0.4.19", fix_version_for_vulnerability={})
    bazel_string = bazel_test._Bazel__dependency_to_direct_bazel_string(dependency)
    assert bazel_string == "@crate_index//:rand_0_4_19"


def test_versioned_multi_name_dependency_to_direct_bazel_string(bazel_test):
    dependency = Dependency(id="random_string", name="rand_chacha", version="0.4.19", fix_version_for_vulnerability={})

    bazel_string = bazel_test._Bazel__dependency_to_direct_bazel_string(dependency)
    assert bazel_string == "@crate_index//:rand_chacha_0_4_19"


def test_parse_vulnerable_dependency_from_cargo_audit(bazel_test):
    cargo_audit_out_slim = {
        "versions": {"patched": [">=0.2.23"], "unaffected": ["=0.2.0"]},
        "package": {"name": "time", "version": "0.1.44"},
    }
    dependency = bazel_test._Bazel__parse_vulnerable_dependency_from_cargo_audit(
        "vulnerability_id", cargo_audit_out_slim
    )
    assert dependency.id == "https://crates.io/crates/time"
    assert dependency.name == "time"
    assert dependency.version == "0.1.44"
    assert dependency.fix_version_for_vulnerability == {"vulnerability_id": [">=0.2.23", "=0.2.0"]}


def test_parse_vulnerable_dependency_from_cargo_audit_with_no_fixes(bazel_test):
    cargo_audit_out_slim = {
        "versions": {"patched": [], "unaffected": []},
        "package": {"name": "time", "version": "0.1.44"},
    }

    dependency = bazel_test._Bazel__parse_vulnerable_dependency_from_cargo_audit(
        "vulnerability_id", cargo_audit_out_slim
    )
    assert dependency.id == "https://crates.io/crates/time"
    assert dependency.name == "time"
    assert dependency.version == "0.1.44"
    assert dependency.fix_version_for_vulnerability == {}


def test_parse_vulnerability_from_cargo_audit(bazel_test):
    cargo_audit_out_slim = {
        "id": "RUSTSEC-2020-0071",
        "title": "Potential segfault in the time crate",
        "cvss": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    }

    vulnerability = bazel_test._Bazel__parse_vulnerability_from_cargo_audit(cargo_audit_out_slim)
    assert vulnerability.id == "https://rustsec.org/advisories/RUSTSEC-2020-0071"
    assert vulnerability.name == "RUSTSEC-2020-0071"
    assert vulnerability.description == "Potential segfault in the time crate"
    assert vulnerability.score == 6


def test_parse_vulnerability_from_cargo_audit_with_no_cvss(bazel_test):
    cargo_audit_out_slim = {"id": "RUSTSEC-2020-0071", "title": "Potential segfault in the time crate", "cvss": None}

    vulnerability = bazel_test._Bazel__parse_vulnerability_from_cargo_audit(cargo_audit_out_slim)
    assert vulnerability.id == "https://rustsec.org/advisories/RUSTSEC-2020-0071"
    assert vulnerability.name == "RUSTSEC-2020-0071"
    assert vulnerability.description == "Potential segfault in the time crate"
    assert vulnerability.score == -1


# TODO : Add test for bazel outputs and findings


# NPM tests


@pytest.fixture
def npm_test():
    return NPM()


@patch("scanner.process_executor.ProcessExecutor.execute_command")
def test_clone_repository_from_url(process_executor_mock, npm_test):
    url = "https://localhost"
    path = pathlib.Path()
    resolved_path = path.resolve()
    npm_test._NPM__clone_repository_from_url(url, path)
    process_executor_mock.assert_called_once_with(
        "git clone --depth=1 https://localhost", resolved_path, {}, use_nix_shell=False
    )


@patch("scanner.process_executor.ProcessExecutor.execute_command", return_value="{'key':'value'}")
@patch("json.loads")
def test_npm_audit_output(json_mock, process_executor_mock, npm_test):
    path = pathlib.Path()
    resolved_path = path.resolve()
    npm_test._NPM__npm_audit_output(path)
    process_executor_mock.assert_called_once_with("npm audit --json", resolved_path, {}, use_nix_shell=False)
    json_mock.assert_called_once_with("{'key':'value'}")


@patch("scanner.process_executor.ProcessExecutor.execute_command", return_value="{'key':'value'}")
@patch("json.loads")
def test_npm_list_output(json_mock, process_executor_mock, npm_test):
    path = pathlib.Path()
    resolved_path = path.resolve()
    npm_test._NPM__npm_list_output(path)
    process_executor_mock.assert_has_calls(
        [
            call("npm install", resolved_path, {}, use_nix_shell=False),
            call("npm list --all --json", resolved_path, {}, use_nix_shell=False),
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
    result = npm_test._NPM__vulnerability_from_npm_audit(vulnerability)
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
    result = npm_test._NPM__vulnerability_from_npm_audit(vulnerability)
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
    first_level_dependency = npm_test._NPM__get_first_level_dependencies_from_npm_list(
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
    first_level_dependency = npm_test._NPM__get_first_level_dependencies_from_npm_list(
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
    first_level_dependency = npm_test._NPM__get_first_level_dependencies_from_npm_list(
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
    first_level_dependency = npm_test._NPM__get_first_level_dependencies_from_npm_list(
        first_level_dependency_tree, "bignumber.js", ["<10.0.0"]
    )
    assert len(first_level_dependency) == 1
    assert isinstance(first_level_dependency[0], Dependency)
    assert first_level_dependency[0].id == "https://www.npmjs.com/package/@dfinity/agent/v/0.10.2"
    assert first_level_dependency[0].name == "@dfinity/agent"
    assert first_level_dependency[0].version == "0.10.2"


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
    vulnerable_dependency = npm_test._NPM__get_vulnerable_dependency_from_npm_list(
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
    vulnerable_dependency = npm_test._NPM__get_vulnerable_dependency_from_npm_list(
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
    vulnerable_dependency = npm_test._NPM__get_vulnerable_dependency_from_npm_list(
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
        _ = npm_test._NPM__get_vulnerable_dependency_from_npm_list(
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
        _ = npm_test._NPM__get_vulnerable_dependency_from_npm_list(
            first_level_dependency_tree, "bignumber.js", "<10.0.0"
        )
        assert "nested lookup failed for dependency bignumber.js with error (no vulnerable versions)" in str(e.value)


class FakeNPM:
    def __init__(self, fake_audit_type: int):
        self.fake_audit_type = fake_audit_type

    def npm_audit_output(self, path: pathlib.Path) -> typing.Dict:
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
                            }
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

    def npm_list_output(self, path: pathlib.Path) -> typing.Dict:
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


def test_findings_helper_no_vulnerabilites(npm_test):
    scanner = "NPM_IC"
    repository = "ic"
    project = "ic"
    path = pathlib.Path()
    fake_npm = FakeNPM(1)
    npm_test._NPM__npm_audit_output = fake_npm.npm_audit_output.__get__(npm_test, NPM)
    npm_test._NPM__npm_list_output = fake_npm.npm_list_output.__get__(npm_test, NPM)

    findings = npm_test._NPM__findings_helper(repository, scanner, path, project)
    assert not findings


def test_findings_helper_one_finding(npm_test):
    scanner = "NPM_IC"
    repository = "ic"
    project = "ic"
    path = pathlib.Path()
    fake_npm = FakeNPM(2)
    npm_test._NPM__npm_audit_output = fake_npm.npm_audit_output.__get__(npm_test, NPM)
    npm_test._NPM__npm_list_output = fake_npm.npm_list_output.__get__(npm_test, NPM)

    findings = npm_test._NPM__findings_helper(repository, scanner, path, project)
    assert len(findings) == 1
    assert findings[0] == Finding(
        repository="ic",
        scanner="NPM_IC",
        vulnerable_dependency=Dependency(
            id="https://www.npmjs.com/package/d3-color/v/2.0.1",
            name="d3-color",
            version="2.0.1",
            fix_version_for_vulnerability={},
        ),
        vulnerabilities=[
            Vulnerability(
                id="https://github.com/advisories/GHSA-36jr-mh4h-2g58",
                name="GHSA-36jr-mh4h-2g58",
                description="d3-color vulnerable to ReDoS",
                score=-1,
            )
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
        patch_responsible=(),
        due_date=None,
        score=-1,
        more_info=None,
    )


def test_findings_helper_vulnerable_dependency_not_in_range(npm_test):
    scanner = "NPM_IC"
    repository = "ic"
    project = "ic"
    path = pathlib.Path()
    fake_npm = FakeNPM(3)
    npm_test._NPM__npm_audit_output = fake_npm.npm_audit_output.__get__(npm_test, NPM)
    npm_test._NPM__npm_list_output = fake_npm.npm_list_output.__get__(npm_test, NPM)

    findings = npm_test._NPM__findings_helper(repository, scanner, path, project)
    assert not findings


def test_findings_helper_transitive_vulnerability(npm_test):
    scanner = "NPM_IC"
    repository = "ic"
    project = "ic"
    path = pathlib.Path()
    fake_npm = FakeNPM(4)
    npm_test._NPM__npm_audit_output = fake_npm.npm_audit_output.__get__(npm_test, NPM)
    npm_test._NPM__npm_list_output = fake_npm.npm_list_output.__get__(npm_test, NPM)

    findings = npm_test._NPM__findings_helper(repository, scanner, path, project)
    assert not findings


@patch("scanner.dependency_manager.NPM._NPM__clone_repository_from_url")
@patch("scanner.dependency_manager.NPM._NPM__findings_helper")
@patch("shutil.rmtree")
def test_get_findings_ic_dir(shutil, findings_helper, clone_repo, npm_test):
    scanner = "NPM_IC"

    repo = Repository(
        "ic", "https://gitlab.com/dfinity-lab/public/ic", [Project("service-worker", "ic/typescript/service-worker")]
    )
    test_path = npm_test.root.parent / "ic/typescript/service-worker"

    npm_test.get_findings(repo, scanner)
    shutil.assert_not_called()
    clone_repo.assert_not_called()
    findings_helper.assert_called_once_with("ic", scanner, test_path, "service-worker")


@patch("scanner.dependency_manager.NPM._NPM__clone_repository_from_url")
@patch("scanner.dependency_manager.NPM._NPM__findings_helper")
@patch("shutil.rmtree")
def test_get_findings_external_dir(shutil, findings_helper, clone_repo, npm_test):
    with patch("pathlib.Path.is_dir", return_value=True):
        scanner = "NPM_IC"

        repo = Repository(
            "cycles-wallet", "https://github.com/dfinity/cycles-wallet", [Project("cycles-wallet", "cycles-wallet")]
        )
        test_path = npm_test.root.parent / "cycles-wallet"

        npm_test.get_findings(repo, scanner)
        shutil.assert_called_once()
        clone_repo.assert_called_once_with("https://github.com/dfinity/cycles-wallet", npm_test.root.parent)
        findings_helper.assert_called_once_with("cycles-wallet", scanner, test_path, "cycles-wallet")
