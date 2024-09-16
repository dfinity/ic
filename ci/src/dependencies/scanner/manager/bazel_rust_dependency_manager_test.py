import json
import os
import pathlib
import typing

import pytest
from model.dependency import Dependency
from model.ic import __test_get_ic_path
from model.project import Project
from model.vulnerability import Vulnerability
from scanner.manager.bazel_rust_dependency_manager import BazelCargoExecutor, BazelRustDependencyManager


@pytest.fixture
def bazel_test():
    return BazelRustDependencyManager()


def open_test_file(rel_path):
    return open(os.path.join(os.path.dirname(__file__), rel_path), "r")


def test_project_root_bazel(bazel_test):
    assert bazel_test.root.exists()
    assert bazel_test.root.is_dir()


def test_cargo_lock_exists(bazel_test):
    cargo_lock_file = bazel_test.root / "Cargo.lock"
    assert cargo_lock_file.exists()


def test_cargo_bazel_lock_exists(bazel_test):
    cargo_bazel_lock_file = bazel_test.root / "Cargo.Bazel.toml.lock"
    assert cargo_bazel_lock_file.exists()


def test_dependency_to_transitive_bazel_string(bazel_test):
    dependency = Dependency(id="random_string", name="chrono", version="0.4.19", fix_version_for_vulnerability={})
    bazel_string = bazel_test._BazelRustDependencyManager__dependency_to_transitive_bazel_string(dependency)
    assert bazel_string == "@crate_index__chrono-0.4.19//:*"


def test_transitive_bazel_string_to_dependency_random(bazel_test):
    bazel_string = "@com_google_protobuf_protoc_linux_aarch64//"
    dependency = bazel_test._BazelRustDependencyManager__transitive_bazel_string_to_dependency(bazel_string)
    assert dependency is None


def test_transitive_bazel_string_to_dependency(bazel_test):
    bazel_string = "@crate_index__chrono-0.4.19//"
    dependency = bazel_test._BazelRustDependencyManager__transitive_bazel_string_to_dependency(bazel_string)
    assert dependency.name == "chrono"
    assert dependency.version == "0.4.19"


def test_transitive_bazel_string_to_dependency_hyphenated(bazel_test):
    bazel_string_hyphenated_crate = "@crate_index__build-info-common-0.4.19//"
    dependency = bazel_test._BazelRustDependencyManager__transitive_bazel_string_to_dependency(
        bazel_string_hyphenated_crate
    )
    assert dependency.name == "build-info-common"
    assert dependency.version == "0.4.19"


def test_transitive_bazel_string_to_dependency_versioned(bazel_test):
    bazel_string_versioned_crate = "@crate_index__rand_chacha-0.4.19//"
    dependency = bazel_test._BazelRustDependencyManager__transitive_bazel_string_to_dependency(
        bazel_string_versioned_crate
    )
    assert dependency.name == "rand_chacha"
    assert dependency.version == "0.4.19"


def test_transitive_bazel_string_to_dependency_zstd(bazel_test):
    bazel_string = "@crate_index__zstd-sys-2.0.2-zstd.1.5.2//"
    dependency = bazel_test._BazelRustDependencyManager__transitive_bazel_string_to_dependency(bazel_string)
    assert dependency.name == "zstd-sys"
    assert dependency.version == "2.0.2"


def test_dependency_to_direct_bazel_string(bazel_test):
    dependency = Dependency(id="random_string", name="chrono", version="0.4.19", fix_version_for_vulnerability={})
    bazel_string = bazel_test._BazelRustDependencyManager__dependency_to_direct_bazel_string(dependency)
    assert bazel_string == "@crate_index//:chrono"


def test_versioned_dependency_to_direct_bazel_string(bazel_test):
    dependency = Dependency(id="random_string", name="rand", version="0.4.19", fix_version_for_vulnerability={})
    bazel_string = bazel_test._BazelRustDependencyManager__dependency_to_direct_bazel_string(dependency)
    assert bazel_string == "@crate_index//:rand_0_4_19"


def test_versioned_multi_name_dependency_to_direct_bazel_string(bazel_test):
    dependency = Dependency(id="random_string", name="rand_chacha", version="0.4.19", fix_version_for_vulnerability={})

    bazel_string = bazel_test._BazelRustDependencyManager__dependency_to_direct_bazel_string(dependency)
    assert bazel_string == "@crate_index//:rand_chacha_0_4_19"


def test_parse_vulnerable_dependency_from_cargo_audit(bazel_test):
    cargo_audit_out_slim = {
        "versions": {"patched": [">=0.2.23"], "unaffected": ["=0.2.0"]},
        "package": {"name": "time", "version": "0.1.44"},
    }
    dependency = bazel_test._BazelRustDependencyManager__parse_vulnerable_dependency_from_cargo_audit(
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

    dependency = bazel_test._BazelRustDependencyManager__parse_vulnerable_dependency_from_cargo_audit(
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

    vulnerability = bazel_test._BazelRustDependencyManager__parse_vulnerability_from_cargo_audit(cargo_audit_out_slim)
    assert vulnerability.id == "https://rustsec.org/advisories/RUSTSEC-2020-0071"
    assert vulnerability.name == "RUSTSEC-2020-0071"
    assert vulnerability.description == "Potential segfault in the time crate"
    assert vulnerability.score == 6


def test_parse_vulnerability_from_cargo_audit_with_no_cvss(bazel_test):
    cargo_audit_out_slim = {"id": "RUSTSEC-2020-0071", "title": "Potential segfault in the time crate", "cvss": None}

    vulnerability = bazel_test._BazelRustDependencyManager__parse_vulnerability_from_cargo_audit(cargo_audit_out_slim)
    assert vulnerability.id == "https://rustsec.org/advisories/RUSTSEC-2020-0071"
    assert vulnerability.name == "RUSTSEC-2020-0071"
    assert vulnerability.description == "Potential segfault in the time crate"
    assert vulnerability.score == -1


def test_parse_first_level_dependencies_and_projects_from_cargo_tree_one_project():
    cargo_tree_output = """some lines
that should be skipped
0vun-dep v1.2.3
1project v4.5.6 (/some/path/to/project)
    """
    dep = Dependency(id="vuln-dep", name="vuln-dep", version="1.2.3")
    executor = MockBazelCargoExecutor(expected_cargo_tree_deps=[dep], expected_cargo_tree_responses=[cargo_tree_output])
    bazel_test = BazelRustDependencyManager(executor=executor)

    first_lvl_deps, projects = bazel_test._BazelRustDependencyManager__get_first_level_dependencies_and_projects_from_cargo(dep, pathlib.PurePath('/some/path/to'))

    assert len(first_lvl_deps) == 0
    assert len(projects) == 1
    assert projects[0] == "to/project"


def test_parse_first_level_dependencies_and_projects_from_cargo_tree_one_dep_two_projects():
    cargo_tree_output = """some lines
that should be skipped
0vun-dep v1.2.3
1inter-dep v1
2inter-dep v2
3first-lvl-dep v0
4project1 v4.5.6 (/path/to/project/src/project1)
4project2 v7.8.9 (/path/to/project/src/project2)
    """
    dep = Dependency(id="vuln-dep", name="vuln-dep", version="1.2.3")
    executor = MockBazelCargoExecutor(expected_cargo_tree_deps=[dep], expected_cargo_tree_responses=[cargo_tree_output])
    bazel_test = BazelRustDependencyManager(executor=executor)

    first_lvl_deps, projects = bazel_test._BazelRustDependencyManager__get_first_level_dependencies_and_projects_from_cargo(dep, pathlib.PurePath('/path/to/project'))

    assert len(first_lvl_deps) == 1
    assert first_lvl_deps[0] == Dependency(id="https://crates.io/crates/first-lvl-dep", name="first-lvl-dep", version="0")
    assert len(projects) == 2
    projects.sort()
    assert projects[0] == "project/src/project1"
    assert projects[1] == "project/src/project2"


def test_parse_first_level_dependencies_and_projects_from_cargo_tree_two_deps_three_projects():
    cargo_tree_output = """0vun-dep v1.2.3
1inter-dep v1
2inter-dep v2
3first-lvl-dep v0
4project1 v4.5.6 (/path/to/project/src/project1)
5other-project-that-should-be-skipped v123 (/path/to/project/src/dont-care)
1first-lvl-dep v1 (https://some-project.url)
2project2 v7.8.9 (/path/to/project/src/project2)
3skip-me v456
1p3 v10 (/path/to/project/src/project3)
2skip-me-again v789 (https://another.project.url)
    """
    dep = Dependency(id="vuln-dep", name="vuln-dep", version="1.2.3")
    executor = MockBazelCargoExecutor(expected_cargo_tree_deps=[dep], expected_cargo_tree_responses=[cargo_tree_output])
    bazel_test = BazelRustDependencyManager(executor=executor)

    first_lvl_deps, projects = bazel_test._BazelRustDependencyManager__get_first_level_dependencies_and_projects_from_cargo(dep, pathlib.PurePath('/path/to/project'))

    assert len(first_lvl_deps) == 2
    first_lvl_deps = sorted(first_lvl_deps, key=lambda x: x.id)
    assert first_lvl_deps[0] == Dependency(id="first-lvl-dep", name="first-lvl-dep", version="1")
    assert first_lvl_deps[1] == Dependency(id="https://crates.io/crates/first-lvl-dep", name="first-lvl-dep", version="0")
    assert len(projects) == 3
    projects.sort()
    assert projects[0] == "project/src/project1"
    assert projects[1] == "project/src/project2"
    assert projects[2] == "project/src/project3"


def test_get_findings_for_cargo_only_repo():
    with open_test_file("test_data/cargo_audit_nns.json") as audit, open_test_file("test_data/cargo_tree_chrono.txt") as chrono, open_test_file("test_data/cargo_tree_time.txt") as time:
        expected_first_vulnerable_dep = Dependency(id='https://crates.io/crates/chrono', name='chrono', version='0.4.19',
                                                   fix_version_for_vulnerability={
                                                       'https://rustsec.org/advisories/RUSTSEC-2020-0159': [
                                                           '>=0.4.20']})
        expected_second_vulnerable_dep = Dependency(id='https://crates.io/crates/time', name='time', version='0.1.45',
                                                    fix_version_for_vulnerability={
                                                        'https://rustsec.org/advisories/RUSTSEC-2020-0071': ['>=0.2.23',
                                                                                                             '=0.2.0',
                                                                                                             '=0.2.1',
                                                                                                             '=0.2.2',
                                                                                                             '=0.2.3',
                                                                                                             '=0.2.4',
                                                                                                             '=0.2.5',
                                                                                                             '=0.2.6']})
        executor = MockBazelCargoExecutor(expected_cargo_audit_output=json.load(audit), expected_cargo_tree_deps=[expected_first_vulnerable_dep, expected_second_vulnerable_dep], expected_cargo_tree_responses=[chrono.read(), time.read()])
        bazel_test = BazelRustDependencyManager(executor=executor)

        findings = bazel_test.get_findings("nns-dapp", Project("nns-dapp", "nns-dapp"), None)

        assert findings is not None
        assert len(findings) == 2
        for finding in findings:
            assert finding.repository == "nns-dapp"
            assert finding.scanner == bazel_test.get_scanner_id()
            assert len(finding.projects) == 2
            assert finding.projects[0].endswith("nns-dapp/rs/backend")
            assert finding.projects[1].endswith("nns-dapp/rs/sns_aggregator")
            assert finding.risk_assessor == []
            assert finding.risk is None
            assert finding.patch_responsible == []
            assert finding.due_date is None
            assert finding.more_info is None

        # unique fields for first finding
        assert findings[0].vulnerable_dependency == expected_first_vulnerable_dep
        assert findings[0].vulnerabilities == [
            Vulnerability(id='https://rustsec.org/advisories/RUSTSEC-2020-0159', name='RUSTSEC-2020-0159',
                          description='Potential segfault in `localtime_r` invocations', score=-1)]
        assert findings[0].first_level_dependencies == [
            Dependency(id='cycles-minting-canister', name='cycles-minting-canister', version='0.8.0',
                       fix_version_for_vulnerability={}),
            Dependency(id='ic-nervous-system-common', name='ic-nervous-system-common', version='0.8.0',
                       fix_version_for_vulnerability={}),
            Dependency(id='ic-nervous-system-root', name='ic-nervous-system-root', version='0.1.0',
                       fix_version_for_vulnerability={}),
            Dependency(id='ic-nns-common', name='ic-nns-common', version='0.8.0',
                       fix_version_for_vulnerability={}),
            Dependency(id='ic-nns-governance', name='ic-nns-governance', version='0.8.0',
                       fix_version_for_vulnerability={}),
            Dependency(id='ic-sns-swap', name='ic-sns-swap', version='0.1.0',
                       fix_version_for_vulnerability={}),
            Dependency(id='ic-sns-wasm', name='ic-sns-wasm', version='1.0.0',
                       fix_version_for_vulnerability={}),
            Dependency(id='registry-canister', name='registry-canister', version='0.8.0',
                       fix_version_for_vulnerability={})]
        assert findings[0].score == -1

        # unique fields for second finding
        assert findings[1].vulnerable_dependency == expected_second_vulnerable_dep
        assert findings[1].vulnerabilities == [
            Vulnerability(id='https://rustsec.org/advisories/RUSTSEC-2020-0071', name='RUSTSEC-2020-0071',
                          description='Potential segfault in the time crate', score=6)]
        assert findings[1].first_level_dependencies == [
            Dependency(id='cycles-minting-canister', name='cycles-minting-canister', version='0.8.0',
                       fix_version_for_vulnerability={}),
            Dependency(id='https://crates.io/crates/chrono', name='chrono', version='0.4.19',
                       fix_version_for_vulnerability={}),
            Dependency(id='ic-nervous-system-common', name='ic-nervous-system-common', version='0.8.0',
                       fix_version_for_vulnerability={}),
            Dependency(id='ic-nervous-system-root', name='ic-nervous-system-root', version='0.1.0',
                       fix_version_for_vulnerability={}),
            Dependency(id='ic-nns-common', name='ic-nns-common', version='0.8.0',
                       fix_version_for_vulnerability={}),
            Dependency(id='ic-nns-governance', name='ic-nns-governance', version='0.8.0',
                       fix_version_for_vulnerability={}),
            Dependency(id='ic-sns-swap', name='ic-sns-swap', version='0.1.0',
                       fix_version_for_vulnerability={}),
            Dependency(id='ic-sns-wasm', name='ic-sns-wasm', version='1.0.0',
                       fix_version_for_vulnerability={}),
            Dependency(id='registry-canister', name='registry-canister', version='0.8.0',
                       fix_version_for_vulnerability={})]
        assert findings[1].score == 6


def test_get_findings_for_bazel_repo():
    with open_test_file("test_data/cargo_audit_ic.json") as audit, open_test_file("test_data/bazel_queries_ic.json") as bazel:
        bazel_query_and_responses = json.load(bazel)
        expected_queries = bazel_query_and_responses["queries"]
        expected_responses = bazel_query_and_responses["responses"]
        executor = MockBazelCargoExecutor(expected_cargo_audit_output=json.load(audit), expected_bazel_queries=expected_queries, expected_bazel_responses=expected_responses)
        bazel_test = BazelRustDependencyManager(executor=executor)

        findings = bazel_test.get_findings("ic", Project("ic", __test_get_ic_path()), None)

        assert findings is not None
        assert len(findings) == 3
        for finding in findings:
            assert finding.repository == "ic"
            assert finding.scanner == bazel_test.get_scanner_id()
            assert finding.risk_assessor == []
            assert finding.risk is None
            assert finding.patch_responsible == []
            assert finding.due_date is None
            assert finding.more_info is None

            # unique fields for first finding
            assert findings[0].vulnerable_dependency == Dependency(id='https://crates.io/crates/chrono', name='chrono',
                                                                   version='0.4.19',
                                                                   fix_version_for_vulnerability={
                                                                       'https://rustsec.org/advisories/RUSTSEC-2020-0159': [
                                                                           '>=0.4.20']})
            assert findings[0].vulnerabilities == [
                Vulnerability(id='https://rustsec.org/advisories/RUSTSEC-2020-0159', name='RUSTSEC-2020-0159',
                              description='Potential segfault in `localtime_r` invocations', score=-1)]
            assert findings[0].first_level_dependencies == [
                Dependency(id='https://crates.io/crates/build-info', name='build-info', version='0.0.26',
                           fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/build-info-build', name='build-info-build',
                           version='0.0.26', fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/cddl', name='cddl', version='0.9.1',
                           fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/cloudflare', name='cloudflare', version='0.9.1',
                           fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/log4rs', name='log4rs', version='1.2.0',
                           fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/prometheus-parse', name='prometheus-parse',
                           version='0.2.4', fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/rsa', name='rsa', version='0.4.0',
                           fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/simple_asn1', name='simple_asn1', version='0.5.4',
                           fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/x509-parser', name='x509-parser', version='0.12.0',
                           fix_version_for_vulnerability={})]
            assert findings[0].projects == ['ic/rs/backup', 'ic/rs/canister_client/sender', 'ic/rs/crypto', 'ic/rs/crypto/ecdsa_secp256k1', 'ic/rs/crypto/ecdsa_secp256r1', 'ic/rs/crypto/internal/crypto_lib/basic_sig/cose',
                                            'ic/rs/crypto/internal/crypto_lib/basic_sig/der_utils', 'ic/rs/crypto/internal/crypto_lib/basic_sig/ecdsa_secp256k1', 'ic/rs/crypto/internal/crypto_lib/basic_sig/ecdsa_secp256r1',
                                            'ic/rs/crypto/internal/crypto_lib/basic_sig/ed25519', 'ic/rs/crypto/internal/crypto_lib/basic_sig/iccsa', 'ic/rs/crypto/internal/crypto_lib/basic_sig/rsa_pkcs1',
                                            'ic/rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/der_utils', 'ic/rs/crypto/internal/crypto_service_provider', 'ic/rs/crypto/node_key_validation',
                                            'ic/rs/crypto/node_key_validation/tls_cert_validation', 'ic/rs/crypto/utils/basic_sig', 'ic/rs/elastic_common_schema', 'ic/rs/monitoring/logger', 'ic/rs/monitoring/onchain_observability/adapter',
                                            'ic/rs/nervous_system/common', 'ic/rs/nns/cmc', 'ic/rs/nns/governance', 'ic/rs/nns/gtc', 'ic/rs/nns/handlers/root/impl', 'ic/rs/nns/handlers/root/interface', 'ic/rs/nns/sns-wasm',
                                            'ic/rs/prep', 'ic/rs/registry/canister',
                                            'ic/rs/registry/nns_data_provider', 'ic/rs/rosetta-api', 'ic/rs/rosetta-api/icrc1/ledger/sm-tests', 'ic/rs/rosetta-api/ledger_canister_blocks_synchronizer',
                                            'ic/rs/rosetta-api/ledger_canister_blocks_synchronizer/test_utils', 'ic/rs/scenario_tests', 'ic/rs/sns/governance', 'ic/rs/sns/root', 'ic/rs/sns/swap', 'ic/rs/tests', 'ic/rs/types/types',
                                            'ic/rs/validator',
                                            'ic/rs/validator/http_request_test_utils']
            assert findings[0].score == -1

            # unique fields for second finding
            assert findings[1].vulnerable_dependency == Dependency(id='https://crates.io/crates/rocksdb', name='rocksdb',
                                                                   version='0.15.0', fix_version_for_vulnerability={
                    'https://rustsec.org/advisories/RUSTSEC-2022-0046': ['>=0.19.0']})
            assert findings[1].vulnerabilities == [
                Vulnerability(id='https://rustsec.org/advisories/RUSTSEC-2022-0046', name='RUSTSEC-2022-0046',
                              description='Out-of-bounds read when opening multiple column families with TTL',
                              score=-1)]
            assert findings[1].first_level_dependencies == []
            assert findings[1].projects == ['ic/rs/artifact_pool']
            assert findings[1].score == -1

            # unique fields for third finding
            assert findings[2].vulnerable_dependency == Dependency(id='https://crates.io/crates/time', name='time',
                                                                   version='0.1.45',
                                                                   fix_version_for_vulnerability={
                                                                       'https://rustsec.org/advisories/RUSTSEC-2020-0071': [
                                                                           '>=0.2.23',
                                                                           '=0.2.0',
                                                                           '=0.2.1',
                                                                           '=0.2.2',
                                                                           '=0.2.3',
                                                                           '=0.2.4',
                                                                           '=0.2.5',
                                                                           '=0.2.6']})
            assert findings[2].vulnerabilities == [
                Vulnerability(id='https://rustsec.org/advisories/RUSTSEC-2020-0071', name='RUSTSEC-2020-0071',
                              description='Potential segfault in the time crate', score=6)]
            assert findings[2].first_level_dependencies == [
                Dependency(id='https://crates.io/crates/build-info', name='build-info', version='0.0.26',
                           fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/build-info-build', name='build-info-build',
                           version='0.0.26', fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/cddl', name='cddl', version='0.9.1',
                           fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/chrono', name='chrono', version='0.4.19',
                           fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/cloudflare', name='cloudflare', version='0.9.1',
                           fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/log4rs', name='log4rs', version='1.2.0',
                           fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/prometheus-parse', name='prometheus-parse',
                           version='0.2.4', fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/rsa', name='rsa', version='0.4.0',
                           fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/simple_asn1', name='simple_asn1', version='0.5.4',
                           fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/thread_profiler', name='thread_profiler', version='0.3.0',
                           fix_version_for_vulnerability={}),
                Dependency(id='https://crates.io/crates/x509-parser', name='x509-parser', version='0.12.0',
                           fix_version_for_vulnerability={})]
            assert findings[2].projects == ['ic/rs/backup', 'ic/rs/canister_client/sender', 'ic/rs/crypto', 'ic/rs/crypto/ecdsa_secp256k1', 'ic/rs/crypto/ecdsa_secp256r1', 'ic/rs/crypto/internal/crypto_lib/basic_sig/cose',
                                            'ic/rs/crypto/internal/crypto_lib/basic_sig/der_utils', 'ic/rs/crypto/internal/crypto_lib/basic_sig/ecdsa_secp256k1', 'ic/rs/crypto/internal/crypto_lib/basic_sig/ecdsa_secp256r1',
                                            'ic/rs/crypto/internal/crypto_lib/basic_sig/ed25519', 'ic/rs/crypto/internal/crypto_lib/basic_sig/iccsa', 'ic/rs/crypto/internal/crypto_lib/basic_sig/rsa_pkcs1',
                                            'ic/rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/der_utils', 'ic/rs/crypto/internal/crypto_service_provider', 'ic/rs/crypto/node_key_validation',
                                            'ic/rs/crypto/node_key_validation/tls_cert_validation', 'ic/rs/crypto/utils/basic_sig', 'ic/rs/elastic_common_schema', 'ic/rs/monitoring/logger', 'ic/rs/monitoring/onchain_observability/adapter',
                                            'ic/rs/nervous_system/common', 'ic/rs/nns/cmc', 'ic/rs/nns/governance', 'ic/rs/nns/gtc', 'ic/rs/nns/handlers/root/impl', 'ic/rs/nns/handlers/root/interface', 'ic/rs/nns/sns-wasm',
                                            'ic/rs/prep', 'ic/rs/registry/canister', 'ic/rs/registry/nns_data_provider', 'ic/rs/replica', 'ic/rs/rosetta-api', 'ic/rs/rosetta-api/icrc1/ledger/sm-tests',
                                            'ic/rs/rosetta-api/ledger_canister_blocks_synchronizer', 'ic/rs/rosetta-api/ledger_canister_blocks_synchronizer/test_utils', 'ic/rs/scenario_tests', 'ic/rs/sns/governance', 'ic/rs/sns/root',
                                            'ic/rs/sns/swap', 'ic/rs/tests', 'ic/rs/types/types', 'ic/rs/validator', 'ic/rs/validator/http_request_test_utils']
            assert findings[2].score == 6


class MockBazelCargoExecutor(BazelCargoExecutor):

    def __init__(self, expected_cargo_audit_output: typing.Dict = (), expected_bazel_queries: typing.List[str] = (), expected_bazel_responses: typing.List[str] = (), expected_cargo_tree_deps: typing.List[Dependency] = (),
                 expected_cargo_tree_responses: typing.List[str] = ()):
        self.cargo_audit = expected_cargo_audit_output

        assert len(expected_bazel_queries) == len(expected_bazel_responses)
        self.bazel = {}
        for i in range(len(expected_bazel_queries)):
            assert expected_bazel_queries[i] not in self.bazel or self.bazel[expected_bazel_queries[i]] == expected_bazel_responses[i]
            self.bazel[expected_bazel_queries[i]] = expected_bazel_responses[i]

        assert len(expected_cargo_tree_deps) == len(expected_cargo_tree_responses)
        self.cargo_tree = {}
        for i in range(len(expected_cargo_tree_deps)):
            dep_key = self.__dependency_key(expected_cargo_tree_deps[i])
            assert dep_key not in self.cargo_tree
            self.cargo_tree[dep_key] = expected_cargo_tree_responses[i]

    @staticmethod
    def __dependency_key(dependency: Dependency):
        return f"{dependency.id}:{dependency.version}"

    def get_bazel_query_output(self, bazel_query: str, path: pathlib.Path) -> str:
        assert bazel_query in self.bazel
        return self.bazel[bazel_query]

    def get_cargo_audit_output(self, path: pathlib.Path, cargo_home=None) -> typing.Dict:
        return self.cargo_audit

    def get_cargo_tree_output_for_vulnerable_dependency(self, vulnerable_dependency: Dependency, path: pathlib.Path,
                                                        cargo_home=None) -> str:
        dep_key = self.__dependency_key(vulnerable_dependency)
        assert dep_key in self.cargo_tree
        return self.cargo_tree[dep_key]
