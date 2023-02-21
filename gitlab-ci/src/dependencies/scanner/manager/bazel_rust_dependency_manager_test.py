import pytest
from model.dependency import Dependency
from scanner.manager.bazel_rust_dependency_manager import BazelRustDependencyManager

# Bazel tests


@pytest.fixture
def bazel_test():
    return BazelRustDependencyManager()


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


def test_transitive_bazel_string_to_dependency_hypenated(bazel_test):
    bazel_string_hypenated_crate = "@crate_index__build-info-common-0.4.19//"
    dependency = bazel_test._BazelRustDependencyManager__transitive_bazel_string_to_dependency(
        bazel_string_hypenated_crate
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


# TODO : Add test for bazel outputs and findings
