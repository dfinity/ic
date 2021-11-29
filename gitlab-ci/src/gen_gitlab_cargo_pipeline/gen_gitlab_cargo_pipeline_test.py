"""
Tests for the gen_gitlab_cargo_pipeline module.

See 'run_test' for detailed description of how the tests are run.

Test cases are taken from ./test_data/${testcase}. The before and after subdirs represent
the state of the git repo before and after. To see the files that have changes run:

    diff -r before/ after/

Typical example usage:

    pytest tests.py
"""
import difflib
import filecmp
import os
import shutil

from git import Repo

import gen_gitlab_cargo_pipeline


def run_test(tmpdir, testcase, branch="feature_branch"):
    """
    Run the test defined in testdata/${testcase}.

    Performs the following operations.

        1. Create a new git repo in tmpdir.
        2. Copy testcases/before to tmpdir/rs/.
        3. Git commit the changes to master.
        4. Git creates a new feature branch.
        5. Copy testcases/after to tmpdir/rs/.
        6. Git commit to the feature branch.
        7. Run gen_gitlab_cargo_pipeline.generate_tests against tmpdir/rs
        8. Compare testcases/before/expected.yml to the generated GitLab YAML config.

    The the test fails, print a path to the expected and generated YAML file and output the file
    diff.

    Args:
    ----
        tmpdir: A temporary directory for the test to use.
        testcase: A string that corresponds to a testcase under the test_data subdir.
        branch: A string that corresponds to the git branch to use for the test.

    """
    path = os.path.dirname(os.path.abspath(__file__))

    repo = Repo.init(tmpdir, bare=False)
    repo.config_writer().set_value("user", "name", "myusername").release()
    repo.config_writer().set_value("user", "email", "myemail").release()

    git = repo.git
    shutil.copytree(os.path.join(path, "test_data", testcase, "before"), tmpdir, dirs_exist_ok=True)
    git.add("-A")
    git.commit("-m initial commit")

    if branch != "master":
        git.checkout("HEAD", b=branch)

    for d in [f"{tmpdir}/rs", f"{tmpdir}/experimental"]:
        if os.path.isdir(d):
            shutil.rmtree(d)
    shutil.copytree(os.path.join(path, "test_data", testcase, "after"), tmpdir, dirs_exist_ok=True)
    git.add("-A")
    git.commit("--allow-empty", "-m feature commit")

    out_filename = os.path.join(tmpdir, "cargo-tests.yml")

    # Remove some some env variables when running tests on CI.
    if "CI_COMMIT_REF_NAME" in os.environ:
        # Make cargo_deps grab the git branch from git and not the env var.
        del os.environ["CI_COMMIT_REF_NAME"]

        # Remove the CI_PIPELINE_ID so that gen cargo pipeline doesn't generate PARENT_PIPELIEN_ID
        # global variable in the CI config. This existance of this env variable is inconsistent
        # across local development test runs and CI tests.
        if "CI_PIPELINE_ID" in os.environ:
            del os.environ["CI_PIPELINE_ID"]

        # Remove CI_MERGE_REQUEST_TITLE from the test suite. This will cause failures on MRs marked
        # with "lessci", because this python test will inherit that value and thus no cargo pipelines
        # will be generated.
        if "CI_MERGE_REQUEST_TITLE" in os.environ:
            del os.environ["CI_MERGE_REQUEST_TITLE"]

        if "CI_MERGE_REQUEST_EVENT_TYPE" in os.environ:
            del os.environ["CI_MERGE_REQUEST_EVENT_TYPE"]

        # Remove CI_MERGE_REQUEST_EVENT_TYPE from the test suite. This will cause the tests to fail
        # while in a merge train.
        if "CI_MERGE_REQUEST_TITLE" in os.environ:
            del os.environ["CI_MERGE_REQUEST_EVENT_TYPE"]

        if "CI_MERGE_REQUEST_TARGET_BRANCH_NAME" in os.environ:
            del os.environ["CI_MERGE_REQUEST_TARGET_BRANCH_NAME"]

    if "CI_COMMIT_REF_PROTECTED" in os.environ:
        del os.environ["CI_COMMIT_REF_PROTECTED"]

    if branch == "master":
        os.environ["CI_COMMIT_REF_PROTECTED"] = "true"

    with open(out_filename, "w") as fout:
        gen_gitlab_cargo_pipeline.generate_tests(
            os.path.join(tmpdir, "rs"),
            os.path.join(tmpdir, "ic-os", "guestos"),
            fout,
            dry_run=True,
            cargo_sample_size=1,
        )

    wantf = os.path.join(path, "test_data", testcase, "expected.yml")

    if not filecmp.cmp(out_filename, wantf):
        with open(out_filename) as file1:
            f1_text = file1.readlines()
        with open(wantf) as file2:
            f2_text = file2.readlines()
        # Find and print the diff:
        assert False, out_filename + " != " + wantf + " \n" + "".join(difflib.ndiff(f1_text, f2_text))


def test_change_two_crates(tmpdir):
    """Tests that a commit has changed two independent crates."""
    run_test(tmpdir, "change_two_crates")


def test_change_one_crate(tmpdir):
    """Tests that a commit has changed one crate."""
    run_test(tmpdir, "change_one_crate")


def test_transitive(tmpdir):
    """Tests that a commit has changed a base crate that two leaf crates transitively depend on."""
    run_test(tmpdir, "transitive")


def test_master(tmpdir):
    """Tests that a when run on master branch, the entire workspace is always tested."""
    run_test(tmpdir, "all_crates_on_master", "master")


def test_no_op(tmpdir):
    """Tests when nothing has changed."""
    run_test(tmpdir, "no_op")


def test_allow_to_fail(tmpdir):
    """Tests when nothing has changed."""
    gen_gitlab_cargo_pipeline.CRATES_ALLOWED_TO_FAIL = ["foo"]
    run_test(tmpdir, "allow_crate_to_fail")


def test_change_crate_not_in_workspace(tmpdir):
    """Tests when a crate has changed, but it doesn't belong to the Rust workspace."""
    run_test(tmpdir, "change_crate_not_in_workspace")


def test_override_crate_test_name(tmpdir):
    """Tests when a crate has changed, but it doesn't belong to the Rust workspace."""
    run_test(tmpdir, "override_crate_test_name")


def test_delete_crate(tmpdir):
    """A disappeared directory doesn't cause crashes."""
    run_test(tmpdir, "delete_crate")


def test_ic_types(tmpdir):
    """Test that changes to ic-types don't create tests for crates that depend on ic-types:0.1.1."""
    run_test(tmpdir, "ic-types-check")


def test_ci_config_change_workspace(tmpdir):
    """Workspace Cargo.toml changes cause all crates to rebuild."""
    run_test(tmpdir, "ci_config_change_workspace")


def test_ci_config_change_src_gitlab_ci_config(tmpdir):
    """Source changes cause all crates to rebuild."""
    run_test(tmpdir, "ci_config_change_src1")


def test_ci_config_change_src_gitlab_ci_src(tmpdir):
    """Source changes cause all crates to rebuild."""
    run_test(tmpdir, "ci_config_change_src2")


def test_guestos_change(tmpdir):
    """Source changes cause all crates to rebuild."""
    run_test(tmpdir, "guestos_change")


def test_ci_and_crate_change(tmpdir):
    """Source changes cause all crates to rebuild."""
    run_test(tmpdir, "ci_and_crate_change")


def test_nix_change(tmpdir):
    """
    Source changes cause all crates to rebuild.

    diff -r nix_change/before/rs/foo.nix nix_change/after/rs/foo.nix
    1a2
    > # touch me
    """
    run_test(tmpdir, "nix_change")


def test_nix_and_crate_change(tmpdir):
    """
    Source changes cause all crates to rebuild.

    diff -r nix_and_crate_change/before/rs/foo/src/main.rs nix_and_crate_change/after/rs/foo/src/main.rs
    0a1
    > # Touch
    diff -r nix_and_crate_change/before/rs/foo.nix nix_and_crate_change/after/rs/foo.nix
    1c1
    <
    ---
    > # touch me
    """
    run_test(tmpdir, "nix_and_crate_change")


def test_nix_changes_outside_rs(tmpdir):
    """
    Changing a nix file outside rs dir should cause a rebuild.

    diff -r nix_changes_outside_rs/before/foo.nix nix_changes_outside_rs/after/foo.nix
    1a2
    > # touch me
    """
    run_test(tmpdir, "nix_changes_outside_rs")


def test_log_rdeps():
    """One case failed in production."""
    marked_crate_to_dep = {
        "ic-artifact-pool": None,
        "ic-types": None,
        "ic-config": None,
        "canister-test": "candid",
        "canister_sandbox": "ic-config",
        "cycles_transfer": "canister-test",
        "dfn_candid": "candid",
        "dfn_core": "canister-test",
        "dfn_http": "candid",
        "ic-admin": "candid",
        "ic-artifact-manager": "ic-artifact-pool",
        "ic-base-types": "candid",
        "ic-canister-client": "ic-types",
        "ic-canister-sandbox-common": "ic-types",
        "ic-canister-sandbox-replica-controller": "ic-canister-sandbox-common",
        "ic-canonical-state": "ic-types",
        "ic-consensus": "ic-artifact-pool",
        "ic-consensus-message": "ic-types",
        "ic-crypto": "ic-config",
        "ic-crypto-internal-basic-sig-ed25519": "ic-types",
        "ic-crypto-internal-csp": "ic-config",
        "ic-crypto-internal-csp-test-utils": "ic-crypto-internal-csp",
        "ic-crypto-key-validation": "ic-base-types",
        "ic-crypto-lib": "ic-types",
        "ic-crypto-test-utils": "ic-crypto-internal-csp-test-utils",
        "ic-crypto-tls-interfaces": "ic-types",
        "ic-cup-explorer": "ic-canister-client",
        "ic-drun": "ic-config",
        "ic-embedders": "ic-canister-sandbox-common",
        "ic-error-types": "candid",
        "ic-execution-environment": "candid",
        "ic-fondue": "canister-test",
        "ic-http-handler": "candid",
        "ic-ic00-types": "candid",
        "ic-ingress-manager": "ic-artifact-pool",
        "ic-interfaces": "ic-types",
        "ic-logger": "ic-config",
        "ic-messaging": "ic-config",
        "ic-metrics": "ic-config",
        "ic-nns-candid": "candid",
        "ic-nns-common": "candid",
        "ic-nns-constants": "ic-base-types",
        "ic-nns-gtc": "canister-test",
        "ic-nns-handler-node": "candid",
        "ic-nns-handler-node-operator": "candid",
        "ic-nns-handler-root": "candid",
        "ic-nns-handler-subnet": "candid",
        "ic-nns-handler-upgrades": "candid",
        "ic-nns-init": "canister-test",
        "ic-nns-integration-tests": "candid",
        "ic-nns-neurons": "candid",
        "ic-nns-proposals": "candid",
        "ic-nns-rewards": "candid",
        "ic-nns-test-utils": "candid",
        "ic-nns-tests": "dfn_core",
        "ic-p2p": "ic-artifact-manager",
        "ic-p8s-service-discovery": "ic-metrics",
        "ic-prep": "ic-crypto",
        "ic-prober": "ic-canister-client",
        "ic-registry-client": "ic-config",
        "ic-registry-common": "ic-canister-client",
        "ic-registry-keys": "ic-base-types",
        "ic-registry-provisional-whitelist": "ic-base-types",
        "ic-registry-routing-table": "candid",
        "ic-registry-subnet-type": "candid",
        "ic-registry-transport": "candid",
        "ic-release": "ic-types",
        "ic-replica": "candid",
        "ic-replica-tests": "ic-base-types",
        "ic-replicated-state": "ic-interfaces",
        "ic-rosetta-api": "candid",
        "ic-scenario-tests": "canister-test",
        "ic-sdk": "ic-config",
        "ic-starter": "ic-config",
        "ic-state-layout": "ic-logger",
        "ic-state-manager": "ic-canonical-state",
        "ic-state-tool": "ic-config",
        "ic-system-api": "ic-interfaces",
        "ic-test-artifact-pool": "ic-artifact-pool",
        "ic-test-utilities": "ic-artifact-pool",
        "ic-transport": "ic-config",
        "ic-types-test-utils": "ic-types",
        "ic-utils": "candid",
        "ic-validator": "ic-crypto",
        "ic-wasm-types": "ic-utils",
        "ic-wasm-utils": "ic-wasm-types",
        "ic-workload-generator": "ic-canister-client",
        "ledger-canister": "candid",
        "lifeline": "candid",
        "memory_tracker": "ic-logger",
        "nodemanager": "candid",
        "phantom_newtype": "candid",
        "pmap": "canister-test",
        "registry-canister": "candid",
        "runtime": "ic-canister-sandbox-replica-controller",
        "rust-canister-tests": "candid",
        "statesync-test": "canister-test",
        "tests": "candid",
        "wallet": "ic-canister-client",
        "web-server": "canister-test",
        "xnet-test": "candid",
        "ic-cow-state": "ic-utils",
        "ic-crypto-internal-logmon": "ic-metrics",
        "ic-crypto-internal-types": "phantom_newtype",
        "ic-crypto-tree-hash": "ic-crypto-internal-types",
        "ic-http-utils": "ic-logger",
        "ic-identity": "ic-crypto-internal-types",
        "tree-deserializer": "ic-crypto-tree-hash",
        "ic-crypto-basic-sig-ed25519": "ic-crypto-internal-types",
        "ic-crypto-internal-cryptolib-bls12381-serde-miracl": "ic-crypto-internal-types",
        "ic-crypto-internal-fs-ni-dkg": "ic-crypto-internal-cryptolib-bls12381-serde-miracl",
        "ic-crypto-basic-sig": "ic-crypto-basic-sig-ed25519",
        "ic-crypto-core": "ic-crypto-basic-sig",
    }
    gen_gitlab_cargo_pipeline.log_rdeps(marked_crate_to_dep)
