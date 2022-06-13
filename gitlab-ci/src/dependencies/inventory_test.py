"""Test package for dependency inventory."""
import dataclasses
import os
import pathlib
import shutil
import stat
import tempfile
import typing
import zipfile
from urllib import request

import git
import inventory
import pytest

# TODO : remove once s3 link is replaced.
pytestmark = pytest.mark.skip(reason="Skipping until the S3 link is fixed")

TEST_DATA = pathlib.Path(__file__).parent / "test_data"
BUCKET = "dfinity-adhoc"
PREFIX = "vuln-deps/"

# TODO : replace with s3 link
TEST_CARGO = ""
CARGO_HOME_DOWNLOAD_LINK = "http://localhost:80/cargo_home2.zip"


def test_dfinity_repo_is_owned():
    """Assert repos under dfinity/ org are considered owned."""
    assert inventory.is_owned_path("https://github.com/dfinity/motoko")


def test_dfinity_lab_repo_is_owned():
    """Assert repos under dfinity-lab/ org are considered owned."""
    assert inventory.is_owned_path("https://gitlab.com/dfinity-lab/core/ic")


def test_local_path_is_owned():
    """Assert local packages are considered owned."""
    assert inventory.is_owned_path("/build/src/dfinity-lab/dfinity/rs/config")


def test_other_repos_not_owned():
    """Assert other repos are not owned."""
    assert not inventory.is_owned_path("https://github.com/dfinity-fake/motoko")
    assert not inventory.is_owned_path("https://github.com/rust-lang/rust")
    assert not inventory.is_owned_path("https://fake-gitlab.com/dfinity-lab/core/ic")


def test_dependency_compare():
    """Assert dependencies with the same package and version are equal."""
    d1 = inventory.Dependency("package1", "1.2.0")
    d2 = inventory.Dependency("package1", "1.2.2")
    d3 = inventory.Dependency("package2", "1.2.0")
    d4 = inventory.Dependency("package1", "1.2.0", is_external=False)

    # For owners wrt internal crates
    d5 = inventory.Dependency(
        "package1", "1.2.0", is_external=False, owner=[("TEAM", "@dfinity-lab/teams/networking-team")]
    )
    d6 = inventory.Dependency(
        "package2", "1.2.0", is_external=False, owner=[("TEAM", "@dfinity-lab/teams/networking-team")]
    )

    assert d1 != d2
    assert d1 != d3
    assert d1 == d4
    assert d5 != d6


def test_dependency_from_cargo_line():
    """Verify building dependency objects from cargo tree output."""
    d = inventory.Dependency.from_cargo_tree("tokio-util v0.3.1")
    assert d.name == "tokio-util" and d.version == "0.3.1" and d.is_external

    d = inventory.Dependency.from_cargo_tree("tokio-util v0.3.1 (*)")
    assert d.name == "tokio-util" and d.version == "0.3.1" and d.is_external

    d = inventory.Dependency.from_cargo_tree("tokio-util v0.3.1 (https://not-dfinity/repo)")
    assert d.name == "tokio-util" and d.version == "0.3.1" and d.is_external

    d = inventory.Dependency.from_cargo_tree("ic-config v0.3.1 (/local)")
    assert d.name == "ic-config" and d.version == "0.3.1" and not d.is_external

    d = inventory.Dependency.from_cargo_tree(f"orchestrator v0.8.0 ({inventory.PROJECT_ROOT}/rs/orchestrator)")
    assert (
        d.name == "orchestrator"
        and d.version == "0.8.0"
        and not d.is_external
        and d.owner == [("TEAM", "@dfinity-lab/teams/orchestrator-owners")]
    )

    d = inventory.Dependency.from_cargo_tree(f"ic-prep v0.8.0 ({inventory.PROJECT_ROOT}/rs/prep)")
    assert d.name == "ic-prep" and d.version == "0.8.0" and not d.is_external and d.owner == []

    with pytest.raises(ValueError):
        # Receives an empty line
        d = inventory.Dependency.from_cargo_tree("")

    with pytest.raises(ValueError):
        # Missing v in version.
        d = inventory.Dependency.from_cargo_tree("ic-config 0.3.1")


def test_package_diff_empty():
    """Verify package diff empty checks are correct."""
    pd = inventory.PackageDiff(name="Diff")
    assert pd.is_empty()

    d = inventory.Dependency(name="tokio-util", version="0.3.1")
    pd.added_deps.add(d)
    assert not pd.is_empty()

    pd.added_deps.clear()
    pd.removed_deps.add(d)
    assert not pd.is_empty()

    pd.removed_deps.clear()
    pd.added_direct_deps.add(d)
    assert not pd.is_empty()

    pd.added_direct_deps.clear()
    pd.removed_direct_deps.add(d)
    assert not pd.is_empty()


class FakeCargo(inventory.Cargo):
    """Fake cargo helper that accepts path to the inventory under TEST_DATA."""

    def __init__(self, inv_path, diffs={}, inv_changed=True, external_direct_deps={}):
        """Init with test data."""
        self.inv_path = TEST_DATA / inv_path
        self.diffs = diffs
        self.inv_changed = inv_changed
        self.external_direct_deps = external_direct_deps

    def get_inventory_file(self):
        """Return path to the test inventory file."""
        return self.inv_path

    def get_package_diff(self):
        """Return empty dict."""
        return self.diffs

    def inventory_changed(self):
        """Return True."""
        return self.inv_changed

    def get_external_direct_deps(self):
        """Return empty dict."""
        return self.external_direct_deps


def test_cargo_duplicate_line():
    """Verify duplicate lines are detected correctly in cargo tree output."""
    assert inventory.Cargo.is_duplicate_line("1url v2.2.0 (*)")
    assert inventory.Cargo.is_duplicate_line("1wabt v0.10.0 (https://github.com/dfinity-lab/wabt-rs) (*)")
    assert not inventory.Cargo.is_duplicate_line("2delay v0.3.1")


def test_cargo_parse_depth():
    """Verify dependency depth is parsed correctly in cargo tree output."""
    assert (2, "delay v0.3.1") == inventory.Cargo.parse_depth("2delay v0.3.1")
    assert (
        0,
        "tests v0.1.0 (/build/src/dfinity/rs/tests)",
    ) == inventory.Cargo.parse_depth("0tests v0.1.0 (/build/src/dfinity/rs/tests)")


def setup_git_repo(tmpdir, testcase):
    """Set up git repo for the given testcase."""
    # Delete this env var as git_changes will use it to assume the target branch when
    # this test runs in CI.
    if "CI_MERGE_REQUEST_TARGET_BRANCH_NAME" in os.environ:
        del os.environ["CI_MERGE_REQUEST_TARGET_BRANCH_NAME"]

    r = git.Repo.init(tmpdir, bare=False)
    r.config_writer().set_value("user", "name", "myusername").release()
    r.config_writer().set_value("user", "email", "myemail").release()
    shutil.copytree(TEST_DATA / testcase / "before", tmpdir, dirs_exist_ok=True)
    r.git.add("-A")
    r.git.commit("-m initial commit")
    r.git.checkout("HEAD", b="feature_branch")
    for p in pathlib.Path(tmpdir).iterdir():
        if p.name == ".git":
            continue
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()
    shutil.copytree(TEST_DATA / testcase / "after", tmpdir, dirs_exist_ok=True)
    r.git.add("-A")
    r.git.commit("--allow-empty", "-m feature commit")
    return r


def setup_cargo_home():
    global TEST_CARGO
    if os.path.isdir(TEST_CARGO):
        return
    else:
        tmpdir = tempfile.mkdtemp()
        TEST_CARGO = pathlib.Path(tmpdir) / "test_data"
        os.mkdir(TEST_CARGO)
        _ = request.urlretrieve(
            url=CARGO_HOME_DOWNLOAD_LINK, filename=pathlib.Path(TEST_CARGO / "cargo_home.zip").as_posix()
        )
        with zipfile.ZipFile(TEST_CARGO / "cargo_home.zip", "r") as zip_ref:
            zip_ref.extractall(TEST_CARGO)
            os.remove(TEST_CARGO / "cargo_home.zip")
            os.chmod(TEST_CARGO / "cargo_home/bin/cargo", stat.S_IXUSR)
            os.chmod(TEST_CARGO / "cargo_home/bin/cargo-audit", stat.S_IXUSR)
    return


class LocalCargo(inventory.Cargo):
    """Cargo patched up to use a local crate registry."""

    def _get_cargo_tree_output(self, package=None, invert_deps=None):
        return super()._get_cargo_tree_output(
            package=package,
            offline=True,
            cargo_home=pathlib.Path(TEST_CARGO / "cargo_home").as_posix(),
            invert_deps=invert_deps,
        )

    def _get_cargo_audit_output(self, cargo_home=None):
        return super()._get_cargo_audit_output(cargo_home=pathlib.Path(TEST_CARGO / "cargo_home").as_posix())


def test_cargo_get_package_diff(tmpdir):
    """Check package diffs are reported correctly."""
    setup_git_repo(tmpdir, "package_diff")
    setup_cargo_home()
    inventory.USE_NIX_SHELL = False
    cargo = LocalCargo(root=tmpdir)

    assert cargo.get_package_diff() == {
        "ic-fake1": inventory.PackageDiff(
            name="ic-fake1",
            added_deps=set(),
            removed_deps={
                inventory.Dependency(name="futures-util", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="futures", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="futures-core", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="proc-macro-nested", version="0.1.7", owner=[], is_external=True),
                inventory.Dependency(name="pin-utils", version="0.1.0", owner=[], is_external=True),
                inventory.Dependency(name="futures-sink", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="futures-task", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="pin-project-lite", version="0.2.6", owner=[], is_external=True),
                inventory.Dependency(name="slab", version="0.4.2", owner=[], is_external=True),
                inventory.Dependency(name="futures-channel", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="futures-executor", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="ic-fake2", version="0.1.0", owner=[], is_external=False),
                inventory.Dependency(name="futures-io", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="memchr", version="2.3.4", owner=[], is_external=True),
            },
            added_direct_deps=set(),
            removed_direct_deps=set(),
        ),
        "ic-fake2": inventory.PackageDiff(
            name="ic-fake2",
            added_deps={inventory.Dependency(name="bytes", version="0.5.6", owner=[], is_external=True)},
            removed_deps=set(),
            added_direct_deps={inventory.Dependency(name="bytes", version="0.5.6", owner=[], is_external=True)},
            removed_direct_deps=set(),
        ),
    }


def test_cargo_get_package_diff_new_toml(tmpdir):
    """Check package diffs are reported correctly if Cargo.toml was added."""
    setup_git_repo(tmpdir, "package_diff_new_toml")
    setup_cargo_home()

    inventory.USE_NIX_SHELL = False
    cargo = LocalCargo(root=tmpdir)

    assert cargo.get_package_diff() == {
        "ic-fake2": inventory.PackageDiff(
            name="ic-fake2",
            added_deps={
                inventory.Dependency(name="futures", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="futures-util", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="futures-core", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="pin-project-lite", version="0.2.6", owner=[], is_external=True),
                inventory.Dependency(name="futures-task", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="futures-channel", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="pin-utils", version="0.1.0", owner=[], is_external=True),
                inventory.Dependency(name="futures-sink", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="proc-macro-nested", version="0.1.7", owner=[], is_external=True),
                inventory.Dependency(name="futures-io", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="slab", version="0.4.2", owner=[], is_external=True),
                inventory.Dependency(name="futures-executor", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="memchr", version="2.3.4", owner=[], is_external=True),
            },
            removed_deps=set(),
            added_direct_deps={inventory.Dependency(name="futures", version="0.3.13", owner=[], is_external=True)},
            removed_direct_deps=set(),
        )
    }


def test_cargo_get_package_diff_remove_toml(tmpdir):
    """Check package diffs are reported correctly if Cargo.toml was removed."""
    setup_git_repo(tmpdir, "package_diff_remove_toml")
    setup_cargo_home()

    inventory.USE_NIX_SHELL = False
    cargo = LocalCargo(root=tmpdir)

    assert cargo.get_package_diff() == {
        "ic-fake2": inventory.PackageDiff(
            name="ic-fake2",
            added_deps=set(),
            removed_deps={
                inventory.Dependency(name="pin-project-lite", version="0.2.6", owner=[], is_external=True),
                inventory.Dependency(name="proc-macro-nested", version="0.1.7", owner=[], is_external=True),
                inventory.Dependency(name="memchr", version="2.3.4", owner=[], is_external=True),
                inventory.Dependency(name="futures-executor", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="futures-sink", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="futures-channel", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="futures-task", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="futures-util", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="slab", version="0.4.2", owner=[], is_external=True),
                inventory.Dependency(name="futures-core", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="futures-io", version="0.3.13", owner=[], is_external=True),
                inventory.Dependency(name="pin-utils", version="0.1.0", owner=[], is_external=True),
                inventory.Dependency(name="futures", version="0.3.13", owner=[], is_external=True),
            },
            added_direct_deps=set(),
            removed_direct_deps={inventory.Dependency(name="futures", version="0.3.13", owner=[], is_external=True)},
        )
    }


def test_get_vulnerable_dependencies(tmpdir):
    """Check vulnerable dependencies are correctly identified."""
    shutil.copytree(TEST_DATA / "vulnerable_deps", tmpdir, dirs_exist_ok=True)
    setup_cargo_home()

    inventory.USE_NIX_SHELL = False

    cargo = LocalCargo(root=tmpdir)

    set_ic_vulnerable1 = []
    set_ic_vulnerable2 = []
    set_ic_vulnerable1.append(
        dataclasses.asdict(
            inventory.PackageVulnerableDependency(
                package_name="ic-vulnerable1:0.1.0",
                is_vulnerable_dependency_direct=False,
                direct_dependency=inventory.Dependency(name="prost-build", version="0.7.0", is_external=True, owner=[]),
                vulnerable_dependency=inventory.Dependency(
                    name="prost-types", version="0.7.0", is_external=True, owner=[]
                ),
                risk_rating=inventory.RiskRating(40),
                dependency_chain=["prost-build:0.7.0"],
                codeowner="",
                reason="Conversion from `prost_types::Timestamp` to `SystemTime` can cause an overflow and panic Affected versions of this crate contained a bug in which untrusted input could cause an overflow and panic when converting a `Timestamp` to `SystemTime`.\n\nIt is recommended to upgrade to `prost-types` v0.8 and switch the usage of `From<Timestamp> for SystemTime` to `TryFrom<Timestamp> for SystemTime`.\n\nSee [#438] for more information.\n\n[#438]: https://github.com/tokio-rs/prost/issues/438",
                fix=[">=0.8.0"],
            )
        )
    )
    set_ic_vulnerable1.append(
        dataclasses.asdict(
            inventory.PackageVulnerableDependency(
                package_name="ic-vulnerable1:0.1.0",
                is_vulnerable_dependency_direct=True,
                direct_dependency=inventory.Dependency(name="wasmtime", version="0.29.0", is_external=True, owner=[]),
                vulnerable_dependency=inventory.Dependency(
                    name="wasmtime", version="0.29.0", is_external=True, owner=[]
                ),
                risk_rating=inventory.RiskRating(40),
                codeowner="",
                reason="Multiple Vulnerabilities in Wasmtime * [Use after free passing `externref`s to Wasm in\n  Wasmtime](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-v4cp-h94r-m7xf)\n\n* [Out-of-bounds read/write and invalid free with `externref`s and GC safepoints\n  in\n  Wasmtime](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-4873-36h9-wv49)\n\n* [Wrong type for `Linker`-define functions when used across two\n  `Engine`s](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-q879-9g95-56mx)",
                fix=[">=0.30.0"],
            )
        )
    )

    set_ic_vulnerable2.append(
        dataclasses.asdict(
            inventory.PackageVulnerableDependency(
                package_name="ic-vulnerable2:0.1.0",
                is_vulnerable_dependency_direct=True,
                direct_dependency=inventory.Dependency(name="tiny_http", version="0.7.0", is_external=True, owner=[]),
                vulnerable_dependency=inventory.Dependency(
                    name="tiny_http", version="0.7.0", is_external=True, owner=[]
                ),
                risk_rating=inventory.RiskRating(40),
                codeowner="",
                reason="HTTP Request smuggling through malformed Transfer Encoding headers HTTP pipelining issues and request smuggling attacks are possible due to incorrect \nTransfer encoding header parsing.\n\nIt is possible conduct HTTP request smuggling attacks (CL:TE/TE:TE) by sending invalid Transfer Encoding headers. \n\nBy manipulating the HTTP response the attacker could poison a web-cache, perform an XSS attack, or obtain sensitive information \nfrom requests other than their own.",
                fix=[">=0.8.0", "^0.6.3"],
            )
        )
    )

    expected: typing.Dict[str, typing.List[typing.Dict]] = {
        "ic-vulnerable1:0.1.0": set_ic_vulnerable1,
        "ic-vulnerable2:0.1.0": set_ic_vulnerable2,
    }
    result = cargo.get_vulnerable_dependencies()
    assert result["metadata"] == ["prost-types:0.7.0", "tiny_http:0.7.0", "wasmtime:0.29.0"]
    assert result["ic-vulnerable1:0.1.0"] == expected["ic-vulnerable1:0.1.0"]
    assert result["ic-vulnerable2:0.1.0"] == expected["ic-vulnerable2:0.1.0"]
