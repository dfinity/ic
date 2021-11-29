"""Test package for dependency inventory."""
import os
import pathlib
import shutil

import git
import inventory
import pytest


TEST_DATA = pathlib.Path(__file__).parent / "test_data"


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
    assert d1 != d2
    assert d1 != d3
    assert d1 == d4


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


def test_diff_delta_numbers():
    """Verify correct numbers are calculated for diff delta."""
    delta = inventory.PackageDiffDelta(total_added=123, total_removed=100, internal_added=77, internal_removed=60)
    assert delta.get_total_delta() == 23
    assert delta.get_internal_delta() == 17


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


def test_inventory_nothing_changed():
    """Verify inventory returns no errors if no dependencies changed."""

    class NoChanges(inventory.Cargo):
        """Fake cargo with no changes."""

        def inventory_changed(self):
            """Return False."""
            return False

        def get_package_diff(self):
            """Return empty dict."""
            return {}

    inv = inventory.Inventory(NoChanges())
    errors = inv.validate()
    assert not errors


def test_inventory_too_few_owners():
    """Assert validation fails if there is only one dependency owner."""
    inv = inventory.Inventory(FakeCargo("one_owner.json"))
    errors = inv.validate()
    assert errors == [
        inventory.Inventory.Error(
            message="JSON Schema validation failed with the following error:\n"
            "[{'email': 'foo@example.com'}] is too short\n"
            "The schema can be found here: gitlab-ci/src/dependencies/inventory.schema.",
            is_fatal=True,
        )
    ]


def test_inventory_no_errors():
    """Assert no errors reported if inventory matches the dependecy tree."""
    inv = inventory.Inventory(
        FakeCargo(
            "valid.json",
            external_direct_deps={"dependency1": set([inventory.Dependency(name="dependency1", version="1.1.0")])},
        ),
    )
    errors = inv.validate()
    assert not errors


def test_inventory_unused_dependency():
    """Assert validation has errors if inventory has unused dependencies."""
    inv = inventory.Inventory(FakeCargo("valid.json"))
    errors = inv.validate()
    assert errors == [
        inventory.Inventory.Error(message="dependency1 is not referenced in any manifest file.", is_fatal=True)
    ]


def test_inventory_version_missing():
    """Assert validation fails if version is missing from the inventory."""
    inv = inventory.Inventory(
        FakeCargo(
            "valid.json",
            external_direct_deps={
                "dependency1": set(
                    [
                        inventory.Dependency(name="dependency1", version="1.1.0"),
                        inventory.Dependency(name="dependency1", version="1.1.1"),
                    ]
                )
            },
        ),
    )
    errors = inv.validate()
    assert errors == [
        inventory.Inventory.Error(
            message="Multiple versions of dependency1 are in use: ['1.1.0', '1.1.1'], "
            "but the following owners do not specify a version explicitly: "
            "['foobar@example.com', 'test@example.com']",
            is_fatal=True,
        )
    ]


def test_inventory_version_owners():
    """Assert validation fails if there is only one version owner."""
    inv = inventory.Inventory(
        FakeCargo(
            "one_version_owner.json",
            external_direct_deps={
                "dependency1": set(
                    [
                        inventory.Dependency(name="dependency1", version="1.1.0"),
                        inventory.Dependency(name="dependency1", version="1.1.1"),
                    ]
                )
            },
        ),
    )
    errors = inv.validate()
    assert errors == [
        inventory.Inventory.Error(
            message="The following versions of dependency1 have less than 2 owners: 1.1.0,1.1.1",
            is_fatal=True,
        )
    ]


def test_inventory_unused_version():
    inv = inventory.Inventory(
        FakeCargo(
            "one_version_owner.json",
            external_direct_deps={
                "dependency1": set(
                    [
                        inventory.Dependency(name="dependency1", version="1.1.0"),
                        inventory.Dependency(name="dependency1", version="0.0.1"),
                    ]
                )
            },
        )
    )
    errors = inv.validate()
    assert errors == [
        inventory.Inventory.Error(
            message="Version 1.1.1 of package dependency1 is not used, but is owned by test@example.com",
            is_fatal=True,
        ),
        inventory.Inventory.Error(
            message="The following versions of dependency1 have less than 2 owners: 1.1.0,1.1.1",
            is_fatal=True,
        ),
    ]


def test_inventory_one_version_in_use():
    """Assert validation fails if inventory specifies a version while only one is in use."""
    inv = inventory.Inventory(
        FakeCargo(
            "one_version_owner.json",
            external_direct_deps={"dependency1": set([inventory.Dependency(name="dependency1", version="1.1.0")])},
        )
    )
    errors = inv.validate()
    assert errors == [
        inventory.Inventory.Error(
            message="Only one version of dependency1 is in use, but the following owners explicitly "
            "specify versions: [\"foobar@example.com (['1.1.0'])\", \"test@example.com (['1.1.1'])\"]",
            is_fatal=True,
        )
    ]


def test_inventory_added_existing_dependency():
    """Assert validation succeeds if an added dependency is already in the inventory."""
    d = inventory.Dependency(name="dependency1", version="1.1.0")
    inv = inventory.Inventory(
        FakeCargo(
            "valid.json",
            external_direct_deps={"dependency1": set([d])},
            diffs={
                "ic-fake-package": inventory.PackageDiff(
                    name="ic-fake-package",
                    added_deps=set([d]),
                    added_direct_deps=set([d]),
                )
            },
        ),
        use_gitlab=False,
    )
    errors = inv.validate()
    assert errors == []


def test_inventory_added_new_dependency():
    """Assert validation fails if an added dependency is not in the inventory."""
    d = inventory.Dependency(name="new-dependency", version="1.1.0")
    inv = inventory.Inventory(
        FakeCargo(
            "valid.json",
            external_direct_deps={
                "new-dependency": set([d]),
                "dependency1": set([inventory.Dependency(name="dependency1", version="1.1.0")]),
            },
            diffs={
                "ic-fake-package": inventory.PackageDiff(
                    name="ic-fake-package",
                    added_deps=set([d]),
                    added_direct_deps=set([d]),
                )
            },
        ),
        use_gitlab=False,
    )
    errors = inv.validate()
    assert errors == [
        inventory.Inventory.Error(message="New dependency new-dependency is added, but it is not in the inventory")
    ]


def test_inventory_added_new_version():
    """Assert validation fails if an added version is not owned by anyone."""
    d = inventory.Dependency(name="dependency1", version="1.1.1")
    inv = inventory.Inventory(
        FakeCargo(
            "valid_with_versions.json",
            external_direct_deps={"dependency1": set([inventory.Dependency(name="dependency1", version="1.1.0"), d])},
            diffs={
                "ic-fake-package": inventory.PackageDiff(
                    name="ic-fake-package",
                    added_deps=set([d]),
                    added_direct_deps=set([d]),
                )
            },
        ),
        use_gitlab=False,
    )
    errors = inv.validate()
    assert errors == [inventory.Inventory.Error("Version 1.1.1 of dependency1 is added, but is not owned by anyone.")]


def test_inventory_added_existing_version():
    """Assert validation succeeds if an added version is already used."""
    d = inventory.Dependency(name="dependency1", version="1.1.0")
    inv = inventory.Inventory(
        FakeCargo(
            "valid_with_versions.json",
            external_direct_deps={"dependency1": set([inventory.Dependency(name="dependency1", version="1.1.1"), d])},
            diffs={
                "ic-fake-package": inventory.PackageDiff(
                    name="ic-fake-package",
                    added_deps=set([d]),
                    added_direct_deps=set([d]),
                )
            },
        ),
        use_gitlab=False,
    )
    errors = inv.validate()
    assert errors == []


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


def test_cargo_inventory_not_changed(tmpdir):
    """Verify inventory_changed returns False if inventory did not change."""
    setup_git_repo(tmpdir, "not_changed_inventory")
    cargo = inventory.Cargo(root=pathlib.Path(tmpdir))
    assert not cargo.inventory_changed()


def test_cargo_inventory_changed(tmpdir):
    """Verify inventory changes are detected correctly."""
    setup_git_repo(tmpdir, "changed_inventory")
    cargo = inventory.Cargo(root=pathlib.Path(tmpdir))
    assert cargo.inventory_changed()


class LocalCargo(inventory.Cargo):
    """Cargo patched up to use a local crate registry."""

    def _get_cargo_tree_output(self, package=None):
        return super()._get_cargo_tree_output(
            package=package,
            offline="--offline",
            cargo_home=f"CARGO_HOME={TEST_DATA}/cargo_home",
        )


def test_cargo_get_external_deps():
    """Verify parsing of cargo tree for external direct dependencies."""
    cargo = LocalCargo(root=TEST_DATA / "external_direct_deps")
    assert cargo.get_external_direct_deps() == {
        "ascii": {inventory.Dependency(name="ascii", version="1.0.0")},
        "askama": {inventory.Dependency(name="askama", version="0.9.0")},
        "async-trait": {inventory.Dependency(name="async-trait", version="0.1.48")},
        "futures": {inventory.Dependency(name="futures", version="0.3.13")},
        "tempfile": {inventory.Dependency(name="tempfile", version="3.2.0")},
    }


def test_cargo_package_diff_no_change(tmpdir):
    """Verify no diff is reported if nothing changed."""
    setup_git_repo(tmpdir, "package_diff_no_change")
    cargo = LocalCargo(root=tmpdir)
    assert cargo.get_package_diff() == {}


def test_cargo_get_package_diff(tmpdir):
    """Check package diffs are reported correctly."""
    setup_git_repo(tmpdir, "package_diff")
    cargo = LocalCargo(root=tmpdir)
    assert cargo.get_package_diff() == {
        "ic-fake2": inventory.PackageDiff(
            name="ic-fake2",
            added_deps={inventory.Dependency(name="bytes", version="0.5.6", is_external=True)},
            removed_deps=set(),
            added_direct_deps={inventory.Dependency(name="bytes", version="0.5.6", is_external=True)},
        ),
        "ic-fake1": inventory.PackageDiff(
            name="ic-fake1",
            added_deps=set(),
            removed_deps={
                inventory.Dependency(name="futures", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-channel", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-core", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-executor", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-io", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-macro", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-sink", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-task", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-util", version="0.3.13", is_external=True),
                inventory.Dependency(name="ic-fake2", version="0.1.0", is_external=False),
                inventory.Dependency(name="pin-project-lite", version="0.2.6", is_external=True),
                inventory.Dependency(name="pin-utils", version="0.1.0", is_external=True),
                inventory.Dependency(name="proc-macro-hack", version="0.5.19", is_external=True),
                inventory.Dependency(name="proc-macro-nested", version="0.1.7", is_external=True),
                inventory.Dependency(name="slab", version="0.4.2", is_external=True),
            },
            added_direct_deps={inventory.Dependency(name="async-trait", version="0.1.48", is_external=True)},
        ),
    }


def test_cargo_get_package_diff_new_toml(tmpdir):
    """Check package diffs are reported correctly if Cargo.toml was added."""
    setup_git_repo(tmpdir, "package_diff_new_toml")
    cargo = LocalCargo(root=tmpdir)
    assert cargo.get_package_diff() == {
        "ic-fake2": inventory.PackageDiff(
            name="ic-fake2",
            added_deps={
                inventory.Dependency(name="futures", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-channel", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-core", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-executor", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-io", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-macro", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-sink", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-task", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-util", version="0.3.13", is_external=True),
                inventory.Dependency(name="memchr", version="2.3.4", is_external=True),
                inventory.Dependency(name="pin-project-lite", version="0.2.6", is_external=True),
                inventory.Dependency(name="pin-utils", version="0.1.0", is_external=True),
                inventory.Dependency(name="proc-macro2", version="1.0.24", is_external=True),
                inventory.Dependency(name="proc-macro-hack", version="0.5.19", is_external=True),
                inventory.Dependency(name="proc-macro-nested", version="0.1.7", is_external=True),
                inventory.Dependency(name="quote", version="1.0.9", is_external=True),
                inventory.Dependency(name="slab", version="0.4.2", is_external=True),
                inventory.Dependency(name="syn", version="1.0.62", is_external=True),
                inventory.Dependency(name="unicode-xid", version="0.2.1", is_external=True),
            },
            removed_deps=set(),
            added_direct_deps={
                inventory.Dependency(name="futures", version="0.3.13", is_external=True),
            },
        )
    }


def test_cargo_get_package_diff_remove_toml(tmpdir):
    """Check package diffs are reported correctly if Cargo.toml was removed."""
    setup_git_repo(tmpdir, "package_diff_remove_toml")
    cargo = LocalCargo(root=tmpdir)
    assert cargo.get_package_diff() == {
        "ic-fake2": inventory.PackageDiff(
            name="ic-fake2",
            added_deps=set(),
            removed_deps={
                inventory.Dependency(name="futures", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-channel", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-core", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-executor", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-io", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-macro", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-sink", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-task", version="0.3.13", is_external=True),
                inventory.Dependency(name="futures-util", version="0.3.13", is_external=True),
                inventory.Dependency(name="memchr", version="2.3.4", is_external=True),
                inventory.Dependency(name="pin-project-lite", version="0.2.6", is_external=True),
                inventory.Dependency(name="pin-utils", version="0.1.0", is_external=True),
                inventory.Dependency(name="proc-macro2", version="1.0.24", is_external=True),
                inventory.Dependency(name="proc-macro-hack", version="0.5.19", is_external=True),
                inventory.Dependency(name="proc-macro-nested", version="0.1.7", is_external=True),
                inventory.Dependency(name="quote", version="1.0.9", is_external=True),
                inventory.Dependency(name="slab", version="0.4.2", is_external=True),
                inventory.Dependency(name="syn", version="1.0.62", is_external=True),
                inventory.Dependency(name="unicode-xid", version="0.2.1", is_external=True),
            },
            added_direct_deps=set(),
        )
    }
