"""Tests for ci/scripts/validate-deflake-bundle.sh and validate-deflake-dependencies.py on temporary git repositories."""

import hashlib
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).parent
# The zero-width non-joiner that validate-deflake-bundle.sh inserts to turn markup in the PR description into text.
Z = "\u200c"
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
DOGECOIN = "git+https://github.com/dfinity/rust-dogecoin?rev=1234567#1234567890abcdef1234567890abcdef12345678"
HASHES_GIT = "git+https://github.com/dfinity/hashes#0123456789abcdef0123456789abcdef01234567"
BETA_GIT = "git+https://github.com/dfinity/beta#89abcdef0123456789abcdef0123456789abcdef"
# How Cargo.lock refers to hashes 1.0.0 from crates.io and from git, since it has both.
HASHES = f"hashes 1.0.0 ({CRATES_IO})"
HASHES_FROM_GIT = "hashes 1.0.0 (git+https://github.com/dfinity/hashes)"

# The versions of probe in Cargo.lock, which Cargo can lock together since no two are semver compatible, and the
# workspace dependencies on probe with the version each one selects.
PROBES = ["0.0.3", "0.0.4", "0.1.5", "0.2.0", "0.10.0", "1.3.0", "2.0.1"]
SELECTING = {
    "probe-zero": ("^0.0.3", "0.0.3"),
    "probe-caret": ("^0.1.2", "0.1.5"),
    "probe-bare": ("0.2", "0.2.0"),
    "probe-two-digits": ("0.10", "0.10.0"),
    "probe-major": ("1", "1.3.0"),
    "probe-full": ("1.2.3", "1.3.0"),
    "probe-tilde": ("~0.1.2", "0.1.5"),
    "probe-tilde-minor": ("~1.3", "1.3.0"),
    "probe-tilde-major": ("~2", "2.0.1"),
    "probe-exact": ("=1.3.0", "1.3.0"),
    "probe-exact-minor": ("=1.3", "1.3.0"),
    "probe-spaced": ("= 1.3.0", "1.3.0"),
}
# Workspace dependencies on probe for which the validator can't tell the version they select.
UNTELLABLE = {
    "probe-any": ('version = "0"', "can't tell which probe in Cargo.lock probe-any selects"),
    "probe-tilde-older": ('version = "~1.2"', "can't tell which probe in Cargo.lock probe-tilde-older selects"),
    "probe-exact-missing": ('version = "=0.1.4"', "can't tell which probe in Cargo.lock probe-exact-missing selects"),
    "probe-range": ('version = ">=1.0, <1.3"', "can't tell whether 0.0.3 satisfies >=1.0, <1.3"),
    "probe-greater": ('version = ">1.2"', "can't tell whether 0.0.3 satisfies >1.2"),
    "probe-star": ('version = "*"', "can't tell whether 0.0.3 satisfies *"),
    "probe-pre": ('version = "=1.3.0-rc.1"', "can't tell whether 0.0.3 satisfies =1.3.0-rc.1"),
    "probe-git": ('git = "https://github.com/dfinity/probe"', "can't tell which probe in Cargo.lock probe-git selects"),
    "probe-git-version": (
        'git = "https://github.com/dfinity/probe", version = "1.3"',
        "can't tell which probe in Cargo.lock probe-git-version selects",
    ),
    "probe-path": ('path = "../probe", version = "1.3"', "can't tell which probe in Cargo.lock probe-path selects"),
    "probe-registry": (
        'version = "0.2", registry = "internal"',
        "can't tell which probe in Cargo.lock probe-registry selects",
    ),
    "probe-unversioned": ('features = ["std"]', "can't tell which probe in Cargo.lock probe-unversioned selects"),
    "probe-newer": ('version = "1.3.5"', "can't tell which probe in Cargo.lock probe-newer selects"),
    "probe-four": ('version = "1.3.0.1"', "can't tell whether 0.0.3 satisfies 1.3.0.1"),
}

ROOT_MANIFEST = (
    """\
[workspace]
members = ["packages/gamma", "rs/alpha", "rs/beta", "rs/zeta"]
resolver = "2"

[workspace.package]
version = "0.9.0"
edition = "2024"

[workspace.dependencies]
bitcoin = { package = "bitcoin-dogecoin", git = "https://github.com/dfinity/rust-dogecoin", rev = "1234567" }
dogecoin = { package = "bitcoin-dogecoin", git = "https://github.com/dfinity/rust-dogecoin", rev = "1234567" }
foo-bar = "1.0"
foo_bar = { package = "foo-bar", version = "1.0" }
hashes = "1.0"
hashes-next = { package = "hashes", version = "2" }
lonely = "1.0"
pre = "~1.1"
rand = "0.8"
rand-next = { package = "rand", version = "0.9" }
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.47", default-features = false }
# No crate depends on it, so it isn't in Cargo.lock.
unused = "1.0"
zero = "0.0"
"""
    + "".join(f'{key} = {{ package = "probe", version = "{req}" }}\n' for key, (req, _) in SELECTING.items())
    + "".join(f'{key} = {{ package = "probe", {spec} }}\n' for key, (spec, _) in UNTELLABLE.items())
)

ALPHA, ALPHA_PATH = (
    """\
[package]
name = "alpha"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { workspace = true }
""",
    "rs/alpha/Cargo.toml",
)
# foo-bar and foo_bar select the same package under the same crate name, which Cargo allows, also in different tables.
BETA, BETA_PATH = (
    """\
[package]
name = "beta"
version.workspace = true
edition.workspace = true

[dependencies]
alpha = { path = "../alpha" }
bitcoin = { workspace = true }
foo-bar = { workspace = true }
lonely = { workspace = true }
rand = { workspace = true }
rand-next = { workspace = true }
serde = { workspace = true, features = ["rc"] }

[dev-dependencies]
foo_bar = { workspace = true }
""",
    "rs/beta/Cargo.toml",
)
GAMMA, GAMMA_PATH = (
    """\
[package]
name = "gamma"
version.workspace = true
edition.workspace = true

[dependencies]
bitcoin = { workspace = true }
foo-bar = { workspace = true }
tokio = { workspace = true }

[target.'cfg(target_os = "linux")'.dependencies]
hashes = { workspace = true }

[target.'cfg(unix)'.dependencies]
foo_bar = { workspace = true, features = ["std"] }
""",
    "packages/gamma/Cargo.toml",
)
# Depends on the packages that no other crate does, since Cargo.lock only has packages with dependents.
ZETA, ZETA_PATH = (
    """\
[package]
name = "zeta"
version.workspace = true
edition.workspace = true

[dependencies]
alpha2 = { package = "alpha", version = "2" }
beta-git = { package = "beta", git = "https://github.com/dfinity/beta" }
bitcoin-old = { package = "bitcoin", version = "0.28" }
foo-bar = { workspace = true }
hashes-git = { package = "hashes", git = "https://github.com/dfinity/hashes" }
hashes-next = { workspace = true }
pre-beta = { package = "pre", version = "=1.1.0-beta.1" }
pre2 = { package = "pre", version = "2" }
probe-0-0-3 = { package = "probe", version = "=0.0.3" }
probe-0-0-4 = { package = "probe", version = "=0.0.4" }
probe-0-1 = { package = "probe", version = "0.1" }
probe-0-2 = { package = "probe", version = "0.2" }
probe-0-10 = { package = "probe", version = "0.10" }
probe-1 = { package = "probe", version = "1" }
probe-2 = { package = "probe", version = "2" }
zero-0-0 = { package = "zero", version = "0.0" }
zero-0-1 = { package = "zero", version = "0.1" }
""",
    "rs/zeta/Cargo.toml",
)
# Crates of workspaces of their own, with their own Cargo.lock, named like packages in the root Cargo.lock, and a
# workspace without a package.
NESTED, NESTED_PATH, NESTED_GIT_PATH = (
    """\
[package]
name = "bitcoin"
version = "0.1.0"
edition = "2021"

[workspace]

[dependencies]
""",
    "rs/nested/Cargo.toml",
    "rs/nested-git/Cargo.toml",
)
NESTED_GIT = NESTED.replace('name = "bitcoin"', 'name = "bitcoin-dogecoin"')
VIRTUAL, VIRTUAL_PATH = '[workspace]\nmembers = ["member"]\nresolver = "2"\n', "rs/virtual/Cargo.toml"

PACKAGES = [
    ("alpha", "0.9.0", None, ["serde"]),
    # A package named like a crate of the workspace, as there are in the real Cargo.lock.
    ("alpha", "2.0.0", CRATES_IO, []),
    (
        "beta",
        "0.9.0",
        None,
        ["alpha 0.9.0", "bitcoin-dogecoin", "foo-bar", "lonely", "rand 0.8.6", "rand 0.9.3", "serde"],
    ),
    # Also named like a crate of the workspace, but from git.
    ("beta", "1.0.0", BETA_GIT, []),
    ("bitcoin", "0.28.2", CRATES_IO, []),
    ("bitcoin-dogecoin", "0.32.5", DOGECOIN, []),
    ("foo-bar", "1.0.0", CRATES_IO, []),
    ("gamma", "0.9.0", None, ["bitcoin-dogecoin", "foo-bar", HASHES, "tokio"]),
    ("hashes", "1.0.0", CRATES_IO, []),
    ("hashes", "1.0.0", HASHES_GIT, []),
    ("hashes", "2.0.0", CRATES_IO, []),
    # Only beta depends on lonely.
    ("lonely", "1.0.0", CRATES_IO, []),
    ("pre", "1.1.0-beta.1", CRATES_IO, []),
    ("pre", "2.0.0", CRATES_IO, []),
    *[("probe", version, CRATES_IO, ["rand 0.9.3"] if version == "1.3.0" else []) for version in PROBES],
    ("rand", "0.8.6", CRATES_IO, []),
    ("rand", "0.9.3", CRATES_IO, []),
    ("serde", "1.0.228", CRATES_IO, []),
    ("tokio", "1.47.1", CRATES_IO, [HASHES, "rand 0.8.6", "serde"]),
    ("zero", "0.0.1", CRATES_IO, []),
    ("zero", "0.1.0", CRATES_IO, []),
    (
        "zeta",
        "0.9.0",
        None,
        [
            "alpha 2.0.0",
            "beta 1.0.0",
            "bitcoin",
            "foo-bar",
            HASHES_FROM_GIT,
            "hashes 2.0.0",
            "pre 1.1.0-beta.1",
            "pre 2.0.0",
            *[f"probe {version}" for version in PROBES],
            "zero 0.0.1",
            "zero 0.1.0",
        ],
    ),
]


def lock(packages=PACKAGES, **changes):
    """Cargo.lock of the packages, with dependencies added (+) or removed (-), like alpha=["+rand 0.8.6"]."""
    text = "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n"
    for name, version, source, dependencies in packages:
        dependencies = list(dependencies)
        for change in changes.pop(name, []):
            if change.startswith("+"):
                dependencies.append(change[1:])
            else:
                dependencies.remove(change[1:])
        text += f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
        if source:
            text += f'source = "{source}"\n'
        if source == CRATES_IO:
            text += f'checksum = "{checksum(name, version)}"\n'
        if dependencies:
            text += "dependencies = [\n" + "".join(f' "{dependency}",\n' for dependency in sorted(dependencies)) + "]\n"
    assert not changes, f"no packages {list(changes)}"
    return text


def checksum(name, version):
    return hashlib.sha256(f"{name} {version}".encode()).hexdigest()


def add(manifest, table, line):
    """Adds the line to the table of the manifest, which gets the table if it doesn't have it."""
    header = f"[{table}]\n"
    if header in manifest:
        return manifest.replace(header, header + line + "\n", 1)
    return f"{manifest}\n{header}{line}\n"


def remove(manifest, line):
    assert line + "\n" in manifest, line
    return manifest.replace(line + "\n", "", 1)


def replace(text, old, new):
    assert old in text, old
    return text.replace(old, new, 1)


def symlink(target):
    return ("120000", target)


BASE_FILES = {
    "Cargo.toml": ROOT_MANIFEST,
    "Cargo.lock": lock(),
    ALPHA_PATH: ALPHA,
    "rs/alpha/src/lib.rs": "pub fn alpha() -> u32 {\n    1\n}\n",
    "rs/alpha/src/big.rs": "x\n" * 600,
    "rs/alpha/src/wide.rs": ("y" * 999 + "\n") * 10,
    "rs/alpha/BUILD.bazel": 'rust_library(name = "alpha")\n',
    "rs/alpha/lib.link": symlink("src/lib.rs"),
    "rs/alpha/sub": ("160000", "1234567890abcdef1234567890abcdef12345678"),
    BETA_PATH: BETA,
    "rs/beta/src/lib.rs": "\n",
    GAMMA_PATH: GAMMA,
    "packages/gamma/src/lib.rs": "\n",
    ZETA_PATH: ZETA,
    "rs/zeta/src/lib.rs": "\n",
    NESTED_PATH: NESTED,
    "rs/nested/Cargo.lock": lock([("bitcoin", "0.1.0", None, [])]),
    "rs/nested/src/lib.rs": "\n",
    NESTED_GIT_PATH: NESTED_GIT,
    VIRTUAL_PATH: VIRTUAL,
    "rs/virtual/Cargo.lock": lock([("virtual-member", "0.1.0", None, [])]),
    "rs/virtual/member/Cargo.toml": '[package]\nname = "virtual-member"\nversion = "0.1.0"\nedition = "2021"\n',
    "rs/virtual/member/src/lib.rs": "\n",
    "rs/nested-git/Cargo.lock": lock([("bitcoin-dogecoin", "0.1.0", None, [])]),
    "rs/nested-git/src/lib.rs": "\n",
    "rs/ic_os/config/types/src/lib.rs": "pub struct Config;\n",
    "ic-os/components/unit.service": "[Unit]\n",
    "bazel/defs.bzl": "def defs():\n    pass\n",
    ".gitattributes": "*.lock linguist-generated\n",
}


class Repo:
    """A git repository whose commits are made of files given as dicts, without a working tree."""

    def __init__(self, path, env):
        self.path, self.env = path, env
        path.mkdir()
        # The validator expects SHA-1 commit ids, whatever the default of this git is.
        self.git("init", "-q", "-b", "master", "--object-format=sha1")

    def git(self, *args, stdin=None, env=None, raw=False):
        run = subprocess.run(
            ["git", *args], cwd=self.path, env=self.env | (env or {}), input=stdin, capture_output=True
        )
        if run.returncode != 0:
            raise AssertionError(f"git {shlex.join(args)} failed: {run.stderr.decode(errors='replace')}")
        return run.stdout if raw else run.stdout.decode().strip()

    def commit(self, files, parent=None, message="fix"):
        """
        Commits the files on top of the parent: each path maps to its contents, to None to delete it, or to a mode
        and the contents, like symlink() and ("160000", commit) for a submodule.
        """
        env = {"GIT_INDEX_FILE": str(self.path / ".git" / "test-index")}
        self.git("read-tree", *([parent] if parent else ["--empty"]), env=env)
        for path, contents in files.items():
            if contents is None:
                self.git("update-index", "--force-remove", "--", path, env=env)
                continue
            mode, contents = contents if isinstance(contents, tuple) else ("100644", contents)
            if mode != "160000":
                data = contents.encode() if isinstance(contents, str) else contents
                contents = self.git("hash-object", "-w", "--stdin", stdin=data)
            self.git("update-index", "--add", "--cacheinfo", f"{mode},{contents},{path}", env=env)
        tree = self.git("write-tree", env=env)
        return self.git("commit-tree", tree, *(["-p", parent] if parent else []), "-m", message)


class ValidatorTest(unittest.TestCase):
    """Shares one repository, whose master is the base of the fixes, between the tests."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(cls.enterClassContext(tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR"))))
        # So that the scripts run with the interpreter of this test, whatever python3 the host has.
        shims = cls.tmp / "bin"
        shims.mkdir()
        (shims / "python3").write_text(f'#!/bin/sh\nexec {shlex.quote(sys.executable)} "$@"\n')
        (shims / "python3").chmod(0o755)
        # Only these settings, and none of the user, the system or this environment, apply to git, bash and perl.
        # The fixed dates make the commits the same in every run.
        cls.env = {
            "PATH": f"{shims}{os.pathsep}{os.environ.get('PATH', os.defpath)}",
            "HOME": str(cls.tmp),
            "TMPDIR": str(cls.tmp),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_AUTHOR_DATE": "2026-10-05T00:00:00Z",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
            "GIT_COMMITTER_DATE": "2026-10-05T00:00:00Z",
        }
        cls.repo = Repo(cls.tmp / "origin", cls.env)
        cls.root = cls.repo.commit({"README.md": "IC\n"}, message="root")
        cls.base = cls.repo.commit(BASE_FILES, parent=cls.root, message="base")
        cls.repo.git("update-ref", "refs/heads/master", cls.base)


class DependencyTest(ValidatorTest):
    """validate-deflake-dependencies.py on a fix on top of the base."""

    def validate(self, files):
        fix = self.repo.commit(files, parent=self.base)
        script = SCRIPTS / "validate-deflake-dependencies.py"
        return subprocess.run(
            [sys.executable, script, self.base, fix],
            cwd=self.repo.path,
            env=self.env,
            capture_output=True,
            encoding="utf-8",
        )

    def assert_accepted(self, files):
        result = self.validate(files)
        self.assertEqual((result.returncode, result.stderr), (0, ""))

    def assert_rejected(self, files, message):
        result = self.validate(files)
        self.assertEqual((result.returncode, result.stderr), (1, message + "\n"))

    def test_accepts_other_changes(self):
        self.assert_accepted({"rs/alpha/src/lib.rs": "pub fn alpha() -> u32 {\n    2\n}\n"})

    def test_needs_two_revisions(self):
        script = SCRIPTS / "validate-deflake-dependencies.py"
        result = subprocess.run([sys.executable, script, self.base], capture_output=True, encoding="utf-8")
        self.assertEqual((result.returncode, result.stderr), (1, f"usage: {script} BASE FIX\n"))

    def test_accepts_formatting_changes(self):
        self.assert_accepted(
            {ALPHA_PATH: replace(ALPHA, "serde = { workspace = true }", "# Serialization.\nserde.workspace = true")}
        )

    def test_adds_and_removes_workspace_dependencies(self):
        rand = "rand = { workspace = true }"
        cases = {
            "a dependency": (ALPHA_PATH, add(ALPHA, "dependencies", rand), {"alpha": ["+rand 0.8.6"]}),
            "a dotted key": (
                ALPHA_PATH,
                add(ALPHA, "dependencies", "rand.workspace = true"),
                {"alpha": ["+rand 0.8.6"]},
            ),
            "a dev-dependency": (
                ALPHA_PATH,
                add(ALPHA, "dev-dependencies", "tokio = { workspace = true }"),
                {"alpha": ["+tokio"]},
            ),
            "a build-dependency": (
                ALPHA_PATH,
                add(ALPHA, "build-dependencies", "hashes = { workspace = true }"),
                {"alpha": [f"+{HASHES}"]},
            ),
            "a renamed package": (
                ALPHA_PATH,
                add(ALPHA, "dependencies", "bitcoin = { workspace = true }"),
                {"alpha": ["+bitcoin-dogecoin"]},
            ),
            "the other version": (
                ALPHA_PATH,
                add(ALPHA, "dependencies", "rand-next = { workspace = true }"),
                {"alpha": ["+rand 0.9.3"]},
            ),
            "a dependency in a new target table": (
                ALPHA_PATH,
                add(ALPHA, "target.'cfg(unix)'.dependencies", rand),
                {"alpha": ["+rand 0.8.6"]},
            ),
            "a dev-dependency in a new target table": (
                ALPHA_PATH,
                add(ALPHA, "target.'cfg(unix)'.dev-dependencies", "tokio = { workspace = true }"),
                {"alpha": ["+tokio"]},
            ),
            "a dependency of a crate with a path dependency": (
                BETA_PATH,
                add(BETA, "dependencies", "tokio = { workspace = true }"),
                {"beta": ["+tokio"]},
            ),
            "a removal": (ALPHA_PATH, remove(ALPHA, "serde = { workspace = true }"), {"alpha": ["-serde"]}),
            "a removal of a renamed package": (
                BETA_PATH,
                remove(BETA, "bitcoin = { workspace = true }"),
                {"beta": ["-bitcoin-dogecoin"]},
            ),
            "a removal of one version": (
                BETA_PATH,
                remove(BETA, "rand-next = { workspace = true }"),
                {"beta": ["-rand 0.9.3"]},
            ),
            "a removal and an addition": (
                ALPHA_PATH,
                add(remove(ALPHA, "serde = { workspace = true }"), "dependencies", "tokio = { workspace = true }"),
                {"alpha": ["-serde", "+tokio"]},
            ),
        }
        for case, (path, manifest, changes) in cases.items():
            with self.subTest(case):
                self.assert_accepted({path: manifest, "Cargo.lock": lock(**changes)})

    def test_changes_target_tables(self):
        linux = "target.'cfg(target_os = \"linux\")'.dependencies"
        removed = remove(GAMMA, f"\n[{linux}]\nhashes = {{ workspace = true }}")
        self.assert_accepted({GAMMA_PATH: removed, "Cargo.lock": lock(gamma=[f"-{HASHES}"])})
        added = add(GAMMA, linux, "rand = { workspace = true }")
        self.assert_accepted({GAMMA_PATH: added, "Cargo.lock": lock(gamma=["+rand 0.8.6"])})

    def test_moves_a_dependency_to_another_kind(self):
        moved = add(remove(ALPHA, "serde = { workspace = true }"), "dev-dependencies", "serde = { workspace = true }")
        self.assert_accepted({ALPHA_PATH: moved})

    def test_changes_several_crates(self):
        self.assert_accepted(
            {
                ALPHA_PATH: add(ALPHA, "dependencies", "rand = { workspace = true }"),
                BETA_PATH: remove(BETA, "rand = { workspace = true }"),
                "Cargo.lock": lock(alpha=["+rand 0.8.6"], beta=["-rand 0.8.6"]),
            }
        )

    def test_keeps_a_package_that_another_dependency_selects(self):
        foo_bar = remove(BETA, "foo_bar = { workspace = true }")
        self.assert_accepted({BETA_PATH: foo_bar})
        self.assert_rejected(
            {BETA_PATH: foo_bar, "Cargo.lock": lock(beta=["-foo-bar"])},
            "Cargo.lock doesn't match the dependency changes of beta 0.9.0",
        )
        self.assert_accepted({BETA_PATH: remove(BETA, "foo-bar = { workspace = true }")})
        both = remove(foo_bar, "foo-bar = { workspace = true }")
        self.assert_accepted({BETA_PATH: both, "Cargo.lock": lock(beta=["-foo-bar"])})
        # Also when the other dependency is in a target table and has features.
        self.assert_accepted({GAMMA_PATH: remove(GAMMA, "foo-bar = { workspace = true }")})

    def test_swaps_dependencies_on_one_package(self):
        # bitcoin and dogecoin both select bitcoin-dogecoin, so Cargo.lock doesn't change.
        swapped = replace(BETA, "bitcoin = { workspace = true }", "dogecoin = { workspace = true }")
        self.assert_accepted({BETA_PATH: swapped})
        self.assert_rejected(
            {BETA_PATH: swapped, "Cargo.lock": lock(beta=["-bitcoin-dogecoin"])},
            "Cargo.lock doesn't match the dependency changes of beta 0.9.0",
        )

    def test_rejects_removing_the_last_dependency_on_a_package(self):
        # Cargo drops the package, but the fix may not remove packages from Cargo.lock.
        dropped = lock([package for package in PACKAGES if package[0] != "lonely"], beta=["-lonely"])
        self.assert_rejected(
            {BETA_PATH: remove(BETA, "lonely = { workspace = true }"), "Cargo.lock": dropped},
            "Cargo.lock adds or removes packages or changes its metadata",
        )

    def test_selects_the_version_of_a_requirement(self):
        for key, (_, selected) in SELECTING.items():
            manifest = add(ALPHA, "dependencies", f"{key} = {{ workspace = true }}")
            for version in PROBES:
                with self.subTest(key=key, version=version):
                    files = {ALPHA_PATH: manifest, "Cargo.lock": lock(alpha=[f"+probe {version}"])}
                    if version == selected:
                        self.assert_accepted(files)
                    else:
                        self.assert_rejected(files, "Cargo.lock doesn't match the dependency changes of alpha 0.9.0")
        zero = add(ALPHA, "dependencies", "zero = { workspace = true }")
        self.assert_accepted({ALPHA_PATH: zero, "Cargo.lock": lock(alpha=["+zero 0.0.1"])})
        self.assert_rejected(
            {ALPHA_PATH: zero, "Cargo.lock": lock(alpha=["+zero 0.1.0"])},
            "Cargo.lock doesn't match the dependency changes of alpha 0.9.0",
        )

    def test_rejects_requirements_it_cannot_resolve(self):
        for key, (_, message) in UNTELLABLE.items():
            with self.subTest(key):
                manifest = add(ALPHA, "dependencies", f"{key} = {{ workspace = true }}")
                self.assert_rejected({ALPHA_PATH: manifest, "Cargo.lock": lock(alpha=["+probe 1.3.0"])}, message)
        # The versions of pre include a pre-release.
        pre = add(ALPHA, "dependencies", "pre = { workspace = true }")
        self.assert_rejected(
            {ALPHA_PATH: pre, "Cargo.lock": lock(alpha=["+pre 1.1.0-beta.1"])},
            "can't tell whether 1.1.0-beta.1 satisfies ~1.1",
        )
        unused = add(ALPHA, "dependencies", "unused = { workspace = true }")
        self.assert_rejected(
            {ALPHA_PATH: unused, "Cargo.lock": lock(alpha=["+unused"])},
            "can't tell which unused in Cargo.lock unused selects",
        )

    def test_refers_to_packages_like_cargo(self):
        manifest = add(ALPHA, "dependencies", "hashes = { workspace = true }")
        self.assert_accepted({ALPHA_PATH: manifest, "Cargo.lock": lock(alpha=[f"+{HASHES}"])})
        # Only hashes 1.0.0 needs its source.
        next = add(ALPHA, "dependencies", "hashes-next = { workspace = true }")
        self.assert_accepted({ALPHA_PATH: next, "Cargo.lock": lock(alpha=["+hashes 2.0.0"])})
        self.assert_rejected(
            {ALPHA_PATH: next, "Cargo.lock": lock(alpha=[f"+hashes 2.0.0 ({CRATES_IO})"])},
            "Cargo.lock doesn't match the dependency changes of alpha 0.9.0",
        )
        for reference in ["hashes", "hashes 1.0.0", HASHES_FROM_GIT]:
            with self.subTest(reference):
                self.assert_rejected(
                    {ALPHA_PATH: manifest, "Cargo.lock": lock(alpha=[f"+{reference}"])},
                    "Cargo.lock doesn't match the dependency changes of alpha 0.9.0",
                )
        rand = add(ALPHA, "dependencies", "rand = { workspace = true }")
        for reference in ["rand", "rand 0.9.3", f"rand 0.8.6 ({CRATES_IO})"]:
            with self.subTest(reference):
                self.assert_rejected(
                    {ALPHA_PATH: rand, "Cargo.lock": lock(alpha=[f"+{reference}"])},
                    "Cargo.lock doesn't match the dependency changes of alpha 0.9.0",
                )
        # The bitcoin package isn't the one that the bitcoin workspace dependency selects.
        bitcoin = add(ALPHA, "dependencies", "bitcoin = { workspace = true }")
        self.assert_rejected(
            {ALPHA_PATH: bitcoin, "Cargo.lock": lock(alpha=["+bitcoin"])},
            "Cargo.lock doesn't match the dependency changes of alpha 0.9.0",
        )
        self.assert_rejected(
            {BETA_PATH: remove(BETA, "rand-next = { workspace = true }"), "Cargo.lock": lock(beta=["-rand 0.8.6"])},
            "Cargo.lock doesn't match the dependency changes of beta 0.9.0",
        )

    def test_rejects_dependencies_the_workspace_does_not_have(self):
        typos = add(ALPHA, "dev-dependencies", "zzz = { workspace = true }")
        for typo in ["typo", "aaa", "mmm", "bbb"]:
            typos = add(typos, "dependencies", f"{typo}.workspace = true")
        self.assert_rejected(
            {ALPHA_PATH: typos},
            "rs/alpha/Cargo.toml adds dependencies the root Cargo.toml doesn't have: aaa, bbb, mmm, typo, zzz",
        )
        self.assert_rejected(
            {ALPHA_PATH: add(ALPHA, "dependencies", 'gamma = { path = "../../packages/gamma" }')},
            "rs/alpha/Cargo.toml adds dependencies the root Cargo.toml doesn't have: gamma",
        )

    def test_rejects_other_manifest_changes(self):
        cases = {
            "a version": add(ALPHA, "dependencies", 'rand = "0.8"'),
            "features": add(ALPHA, "dependencies", 'rand = { workspace = true, features = ["small_rng"] }'),
            "an optional dependency": add(ALPHA, "dependencies", "rand = { workspace = true, optional = true }"),
            "a workspace key other than true": add(ALPHA, "dependencies", "rand = { workspace = 1 }"),
            "a list instead of a table": add(ALPHA, "dependencies", 'rand = ["workspace"]'),
            "a target dependency with a version": add(ALPHA, "target.'cfg(unix)'.dependencies", 'rand = "0.8"'),
            "another key in a target table": add(ALPHA, "target.'cfg(unix)'", "rustflags = []"),
            "a package key": replace(ALPHA, "edition.workspace = true", 'edition = "2021"'),
            "a build script": replace(
                ALPHA, "edition.workspace = true\n", 'edition.workspace = true\nbuild = "b.rs"\n'
            ),
            "features of the crate": add(ALPHA, "features", "default = []"),
            "a patch": add(ALPHA, "patch.crates-io", 'serde = { path = "../serde" }'),
            "a dependency out of the dependency tables": replace(ALPHA, "[dependencies]", "[dependencies-x]"),
        }
        for case, manifest in cases.items():
            with self.subTest(case):
                self.assert_rejected(
                    {ALPHA_PATH: manifest}, f"{ALPHA_PATH} changes beyond adding or removing workspace dependencies"
                )
        self.assert_rejected(
            {BETA_PATH: replace(BETA, 'features = ["rc"]', 'features = ["rc", "derive"]')},
            f"{BETA_PATH} changes beyond adding or removing workspace dependencies",
        )
        # validate-deflake-bundle.sh doesn't let the fix change the root Cargo.toml in the first place.
        self.assert_rejected(
            {"Cargo.toml": replace(ROOT_MANIFEST, 'rand = "0.8"', 'rand = "0.9"')},
            "Cargo.toml changes beyond adding or removing workspace dependencies",
        )

    def test_rejects_added_deleted_and_renamed_manifests(self):
        new = replace(ALPHA, 'name = "alpha"', 'name = "delta"')
        self.assert_rejected({"rs/delta/Cargo.toml": new}, "rs/delta/Cargo.toml is added or deleted")
        self.assert_rejected({BETA_PATH: None}, "rs/beta/Cargo.toml is added or deleted")
        self.assert_rejected({BETA_PATH: None, "rs/beta2/Cargo.toml": BETA}, "rs/beta/Cargo.toml is added or deleted")

    def test_rejects_manifests_outside_the_root_workspace(self):
        for path, manifest in {NESTED_PATH: NESTED, NESTED_GIT_PATH: NESTED_GIT}.items():
            with self.subTest(path):
                self.assert_rejected(
                    {path: add(manifest, "dependencies", "serde = { workspace = true }")},
                    f"the fix changes manifests outside the root workspace: {path}",
                )
        self.assert_rejected(
            {VIRTUAL_PATH: "# A workspace.\n" + VIRTUAL},
            f"the fix changes manifests outside the root workspace: {VIRTUAL_PATH}",
        )

    def test_rejects_invalid_manifests(self):
        result = self.validate({ALPHA_PATH: ALPHA + "\n[dependencies]\nrand = { workspace = true }\n"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("TOMLDecodeError", result.stderr)

    def test_rejects_lockfile_changes_that_do_not_match(self):
        rand = add(ALPHA, "dependencies", "rand = { workspace = true }")
        cases = {
            "a missing change": ({ALPHA_PATH: rand}, "alpha 0.9.0"),
            "a change without a manifest change": ({"Cargo.lock": lock(alpha=["+rand 0.8.6"])}, "alpha 0.9.0"),
            "a change of another crate": ({ALPHA_PATH: rand, "Cargo.lock": lock(gamma=["+rand 0.8.6"])}, "alpha 0.9.0"),
            "an extra change": ({ALPHA_PATH: rand, "Cargo.lock": lock(alpha=["+rand 0.8.6", "+tokio"])}, "alpha 0.9.0"),
            "a change of a registry package": ({"Cargo.lock": lock(tokio=["+lonely"])}, "tokio 1.47.1"),
            "a removed dependency of a registry package": ({"Cargo.lock": lock(tokio=["-serde"])}, "tokio 1.47.1"),
            "a changed checksum": ({"Cargo.lock": replace(lock(), checksum("rand", "0.8.6"), "0" * 64)}, "rand 0.8.6"),
            "another changed field": (
                {"Cargo.lock": replace(lock(), 'name = "serde"\n', 'name = "serde"\nreplace = "serde 1.0.0"\n')},
                "serde 1.0.228",
            ),
            "a partial removal": (
                {
                    BETA_PATH: remove(remove(BETA, "rand = { workspace = true }"), "bitcoin = { workspace = true }"),
                    "Cargo.lock": lock(beta=["-rand 0.8.6"]),
                },
                "beta 0.9.0",
            ),
        }
        for case, (files, package) in cases.items():
            with self.subTest(case):
                self.assert_rejected(files, f"Cargo.lock doesn't match the dependency changes of {package}")

    def test_rejects_lockfile_changes_of_its_packages(self):
        cases = {
            "an added package": lock([*PACKAGES, ("new", "1.0.0", CRATES_IO, [])]),
            "a removed package": lock(
                [package for package in PACKAGES if package[0] != "zero"], zeta=["-zero 0.0.1", "-zero 0.1.0"]
            ),
            "a changed version": replace(lock(), 'version = "0.8.6"', 'version = "0.8.7"'),
            "a changed source": replace(lock(), f'source = "{DOGECOIN}"', f'source = "{DOGECOIN}0"'),
            "a changed version of Cargo.lock": replace(lock(), "version = 4", "version = 3"),
            "added metadata": lock() + '\n[metadata]\nkey = "value"\n',
        }
        for case, lockfile in cases.items():
            with self.subTest(case):
                self.assert_rejected(
                    {"Cargo.lock": lockfile}, "Cargo.lock adds or removes packages or changes its metadata"
                )

    def test_rejects_malformed_lockfiles(self):
        duplicate = lock() + '\n[[package]]\nname = "alpha"\nversion = "0.9.0"\n'
        self.assert_rejected({"Cargo.lock": duplicate}, "Cargo.lock has duplicate packages")
        self.assert_rejected(
            {"Cargo.lock": lock(alpha=["+serde"])}, "Cargo.lock lists a dependency of alpha 0.9.0 twice"
        )
        for dependencies in ["[1]", '{ serde = "1" }', '"serde"']:
            with self.subTest(dependencies):
                self.assert_rejected(
                    {"Cargo.lock": replace(lock(), 'dependencies = [\n "serde",\n]', f"dependencies = {dependencies}")},
                    "Cargo.lock lists the dependencies of alpha 0.9.0 as something other than strings",
                )


SLUG = "rs-alpha-alpha_test-0123abcd"
LABEL = "//rs/alpha:alpha_test"
LABELS = "//rs/alpha:alpha_test //rs/alpha:alpha_test_local"
HEADER = (
    "This PR was created by https://github.com/dfinity/ic/actions/runs/123 following"
    " `.claude/skills/fix-flaky-tests/SKILL.md` to deflake:\n* `//rs/alpha:alpha_test`\n* `//rs/alpha:alpha_test_local`\n"
    "\n---\n\n"
)
CLAUDE = "claude[bot] <209825114+claude[bot]@users.noreply.github.com>"
FIX = {"rs/alpha/src/lib.rs": "pub fn alpha() -> u32 {\n    2\n}\n"}


class BundleTest(ValidatorTest):
    """validate-deflake-bundle.sh on a bundle of a fix, in a repository that only has the base of origin."""

    def validate(
        self, files=FIX, *, fix=None, base=None, refs=("refs/heads/deflake",), edit=None, body=b"Fixes it.\n", unset=()
    ):
        """Bundles the fix of the files, or the given fix, like fix-flaky-test.yml does and validates it."""
        base = base or self.base
        fix = fix or self.repo.commit(files, parent=base)
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory(dir=self.tmp)))
        deflake = tmp / "runner" / "deflake"
        deflake.mkdir(parents=True)
        for ref in refs:
            self.repo.git("update-ref", ref, fix)
        bundle = deflake / "deflake.bundle"
        self.repo.git("bundle", "create", "-q", str(bundle), *refs, f"^{base}")
        if edit:
            bundle.write_bytes(edit(bundle.read_bytes()))
        if body is not None:
            (deflake / "body.md").write_bytes(body)
        self.check = Repo(tmp / "check", self.env)
        self.check.git("remote", "add", "origin", self.repo.path.as_uri())
        self.github_env = tmp / "github-env"
        env = self.env | {
            "RUNNER_TEMP": str(tmp / "runner"),
            "BASE_SHA": self.base,
            "SLUG": SLUG,
            "RUN_DATE": "2026-10-05",
            "LABEL": LABEL,
            "LABELS": LABELS,
            "RUN_ID": "123",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_REPOSITORY": "dfinity/ic",
            "GITHUB_ENV": str(self.github_env),
        }
        for name in unset:
            del env[name]
        script = SCRIPTS / "validate-deflake-bundle.sh"
        return subprocess.run(
            ["bash", script], cwd=self.check.path, env=env, capture_output=True, encoding="utf-8", errors="replace"
        )

    def assert_accepted(self, *args, **kwargs):
        result = self.validate(*args, **kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        return dict(line.split("=", 1) for line in self.github_env.read_text(encoding="utf-8").splitlines())

    def assert_rejected(self, message, *args, **kwargs):
        result = self.validate(*args, **kwargs)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stderr.splitlines()[-1], f"needs_human: {message}")
        return result

    def body(self, exported):
        # As bytes, since reading text would translate carriage returns.
        return Path(exported["BODY_FILE"]).read_bytes().decode()

    def diff_bytes(self, files):
        fix = self.repo.commit(files, parent=self.base)
        return len(self.repo.git("diff", "--no-renames", self.base, fix, raw=True))

    def test_prepares_the_pr(self):
        exported = self.assert_accepted(FIX)
        self.assertEqual(exported.keys(), {"BRANCH", "NEW", "TITLE", "BODY_FILE"})
        self.assertEqual(exported["BRANCH"], f"ai/deflake-{SLUG}-2026-10-05")
        self.assertEqual(exported["TITLE"], f"fix: deflake {LABEL}")
        self.assertEqual(self.body(exported), HEADER + "Fixes it.\n")
        headers, message = self.check.git("cat-file", "commit", exported["NEW"]).split("\n\n", 1)
        headers = [line.split(" ", 1) for line in headers.splitlines()]
        self.assertEqual(
            [(key, value.rsplit(" ", 2)[0]) for key, value in headers],
            [
                ("tree", self.check.git("rev-parse", "refs/deflake/fix^{tree}")),
                ("parent", self.base),
                ("author", CLAUDE),
                ("committer", CLAUDE),
            ],
        )
        self.assertEqual(message, f"fix: deflake {LABEL}")

    def test_accepts_allowed_files(self):
        self.assert_accepted(
            {
                "rs/alpha/src/lib.rs": "pub fn alpha() -> u32 {\n    2\n}\n",
                "rs/alpha/BUILD.bazel": 'rust_library(name = "alpha", crate_name = "alpha")\n',
                "rs/alpha/src/new file.rs": "\n",
                "rs/alpha/build.rs": "fn main() {}\n",
                "rs/ic_os/config/src/lib.rs": "\n",
                "packages/gamma/src/lib.rs": "pub fn gamma() {}\n",
                "ic-os/components/unit.service": "[Unit]\nAfter=network.target\n",
                "ic-os/components/Dockerfile": "FROM scratch\n",
            }
        )

    def test_accepts_dependency_changes(self):
        files = {ALPHA_PATH: add(ALPHA, "dependencies", "rand = { workspace = true }")}
        self.assert_accepted(files | {"Cargo.lock": lock(alpha=["+rand 0.8.6"])})
        self.assert_rejected("the fix changes dependencies beyond adding or removing workspace dependencies", files)

    def test_rejects_disallowed_files(self):
        disallowed = [
            "MODULE.bazel",
            "rs/x/MODULE.bazel",
            "rs/x/deps.MODULE.bazel",
            "MODULE.bazel.lock",
            "rs/x/MODULE.bazel.lock",
            "REPO.bazel",
            "rs/x/REPO.bazel",
            "WORKSPACE",
            "rs/x/WORKSPACE",
            "WORKSPACE.bazel",
            "rs/x/WORKSPACE.bazel",
            "rs/x/.cargo/config",
            "rs/x/.cargo/config.toml",
            "ic-os/x/.cargo/config.toml",
            "rs/x/rust-toolchain",
            "rs/x/rust-toolchain.toml",
            "rs/x/Cargo.lock",
            "packages/x/yarn.lock",
            "rs/x/requirements.txt",
            "rs/x/requirements-dev.txt",
            "rs/x/pyproject.toml",
            "rs/x/package.json",
            "rs/x/package-lock.json",
            "rs/x/go.mod",
            "rs/x/go.sum",
            "rs/x/defs.bzl",
            "ic-os/x/defs.bzl",
            "rs/x/.bazelrc",
            ".bazelrc",
            ".gitattributes",
            "rs/x/.gitattributes",
            ".gitmodules",
            "rs/ic_os/config/types/src/lib.rs",
            "rs/ic_os/config/types/src/new.rs",
            "rs/ic_os/config/types/BUILD.bazel",
            "Cargo.toml",
            ".github/workflows/x.yml",
            "bazel/x.bzl",
            "ci/x.sh",
            "README.md",
        ]
        result = self.validate({path: "x\n" for path in disallowed} | FIX)
        self.assertEqual(result.returncode, 1, result.stderr)
        message, paths = result.stderr.splitlines()[-1].split(": ", 1)[1].split(": ", 1)
        self.assertEqual(message, "the fix changes disallowed files")
        self.assertEqual(sorted(paths.split(" ")), sorted(disallowed))

    def test_rejects_paths_that_look_allowed(self):
        # The message quotes the paths for bash.
        cases = {
            "rsx/lib.rs": "rsx/lib.rs",
            "packagesx/lib.rs": "packagesx/lib.rs",
            "ic-osx/lib.rs": "ic-osx/lib.rs",
            " rs/lib.rs": "\\ rs/lib.rs",
            "r\\s/lib.rs": "r\\\\s/lib.rs",
            "x\n::error::injected": "$'x\\n::error::injected'",
        }
        for path, quoted in cases.items():
            with self.subTest(path):
                self.assert_rejected(f"the fix changes disallowed files: {quoted}", {path: "x\n"})

    def test_rejects_deleting_and_renaming_disallowed_files(self):
        self.assert_rejected("the fix changes disallowed files: bazel/defs.bzl", {"bazel/defs.bzl": None})
        renamed = {"bazel/defs.bzl": None, "rs/alpha/defs.txt": BASE_FILES["bazel/defs.bzl"]}
        self.assert_rejected("the fix changes disallowed files: bazel/defs.bzl", renamed)

    def test_rejects_symlinks_and_submodules(self):
        cases = {
            "an added symlink": {"rs/alpha/new.link": symlink("lib.rs")},
            "a changed symlink": {"rs/alpha/lib.link": symlink("src/main.rs")},
            "a deleted symlink": {"rs/alpha/lib.link": None},
            "a symlink replacing a file": {"rs/alpha/src/lib.rs": symlink("/etc/passwd")},
            "a file replacing a symlink": {"rs/alpha/lib.link": "pub fn alpha() {}\n"},
            "an added submodule": {"rs/alpha/new-sub": ("160000", self.root)},
            "a changed submodule": {"rs/alpha/sub": ("160000", self.root)},
            "a deleted submodule": {"rs/alpha/sub": None},
            "a file replacing a submodule": {"rs/alpha/sub": "x\n"},
        }
        for case, files in cases.items():
            with self.subTest(case):
                self.assert_rejected("the fix changes a symlink or submodule", files)

    def test_rejects_binary_files(self):
        self.assert_rejected("the fix changes binary files", {"rs/alpha/data.bin": b"\x00\x01\x02"})

    def test_limits_the_lines(self):
        self.assert_accepted({"rs/alpha/src/lines.rs": "x\n" * 1000})
        self.assert_rejected("the fix changes 1001 lines", {"rs/alpha/src/lines.rs": "x\n" * 1001})
        # Deleted lines count too, in all files, and a renamed file counts as deleted and added.
        deleted = {"rs/alpha/src/big.rs": None, "rs/alpha/src/lines.rs": "x\n" * 401}
        self.assert_rejected("the fix changes 1001 lines", deleted)
        renamed = {"rs/alpha/src/big.rs": None, "rs/alpha/src/moved.rs": BASE_FILES["rs/alpha/src/big.rs"]}
        self.assert_rejected("the fix changes 1200 lines", renamed)

    def test_limits_the_bytes(self):
        renamed = {"rs/alpha/src/wide.rs": None, "rs/alpha/src/moved.rs": BASE_FILES["rs/alpha/src/wide.rs"]}
        for case, files in {"a new file": {}, "a new and a renamed file": renamed}.items():
            with self.subTest(case):
                # The diff grows with the length of the new line, and has 1000000 bytes for this one.
                n = 1_000_000 - self.diff_bytes(files | {"rs/alpha/src/line.rs": "x\n"}) + 1
                self.assert_accepted(files | {"rs/alpha/src/line.rs": "x" * n + "\n"})
                long = files | {"rs/alpha/src/line.rs": "x" * (n + 1) + "\n"}
                self.assert_rejected("the diff of the fix has 1000001 bytes", long)

    def test_rejects_bundles_of_other_commits(self):
        self.assert_rejected(f"the bundle doesn't build on {self.base}", base=self.root)
        for index in [1, 2]:
            with self.subTest(f"another prerequisite at {index}"):
                another = lambda bundle: insert_into_header(bundle, index, f"-{self.root}")  # noqa: E731
                self.assert_rejected(f"the bundle doesn't build on {self.base}", edit=another)
        self.assert_rejected(
            "the bundle has other refs than refs/heads/deflake", refs=("refs/heads/deflake", "refs/heads/other")
        )
        self.assert_rejected("the bundle has other refs than refs/heads/deflake", refs=("refs/heads/fix",))
        # git bundle list-heads shows a ref with a space after its name.
        spaced = lambda bundle: replace(bundle, b" refs/heads/deflake\n", b" refs/heads/deflake x\n")  # noqa: E731
        self.assert_rejected("the bundle has other refs than refs/heads/deflake", edit=spaced)
        second = self.repo.commit({"rs/alpha/src/b.rs": "\n"}, parent=self.repo.commit(FIX, parent=self.base))
        self.assert_rejected("the fix isn't a single commit", fix=second)
        side = self.repo.commit(FIX, parent=self.base)
        merge = self.repo.git("commit-tree", f"{side}^{{tree}}", "-p", self.base, "-p", side, "-m", "merge")
        self.assert_rejected("the fix isn't a single commit", fix=merge)
        # git doesn't create a bundle of the base itself, but fetches one.
        empty = self.repo.git("pack-objects", "--stdout", stdin=b"", raw=True)
        itself = f"# v2 git bundle\n-{self.base}\n{self.base} refs/heads/deflake\n\n".encode() + empty
        self.assert_rejected("the fix isn't a single commit", edit=lambda _: itself)
        self.assert_rejected("the fix doesn't change anything", fix=self.repo.commit({}, parent=self.base))

    def test_rejects_a_bundle_without_prerequisites(self):
        orphan = self.repo.commit(BASE_FILES | FIX)
        self.assert_rejected(f"the bundle doesn't build on {self.base}", fix=orphan, base=self.root)
        # With the base as its prerequisite, the bundle still doesn't contain a fix on top of it.
        prerequisite = lambda bundle: insert_into_header(bundle, 1, f"-{self.base}")  # noqa: E731
        self.assert_rejected(f"the fix isn't on top of {self.base}", fix=orphan, base=self.root, edit=prerequisite)

    def test_rejects_unfetchable_bundles(self):
        self.assert_rejected("the bundle can't be fetched", edit=lambda bundle: bundle[:-30])
        # A tree with a .git directory, which git refuses to check out, doesn't pass fsck either.
        blob = self.repo.git("hash-object", "-w", "--stdin", stdin=b"[core]\n\tfsmonitor = touch /tmp/pwned\n")
        dotgit = self.repo.git("mktree", stdin=f"100644 blob {blob}\tconfig\n".encode())
        evil = self.repo.git("mktree", stdin=f"040000 tree {dotgit}\t.git\n".encode())
        alpha = self.repo.git("ls-tree", f"{self.base}:rs/alpha") + f"\n040000 tree {evil}\tevil\n"
        rs = replace_entry(self.repo, f"{self.base}:rs", "alpha", self.repo.git("mktree", stdin=alpha.encode()))
        root = replace_entry(self.repo, self.base, "rs", rs)
        fix = self.repo.git("commit-tree", root, "-p", self.base, "-m", "fix")
        self.assertIn("hasDotgit", self.assert_rejected("the bundle can't be fetched", fix=fix).stderr)

    def test_fails_without_a_body_or_an_input(self):
        result = self.validate(body=None)
        self.assertEqual(result.returncode, 1)
        self.assertIn("body.md", result.stderr)
        for name in ["BASE_SHA", "LABEL"]:
            with self.subTest(name):
                result = self.validate(unset=(name,))
                self.assertEqual(result.returncode, 1)
                self.assertIn(f"{name}: unbound variable", result.stderr)

    def test_turns_markup_in_the_body_into_text(self):
        cases = {
            "<!-- hidden -->": f"<{Z}!-- hidden -->",
            # Dropping invisible characters can't form markup.
            "<!\u200b-- hidden -->": f"<{Z}!-- hidden -->",
            "<deta\u200bils>hidden</details>": f"<{Z}details>hidden<{Z}/details>",
            "<?hidden?> <!X hidden> <![CDATA[hidden]]>": f"<{Z}?hidden?> <{Z}!X hidden> <{Z}![CDATA[hidden]]>",
            "<DETAILS open><SUMMARY>Logs</SUMMARY>hidden</DETAILS>": (
                f"<{Z}DETAILS open><{Z}SUMMARY>Logs<{Z}/SUMMARY>hidden<{Z}/DETAILS>"
            ),
            "<style>hidden</style> <https://example.com>": f"<{Z}style>hidden<{Z}/style> <{Z}https://example.com>",
            "&shy;&#8203;&#x200B;&AMP;&CounterClockwiseContourIntegral;": (
                f"&{Z}shy;&{Z}#8203;&{Z}#x200B;&{Z}AMP;&{Z}CounterClockwiseContourIntegral;"
            ),
            '[x]: /url "hidden"\n> - [y]: /url\n[a\\]b]: /url\n[^1]: hidden': (
                f'[x]{Z}: /url "hidden"\n> - [y]{Z}: /url\n[a\\]b]{Z}: /url\n[^1]{Z}: hidden'
            ),
            '[](https://hidden.example) [x](/url "hidden") ![hidden](/image.png)': (
                f'[]{Z}(https://hidden.example) [x]{Z}(/url "hidden") ![hidden]{Z}(/image.png)'
            ),
            # The info strings of code fences are shown as their first lines.
            "```mermaid hidden\nx\n```\n~~~ geojson\n~~~\n````~math\n````\n~~~`hidden\n~~~\n```\thidden\n```": (
                "```\nmermaid hidden\nx\n```\n~~~\n geojson\n~~~\n````\n~math\n````\n~~~\n`hidden\n~~~\n```\n\thidden\n```"
            ),
            # Fences only open at the start of a line, also in quotes and lists, whose indentation the info keeps.
            "1. ```sh\n   x\n   ```\n> ```mermaid hidden\n> y\n> ```\n- - ```z\n": (
                "1. ```\n   sh\n   x\n   ```\n> ```\n> mermaid hidden\n> y\n> ```\n- - ```\n    z\n"
            ),
            "~~x\n~~~~x\n```  x\n```\u00a0x\n```  \nWrite ```rust at the top.\n``\u200b`mermaid\n": (
                "~~x\n~~~~\nx\n```\n  x\n```\n\u00a0x\n```  \nWrite ```rust at the top.\n```\nmermaid\n"
            ),
            "| a | b |\n| :- | -: |\n| c | d | hidden |\n> a |\n> --- |\n|\t-\t|\nsetext\n---\n| a |\n| - |": (
                f"| a | b |\n| :-{Z} | -{Z}: |\n| c | d | hidden |\n> a |\n> -{Z}-{Z}-{Z} |\n|\t-{Z}\t|\nsetext\n---\n"
                f"| a |\n| -{Z} |"
            ),
            "$$\nx % hidden\n$$ and $t$ and \\$x\\$": "&#36;&#36;\nx % hidden\n&#36;&#36; and &#36;t&#36; and &#36;x&#36;",
            "@octocat @Octocat (@dfinity/team) _@octocat_ \u00e9@octocat path/@octocat @1user": (
                f"@{Z}octocat @{Z}Octocat (@{Z}dfinity/team) _@{Z}octocat_ \u00e9@{Z}octocat path/@{Z}octocat @{Z}1user"
            ),
            # Invisible, private-use, unassigned and control characters.
            "a\u200bb\u202ec\ue000d\u0378e\ufe0ff\U000e0100g\u034fh\u180bi\u3164j\U000e0041k\x1bl\x7fm\x85n\u0600o\rp\U000f0000r\r\n\tq": (
                "abcdefghijklmnopr\n\tq"
            ),
            # Anything else stays, and code looks the same.
            "Use `Vec<u8>`, `&self` and `x[0]: y`, a < b && c > d, x @ 1..=5, <1, <\u00e9, [a][b], &a_b; &; \\n, ``x``.": (
                f"Use `Vec<{Z}u8>`, `&self` and `x[0]{Z}: y`, a < b && c > d, x @ 1..=5, <1, <\u00e9, [a][b], &a_b; &; \\n, ``x``."
            ),
            "https://example.com/a?b=1&c=2 bas@dfinity.org git@github.com:dfinity/ic.git @_x": (
                "https://example.com/a?b=1&c=2 bas@dfinity.org git@github.com:dfinity/ic.git @_x"
            ),
        }
        for body, expected in cases.items():
            with self.subTest(body):
                self.assertEqual(self.body(self.assert_accepted(body=body.encode())), HEADER + expected)

    def test_truncates_the_body(self):
        exported = self.assert_accepted(body=("\u00e9" * 70_000).encode())
        self.assertEqual(self.body(exported), HEADER + "\u00e9" * 60_000)
        # Across lines and paragraphs, a NUL, and including what the sanitizer inserts.
        exported = self.assert_accepted(body=("<a\n" * 30_000).encode())
        self.assertEqual(self.body(exported), HEADER + f"<{Z}a\n" * 15_000)
        exported = self.assert_accepted(body=("x" * 40_000 + "\n\n" + "y" * 40_000).encode())
        self.assertEqual(self.body(exported), HEADER + "x" * 40_000 + "\n\n" + "y" * 19_998)
        exported = self.assert_accepted(body=b"x" * 40_000 + b"\x00" + b"y" * 40_000)
        self.assertEqual(self.body(exported), HEADER + "x" * 40_000 + "y" * 20_000)
        exported = self.assert_accepted(body=("$" * 13_000).encode())
        self.assertEqual(self.body(exported), HEADER + "&#36;" * 12_000)
        exported = self.assert_accepted(body=("x" * 59_990 + "\n```mermaid").encode())
        self.assertEqual(self.body(exported), HEADER + "x" * 59_990 + "\n```\nmerma")
        exported = self.assert_accepted(body=("x" * 59_997 + "\n|-|").encode())
        self.assertEqual(self.body(exported), HEADER + "x" * 59_997 + "\n|-")
        # Without the invisible characters, the first 240000 bytes have fewer than 60000 characters.
        exported = self.assert_accepted(body=("\u200b" * 79_990 + "0123456789" * 4).encode())
        self.assertEqual(self.body(exported), HEADER + "0123456789" * 3)
        # They end in the middle of an emoji, which is decoded like other malformed UTF-8.
        exported = self.assert_accepted(body=("\u200b" * 79_999 + "😀").encode())
        self.assertEqual(self.body(exported), HEADER + "\ufffd")
        self.assertEqual(self.body(self.assert_accepted(body=b"a\xffb\xed\xa0\x80c")), HEADER + "a\ufffdb\ufffdc")


def insert_into_header(bundle, index, line):
    """The bundle with the line inserted into its header, whose line 0 is the signature."""
    header, pack = bundle.split(b"\n\n", 1)
    lines = header.split(b"\n")
    lines.insert(index, line.encode())
    return b"\n".join(lines) + b"\n\n" + pack


def replace_entry(repo, tree, name, new):
    """The tree with its entry of the given name, a tree, replaced by the new one."""
    entries = [entry for entry in repo.git("ls-tree", tree).splitlines() if not entry.endswith(f"\t{name}")]
    return repo.git("mktree", stdin="\n".join([*entries, f"040000 tree {new}\t{name}"]).encode() + b"\n")


if __name__ == "__main__":
    unittest.main()
