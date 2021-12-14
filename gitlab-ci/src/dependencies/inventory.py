#!/usr/bin/env python3
"""Helper package for parsing dependency inventories."""
import abc
import collections
import dataclasses
import fnmatch
import logging
import os
import pathlib
import subprocess
import typing

import git
import gitlab
import json5
import jsonschema
import toml

import git_changes

PROJECT_ROOT = pathlib.Path(os.environ.get("CI_PROJECT_DIR", pathlib.Path(__file__).parent.parent.parent.parent))

GITLAB_TOKEN = os.environ.get("GITLAB_API_TOKEN", "")
if GITLAB_TOKEN is None:
    logging.error("GITLAB_API_TOKEN is not set, can not send comments to GitLab")

GITLAB_PROJECT_NAME = os.environ.get("CI_PROJECT_PATH", "dfinity-lab/core/ic")
DELTA_HEADER = "*Dependency Delta*"

with open(pathlib.Path(__file__).parent / "inventory.schema") as f:
    SCHEMA = json5.load(f)


def is_owned_path(path):
    if path.startswith("https://gitlab.com/dfinity-lab/"):
        return True
    if path.startswith("https://github.com/dfinity/"):
        return True
    if path.startswith("https://github.com/dfinity-lab/"):
        return True
    if path.startswith("/"):
        return True

    return False


@dataclasses.dataclass
class Dependency:
    """Data class for dependency information."""

    name: str
    version: str
    is_external: bool = True

    def _key(self):
        return self.name + self.version

    def __hash__(self):
        """Hash to be used for deduplication in sets and dicts."""
        return hash(self._key())

    def __eq__(self, other):
        """Compare two dependencies."""
        return self._key() == other._key()

    @classmethod
    def from_cargo_tree(cls, line: str) -> "Dependency":
        """
        Convert single line from cargo tree to a dependency.

        Expects that the depth prefix was already removed.
        """
        is_external = True

        name, line = line.split(" ", 1)
        if " " in line:
            version, line = line.split(" ", 1)
            path = line.split(" ")[0]
            if path != "(*)" and is_owned_path(path[1:-1]):
                is_external = False
        else:
            version = line

        if version[0] != "v":
            raise ValueError("Version should start with v")
        version = version[1:]
        return Dependency(name=name, version=version, is_external=is_external)


@dataclasses.dataclass
class PackageDiff:
    """Data class for package dependency diff."""

    name: str
    added_deps: set = dataclasses.field(default_factory=set)
    removed_deps: set = dataclasses.field(default_factory=set)
    added_direct_deps: set = dataclasses.field(default_factory=set)

    def is_empty(self) -> bool:
        """Return True if package diff is empty."""
        return not len(self.added_deps) and not len(self.removed_deps) and not len(self.added_direct_deps)


@dataclasses.dataclass
class PackageDiffDelta:
    """Data class for diff deltas."""

    total_added: int = 0
    total_removed: int = 0
    internal_added: int = 0
    internal_removed: int = 0

    def get_total_delta(self):
        """Return total dependency delta."""
        return self.total_added - self.total_removed

    def get_internal_delta(self):
        """Return internal dependency delta."""
        return self.internal_added - self.internal_removed


class PackageManager(abc.ABC):
    """Base class for helper classes for different package managers."""

    @abc.abstractmethod
    def get_inventory_file(self) -> pathlib.Path:
        """Return path to inventory file."""

    @abc.abstractmethod
    def get_external_direct_deps(self) -> typing.Dict[str, typing.Set[Dependency]]:
        """Key is a dependency name, value is a set of all versions in use."""

    @abc.abstractmethod
    def get_package_diff(self) -> typing.Dict[str, PackageDiff]:
        """Return list of package diffs for modified packages."""

    @abc.abstractmethod
    def inventory_changed(self) -> bool:
        """Return true if inventory was modified."""


class Cargo(PackageManager):
    """Helper for cargo-related functions."""

    def __init__(self, root=PROJECT_ROOT):
        """Construct default object."""
        self.package_files = {}
        self.direct_deps = None
        self.root = root

    @classmethod
    def is_duplicate_line(cls, dep_line: str) -> bool:
        """Return True if this line already occurred in the output before."""
        return dep_line.endswith("(*)")

    @classmethod
    def parse_depth(cls, dep_line: str) -> typing.Tuple[int, str]:
        """Return depth as int and the remaining dependency string."""
        i = 0
        while dep_line[i].isdigit():
            i += 1
        return (int(dep_line[:i]), dep_line[i:])

    def get_inventory_file(self) -> pathlib.Path:
        """Return path to inventory file."""
        return self.root / ".dependencies" / "cargo.json"

    def get_external_direct_deps(self) -> typing.Dict[str, typing.Set[Dependency]]:
        """Return dict of external direct dependencies."""
        # Running cargo tree for the whole codebase is expensive.
        if self.direct_deps:
            return self.direct_deps

        self.direct_deps = collections.defaultdict(set)
        logging.info("Running cargo tree...")
        tree = self._get_cargo_tree_output()
        current_path = []

        logging.info("Parsing cargo tree...")
        # nix-shell outputs affinity, etc, so skip to the first package
        while tree[0] != "0":
            _, tree = tree.split("\n", 1)

        for dep_line in tree.split("\n"):
            if not dep_line:
                continue
            depth, dep_line = Cargo.parse_depth(dep_line)
            dependency = Dependency.from_cargo_tree(dep_line)
            if depth == len(current_path):
                current_path.append(dependency)
            else:
                current_path[depth] = dependency
                del current_path[depth + 1 :]

            if dependency.is_external:
                parent = current_path[depth - 1]
                if not parent.is_external:
                    self.direct_deps[dependency.name].add(dependency)

        return self.direct_deps

    def get_package_diff(self) -> typing.Dict[str, PackageDiff]:
        """Return list of dependency diffs for modified packages."""
        changed = []

        for f in git_changes.get_changed_files(self.root, ["rs/"]):
            if fnmatch.fnmatch(f, "*/Cargo.toml"):
                changed.append(pathlib.Path(f))

        if not changed:
            logging.info("No Cargo.toml modified.")
            return {}

        logging.info(
            "Modified Cargo.toml files: %s",
            ",".join(map(lambda x: x.as_posix(), changed)),
        )

        diffs = {}
        for mfile in changed:
            if not mfile.exists():
                # Manifest was completely removed.
                continue
            logging.info("Collecting current dependencies for %s", mfile.as_posix())
            with open(mfile) as f:
                manifest = toml.load(f)

            if "package" not in manifest:
                logging.info("No package entry, probably a workspace, skipping")
                continue

            diff = PackageDiff(name=manifest["package"]["name"])
            for dep_line in self._enumerate_package_deps(manifest):
                depth, dep_line = Cargo.parse_depth(dep_line)
                dependency = Dependency.from_cargo_tree(dep_line)

                if dependency.name == diff.name:
                    # Skip the package itself
                    continue
                if depth == 1 and dependency.is_external:
                    # This should be done before duplicate check, because
                    # the same dependency may be direct and indirect.
                    diff.added_direct_deps.add(dependency)

                if Cargo.is_duplicate_line(dep_line):
                    continue

                diff.added_deps.add(dependency)

            diffs[diff.name] = diff

        # Running cargo tree modifies local Cargo.lock
        logging.info("Resetting local git changes")
        repo = git.Repo(self.root)
        repo.git.reset("--hard")
        merge_top = repo.head.commit
        logging.info("Checking out merge base")
        repo.git.checkout(git_changes.get_merge_base(repo)[0].hexsha)

        for mfile in changed:
            if not mfile.exists():
                # Manifest was freshly added.
                continue

            logging.info("Collecting previous dependencies for %s", mfile.as_posix())
            with open(mfile) as f:
                manifest = toml.load(f)

            if "package" not in manifest:
                logging.info("No package entry, probably a workspace, skipping")
                continue

            name = manifest["package"]["name"]
            if name not in diffs:
                diffs[name] = PackageDiff(name=name)

            # (*) only marks a truncated duplicate subtree, duplicated
            # dependencies without further dependencies will not have it.
            already_seen = set()
            diff = diffs[name]
            for dep_line in self._enumerate_package_deps(manifest):
                depth, dep_line = Cargo.parse_depth(dep_line)
                dependency = Dependency.from_cargo_tree(dep_line)

                if dependency.name == diff.name:
                    # Skip the package itself
                    continue

                if depth == 1 and dependency.is_external and dependency in diff.added_direct_deps:
                    diff.added_direct_deps.remove(dependency)

                if Cargo.is_duplicate_line(dep_line) or dependency in already_seen:
                    continue

                if dependency in diff.added_deps:
                    already_seen.add(dependency)
                    diff.added_deps.remove(dependency)
                else:
                    diff.removed_deps.add(dependency)

        logging.info("Resetting local git changes")
        repo.git.reset("--hard")
        logging.info("Checking out merge top")
        repo.git.checkout(merge_top)

        return {name: diffs[name] for name in diffs if not diffs[name].is_empty()}

    def _enumerate_package_deps(self, manifest):
        logging.info("Running cargo tree...")
        try:
            tree = self._get_cargo_tree_output(
                package="{}:{}".format(manifest["package"]["name"], manifest["package"]["version"])
            )
        except subprocess.CalledProcessError:
            return

        logging.info("Parsing cargo tree...")
        # nix-shell outputs affinity, etc, so skip to the first package
        while not tree[0] == "0":
            _, tree = tree.split("\n", 1)

        for dep_line in tree.split("\n"):
            if not dep_line:
                continue
            yield dep_line

    def _get_cargo_tree_output(self, package=None, offline="", cargo_home=""):
        logging.info("Running cargo tree...")
        command = f"cd {self.root}/rs && {cargo_home} cargo tree --edges=no-dev --prefix=depth {offline}"
        if package:
            command += f" -p {package}"
        return subprocess.check_output(
            [
                "nix-shell",
                "--run",
                command,
            ],
            cwd=PROJECT_ROOT / "rs",
            encoding="utf-8",
        ).strip()

    def inventory_changed(self) -> bool:
        """Return True if inventory was modified."""
        if git_changes.get_changed_files(
            self.root,
            [self.get_inventory_file().relative_to(self.root).as_posix()],
        ):
            logging.info("Inventory changed.")
            return True
        logging.info("Inventory did not change.")
        return False


class Inventory:
    """Dependencty inventory helper."""

    @dataclasses.dataclass
    class Error:
        """Data class for inventory error reporting."""

        message: str
        is_fatal: bool = False

    def __init__(self, package_manager: PackageManager, use_gitlab=True):
        """Load dependency inventory from a file."""
        with open(package_manager.get_inventory_file()) as f:
            self.dependencies = json5.load(f)

        self.package_manager = package_manager
        self.use_gitlab = use_gitlab

    def _comment_on_gitlab(self, deltas):
        """Add a gitlab comment with dependency delta info."""
        if not deltas or not GITLAB_TOKEN:
            return

        comment_body = self._generate_comment_markdown(deltas)
        glab = gitlab.Gitlab("https://gitlab.com", private_token=os.environ["GITLAB_API_TOKEN"])
        glab.auth()  # needed for setting glab.user.username (current user)
        glab_repo = glab.projects.get(GITLAB_PROJECT_NAME)
        for merge_req in glab_repo.mergerequests.list(
            state="opened",
            order_by="updated_at",
            source_branch=os.environ["CI_COMMIT_REF_NAME"],
        ):
            comment = None
            for note in merge_req.notes.list():
                if note.author["username"] == glab.user.username and note.body.startswith(DELTA_HEADER):
                    comment = note
                    break
            if comment:
                comment.body = comment_body
                comment.save()
            else:
                merge_req.notes.create({"body": comment_body})

    def _generate_comment_markdown(self, deltas):
        """Generate dependency delta comment using markdown."""
        delta_body = DELTA_HEADER + "\n"
        for name, delta in deltas.items():
            delta_body += (
                "* {}\n" "  * Internal: {:+} ({} added, {} removed)\n" "  * Total: {:+} ({} added, {} removed)\n"
            ).format(
                name,
                delta.get_internal_delta(),
                delta.internal_added,
                delta.internal_removed,
                delta.get_total_delta(),
                delta.total_added,
                delta.total_removed,
            )
        return delta_body

    def validate(self):
        """Validate the inventory."""
        errors = []

        logging.info("Enumerate changed packages")
        diffs = self.package_manager.get_package_diff()

        if not diffs:
            if not self.package_manager.inventory_changed():
                logging.info("Inventory and dependencies were not modified, skipping")
                return []

        try:
            jsonschema.validate(instance=self.dependencies, schema=SCHEMA)
        except jsonschema.ValidationError as e:
            return [
                self.Error(
                    message="JSON Schema validation failed with the following error:\n{}\n"
                    "The schema can be found here: gitlab-ci/src/dependencies/inventory.schema.".format(e.message),
                    is_fatal=True,
                )
            ]

        external_direct_deps = self.package_manager.get_external_direct_deps()
        for d in self.dependencies:
            logging.info("Validating %s", d)
            if d not in external_direct_deps:
                errors.append(
                    self.Error(
                        message="{} is not referenced in any manifest file.".format(d),
                        is_fatal=True,
                    )
                )
            elif len(external_direct_deps[d]) > 1:
                version_missing = []
                owners_count = collections.defaultdict(int)
                for owner in self.dependencies[d]["owners"]:
                    if "versions" not in owner:
                        version_missing.append(owner["email"])
                        continue
                    for version in owner["versions"]:
                        owners_count[version] += 1
                        if Dependency(name=d, version=version) not in external_direct_deps[d]:
                            errors.append(
                                self.Error(
                                    message="Version {} of package {} is not used, but is owned by {}".format(
                                        version, d, owner["email"]
                                    ),
                                    is_fatal=True,
                                )
                            )
                            continue

                insufficient_owners = [v for v, c in owners_count.items() if c < 2]
                if insufficient_owners:
                    errors.append(
                        self.Error(
                            message="The following versions of {} have less than 2 owners: {}".format(
                                d, ",".join(sorted(insufficient_owners))
                            ),
                            is_fatal=True,
                        )
                    )

                if version_missing:
                    errors.append(
                        self.Error(
                            message="Multiple versions of {} are in use: {}, but "
                            "the following owners do not specify a version "
                            "explicitly: {}".format(
                                d,
                                sorted([x.version for x in external_direct_deps[d]]),
                                version_missing,
                            ),
                            is_fatal=True,
                        )
                    )
            else:
                has_version = []
                for owner in self.dependencies[d]["owners"]:
                    if "versions" in owner:
                        has_version.append("{} ({})".format(owner["email"], owner["versions"]))
                if has_version:
                    errors.append(
                        self.Error(
                            message="Only one version of {} is in use, but the "
                            "following owners explicitly specify versions: {}".format(d, sorted(has_version)),
                            is_fatal=True,
                        )
                    )

        deltas = {}
        for package, diff in diffs.items():
            delta = PackageDiffDelta(total_added=len(diff.added_deps), total_removed=len(diff.removed_deps))
            for dep in diff.added_deps:
                if not dep.is_external:
                    delta.internal_added += 1

            for dep in diff.removed_deps:
                if not dep.is_external:
                    delta.internal_removed += 1
            if delta.total_added > 0 or delta.total_removed > 0:
                # Diff may be non-empty if direct dependencies were added. This may not
                # affect total dependencies if these were already present indirectly.
                deltas[package] = delta

            for dep in diff.added_direct_deps:
                if dep.name not in self.dependencies:
                    errors.append(
                        self.Error(
                            message="New dependency {} is added, but it is not in the inventory".format(dep.name)
                        )
                    )
                    continue

                if len(external_direct_deps[dep.name]) > 1:
                    # Several versions of this dependency are in use, ensure the
                    # added one is in the inventory.
                    found = False
                    for owner in self.dependencies[dep.name]["owners"]:
                        if "versions" not in owner:
                            continue
                        for version in owner["versions"]:
                            if version == dep.version:
                                found = True
                                break
                        if found:
                            break
                    if not found:
                        errors.append(
                            self.Error(
                                message="Version {} of {} is added, but is not owned by anyone.".format(
                                    dep.version, dep.name
                                )
                            )
                        )
        if self.use_gitlab:
            self._comment_on_gitlab(deltas)

        return errors
