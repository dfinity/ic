#!/usr/bin/env python3
"""Helper package for parsing dependency inventories."""
import abc
import dataclasses
import fnmatch
import json
import logging
import os
import pathlib
import subprocess
import typing

import git
import gitlab
import toml
from aenum import MultiValueEnum
from codeowners import CodeOwners
from cvss import CVSS3

import git_changes


PROJECT_ROOT = pathlib.Path(os.environ.get("CI_PROJECT_DIR", pathlib.Path(__file__).parent.parent.parent.parent))


GITLAB_TOKEN = os.environ.get("GITLAB_API_TOKEN", "")
if GITLAB_TOKEN is None:
    logging.error("GITLAB_API_TOKEN is not set, can not send comments to GitLab")

GITLAB_PROJECT_NAME = os.environ.get("CI_PROJECT_PATH", "dfinity-lab/core/ic")
DELTA_HEADER = "*Dependency Delta*"
CARGO_ADVISORY_DB = "./advisory-db"
USE_NIX_SHELL = True


with open(pathlib.Path(f"{PROJECT_ROOT}/.gitlab/CODEOWNERS")) as file:
    OWNERS = CodeOwners(file.read())


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


class RiskRating(MultiValueEnum):
    CRITICAL = tuple([x for x in range(90, 101)])
    HIGH = tuple([x for x in range(70, 90)])
    MEDIUM = tuple([x for x in range(40, 70)])
    LOW = tuple([x for x in range(0, 40)])


@dataclasses.dataclass
class Dependency:
    """Data class for dependency information."""

    name: str
    version: str
    owner: typing.List = dataclasses.field(default_factory=list)
    is_external: bool = True

    def __key(self):
        return self.name + self.version

    def __hash__(self):
        """Hash to be used for deduplication in sets and dicts."""
        return hash(self.__key())

    def __eq__(self, other):
        """Compare two dependencies."""
        return self.__key() == other.__key()

    @classmethod
    def from_cargo_tree(cls, line: str) -> "Dependency":
        """
        Convert single line from cargo tree to a dependency.

        Expects that the depth prefix was already removed.
        and the line is not empty or malformed
        """
        is_external = True
        name, line = line.split(" ", 1)
        path, owner = "", []
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

        if path:
            path = os.path.relpath(path[1:-1], PROJECT_ROOT) + "/"
            owner = OWNERS.of(path)

        return Dependency(name=name, version=version, is_external=is_external, owner=owner)


@dataclasses.dataclass
class PackageVulnerableDependency:
    """The internal crate under consideration (package_name:package_version)"""

    package_name: str

    """The codeowner / team owner for the internal crate"""
    codeowner: str

    """The dependency which has a vulnerability"""
    vulnerable_dependency: Dependency

    """Description of the vulnerability"""
    reason: str

    """Fixed version of dependency is available to update"""
    fix: typing.List[str]

    """True if the vulnerable dependency is a direct dependency"""
    is_vulnerable_dependency_direct: bool

    """ A direct dependency for the given crate which is affected.
        if is_vulnerable_dependency_direct is True
            This is the vulenerable dependency
        else
            The vulnerable dependecy is in the dependency tree of the direct dependency"""
    direct_dependency: Dependency

    """Contains the chain of dependencies between package direct dependency and
    actual vulnerable dependency"""
    dependency_chain: typing.List[Dependency] = dataclasses.field(default_factory=list)

    """Get a risk rating for the vulnerable dependency based on the CVSS BASE score. If CVSS
    score is not available, it will have RiskRating.MEDIUM by default"""
    risk_rating: RiskRating = RiskRating(5)

    def __key(self):
        """Implement key for PackageVulnerableDependency"""
        return (
            self.package_name,
            self.vulnerable_dependency.name + ":" + self.vulnerable_dependency.version,
            self.direct_dependency.name + ":" + self.direct_dependency.version,
            self.is_vulnerable_dependency_direct,
            tuple(self.dependency_chain),
            self.codeowner,
        )

    def __hash__(self):
        """Implement hash for PackageVulnerableDependency"""
        return hash(self.__key())

    def __eq__(self, other):
        """Implement eq for PackageVulnerableDependency"""
        return self.__key() == other.__key()

    def __lt__(self, other):
        """Implement lt for PackageVulnerableDependency"""
        return self.__key() < other.__key()

    def __str__(self):
        """Implement str for PackageVulnerableDependency"""
        return str(self.__key())

    def __repr__(self):
        """Implement repr for PackageVulnerableDependency"""
        return str(self.__key())


@dataclasses.dataclass
class PackageDiff:
    """Data class for package dependency diff."""

    name: str
    added_deps: set = dataclasses.field(default_factory=set)
    removed_deps: set = dataclasses.field(default_factory=set)
    added_direct_deps: set = dataclasses.field(default_factory=set)
    removed_direct_deps: set = dataclasses.field(default_factory=set)

    def is_empty(self) -> bool:
        """Return True if package diff is empty."""
        return (
            not len(self.added_deps)
            and not len(self.removed_deps)
            and not len(self.added_direct_deps)
            and not len(self.removed_direct_deps)
        )


class PackageManager(abc.ABC):
    """Base class for helper classes for different package managers."""

    @abc.abstractmethod
    def get_inventory_file(self) -> pathlib.Path:
        """Return path to inventory file."""

    @abc.abstractmethod
    def get_external_direct_deps(self) -> typing.List[typing.Dict]:
        """Key is a dependency name, value is a set of all versions in use."""

    @abc.abstractmethod
    def get_package_diff(self) -> typing.Dict[str, PackageDiff]:
        """Return list of package diffs for modified packages."""

    @abc.abstractmethod
    def inventory_changed(self) -> bool:
        """Return true if inventory was modified."""

    @abc.abstractmethod
    def get_vulnerable_dependencies(self, crates=None) -> typing.Set[Dependency]:
        """Return list of vulnerable dependencies"""

    @abc.abstractmethod
    def get_modified_crates(self) -> typing.Set[str]:
        """Return list of modified internal crates"""

    @abc.abstractmethod
    def create_external_inventory(self) -> typing.Dict[str, typing.Set]:
        """Return the entire inventory of external dependencies"""


class ProcessExecutor:
    def __init__(self, command):
        self.command = command

    @staticmethod
    def execute_command(command, cwd, environment):
        environ = dict(os.environ)
        environ.update(environment)
        logging.info("Executing : " + command)
        if USE_NIX_SHELL:
            result = subprocess.run(
                [
                    "nix-shell",
                    "--run",
                    command,
                ],
                cwd=cwd,
                encoding="utf-8",
                env=environ,
                capture_output=True,
                text=True,
            )
        else:
            command = command.split()
            result = subprocess.run(command, cwd=cwd, encoding="utf-8", capture_output=True, text=True, env=environ)
        if result.returncode > 1:
            logging.error("Process Executor failed for " + str(command))
            logging.error(result.stderr)
            logging.error(result.stdout)
            raise subprocess.CalledProcessError(result.returncode, command, result.args, result.stderr)
        else:
            return result.stdout.strip()


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
        return int(dep_line[:i]), dep_line[i:]

    def get_inventory_file(self) -> pathlib.Path:
        """Return path to inventory file."""
        return pathlib.Path(f"{self.root}/.dependencies/cargo.json")

    def get_whitelist_file(self) -> pathlib.Path:
        """Return path to whitelist file."""
        return pathlib.Path(f"{self.root}/.dependencies/vulnerable_crates_whitelist.json")

    # add method for external dependency file

    def _enumerate_package_deps(self, manifest):
        try:
            tree = self._get_cargo_tree_output(
                package="{}:{}".format(manifest["package"]["name"], manifest["package"]["version"])
            )
        except subprocess.CalledProcessError:
            logging.error("cargo tree failed for " + manifest["package"]["name"] + ":" + manifest["package"]["version"])
            return
        logging.info("Parsing cargo tree...")
        # nix-shell outputs affinity, etc, so skip to the first package
        while tree and not tree[0] == "0":
            _, tree = tree.split("\n", 1)

        for dep_line in tree.split("\n"):
            if not dep_line:
                continue
            yield dep_line

    def _get_cargo_tree_output(self, cargo_home=None, package=None, invert_deps=None, offline=False):
        logging.info("Running cargo tree...")
        environment = {}
        cargo_bin = ""
        cwd = f"{self.root}/rs"
        if cargo_home is not None:
            cargo_bin = f"{cargo_home}/bin/"
            environment["CARGO_HOME"] = cargo_home
        command = f"{cargo_bin}cargo tree --edges=no-dev,no-proc-macro --prefix=depth"
        if package:
            if isinstance(package, str):
                command += f" -p {package}"
            elif isinstance(package, list):
                package_join = " -p ".join(package)
                command += f" -p {package_join}"
        if invert_deps:
            command += f" -i {invert_deps}"
        if offline:
            command += " --offline"
        return ProcessExecutor.execute_command(command, cwd, environment)

    def _get_cargo_audit_output(self, cargo_home=None):
        logging.info("Running cargo audit...")
        environment = {}
        advisory_path = ""
        cargo_bin = ""
        cwd = f"{self.root}/rs"
        if cargo_home is not None:
            cargo_bin = f"{cargo_home}/bin/"
            environment["CARGO_HOME"] = cargo_home
            advisory_path = f"{cargo_home}/advisory-db/"

        command = f"{cargo_bin}cargo audit --json"

        if advisory_path:
            command += f" -d {advisory_path} --stale -n"

        return ProcessExecutor.execute_command(command, cwd, environment)

    def _get_cargo_workspace_output(self, cargo_home=None):
        logging.info("Running cargo workspaces...")
        environment = {}
        cargo_bin = ""
        cwd = f"{self.root}/rs"
        if cargo_home is not None:
            cargo_bin = f"{cargo_home}/bin/"
            environment["CARGO_HOME"] = cargo_home

        command = f"{cargo_bin}cargo workspaces list --json"
        return ProcessExecutor.execute_command(command, cwd, environment)

    """
    This will recreate the entire inventory file and takes a
    lot of time since it parse through every Cargo.toml file
    to identify external dependencies.
    """

    def create_external_inventory(self) -> typing.Dict[str, typing.Set]:
        external_inventory: typing.List[typing.Dict] = []
        try:
            cargo_workspace_out = self._get_cargo_workspace_output()
            while cargo_workspace_out[0] != "[":
                _, cargo_workspace_out = cargo_workspace_out.split("\n", 1)
            workspace = json.loads(cargo_workspace_out)
        except Exception as err:
            logging.error("Unable to parse cargo workspace JSON " + str(err))
            return external_inventory

        for internal_crate in workspace:
            logging.info(
                "Updating inventory for dependencies in internal crate "
                + internal_crate["name"]
                + ":"
                + internal_crate["version"]
            )
            for dep_line in self._enumerate_package_deps(
                {"package": {"name": internal_crate["name"], "version": internal_crate["version"]}}
            ):
                depth, dep_line = Cargo.parse_depth(dep_line)
                dependency = Dependency.from_cargo_tree(dep_line)

                if dependency.name == internal_crate["name"]:
                    continue
                if depth == 1 and dependency.is_external:
                    dep_index = next(
                        (
                            index
                            for index, crate in enumerate(external_inventory)
                            if dependency.name + ":" + dependency.version == crate["name"] + ":" + crate["version"]
                        ),
                        -1,
                    )
                    if dep_index == -1:
                        logging.info("No entry for " + dependency.name + ":" + dependency.version + ". Creating...")
                        external_inventory.append(
                            {
                                "name": dependency.name,
                                "version": dependency.version,
                                "internal_crates": set([internal_crate["name"]]),
                                "count": 1,
                            }
                        )
                    else:
                        logging.info("Entry found for " + dependency.name + ":" + dependency.version + ". Updating...")
                        external_inventory[dep_index]["internal_crates"].update([internal_crate["name"]])
                        external_inventory[dep_index]["count"] = external_inventory[dep_index]["count"] + 1

                if Cargo.is_duplicate_line(dep_line):
                    continue

        for index, external_crate in enumerate(external_inventory):
            external_inventory[index]["internal_crates"] = list(external_crate["internal_crates"])
        return sorted(external_inventory, key=lambda crate: crate["count"], reverse=True)

    def get_package_diff(self) -> typing.Dict[str, PackageDiff]:
        """Return list of dependency diffs for modified packages."""
        changed = []

        for changed_file in git_changes.get_changed_files(self.root, ["rs/"]):
            if fnmatch.fnmatch(changed_file, "*/Cargo.toml"):
                changed.append(pathlib.Path(changed_file))

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
            with open(mfile) as changed_file:
                manifest = toml.load(changed_file)

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

        # Reset to head creates an exception on CI
        try:
            active_branch = repo.active_branch
        except Exception as err:
            logging.info("Running on CI, usuing HEAD hexsha instead of branch name to revert " + str(err))
            active_branch = repo.head.commit

        logging.info("Checking out merge base")
        repo.git.checkout(git_changes.get_merge_base(repo)[0].hexsha)

        for mfile in changed:
            if not mfile.exists():
                # Manifest was freshly added.
                continue

            logging.info("Collecting previous dependencies for %s", mfile.as_posix())
            with open(mfile) as changed_file:
                manifest = toml.load(changed_file)

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
                    if depth == 1 and dependency.is_external:
                        diff.removed_direct_deps.add(dependency)

        logging.info("Resetting local git changes")
        repo.git.reset("--hard")
        logging.info("Checking out merge top")
        repo.git.checkout(active_branch)

        return {name: diffs[name] for name in diffs if not diffs[name].is_empty()}

    def get_external_direct_deps(self) -> typing.List[typing.Dict]:
        logging.info("Getting newly added external dependencies...")
        external_new_deps: typing.List[typing.Dict] = []
        package_diffs = self.get_package_diff()
        if package_diffs:
            for internal_crate, diff in package_diffs.items():
                for dep in diff.added_direct_deps:
                    if dep.is_external:
                        dep_index = next(
                            (
                                index
                                for index, crate in enumerate(external_new_deps)
                                if dep.name + ":" + dep.version == crate["name"] + ":" + crate["version"]
                            ),
                            -1,
                        )
                        if dep_index == -1:
                            external_new_deps.append(
                                {"name": dep.name, "version": dep.version, "internal_crates": set([internal_crate])}
                            )
                        else:
                            external_new_deps[dep_index]["internal_crates"].update([internal_crate])
            for index, external_crate in enumerate(external_new_deps):
                external_new_deps[index]["internal_crates"] = list(external_crate["internal_crates"])
        return external_new_deps

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

    def get_modified_crates(self) -> typing.Set[str]:
        modified_crates: typing.Set[str] = set()

        try:
            cargo_workspace_out = self._get_cargo_workspace_output()
            while cargo_workspace_out[0] != "[":
                _, cargo_workspace_out = cargo_workspace_out.split("\n", 1)
            workspace = json.loads(cargo_workspace_out)
        except Exception as err:
            logging.error("Unable to parse cargo workspace JSON " + str(err))
            return modified_crates
        logging.info("Idenitifying files updated in rs/ directory")
        modified_crate_files = git_changes.get_changed_files(self.root, ["rs/"])

        for file in modified_crate_files:
            matching_paths = []
            for crate in workspace:
                if file.startswith(crate["location"]):
                    matching_paths.append(crate)
            # will only work on linux
            if matching_paths:
                modified_crate = max(matching_paths, key=lambda path: path["location"].count("/"))
                modified_crates.add(modified_crate["name"] + ":" + modified_crate["version"])
        return modified_crates

    def get_vulnerable_dependencies(self, crates=None) -> typing.Dict[str, typing.List[typing.Dict]]:
        """Return list of vulnerable dependencies"""
        package_vulnerable_dependencies_map: typing.Dict[str, typing.List[typing.Dict]] = {}
        global USE_NIX_SHELL
        try:
            # Hot fix - Because the version of cargo audit through nix is outdated
            temp = USE_NIX_SHELL
            USE_NIX_SHELL = False
            audit_out_json = self._get_cargo_audit_output()
            USE_NIX_SHELL = temp
            audit_out = json.loads(audit_out_json)
        except subprocess.CalledProcessError as err:
            logging.error("Command execution failed for cargo audit " + str(err))
            return package_vulnerable_dependencies_map
        except ValueError as err:
            logging.error("Unable to serialize cargo audit output to JSON " + str(err))
            return package_vulnerable_dependencies_map

        vulnerabilities_list = list()
        # unmaintained_list = list()
        # yanked_list = list()

        if "vulnerabilities" in audit_out and "list" in audit_out["vulnerabilities"]:
            logging.info("Iterating through vulnerable crates in cargo audit")
            for v in audit_out["vulnerabilities"]["list"]:
                audit_slim = {}
                audit_slim["name"] = v["package"]["name"] + ":" + v["package"]["version"]
                audit_slim["reason"] = v["advisory"]["title"] + " " + v["advisory"]["description"]

                if v["versions"]["patched"]:
                    audit_slim["fix"] = v["versions"]["patched"]
                else:
                    audit_slim["fix"] = []

                if v["advisory"]["cvss"]:
                    score = int(CVSS3(v["advisory"]["cvss"]).scores()[0] * 10)
                    audit_slim["rating"] = RiskRating(score)
                else:
                    audit_slim["rating"] = RiskRating(50)
                vulnerabilities_list.append(audit_slim)

        # Currently we only flag vulnerable dependencies, but later we can include
        # yanked and unmaintanied dependencies

        # if 'warnings' in audit_out and 'unmaintained' in audit_out['warnings']:
        #     for v in audit_out['warnings']['unmaintained']:
        #         key = v['package']['name'] + ":" + v['package']['version']
        #         unmaintained_list.append(key)

        # if 'warnings' in audit_out and 'yanked' in audit_out['warnings']:
        #     for v in audit_out['warnings']['yanked']:
        #         key = v['package']['name'] + ":" + v['package']['version']
        #         yanked_list.append(key)

        # For checking with whitelist

        package_vulnerable_dependencies_map["metadata"] = [v["name"] for v in vulnerabilities_list]

        logging.info("Running cargo tree inverse for each vulnerable dependency...")
        for vulnerable in vulnerabilities_list:
            self._build_vulnerable_dependency(vulnerable, crates, package_vulnerable_dependencies_map)
        return package_vulnerable_dependencies_map

    def _build_vulnerable_dependency(self, vulnerable, crates, package_vulnerable_dependencies_map):

        # Cargo tree is used here to check if a vulnerable dependency is a dependency of
        # the crates modified by the developer.
        # However, there are a few edge cases
        #
        # If it's not a dependency, cargo tree doesn't exit gracefully.
        # Instead it throws, error: package ID specification `actix-http:3.0.0-beta.6` did not match any packages
        #
        # Sometimes, cargo tree produces no output without error.
        #
        # Since we are parsing an external command, this list may grow.

        # Case 1
        try:
            tree = self._get_cargo_tree_output(invert_deps=vulnerable["name"], package=crates)
        except subprocess.CalledProcessError:
            logging.error("cargo tree failed for " + vulnerable["name"])
            package_vulnerable_dependencies_map["metadata"].remove(vulnerable["name"])
            return

        # Case 2
        if not tree:
            logging.error("cargo tree is empty for " + vulnerable["name"])
            package_vulnerable_dependencies_map["metadata"].remove(vulnerable["name"])
            return

        while tree[0] != "0":
            _, tree = tree.split("\n", 1)

        dep_line, tree = tree.split("\n", 1)
        depth, dep_line = Cargo.parse_depth(dep_line)
        if depth != 0:
            raise RuntimeError("Cargo tree output format error. Expected depth 0!")
        vulnerable_dependency = Dependency.from_cargo_tree(dep_line)
        previous_dependency = vulnerable_dependency
        current_depth = 0
        skip_higher_depth = False
        current_chain = list()
        for dep_line in tree.split("\n"):
            dep_line = dep_line.strip()
            if not dep_line or Cargo.is_duplicate_line(dep_line):
                continue

            depth, dep_line = Cargo.parse_depth(dep_line)
            # Hot fix - Cargo tree produces 2 trees for some instances.
            # if depth == 0:
            #     raise RuntimeError("Cargo tree output format error. There can be only one item with depth 0!")
            if depth == 0 or skip_higher_depth is True and depth > current_depth:
                continue

            skip_higher_depth = False
            if len(current_chain) >= depth:
                del current_chain[depth - 1 :]
            dependency = Dependency.from_cargo_tree(dep_line)
            package_name = dependency.name + ":" + dependency.version
            if dependency.is_external is False:
                direct_dependency = False
                if depth == 1:
                    direct_dependency = True
                skip_higher_depth = True

                package_vulnerable_dependency = PackageVulnerableDependency(
                    package_name=package_name,
                    reason=vulnerable["reason"],
                    risk_rating=vulnerable["rating"],
                    fix=vulnerable["fix"],
                    is_vulnerable_dependency_direct=direct_dependency,
                    direct_dependency=previous_dependency,
                    vulnerable_dependency=vulnerable_dependency,
                    codeowner=" ".join(str(x) for x in dependency.owner),
                    dependency_chain=current_chain.copy(),
                )

                if package_name not in package_vulnerable_dependencies_map:
                    package_vulnerable_dependencies_map[package_name] = []
                package_vulnerable_dependencies_map[package_name].append(
                    dataclasses.asdict(package_vulnerable_dependency)
                )
            elif dependency.is_external is True:
                current_chain.append(package_name)
                previous_dependency = dependency
            current_depth = depth


class Inventory:
    """Dependency inventory helper."""

    @dataclasses.dataclass
    class Error:
        """Data class for inventory error reporting."""

        message: str
        is_fatal: bool = False

    def __init__(self, package_manager: PackageManager, use_gitlab=True):
        """Load dependency inventory from a file."""
        self.dependencies = ""
        self.package_manager = package_manager
        self.use_gitlab = use_gitlab

    def comment_on_gitlab(self, deltas):
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
        delta_body = "Vulnerable dependencies were found in the MR. Please check the JIRA issue {url}".format(
            url=deltas
        )
        return delta_body
