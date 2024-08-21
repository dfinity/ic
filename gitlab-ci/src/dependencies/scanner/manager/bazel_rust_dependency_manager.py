import fnmatch
import json
import logging
import os
import pathlib
import shutil
import subprocess
import traceback
import typing

import git
import git_changes
import parse
from cvss import CVSS3
from model.dependency import Dependency
from model.finding import Finding
from model.project import Project
from model.vulnerability import Vulnerability
from packaging import version
from scanner.manager.dependency_manager import DependencyManager
from scanner.process_executor import ProcessExecutor

RUSTSEC_URL = "https://rustsec.org/advisories/"
CRATES_IO_URL = "https://crates.io/crates/"


# noinspection PyMethodMayBeStatic
class BazelCargoExecutor:

    def get_bazel_query_output(self, bazel_query: str, path: pathlib.Path) -> str:
        bazel_query_command = "bazel query"
        bazel_extra_arguments = "--output package --notool_deps --noimplicit_deps --nohost_deps --ui_event_filters=-WARNING,-ERROR,-INFO"

        command = f"{bazel_query_command} {bazel_query} {bazel_extra_arguments}"
        environment = {}
        result = ""

        try:
            result = ProcessExecutor.execute_command(command, path.resolve(), environment, "--keep_going" in command, False)
        except subprocess.CalledProcessError:
            logging.debug(f"Command execution failed for bazel projects:\n{traceback.format_exc()}")
        finally:
            return result

    def get_cargo_audit_output(self, path: pathlib.Path, cargo_home=None) -> typing.Dict:
        environment = {}

        if cargo_home is not None:
            # Custom cargo home. For testing
            cargo_bin = f"{cargo_home}/bin/"
            environment["CARGO_HOME"] = cargo_home
            advisory_path = f"{cargo_home}/advisory-db/"
            command = f"{cargo_bin}cargo audit --json -d {advisory_path} --stale -n"
        else:
            command = "cargo audit --json"

        result = ProcessExecutor.execute_command(command, path.resolve(), environment)
        audit_out = json.loads(result)
        return audit_out

    def get_cargo_tree_output_for_vulnerable_dependency(self, vulnerable_dependency: Dependency, path: pathlib.Path, cargo_home=None) -> str:
        environment = {}

        if cargo_home is not None:
            # Custom cargo home. For testing
            cargo_bin = f"{cargo_home}/bin/"
            environment["CARGO_HOME"] = cargo_home
            advisory_path = f"{cargo_home}/advisory-db/"
            command = f"{cargo_bin}cargo tree --edges=no-proc-macro --prefix=depth -d {advisory_path} --stale -n -i " + ":".join([vulnerable_dependency.name, vulnerable_dependency.version])
        else:
            command = "cargo tree --edges=no-proc-macro --prefix=depth -i " + ":".join([vulnerable_dependency.name, vulnerable_dependency.version])

        try:
            return ProcessExecutor.execute_command(command, path.resolve(), environment)
        except subprocess.CalledProcessError:
            return ""


class BazelRustDependencyManager(DependencyManager):
    """Helper for Bazel-related functions."""

    def __init__(self, executor: BazelCargoExecutor = BazelCargoExecutor()):
        super().__init__()
        self.executor = executor

    def get_scanner_id(self) -> str:
        return "BAZEL_RUST"

    @staticmethod
    def __dependency_to_transitive_bazel_string(dep: Dependency) -> str:
        return f"@crate_index__{dep.name}-{dep.version}//:*"

    @staticmethod
    def __transitive_bazel_string_to_dependency(bazel_string: str) -> typing.Optional[Dependency]:
        # @crate_index__zstd-sys-2.0.2-zstd.1.5.2//
        result = parse.parse("@crate_index__{0}//", bazel_string)
        # <Result ('zstd-sys-2.0.2-zstd.1.5.2',) {}>
        if result:
            parse_result = result[0].split("-")
            # ['zstd', 'sys', '2.0.2', 'zstd.1.5.2']
            for split_string in parse_result:
                # 2.0.2
                if isinstance(version.parse(split_string), version.Version):
                    version_str = split_string
            # split with -2.0.2
            # noinspection PyUnboundLocalVariable
            name = result[0].split(f"-{version_str}", 1)[0]
            # ['zstd-sys', '-zstd.1.5.2'] -> 'zstd-sys'
            return Dependency(
                id=f"{CRATES_IO_URL}{name}", name=name, version=version_str, fix_version_for_vulnerability={}
            )
        return

    @staticmethod
    def __dependency_to_direct_bazel_string(dep: Dependency) -> str:
        # Needs to be updated manually.
        # TODO : Automate getting versioned names
        versioned_names = ["mockall", "rand", "rand_chacha", "rand_distr", "rsa", "sha2"]
        if dep.name in versioned_names:
            vers = dep.version.replace(".", "_")
            return f"@crate_index//:{dep.name}_{vers}"

        return f"@crate_index//:{dep.name}"

    @staticmethod
    def __parse_vulnerable_dependency_from_cargo_audit(
        vulnerability_id: str, vulnerability_from_cargo_audit: typing.Dict
    ) -> Dependency:
        if vulnerability_from_cargo_audit["versions"]["patched"]:
            fix = {
                vulnerability_id: vulnerability_from_cargo_audit["versions"]["patched"]
                                  + vulnerability_from_cargo_audit["versions"]["unaffected"]
            }
        else:
            fix = {}

        # For certain external crates, we maintain our own forks
        # Hence, id URL might not be 100% accurate
        # TODO : retrieve URL from crate.spec
        return Dependency(
            id=f"{CRATES_IO_URL}{vulnerability_from_cargo_audit['package']['name']}",
            name=vulnerability_from_cargo_audit["package"]["name"],
            version=vulnerability_from_cargo_audit["package"]["version"],
            fix_version_for_vulnerability=fix,
        )

    @staticmethod
    def __parse_vulnerability_from_cargo_audit(vulnerability_from_cargo_audit: typing.Dict) -> Vulnerability:
        if vulnerability_from_cargo_audit["cvss"]:
            score = int(CVSS3(vulnerability_from_cargo_audit["cvss"]).scores()[0])
        else:
            score = -1

        return Vulnerability(
            id=f"{RUSTSEC_URL}{vulnerability_from_cargo_audit['id']}",
            name=vulnerability_from_cargo_audit["id"],
            description=vulnerability_from_cargo_audit["title"],
            score=score,
        )

    def has_dependencies_changed(self) -> typing.Dict[str, bool]:

        external_crates_bzl = (self.root / "bazel" / "external_crates.bzl").as_posix()
        cargo_lock_toml = (self.root / "Cargo.Bazel.toml.lock").as_posix()

        dependency_changes = {"external_crates_bzl": False, "cargo_lock_toml": False}

        for changed_file in git_changes.get_changed_files(self.root, [""]):
            if changed_file == external_crates_bzl:
                dependency_changes["external_crates_bzl"] = True

            if changed_file == cargo_lock_toml:
                dependency_changes["cargo_lock_toml"] = True

        return dependency_changes

    def get_dependency_diff(self) -> typing.List[Dependency]:
        dependency_builder = []

        bazel_query = '"deps(@crate_index//:all)"'
        branch_dependencies = self.executor.get_bazel_query_output(bazel_query, self.root)
        branch_dependencies = branch_dependencies.split("\n")

        # Reset any modified files
        logging.info("Resetting local git changes")
        repo = git.Repo(self.root)
        repo.git.reset("--hard")

        # Reset to head creates an exception on CI
        # noinspection PyBroadException
        try:
            active_branch = repo.active_branch
        except Exception:
            logging.info(f"Running on CI, using HEAD hexsha instead of branch name to revert {traceback.format_exc()}")
            active_branch = repo.head.commit

        logging.info("Checking out merge base")
        repo.git.checkout(git_changes.get_merge_base(repo)[0].hexsha)

        base_dependencies = self.executor.get_bazel_query_output(bazel_query, self.root)
        base_dependencies = base_dependencies.split("\n")

        logging.info("Resetting local git changes")
        repo.git.reset("--hard")
        logging.info("Checking out merge top")
        repo.git.checkout(active_branch)

        dependencies_diff = list(set(branch_dependencies).difference(set(base_dependencies)))

        if not dependencies_diff:
            return []

        for dependency in dependencies_diff:
            parsed_dependency = self.__transitive_bazel_string_to_dependency(dependency)
            if parsed_dependency:
                dependency_builder.append(parsed_dependency)
        return dependency_builder

    def get_modified_packages(self) -> typing.List[str]:
        changed = []

        for changed_file in git_changes.get_changed_files(self.root, ["rs/"]):
            if fnmatch.fnmatch(changed_file, "*/BUILD.bazel"):
                file_path = pathlib.Path(changed_file)
                changed.append(str(file_path.parent.relative_to(self.root)))

        if not changed:
            logging.info("No bazel build files modified.")
            return []

        return changed

    def get_findings(
        self, repository_name: str, project: Project, engine_version: typing.Optional[str]
    ) -> typing.List[Finding]:
        finding_builder: typing.List[Finding] = []
        # Unless cargo dependency is completely removed from the system,
        # set(cargo) - set(bazel) \neq 0
        # Hence, perform cargo audit on the existing Cargo.lock file and then
        # perform the move. The second result will be used for creating the findings,
        # and the delta between the results will be logged for now.
        # TODO : Remove when cargo is completely out of the system.

        path = self.root.parent / project.path

        # currently only the ic repo uses bazel
        use_bazel = repository_name == "ic"
        if use_bazel:
            logging.info("Performing cargo audit on old Cargo.lock")
            old_cargo_audit = self.executor.get_cargo_audit_output(path)
            logging.info("Old cargo audit output %s", old_cargo_audit)

            # move Cargo.Bazel.toml.lock to Cargo.lock
            logging.info("Moving Cargo.Bazel.toml.lock to Cargo.lock")
            src = self.root / "Cargo.Bazel.toml.lock"
            dst = self.root / "Cargo.lock"

            if src.is_file() and dst.is_file():
                shutil.copy(src, dst)

        logging.info("Performing cargo audit on new Cargo.lock")
        new_cargo_audit = self.executor.get_cargo_audit_output(path)

        # cargo_audit_diff = jsondiff.diff(old_cargo_audit, new_cargo_audit)

        if "vulnerabilities" in new_cargo_audit and "list" in new_cargo_audit["vulnerabilities"]:
            logging.info("Iterating through vulnerable crates in cargo audit")
            # Cargo audit outputs a list of vulnerabilities irrespective of them
            # belonging in the same package.
            for audit_vulnerability in new_cargo_audit["vulnerabilities"]["list"]:
                vulnerability = self.__parse_vulnerability_from_cargo_audit(audit_vulnerability["advisory"])
                vulnerable_dependency = self.__parse_vulnerable_dependency_from_cargo_audit(
                    vulnerability.id, audit_vulnerability
                )
                if use_bazel:
                    first_level_dependencies = self.__get_first_level_dependencies_for_vulnerable_dependency(
                        vulnerable_dependency
                    )
                    projects = self.__get_projects_for_vulnerable_dependency(
                        project, vulnerable_dependency, first_level_dependencies
                    )
                else:
                    first_level_dependencies, projects = self.__get_first_level_dependencies_and_projects_from_cargo(vulnerable_dependency, path)
                lookup = next(
                    (
                        index
                        for index, value in enumerate(finding_builder)
                        if vulnerable_dependency.id == value.vulnerable_dependency.id
                           and vulnerable_dependency.name == value.vulnerable_dependency.name
                           and vulnerable_dependency.version == value.vulnerable_dependency.version
                    ),
                    -1,
                )
                if lookup == -1:
                    # new finding
                    # All other parameters are out of context for the package manager.
                    # Should be consumed by the scanner and updated accordingly.
                    finding_builder.append(
                        Finding(
                            repository=repository_name,
                            scanner=self.get_scanner_id(),
                            vulnerable_dependency=vulnerable_dependency,
                            vulnerabilities=[vulnerability],
                            first_level_dependencies=first_level_dependencies,
                            projects=projects,
                            risk_assessor=[],
                            score=vulnerability.score,
                        )
                    )
                else:
                    finding_builder[lookup].vulnerabilities.append(vulnerability)
                    finding_builder[lookup].score = max(
                        [vulnerability.score for vulnerability in finding_builder[lookup].vulnerabilities]
                    )
                    if vulnerability.id in vulnerable_dependency.fix_version_for_vulnerability:
                        finding_builder[lookup].vulnerable_dependency.fix_version_for_vulnerability[
                            vulnerability.id
                        ] = vulnerable_dependency.fix_version_for_vulnerability[vulnerability.id]
        for finding in finding_builder:
            finding.vulnerabilities.sort(key=lambda x: x.id)
            finding.first_level_dependencies.sort(key=lambda x: x.id)
            finding.projects.sort()
        return finding_builder

    @staticmethod
    def __cargo_tree_parse_depth(dep_line: str) -> typing.Tuple[int, str]:
        i = 0
        while dep_line[i].isdigit():
            i += 1
        return int(dep_line[:i]), dep_line[i:]

    @staticmethod
    def __cargo_tree_is_duplicate_line(dep_line) -> bool:
        return dep_line.endswith("(*)")

    @staticmethod
    def __cargo_tree_parse_dependency_or_project(line: str, project_path: pathlib.Path) -> typing.Union[Dependency, str]:
        # a few sample lines (crates.io dep, repo dep, project):
        # build-info-build v0.0.26
        # cycles-minting-canister v0.8.0 (https://github.com/dfinity/ic?rev=89129b8212791d7e05cab62ff08eece2888a86e0#89129b82)
        # nns-dapp v2.0.29 (/Users/tmu/Projects/nns-dapp/rs/backend)

        name, line = line.split(" ", 1)
        path: typing.Optional[str] = None
        if " " in line:
            vers, line = line.split(" ", 1)
            path = line.split(" ")[0]
            if path:
                # path is surrounded by brackets
                path = path[1:-1]
        else:
            vers = line

        if vers[0] != "v":
            raise ValueError("Version should start with v")
        vers = vers[1:]

        if path is None:
            # crates.io dependency
            return Dependency(id=f"{CRATES_IO_URL}{name}", name=name, version=vers, fix_version_for_vulnerability={})
        if path.startswith("/"):
            # project
            return os.path.relpath(path, project_path.parent)
        # if it is not a crates.io crate and not project path it is most likely a repo path, e.g.,
        # ic-sns-wasm v1.0.0 (https://github.com/dfinity/ic?rev=89129b8212791d7e05cab62ff08eece2888a86e0#89129b82)
        # in this case the path doesn't uniquely identify the dependency so we use the name as ID
        return Dependency(id=name, name=name, version=vers, fix_version_for_vulnerability={})

    def __get_first_level_dependencies_and_projects_from_cargo(self, vulnerable_dependency: Dependency, path: pathlib.Path) -> typing.Tuple[typing.List[Dependency], typing.List[str]]:
        tree = self.executor.get_cargo_tree_output_for_vulnerable_dependency(vulnerable_dependency, path)
        # sample cargo tree output:
        # 0time v0.1.45
        # 1chrono v0.4.19
        # 2build-info-build v0.0.26
        # 3cycles-minting-canister v0.8.0 (https://github.com/dfinity/ic?rev=89129b8212791d7e05cab62ff08eece2888a86e0#89129b82)
        # 4ic-nns-governance v0.8.0 (https://github.com/dfinity/ic?rev=89129b8212791d7e05cab62ff08eece2888a86e0#89129b82)
        # 5nns-dapp v2.0.29 (/Users/tmu/Projects/nns-dapp/rs/backend)
        # 4nns-dapp v2.0.29 (/Users/tmu/Projects/nns-dapp/rs/backend)
        if not tree:
            logging.error("cargo tree is empty for a vulnerable dependency.")
            logging.debug(f"cargo tree is empty for {vulnerable_dependency}")
            return [], []
        while tree[0] != "0":
            _, tree = tree.split("\n", 1)
        dep_line, tree = tree.split("\n", 1)
        depth, dep_line = self.__cargo_tree_parse_depth(dep_line)
        if depth != 0:
            logging.error(f"Cargo tree output format error. Expected depth 0, got {depth}!")
            return [], []
        current_depth = 0
        skip_higher_depth = False
        current_chain = list()
        first_level_dependencies = {}
        projects = set()
        try:
            for dep_line in tree.split("\n"):
                dep_line = dep_line.strip()
                if not dep_line or self.__cargo_tree_is_duplicate_line(dep_line):
                    continue
                depth, dep_line = self.__cargo_tree_parse_depth(dep_line)

                # Hot fix - Cargo tree produces 2 trees for some instances.
                # if depth == 0:
                #     raise RuntimeError("Cargo tree output format error. There can be only one item with depth 0!")
                if depth == 0 or skip_higher_depth is True and depth > current_depth:
                    continue
                skip_higher_depth = False
                if len(current_chain) >= depth:
                    del current_chain[depth - 1:]

                dependency_or_project = self.__cargo_tree_parse_dependency_or_project(dep_line, path)
                if isinstance(dependency_or_project, str):
                    # a project was returned
                    projects.add(dependency_or_project)
                    if len(current_chain) > 0:
                        # the dependency before the project in the chain is the 1st lvl dep
                        first_level_dependencies[current_chain[-1].id + ":" + current_chain[-1].version] = current_chain[-1]
                    skip_higher_depth = True
                else:
                    # a dependency was returned
                    current_chain.append(dependency_or_project)
                current_depth = depth
        except (RuntimeError, ValueError):
            logging.error("error while parsing 1st level deps & projects from cargo tree.")
            logging.debug(f"error while parsing 1st level deps & projects from cargo tree {tree}\n{traceback.format_exc()}")

        return list(first_level_dependencies.values()), list(projects)

    def __is_transitive_dependency_first_level_dependency(self, dep: Dependency) -> bool:
        direct_dependency_string = self.__dependency_to_direct_bazel_string(dep)
        # Need to provide keep_going
        bazel_query = f'"rdeps(@crate_index//:all, {direct_dependency_string} ,1)" --keep_going'
        # TODO : require a way for supressing bazel query ERRORs
        # Since, ERROR signifies the package is not declared in the crate_index
        result = self.executor.get_bazel_query_output(bazel_query, self.root)
        if not result:
            return False
        result = result.split("\n")
        if "@crate_index//" in result and len(result) == 1:
            # direct_dependency
            return True
        return False

    def __get_first_level_dependencies_for_vulnerable_dependency(self, dep: Dependency) -> typing.List[Dependency]:
        dependency_builder: typing.List[Dependency] = []
        bazel_dependency = self.__dependency_to_transitive_bazel_string(dep)
        bazel_query = f'"rdeps(@crate_index//:all, {bazel_dependency}) except {bazel_dependency}"'
        result = self.executor.get_bazel_query_output(bazel_query, self.root)

        if not result:
            return dependency_builder

        result = result.split("\n")

        if "@crate_index//" in result and len(result) == 1:
            # direct_dependency
            return dependency_builder
        result.remove("@crate_index//")
        for transitive_bazel_string in sorted(result):
            transitive_dependency = self.__transitive_bazel_string_to_dependency(transitive_bazel_string)
            if transitive_dependency and self.__is_transitive_dependency_first_level_dependency(transitive_dependency):
                dependency_builder.append(transitive_dependency)
        return dependency_builder

    def __get_projects_for_vulnerable_dependency(
        self, project: Project, vulnerable_dependency: Dependency, first_level_dependencies: typing.List[Dependency]
    ) -> typing.List[str]:
        project_builder: typing.Set = set()

        dependencies = [vulnerable_dependency]
        if first_level_dependencies:
            dependencies += first_level_dependencies

        for dependency in dependencies:
            bazel_dependency = self.__dependency_to_transitive_bazel_string(dependency)
            # rank 2 because package -> crate_index -> dependency
            bazel_query = f'"kind("rust_library", rdeps(//rs/..., {bazel_dependency}, 2)) except rdeps(@crate_index//:all, {bazel_dependency})" --keep_going'
            result = self.executor.get_bazel_query_output(bazel_query, self.root)

            if not result:
                continue

            result = result.split("\n")
            for project_string in result:
                project_builder.add(f"{project.path}/{project_string}")

        project_builder.discard("")
        return list(project_builder)
