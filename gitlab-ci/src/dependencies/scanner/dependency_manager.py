import abc
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
import parse
from cvss import CVSS3
from model.dependency import Dependency
from model.finding import Finding
from model.repository import Repository
from model.vulnerability import Vulnerability
from nested_lookup import nested_lookup
from packaging import version
from scanner.process_executor import ProcessExecutor
from semver import satisfies

import git_changes

PROJECT_ROOT = pathlib.Path(
    os.environ.get("CI_PROJECT_DIR", pathlib.Path(__file__).absolute().parent.parent.parent.parent.parent)
)
RUSTSEC_URL = "https://rustsec.org/advisories/"
CRATES_IO_URL = "https://crates.io/crates/"
NPM_URL = "https://www.npmjs.com/package/"


class DependencyManager(abc.ABC):
    """Base class for helper classes for different package managers."""

    @abc.abstractmethod
    def get_dependency_diff(self) -> typing.List[Dependency]:
        """Return list of dependency diffs for modified packages."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_findings(self, repository: Repository, scanner: str) -> typing.List[Finding]:
        """Return list of vulnerable dependencies"""
        raise NotImplementedError

    @abc.abstractmethod
    def get_modified_packages(self) -> typing.List[str]:
        """Return list of modified internal packages"""
        raise NotImplementedError

    @abc.abstractmethod
    def has_dependencies_changed(self) -> typing.Dict[str, bool]:
        """Return true if dependencies have changed in a MR"""
        raise NotImplementedError


class Bazel(DependencyManager):
    """Helper for Bazel-related functions."""

    def __init__(self, root=PROJECT_ROOT):
        """Construct default object."""
        self.root = root

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
            version = dep.version.replace(".", "_")
            return f"@crate_index//:{dep.name}_{version}"

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

        # For certain external crates, we maintian our own forks
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

    def __get_bazel_query_output(self, bazel_query: str) -> str:
        bazel_query_command = "bazel query"
        bazel_extra_arguments = "--output package --notool_deps --noimplicit_deps --nohost_deps"

        command = f"{bazel_query_command} {bazel_query} {bazel_extra_arguments}"
        environment = {}
        cwd = self.root
        result = ""

        try:
            result = ProcessExecutor.execute_command(command, cwd.resolve(), environment, use_nix_shell=False)
        except subprocess.CalledProcessError:
            logging.error(f"Command execution failed for bazel projects:\n{traceback.format_exc()}")
        finally:
            return result

    def __get_cargo_audit_output(self, cargo_home=None) -> typing.Dict:
        environment = {}
        cwd = self.root / "rs"

        if cargo_home is not None:
            # Custom cargo home. For testing
            cargo_bin = f"{cargo_home}/bin/"
            environment["CARGO_HOME"] = cargo_home
            advisory_path = f"{cargo_home}/advisory-db/"
            command = f"{cargo_bin}cargo audit --json -d {advisory_path} --stale -n"
        else:
            command = "cargo audit --json"

        result = ProcessExecutor.execute_command(command, cwd.resolve(), environment, use_nix_shell=False)
        audit_out = json.loads(result)
        return audit_out

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
        branch_dependencies = self.__get_bazel_query_output(bazel_query)
        branch_dependencies = branch_dependencies.split("\n")

        # Reset any modified files
        logging.info("Resetting local git changes")
        repo = git.Repo(self.root)
        repo.git.reset("--hard")

        # Reset to head creates an exception on CI
        try:
            active_branch = repo.active_branch
        except Exception:
            logging.info(f"Running on CI, usuing HEAD hexsha instead of branch name to revert {traceback.format_exc()}")
            active_branch = repo.head.commit

        logging.info("Checking out merge base")
        repo.git.checkout(git_changes.get_merge_base(repo)[0].hexsha)

        base_dependencies = self.__get_bazel_query_output(bazel_query)
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

    def get_findings(self, repository: Repository, scanner: str) -> typing.List[Finding]:
        finding_builder: typing.List[Finding] = []
        # Unless cargo dependency is completely removed from the system,
        # set(cargo) - set(bazel) \neq 0
        # Hence, perform cargo audit on the existing Cargo.lock file and then
        # perform the move. The second result will be used for creating the findings,
        # and the delta between the results will be logged for now.
        # TODO : Remove when cargo is completely out of the system.

        logging.info("Performing cargo audit on old rs/Cargo.lock")
        old_cargo_audit = self.__get_cargo_audit_output()
        logging.info("Old cargo audit output %s", old_cargo_audit)

        # move Cargo.Bazel.toml.lock to rs/Cargo.lock
        logging.info("Moving Cargo.Bazel.toml.lock to rs/Cargo.lock")
        src = self.root / "Cargo.Bazel.toml.lock"
        dst = self.root / "rs" / "Cargo.lock"

        if src.is_file() and dst.is_file():
            shutil.copy(src, dst)

        logging.info("Performing cargo audit on new rs/Cargo.lock")
        new_cargo_audit = self.__get_cargo_audit_output()

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
                first_level_dependencies = self.__get_first_level_dependencies_for_vulnerable_dependency(
                    vulnerable_dependency
                )
                projects = self.__get_projects_for_vulnerable_dependency(
                    vulnerable_dependency, first_level_dependencies
                )
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
                            repository=repository.name,
                            scanner=scanner,
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
        return finding_builder

    def __is_transitive_dependency_first_level_dependency(self, dep: Dependency) -> bool:
        direct_dependency_string = self.__dependency_to_direct_bazel_string(dep)
        # Need to provide keep_going
        bazel_query = f'"rdeps(@crate_index//:all, {direct_dependency_string} ,1)" --keep_going'
        # TODO : require a way for supressing bazel query ERRORs
        # Since, ERROR signifies the package is not declared in the crate_index
        result = self.__get_bazel_query_output(bazel_query)
        if not result:
            return False
        result = result.split("\n")
        if "@crate_index//" in result and len(result) == 1:
            # direct_dependency
            return True
        return False

    def __get_first_level_dependencies_for_vulnerable_dependency(self, dep: Dependency) -> typing.List[Dependency]:
        dependecy_builder: typing.List[Dependency] = []
        bazel_dependency = self.__dependency_to_transitive_bazel_string(dep)
        bazel_query = f'"rdeps(@crate_index//:all, {bazel_dependency}) except {bazel_dependency}"'
        result = self.__get_bazel_query_output(bazel_query)

        if not result:
            return dependecy_builder

        result = result.split("\n")

        if "@crate_index//" in result and len(result) == 1:
            # direct_dependency
            return dependecy_builder
        result.remove("@crate_index//")
        for transitive_bazel_string in sorted(result):
            transitive_dependency = self.__transitive_bazel_string_to_dependency(transitive_bazel_string)
            if transitive_dependency and self.__is_transitive_dependency_first_level_dependency(transitive_dependency):
                dependecy_builder.append(transitive_dependency)
        return dependecy_builder

    def __get_projects_for_vulnerable_dependency(
        self, vulnerable_dependency: Dependency, first_level_dependencies: typing.List[Dependency]
    ) -> typing.List[str]:
        project_builder: typing.Set = set()

        dependencies = [vulnerable_dependency]
        if first_level_dependencies:
            dependencies += first_level_dependencies

        for dependency in dependencies:
            bazel_dependency = self.__dependency_to_transitive_bazel_string(dependency)
            # rank 2 because package -> crate_index -> dependency
            bazel_query = f'"kind("rust_library", rdeps(//rs/..., {bazel_dependency}, 2)) except rdeps(@crate_index//:all, {bazel_dependency})"'
            result = self.__get_bazel_query_output(bazel_query)

            if not result:
                continue

            result = result.split("\n")
            for project_string in result:
                project_builder.add(project_string)

        project_builder.discard("")
        return sorted(list(project_builder))


class NPM(DependencyManager):
    """Helper for NPM-related functions."""

    def __init__(self, root=PROJECT_ROOT):
        """Construct default object."""
        self.root = root

    def get_dependency_diff(self):
        raise NotImplementedError

    def get_modified_packages(self):
        raise NotImplementedError

    def has_dependencies_changed(self):
        raise NotImplementedError

    @staticmethod
    def __clone_repository_from_url(url: str, path: pathlib.Path):
        environment = {}
        cwd = path
        command = f"git clone --depth=1 {url}"
        logging.info(f"Performing git clone {url}")
        _ = ProcessExecutor.execute_command(command, cwd.resolve(), environment, use_nix_shell=False)
        return

    @staticmethod
    def __npm_audit_output(path: pathlib.Path) -> typing.Dict:
        audit_out: typing.Dict = {}

        environment = {}
        cwd = path
        command = "npm audit --json"

        logging.info(f"Performing npm audit {cwd.resolve()}")
        result = ProcessExecutor.execute_command(command, cwd.resolve(), environment, use_nix_shell=False)
        audit_out = json.loads(result)

        return audit_out

    @staticmethod
    def __npm_list_output(path: pathlib.Path) -> typing.Dict:
        list_out: typing.Dict = {}
        environment = {}
        cwd = path
        command = "npm install"
        logging.info(f"Performing npm install {cwd.resolve()}")
        _ = ProcessExecutor.execute_command(command, cwd.resolve(), environment, use_nix_shell=False)

        command = "npm list --all --json"

        result = ProcessExecutor.execute_command(command, cwd.resolve(), environment, use_nix_shell=False)
        list_out = json.loads(result)
        return list_out

    @staticmethod
    def __vulnerability_from_npm_audit(vulnerability: typing.Dict) -> Vulnerability:
        score = -1

        if "cvss" in vulnerability and "score" in vulnerability["cvss"] and vulnerability["cvss"]["score"]:
            score = int(vulnerability["cvss"]["score"])

        return Vulnerability(
            id=vulnerability["url"],
            name=vulnerability["url"].split("/")[-1],
            description=vulnerability["title"],
            score=score,
        )

    @staticmethod
    def __get_first_level_dependencies_from_npm_list(
        npm_list: typing.Dict, dependency: str, range_str: typing.List[str]
    ) -> typing.List[Dependency]:
        first_level_dependencies: typing.List[Dependency] = []

        for dependency_name, dependenices in npm_list["dependencies"].items():
            results = nested_lookup(dependency, dependenices)

            # vulnerable dependency isn't used by this dependency
            if not results:
                continue

            vulnerable_dependency_used = False
            for result in results:
                for ranges in range_str:
                    if satisfies(result["version"], ranges):
                        vulnerable_dependency_used = True

            # vulnerable version of this dependency isn't used by this dependency
            if not vulnerable_dependency_used:
                continue

            first_level_dependencies.append(
                Dependency(
                    id=f"{NPM_URL}{dependency_name}/v/{dependenices['version']}",
                    name=dependency_name,
                    version=dependenices["version"],
                )
            )
        return first_level_dependencies

    @staticmethod
    def __get_vulnerable_dependency_from_npm_list(
        npm_list: typing.Dict, dependency: str, range_str: str
    ) -> typing.List[Dependency]:
        results = nested_lookup(dependency, npm_list)
        if not results:
            raise RuntimeError(f"nested lookup failed for dependency {dependency} with error (no dependency)")

        vulnerable_dependency: typing.List = []
        for result in results:
            if not satisfies(result["version"], range_str):
                continue

            if result["version"] in [dependency.version for dependency in vulnerable_dependency]:
                continue
            # TODO : How do we get fix version ?
            # fixAvailable is either a bool or top level dependency.
            # npm audit fix --dry-run --list doesn't give anything useful.
            # npm audit fix && npm list --all might give the fix version but complicated
            vulnerable_dependency.append(
                Dependency(
                    id=f"{NPM_URL}{dependency}/v/{result['version']}", name=dependency, version=result["version"]
                )
            )

        if len(vulnerable_dependency) == 0:
            raise RuntimeError(f"nested lookup failed for dependency {dependency} with error (no vulnerable versions)")

        return vulnerable_dependency

    def __findings_helper(
        self, repository: str, scanner: str, path: pathlib.Path, project: str
    ) -> typing.List[Finding]:
        finding_builder: typing.List[Finding] = []

        npm_audit_output = self.__npm_audit_output(path)

        # no vulnerabilities
        if "vulnerabilities" not in npm_audit_output or len(npm_audit_output["vulnerabilities"]) == 0:
            return finding_builder

        npm_list_output = self.__npm_list_output(path)

        for dependency_key, dependency_value in npm_audit_output["vulnerabilities"].items():
            vulnerable_dependencies = self.__get_vulnerable_dependency_from_npm_list(
                npm_list_output, dependency_key, dependency_value["range"]
            )

            if not vulnerable_dependencies:
                continue

            for vulnerable_dependency in vulnerable_dependencies:
                vulnerabilities: typing.List[Vulnerability] = []

                ranges_to_check = []

                if "via" in dependency_value and len(dependency_value["via"]) > 0:
                    for vulnerability_value in dependency_value["via"]:
                        # npm provides transitive dependency here
                        if type(vulnerability_value) is not dict:
                            continue

                        if not satisfies(vulnerable_dependency.version, vulnerability_value["range"]):
                            continue

                        vulnerabilities.append(self.__vulnerability_from_npm_audit(vulnerability_value))

                        if vulnerability_value["range"] not in ranges_to_check:
                            ranges_to_check.append(vulnerability_value["range"])

                # all vulnerabilites were via transitive dependency, so we skip
                if len(vulnerabilities) == 0:
                    continue

                first_level_dependecies: typing.List[Dependency] = self.__get_first_level_dependencies_from_npm_list(
                    npm_list_output, dependency_key, ranges_to_check
                )
                score = max(vulnerability.score for vulnerability in vulnerabilities)

                finding_builder.append(
                    Finding(
                        repository=repository,
                        scanner=scanner,
                        vulnerable_dependency=vulnerable_dependency,
                        vulnerabilities=vulnerabilities,
                        first_level_dependencies=first_level_dependecies,
                        projects=[project],
                        risk_assessor=[],
                        score=score,
                    )
                )
        return finding_builder

    def get_findings(self, repository: Repository, scanner: str) -> typing.List[Finding]:
        finding_builder: typing.List[Finding] = []
        if repository.name != "ic":
            # we are cloning an external repository
            top_level_path = self.root.parent / repository.name
            if top_level_path.is_dir():
                # git clone fails if the directory already exists
                shutil.rmtree(top_level_path)
            self.__clone_repository_from_url(repository.url, self.root.parent)

        for project in repository.projects:
            path = self.root.parent / project.path
            if not path.is_dir():
                raise RuntimeError(f"path {path} is invalid")
            logging.info(f"Calling finding helper for {repository.name} {path} {project.name}")
            finding_builder.extend(self.__findings_helper(repository.name, scanner, path, project.name))

        return finding_builder
