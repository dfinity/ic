import abc
import json
import logging
import os
import pathlib
import shutil
import subprocess
import traceback
import typing

import parse
from cvss import CVSS3
from model.dependency import Dependency
from model.finding import Finding
from model.vulnerability import Vulnerability
from scanner.process_executor import ProcessExecutor

PROJECT_ROOT = pathlib.Path(
    os.environ.get("CI_PROJECT_DIR", pathlib.Path(__file__).absolute().parent.parent.parent.parent.parent)
)
RUSTSEC_URL = "https://rustsec.org/advisories/"
CRATES_IO_URL = "https://crates.io/crates/"


class DependencyManager(abc.ABC):
    """Base class for helper classes for different package managers."""

    @abc.abstractmethod
    def get_dependency_diff(self) -> typing.Dict[str, str]:
        """Return list of dependency diffs for modified packages."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_findings(self, repository: str, scanner: str) -> typing.List[Finding]:
        """Return list of vulnerable dependencies"""
        raise NotImplementedError

    @abc.abstractmethod
    def get_modified_packages(self) -> typing.List[str]:
        """Return list of modified internal packages"""
        raise NotImplementedError


class Bazel(DependencyManager):
    """Helper for Bazel-related functions."""

    def __init__(self, root=PROJECT_ROOT):
        """Construct default object."""
        self.root = root

    # TODO : Needed when we work on merge requests
    def get_dependency_diff(self):
        raise NotImplementedError

    # TODO : Needed when we work on merge requests
    def get_modified_packages(self):
        raise NotImplementedError

    @staticmethod
    def __dependency_to_transitive_bazel_string(dep: Dependency) -> str:
        return f"@crate_index__{dep.name}-{dep.version}//:*"

    @staticmethod
    def __transitive_bazel_string_to_dependency(bazel_string: str) -> Dependency:
        result = parse.parse("@crate_index__{0}//", bazel_string)
        result = result[0].rsplit("-", 1)
        return Dependency(
            id=f"{CRATES_IO_URL}{result[0]}", name=result[0], version=result[1], fix_version_for_vulnerability={}
        )

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

    def get_findings(self, repository: str, scanner: str) -> typing.List[Finding]:
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
                            repository=repository,
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
        for transitive_bazel_string in result:
            transitive_dependency = self.__transitive_bazel_string_to_dependency(transitive_bazel_string)
            if self.__is_transitive_dependency_first_level_dependency(transitive_dependency):
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
