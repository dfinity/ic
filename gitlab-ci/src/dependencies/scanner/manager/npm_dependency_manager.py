import json
import logging
import os
import pathlib
import typing

from model.dependency import Dependency
from model.finding import Finding
from model.project import Project
from model.vulnerability import Vulnerability
from nested_lookup import nested_lookup
from nodesemver import satisfies
from scanner.manager.dependency_manager import DependencyManager
from scanner.process_executor import ProcessExecutor

NPM_URL = "https://www.npmjs.com/package/"


class NPMDependencyManager(DependencyManager):
    """Helper for NPM-related functions."""

    def get_scanner_id(self) -> str:
        return "NPM"

    def get_dependency_diff(self) -> typing.List[Dependency]:
        raise NotImplementedError

    def get_modified_packages(self) -> typing.List[str]:
        raise NotImplementedError

    def has_dependencies_changed(self) -> typing.Dict[str, bool]:
        raise NotImplementedError

    @staticmethod
    def __clone_repository_from_url(url: str, path: pathlib.Path):
        environment = {}
        cwd = path
        command = f"git clone --depth=1 {url}"
        logging.info(f"Performing git clone {url}")
        _ = ProcessExecutor.execute_command(command, cwd.resolve(), environment)
        return

    @staticmethod
    def __npm_audit_output(engine_version: int, path: pathlib.Path) -> typing.Dict:
        nvm_dir = os.environ.get("NVM_DIR", "/opt/nvm")
        environment = {}
        cwd = path
        command = f"bash -c 'source {nvm_dir}/nvm.sh && nvm use default {engine_version} --silent && npm audit --json'"

        logging.info(f"Performing npm audit {cwd.resolve()}")
        result = ProcessExecutor.execute_command(command, cwd.resolve(), environment)
        audit_out = json.loads(result)

        return audit_out

    @staticmethod
    def __npm_list_output(engine_version: int, path: pathlib.Path) -> typing.Dict:
        nvm_dir = os.environ.get("NVM_DIR", "/opt/nvm")
        environment = {}
        cwd = path
        command = f"bash -c 'source {nvm_dir}/nvm.sh && nvm use default {engine_version} --silent && npm ci'"
        logging.info(f"Performing npm ci {cwd.resolve()}")
        _ = ProcessExecutor.execute_command(command, cwd.resolve(), environment)

        command = (
            f"bash -c 'source {nvm_dir}/nvm.sh && nvm use default {engine_version} --silent && npm list --all --json'"
        )

        result = ProcessExecutor.execute_command(command, cwd.resolve(), environment)
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

        for dependency_name, dependencies in npm_list["dependencies"].items():
            results = nested_lookup(dependency, dependencies)

            # vulnerable dependency isn't used by this dependency
            if not results:
                continue

            vulnerable_dependency_used = False
            for result in results:
                for ranges in range_str:
                    if "version" in result and satisfies(result["version"], ranges):
                        vulnerable_dependency_used = True

            # vulnerable version of this dependency isn't used by this dependency
            if not vulnerable_dependency_used:
                continue

            first_level_dependencies.append(
                Dependency(
                    id=f"{NPM_URL}{dependency_name}/v/{dependencies['version']}",
                    name=dependency_name,
                    version=dependencies["version"],
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
            if "version" not in result or not satisfies(result["version"], range_str):
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

    def get_findings(
        self, repository_name: str, project: typing.Optional[Project], engine_version: typing.Optional[int]
    ) -> typing.List[Finding]:
        path = self.root.parent / project.path
        finding_builder: typing.List[Finding] = []

        npm_audit_output = self.__npm_audit_output(engine_version, path)

        # no vulnerabilities
        if "vulnerabilities" not in npm_audit_output or len(npm_audit_output["vulnerabilities"]) == 0:
            return finding_builder

        npm_list_output = self.__npm_list_output(engine_version, path)

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

                # all vulnerabilities were via transitive dependency, so we skip
                if len(vulnerabilities) == 0:
                    continue
                vulnerabilities.sort(key=lambda x: x.id)

                first_level_dependencies: typing.List[Dependency] = self.__get_first_level_dependencies_from_npm_list(
                    npm_list_output, dependency_key, ranges_to_check
                )
                first_level_dependencies.sort(key=lambda x: x.id)
                score = max(vulnerability.score for vulnerability in vulnerabilities)

                finding_builder.append(
                    Finding(
                        repository=repository_name,
                        scanner=self.get_scanner_id(),
                        vulnerable_dependency=vulnerable_dependency,
                        vulnerabilities=vulnerabilities,
                        first_level_dependencies=first_level_dependencies,
                        projects=[project.name],
                        risk_assessor=[],
                        score=score,
                    )
                )
        return finding_builder
