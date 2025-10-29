import abc
import json
import logging
import os
import re
import time
import typing
from html import unescape
from pathlib import Path

from model.dependency import Dependency
from model.finding import Finding
from model.project import Project
from model.vulnerability import Vulnerability
from notification.app_owner_msg_subscriber import AppOwnerMsgSubscriber
from notification.console_logger_app_owner_msg_subscriber import ConsoleLoggerAppOwnerMsgSubscriber
from scanner.manager.dependency_manager import DependencyManager
from scanner.process_executor import ProcessExecutor

TRIVY_SCANNER_ID = "BAZEL_TRIVY_CS"
TRIVY_SCAN_RETRIES = 10
RE_SHA256_HASH = re.compile(r"^[\da-fA-F]{64}$")
RE_ROOTFS_FILE = re.compile(r"^/tmp/tmp\.\w+/tmp_rootfs/(.+)$")
RE_VULNERABLE_DEPENDENCY_ID_REPLACEMENTS = [re.compile(r"^(?P<dependency_id>linux-modules-[^-]+).*$")]


class TrivyResultParser(abc.ABC):
    """Base class for helper classes for converting different trivy results to findings."""

    @abc.abstractmethod
    def get_parser_id(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def is_supported_type(self, result_class: str, result_type: typing.Optional[str]) -> bool:
        """Return true if this parser supports the provided result class type combination"""
        raise NotImplementedError

    @abc.abstractmethod
    def trivy_result_to_finding(
        self,
        trivy_data: typing.Dict[str, typing.Any],
        result_index: int,
        file_to_hash: typing.Dict[str, str],
        repository: str,
        scanner: str,
        project: Project,
    ) -> typing.List[Finding]:
        """Return list of dependency diffs for modified packages"""
        raise NotImplementedError

    @staticmethod
    def __score(vulnerability: typing.Dict[str, typing.Any]) -> int:
        scores = []
        if "CVSS" in vulnerability:
            if "nvd" in vulnerability["CVSS"]:
                if "V3Score" in vulnerability["CVSS"]["nvd"]:
                    scores.append(round(vulnerability["CVSS"]["nvd"]["V3Score"]))
            if "redhat" in vulnerability["CVSS"]:
                if "V3Score" in vulnerability["CVSS"]["redhat"]:
                    scores.append(round(vulnerability["CVSS"]["redhat"]["V3Score"]))
        if len(scores) > 0:
            return max(scores)
        return -1

    @staticmethod
    def trivy_result_to_dependencies_and_vulnerabilities(
        trivy_data: typing.Dict[str, typing.Any], result_index: int
    ) -> typing.List[typing.Tuple[Dependency, typing.List[Vulnerability]]]:
        """Returns list of tuples where 1st element of the tuple is vulnerable dependency and 2nd element is list of corresponding vulnerabilities"""

        results = trivy_data["Results"][result_index]
        if "Vulnerabilities" not in results:
            return []

        trivy_vulnerabilities_by_vuln_dep = {}
        for trivy_vulnerability in results["Vulnerabilities"]:
            vulnerable_dependency = Dependency(
                id=trivy_vulnerability["PkgName"],
                name=trivy_vulnerability["PkgName"],
                version=trivy_vulnerability["InstalledVersion"],
            )
            vulnerable_dependency_id = f"{vulnerable_dependency.id}|{vulnerable_dependency.version}"
            if vulnerable_dependency_id not in trivy_vulnerabilities_by_vuln_dep:
                trivy_vulnerabilities_by_vuln_dep[vulnerable_dependency_id] = [vulnerable_dependency, []]
            trivy_vulnerabilities_by_vuln_dep[vulnerable_dependency_id][1].append(trivy_vulnerability)

        vulnerabilities_by_vuln_dep = {}
        for vulnerable_dependency, trivy_vulnerabilities in trivy_vulnerabilities_by_vuln_dep.values():
            vulnerable_dependency_id = f"{vulnerable_dependency.id}|{vulnerable_dependency.version}"
            vulnerable_dependency.fix_version_for_vulnerability = {}
            vulnerabilities = []
            for trivy_vulnerability in trivy_vulnerabilities:
                vulnerability_id = (
                    trivy_vulnerability["PrimaryURL"]
                    if "PrimaryURL" in trivy_vulnerability
                    else trivy_vulnerability["VulnerabilityID"]
                )
                vulnerabilities.append(
                    Vulnerability(
                        id=vulnerability_id,
                        name=trivy_vulnerability["VulnerabilityID"],
                        description=unescape(trivy_vulnerability["Title"]) if "Title" in trivy_vulnerability else "n/a",
                        score=TrivyResultParser.__score(trivy_vulnerability),
                    )
                )
                if "FixedVersion" in trivy_vulnerability:
                    vulnerable_dependency.fix_version_for_vulnerability[vulnerability_id] = [
                        trivy_vulnerability["FixedVersion"]
                    ]
            vulnerabilities_by_vuln_dep[vulnerable_dependency_id] = [vulnerable_dependency, vulnerabilities]
        return [*vulnerabilities_by_vuln_dep.values()]

    @staticmethod
    def sanitize_dependency_id(vulnerable_dependency_id: str):
        """Removes version information from the dependency id for selected dependencies (allows linking findings on dependency updates)"""

        for regex in RE_VULNERABLE_DEPENDENCY_ID_REPLACEMENTS:
            match = regex.match(vulnerable_dependency_id)
            if match:
                return match.group("dependency_id")
        return vulnerable_dependency_id

    def convert_project_for_finding(self, project: Project):
        proj = project.path if project.link is None else f"{project.path} ({project.link})"
        return f"{self.get_parser_id()}: {proj}"


class OSPackageTrivyResultParser(TrivyResultParser):
    def get_parser_id(self) -> str:
        return "OSP"

    def is_supported_type(self, result_class: str, result_type: typing.Optional[str]) -> bool:
        return result_class == "os-pkgs"

    def trivy_result_to_finding(
        self,
        trivy_data: typing.Dict[str, typing.Any],
        result_index: int,
        file_to_hash: typing.Dict[str, str],
        repository: str,
        scanner: str,
        project: Project,
    ) -> typing.List[Finding]:
        """For OS packages one finding is created for all packages that have the same vulnerabilities"""
        vulnerabilities_by_vuln_dep = self.trivy_result_to_dependencies_and_vulnerabilities(trivy_data, result_index)
        if len(vulnerabilities_by_vuln_dep) == 0:
            return []

        findings_by_vulnerabilities: typing.Dict[str, Finding] = {}
        for vulnerable_dependency, vulnerabilities in vulnerabilities_by_vuln_dep:
            max_score = 0
            vulnerability_ids = []
            for vulnerability in vulnerabilities:
                vulnerability_ids.append(vulnerability.id)
                if max_score != -1:
                    max_score = -1 if vulnerability.score == -1 else max(max_score, vulnerability.score)
            vulnerability_key = ";".join(sorted(vulnerability_ids))
            if vulnerability_key in findings_by_vulnerabilities:
                findings_by_vulnerabilities.get(vulnerability_key).first_level_dependencies.append(
                    vulnerable_dependency
                )
            else:
                findings_by_vulnerabilities[vulnerability_key] = Finding(
                    repository=repository,
                    scanner=scanner,
                    vulnerable_dependency=vulnerable_dependency,
                    vulnerabilities=vulnerabilities,
                    first_level_dependencies=[],
                    projects=[self.convert_project_for_finding(project)],
                    risk_assessor=[],
                    score=max_score,
                )

        findings = []
        for finding in findings_by_vulnerabilities.values():
            dependencies = [finding.vulnerable_dependency] + finding.first_level_dependencies
            dependencies.sort(key=lambda x: x.id)
            finding.vulnerable_dependency = dependencies[0]
            finding.first_level_dependencies = dependencies[1:]
            finding.vulnerable_dependency.id = self.sanitize_dependency_id(finding.vulnerable_dependency.id)
            finding.vulnerabilities.sort(key=lambda x: x.id)
            findings.append(finding)
        return findings


class BinaryTrivyResultParser(TrivyResultParser):
    def get_parser_id(self) -> str:
        return "BIN"

    def is_supported_type(self, result_class: str, result_type: typing.Optional[str]) -> bool:
        return result_class == "lang-pkgs" and result_type is not None and result_type.endswith("binary")

    def trivy_result_to_finding(
        self,
        trivy_data: typing.Dict[str, typing.Any],
        result_index: int,
        file_to_hash: typing.Dict[str, str],
        repository: str,
        scanner: str,
        project: Project,
    ) -> typing.List[Finding]:
        """For binaries only one finding is created, where the vulnerable dependency is the binary and the vulnerable dependencies of the binary are listed as 1st level dependencies"""
        vulnerabilities_by_vuln_dep = self.trivy_result_to_dependencies_and_vulnerabilities(trivy_data, result_index)
        if len(vulnerabilities_by_vuln_dep) == 0:
            return []

        binary_id: str = trivy_data["Results"][result_index]["Target"]
        binary_name = binary_id.split("/")[-1] if "/" in binary_id and not binary_id.endswith("/") else binary_id
        if binary_id not in file_to_hash:
            raise RuntimeError(f"binary {binary_id} not found in file hash list in repo {repository} project {project}")
        vulnerable_dependency = Dependency(
            id=self.sanitize_dependency_id(binary_id), name=binary_name, version=file_to_hash[binary_id]
        )
        all_vulnerability_ids = set()
        max_score = 0
        for _, vulnerabilities in vulnerabilities_by_vuln_dep:
            for vulnerability in vulnerabilities:
                if max_score != -1:
                    max_score = -1 if vulnerability.score == -1 else max(max_score, vulnerability.score)
                all_vulnerability_ids.add(vulnerability.id)

        for dependency, vulnerabilities in vulnerabilities_by_vuln_dep:
            dep_vulnerability_ids = set()
            for vulnerability in vulnerabilities:
                dep_vulnerability_ids.add(vulnerability.id)
            for vulnerability_id in all_vulnerability_ids.difference(dep_vulnerability_ids):
                dependency.fix_version_for_vulnerability[vulnerability_id] = ["n/a"]  # not affected

        vulnerabilities: typing.List[Vulnerability] = sum([*map(lambda x: x[1], vulnerabilities_by_vuln_dep)], [])
        vulnerabilities.sort(key=lambda x: x.id)
        first_level_deps: typing.List[Dependency] = [*map(lambda x: x[0], vulnerabilities_by_vuln_dep)]
        first_level_deps.sort(key=lambda x: x.id)
        return [
            Finding(
                repository=repository,
                scanner=scanner,
                vulnerable_dependency=vulnerable_dependency,
                vulnerabilities=vulnerabilities,
                first_level_dependencies=first_level_deps,
                projects=[self.convert_project_for_finding(project)],
                risk_assessor=[],
                score=max_score,
            )
        ]


class SecretTrivyResultParser(TrivyResultParser):
    def get_parser_id(self) -> str:
        return "SEC"

    def is_supported_type(self, result_class: str, result_type: typing.Optional[str]) -> bool:
        return result_class == "secret"

    def trivy_result_to_finding(
        self,
        trivy_data: typing.Dict[str, typing.Any],
        result_index: int,
        file_to_hash: typing.Dict[str, str],
        repository: str,
        scanner: str,
        project: Project,
    ) -> typing.List[Finding]:
        """For secrets one finding is created"""
        secret_id: str = trivy_data["Results"][result_index]["Target"]
        secret_name = secret_id.split("/")[-1] if "/" in secret_id and not secret_id.endswith("/") else secret_id
        vulnerable_dependency = Dependency(
            id=self.sanitize_dependency_id(secret_id), name=secret_name, version="current"
        )
        vulnerabilities = []
        for secret in trivy_data["Results"][result_index]["Secrets"]:
            vulnerabilities.append(
                Vulnerability(id=secret["RuleID"], name=secret["RuleID"], description=secret["Title"])
            )
        vulnerabilities.sort(key=lambda x: x.id)
        return [
            Finding(
                repository=repository,
                scanner=scanner,
                vulnerable_dependency=vulnerable_dependency,
                vulnerabilities=vulnerabilities,
                first_level_dependencies=[],
                projects=[self.convert_project_for_finding(project)],
                risk_assessor=[],
            )
        ]


class TrivyExecutor:
    # noinspection PyMethodMayBeStatic
    def run_trivy_and_parse_data(self, path: Path) -> typing.Tuple[typing.Dict[str, typing.Any], typing.Dict[str, str]]:
        json_file_path = f"{path.resolve()}/findings.json"
        hash_file_path = f"{path.resolve()}/file-hashes.txt"
        command = (
            f"bazel run vuln-scan -- --output-path {json_file_path} --format json --hash-output-path {hash_file_path}"
        )
        for i in range(1, TRIVY_SCAN_RETRIES + 1):
            logging.debug(f"{i}. trivy scan attempt")
            trivy_output = ProcessExecutor.execute_command(command, path.resolve(), {})
            if os.path.exists(json_file_path):
                with open(json_file_path, "r") as file:
                    # trivy ships its DB via their github which might get rate limited resulting in errors like:
                    #
                    # init error: DB error: failed to download vulnerability DB: OCI artifact error: OCI artifact error: OCI repository error: GET https://ghcr.io/v2/aquasecurity/trivy-db/manifests/2: TOOMANYREQUESTS: retry-after: 73.254µs, allowed: 44000/minute
                    #
                    # when this happens the json file will have size 0, in this case we will retry a few times and finally fail if we don't get the DB
                    # as future improvement we could consider creating a private AWS ECR pull-through cache rule as suggested here: https://github.com/aquasecurity/trivy/discussions/7668#discussioncomment-11053681
                    # and then configuring trivy to pull the DB from there which would give us a cached version if the original source is not available
                    if os.fstat(file.fileno()).st_size == 0:
                        error_msg = f"trivy scan attempt failed (file size 0) with output:\n{trivy_output}"
                    else:
                        trivy_data = json.load(file)
                        break
            else:
                error_msg = f"trivy scan attempt failed ({json_file_path} doesn't exists) with output:\n{trivy_output}"

            # if we end up here json_file_path does not exist or the file has size 0
            if i >= TRIVY_SCAN_RETRIES:
                logging.error(error_msg)
                raise RuntimeError(error_msg)

            logging.debug(error_msg)
            time.sleep(i)

        file_to_hash: typing.Dict[str, str] = {}
        with open(hash_file_path, "r") as file:
            for line in file:
                parts = line.split()
                if len(parts) != 2 or not RE_SHA256_HASH.match(parts[0]) or not RE_ROOTFS_FILE.match(parts[1]):
                    raise RuntimeError(f"could not parse line {line} in {hash_file_path}")
                rootfs_file = RE_ROOTFS_FILE.match(parts[1]).group(1)
                if rootfs_file in file_to_hash and file_to_hash[rootfs_file] != parts[0]:
                    raise RuntimeError(
                        f"found file {rootfs_file} twice with different hashes in {hash_file_path}, hash1: {file_to_hash[rootfs_file]}, hash2: {parts[0]}"
                    )
                file_to_hash[rootfs_file] = parts[0]

        return trivy_data, file_to_hash


class BazelTrivyContainer(DependencyManager):
    """Helper for Trivy-related functions."""

    def __init__(
        self,
        executor: TrivyExecutor = TrivyExecutor(),
        app_owner_msg_subscriber: AppOwnerMsgSubscriber = ConsoleLoggerAppOwnerMsgSubscriber(),
    ):
        super().__init__()
        self.parsers = (OSPackageTrivyResultParser(), BinaryTrivyResultParser(), SecretTrivyResultParser())
        self.executor = executor
        self.app_owner_msg_subscriber = app_owner_msg_subscriber

    def get_scanner_id(self) -> str:
        return TRIVY_SCANNER_ID

    def get_dependency_diff(self) -> typing.List[Dependency]:
        raise NotImplementedError

    def get_modified_packages(self) -> typing.List[str]:
        raise NotImplementedError

    def has_dependencies_changed(self) -> typing.Dict[str, bool]:
        raise NotImplementedError

    def get_findings(
        self, repository_name: str, project: Project, engine_version: typing.Optional[str]
    ) -> typing.List[Finding]:
        path = self.root.parent / project.path

        trivy_data, file_to_hash = self.executor.run_trivy_and_parse_data(path)
        if "Results" not in trivy_data:
            return []

        findings = []
        for i in range(len(trivy_data["Results"])):
            if "Class" not in trivy_data["Results"][i]:
                raise RuntimeError(f"trivy result {i} has no Class key in repo {repository_name} project {project}")
            result_class = trivy_data["Results"][i]["Class"]
            result_type = trivy_data["Results"][i]["Type"] if "Type" in trivy_data["Results"][i] else None
            result_parsed = False
            for parser in self.parsers:
                if parser.is_supported_type(result_class, result_type):
                    findings.extend(
                        parser.trivy_result_to_finding(
                            trivy_data, i, file_to_hash, repository_name, self.get_scanner_id(), project
                        )
                    )
                    result_parsed = True
                    break
            if not result_parsed:
                log_msg = f"skipping trivy result {i} with class {result_class} and type {result_type} in repo {repository_name} project {project} because no parser can handle the result"
                logging.warning(log_msg)
                self.app_owner_msg_subscriber.send_notification_to_app_owners(log_msg)

        return findings
