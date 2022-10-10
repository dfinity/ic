import re
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from typing import Dict
from typing import List
from typing import Optional

import gitlab.base
import pytz
from pipeline.alert import AlertService
from pipeline.backend.system_tests_artifact_manager import SystemTestsArtifactManager
from util.print import eprint

from .group import Group


class CiException(Exception):
    pass


class CiPipelineNotFoundException(CiException):
    def __init__(self, pipeline_id: str):
        super().__init__(pipeline_id)
        self.pipeline_id = pipeline_id


class CiJobNotFoundException(CiException):
    def __init__(self, jid: int):
        super().__init__(jid)
        self.jid = jid


class CiJobNotDefinedForGroup(CiException):
    pass


class PotArtifactNotFoundInCi(CiException):
    def __init__(self, jid: int, art_path: str):
        super().__init__(jid, art_path)
        self.jid = jid
        self.pot_name = art_path


class GroupNamesNotFoundInSystestLog(CiException):
    def __init__(self, system_tests_log: Path):
        super().__init__(system_tests_log)
        self.system_tests_log = system_tests_log


class Ci:

    # Should be in sync with testnet/tests/pipeline/pipeline.yml
    _MONITORED_REGULAR_JOB_TYPES = set(
        [
            "rosetta-hourly",
            "system-tests-hourly",
            "system-tests-nightly",
            "wasm-generator-hourly",
            "wasm-generator-nightly",
        ]
    )

    # Should be in sync with gitlab-ci/config/47--guest-os-test--guest-os-e2e-test.yml
    _MONITORED_PREMASTER_JOB_TYPES = set(
        [
            "system-tests-pre-master",
            # "system-tests-hotfix",
        ]
    )

    def __init__(self, url: str, project: str, token: str, slack: AlertService):
        self.gl = gitlab.Gitlab(url=url, private_token=token)
        self.project = self.gl.projects.get(project)
        self.slack = slack

    # Example:        2022-02-22T15:47:51.081Z
    _ES_TIMESTAMP_FMT = "%Y-%m-%dT%H:%M:%S.%f%z"

    @staticmethod
    def job_ts(job) -> datetime:
        """Returns the timestamp of a GitLab job"""
        return datetime.strptime(job.created_at, Ci._ES_TIMESTAMP_FMT)

    @staticmethod
    def job_url(job) -> str:
        return job._attrs["web_url"]

    @staticmethod
    def job_to_str(job) -> str:
        return f"GitLabJob<created_at={job.created_at}, url={Ci.job_url(job)}, name={job.name}>"

    def get_last_hourly_jobs(self, page_size=1_000) -> List[gitlab.base.RESTObject]:
        now = datetime.now(pytz.utc)
        jobs: List[gitlab.base.RESTObject]
        jobs = []
        page = (
            1  # The first page is page1 as per https://python-gitlab.readthedocs.io/en/v3.4.0/api-usage.html#pagination
        )
        while True:
            eprint(f"Scanning page #{page} ...")

            new_jobs = self.project.jobs.list(
                per_page=page_size,
                page=page,
                as_list=True,
                order_by="id",
                sort="desc",
                include_retried=True,
                retry_transient_errors=True,
                # we are potentially interested in all completed jobs
                scope=["success"],
            )

            for job in new_jobs:
                if "hotfix" not in job.name and "ic-prod-tests" in job.tag_list:
                    eprint(f"Job {job.name} was created at {job.created_at}")
                    jobs.append(job)

                # Collect logs for CI pipelines created within the last 1 hour
                # + 5 min (to be sure we don't miss anything)
                if now - Ci.job_ts(job) > timedelta(hours=1, minutes=5):
                    eprint("Searched through all CI jobs within the last hour")
                    return jobs

            page += 1
            if not new_jobs:
                eprint("Searched through all existing CI jobs")
                return jobs

    def get_jobs_for_premaster_pipeline(self, pipeline_id: str, page_size=1_000) -> List[gitlab.base.RESTObject]:
        pipeline: gitlab.base.RESTObject
        try:
            pipeline = self.project.pipelines.get(id=pipeline_id)
        except gitlab.exceptions.GitlabGetError:
            eprint(f"Cannot find pipeline with ID {pipeline_id}")
            raise CiPipelineNotFoundException(pipeline_id)

        jobs: List[gitlab.base.RESTObject] = []
        page = (
            1  # The first page is page1 as per https://python-gitlab.readthedocs.io/en/v3.4.0/api-usage.html#pagination
        )

        while True:
            new_jobs = pipeline.jobs.list(
                per_page=page_size,
                page=page,
                as_list=True,
                order_by="id",
                sort="desc",
                include_retried=False,
                retry_transient_errors=True,
            )
            for job in new_jobs:
                if job.name in Ci._MONITORED_PREMASTER_JOB_TYPES:
                    eprint(f"Found job {job.name} created at {job.created_at}")
                    jobs.append(job)

            page += 1
            if not new_jobs or len(jobs) == len(Ci._MONITORED_PREMASTER_JOB_TYPES):
                eprint(f"Searched through all existing CI jobs for pipeline {pipeline_id}")
                return jobs

    @staticmethod
    def _get_groups_from_trace(trace: str, include_pattern: Optional[str] = None) -> Optional[Dict[str, Group]]:
        groups: Dict[str, Group] = dict()
        group_names = re.findall("creating group '(.*)'", trace)
        if not group_names:
            return None
        eprint(f"Found {len(group_names)} group(s)")
        gname: str
        for gname in group_names:
            if include_pattern is None or re.match(include_pattern, gname):
                eprint(f" + {gname}", end="\n", flush=True)
                groups[gname] = Group(gname)
        return groups

    def _get_group_names_from_jobs(
        self, jobs: List[gitlab.base.RESTObject], include_pattern: Optional[str] = None
    ) -> Dict[str, Group]:
        groups: Dict[str, Group] = dict()
        for job in jobs:
            eprint(f"Searching for group names for job `{job.name}` ...")
            trace = job.trace().decode("utf-8")
            new_groups = self._get_groups_from_trace(trace, include_pattern=include_pattern)
            if not new_groups:
                eprint(f"Warning: cannot find test group name for job {Ci.job_url(job)}")
            else:
                intersect = set(new_groups.keys()).intersection(groups.keys())
                if set() != intersect:
                    short_msg = "duplicate groups found"
                    msg = short_msg + ", ".join(
                        map(lambda g: str(new_groups[g]) + " and " + str(groups[g]), intersect)  # type: ignore
                    )
                    self.slack.alert(msg, short_msg, level="🍒")
                groups.update(new_groups)
        return groups

    def get_regular_groups(self) -> Dict[str, Group]:
        """Returns: Map from group names to Groups (corresponding to hourly and nightly system tests)"""
        jobs = self.get_last_hourly_jobs()
        jobs_str = "\n".join(map(lambda j: Ci.job_to_str(j), jobs))
        eprint(f"Found {len(jobs)} jobs:\n{jobs_str}")
        return self._get_group_names_from_jobs(jobs)

    def get_premaster_groups_for_pipeline(
        self, pipeline_id: str, include_pattern: Optional[str] = None
    ) -> Dict[str, Group]:
        """
        Returns: Map from group names to Groups (corresponding to pre-master system tests)
        Throws:
        - CiPipelineNotFoundException if no pipeline is found for pipeline_id
        - CiJobNotFoundException      if expected jobs are not found
        """
        jobs = self.get_jobs_for_premaster_pipeline(pipeline_id)
        # [ProjectPipelineJob]s do not have method trace(), so we need to get a [ProjectJob] with the same ID
        traceful_jobs: List[gitlab.base.RESTObject] = []
        for job in jobs:
            try:
                traceful_jobs.append(self.project.jobs.get(id=job.id))
            except gitlab.exceptions.GitlabGetError:
                eprint(f"Could not find project job for pipeline job with ID {job.id}")
                raise CiJobNotFoundException(job.id)
        eprint(f"Found {len(traceful_jobs)} jobs")
        return self._get_group_names_from_jobs(traceful_jobs, include_pattern)

    @staticmethod
    def get_groups_from_systest_logs(path: Path) -> Dict[str, Group]:
        """
        Arguments:
        - path: str -- path to a test driver log
        Returns: Map from group names to Groups
        Throws:
        - GroupNamesNotFoundInSystestLog if no grroups names were found
        """
        trace: str
        with open(path, "r") as system_tests_log:
            trace = "\n".join(system_tests_log.readlines())
        groups = Ci._get_groups_from_trace(trace)
        if not groups:
            eprint(f"Could not find any groups in test driver log {str(path)}")
            raise GroupNamesNotFoundInSystestLog(path)
        return groups

    def get_registry_snapshot_for_group(self, group: Group) -> str:
        jid = group.job_id()
        if jid is None:
            eprint(f"Cannot obtain initial registry snapshot for {str(group)} without job ID")
            raise CiJobNotDefinedForGroup()

        try:
            job = self.project.jobs.get(jid)
        except gitlab.exceptions.GitlabGetError:
            eprint(f"Cannot find job with ID {jid}")
            raise CiJobNotFoundException(jid)

        snap_bs: bytes
        try:
            snap_path = str(SystemTestsArtifactManager("working_dir").registry_snapshot_path(group.pot_name()))
            snap_bs = job.artifact(snap_path)
            if snap_bs is None:
                gitlab.exceptions.GitlabGetError()
        except gitlab.exceptions.GitlabGetError:
            eprint(f"Could not find artifact {snap_path} of {str(group)}")
            raise PotArtifactNotFoundInCi(jid, snap_path)

        return snap_bs.decode().strip()

    def get_artifacts_for_group(self, group: Group, dest_path: Path) -> None:
        jid = group.job_id()
        if jid is None:
            eprint(f"Cannot obtain initial registry snapshot for {str(group)} without job ID")
            raise CiJobNotDefinedForGroup()

        try:
            job = self.project.jobs.get(jid)
        except gitlab.exceptions.GitlabGetError:
            eprint(f"Cannot find job with ID {jid}")
            raise CiJobNotFoundException(jid)

        with open(dest_path, "wb") as fout:
            job.artifacts(streamed=True, action=fout.write)
