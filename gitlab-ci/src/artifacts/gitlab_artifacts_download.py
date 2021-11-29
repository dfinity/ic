#!/usr/bin/env python3
#
# Utility for downloading GitLab artifacts.
# It can download artifacts from any of the following:
# - a given git revision + gitlab job name
# - git reference (e.g. branch name) + gitlab job name
# - gitlab pipeline id + gitlab job name
# - gitlab job id
#
# Example usage:
# [download artifacts from the given git revision, from any pipeline]
# ./gitlab-ci/src/artifacts/gitlab_artifacts_download.py \
#   --git-rev e71555224cb95a8ff10d8b83d9dd2428029741eb --job-name cargo-build-release-linux-native
#
# [download artifacts from the specific GitLab Pipeline Id]
# ./gitlab-ci/src/artifacts/gitlab_artifacts_download.py \
#   --pipeline-id 322487577 --job-name cargo-build-release-linux-native
#
# [download artifacts from the specific GitLab Job Id]
# ./gitlab-ci/src/artifacts/gitlab_artifacts_download.py --job-id 1354236856
#
import argparse
import functools
import gzip
import io
import logging
import os
import pathlib
import shutil
import stat
import time
import zipfile
from typing import Any

import git
import gitlab

DFINITY_PROJECT = 22_487_979
MAX_GIT_FETCH_ATTEMPTS = 10


class GL:
    """Interface with GitLab over its Job API and download artifacts."""

    def __init__(self, out_dir: str, remote_path: str, unpack: bool, mark_executable: bool):
        """Init the object with the token necessary to access the private repo."""
        token = os.environ.get("GITLAB_API_TOKEN")
        if not token:
            logging.error("GitLab token not set. Please set a token in the GITLAB_API_TOKEN environment variable")
            exit(1)
        self.gl = gitlab.Gitlab("https://gitlab.com", private_token=token)
        self.project = self.gl.projects.get(DFINITY_PROJECT)
        self.local_repo = git.Repo(os.path.dirname(__file__), search_parent_directories=True)
        self.repo_root = pathlib.Path(self.local_repo.git.rev_parse("--show-toplevel"))
        self.out_dir = out_dir
        self.remote_path = remote_path
        self.unpack = unpack
        self.mark_executable = mark_executable

    def _search_git_rev_for_artifacts(self, git_rev: str, job_name: str):
        """Search pipelines executed for the given git revision and return the newest job matching job_name."""
        logging.info(
            "Git revision %s: searching for successful job named '%s'",
            git_rev,
            job_name,
        )

        for pipeline in self.project.pipelines.list(sha=git_rev, per_page=1000):
            if job := self._search_pipeline_for_job_name(pipeline, job_name):
                return job

    def _search_pipeline_for_job_name(self, pipeline: Any, job_name: str):
        """Search pipeline for the given job name and return job object if found for job_name."""
        logging.info(
            "Checking pipeline %s (%s) => %s",
            pipeline.id,
            pipeline.status,
            pipeline.web_url,
        )
        for job in pipeline.jobs.list(all=True, per_page=1000):
            logging.debug("Checking job %s => %s", job.name, job.web_url)
            if job.name == job_name:
                # Convert ProjectPipelineJob to ProjectJob
                return self.project.jobs.get(job.id)

        for bridge_pipeline in pipeline.bridges.list(all=True, per_page=1000):
            if not bridge_pipeline.downstream_pipeline:
                logging.debug(
                    "No children in bridge pipeline %s => %s",
                    pipeline.id,
                    pipeline.web_url,
                )
                return
            child_pipeline = self.project.pipelines.get(bridge_pipeline.downstream_pipeline["id"])
            logging.debug(
                "Checking child pipeline %s => %s",
                child_pipeline.id,
                child_pipeline.web_url,
            )
            if job := self._search_pipeline_for_job_name(child_pipeline, job_name):
                return job
        if pipeline.status == "success":
            logging.error("No job named %s in passed pipeline %s", job_name, pipeline.id)
        else:
            logging.debug("No job named %s in failed pipeline %s", job_name, pipeline.id)

    def _git_fetch_master(self):
        import git

        exc = None
        for i in range(MAX_GIT_FETCH_ATTEMPTS):
            try:
                # Get the 1st remote name. This is typically 'origin' but may be something else as well.
                remote_name = self.local_repo.git.remote("show").split()[0]
                origin = self.local_repo.remote(name=remote_name)
                logging.info("Updating master branch: git fetch %s master:master", remote_name)
                origin.fetch("master:master", prune=True, prune_tags=True, force=True)
                return
            except git.GitCommandError as e:
                logging.warning("Error [%d/%d] fetching changes: %s", i, MAX_GIT_FETCH_ATTEMPTS, e)
                exc = e
                time.sleep(10)
        if exc:
            raise exc  # raise the last exception if there were too many attempts

    @functools.lru_cache(maxsize=32)  # Only fetch origin/master once per execution
    def _get_merge_base(self):
        if not self.local_repo.head.is_detached and str(self.local_repo.active_branch) == "master":
            # Support running the function (tests) on master
            return [self.local_repo.head.commit]
        # Make sure the master branch is up-to-date.
        if self.local_repo.remotes:
            self._git_fetch_master()
        else:
            logging.warning("No git remotes found.")

        merge_base = self.local_repo.merge_base("master", self.local_repo.head.commit)
        if not merge_base:
            logging.error("No common merge base exists between HEAD and master")
            ref_name = self.local_repo.head.ref
            raise ValueError(f"No merge base between {ref_name} and master.")

        return merge_base

    def download_artifacts_for_job(self, job: Any):
        """Download the artifacts for the given GitLab job object."""
        local_path = pathlib.Path(
            self.out_dir or f"{self.repo_root}/artifacts/{job.commit['id']}/{os.path.dirname(self.remote_path or '')}"
        )
        local_path.mkdir(exist_ok=True, parents=True)

        try:
            if self.remote_path:
                out_file = local_path / os.path.basename(self.remote_path)
                with open(out_file, "wb") as wb:
                    job.artifact(path=self.remote_path, streamed=True, action=wb.write)
            else:
                out_file = io.BytesIO()
                job.artifacts(streamed=True, action=out_file.write)
                with zipfile.ZipFile(out_file, "r") as zf:
                    zf.extractall(local_path)
            logging.info(
                "Gitlab artifacts for Job ID '%s' downloaded to %s",
                job.id,
                local_path.absolute(),
            )

            if self.unpack:
                logging.info("Unpacking %s/**/*.gz", local_path)
                for path in local_path.rglob("*.gz"):
                    logging.debug("Unpack %s", path)
                    if str(path).endswith(".tar.gz") or str(path).endswith(".tgz"):
                        shutil.unpack_archive(path, extract_dir=path.absolute().parent)
                    else:
                        with gzip.open(path, "rb") as f_in:
                            with open(
                                path.absolute().parent / os.path.basename(path)[:-3],
                                "wb",
                            ) as f_out:
                                shutil.copyfileobj(f_in, f_out)

            if self.mark_executable:
                logging.info("Marking executable %s/**/*", local_path)
                for path in local_path.rglob("*"):
                    mode = os.stat(path).st_mode
                    os.chmod(path, mode | stat.S_IEXEC)

            return True
        except gitlab.exceptions.GitlabGetError as exc:
            logging.warning(
                "Gitlab artifacts for Job ID '%s' failed to download due to %s",
                job.id,
                exc,
            )

    def download_artifacts_for_job_id(self, job_id: str):
        """Download the artifacts for the given GitLab job ID."""
        job = self.project.jobs.get(job_id)
        self.download_artifacts_for_job(job)

    def download_latest_artifacts_to_git_rev(self, git_rev: str, job_name: str):
        """Download the latest artifacts available at or before the given git revision."""
        for ref in self.local_repo.iter_commits(rev=git_rev, max_count=50):
            job = self._search_git_rev_for_artifacts(ref, job_name)
            if job:
                logging.info(
                    "Git rev %s: successful job named '%s' found %s",
                    ref,
                    job_name,
                    job.web_url,
                )
                job = self.project.jobs.get(job.id)
                if self.download_artifacts_for_job(job):
                    break
            else:
                logging.info("Git rev %s: no successful job named '%s' found", ref, job_name)

    def download_artifacts_for_pipeline_job(self, pipeline_id: str, job_name: str):
        """Download artifacts for the provided pipeline_id and job_name."""
        pipeline = self.project.pipelines.get(pipeline_id)
        job = self._search_pipeline_for_job_name(pipeline, job_name)
        if job:
            self.download_artifacts_for_job(job)

    def download_latest_artifacts_to_merge_base(self, job_name: str):
        """Download the newest master artifacts available for the ref's merge base."""
        merge_base = self._get_merge_base()

        return self.download_latest_artifacts_to_git_rev(git_rev=merge_base, job_name=job_name)

    def download_artifacts_for_git_rev(self, git_rev: str, job_name: str):
        """Download the artifacts for the provided git revision, by searching pipelines and jobs."""
        job = self._search_git_rev_for_artifacts(git_rev, job_name)
        if job:
            job = self.project.jobs.get(job.id)
            self.download_artifacts_for_job(job)
        else:
            logging.error("Git rev %s: no successful job named '%s' found", git_rev, job_name)

    def download_artifacts_for_ref(self, ref: str, job_name: str):
        """Download the artifacts for the provided git reference, can only download the entire archive."""
        try:
            out_file = io.BytesIO()
            self.project.artifacts(ref_name=ref, job=job_name, streamed=True, action=out_file.write)
            with zipfile.ZipFile(out_file, "r") as zf:
                out_dir = pathlib.Path(self.out_dir or f"{self.repo_root}/artifacts/{ref}")
                out_dir.mkdir(exist_ok=True)
                zf.extractall(out_dir)
            logging.info("Gitlab artifacts for reference '%s' downloaded", ref)
        except gitlab.exceptions.GitlabGetError as exc:
            logging.warning(
                "Gitlab artifacts for reference '%s' failed to download due to %s",
                ref,
                exc,
            )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--git-rev",
        action="store",
        help="Git revision for which to download the artifact",
    )

    parser.add_argument(
        "--git-ref",
        action="store",
        help="Git reference for which to download the artifacts (default=master)",
        nargs="?",
        const="master",
        default="master",
    )

    parser.add_argument(
        "--latest-to",
        action="store",
        help="Download latest artifacts available at or before the given git revision",
    )

    parser.add_argument(
        "--latest-to-merge-base",
        action="store_true",
        help="Download latest artifacts available on master at or before the merge-base",
    )

    parser.add_argument(
        "--job-id",
        action="store",
        help="GitLab job id for which to download the artifacts",
    )

    parser.add_argument(
        "--pipeline-id",
        action="store",
        help="GitLab pipeline id for which to download the artifacts (use together with --job-name).",
    )

    parser.add_argument(
        "--job-name",
        action="store",
        help="Job name for which to download the artifacts",
    )

    parser.add_argument(
        "--remote-path",
        action="store",
        help="Remote (artifact) path to download. E.g. 'artifacts/release/replica.gz'",
    )

    parser.add_argument(
        "--unpack",
        action="store_true",
        help="Unpack the downloaded binaries.",
    )

    parser.add_argument(
        "--mark-executable",
        action="store_true",
        help="Mark (chmod) the downloaded binaries (optionally unpacked if --unpack provided) as executable.",
    )

    parser.add_argument(
        "-o",
        "--out-dir",
        help="Store the output in the provided dir.",
        nargs="?",
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    gl = GL(args.out_dir, args.remote_path, args.unpack, args.mark_executable)

    if args.job_id:
        gl.download_artifacts_for_job_id(args.job_id)
    elif args.pipeline_id:
        gl.download_artifacts_for_pipeline_job(args.pipeline_id, args.job_name)
    elif args.latest_to:
        if not (args.job_name):
            logging.error(" --job-name need to be provided to download with --latest-to")
            parser.print_help()
            exit(1)
        gl.download_latest_artifacts_to_git_rev(git_rev=args.latest_to, job_name=args.job_name)
    elif args.latest_to_merge_base:
        if not (args.job_name):
            logging.error(" --job-name need to be provided to download with --merge-base")
            parser.print_help()
            exit(1)
        gl.download_latest_artifacts_to_merge_base(job_name=args.job_name)
    elif args.git_rev:
        if not (args.git_ref and args.job_name):
            logging.error(" --job-name needs to be provided in order to download by --git-rev")
            parser.print_help()
            exit(1)
        gl.download_artifacts_for_git_rev(args.git_rev, args.job_name)
    elif args.git_ref:
        if not (args.git_ref and args.job_name):
            logging.error(" --job-name needs to be provided in order to download by --git-ref")
            parser.print_help()
            exit(1)
        gl.download_artifacts_for_ref(args.git_ref, args.job_name)


if __name__ == "__main__":
    main()
