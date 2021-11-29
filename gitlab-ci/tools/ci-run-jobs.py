#!/usr/bin/env python3
import argparse
import logging
import os
import shutil
import subprocess
import sys

import yaml

"""
Importing sys_path_patch adds the REPO_ROOT/gitlab-ci/src to the PYTHON_PATH
So this should be done before importing anything else from gitlab-ci/src
"""
import sys_path_patch  # noqa
from gen_gitlab_cargo_pipeline import generate_gitlab_yaml_for_all_crates
from gen_gitlab_cargo_pipeline import generate_gitlab_yaml_for_noop
from gitlab_config import dfinity_gitlab_config
from sys_path_patch import repo_root


def gitlab_ci_cfg_load(orig_ci_cfg_path):
    gitlab_cfg = dfinity_gitlab_config.DfinityGitLabConfig(repo_root)
    gitlab_cfg.ci_cfg_load_from_file(open(orig_ci_cfg_path))

    gitlab_cfg.ci_cfg_load(generate_gitlab_yaml_for_all_crates(rust_workspace=repo_root / "rs"))
    gitlab_cfg.ci_cfg_load(generate_gitlab_yaml_for_noop(rust_workspace=repo_root / "rs"))
    return gitlab_cfg


def gitlab_ci_cfg_for_jobs(gitlab_cfg, job_list):
    result = {}
    always_included_jobs = [
        "stages",
        "variables",
        "default",
        "notify-gitlab-start",
        "notify-gitlab-success",
        "notify-gitlab-failure",
    ]
    for job_name in always_included_jobs:
        job_config = gitlab_cfg.ci_cfg_get_job(job_name)
        if job_config:
            result[job_name] = job_config
    for job_name in job_list:
        job_config = gitlab_cfg.ci_cfg_get_job_set_push(job_name)
        if job_config:
            result[job_name] = job_config
        else:
            logging.error("Job '%s' not found", job_name)
            logging.info("Job list: \n%s", yaml.dump(gitlab_cfg.ci_cfg_jobs()))
            sys.exit(1)
    return yaml.dump(result, sort_keys=True)


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "jobs_to_run",
        metavar="JOB",
        help="A list of CI jobs to run",
        action="store",
        nargs="*",
    )

    parser.add_argument("-l", "--list", help="A list of all CI jobs", action="store_true")

    parser.add_argument(
        "-r",
        "--restore",
        "--reset",
        help="Restore the original CI config",
        action="store_true",
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    orig_ci_cfg_path = repo_root / ".gitlab-ci.yml.original"
    if not os.path.exists(orig_ci_cfg_path) or os.path.getsize(orig_ci_cfg_path) == 0:
        # Restore the original file contents from origin/master
        with open(orig_ci_cfg_path, "wb") as f:
            orig_ci_cfg = subprocess.check_output(["git", "show", "origin/master:.gitlab-ci.yml"])
            f.write(orig_ci_cfg)

    gitlab_cfg = gitlab_ci_cfg_load(orig_ci_cfg_path)

    if args.list:
        print(yaml.dump(gitlab_cfg.ci_cfg_jobs()))
        sys.exit(0)
    elif args.restore:
        # Restore the original files and prepare for commit
        shutil.copy(orig_ci_cfg_path, repo_root / ".gitlab-ci.yml")
        logging.info("Original CI config restored.")
        subprocess.check_call(["git", "add", "--force", str(repo_root / ".gitlab-ci.yml")])
        if os.path.exists(orig_ci_cfg_path):
            subprocess.call(
                ["git", "rm", "--force", str(orig_ci_cfg_path)],
                stderr=subprocess.DEVNULL,
            )
        logging.info("Please run 'git commit' and then 'git push'")
        sys.exit(0)
    else:
        # Backup the original files and create a small CI pipeline
        if not args.jobs_to_run:
            print("No jobs provided.")
            parser.print_help()
            sys.exit(1)

        job_list = set(args.jobs_to_run)

        # Overwrite .gitlab-ci.yml with the one containing only a short-list of jobs
        with open(repo_root / ".gitlab-ci.yml", "w") as f:
            f.write(gitlab_ci_cfg_for_jobs(gitlab_cfg, job_list))

        subprocess.check_call(
            [
                "git",
                "add",
                "--force",
                str(repo_root / ".gitlab-ci.yml"),
                str(orig_ci_cfg_path),
            ]
        )

        logging.info("Updated '.gitlab-ci.yml' file.")
        logging.info("Please run 'git commit' and then 'git push'")


if __name__ == "__main__":
    main()
