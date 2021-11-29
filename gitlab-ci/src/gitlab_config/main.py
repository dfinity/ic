#!/usr/bin/env python3
import argparse
import logging
import os
import sys

import dfinity_gitlab_config
import gitrepo
import yaml

import gen_gitlab_cargo_pipeline

if __name__ == "__main__":
    repo = gitrepo.GitRepo()

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--cfg-file",
        help="Root config file",
        type=argparse.FileType("r"),
    )

    parser.add_argument(
        "--cfg-validate",
        help="Validate the CI jobs",
        action="store_true",
    )

    parser.add_argument(
        "--cfg-dump-all",
        help="Dump the CI config for all jobs to the provided file or stdout",
        action="store_true",
    )

    parser.add_argument(
        "--cfg-dump-jobs",
        help="Dump the CI config for comma-separated jobs",
        action="store",
        metavar=("JOB_NAMES"),
    )

    parser.add_argument(
        "--stages-list",
        help="List the CI config stages",
        action="store_true",
    )

    parser.add_argument(
        "--job-list",
        help="List the CI jobs, divided into stages",
        action="store_true",
    )

    parser.add_argument(
        "--job-list-validate",
        help="Validate the list of CI jobs, check that all required jobs are present",
        action="store_true",
    )

    parser.add_argument(
        "--job-script",
        help="Dump the CI job script",
        action="store",
    )

    parser.add_argument(
        "--job-script-simulate",
        help="Simulate the CI job script",
        action="store",
    )

    parser.add_argument(
        "--cfg-include-list",
        help="List all files included in the CI config",
        action="store_true",
    )

    parser.add_argument(
        "-o",
        "--out",
        help="Store the output in the provided file (default is stdout)",
        type=argparse.FileType("w"),
        nargs="?",
        const="-",
        default="-",
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    gitlab = dfinity_gitlab_config.DfinityGitLabConfig(repo_root_local=repo.repo_root())

    if args.cfg_file:
        # If a --cfg-file argument is provided, then only load that file
        gitlab.ci_cfg_load_from_file(args.cfg_file)
    else:
        # Otherwise, load both the parent and the child pipeline
        with open(f"{repo.repo_root()}/.gitlab-ci.yml") as f:
            gitlab.ci_cfg_load_from_file(f)

    gitlab.ci_cfg_load(
        gen_gitlab_cargo_pipeline.generate_gitlab_yaml_for_all_crates(
            rust_workspace=os.path.join(repo.repo_root(), "rs")
        )
    )
    gitlab.ci_cfg_load(
        gen_gitlab_cargo_pipeline.generate_gitlab_yaml_for_noop(rust_workspace=os.path.join(repo.repo_root(), "rs"))
    )

    if args.cfg_validate:
        gitlab.ci_cfg_lint()
        logging.info("CI config validation complete")

    if args.cfg_dump_all:
        with args.out as f:
            f.write(yaml.dump(gitlab.ci_cfg_expanded, sort_keys=True))
            logging.debug("File %s written", args.out.name)

    if args.cfg_dump_jobs:
        result = {}
        requested_jobs = set(args.cfg_dump_jobs.split(","))
        always_included_jobs = [
            "stages",
            "variables",
            "default",
            "notify-gitlab-start",
            "notify-gitlab-success",
            "notify-gitlab-failure",
        ]
        for job_name in always_included_jobs:
            job_config = gitlab.ci_cfg_get_job(job_name)
            result[job_name] = job_config
        for job_name in requested_jobs:
            job_config = gitlab.ci_cfg_get_job_set_push(job_name)
            if job_config:
                result[job_name] = job_config
            else:
                logging.error("Job '%s' not found", job_name)
                logging.info("Job list: \n%s", yaml.dump(gitlab.ci_cfg_jobs()))
                sys.exit(1)
        with args.out as f:
            f.write(yaml.dump(result, sort_keys=True))
            logging.debug("File %s written", args.out.name)

    if args.cfg_include_list:
        with args.out as f:
            f.write(yaml.dump(gitlab.ci_cfg_included_files()))
            logging.debug("File %s written", args.out.name)

    if args.stages_list:
        with args.out as f:
            f.write(yaml.dump(gitlab.ci_cfg_expanded.get("stages", [])))
            logging.debug("File %s written", args.out.name)
        sys.exit(0)

    if args.job_list:
        with args.out as f:
            f.write(yaml.dump(gitlab.ci_cfg_jobs_divided_to_stages(), sort_keys=False))

    if args.job_list_validate:
        file_name = os.path.join(repo.repo_root(), "rs/gitlab-ci-config.yml")
        with open(file_name) as fin:
            parsed_yml = yaml.load(fin, Loader=yaml.FullLoader)
            job_list_required = set(parsed_yml["ci_jobs_required"])
            job_list_present = set(gitlab.ci_cfg_jobs())
            job_list_required_missing = job_list_required.difference(job_list_present)
            logging.debug("Loaded required jobs: %s", job_list_required)
            logging.debug("Loaded present jobs: %s", job_list_present)
            logging.debug("Calculated missing jobs: %s", job_list_required_missing)
            if job_list_required_missing:
                logging.error(
                    "The following required jobs are missing: %s",
                    job_list_required_missing,
                )
                sys.exit(1)
            else:
                logging.info("All %d required jobs are present", len(job_list_required))

    if args.job_script:
        with args.out as f:
            f.write(gitlab.ci_job_script(args.job_script))

    if args.job_script_simulate:
        with args.out as f:
            f.write(gitlab.ci_job_simulate(args.job_script_simulate))
