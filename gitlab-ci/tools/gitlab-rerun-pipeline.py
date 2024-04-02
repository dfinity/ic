#!/usr/bin/env python3
#
# Re-run the GitLab pipeline for the specified git reference (branch).
#
# Example:
# ./gitlab-rerun-pipeline.py my-nice-branch
#
import argparse
import json
import logging
import os
import pathlib

import git
import requests

GITLAB_PROJECT_ID = "25333072"

git_repo = git.Repo(os.path.dirname(__file__), search_parent_directories=True)
repo_root = pathlib.Path(git_repo.git.rev_parse("--show-toplevel"))


def create_branch_from_git_rev(git_rev: str) -> str:
    branch_name = f"rebuild-revision-{git_rev[:10]}"
    try:
        # check if the branch already exists
        git_repo.rev_parse(branch_name)
        logging.info("Found git branch: %s", branch_name)
    except git.BadName:
        logging.info("Creating git branch: %s", branch_name)
        git_repo.git.checkout("-b", branch_name, git_rev, "--force")
    for remote_name in git_repo.git.remote("show").split():
        git_repo.git.push("--set-upstream", remote_name, branch_name)
        logging.info("Pushed git branch to %s", remote_name)
    return branch_name


def trigger_pipeline(branch: str, trigger_token: str):
    r = requests.post(
        f"https://gitlab.com/api/v4/projects/{GITLAB_PROJECT_ID}/trigger/pipeline",
        data={"token": trigger_token, "ref": branch},
    )
    if 200 <= r.status_code <= 299:
        logging.info("Request submitted successfully:")
        logging.info("%s", json.dumps(r.json(), indent=2))
    else:
        raise ValueError(f"The server returned a {r.status_code}.")


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--branch",
        action="store",
        help="Git branch for which to re-run the pipeline.",
    )

    parser.add_argument(
        "--git-rev",
        action="store",
        help="Git revision (commit sha) for which to re-run the pipeline.",
    )

    parser.add_argument(
        "--gitlab-trigger-token",
        action="store",
        help="GitLab trigger token. Get one at https://gitlab.com/dfinity-lab/core/dfinity/-/settings/ci_cd#js-pipeline-triggers",
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    branch = None
    if args.branch:
        branch = args.branch
    else:
        if args.git_rev:
            branch = create_branch_from_git_rev(args.git_rev)

    if not branch:
        logging.error("Git branch not provided")
        parser.print_help()
        exit(1)

    if not args.gitlab_trigger_token:
        logging.error("GitLab trigger token not provided.")
        parser.print_help()
        exit(1)

    trigger_pipeline(branch, args.gitlab_trigger_token)


if __name__ == "__main__":
    main()
