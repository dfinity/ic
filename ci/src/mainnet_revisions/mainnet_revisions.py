#!/usr/bin/env python3
import argparse
import json
import logging
import os
import pathlib
import subprocess
import urllib.request
from enum import Enum
from typing import List

SAVED_VERSIONS_SUBNETS_PATH = "mainnet-subnet-revisions.json"
nns_subnet_id = "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
app_subnet_id = "io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe"
PUBLIC_DASHBOARD_API = "https://ic-api.internetcomputer.org"
SAVED_VERSIONS_CANISTERS_PATH = "mainnet-canister-revisions.json"


class Command(Enum):
    SUBNETS = 1
    CANISTERS = 2


def sync_main_branch_and_checkout_branch(
    repo_root: pathlib.Path, main_branch: str, branch_to_checkout: str, logger: logging.Logger
):
    if not repo_root.exists():
        raise Exception("Expected dir %s to exist", repo_root.name)

    subprocess.call(["git", "fetch", "--depth=1", "--no-tags", "origin", f"{main_branch}:{main_branch}"], cwd=repo_root)

    result = subprocess.run(["git", "status", "--porcelain"], stdout=subprocess.PIPE, text=True, check=True)
    if result.stdout.strip():
        raise Exception("Found uncommited work! Commit and then proceed. Uncommited work:\n%s", result.stdout.strip())

    if subprocess.call(["git", "checkout", branch_to_checkout], cwd=repo_root) == 0:
        # The branch already exists, update the existing MR
        logger.info("Found an already existing target branch")
    else:
        subprocess.check_call(["git", "checkout", "-b", branch_to_checkout], cwd=repo_root)
    subprocess.check_call(["git", "reset", "--hard", f"origin/{main_branch}"], cwd=repo_root)


def commit_and_create_pr(
    repo: str,
    repo_root: pathlib.Path,
    branch: str,
    check_for_updates_in_paths: List[str],
    logger: logging.Logger,
    commit_message: str,
    description: str,
):
    git_modified_files = subprocess.check_output(["git", "ls-files", "--modified", "--others"], cwd=repo_root).decode(
        "utf8"
    )

    paths_to_add = [path for path in check_for_updates_in_paths if path in git_modified_files]

    if len(paths_to_add) > 0:
        logger.info("Creating/updating a MR that updates the saved NNS subnet revision")
        cmd = ["git", "add"] + paths_to_add
        logger.info("Running command '%s'", " ".join(cmd))
        subprocess.check_call(cmd, cwd=repo_root)
        cmd = [
            "git",
            "-c",
            "user.name=CI Automation",
            "-c",
            "user.email=infra+github-automation@dfinity.org",
            "commit",
            "-m",
            commit_message,
        ] + paths_to_add
        logger.info("Running command '%s'", " ".join(cmd))
        subprocess.check_call(
            cmd,
            cwd=repo_root,
        )
        subprocess.check_call(["git", "push", "origin", branch, "-f"], cwd=repo_root)

        if not subprocess.check_output(
            ["gh", "pr", "list", "--head", branch, "--repo", repo],
            cwd=repo_root,
        ).decode("utf8"):
            subprocess.check_call(
                [
                    "gh",
                    "pr",
                    "create",
                    "--head",
                    branch,
                    "--repo",
                    repo,
                    "--body",
                    description,
                    "--title",
                    commit_message,
                ],
                cwd=repo_root,
            )


def get_saved_versions(repo_root: pathlib.Path, file_path: pathlib.Path):
    """
    Return a dict with all saved versions.

    Example of the file contents:
    {
        "subnets": {
            "tbd26...": "xxxxxREVISIONxxx"
        },
    }
    The file can also be extended with other data, e.g., canister versions:
    {
        "canisters" {
            "rwlgt-iiaaa-aaaaa-aaaaa-cai": "xxxxxREVISIONxxx"
        }
    }
    """
    full_path = repo_root / file_path
    if full_path.exists():
        with open(full_path, "r", encoding="utf-8") as f:
            return json.load(f)
    else:
        return {}


def update_saved_subnet_version(subnet: str, version: str, repo_root: pathlib.Path, file_path: pathlib.Path):
    """Update the version that we last saw on a particular IC subnet."""
    saved_versions = get_saved_versions(repo_root=repo_root, file_path=file_path)
    subnet_versions = saved_versions.get("subnets", {})
    subnet_versions[subnet] = version
    saved_versions["subnets"] = subnet_versions
    with open(repo_root / SAVED_VERSIONS_SUBNETS_PATH, "w", encoding="utf-8") as f:
        json.dump(saved_versions, f, indent=2)


def get_saved_nns_subnet_version(repo_root: pathlib.Path, file_path: pathlib.Path):
    """Get the last known version running on the NNS subnet."""
    saved_versions = get_saved_versions(repo_root=repo_root, file_path=file_path)
    return saved_versions.get("subnets", {}).get(nns_subnet_id, "")


def get_saved_app_subnet_version(repo_root: pathlib.Path, file_path: pathlib.Path):
    """Get the last known version running on an App subnet."""
    saved_versions = get_saved_versions(repo_root=repo_root, file_path=file_path)
    return saved_versions.get("subnets", {}).get(app_subnet_id, "")


def get_subnet_replica_version(subnet_id: str) -> str:
    req = urllib.request.Request(
        url=f"{PUBLIC_DASHBOARD_API}/api/v3/subnets/{subnet_id}", headers={"user-agent": "python"}
    )

    with urllib.request.urlopen(req, timeout=30) as request:
        replica_versions = json.loads(request.read().decode())["replica_versions"]
        latest_replica_version = sorted(replica_versions, key=lambda x: x["executed_timestamp_seconds"])[-1][
            "replica_version_id"
        ]
        return latest_replica_version


def update_mainnet_revisions_subnets_file(repo_root: pathlib.Path, logger: logging.Logger, file_path: pathlib.Path):
    current_nns_version = get_subnet_replica_version(nns_subnet_id)
    logger.info("Current NNS subnet (%s) revision: %s", nns_subnet_id, current_nns_version)
    current_app_subnet_version = get_subnet_replica_version(app_subnet_id)
    logger.info("Current App subnet (%s) revision: %s", app_subnet_id, current_app_subnet_version)

    update_saved_subnet_version(
        subnet=nns_subnet_id, version=current_nns_version, repo_root=repo_root, file_path=file_path
    )
    update_saved_subnet_version(
        subnet=app_subnet_id, version=current_app_subnet_version, repo_root=repo_root, file_path=file_path
    )


def update_mainnet_revisions_canisters_file(repo_root: pathlib.Path, logger: logging.Logger):
    cmd = [
        "bazel",
        "run",
        "--config=ci",
    ]
    if os.environ.get("CI"):
        cmd.append("--repository_cache=/cache/bazel")
    cmd.append("//rs/nervous_system/tools/sync-with-released-nervous-system-wasms")

    logger.info("Running command: %s", " ".join(cmd))
    subprocess.check_call(cmd, cwd=repo_root)


def get_logger(level) -> logging.Logger:
    FORMAT = "[%(asctime)s] %(levelname)-8s %(message)s"
    logging.basicConfig(format=FORMAT, level=level)
    return logging.getLogger("logger")


def get_repo_root() -> pathlib.Path:
    return pathlib.Path(
        subprocess.run(["git", "rev-parse", "--show-toplevel"], text=True, stdout=subprocess.PIPE).stdout.strip()
    )


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="GitCiHelper", description="Tool for automating git operations for CI")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")

    subparsers = parser.add_subparsers(title="subcommands", description="valid commands", help="sub-command help")

    parser_subnets = subparsers.add_parser("subnets", help=f"Update {SAVED_VERSIONS_SUBNETS_PATH} file")
    parser_subnets.set_defaults(command=Command.SUBNETS)

    parser_canisters = subparsers.add_parser("canisters", help=f"Update {SAVED_VERSIONS_CANISTERS_PATH} file")
    parser_canisters.set_defaults(command=Command.CANISTERS)

    return parser


def main():
    """Do the main work."""

    parser = get_parser()
    args = parser.parse_args()
    logger = get_logger(logging.DEBUG if args.verbose else logging.INFO)

    repo = "dfinity/ic"
    repo_root = get_repo_root()
    main_branch = "master"

    if not hasattr(args, "command"):
        parser.print_help()
        exit(1)

    pr_description = """{description}

This PR is created automatically using [`mainnet_revisions.py`](https://github.com/dfinity/ic/blob/master/ci/src/mainnet_revisions/mainnet_revisions.py)
    """

    if args.command == Command.SUBNETS:
        branch = "ic-mainnet-revisions"
        sync_main_branch_and_checkout_branch(repo_root, main_branch, branch, logger)
        update_mainnet_revisions_subnets_file(repo_root, logger, pathlib.Path(SAVED_VERSIONS_SUBNETS_PATH))
        commit_and_create_pr(
            repo,
            repo_root,
            branch,
            [SAVED_VERSIONS_SUBNETS_PATH],
            logger,
            "chore: Update Mainnet IC revisions subnets file",
            pr_description.format(
                description="Update mainnet revisions file to include the latest version released on the mainnet."
            ),
        )
    elif args.command == Command.CANISTERS:
        branch = "ic-nervous-system-wasms"
        sync_main_branch_and_checkout_branch(repo_root, main_branch, branch, logger)
        update_mainnet_revisions_canisters_file(repo_root, logger)
        commit_and_create_pr(
            repo,
            repo_root,
            branch,
            [SAVED_VERSIONS_CANISTERS_PATH],
            logger,
            "chore: Update Mainnet IC revisions canisters file",
            pr_description.format(
                description="Update mainnet system canisters revisions file to include the latest WASM version released on the mainnet."
            ),
        )
    else:
        raise Exception("This shouldn't happen")


if __name__ == "__main__":
    main()
