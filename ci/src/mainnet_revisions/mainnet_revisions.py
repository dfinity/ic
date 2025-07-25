#!/usr/bin/env python3
import argparse
import json
import logging
import pathlib
import subprocess
import urllib.request
from enum import Enum
from typing import List

MAINNET_ICOS_REVISIONS_FILE = "mainnet-icos-revisions.json"
nns_subnet_id = "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
app_subnet_id = "io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe"
PUBLIC_DASHBOARD_API = "https://ic-api.internetcomputer.org"
SAVED_VERSIONS_CANISTERS_FILE = "mainnet-canister-revisions.json"


class Command(Enum):
    ICOS = 1
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
        # The branch already exists, update the existing PR
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
    enable_auto_merge: bool = False,
):
    git_modified_files = subprocess.check_output(["git", "ls-files", "--modified", "--others"], cwd=repo_root).decode(
        "utf8"
    )

    paths_to_add = [path for path in check_for_updates_in_paths if path in git_modified_files]

    if len(paths_to_add) > 0:
        logger.info("Creating/updating a PR that updates the saved icos revisions")
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
                    "--label",
                    "CI_ALL_BAZEL_TARGETS",
                ],
                cwd=repo_root,
            )
        pr_number = subprocess.check_output(
            ["gh", "pr", "view", "--json", "number", "-q", ".number"], cwd=repo_root, text=True
        ).strip()
        if enable_auto_merge:
            subprocess.check_call(["gh", "pr", "merge", pr_number, "--auto"], cwd=repo_root)


def get_subnet_replica_version_info(subnet_id: str) -> (str, str):
    """Use the dashboard to pull the latest version info for the given subnet."""
    req = urllib.request.Request(
        url=f"{PUBLIC_DASHBOARD_API}/api/v3/subnets/{subnet_id}", headers={"user-agent": "python"}
    )

    with urllib.request.urlopen(req, timeout=30) as request:
        replica_versions = json.loads(request.read().decode())["replica_versions"]
        latest_replica_version = sorted(replica_versions, key=lambda x: x["executed_timestamp_seconds"])[-1][
            "replica_version_id"
        ]

    req = urllib.request.Request(
        url=f"{PUBLIC_DASHBOARD_API}/api/v3/subnet-replica-versions/{latest_replica_version}",
        headers={"user-agent": "python"},
    )

    with urllib.request.urlopen(req, timeout=30) as request:
        proposal_id = json.loads(request.read().decode())["proposal_id"]

    req = urllib.request.Request(
        url=f"{PUBLIC_DASHBOARD_API}/api/v3/proposals/{proposal_id}", headers={"user-agent": "python"}
    )

    with urllib.request.urlopen(req, timeout=30) as request:
        proposal = json.loads(request.read().decode())
        version = proposal["payload"]["replica_version_to_elect"]
        hash = proposal["payload"]["release_package_sha256_hex"]

        return (version, hash)


def get_latest_hostos_version_info() -> (str, str):
    """Use the dashboard to pull the version info for the most recent HostOS version."""
    req = urllib.request.Request(
        url=f"{PUBLIC_DASHBOARD_API}/api/v3/proposals?include_status=EXECUTED&include_action_nns_function=ReviseElectedHostosVersions",
        headers={"user-agent": "python"},
    )

    with urllib.request.urlopen(req, timeout=30) as request:
        # Hunt for the latest ReviseElectedHostosVersions proposal that added a version
        proposals = json.loads(request.read().decode())["data"]
        sorted_proposals = sorted(proposals, key=lambda x: x["executed_timestamp_seconds"], reverse=True)
        latest_elect_proposal = next(v for v in sorted_proposals if v["payload"]["hostos_version_to_elect"])

        version = latest_elect_proposal["payload"]["hostos_version_to_elect"]
        hash = latest_elect_proposal["payload"]["release_package_sha256_hex"]

        return (version, hash)


def update_saved_subnet_revision(repo_root: pathlib.Path, logger: logging.Logger, file_path: pathlib.Path, subnet: str):
    """Fetch and update the saved subnet version and hash."""
    (version, hash) = get_subnet_replica_version_info(nns_subnet_id)
    logger.info("Current subnet (%s) revision: %s hash: %s", subnet, version, hash)

    full_path = repo_root / file_path
    # Check if the subnet revision is already up-to-date.
    with open(full_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    guestos_info = data.get("guestos", {})
    subnet_infos = guestos_info.get("subnets", {})
    subnet_info = subnet_infos.get(subnet, {})
    existing_version = subnet_info.get("version", "")
    if existing_version == version:
        logger.info("Subnet revision already updated to version %s. Skipping update.", version)
        return

    data["guestos"]["subnets"][subnet] = {"version": version, "update_img_hash": hash}
    with open(full_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    logger.info("Updated subnet %s revision to version %s with image hash %s", subnet, version, hash)


def update_saved_hostos_revision(repo_root: pathlib.Path, logger: logging.Logger, file_path: pathlib.Path):
    """Fetch and update the saved HostOS version and hash."""
    (version, hash) = get_latest_hostos_version_info()
    logger.info("Latest HostOS revision: %s hash: %s", version, hash)

    full_path = repo_root / file_path
    # Check if the hostos revision is already up-to-date.
    with open(full_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    hostos_info = data.get("hostos", {})
    latest_release = hostos_info.get("latest_release", {})
    existing_version = latest_release.get("version", "")
    if existing_version == version:
        logger.info("Hostos revision already updated to version %s. Skipping update.", version)
        return

    data["hostos"] = {"latest_release": {"version": version, "update_img_hash": hash}}
    with open(full_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    logger.info("Updated hostos revision to version %s with image hash %s", version, hash)


def update_mainnet_icos_revisions_file(repo_root: pathlib.Path, logger: logging.Logger, file_path: pathlib.Path):
    update_saved_subnet_revision(repo_root, logger, file_path, nns_subnet_id)
    update_saved_subnet_revision(repo_root, logger, file_path, app_subnet_id)

    update_saved_hostos_revision(repo_root, logger, file_path)


def update_mainnet_revisions_canisters_file(repo_root: pathlib.Path, logger: logging.Logger):
    cmd = [
        "bazel",
        "run",
    ]
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
    parser.add_argument("--dry-run", "-n", action="store_true", help="Do not commit changes")

    subparsers = parser.add_subparsers(title="subcommands", description="valid commands", help="sub-command help")

    parser_icos = subparsers.add_parser("icos", help=f"Update {MAINNET_ICOS_REVISIONS_FILE} file")
    parser_icos.set_defaults(command=Command.ICOS)

    parser_canisters = subparsers.add_parser("canisters", help=f"Update {SAVED_VERSIONS_CANISTERS_FILE} file")
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

    if args.dry_run:
        logger.info("Dry run, will not change git state.")

    if args.command == Command.ICOS:
        if not args.dry_run:
            branch = "ic-mainnet-revisions"
            sync_main_branch_and_checkout_branch(repo_root, main_branch, branch, logger)
        update_mainnet_icos_revisions_file(repo_root, logger, pathlib.Path(MAINNET_ICOS_REVISIONS_FILE))
        if not args.dry_run:
            commit_and_create_pr(
                repo,
                repo_root,
                branch,
                [MAINNET_ICOS_REVISIONS_FILE],
                logger,
                "chore: Update Mainnet ICOS revisions file",
                pr_description.format(
                    description="Update mainnet revisions file to include the latest version released on the mainnet."
                ),
                enable_auto_merge=True,
            )
    elif args.command == Command.CANISTERS:
        if not args.dry_run:
            branch = "ic-nervous-system-wasms"
            sync_main_branch_and_checkout_branch(repo_root, main_branch, branch, logger)
        update_mainnet_revisions_canisters_file(repo_root, logger)
        if not args.dry_run:
            commit_and_create_pr(
                repo,
                repo_root,
                branch,
                [SAVED_VERSIONS_CANISTERS_FILE],
                logger,
                "chore: Update Mainnet IC revisions canisters file",
                pr_description.format(
                    description="Update mainnet system canisters revisions file to include the latest WASM version released on the mainnet."
                ),
                enable_auto_merge=True,
            )
    else:
        raise Exception("This shouldn't happen")


if __name__ == "__main__":
    main()
