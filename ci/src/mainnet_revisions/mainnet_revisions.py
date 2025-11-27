#!/usr/bin/env python3
import argparse
import hashlib
import json
import logging
import pathlib
import re
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass
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


@dataclass
class VersionInfo:
    version: str
    hash: str
    dev_hash: str
    launch_measurements: dict
    dev_measurements: dict


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
                ],
                cwd=repo_root,
            )
        pr_number = subprocess.check_output(
            ["gh", "pr", "view", "--json", "number", "-q", ".number"], cwd=repo_root, text=True
        ).strip()
        if enable_auto_merge:
            subprocess.check_call(["gh", "pr", "merge", pr_number, "--auto"], cwd=repo_root)


def get_subnet_replica_version_info(subnet_id: str) -> VersionInfo:
    """Use the dashboard to pull the latest version info for the given subnet."""
    req = urllib.request.Request(
        url=f"{PUBLIC_DASHBOARD_API}/api/v3/subnets/{subnet_id}", headers={"user-agent": "python"}
    )
    with urllib.request.urlopen(req, timeout=30) as request:
        response = json.loads(request.read().decode())

    replica_versions = response["replica_versions"]
    latest_replica_version = sorted(replica_versions, key=lambda x: x["executed_timestamp_seconds"])[-1][
        "replica_version_id"
    ]

    return get_replica_version_info(latest_replica_version)


def get_replica_version_info(replica_version: str) -> VersionInfo:
    req = urllib.request.Request(
        url=f"{PUBLIC_DASHBOARD_API}/api/v3/subnet-replica-versions/{replica_version}",
        headers={"user-agent": "python"},
    )
    with urllib.request.urlopen(req, timeout=30) as request:
        response = json.loads(request.read().decode())

    proposal_id = response["proposal_id"]

    req = urllib.request.Request(
        url=f"{PUBLIC_DASHBOARD_API}/api/v3/proposals/{proposal_id}", headers={"user-agent": "python"}
    )
    with urllib.request.urlopen(req, timeout=30) as request:
        response = json.loads(request.read().decode())

    version = response["payload"]["replica_version_to_elect"]
    hash = response["payload"]["release_package_sha256_hex"]
    launch_measurements = response["payload"]["guest_launch_measurements"]

    dev_hash = download_and_hash_file(
        f"https://download.dfinity.systems/ic/{version}/guest-os/update-img-dev/update-img.tar.zst"
    )

    dev_measurements = download_and_read_file(
        f"https://download.dfinity.systems/ic/{version}/guest-os/update-img-dev/launch-measurements.json"
    )

    return VersionInfo(version, hash, dev_hash, launch_measurements, dev_measurements)


def get_latest_replica_version_info() -> VersionInfo:
    """Use the dashboard to pull the version info for the most recent GuestOS version."""
    req = urllib.request.Request(
        url=f"{PUBLIC_DASHBOARD_API}/api/v3/proposals?include_status=EXECUTED&include_action_nns_function=ReviseElectedGuestosVersions",
        headers={"user-agent": "python"},
    )
    with urllib.request.urlopen(req, timeout=30) as request:
        response = json.loads(request.read().decode())

    # Hunt for the latest ReviseElectedGuestosVersions proposal that added a version
    proposals = response["data"]
    filtered_proposals = filter(lambda x: "-base" in x["summary"].partition("\n")[0], proposals)
    sorted_proposals = sorted(filtered_proposals, key=lambda x: x["executed_timestamp_seconds"], reverse=True)
    latest_elect_proposal = next(v for v in sorted_proposals if v["payload"]["replica_version_to_elect"])

    version = latest_elect_proposal["payload"]["replica_version_to_elect"]
    hash = latest_elect_proposal["payload"]["release_package_sha256_hex"]
    launch_measurements = latest_elect_proposal["payload"]["guest_launch_measurements"]

    dev_hash = download_and_hash_file(
        f"https://download.dfinity.systems/ic/{version}/guest-os/update-img-dev/update-img.tar.zst"
    )

    dev_measurements = download_and_read_file(
        f"https://download.dfinity.systems/ic/{version}/guest-os/update-img-dev/launch-measurements.json"
    )

    return VersionInfo(version, hash, dev_hash, launch_measurements, dev_measurements)


def get_latest_hostos_version_info(logger: logging.Logger) -> VersionInfo:
    """Use the dashboard to pull the version info for the most recent HostOS version."""
    req = urllib.request.Request(
        url=f"{PUBLIC_DASHBOARD_API}/api/v3/proposals?include_status=EXECUTED&include_action_nns_function=ReviseElectedHostosVersions",
        headers={"user-agent": "python"},
    )
    with urllib.request.urlopen(req, timeout=30) as request:
        response = json.loads(request.read().decode())

    # Hunt for the latest ReviseElectedHostosVersions proposal that added a version
    proposals = response["data"]
    filtered_proposals = filter(lambda x: "-base" in x["summary"].partition("\n")[0], proposals)
    sorted_proposals = sorted(filtered_proposals, key=lambda x: x["executed_timestamp_seconds"], reverse=True)
    latest_elect_proposal = next(v for v in sorted_proposals if v["payload"]["hostos_version_to_elect"])

    version = latest_elect_proposal["payload"]["hostos_version_to_elect"]
    hash = latest_elect_proposal["payload"]["release_package_sha256_hex"]

    dev_hash = download_and_hash_file(
        f"https://download.dfinity.systems/ic/{version}/host-os/update-img-dev/update-img.tar.zst"
    )

    # Pull the measurements of the GuestOS version from the proposal
    try:
        replica_info = get_replica_version_info(version)
    except:
        logger.info(
            "Unable to find matching GuestOS release. It is expected that HostOS is always released alongside GuestOS."
        )
        raise

    return VersionInfo(version, hash, dev_hash, replica_info.launch_measurements, replica_info.dev_measurements)


def update_saved_subnet_revision(repo_root: pathlib.Path, logger: logging.Logger, file_path: pathlib.Path, subnet: str):
    """Fetch and update the saved subnet version and hash."""
    replica_info = get_subnet_replica_version_info(subnet)
    logger.info("Current subnet (%s) revision: %s hash: %s", subnet, replica_info.version, replica_info.hash)

    full_path = repo_root / file_path
    # Check if the subnet revision is already up-to-date.
    with open(full_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    existing_version = data.get("guestos", {}).get("subnets", {}).get(subnet, {}).get("version", "")
    if existing_version == replica_info.version:
        logger.info("Subnet revision already updated to version %s. Skipping update.", replica_info.version)
        return

    data["guestos"]["subnets"][subnet] = {
        "version": replica_info.version,
        "update_img_hash": replica_info.hash,
        "update_img_hash_dev": replica_info.dev_hash,
        "launch_measurements": replica_info.launch_measurements,
        "launch_measurements_dev": replica_info.dev_measurements,
    }
    with open(full_path, "w", encoding="utf-8") as f:
        contents = collapse_simple_lists(json.dumps(data, indent=2))
        f.write(contents)

    logger.info(
        "Updated subnet %s revision to version %s with image hash %s", subnet, replica_info.version, replica_info.hash
    )


def update_saved_replica_revision(repo_root: pathlib.Path, logger: logging.Logger, file_path: pathlib.Path):
    """Fetch and update the latest replica version and hash."""
    replica_info = get_latest_replica_version_info()
    logger.info("Latest revision: %s hash: %s", replica_info.version, replica_info.hash)

    full_path = repo_root / file_path
    # Check if the latest revision is already up-to-date.
    with open(full_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    existing_version = data.get("guestos", {}).get("latest_release", {}).get("version", "")
    if existing_version == replica_info.version:
        logger.info("Latest revision already updated to version %s. Skipping update.", replica_info.version)
        return

    data["guestos"]["latest_release"] = {
        "version": replica_info.version,
        "update_img_hash": replica_info.hash,
        "update_img_hash_dev": replica_info.dev_hash,
        "launch_measurements": replica_info.launch_measurements,
        "launch_measurements_dev": replica_info.dev_measurements,
    }
    with open(full_path, "w", encoding="utf-8") as f:
        contents = collapse_simple_lists(json.dumps(data, indent=2))
        f.write(contents)

    logger.info("Updated latest revision to version %s with image hash %s", replica_info.version, replica_info.hash)


def update_saved_hostos_revision(repo_root: pathlib.Path, logger: logging.Logger, file_path: pathlib.Path):
    """Fetch and update the saved HostOS version and hash."""
    replica_info = get_latest_hostos_version_info(logger)
    logger.info("Latest HostOS revision: %s hash: %s", replica_info.version, replica_info.hash)

    full_path = repo_root / file_path
    # Check if the hostos revision is already up-to-date.
    with open(full_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    existing_version = data.get("hostos", {}).get("latest_release", {}).get("version", "")
    if existing_version == replica_info.version:
        logger.info("Hostos revision already updated to version %s. Skipping update.", replica_info.version)
        return

    data["hostos"] = {
        "latest_release": {
            "version": replica_info.version,
            "update_img_hash": replica_info.hash,
            "update_img_hash_dev": replica_info.dev_hash,
            "launch_measurements": replica_info.launch_measurements,
            "launch_measurements_dev": replica_info.dev_measurements,
        }
    }

    with open(full_path, "w", encoding="utf-8") as f:
        contents = collapse_simple_lists(json.dumps(data, indent=2))
        f.write(contents)

    logger.info("Updated hostos revision to version %s with image hash %s", replica_info.version, replica_info.hash)


def update_mainnet_icos_revisions_file(repo_root: pathlib.Path, logger: logging.Logger, file_path: pathlib.Path):
    update_saved_replica_revision(repo_root, logger, file_path)
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


def download_and_hash_file(url: str):
    with tempfile.NamedTemporaryFile() as tmp_file:
        urllib.request.urlretrieve(url, tmp_file.name)
        with open(tmp_file.name, "rb") as f:
            return hashlib.file_digest(f, "sha256").hexdigest()


def download_and_read_file(url: str):
    with tempfile.NamedTemporaryFile() as tmp_file:
        urllib.request.urlretrieve(url, tmp_file.name)
        with open(tmp_file.name, "rb") as f:
            return json.loads(f.read().decode())


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


def collapse_simple_lists(contents):
    return re.sub(
        # Capture simple lists (single level, only digits)
        r"\[[\d\s,]*\]",
        # Format onto a single line
        lambda m: " ".join([v.strip() for v in m.group(0).splitlines()]),
        contents,
    )


if __name__ == "__main__":
    main()
