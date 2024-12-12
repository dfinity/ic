#!/usr/bin/env python3
import json
import logging
import pathlib
import urllib.request

import git_lib

# from pylib.ic_deployment import IcDeployment

SAVED_VERSIONS_PATH = "testnet/mainnet_revisions.json"
nns_subnet_id = "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
app_subnet_id = "io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe"
PUBLIC_DASHBOARD_API = "https://ic-api.internetcomputer.org"


def get_saved_versions(repo_root: pathlib.Path):
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
    saved_versions_path = repo_root / SAVED_VERSIONS_PATH
    if saved_versions_path.exists():
        with open(saved_versions_path, "r", encoding="utf-8") as f:
            return json.load(f)
    else:
        return {}


def update_saved_subnet_version(subnet: str, version: str, repo_root: pathlib.Path):
    """Update the version that we last saw on a particular IC subnet."""
    saved_versions = get_saved_versions(repo_root=repo_root)
    subnet_versions = saved_versions.get("subnets", {})
    subnet_versions[subnet] = version
    saved_versions["subnets"] = subnet_versions
    with open(repo_root / SAVED_VERSIONS_PATH, "w", encoding="utf-8") as f:
        json.dump(saved_versions, f, indent=2)


def get_saved_nns_subnet_version(repo_root: pathlib.Path):
    """Get the last known version running on the NNS subnet."""
    saved_versions = get_saved_versions(repo_root=repo_root)
    return saved_versions.get("subnets", {}).get(nns_subnet_id, "")


def get_saved_app_subnet_version(repo_root: pathlib.Path):
    """Get the last known version running on an App subnet."""
    saved_versions = get_saved_versions(repo_root=repo_root)
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


def work(repo_root: pathlib.Path, logger: logging.Logger):
    current_nns_version = get_subnet_replica_version(nns_subnet_id)
    logger.info("Current NNS subnet (%s) revision: %s", nns_subnet_id, current_nns_version)
    current_app_subnet_version = get_subnet_replica_version(app_subnet_id)
    logger.info("Current App subnet (%s) revision: %s", app_subnet_id, current_app_subnet_version)

    update_saved_subnet_version(subnet=nns_subnet_id, version=current_nns_version, repo_root=repo_root)
    update_saved_subnet_version(subnet=app_subnet_id, version=current_app_subnet_version, repo_root=repo_root)


def main():
    """Do the main work."""

    parser = git_lib.init_helpful_parser()
    args = parser.parse_args()
    logger = git_lib.get_logger(logging.DEBUG if args.verbose else logging.INFO)

    repo = "dfinity/ic"
    repo_root = git_lib.get_repo_root()
    main_branch = "master"
    branch = "ic-mainnet-revisions"

    git_lib.sync_main_branch_and_checkout_branch(repo_root, main_branch, branch, logger)
    work(repo_root, logger)
    git_lib.commit_and_create_pr(repo, repo_root, branch, [SAVED_VERSIONS_PATH], logger)


if __name__ == "__main__":
    main()
