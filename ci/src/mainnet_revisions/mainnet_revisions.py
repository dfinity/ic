#!/usr/bin/env python3
import argparse
import json
import logging
import os
import pathlib
import subprocess
import sys
import tempfile

# from pylib.ic_deployment import IcDeployment

SAVED_VERSIONS_PATH = "testnet/mainnet_revisions.json"
nns_subnet_id = "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
app_subnet_id = "io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe"

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
    ic_admin_path = os.getenv("IC_ADMIN_PATH", "ic-admin")
    output = subprocess.run(
        [ic_admin_path, "--nns-urls", "https://ic0.app" ,"get-subnet", subnet_id],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    if output.returncode != 0:
        print("Failed to get subnet", subnet_id, "Error:", output.stderr)
        exit(1)

    response = json.loads(output.stdout)
    return response["records"][0]["value"]["replica_version_id"]

def get_repo_root() -> str:
    return subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        text=True,
        stdout=subprocess.PIPE
    ).stdout.strip()

def main():
    """Do the main work."""

    class HelpfulParser(argparse.ArgumentParser):
        """An argparse parser that prints usage on any error."""

        def error(self, message):
            sys.stderr.write("error: %s\n" % message)
            self.print_help()
            sys.exit(2)

    parser = HelpfulParser()

    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    current_nns_version = get_subnet_replica_version(nns_subnet_id)
    logging.info("Current NNS subnet (%s) revision: %s", nns_subnet_id, current_nns_version)
    current_app_subnet_version = get_subnet_replica_version(app_subnet_id)
    logging.info("Current App subnet (%s) revision: %s", app_subnet_id, current_app_subnet_version)

    ic_repo_push_token = os.environ.get("PUSH_TO_IC", "ENV_VAR_NOT_SET")
    repo = "dfinity/ic"
    remote_url = f"https://oauth2:{ic_repo_push_token}@github.com/{repo}.git"

    repo_root_dir = tempfile.TemporaryDirectory()
    repo_root = pathlib.Path(repo_root_dir.name)

    if not repo_root.parent.exists():
        os.makedirs(repo_root.parent)

    running_on_ci = os.environ.get("CI") or os.environ.get("GITHUB_ACTION")
    if running_on_ci:
        logging.info("Setting up git credentials for CI")
        subprocess.check_call(["git", "config", "--global", "credential.helper", "store --file ~/.git-credentials"])
        with open(os.path.expanduser("~/.git-credentials"), "w") as f:
            f.write(f"{remote_url}\nusername=oauth2\npassword={ic_repo_push_token}\n")
    else:
        logging.info("Running locally, using default git credentials of the current user")

    # Since its always a new temp directory here its safe to blindly clone
    subprocess.check_call(["git", "clone", "--depth=50", remote_url, repo_root])

    branch = "ic-mainnet-revisions"
    if subprocess.call(["git", "checkout", branch], cwd=repo_root) == 0:
        # The branch already exists, update the existing MR
        logging.info("Found an already existing target branch")
    else:
        subprocess.check_call(["git", "checkout", "-b", branch], cwd=repo_root)
    subprocess.check_call(["git", "reset", "--hard", "origin/master"], cwd=repo_root)

    update_saved_subnet_version(subnet=nns_subnet_id, version=current_nns_version, repo_root=pathlib.Path(repo_root))
    update_saved_subnet_version(
        subnet=app_subnet_id, version=current_app_subnet_version, repo_root=pathlib.Path(repo_root)
    )
    git_modified_files = subprocess.check_output(["git", "ls-files", "--modified", "--others"], cwd=repo_root).decode(
        "utf8"
    )
    if SAVED_VERSIONS_PATH in git_modified_files:
        logging.info("Creating/updating a MR that updates the saved NNS subnet revision")
        subprocess.check_call(["git", "add", SAVED_VERSIONS_PATH], cwd=repo_root)
        if running_on_ci:
            subprocess.check_call(["git", "config", "--global", "user.email", "infra@dfinity.org"], cwd=repo_root)
            subprocess.check_call(["git", "config", "--global", "user.name", "CI Automation"], cwd=repo_root)
        subprocess.check_call(
            ["git", "commit", "-m", "chore: Update Mainnet IC revisions file", SAVED_VERSIONS_PATH],
            cwd=repo_root,
        )
        subprocess.check_call(
            ["git", "push", "origin", branch, "-f"],
            cwd=repo_root
        )
        gh_env = os.environ.copy()
        gh_env["GITHUB_TOKEN"] = ic_repo_push_token

        if not subprocess.check_output(
            ["gh", "pr", "list", "--head", branch, "--repo", repo],
            cwd=repo_root,
            env=gh_env,
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
                    "--fill",
                ],
                cwd=repo_root,
                env=gh_env,
            )

    repo_root_dir.cleanup()

if __name__ == "__main__":
    main()
