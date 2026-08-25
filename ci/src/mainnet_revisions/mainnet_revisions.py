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

# Release binaries (published on the CDN under `.../binaries/x86_64-linux/` as
# `<name>.gz`) whose sha256 we record for every mainnet revision. They are exposed
# to Bazel by //bazel:mainnet-icos-binaries.bzl and consumed by system-tests that
# have to run a binary built at a mainnet version.
# Keep sorted; this determines the key order in the generated JSON.
MAINNET_BINARIES = [
    "canister_sandbox",
    "compiler_sandbox",
    "ic-replay",
    "replicated-state-test",
    "sandbox_launcher",
    "state-layout-test",
    "types-test",
]


# The fields below end up interpolated into download URLs, into the names of
# downloaded files and (for the binary names) verbatim into a generated BUILD file by
# //bazel:mainnet-icos-{images,binaries,versions}.bzl. They are read from the public
# dashboard API and from CDN-served SHA256SUMS files -- neither of which is
# authenticated -- and the resulting PR is auto-approved and auto-merged, so a value
# that is not exactly a commit id / sha256 / plain name must never be written to
# mainnet-icos-revisions.json in the first place. The repository rules reject such
# values as well (see bazel/mainnet-artifact-refs.bzl, which these patterns mirror);
# failing here means a poisoned upstream value never reaches a PR.
COMMIT_ID_PATTERN = re.compile(r"\A[0-9a-f]{40}\Z")
SHA256_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")
ARTIFACT_NAME_PATTERN = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def check_commit_id(value, what: str):
    if not isinstance(value, str) or not COMMIT_ID_PATTERN.match(value):
        raise ValueError(f"{what} must be a 40-character lowercase hex git commit id, got {value!r}")


def check_sha256(value, what: str):
    # The empty string is not merely malformed: repository_ctx.download reads it as
    # "do not verify this download".
    if not isinstance(value, str) or not SHA256_PATTERN.match(value):
        raise ValueError(f"{what} must be a 64-character lowercase hex sha256, got {value!r}")


def check_artifact_name(value, what: str):
    if not isinstance(value, str) or not ARTIFACT_NAME_PATTERN.match(value) or ".." in value:
        raise ValueError(f"{what} must only contain [A-Za-z0-9._-] and no '..', got {value!r}")


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
    # SHA256 of the setup-os disk-img.tar.zst (prod and dev channels). Unlike
    # `hash` (the NNS-elected update image), the setup-os image is not elected
    # via the NNS, so this is read from the CDN SHA256SUMS file.
    setupos_hash: str
    setupos_dev_hash: str
    # SHA256 of each of MAINNET_BINARIES as published (gzipped) on the CDN under
    # `binaries/x86_64-linux/`, read from that directory's SHA256SUMS. Consumed by
    # //bazel:mainnet-icos-binaries.bzl.
    binaries: dict

    def __post_init__(self):
        """
        Rejects values that must never reach mainnet-icos-revisions.json.

        Every path that records a version constructs a VersionInfo, so this is the
        single choke point between the unauthenticated upstreams and the JSON file.
        `launch_measurements` is deliberately not checked here: it is arbitrary JSON
        by design and is not interpolated into a URL or a file name.
        """
        check_commit_id(self.version, "version")
        for field in ("hash", "dev_hash", "setupos_hash", "setupos_dev_hash"):
            check_sha256(getattr(self, field), field)
        if not isinstance(self.binaries, dict):
            raise ValueError(f"binaries must be a dict, got {self.binaries!r}")
        for name, digest in self.binaries.items():
            check_artifact_name(name, "binaries key")
            check_sha256(digest, f"binaries[{name!r}]")


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
    launch_measurements = get_launch_measurements(version, response["payload"]["guest_launch_measurements"])

    dev_hash = download_and_hash_file(
        f"https://download.dfinity.systems/ic/{version}/guest-os/update-img-dev/update-img.tar.zst"
    )

    dev_measurements = download_and_read_file(
        f"https://download.dfinity.systems/ic/{version}/guest-os/update-img-dev/launch-measurements.json"
    )

    setupos_base = f"https://download.dfinity.systems/ic/{version}/setup-os"
    setupos_hash = download_and_read_sha256sums(f"{setupos_base}/disk-img/SHA256SUMS", "disk-img.tar.zst")
    setupos_dev_hash = download_and_read_sha256sums(f"{setupos_base}/disk-img-dev/SHA256SUMS", "disk-img.tar.zst")

    binaries = get_binary_hashes(version)

    return VersionInfo(
        version,
        hash,
        dev_hash,
        launch_measurements,
        dev_measurements,
        setupos_hash,
        setupos_dev_hash,
        binaries,
    )


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
    launch_measurements = get_launch_measurements(
        version, latest_elect_proposal["payload"]["guest_launch_measurements"]
    )

    dev_hash = download_and_hash_file(
        f"https://download.dfinity.systems/ic/{version}/guest-os/update-img-dev/update-img.tar.zst"
    )

    dev_measurements = download_and_read_file(
        f"https://download.dfinity.systems/ic/{version}/guest-os/update-img-dev/launch-measurements.json"
    )

    setupos_base = f"https://download.dfinity.systems/ic/{version}/setup-os"
    setupos_hash = download_and_read_sha256sums(f"{setupos_base}/disk-img/SHA256SUMS", "disk-img.tar.zst")
    setupos_dev_hash = download_and_read_sha256sums(f"{setupos_base}/disk-img-dev/SHA256SUMS", "disk-img.tar.zst")

    binaries = get_binary_hashes(version)

    return VersionInfo(
        version,
        hash,
        dev_hash,
        launch_measurements,
        dev_measurements,
        setupos_hash,
        setupos_dev_hash,
        binaries,
    )


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

    return VersionInfo(
        version,
        hash,
        dev_hash,
        replica_info.launch_measurements,
        replica_info.dev_measurements,
        replica_info.setupos_hash,
        replica_info.setupos_dev_hash,
        replica_info.binaries,
    )


def update_saved_subnet_revision(repo_root: pathlib.Path, logger: logging.Logger, file_path: pathlib.Path, subnet: str):
    """Fetch and update the saved subnet version and hash."""
    replica_info = get_subnet_replica_version_info(subnet)
    logger.info("Current subnet (%s) revision: %s hash: %s", subnet, replica_info.version, replica_info.hash)

    full_path = repo_root / file_path
    # Check if the subnet revision is already up-to-date.
    with open(full_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    existing = data.get("guestos", {}).get("subnets", {}).get(subnet, {})
    if is_record_up_to_date(existing, replica_info.version):
        logger.info("Subnet revision already updated to version %s. Skipping update.", replica_info.version)
        return

    data["guestos"]["subnets"][subnet] = {
        "version": replica_info.version,
        "update_img_hash": replica_info.hash,
        "update_img_hash_dev": replica_info.dev_hash,
        "setupos_disk_img_hash": replica_info.setupos_hash,
        "setupos_disk_img_hash_dev": replica_info.setupos_dev_hash,
        "binaries": replica_info.binaries,
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

    existing = data.get("guestos", {}).get("latest_release", {})
    if is_record_up_to_date(existing, replica_info.version):
        logger.info("Latest revision already updated to version %s. Skipping update.", replica_info.version)
        return

    data["guestos"]["latest_release"] = {
        "version": replica_info.version,
        "update_img_hash": replica_info.hash,
        "update_img_hash_dev": replica_info.dev_hash,
        "setupos_disk_img_hash": replica_info.setupos_hash,
        "setupos_disk_img_hash_dev": replica_info.setupos_dev_hash,
        "binaries": replica_info.binaries,
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

    existing = data.get("hostos", {}).get("latest_release", {})
    if is_record_up_to_date(existing, replica_info.version):
        logger.info("Hostos revision already updated to version %s. Skipping update.", replica_info.version)
        return

    data["hostos"] = {
        "latest_release": {
            "version": replica_info.version,
            "update_img_hash": replica_info.hash,
            "update_img_hash_dev": replica_info.dev_hash,
            "setupos_disk_img_hash": replica_info.setupos_hash,
            "setupos_disk_img_hash_dev": replica_info.setupos_dev_hash,
            "binaries": replica_info.binaries,
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


def download_sha256sums(url: str) -> dict:
    """Download a SHA256SUMS file and return a mapping from filename to its hex sha256."""
    with tempfile.NamedTemporaryFile() as tmp_file:
        urllib.request.urlretrieve(url, tmp_file.name)
        with open(tmp_file.name, "r", encoding="utf-8") as f:
            return {p[1]: p[0] for p in (line.split() for line in f) if len(p) == 2}


def download_and_read_sha256sums(url: str, filename: str) -> str:
    """Download a SHA256SUMS file and return the hex sha256 recorded for `filename`."""
    sha256 = download_sha256sums(url).get(filename)
    if sha256 is None:
        raise Exception(f"No sha256 for {filename} in {url}")
    return sha256


def get_binary_hashes(version: str) -> dict:
    """
    Return {binary name: sha256 of <name>.gz} for MAINNET_BINARIES at `version`.

    Read from the SHA256SUMS of the very directory that
    //bazel:mainnet-icos-binaries.bzl downloads the binaries from, so the recorded
    hash and the verified download can never refer to different copies.

    Raises if a binary is missing: failing the updater's own PR is much better than
    recording nothing and breaking `bazel build` for everyone once the repository
    rule can no longer find it.
    """
    url = f"https://download.dfinity.systems/ic/{version}/binaries/x86_64-linux/SHA256SUMS"
    sums = download_sha256sums(url)
    missing = [name for name in MAINNET_BINARIES if f"{name}.gz" not in sums]
    if missing:
        raise Exception(f"No sha256 for {', '.join(missing)} in {url}")
    return {name: sums[f"{name}.gz"] for name in MAINNET_BINARIES}


def is_record_up_to_date(existing: dict, version: str) -> bool:
    """Whether `existing` is on `version` and already has every field we record."""
    return existing.get("version", "") == version and all(f in existing for f in ("setupos_disk_img_hash", "binaries"))


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


# NOTE: We convert the "human" hex format from the dashboard API to the byte
# format that is actually used in the proposal directly.
def decode_measurements(launch_measurements):
    for measurement in launch_measurements["guest_launch_measurements"]:
        measurement["measurement"] = list(bytes.fromhex(measurement["measurement"]))
    return launch_measurements


def get_launch_measurements(version, payload_measurements):
    # `guest_launch_measurements` can be null in the NNS proposal payload
    # (observed for a version elected via a "Security patch update" proposal).
    # In that case, fall back to the measurements published on the CDN alongside
    # the prod update image, which are already in the byte-list format used in
    # this file (unlike the hex format in the proposal payload).
    if payload_measurements is None:
        return download_and_read_file(
            f"https://download.dfinity.systems/ic/{version}/guest-os/update-img/launch-measurements.json"
        )
    return decode_measurements(payload_measurements)


if __name__ == "__main__":
    main()
