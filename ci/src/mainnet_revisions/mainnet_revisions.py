#!/usr/bin/env python3
import argparse
import hashlib
import json
import logging
import os
import pathlib
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import List

MAINNET_ICOS_REVISIONS_FILE = "mainnet-icos-revisions.json"
nns_subnet_id = "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
app_subnet_id = "io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe"
PUBLIC_DASHBOARD_API = "https://ic-api.internetcomputer.org"
SAVED_VERSIONS_CANISTERS_FILE = "mainnet-canister-revisions.json"
CDN_BASE_URL = "https://download.dfinity.systems"

# Every version recorded here is NNS-elected and therefore built by the
# release-testing pipeline, whose attest-uploads job attests everything the build
# uploaded to the CDN. fetch-attested-sums.sh verifies a CDN SHA256SUMS file against
# that attestation, pinned to this signer and to the exact commit.
ATTESTATION_SIGNER_WORKFLOW = "dfinity/ic/.github/workflows/release-testing.yml"
# The signer pin fixes which workflow signed, not from which ref it ran
# (release-testing.yml can be dispatched on arbitrary branches): only accept
# attestations minted from release-qualification branches.
ATTESTATION_SOURCE_REF_REGEX = r"refs/heads/(rc--|hotfix-)[^/]+"
FETCH_ATTESTED_SUMS_SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "fetch-attested-sums.sh"

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
# dashboard API -- which is not authenticated -- and from CDN-served SHA256SUMS files,
# which are verified against the build's provenance attestation whenever the version's
# commit is public (see VersionArtifactSums). The resulting PR is
# auto-approved and auto-merged, so a value that is not exactly a commit id / sha256 /
# plain name must never be written to mainnet-icos-revisions.json in the first place.
# The repository rules reject such values as well (see bazel/mainnet-artifact-refs.bzl,
# which these patterns mirror); failing here means a poisoned upstream value never
# reaches a PR.
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


def check_elected_update_img_hash_against_build(sums: "VersionArtifactSums", variant: str, elected_hash: str):
    """
    The NNS-elected update-image hash and the hash recorded at build time must agree.

    `elected_hash` comes from the proposal payload (via the dashboard API), the
    build-time hash from the (attestation-verified) CDN SHA256SUMS: a mismatch means
    the CDN does not serve what the NNS elected, or the dashboard misreported the
    proposal -- either way nothing must be recorded.
    """
    check_sha256(elected_hash, f"elected {variant} update-img hash")
    built_hash = sums.file_sha256(f"{variant}/update-img", "update-img.tar.zst")
    if built_hash != elected_hash:
        raise Exception(
            f"NNS-elected {variant} update-img hash {elected_hash} for {sums.version} does not match "
            f"the build-time hash {built_hash}"
        )


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
    # True when the hashes above were taken from unverified CDN sums because the
    # version's commit was not public yet (see VersionArtifactSums). Recorded as
    # the "attestation_pending" marker so is_record_up_to_date() re-checks the
    # record every run and forces attestation verification once the commit is
    # disclosed.
    attestation_pending: bool

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
        if not isinstance(self.attestation_pending, bool):
            raise ValueError(f"attestation_pending must be a bool, got {self.attestation_pending!r}")


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


def get_subnet_latest_replica_version(subnet_id: str) -> str:
    """Use the dashboard to pull the latest replica version id for the given subnet."""
    req = urllib.request.Request(
        url=f"{PUBLIC_DASHBOARD_API}/api/v3/subnets/{subnet_id}", headers={"user-agent": "python"}
    )
    with urllib.request.urlopen(req, timeout=30) as request:
        response = json.loads(request.read().decode())

    replica_versions = response["replica_versions"]
    return sorted(replica_versions, key=lambda x: x["executed_timestamp_seconds"])[-1]["replica_version_id"]


def guestos_version_info_from_payload(payload: dict) -> VersionInfo:
    """
    Build the GuestOS VersionInfo from a ReviseElectedGuestosVersions payload.

    The prod update-img hash comes from the proposal; every other hash comes from
    the version's (attestation-verified) CDN SHA256SUMS via VersionArtifactSums,
    and the two sources are cross-checked against each other.
    """
    version = payload["replica_version_to_elect"]
    hash = payload["release_package_sha256_hex"]

    sums = VersionArtifactSums(version)
    check_elected_update_img_hash_against_build(sums, "guest-os", hash)

    launch_measurements = get_launch_measurements(sums, payload["guest_launch_measurements"])
    dev_hash = sums.file_sha256("guest-os/update-img-dev", "update-img.tar.zst")
    dev_measurements = sums.verified_json("guest-os/update-img-dev", "launch-measurements.json")
    setupos_hash = sums.file_sha256("setup-os/disk-img", "disk-img.tar.zst")
    setupos_dev_hash = sums.file_sha256("setup-os/disk-img-dev", "disk-img.tar.zst")
    binaries = get_binary_hashes(sums)

    return VersionInfo(
        version,
        hash,
        dev_hash,
        launch_measurements,
        dev_measurements,
        setupos_hash,
        setupos_dev_hash,
        binaries,
        attestation_pending=sums.attested is False,
    )


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

    return guestos_version_info_from_payload(response["payload"])


def get_latest_elected_guestos_payload() -> dict:
    """Use the dashboard to pull the proposal payload of the most recent GuestOS version."""
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

    return latest_elect_proposal["payload"]


def get_latest_elected_hostos_payload() -> dict:
    """Use the dashboard to pull the proposal payload of the most recent HostOS version."""
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

    return latest_elect_proposal["payload"]


def hostos_version_info_from_payload(payload: dict, logger: logging.Logger) -> VersionInfo:
    """Build the HostOS VersionInfo from a ReviseElectedHostosVersions payload."""
    version = payload["hostos_version_to_elect"]
    hash = payload["release_package_sha256_hex"]

    sums = VersionArtifactSums(version)
    check_elected_update_img_hash_against_build(sums, "host-os", hash)

    dev_hash = sums.file_sha256("host-os/update-img-dev", "update-img.tar.zst")

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
        # The GuestOS info above is collected for the same commit, so a fallback
        # on either side leaves the whole record pending re-verification.
        attestation_pending=sums.attested is False or replica_info.attestation_pending,
    )


def version_record(info: VersionInfo) -> dict:
    """
    The mainnet-icos-revisions.json record for `info`.

    A record built from unverified CDN sums (the version's commit was not public
    yet) carries the "attestation_pending" marker: is_record_up_to_date() then
    keeps re-checking it and forces attestation verification -- rewriting the
    record, without the marker -- once the commit is disclosed.
    """
    record = {
        "version": info.version,
        "update_img_hash": info.hash,
        "update_img_hash_dev": info.dev_hash,
        "setupos_disk_img_hash": info.setupos_hash,
        "setupos_disk_img_hash_dev": info.setupos_dev_hash,
        "binaries": info.binaries,
        "launch_measurements": info.launch_measurements,
        "launch_measurements_dev": info.dev_measurements,
    }
    if info.attestation_pending:
        record["attestation_pending"] = True
    return record


def update_saved_subnet_revision(repo_root: pathlib.Path, logger: logging.Logger, file_path: pathlib.Path, subnet: str):
    """Fetch and update the saved subnet version and hash."""
    version = get_subnet_latest_replica_version(subnet)
    check_commit_id(version, "version")
    logger.info("Current subnet (%s) revision: %s", subnet, version)

    full_path = repo_root / file_path
    # Check if the subnet revision is already up-to-date BEFORE collecting (and
    # verifying) the version's artifact hashes: the check must stay cheap and must
    # keep working for already-recorded versions that predate the attestation
    # rollout.
    with open(full_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    existing = data.get("guestos", {}).get("subnets", {}).get(subnet, {})
    if is_record_up_to_date(existing, version):
        logger.info("Subnet revision already updated to version %s. Skipping update.", version)
        return

    replica_info = get_replica_version_info(version)

    data["guestos"]["subnets"][subnet] = version_record(replica_info)
    with open(full_path, "w", encoding="utf-8") as f:
        contents = collapse_simple_lists(json.dumps(data, indent=2))
        f.write(contents)

    logger.info(
        "Updated subnet %s revision to version %s with image hash %s", subnet, replica_info.version, replica_info.hash
    )


def update_saved_replica_revision(repo_root: pathlib.Path, logger: logging.Logger, file_path: pathlib.Path):
    """Fetch and update the latest replica version and hash."""
    payload = get_latest_elected_guestos_payload()
    version = payload["replica_version_to_elect"]
    check_commit_id(version, "version")
    logger.info("Latest revision: %s", version)

    full_path = repo_root / file_path
    # Check if the latest revision is already up-to-date BEFORE collecting (and
    # verifying) the version's artifact hashes: the check must stay cheap and must
    # keep working for already-recorded versions that predate the attestation
    # rollout.
    with open(full_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    existing = data.get("guestos", {}).get("latest_release", {})
    if is_record_up_to_date(existing, version):
        logger.info("Latest revision already updated to version %s. Skipping update.", version)
        return

    replica_info = guestos_version_info_from_payload(payload)

    data["guestos"]["latest_release"] = version_record(replica_info)
    with open(full_path, "w", encoding="utf-8") as f:
        contents = collapse_simple_lists(json.dumps(data, indent=2))
        f.write(contents)

    logger.info("Updated latest revision to version %s with image hash %s", replica_info.version, replica_info.hash)


def update_saved_hostos_revision(repo_root: pathlib.Path, logger: logging.Logger, file_path: pathlib.Path):
    """Fetch and update the saved HostOS version and hash."""
    payload = get_latest_elected_hostos_payload()
    version = payload["hostos_version_to_elect"]
    check_commit_id(version, "version")
    logger.info("Latest HostOS revision: %s", version)

    full_path = repo_root / file_path
    # Check if the hostos revision is already up-to-date BEFORE collecting (and
    # verifying) the version's artifact hashes: the check must stay cheap and must
    # keep working for already-recorded versions that predate the attestation
    # rollout.
    with open(full_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    existing = data.get("hostos", {}).get("latest_release", {})
    if is_record_up_to_date(existing, version):
        logger.info("Hostos revision already updated to version %s. Skipping update.", version)
        return

    replica_info = hostos_version_info_from_payload(payload, logger)

    data["hostos"] = {"latest_release": version_record(replica_info)}

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


def download_bytes(url: str) -> bytes:
    with tempfile.NamedTemporaryFile() as tmp_file:
        urllib.request.urlretrieve(url, tmp_file.name)
        with open(tmp_file.name, "rb") as f:
            return f.read()


def parse_sha256sums(contents: str) -> dict:
    """Parse SHA256SUMS contents into a mapping from filename to its hex sha256."""
    return {p[1]: p[0] for p in (line.split() for line in contents.splitlines()) if len(p) == 2}


def download_sha256sums(url: str) -> dict:
    """
    Download a SHA256SUMS file and return a mapping from filename to its hex sha256.

    The result restates whatever the CDN serves: only VersionArtifactSums may call
    this, as the fallback for versions whose commit is not public yet.
    """
    return parse_sha256sums(download_bytes(url).decode())


def fetch_attested_sha256sums(version: str, subdir: str) -> dict:
    """
    Verified {filename: hex sha256} for the CDN directory ic/<version>/<subdir>.

    Downloads the directory's SHA256SUMS and verifies it against the
    build-provenance attestation minted by release-testing.yml's attest-uploads job
    for exactly this commit, via ci/scripts/fetch-attested-sums.sh.
    Raises CalledProcessError when no such attestation exists or the file does not
    match it; nothing is parsed before verification succeeds.
    """
    with tempfile.NamedTemporaryFile() as tmp_file:
        subprocess.run(
            [
                str(FETCH_ATTESTED_SUMS_SCRIPT),
                version,
                subdir,
                ATTESTATION_SIGNER_WORKFLOW,
                ATTESTATION_SOURCE_REF_REGEX,
                tmp_file.name,
            ],
            check=True,
        )
        with open(tmp_file.name, "r", encoding="utf-8") as f:
            return parse_sha256sums(f.read())


def commit_is_public(version: str) -> bool:
    """
    Whether `version` is a commit in the public dfinity/ic repository.

    The updater's checkout is shallow, so ask the GitHub API. For a well-formed
    sha that is absent, GET /repos/dfinity/ic/commits/<sha> answers 422 with the
    message "No commit found for SHA" (verified live; NOT 404). Only that exact
    answer counts as "not public": GitHub also uses 422 for other validation
    failures and request throttling, and this answer gates whether unverified
    CDN data may be recorded, so anything else fails closed by raising.
    """
    headers = {"user-agent": "python"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url=f"https://api.github.com/repos/dfinity/ic/commits/{version}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30):
            return True
    except urllib.error.HTTPError as e:
        if e.code == 422 and "No commit found for SHA" in e.read().decode(errors="replace"):
            return False
        raise


class VersionArtifactSums:
    """
    SHA256SUMS access for one version's CDN artifacts.

    For a public commit the SHA256SUMS files MUST verify against the build's
    attestation: a failure aborts the update (no PR is created; the cron retries).
    Versions recorded before the attestation rollout are never re-fetched here:
    is_record_up_to_date() keeps complete records untouched, so this requirement
    only bites for versions whose builds are expected to attest. (Dispatching
    release-testing.yml on an old branch cannot backfill such versions: workflows
    run from the dispatched ref's tree, which predates the attest-uploads job.)

    A version whose commit is NOT public yet (an undisclosed hotfix built
    in ic-private and not attested in this repository) falls back to trusting the
    CDN with a loud warning -- time-bounded until disclosure: the exact elected
    commit is pushed to dfinity/ic as a hotfix-* branch, whose Release Testing run
    re-builds it (rclone --immutable --checksum requires the rebuild to match the
    CDN byte-for-byte) and mints the attestation. The fallback is recorded with
    the "attestation_pending" marker, which makes is_record_up_to_date() treat
    the record as stale as soon as the commit is disclosed, so the next cron run
    re-verifies the hashes against the attestation and drops the marker. That
    fallback is not attacker-selectable within the finding's threat model: CDN
    write access cannot remove a commit from the public repository.
    """

    def __init__(self, version: str):
        check_commit_id(version, "version")
        self.version = version
        self.logger = logging.getLogger("logger")
        # None: undecided; True: attested (required); False: CDN fallback.
        self.attested = None

    def sums(self, subdir: str) -> dict:
        """Verified {filename: hex sha256} for the CDN directory <subdir>."""
        if self.attested is False:
            return download_sha256sums(f"{CDN_BASE_URL}/ic/{self.version}/{subdir}/SHA256SUMS")
        try:
            result = fetch_attested_sha256sums(self.version, subdir)
            self.attested = True
            return result
        except subprocess.CalledProcessError:
            if self.attested:
                # Another directory of the same build verified: this one must too.
                raise
            if commit_is_public(self.version):
                raise Exception(
                    f"No build-provenance attestation verifies ic/{self.version}/{subdir}/SHA256SUMS. "
                    f"Refusing to record CDN-served hashes for the public commit {self.version}; "
                    "backfill the attestation by re-running release-testing.yml on its branch "
                    "(for a hotfix without one: push its elected commit to dfinity/ic as a "
                    "hotfix-* branch first)."
                )
            self.logger.warning(
                "Commit %s is not public (undisclosed security patch?): recording UNVERIFIED "
                "CDN-served hashes for it. Re-verify once the commit is disclosed.",
                self.version,
            )
            self.attested = False
            return download_sha256sums(f"{CDN_BASE_URL}/ic/{self.version}/{subdir}/SHA256SUMS")

    def file_sha256(self, subdir: str, filename: str) -> str:
        """The recorded hex sha256 of ic/<version>/<subdir>/<filename>."""
        sha256 = self.sums(subdir).get(filename)
        if sha256 is None:
            raise Exception(f"No sha256 for {filename} in ic/{self.version}/{subdir}/SHA256SUMS")
        return sha256

    def verified_json(self, subdir: str, filename: str):
        """Download ic/<version>/<subdir>/<filename>, verify its bytes, parse as JSON."""
        expected = self.file_sha256(subdir, filename)
        check_sha256(expected, f"sha256 of {subdir}/{filename}")
        contents = download_bytes(f"{CDN_BASE_URL}/ic/{self.version}/{subdir}/{filename}")
        actual = hashlib.sha256(contents).hexdigest()
        if actual != expected:
            raise Exception(
                f"ic/{self.version}/{subdir}/{filename} does not match its SHA256SUMS entry: "
                f"expected {expected}, got {actual}"
            )
        return json.loads(contents.decode())


def get_binary_hashes(sums: VersionArtifactSums) -> dict:
    """
    Return {binary name: sha256 of <name>.gz} for MAINNET_BINARIES at `sums.version`.

    Read from the (attestation-verified) SHA256SUMS of the very directory that
    //bazel:mainnet-icos-binaries.bzl downloads the binaries from, so the recorded
    hash and the verified download can never refer to different copies.

    Raises if a binary is missing: failing the updater's own PR is much better than
    recording nothing and breaking `bazel build` for everyone once the repository
    rule can no longer find it.
    """
    subdir = "binaries/x86_64-linux"
    binary_sums = sums.sums(subdir)
    missing = [name for name in MAINNET_BINARIES if f"{name}.gz" not in binary_sums]
    if missing:
        raise Exception(f"No sha256 for {', '.join(missing)} in ic/{sums.version}/{subdir}/SHA256SUMS")
    return {name: binary_sums[f"{name}.gz"] for name in MAINNET_BINARIES}


def is_record_up_to_date(existing: dict, version: str) -> bool:
    """
    Whether `existing` is on `version` and already has every field we record.

    A record carrying the "attestation_pending" marker was written from
    unverified CDN sums while its commit was still private (see version_record):
    it stays up to date only while the commit remains private. Once the commit
    is disclosed the record counts as stale, so the caller re-collects the
    hashes -- now under mandatory attestation verification, since
    VersionArtifactSums no longer sees a private commit -- and rewrites the
    record without the marker. Records without the marker (attested, or
    predating the attestation rollout) skip without the extra API call.
    """
    if existing.get("version", "") != version:
        return False
    if not all(f in existing for f in ("setupos_disk_img_hash", "binaries")):
        return False
    if existing.get("attestation_pending"):
        return not commit_is_public(version)
    return True


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


def get_launch_measurements(sums: VersionArtifactSums, payload_measurements):
    # `guest_launch_measurements` can be null in the NNS proposal payload
    # (observed for a version elected via a "Security patch update" proposal).
    # In that case, fall back to the measurements published on the CDN alongside
    # the prod update image, which are already in the byte-list format used in
    # this file (unlike the hex format in the proposal payload).
    if payload_measurements is None:
        return sums.verified_json("guest-os/update-img", "launch-measurements.json")
    return decode_measurements(payload_measurements)


if __name__ == "__main__":
    main()
