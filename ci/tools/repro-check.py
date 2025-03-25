#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime
from pathlib import Path

# ------------------------------------------------------------------------------
# COLOR AND LOGGING UTILITIES
# ------------------------------------------------------------------------------
RESET = "\033[0m"
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[0;33m"
BLUE = "\033[0;34m"
PURPLE = "\033[0;35m"

def now_str():
    """Matches the original date +'%Y/%m/%d | %H:%M:%S | %s' output."""
    ts = time.time()
    dt = datetime.fromtimestamp(ts)
    return dt.strftime(f"%Y/%m/%d | %H:%M:%S | {int(ts)}")

def print_red(msg):
    print(f"{RED}{now_str()} {msg}{RESET}", file=sys.stderr)

def print_green(msg):
    print(f"{GREEN}{now_str()} {msg}{RESET}")

def print_yellow(msg):
    print(f"{YELLOW}{now_str()} {msg}{RESET}")

def print_blue(msg):
    print(f"{BLUE}{now_str()} {msg}{RESET}")

def print_purple(msg):
    print(f"{PURPLE}{now_str()} {msg}{RESET}")

def log(msg):
    """Used for normal info logs."""
    print_blue(f"[ℹ️] {msg}")

def log_success(msg):
    """Used when something validated successfully."""
    print_green(f"[✅] {msg}")

def log_warning(msg):
    """Used for warnings (like insufficient memory/disk)."""
    print_yellow(f"[⚠️ Warning] {msg}")

def log_stderr(msg):
    """Used for important error messages."""
    print_red(f"[❌] {msg}")

def log_debug(msg):
    """Debug prints only if $DEBUG is set (any non-empty value)."""
    if os.getenv("DEBUG", ""):
        print_purple(f"[🐞] {msg}")

def fail(msg):
    """Exit the script with an error."""
    print_red(f"[💥] {msg}")
    sys.exit(1)

# ------------------------------------------------------------------------------
# ARGUMENT PARSING
# ------------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "This script builds and diffs the update image between CI and build-ic.\n\n"
            "By default (with no arguments), it:\n"
            " - uses the current directory's HEAD commit\n"
            " - checks all OS images (GuestOS, HostOS, SetupOS)\n"
            " - verifies reproducibility.\n\n"
            "Options:\n"
            " -h, --help      Show this help message.\n"
            " --guestos       Verify only GuestOS images.\n"
            " --hostos        Verify only HostOS images.\n"
            " --setupos       Verify only SetupOS images.\n"
            " -p <proposal>   Proposal ID (for an Elect Replica or HostOS proposal).\n"
            " -c <commit>     Git commit/branch/sha in the IC repo to verify.\n"
            " --clean         Clean up the download cache before running.\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("--guestos", action="store_true",
                        help="Verify only GuestOS images.")
    parser.add_argument("--hostos", action="store_true",
                        help="Verify only HostOS images.")
    parser.add_argument("--setupos", action="store_true",
                        help="Verify only SetupOS images.")
    parser.add_argument("-p", "--proposal-id", type=str, default="",
                        help="Proposal ID to check (for an Elect Replica or HostOS proposal).")
    parser.add_argument("-c", "--commit", type=str, default="",
                        help="Git revision/commit to use from the IC repository.")
    parser.add_argument("--clean", action="store_true",
                        help="Clean up the download cache before running.")
    args = parser.parse_args()

    if not args.guestos and not args.hostos and not args.setupos:
        args.guestos = True
        args.hostos = True
        args.setupos = True

    return args

# ------------------------------------------------------------------------------
# VERIFIER CLASS
# ------------------------------------------------------------------------------
class ReproducibilityVerifier:
    def __init__(self, verify_guestos, verify_hostos, verify_setupos, proposal_id, git_commit, clean):
        self.verify_guestos = verify_guestos
        self.verify_hostos = verify_hostos
        self.verify_setupos = verify_setupos
        self.proposal_id = proposal_id
        self.git_commit = git_commit

        self.git_hash = ""
        self.guestos_proposal = False
        self.hostos_proposal = False
        self.proposal_package_url = ""
        self.proposal_package_sha256_hex = ""

        # Will hold final downloaded or built sha256 sums
        self.ci_package_guestos_sha256_hex = ""
        self.ci_package_hostos_sha256_hex = ""
        self.ci_package_setupos_sha256_hex = ""

        # Ephemeral script directories
        self.tmpdir: Path = Path()
        self.out_dir: Path = Path()
        self.ci_out: Path = Path()
        self.dev_out: Path = Path()
        self.proposal_out: Path = Path()

        # Cache directories
        self.base_cache_dir = Path("/tmp/ic-repro-cache")
        if clean and self.base_cache_dir.is_dir():
            shutil.rmtree(self.base_cache_dir)
        self.cache_for_this_hash: Path = Path()

    # ------------------ Environment Checks ------------------
    def check_architecture(self):
        """Check if x86_64."""
        if platform.machine() == "x86_64":
            log_success("x86_64 architecture detected")
        else:
            fail("Please run this script on x86_64 architecture")

    def check_os_version(self):
        """
        Attempt to parse /etc/os-release or /usr/lib/os-release
        and check if it is Ubuntu >= 22.04.
        """
        release_files = ["/etc/os-release", "/usr/lib/os-release"]
        os_info = {}
        for fpath in release_files:
            path_obj = Path(fpath)
            if path_obj.is_file():
                with path_obj.open("r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if "=" in line:
                            k, v = line.split("=", 1)
                            os_info[k] = v.strip('"')

        # check "NAME" and "VERSION_ID"
        os_name = os_info.get("NAME", "")
        if os_name == "Ubuntu":
            log_success("Ubuntu OS detected")
        else:
            log_warning("Please run this script on Ubuntu OS")

        try:
            version_id = float(os_info.get("VERSION_ID", "0"))
            if version_id >= 22.04:
                log_success("Version ≥22.04 detected")
            else:
                log_warning("Please run this script on Ubuntu version 22.04 or higher")
        except ValueError:
            pass

    def check_memory_at_least_gb(self, required_gb=16):
        """Check for at least 16GB of RAM."""
        meminfo_path = Path("/proc/meminfo")
        try:
            with meminfo_path.open("r") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            mem_kb = int(parts[1])
                            mem_gb = mem_kb // 1024 // 1024
                            if mem_gb < required_gb:
                                log_warning(f"You need at least {required_gb}GB of RAM on this machine")
                            else:
                                log_success(f"{required_gb}GB or more RAM detected")
                        return
            log_warning("Could not detect memory from /proc/meminfo")
        except Exception:
            log_warning("Memory check failed. Could not parse /proc/meminfo")

    def check_disk_at_least_gb(self, required_gb=100):
        """Check for at least 100GB of free disk space."""
        try:
            fs_stat = os.statvfs(".")
            free_bytes = fs_stat.f_bavail * fs_stat.f_frsize
            free_gb = free_bytes / (1024 * 1024 * 1024)
            if free_gb < required_gb:
                log_warning(f"You need at least {required_gb}GB of free disk space on this machine")
            else:
                log_success(f"More than {required_gb}GB of free disk space detected")
        except Exception:
            log_warning("Disk check failed. Could not run statvfs on '.'")

    def check_and_install_dependencies(self):
        dependencies = ["git", "podman"]
        log("Check and install needed dependencies")
        for pkg in dependencies:
            if shutil.which(pkg) is None:
                log(f"Installing missing package: {pkg}")
                try:
                    subprocess.run(["sudo", "apt-get", "install", "-y", pkg], check=True)
                except subprocess.CalledProcessError:
                    fail(f"Failed to install {pkg}. Exiting.")
            else:
                log_success(f"{pkg} is already installed")

    def check_git_repo(self):
        """Check that we are inside a Git repo."""
        log_debug("Check we are inside a Git repository")
        try:
            cmd = ["git", "rev-parse", "--is-inside-work-tree"]
            inside = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
            if inside != "true":
                fail("Please run this script inside of a git repository")
            log_debug("Inside git repository")
        except subprocess.CalledProcessError:
            fail("Please run this script inside of a git repository")

    def check_ic_repo(self):
        """
        Check that the remote matches 'ic' as in the original script:
          if [[ "$git_remote" == */ic* ]]; then ...
        """
        log_debug("Check the repository is an IC repository")
        try:
            cmd = ["git", "config", "--get", "remote.origin.url"]
            git_remote = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
            if "/ic" not in git_remote:
                fail("When not specifying any option please run this script inside an IC git repository")
            log_debug("Inside IC repository")
        except subprocess.CalledProcessError:
            fail("When not specifying any option please run this script inside an IC git repository")

    def check_environment(self):
        """Run all environment checks in the correct order."""
        self.check_architecture()
        self.check_os_version()
        self.check_memory_at_least_gb(16)
        self.check_disk_at_least_gb(100)
        self.check_and_install_dependencies()

    # ------------------ JSON & Hashing Helpers ------------------
    @staticmethod
    def compute_sha256(file_path: Path) -> str:
        sha = hashlib.sha256()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha.update(chunk)
        return sha.hexdigest()

    @staticmethod
    def fetch_url_to_file(url: str, dest_path: Path):
        log_debug(f"Downloading {url} to {dest_path}")
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            urllib.request.urlretrieve(url, str(dest_path))
        except Exception as e:
            fail(f"Could not download {url} -> {dest_path}. Error: {e}")

    @staticmethod
    def extract_field_json(data, field_spec: str) -> str:
        """
        Minimal replicate of 'jq --raw-output ".payload.release_package_urls[0]"' etc.
        'field_spec' is a dotted path with optional [index].
        Example: ".payload.release_package_urls[0]"
        """
        if not field_spec.startswith("."):
            fail(f"Invalid JSON path: {field_spec}")
        field_spec = field_spec[1:]  # remove leading dot

        obj = data
        parts = field_spec.split(".")
        for p in parts:
            if "[" in p and "]" in p:
                bracket_index = p.index("[")
                key = p[:bracket_index]
                idx_str = p[bracket_index+1 : p.index("]")]
                idx = int(idx_str)
                obj = obj[key][idx]
            else:
                if p:
                    obj = obj[p]
        if obj is None:
            fail(f"Field {field_spec} is null in the JSON data.")
        return str(obj)

    @staticmethod
    def verify_sha256_against_sums(sums_file: Path, base_dir: Path, filename: str, expected_git_hash: str) -> str:
        """
        Parse the sums_file (SHA256SUMS) line by line, looking for lines in the format:
              <hash>  [*]filename
        Then, compute the hash of 'filename' locally and compare.
        If there's a mismatch, fail.
        Returns the hash from the sums file if it passes validation.
        """
        target_path = base_dir / filename
        with sums_file.open("r", encoding="utf-8") as f:
            lines = f.read().splitlines()

        found_line = None
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                file_part = parts[1].lstrip('*')
                if file_part == filename:
                    found_line = line
                    break

        if not found_line:
            log(f"{sums_file} contents:\n{''.join(lines)}")
            fail(f"Couldn't find {filename} in {sums_file}")

        listed_hash = found_line.split()[0]
        local_hash = ReproducibilityVerifier.compute_sha256(target_path)
        if local_hash != listed_hash:
            fail(
                f"The hash for {filename} in {base_dir} doesn't match the published artifact "
                f"for git hash: {expected_git_hash}\n"
                f"Local: {local_hash}\n"
                f"Published: {listed_hash}"
            )
        return listed_hash

    @staticmethod
    def compare_hashes(local_hash_value: str, ci_hash_value: str, os_type: str):
        if local_hash_value != ci_hash_value:
            log_stderr(
                f"Error! The sha256 sum from the proposal/CDN does not match the one we just built for {os_type}.\n"
                f"\tThe sha256 sum we just built:\t\t{local_hash_value}\n"
                f"\tThe sha256 sum from the CDN:\t\t{ci_hash_value}."
            )
        else:
            log_success(f"Verification successful for {os_type}!")
            log_success(
                f"The shasum for {os_type} from the artifact built locally and the one "
                f"fetched from the proposal/CDN match:\n"
                f"\t\tLocal = {local_hash_value}\n"
                f"\t\tCDN   = {ci_hash_value}\n"
            )

    # ------------------ Cache Management ------------------
    def init_cache(self):
        """
        Ensure /tmp/ic-repro-cache exists. Keep only the two newest subdirectories (by mtime).
        Then create or reuse /tmp/ic-repro-cache/<git_hash> for this run.
        """
        self.base_cache_dir.mkdir(parents=True, exist_ok=True)
        # Keep only the two newest
        self.trim_old_caches(keep=2)

        # Create or reuse the directory for the current git_hash
        self.cache_for_this_hash = self.base_cache_dir / self.git_hash
        if not self.cache_for_this_hash.exists():
            self.cache_for_this_hash.mkdir(parents=True)
        # Update mtime so it's recognized as "new"
        self.cache_for_this_hash.touch()

    def trim_old_caches(self, keep=2):
        """
        Keep only the `keep` newest subdirectories in /tmp/ic-repro-cache, based on mtime.
        Delete older ones.
        """
        if not self.base_cache_dir.is_dir():
            return

        # List subdirs
        entries = []
        for sub in self.base_cache_dir.iterdir():
            if sub.is_dir():
                entries.append(sub)

        # Sort by last modification time descending
        entries.sort(key=lambda p: p.stat().st_mtime, reverse=True)

        # Keep the first `keep`, delete the rest
        for older in entries[keep:]:
            log_debug(f"Removing old cache: {older}")
            shutil.rmtree(older, ignore_errors=True)

    def cached_download(self, url: str, cache_subdir: Path, target_file: Path):
        """
        Download the file from 'url' to the cache location:
          /tmp/ic-repro-cache/<git_hash>/<cache_subdir>/<filename>
        Then hard-link from the cache to 'target_file'.

        Steps:
          1) Derive the final path in the local cache based on `cache_subdir` + target_file.name.
          2) If the cache file doesn't exist (or is empty), download it.
          3) Hard-link from the cache file to the requested `target_file`.
        """
        dest_dir = self.cache_for_this_hash / cache_subdir
        dest_dir.mkdir(parents=True, exist_ok=True)

        cache_file = dest_dir / target_file.name
        # If it's already in the cache and non-empty, skip downloading
        if not (cache_file.exists() and cache_file.stat().st_size > 0):
            log_debug(f"Cache miss, downloading: {url}")
            self.fetch_url_to_file(url, cache_file)
        else:
            log_debug(f"File already cached, skipping download: {url}")

        # Hard-link into place
        target_file.parent.mkdir(parents=True, exist_ok=True)
        if target_file.exists():
            target_file.unlink()
        os.link(cache_file, target_file)

    # ------------------ Core Logic ------------------
    def process_proposal(self):
        """If we have a proposal, fetch proposal JSON, parse fields, set self.git_hash."""
        if not self.proposal_id:
            return

        proposal_json_path = Path("proposal-body.json")
        proposal_url = f"https://ic-api.internetcomputer.org/api/v3/proposals/{self.proposal_id}"
        log_debug(f"Fetching proposal {proposal_url}")

        try:
            with urllib.request.urlopen(proposal_url) as resp:
                if resp.status < 200 or resp.status >= 300:
                    fail(f"Could not fetch proposal {self.proposal_id}, HTTP code {resp.status}")
                data = resp.read()
            proposal_json_path.write_bytes(data)
        except Exception as e:
            fail(f"Could not fetch {self.proposal_id}. Error: {e}")

        proposal_data = json.loads(proposal_json_path.read_text(encoding="utf-8"))
        self.proposal_package_url = self.extract_field_json(proposal_data, ".payload.release_package_urls[0]")
        self.proposal_package_sha256_hex = self.extract_field_json(proposal_data, ".payload.release_package_sha256_hex")

        # Check if it's a guestos or hostos proposal
        prop_str = json.dumps(proposal_data)
        if "replica_version_to_elect" in prop_str:
            self.guestos_proposal = True
            self.git_hash = self.extract_field_json(proposal_data, ".payload.replica_version_to_elect")
        elif "hostos_version_to_elect" in prop_str:
            self.hostos_proposal = True
            self.git_hash = self.extract_field_json(proposal_data, ".payload.hostos_version_to_elect")
        else:
            fail(f"Proposal #{self.proposal_id} is missing replica_version_to_elect or hostos_version_to_elect")

    def decide_git_hash(self):
        """If we have a proposal, it's set. Otherwise we check self.git_commit or local HEAD."""
        if self.proposal_id:
            return
        if self.git_commit:
            self.git_hash = self.git_commit
        else:
            self.check_git_repo()
            self.git_hash = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()

    def prepare_directories(self):
        """Create ephemeral directories for the script's normal usage."""
        debug_mode = bool(os.getenv("DEBUG", ""))
        if debug_mode:
            tmpdir_str = tempfile.mkdtemp(prefix="verify_script_")
            log_debug("DEBUG mode, not automatically removing the tempdir.")
        else:
            tmpdir_obj = tempfile.TemporaryDirectory(prefix="verify_script_")
            tmpdir_str = tmpdir_obj.name

        self.tmpdir = Path(tmpdir_str)
        log(f"Using temporary directory: {self.tmpdir}")

        self.out_dir = self.tmpdir / "disk-images" / self.git_hash
        self.ci_out = self.out_dir / "ci-img"
        self.dev_out = self.out_dir / "dev-img"
        self.proposal_out = self.out_dir / "proposal-img"

        # Create subdirectories
        for path in [
            self.ci_out / "guestos",
            self.ci_out / "hostos",
            self.ci_out / "setupos",
            self.dev_out / "guestos",
            self.dev_out / "hostos",
            self.dev_out / "setupos",
            self.proposal_out
        ]:
            path.mkdir(parents=True, exist_ok=True)

    def verify_proposal_artifacts(self):
        """
        If there's a proposal, confirm:
        - the artifact's URL matches the expected
        - the downloaded artifact's hash matches the proposal's
        """
        if not self.proposal_id:
            return

        log("Check the proposal URL is correctly formatted")
        prefix = f"https://download.dfinity.systems/ic/{self.git_hash}"
        if self.guestos_proposal:
            expected_url = prefix + "/guest-os/update-img/update-img.tar.zst"
        else:
            expected_url = prefix + "/host-os/update-img/update-img.tar.zst"

        if self.proposal_package_url != expected_url:
            fail(
                "The artifact's URL is wrongly formatted, please report this to DFINITY\n"
                f"\tcurrent  = {self.proposal_package_url}\n"
                f"\texpected = {expected_url}"
            )

        log("Download the proposal artifacts")
        # We'll store them in subfolder "proposal"
        # The final file in ephemeral directory is e.g. {self.proposal_out}/update-img.tar.zst
        proposal_target = self.proposal_out / "update-img.tar.zst"
        self.cached_download(
            url=self.proposal_package_url,
            cache_subdir=Path("proposal"),
            target_file=proposal_target
        )

        # Check the hash
        log("Check the hash of the artifacts is correct")
        actual_hash = self.compute_sha256(proposal_target)
        if actual_hash != self.proposal_package_sha256_hex:
            fail(
                "The proposal's artifacts hash does not match!\n"
                f"Expected: {self.proposal_package_sha256_hex}\n"
                f"Actual:   {actual_hash}"
            )
        log_success("The proposal's artifacts and hash match")

    def download_ci_files(self, os_type: str, output_dir: Path):
        """Download update-img.tar.zst or disk-img.tar.zst + SHA256SUMS for the given OS type, with caching."""
        base_url = f"https://download.dfinity.systems/ic/{self.git_hash}"

        if os_type == "setup-os":
            tar_name = "disk-img.tar.zst"
            sums_name = "SHA256SUMS"
            artifact_subdir = "disk-img"
        else:
            tar_name = "update-img.tar.zst"
            sums_name = "SHA256SUMS"
            artifact_subdir = "update-img"

        artifact_url = f"{base_url}/{os_type}/{artifact_subdir}/{tar_name}"
        sums_url = f"{base_url}/{os_type}/{artifact_subdir}/{sums_name}"

        log(f"Download {os_type} image built and pushed by CI system...")

        # We'll store them in subfolder: <os_type>/<artifact_subdir> to mirror the original structure
        artifact_cache_subdir = Path(os_type) / artifact_subdir

        self.cached_download(artifact_url, artifact_cache_subdir, output_dir / tar_name)
        self.cached_download(sums_url, artifact_cache_subdir, output_dir / sums_name)

    def verify_ci_artifacts(self):
        """
        Download the requested OS artifacts from the CI (CDN), verify their hashes via SHA256SUMS,
        store them in self.ci_package_* variables.
        """
        if self.verify_guestos:
            self.download_ci_files("guest-os", self.ci_out / "guestos")
        if self.verify_hostos:
            self.download_ci_files("host-os", self.ci_out / "hostos")
        if self.verify_setupos:
            self.download_ci_files("setup-os", self.ci_out / "setupos")

        log("Validating that uploaded image hashes match the provided proposal hashes (SHA256SUMS check)")

        if self.verify_guestos:
            sums_file = self.ci_out / "guestos" / "SHA256SUMS"
            self.ci_package_guestos_sha256_hex = self.verify_sha256_against_sums(
                sums_file, self.ci_out / "guestos", "update-img.tar.zst", self.git_hash
            )
        if self.verify_hostos:
            sums_file = self.ci_out / "hostos" / "SHA256SUMS"
            self.ci_package_hostos_sha256_hex = self.verify_sha256_against_sums(
                sums_file, self.ci_out / "hostos", "update-img.tar.zst", self.git_hash
            )
        if self.verify_setupos:
            sums_file = self.ci_out / "setupos" / "SHA256SUMS"
            self.ci_package_setupos_sha256_hex = self.verify_sha256_against_sums(
                sums_file, self.ci_out / "setupos", "disk-img.tar.zst", self.git_hash
            )

        log_success("The CI's artifacts and hash match")

    def compare_proposal_vs_cdn(self):
        """Compare the proposal package hash vs. the hash from the CDN artifacts if there's a proposal."""
        log("Check the shasum in the proposal vs. the one from CDN")
        if not self.proposal_id:
            return

        if self.guestos_proposal:
            if self.proposal_package_sha256_hex != self.ci_package_guestos_sha256_hex:
                fail(
                    "The sha256 sum from the proposal does not match the one from the CDN storage for guestOS.\n"
                    f"Proposal sum: {self.proposal_package_sha256_hex}\n"
                    f"CDN sum:      {self.ci_package_guestos_sha256_hex}"
                )
            else:
                log_success("The guestos shasum from the proposal and CDN match")
        else:
            # it must be a hostos proposal
            if self.verify_hostos:
                if self.proposal_package_sha256_hex != self.ci_package_hostos_sha256_hex:
                    fail(
                        "The sha256 sum from the proposal does not match the one from the CDN storage for hostOS.\n"
                        f"Proposal sum: {self.proposal_package_sha256_hex}\n"
                        f"CDN sum:      {self.ci_package_hostos_sha256_hex}"
                    )
                else:
                    log_success("The hostos shasum from the proposal and CDN match")

    def clone_and_checkout_repo(self, ic_clone_path: Path):
        """Clone or copy the IC repo, checkout the right commit."""
        # Opportunistically use the local cache if available
        ic_clone_path_cache = self.base_cache_dir / "repo"
        if os.getenv("CI") is not None:
            log(f"Copy IC repository from {Path.cwd()} to temporary directory")
            subprocess.run(["git", "clone", str(Path.cwd()), str(ic_clone_path)], check=True)
        else:
            log("Clone IC repository from GitHub")
            try:
                subprocess.run(
                    ["git", "-C", str(ic_clone_path_cache), "fsck"],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except subprocess.CalledProcessError:
                log_debug(f"Git fsck failed in cache {ic_clone_path_cache}, removing IC repo git cache")
                shutil.rmtree(ic_clone_path_cache, ignore_errors=True)
            subprocess.run(
                ["git", "clone", "--reference-if-able", str(ic_clone_path_cache), "--dissociate",
                    "https://github.com/dfinity/ic", str(ic_clone_path)],
                check=True
            )
        os.chdir(ic_clone_path)  # The following build steps expect to be in the repo root

        # If user specified the git commit, verify that it exists
        if self.git_commit:
            self.check_git_repo()
            self.check_ic_repo()
            try:
                subprocess.run(["git", "cat-file", "-e", f"{self.git_commit}^{{commit}}"], check=True)
            except subprocess.CalledProcessError:
                fail("When specifying -c, please provide a git hash on a branch of the IC repository.")

        log(f"Checkout {self.git_hash}")
        subprocess.run(["git", "fetch", "--quiet", "origin", self.git_hash], check=True)
        subprocess.run(["git", "checkout", "--quiet", self.git_hash], check=True)

        # Update the repo cache for the next run
        shutil.rmtree(ic_clone_path_cache, ignore_errors=True)
        shutil.copytree(ic_clone_path, ic_clone_path_cache)

    def build_and_compare_locally(self):
        """Clone the repo, then build and compare local artifacts with the CI's."""
        ic_clone_path = self.tmpdir / "ic"
        self.clone_and_checkout_repo(ic_clone_path)

        log("Build IC-OS (./ci/container/build-ic.sh --icos)")
        subprocess.run(["./ci/container/build-ic.sh", "--icos"], check=True)
        log_success("Built IC-OS successfully")

        # Move the resulting artifacts to the dev_out directory, for the final hash comparison
        artifacts_path = ic_clone_path / "artifacts" / "icos"

        def move_artifact(parent: str, file: str):
            src = artifacts_path / parent / file
            dst = self.dev_out / parent / file
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(src, dst)

        if self.verify_guestos:
            move_artifact("guestos", "update-img.tar.zst")

        if self.verify_hostos:
            move_artifact("hostos", "update-img.tar.zst")

        if self.verify_setupos:
            move_artifact("setupos", "disk-img.tar.zst")

        # Compare final hashes
        log("Check if the hash of locally built artifact matches the one fetched from the proposal/CDN")
        if self.verify_guestos:
            local_path = self.dev_out / "guestos" / "update-img.tar.zst"
            dev_package_guestos_sha256_hex = self.compute_sha256(local_path)
            self.compare_hashes(dev_package_guestos_sha256_hex, self.ci_package_guestos_sha256_hex, "GuestOS")

        if self.verify_hostos:
            local_path = self.dev_out / "hostos" / "update-img.tar.zst"
            dev_package_hostos_sha256_hex = self.compute_sha256(local_path)
            self.compare_hashes(dev_package_hostos_sha256_hex, self.ci_package_hostos_sha256_hex, "HostOS")

        if self.verify_setupos:
            local_path = self.dev_out / "setupos" / "disk-img.tar.zst"
            dev_package_setupos_sha256_hex = self.compute_sha256(local_path)
            self.compare_hashes(dev_package_setupos_sha256_hex, self.ci_package_setupos_sha256_hex, "SetupOS")

    # ------------------ High-Level Run ------------------
    def run(self):
        start_time = time.time()

        # Environment checks
        log("Check the environment")
        self.check_environment()

        # If we have a proposal, process it and set self.git_hash accordingly
        self.process_proposal()
        # Or decide the git_hash from user commit or HEAD
        self.decide_git_hash()

        # Initialize the persistent cache for this hash, removing older caches
        self.init_cache()

        # Prepare ephemeral directories
        self.prepare_directories()
        # Verify proposal artifacts, if any
        self.verify_proposal_artifacts()
        # Download & verify CI artifacts
        self.verify_ci_artifacts()
        # Compare proposal vs. CDN if there's a proposal
        self.compare_proposal_vs_cdn()
        # Finally, build locally and compare
        self.build_and_compare_locally()

        # Done
        elapsed = time.time() - start_time
        h, rem = divmod(elapsed, 3600)
        m, s = divmod(rem, 60)
        log(f"Total time: {int(h)}h {int(m)}m {int(s)}s")
        sys.exit(0)

# ------------------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------------------
def main():
    args = parse_args()

    verifier = ReproducibilityVerifier(
        verify_guestos=args.guestos,
        verify_hostos=args.hostos,
        verify_setupos=args.setupos,
        proposal_id=args.proposal_id,
        git_commit=args.commit,
        clean=args.clean,
    )
    verifier.run()

if __name__ == "__main__":
    main()
