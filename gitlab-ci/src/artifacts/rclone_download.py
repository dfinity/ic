#!/usr/bin/env python3
#
# Utility to download the S3 CDN artifacts, using rclone.
# It can download artifacts from a given git revision or from latest available merge base master.
# The tool will prefer the "blessed" artifacts, which can be found on the CDN at "/blessed/<remote-path>"
#
# Example usage of the script:
#
#   Search for and download the most recent artifacts available before the master merge base.
#   ./rclone_download.py  --master-merge-base --remote-path=guest-os --out=/tmp/foo --latest-to
#
#   Download artifacts from the provided git revision, returns an error if not available.
#   ./rclone_download.py  --git-rev=612b7bd30f84f9d8a4197d4241d9b906b0a916b4 --remote-path=guest-os --out=/tmp/foo
#
#   Download all artifacts from the provided git revision, store them in the default folder
#      <REPO_ROOT>/artifacts/<git-rev>/<remote-path>
#   ./rclone_download.py  --git-rev=612b7bd30f84f9d8a4197d4241d9b906b0a916b4
#
#   Download the latest artifacts available before the provided git revision.
#   ./rclone_download.py  --git-rev=612b7bd30f84f9d8a4197d4241d9b906b0a916b4 --remote-path=guest-os --out=/tmp/foo --latest-to
#
import argparse
import gzip
import logging
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import time

MAX_GIT_FETCH_ATTEMPTS = 10
MAX_RCLONE_ATTEMPTS = 10


class RcloneDownload:
    """Utilities to rclone from a given the IC CDN."""

    def __init__(self, config, remote_path, out, timeout, dry_run, unpack, mark_executable):
        """Init the object with configuration settings."""
        self._local_repo = None
        # Setting the repo_root relies on the relative path of the script in the repo
        # in order to support tool usage with stdlib only for the common path
        self.repo_root = pathlib.Path(__file__).parent.parent.parent.parent.absolute()

        if not config:
            config = os.path.join(self.repo_root, ".rclone-anon.conf")

        self.config = config
        self.remote_path = remote_path
        self.out = out
        self.timeout = timeout
        self.dry_run = dry_run
        self.unpack = unpack
        self.mark_executable = mark_executable

    @property
    def local_repo(self):
        """Return an instance of git.Repo()."""
        import git

        if self._local_repo is None:
            self._local_repo = git.Repo(self.repo_root)
        return self._local_repo

    def _merge_base(self, merge_base) -> str:

        self._git_fetch_branch(merge_base)
        return self.local_repo.merge_base(merge_base, self.local_repo.head.commit)

    def _rclone_check_if_exists(self, cdn_path) -> bool:
        for i in range(MAX_RCLONE_ATTEMPTS):
            try:
                p = subprocess.run(
                    ["rclone", f"--config={self.config}", "ls", cdn_path],
                    timeout=300,  # Listing files should be instant, 20 seconds is plenty
                    capture_output=True,
                )
                return len(p.stdout.splitlines()) > 0
            except subprocess.TimeoutExpired as e:
                logging.warning(
                    "rclone timeout: %s\n%s\n%s",
                    e.stdout,
                    e.stderr,
                    e,
                )
                if i + 1 < MAX_RCLONE_ATTEMPTS:
                    logging.info("Retrying after 20 seconds.")
                    time.sleep(20)
            except subprocess.CalledProcessError as e:
                logging.warning(
                    "rclone failed (%d) with exception: %s\n%s",
                    e.returncode,
                    e.output,
                    e,
                )
                if i + 1 < MAX_RCLONE_ATTEMPTS:
                    logging.info("Retrying after 20 seconds.")
                    time.sleep(20)
        return False

    def _rclone(self, git_rev, include, blessed_only) -> bool:
        if blessed_only:
            # Only attempt to download from /blessed. The contents of /blessed are immutable.
            prefixes = ["blessed/ic"]
        else:
            # If /blessed/ic exists, use it. Otherwise fallback to /ic.
            prefixes = ["blessed/ic", "ic"]

        for prefix in prefixes:
            cdn_path = f"public-s3:dfinity-download-public/{prefix}/{git_rev}/{self.remote_path}"
            if not self._rclone_check_if_exists(cdn_path):
                logging.debug("CDN directory does not exist: %s", cdn_path)
                continue
            logging.info("CDN directory exists: %s", cdn_path)

            local_path = pathlib.Path(self.out or f"{self.repo_root}/artifacts/{git_rev}/{self.remote_path}")
            cmd = [
                "rclone",
                f"--config={self.config}",
                "--transfers=100",
                "--multi-thread-cutoff=1M",
                "--multi-thread-streams=100",
                "--checksum",
                "--include",
                include or "*",
                "copyto",
                cdn_path,
                local_path,
            ]

            if self.dry_run:
                logging.info("Dry-running rclone: %s", cmd)
                cmd.insert(0, "echo")
            else:
                logging.debug("Running rclone: %s", cmd)

            for i in range(MAX_RCLONE_ATTEMPTS):
                try:
                    subprocess.run(cmd, timeout=self.timeout, capture_output=True)
                    logging.info("CDN artifacts from %s downloaded to %s", cdn_path, local_path)
                    self._postprocess_downloads(local_path)
                    return True
                except subprocess.TimeoutExpired as e:
                    logging.warning(
                        "rclone timeout: %s\n%s\n%s",
                        e.stdout,
                        e.stderr,
                        e,
                    )
                    if i + 1 < MAX_RCLONE_ATTEMPTS:
                        logging.info("Retrying after 10 seconds.")
                        time.sleep(10)
                except subprocess.CalledProcessError as e:
                    logging.warning(
                        "rclone failed (%d) with exception: %s\n%s\n%s",
                        e.returncode,
                        e.stdout,
                        e.stderr,
                        e,
                    )
                    if i + 1 < MAX_RCLONE_ATTEMPTS:
                        logging.info("Retrying after 10 seconds.")
                        time.sleep(10)

        return False

    def _postprocess_downloads(self, local_path):
        if self.unpack:
            logging.info("Unpacking %s/**/*.gz", local_path)
            for path in local_path.rglob("*.gz"):
                logging.debug("Unpack %s", path)
                if str(path).endswith(".tar.gz") or str(path).endswith(".tgz"):
                    shutil.unpack_archive(path, extract_dir=path.absolute().parent)
                else:
                    with gzip.open(path, "rb") as f_in:
                        with open(path.absolute().parent / os.path.basename(path)[:-3], "wb") as f_out:
                            shutil.copyfileobj(f_in, f_out)
        if self.mark_executable:
            logging.info("Marking executable %s/**/*", local_path)
            for path in local_path.rglob("*"):
                mode = os.stat(path).st_mode
                os.chmod(path, mode | stat.S_IEXEC)

    def _git_fetch_branch(self, branch) -> None:
        import git

        exc = None
        for i in range(MAX_GIT_FETCH_ATTEMPTS):
            try:
                # Get the 1st remote name. This is typically 'origin' but may be something else as well.
                remote_name = self.local_repo.git.remote("show").split()[0]
                origin = self.local_repo.remote(name=remote_name)
                logging.info(
                    "Updating %s branch: git fetch %s %s:%s",
                    branch,
                    remote_name,
                    branch,
                    branch,
                )
                origin.fetch(f"{branch}:{branch}", prune=True, prune_tags=True, force=True)
                return
            except git.GitCommandError as e:
                logging.warning("Error [%d/%d] fetching changes: %s", i, MAX_GIT_FETCH_ATTEMPTS, e)
                exc = e
                time.sleep(10)
        if exc:
            raise exc  # raise the last exception if there were too many attempts

    def _fetch_latest_from_git_rev(self, git_rev, include, blessed_only) -> bool:
        for ref in self.local_repo.iter_commits(rev=git_rev, max_count=50):
            logging.info("Trying: %s", ref)
            if self._rclone(ref, include, blessed_only):
                return True

        logging.error("Could not rclone files after searching a back from git rev %s", git_rev)
        return False


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--timeout",
        action="store",
        default=600,
        help="Timeout in seconds for each clone command.",
    )

    parser.add_argument(
        "--config",
        action="store",
        help="Path to rclone config file. Default is `<REPO_ROOT>/.rclone-anon.conf`.",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Mock the upload, for debugging purposes.",
    )

    parser.add_argument(
        "--git-rev",
        action="store",
        help="Git revision (SHA) to download artifacts from.",
    )

    parser.add_argument(
        "--merge-base",
        action="store",
        help="Download artifacts from the merge base between HEAD and a branch.",
    )

    parser.add_argument(
        "--latest-to",
        action="store_true",
        help="Search backwards for the latest available artifacts, if the exact master or git-rev are not available.",
    )

    parser.add_argument(
        "--remote-path",
        action="store",
        default="",
        help="Path to download from e.g. guest-os.",
    )

    parser.add_argument(
        "--include",
        action="store",
        help="Include (whitelist) these files when downloading (https://rclone.org/filtering/).",
    )

    parser.add_argument(
        "--blessed-only",
        action="store_true",
        help="Only attempt to download the blessed binaries.",
    )

    parser.add_argument(
        "--unpack",
        action="store_true",
        help="Unpack the downloaded binaries.",
    )

    parser.add_argument(
        "--mark-executable",
        action="store_true",
        help="Mark (chmod) the downloaded binaries (optionally unpacked if --unpack provided) as executable.",
    )

    parser.add_argument(
        "-o",
        "--out",
        help="Store the output in the provided dir.",
        nargs="?",
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    ra = RcloneDownload(
        args.config,
        args.remote_path,
        args.out,
        args.timeout,
        args.dry_run,
        args.unpack,
        args.mark_executable,
    )

    if args.merge_base:
        git_rev = ra._merge_base(args.merge_base)
    else:
        git_rev = args.git_rev

    if args.latest_to:
        if not ra._fetch_latest_from_git_rev(git_rev, args.include, args.blessed_only):
            sys.exit(1)
    else:
        if not ra._rclone(git_rev, args.include, args.blessed_only):
            logging.error("Could not rclone files from git rev %s", git_rev)
            sys.exit(1)


if __name__ == "__main__":
    main()
