#!/usr/bin/env python3
#
# Utility to upload artifacts into the S3 bucket.
#
# Example usage of the script:
#
#   Search for the youngest available artifacts available since the master merge base.
#   ./rclone_download.py ./artifacts/canisters
#
import argparse
import logging
import os
import pathlib
import subprocess
import time

MAX_RCLONE_ATTEMPTS = 3


class RcloneUpload:
    """Upload a local folder to the CDN, using rclone."""

    def __init__(self, config, timeout, dry_run=False):
        """Init the object with configuration settings."""
        self.repo_root = pathlib.Path(__file__).parent.parent.parent.parent.absolute()

        if not config:
            config = self.repo_root / ".rclone.conf"

        self.config = config
        self.timeout = timeout
        self.dry_run = dry_run

    def _upload(self, local_path, remote_subdir, other_options=[]):
        cmd = [
            "rclone",
            f"--config={self.config}",
            "--progress",
            "--stats-one-line",
            "--checksum",
            *other_options,
            "copyto",
            local_path,
            f"public-s3:dfinity-download-public/{remote_subdir}",
        ]

        if self.dry_run:
            logging.info("Dry-running rclone: %s", cmd)
            cmd.insert(0, "echo")
        else:
            logging.debug("Running rclone: %s", cmd)

        for i in range(MAX_RCLONE_ATTEMPTS):
            try:
                subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=self.timeout)
                break
            except subprocess.SubprocessError as e:
                logging.warning(
                    "rclone failed (%d) with exception: %s\n%s",
                    e.returncode,
                    e.output,
                    e,
                )
                if i + 1 < MAX_RCLONE_ATTEMPTS:
                    logging.info("Retrying after 10 seconds.")
                    time.sleep(10)
        else:
            raise Exception("Failed to upload too many times.")

    def upload_artifacts(self, local_path, remote_subdir, version):
        """Upload artifacts from local_path to the CDN in remote_subdir."""
        if os.environ.get("CI_COMMIT_REF_PROTECTED") == "true":
            # The first build of blessed binaries (prepared on verified builders) is also stored at /blessed
            # The /blessed folder is already prioritized when downloading from the HTTPS endpoint,
            # see dfinity-lab/infra#1604
            # I.e. curl https://download.dfinity.systems/ic/some/binary will first try to download from
            # dfinity-download-public/blessed/ic/some/binary and fallback to dfinity-download-public/ic/some/binary.
            self._upload(
                local_path=local_path,
                remote_subdir=f"blessed/ic/{version}/{remote_subdir}",
                other_options=["--ignore-existing"],
            )

        self._upload(
            local_path=local_path, remote_subdir=f"ic/{version}/{remote_subdir}", other_options=["--ignore-existing"]
        )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--timeout",
        action="store",
        default=120,
        help="Timeout in seconds for each rclone call.",
    )

    parser.add_argument(
        "--config",
        action="store",
        help="Path to rclone config file. Default is `<REPO_ROOT>/.rclone.conf`.",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Mock the upload, for debugging purposes.",
    )

    parser.add_argument(
        "--version",
        action="store",
        help="Specify the version string.",
    )

    parser.add_argument(
        "local_path",
        action="store",
        help="Local path to upload.",
    )

    parser.add_argument(
        "remote_subdir",
        action="store",
        help="Subdirectory on CDN, to upload at.",
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    rclone = RcloneUpload(args.config, args.timeout, args.dry_run)

    local_path = str(pathlib.Path(args.local_path).absolute())

    version = args.version or os.environ.get("CI_COMMIT_SHA")
    if not version:
        logging.error(
            "Cannot determine version string either from --version nor " "from CI_COMMIT_SHA environment variable"
        )

    rclone.upload_artifacts(local_path, args.remote_subdir, version)


if __name__ == "__main__":
    main()
