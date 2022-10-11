import logging
from os import getenv
from pathlib import Path

from ci import buildevent
from ci import cwd
from ci import ENV
from ci import sh


def run():
    build_extra_suffix = getenv("BUILD_EXTRA_SUFFIX", "")
    build_out = f"build-out/disk-img{build_extra_suffix}"
    upload_target = f"guest-os/disk-img{build_extra_suffix}"
    version = ENV.build_id
    logging.info(f"Build ID: {version}")

    build_mode = "dev" if "-dev" in build_extra_suffix else "prod"
    malicious_mode = "-malicious" if "-malicious" in build_extra_suffix else ""

    with cwd("ic-os/guestos"):
        sh(f"{ENV.top}/gitlab-ci/src/job_scripts/lib/guest-os-diskimg.sh", build_out, build_mode, malicious_mode)

        version_txt = Path(f"{ENV.top}/version.txt")
        if version_txt.is_file():
            legacy_version = version
            version = version_txt.read_text().strip()

        if ENV.is_gitlab:
            with buildevent("rclone"):
                sh(
                    f"{ENV.top}/gitlab-ci/src/artifacts/rclone_upload.py",
                    f"--version={version}",
                    "--verbose",
                    build_out,
                    upload_target,
                )
            if legacy_version:
                with buildevent("rclone"):
                    sh(
                        f"{ENV.top}/gitlab-ci/src/artifacts/rclone_upload.py",
                        f"--version={legacy_version}",
                        "--verbose",
                        build_out,
                        upload_target,
                    )

    logging.info(f"Build ID (real or fake git revision): {version}")
