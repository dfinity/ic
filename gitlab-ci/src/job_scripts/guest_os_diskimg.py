import logging
from os import environ
from os import getenv

from ci import buildevent
from ci import cwd
from ci import ENV
from ci import sh
from ci import sha256


def run():
    build_extra_args = getenv("BUILD_EXTRA_ARGS", "")
    build_extra_suffix = getenv("BUILD_EXTRA_SUFFIX", "")
    build_out = f"build-out/disk-img{build_extra_suffix}"
    build_tmp = f"build-tmp{build_extra_suffix}"
    upload_target = f"guest-os/disk-img{build_extra_suffix}"
    version = ENV.build_id
    logging.info(f"Build ID: {version}")

    with cwd("ic-os/guestos"):
        # lib/guest-os-diskimg.sh fails if these are not set, which they aren't when running locally
        offline_defaults = {"BUILD_EXTRA_ARGS": "", "BUILD_EXTRA_SUFFIX": "", "CI_JOB_ID": ""}
        # override those variables with the already-set ones if there are any
        script_env = {**offline_defaults, **environ.copy()}

        sh(
            "capsule",
            "--passive",
            "-v",
            "-t",
            sha256(f"{build_extra_args}{build_extra_suffix}\n"),
            "-t",
            version,
            "-o",
            f"{build_out}/**/*",
            "--",
            f"{ENV.top}/gitlab-ci/src/job_scripts/lib/guest-os-diskimg.sh",
            build_out,
            build_tmp,
            upload_target,
            version,
            environ.get("CDPRNET", ""),
            env=script_env,
        )

        if ENV.is_gitlab:
            with buildevent("rclone"):
                sh(
                    f"{ENV.top}/gitlab-ci/src/artifacts/rclone_upload.py",
                    f"--version={version}",
                    "--verbose",
                    build_out,
                    upload_target,
                )

    logging.info(f"Build ID (real or fake git revision): {version}")
