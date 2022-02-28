from os import environ
from typing import Optional

from artifacts.collector import Collector
from ci import buildevent
from ci import ENV
from ci import sh
from ci import show_sccache_stats


def run(build_command: Optional[str] = None, artifact_ext: str = ""):
    # TODO: get rid of this usage of git revision
    environ["VERSION"] = ENV.build_id

    # Make sure git-related non-determinism does't get through.
    date = sh("date", capture=True)
    if ENV.is_gitlab:
        sh(
            "git",
            "-c",
            "user.name=Gitlab CI",
            "-c",
            "user.email=infra+gitlab-automation@dfinity.org",
            "commit",
            "--allow-empty",
            "-m",
            f"Non-determinism detection commit at {date}",
        )

    with buildevent("cargo-build"):
        if build_command is not None:
            sh("bash", "-c", build_command, cwd=f"{ENV.top}/rs")
        else:
            sh(
                "capsule",
                "--passive",
                "-v",
                "--",
                f"{ENV.top}/gitlab-ci/src/job_scripts/lib/cargo-build-release-linux-native.sh",
                cwd=f"{ENV.top}/rs",
            )

    sh("ls", "-l", f"{ENV.platform_target_dir}/release")

    with buildevent("collect-artifacts"):
        Collector.collect(artifacts_dir=f"artifacts/release{artifact_ext}")

    show_sccache_stats()
