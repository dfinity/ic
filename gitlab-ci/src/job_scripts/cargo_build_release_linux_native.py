from os import environ
from typing import Callable
from typing import Optional

from artifacts.collector import Collector
from ci import buildevent
from ci import ENV
from ci import sh
from ci import show_sccache_stats


def run(
    target: str = "//:binaries",
    artifact_ext: str = "",
    sccache_stats=False,
    after_script: Optional[Callable[[], None]] = None,
):
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
        sh(
            f"{ENV.top}/gitlab-ci/src/job_scripts/lib/cargo-build-release-linux-native.sh",
            target,
            cwd=f"{ENV.top}/rs",
        )
        if after_script is not None:
            after_script()

    sh("ls", "-l", f"{ENV.platform_target_dir}/release")

    with buildevent("collect-artifacts"):
        Collector.collect(artifacts_dir=f"artifacts/release{artifact_ext}")

    if sccache_stats:
        show_sccache_stats()
