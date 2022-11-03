from os import environ
from os import getenv

from ci import ENV
from ci import mkdir_p
from ci import sh


artifact_ext = getenv("ARTIFACT_EXT", "")
default_artifacts_dir = f"{ENV.top}/artifacts/canisters{artifact_ext}"


def run(artifacts_dir=default_artifacts_dir):
    mkdir_p(artifacts_dir)

    # TODO: get rid of this usage of git revision
    environ["VERSION"] = ENV.build_id

    # Make sure git-related non-determinism does't get through.
    if ENV.is_gitlab:
        date = sh("date", capture=True)
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

    sh("bazel", "build", "--config=ci", "//publish/canisters")
    sh(f"cp $(bazel cquery --output=files //publish/canisters) {artifacts_dir}", shell=True)
    sh(f"sha256sum {artifacts_dir}/*", shell=True)

    if ENV.is_gitlab:
        sh("gitlab-ci/src/artifacts/openssl-sign.sh", f"{ENV.top}/artifacts/canisters{artifact_ext}")
