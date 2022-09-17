from . import cargo_build_release_linux_native


def run():
    cargo_build_release_linux_native.run(
        target="//:malicious_replica",
        artifact_ext="-malicious",
    )
