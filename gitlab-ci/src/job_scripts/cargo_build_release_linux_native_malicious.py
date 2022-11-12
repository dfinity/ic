from . import cargo_build_release_linux_native


def run():
    cargo_build_release_linux_native.run(
        target="//publish/malicious:replica",
        artifact_ext="-malicious",
    )
