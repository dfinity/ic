from . import cargo_build_release_linux_native


def run():
    cargo_build_release_linux_native.run(
        build_command="cd replica; cargo build --features malicious_code --bin replica --release --target x86_64-unknown-linux-gnu ; cd -",
        artifact_ext="-malicious",
    )
