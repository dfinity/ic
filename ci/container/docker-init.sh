#!/usr/bin/env bash
# Entrypoint shim for the dev container started by container-run.sh when using
# docker.

set -euo pipefail

# Docker exposes /dev/fuse as mode 600 root:root, which the unprivileged
# container user can't open. fuse-overlayfs (used by the inner rootless
# podman) needs read/write access to it, so we open up the perms here.
if [ -e /dev/fuse ] && [ ! -w /dev/fuse ]; then
    sudo chmod 0666 /dev/fuse
fi

# Bazel rules in .bazelrc.build bind-mount /tmp/zig-cache into sandboxed
# actions for the hermetic_cc toolchain. Ensure it exists and is writable.
if [ ! -d /tmp/zig-cache ]; then
    sudo mkdir -p /tmp/zig-cache
    sudo chown "$(id -u)":"$(id -g)" /tmp/zig-cache
fi

exec /ic/ci/container/init.sh "$@"
