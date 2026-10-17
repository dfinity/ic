#!/usr/bin/env bash

# Process wrapper for the ic-os commands that run podman: the
# IcosContainerBaseImage actions of toolchain.bzl (which build the base images
# of the local-base-* images) and the bare-metal deployment tool
# (ic-os/dev-tools/bare_metal_deployment). All other ic-os build actions use
# tmpdir_wrapper.sh.
# Usage:
# ./proc_wrapper.sh COMMAND

set -euo pipefail

# Each build stage should have a unique storage dir. All podman calls within
# one stage should use the same storage.
# /tmp/containers should be a tmpfs for best performance.
mkdir -p /tmp/containers
podman_storage_dir=$(mktemp -d --tmpdir="/tmp/containers" "icosbuildXXXX")

tmpdir=$(mktemp -d --tmpdir "icosbuildXXXX")
# podman runs rootless and writes files under the storage dir owned by
# mapped subordinate uids; the calling user can't `rm` them directly.
# We use `podman unshare rm` so the cleanup runs inside the userns where
# those uids are mapped to 0. The dev container has sudo NOPASSWD as a
# fallback in case `podman unshare` is unavailable for any reason.
_cleanup() {
    if ! podman --root "$podman_storage_dir/root" --runroot "$podman_storage_dir/runroot" --tmpdir "$podman_storage_dir/tmpdir" \
        unshare rm -rf "$tmpdir" "$podman_storage_dir" 2>/dev/null; then

        echo >&2 "WARNING: could not unshare podman runroot, forcing"
        sudo rm -rf "$tmpdir" "$podman_storage_dir"
    fi
}
trap _cleanup INT TERM EXIT
TMPDIR="$tmpdir" PODMAN_STORAGE_DIR="$podman_storage_dir" "$@"
