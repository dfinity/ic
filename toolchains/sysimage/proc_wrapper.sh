#!/usr/bin/env bash

# Process wrapper for commands that are run as part of the ic-os build.
# Usage:
# ./proc_wrapper.sh COMMAND

set -euo pipefail

# Each build stage should have a unique storage dir. All podman calls within
# one stage should use the same storage.
# /tmp/containers should be a tmpfs for best performance.
mkdir -p /tmp/containers
podman_storage_dir=$(mktemp -d --tmpdir="/tmp/containers" "icosbuildXXXX")

# Podman keeps its container lock manager in a POSIX shared memory segment: one
# per uid when rootless, and a single unsuffixed one when running as root. It
# opens that segment if it exists and otherwise creates it O_EXCL -- with nothing
# serializing the gap between those two steps. ic-os actions run concurrently and
# unsandboxed, so on a machine where the segment does not exist yet (a fresh CI
# container) the first burst of actions all find it missing and race to create it.
# The losers die:
#   Error: failed to get new shm lock manager: failed to create 2048 locks in
#   /libpod_rootless_lock_<uid>: file exists
# Close that window by materializing the segment exactly once, under a lock of
# our own, before the build starts. Once it exists podman only ever opens it, so
# every later action pays a single `test -e`: no lock, no extra podman, and the
# builds themselves are never serialized.
#
# Note that root is NOT exempt: rootful podman keeps the same kind of segment,
# just under a different name (/run/libpod is its tmp dir, not its lock), and
# ci/container/container-run.sh runs the build as root whenever the host uid has
# no matching container user. So pick the name by euid rather than skipping.
if [ "$EUID" -eq 0 ]; then
    podman_lock_segment="/dev/shm/libpod_lock"
else
    podman_lock_segment="/dev/shm/libpod_rootless_lock_$EUID"
fi
# Our own lock file goes in a private directory rather than straight into
# /dev/shm: that is world-writable, so a fixed path in it could be pre-created by
# another uid -- as a symlink, whereupon opening it would truncate whatever it
# points at, or hang if it points at a fifo. Nobody can plant anything inside a
# 0700 directory we own, so check that we do own it and skip the pre-warm if not.
#
# The whole block is best-effort, hence the trailing `|| true`: `set -e` would
# otherwise turn any hiccup here into a failed build. If any of it does not work
# out we simply build unprotected, exactly as before.
podman_lock_dir="/dev/shm/icos-podman-$EUID"
if [ -w /dev/shm ] && [ ! -e "$podman_lock_segment" ] \
    && { mkdir -m 700 "$podman_lock_dir" 2>/dev/null || [ -d "$podman_lock_dir" ]; } \
    && [ ! -L "$podman_lock_dir" ] && [ -O "$podman_lock_dir" ]; then
    (
        # Bounded wait: if a sibling action wedges while holding this lock, build
        # unprotected instead of hanging here forever.
        flock -w 30 9 || exit 0
        # Re-check under the lock: whoever got here first already created it.
        if [ ! -e "$podman_lock_segment" ]; then
            # Any podman command initializes the lock manager; `info` is the
            # cheapest. Real podman problems are reported by the build below.
            podman --root "$podman_storage_dir/root" --runroot "$podman_storage_dir/runroot" \
                info >/dev/null 2>&1 || true
        fi
    ) 9>>"$podman_lock_dir/init.lck" || true
fi

tmpdir=$(mktemp -d --tmpdir "icosbuildXXXX")
# podman runs rootless and writes files under the storage dir owned by
# mapped subordinate uids; the calling user can't `rm` them directly.
# We use `podman unshare rm` so the cleanup runs inside the userns where
# those uids are mapped to 0. The dev container has sudo NOPASSWD as a
# fallback in case `podman unshare` is unavailable for any reason.
_cleanup() {
    if ! podman --root "$podman_storage_dir/root" --runroot "$podman_storage_dir/runroot" \
        unshare rm -rf "$tmpdir" "$podman_storage_dir" 2>/dev/null; then

        echo >&2 "WARNING: could not unshare podman runroot, forcing"
        sudo rm -rf "$tmpdir" "$podman_storage_dir"
    fi
}
trap _cleanup INT TERM EXIT
TMPDIR="$tmpdir" PODMAN_STORAGE_DIR="$podman_storage_dir" "$@"
