#!/usr/bin/env bash

# Process wrapper for commands that are run as part of the ic-os build.
# Usage:
# ./proc_wrapper.sh COMMAND

set -euo pipefail

if [ "${USE_TMPFS:-}" = "true" ]; then
    while [ "$(ls /tmp/tmpfs | wc -l)" -gt 4 ]; do
        echo "Waiting..."
        sleep 1
    done

    tmpdir=$(mktemp -d --tmpdir "icosbuildXXXX")
    tmpfs_tmpdir=$(mktemp -d --tmpdir=/tmp/tmpfs "icosbuildXXXX")
    trap 'sudo rm -rf "$tmpdir" "$tmpfs_tmpdir"' INT TERM EXIT
    TMPDIR="$tmpdir" TMPFS_TMPDIR="$tmpfs_tmpdir" "$@"
else
    tmpdir=$(mktemp -d --tmpdir "icosbuildXXXX")
    trap 'sudo rm -rf "$tmpdir"' INT TERM EXIT
    TMPDIR="$tmpdir" "$@"
fi
