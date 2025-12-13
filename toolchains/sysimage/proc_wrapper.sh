#!/usr/bin/env bash

# Process wrapper for commands that are run as part of the ic-os build.
# Usage:
# ./proc_wrapper.sh COMMAND

set -euo pipefail

# Temporary shim to create tmpfs on demand, until we have userspace overlayfs,
# or tmpfs natively available on CI.
tmpfs_tmpdir=$(mktemp -d --tmpdir "icosbuildXXXX")
sudo mount -t tmpfs none "${tmpfs_tmpdir}"

tmpdir=$(mktemp -d --tmpdir "icosbuildXXXX")
trap 'sudo umount "${tmpfs_tmpdir}"; ls -lahR "$tmpdir" "${tmpfs_tmpdir}"; sudo rm -rf "$tmpdir" "${tmpfs_tmpdir}"' INT TERM EXIT
TMPDIR="$tmpdir" TMPFS_TMPDIR="${tmpfs_tmpdir}" "$@"
