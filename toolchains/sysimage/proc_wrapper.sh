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

tmpdir=$(mktemp -d --tmpdir "icosbuildXXXX")
trap 'sudo rm -rf "$tmpdir"; sudo rm -rf "$podman_storage_dir"' INT TERM EXIT
TMPDIR="$tmpdir" PODMAN_STORAGE_DIR="$podman_storage_dir" "$@"
