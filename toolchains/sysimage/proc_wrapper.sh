#!/usr/bin/env bash

# Process wrapper for commands that are run as part of the ic-os build.
# Usage:
# ./proc_wrapper.sh COMMAND

set -euo pipefail

cleanup() {
  sudo umount "$tmpdir"
  sudo rm -rf "$tmpdir"
}

tmpdir=$(sudo mktemp -d "/tmp/tmpfs/icosbuildXXXX")
lower="$tmpdir/overlayfslower"
upper="$tmpdir/overlayfsupper"
workdir="$tmpdir/overlayfsworkdir"
upper=$(sudo mktemp -d "/mnt/icosbuildtmpXXXX/overlayfsupper")
workdir=$(sudo mktemp -d "/mnt/icosbuildtmpXXXX/overlayfsworkdir")
mountpoint=$(sudo mktemp -d "/mnt/icosbuildtmpXXXX/mount")
sudo mount -t overlay overlay -o lowerdir="$lower",upperdir="$upper",workdir="$workdir" "$tmpdir"
trap cleanup INT TERM EXIT
ICOS_TMPDIR="$tmpdir" "$@"
