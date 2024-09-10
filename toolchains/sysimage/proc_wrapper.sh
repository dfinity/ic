#!/usr/bin/env bash

# Process wrapper for commands that are run as part of the ic-os build.
# Usage:
# ./proc_wrapper.sh COMMAND

set -euo pipefail

cleanup() {
  sudo umount "$tmpdir"
  sudo rm -rf "$tmpdir"
}

tmpdir=$(sudo mktemp -d "/mnt/icosbuildtmpXXXX")
sudo mount -o size=8G -t tmpfs none "$tmpdir"
trap cleanup INT TERM EXIT
ICOS_TMPDIR="$tmpdir" "$@"
