#!/usr/bin/env bash

# Process wrapper for commands that are run as part of the ic-os build.
# Usage:
# ./proc_wrapper.sh COMMAND

set -euo pipefail

tmpdir=$(mktemp -d --tmpdir "icosbuildXXXX")
trap 'sudo rm -rf "$tmpdir"' INT TERM EXIT
ICOS_TMPDIR="$tmpdir" "$@"

start_time=$(date +%s.%N)
# Calculate the checksum for every output created by Bazel. For the calculation, we use icsum which is much
# faster than Bazel's built-in checksum for sparse files (e.g. disk images).
for arg in $@; do
    if [[ -w "$arg" ]] && ! getfattr -n user.icsum "$arg" > /dev/null 2>&1; then
        setfattr -n user.icsum -v $(icsum "$arg") "$arg"
    fi
done
