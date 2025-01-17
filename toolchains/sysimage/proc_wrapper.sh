#!/usr/bin/env bash

# Process wrapper for commands that are run as part of the ic-os build.
# Usage:
# ./proc_wrapper.sh COMMAND

set -euo pipefail

tmpdir=$(mktemp -d --tmpdir "icosbuildXXXX")
trap 'sudo rm -rf "$tmpdir"' INT TERM EXIT
ICOS_TMPDIR="$tmpdir" "$@"

start_time=$(date +%s.%N)
# Calculate user.sha256sum for every output which is used by Bazel. Calculating it based on the tarred file is much
# faster than Bazel calculating it based on the non-tarred file. This is because many of our outputs are sparse
# files.
for arg in $@; do
    if [[ -w "$arg" ]] && ! getfattr -n user.sha256sum "$arg" > /dev/null 2>&1; then
        setfattr -n user.sha256sum -v $(/ic/target/release/fast-digest "$arg") "$arg"
    fi
done

end_time=$(date +%s.%N)
elapsed_time=$(echo "$end_time - $start_time" | bc)
echo "x Elapsed time: $elapsed_time seconds"
