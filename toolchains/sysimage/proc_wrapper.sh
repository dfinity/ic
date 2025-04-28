#!/usr/bin/env bash

# Process wrapper for commands that are run as part of the ic-os build.
# Usage:
# ./proc_wrapper.sh COMMAND

set -euo pipefail

tmpdir=$(mktemp -d --tmpdir "icosbuildXXXX")
trap 'sudo rm -rf "$tmpdir"' INT TERM EXIT
TMPDIR="$tmpdir" "$@"
