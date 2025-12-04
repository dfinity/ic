#!/usr/bin/env bash

# Checks for candid compatibility between commits.
# The 'DID_PATH' must be a checked-in candid service.

set -euo pipefail

real_workspace=$(realpath "${WORKSPACE_FILE:?WORKSPACE_FILE not set}")
workspace_root=$(dirname "$real_workspace")

echo "candid checker: '${DID_CHECK_BIN:?DID_CHECK_BIN not set}'"
echo "did path: '${DID_PATH:?DID_PATH not set}'"
echo "inferred workspace root: '$workspace_root'"

# The rev to compare to.
# When unset, we compare against HEAD, effectively checking
# that the machinery works.
readonly did_check_rev="${DID_CHECK_REV:-HEAD}"

readonly tmpfile="$(mktemp $TEST_TMPDIR/prev.XXXXXX)"
readonly errlog="$(mktemp $TEST_TMPDIR/err.XXXXXX)"

if ! git -C "$workspace_root" show "$did_check_rev:$DID_PATH" >"$tmpfile" 2>"$errlog"; then
    if grep -sq -- "exists on disk, but not in \\|does not exist in 'HEAD'" "$errlog"; then
        echo "$DID_PATH is a new file, skipping backwards compatibility check"
        exit 0
    else
        cat "$errlog"
        exit 1
    fi
fi

"$DID_CHECK_BIN" "$DID_PATH" "$tmpfile"
echo "$DID_PATH passed candid checks"

# In addition to the usual `didc check after.did before.did` it can be helpful to check the reverse as well.
# This is This is useful when it is expected that clients will "jump the gun", i.e. upgrade before servers.
# This is an unusual (but not unheard of) use case.
if [[ "${ENABLE_ALSO_REVERSE:-}" == "1" ]]; then
    echo "running also-reverse check"
    "$DID_CHECK_BIN" "$tmpfile" "$DID_PATH"
    echo "$DID_PATH passed reversed candid checks"
fi
