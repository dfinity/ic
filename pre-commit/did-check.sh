#!/usr/bin/env bash

# Checks for candid compatibility between commits.

set -euo pipefail

DID_CHECK_BIN="$(readlink "${DID_CHECK_BIN:?should point to didc checker}")"

cd "${BUILD_WORKSPACE_DIRECTORY:?Expected to run from bazel}"

# The rev to compare to.
# When unset, we compare against HEAD, effectively checking
# that the machinery works.
readonly did_check_rev="$(git rev-parse "${DID_CHECK_REV:-HEAD}")"

echo "Checking against $did_check_rev"

tmpdir=$(mktemp -d)
trap "rm -rf '$tmpdir'" EXIT

exit_status=0

# Patterns of files we do not want to test
blacklist=(
    "inject_version_into_wasm" # this is a bazel test
    "empty.did"                # the didc checker does not like empty service files
    "test.did"                 # we avoid checking test dids
)

# turn blacklist into a grep exclusion
OLDIFS="$IFS"
IFS='|'
grep_vE="${blacklist[*]}"
IFS="$OLDIFS"

for DID_PATH in $(git ls-files | grep '.did$' | grep -vE "$grep_vE"); do
    echo -n "checking '$DID_PATH' ... "
    tmpfile="$tmpdir/$DID_PATH"
    errlog="$tmpdir/$DID_PATH.err"
    mkdir -p "$(dirname "$tmpfile")"

    if ! git show "$did_check_rev:$DID_PATH" >"$tmpfile" 2>"$errlog"; then
        if grep -sq -- "exists on disk, but not in \\|does not exist in 'HEAD'" "$errlog"; then
            echo "$DID_PATH is a new file, skipping backwards compatibility check"
            exit 0
        else
            cat "$errlog"
            exit 1
        fi
    fi

    if "$DID_CHECK_BIN" "$DID_PATH" "$tmpfile"; then
        echo ok
    else
        echo fail
        exit_status=1
    fi

    # In addition to the usual `didc check after.did before.did` it can be helpful to check the reverse as well.
    # This is This is useful when it is expected that clients will "jump the gun", i.e. upgrade before servers.
    # This is an unusual (but not unheard of) use case.
    if [[ "${ENABLE_ALSO_REVERSE:-}" == "1" ]]; then
        echo "running also-reverse check"
        "$DID_CHECK_BIN" "$tmpfile" "$DID_PATH"
        echo "$DID_PATH passed reversed candid checks"
    fi
done

exit "$exit_status"
