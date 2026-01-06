#!/usr/bin/env bash

# Process wrapper for commands that are run as part of the ic-os build.
# Usage:
# ./proc_wrapper.sh COMMAND

set -euo pipefail

cleanup() {
    if [ -f "${tmpdir}/cidfile" ]; then
        CONTAINER_ID=$(cut -d':' -f2 <"${tmpdir}/cidfile")

        # NOTE: /usr/bin/newuidmap is required to be on $PATH for podman. bazel
        # strips this out - add it back manually.
        export PATH="$PATH:/usr/bin"
        podman container stop "${CONTAINER_ID}"
        podman container cleanup --rm "${CONTAINER_ID}"
    fi

    sudo rm -rf "$tmpdir"
}

tmpdir=$(mktemp -d --tmpdir "icosbuildXXXX")
trap cleanup INT TERM EXIT
TMPDIR="$tmpdir" "$@"
