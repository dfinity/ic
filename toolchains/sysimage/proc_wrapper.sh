#!/usr/bin/env bash

# Process wrapper for commands that are run as part of the ic-os build.
# Usage:
# ./proc_wrapper.sh COMMAND

# EERO 1

set -uox pipefail

cleanup() {
    echo "Cleaning up tmpdir from proc_wrapper"
    ls -lah $tmpdir/* || true
    if [ -f "${tmpdir}/cidfile" ]; then
        CONTAINER_ID=$(cut -d':' -f2 <"${tmpdir}/cidfile")

        rm -f $(find "${tmpdir}" -iname pause.pid)

        # NOTE: /usr/bin/newuidmap is required to be on $PATH for podman. bazel
        # strips this out - add it back manually.
        export PATH="/usr/bin:$PATH"
        podman container stop "${CONTAINER_ID}" || true
        podman container cleanup --rm "${CONTAINER_ID}" || true
        podman system prune --external || true

        podman ps --all || true

    fi

    sudo rm -rf $tmpdir/containers-user-1001 || true
    sudo rm -rf $tmpdir/podman-run-1001 || true
    ls -lahR $tmpdir/containers-user-1001 || true
    ls -lahR $tmpdir/podman-run-1001 || true

    sudo rm -rf "$tmpdir"
    res=$?
    if [ $res -ne 0 ]; then
        echo "Failed to cleanup"
        ls -lahR $tmpdir || true
        exit $res
    fi
}

tmpdir=$(mktemp -d --tmpdir "icosbuildXXXX")
trap cleanup INT TERM EXIT
TMPDIR="$tmpdir" "$@"
