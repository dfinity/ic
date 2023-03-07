#!/bin/bash

# Install an update artifact and prepare to boot it next time.
# The update artifact is read from the file pointed to by the first argument.

set -eo pipefail

TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" exit

tar -xaf "$1" -C "${TMPDIR}"

/opt/ic/bin/manageboot.sh install "${TMPDIR}"/boot.img "${TMPDIR}"/root.img
