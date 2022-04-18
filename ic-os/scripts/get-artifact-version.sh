#!/usr/bin/env bash

set -eo pipefail

source $(dirname "${BASH_SOURCE[0]}")/artifact-utils.sh

INPUT_FILE="$2"

function usage() {
    cat <<EOF
get-artifact-version [--disk|--upgrade] file

Extract version information from IC guest OS build
artifact (either the "initial disk image", or the
"system upgrade image").
EOF
}

case "$1" in
    --disk)
        version_from_disk_image "${INPUT_FILE}"
        ;;
    --upgrade)
        version_from_upgrade_image "${INPUT_FILE}"
        ;;
    *)
        usage
        exit 1
        ;;
esac
