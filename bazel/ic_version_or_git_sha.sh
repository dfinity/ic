#!/usr/bin/env bash

set -eEuo pipefail

if [ $# -ne 2 ]; then
    echo "Usage: $0 <path/to/volatile-status.txt> <path/to/output/file.txt>" >&2
    exit 1
fi

if [ -n "${VERSION}" ]; then
    echo "${VERSION}" >"$2"
    exit
fi

while read -r k v; do
    case "$k" in
        COMMIT_SHA)
            VERSION="$v"
            ;;
        GIT_TREE_STATUS)
            GIT_TREE_STATUS="$v"
            ;;
        BUILD_TIMESTAMP)
            BUILD_TIMESTAMP="$v"
            ;;
    esac
done <"$1"

if [ "${GIT_TREE_STATUS}" != 'Clean' ]; then
    VERSION="${VERSION}-${BUILD_TIMESTAMP}"
fi

echo "${VERSION}" >"$2"
