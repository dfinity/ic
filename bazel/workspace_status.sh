#!/usr/bin/env bash

set -euo pipefail

# By default, we set a hardcoded, constant version to avoid rebuilds. Only when
# --stamp is provided do we write a meaningful version.
if [ "$#" == "0" ]; then
    echo "STABLE_VERSION 0000000000000000000000000000000000000000"
    echo "STABLE_COMMIT_TIMESTAMP 4000000000" # arbitrary (constant) timestamp
    echo "STABLE_COMMIT_DATE_ISO_8601 0000-00-00T00:00:00+00:00"
elif [ "$#" == "1" ] && [ "$1" == "--stamp" ]; then
    version="$(git rev-parse HEAD)"
    # If the checkout is not clean, mark the version as dirty
    if [ -n "$(git status --porcelain)" ]; then
        version="$version-dirty"
    fi
    echo "STABLE_VERSION $version"
    echo "STABLE_COMMIT_TIMESTAMP $(git show -s --format=%ct)"
    echo "STABLE_COMMIT_DATE_ISO_8601 $(git show -s --format=%cI)"
else
    exit 1
fi

# Used to read credentials for S3 upload
echo "HOME ${HOME}"

# Used as farm metadata
test -n "${CI_JOB_NAME:-}" && echo "STABLE_FARM_JOB_NAME ${CI_JOB_NAME}"
if [[ -n "${USER:-}" ]]; then
    echo "STABLE_FARM_USER ${USER}"
elif [[ -n "${HOSTUSER:-}" ]]; then
    echo "STABLE_FARM_USER ${HOSTUSER}"
fi
