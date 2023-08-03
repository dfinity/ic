#!/usr/bin/env bash

set -eExuo pipefail

if [[ -n "$(git rev-parse -q --verify MERGE_HEAD)" ]]; then
    echo "Currently merging, skipping buf checks"
    exit 0
fi

if [[ "${CI:-}" == "true" ]]; then
    echo "Fetch the master branch"
    git fetch origin master:master
fi

OVERRIDE_BUF_CHECK_STRING="[override-buf-check]"

if [[ $CI_MERGE_REQUEST_TITLE == *"$OVERRIDE_BUF_CHECK_STRING"* ]]; then
    exit 0
fi

MERGE_BASE="$(git merge-base HEAD master)"

(
    trap 'echo "To disable this check, add ${OVERRIDE_BUF_CHECK_STRING} to the name of your MR"' ERR INT
    buf breaking --config buf.yaml --against ".git#ref=$MERGE_BASE"
)
