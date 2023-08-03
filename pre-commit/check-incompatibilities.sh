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

MERGE_BASE="$(git merge-base HEAD master)"
buf breaking --config buf.yaml --against ".git#ref=$MERGE_BASE"
