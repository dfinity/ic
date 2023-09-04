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

buf build -o current.bin
buf build ".git#ref=$MERGE_BASE" -o against.bin

buf breaking current.bin --against against.bin --config=buf.yaml
