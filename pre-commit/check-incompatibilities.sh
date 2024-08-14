#!/usr/bin/env bash

set -eExuo pipefail

if [[ -n "$(git rev-parse -q --verify MERGE_HEAD)" ]]; then
    echo "Currently merging, skipping buf checks"
    exit 0
fi

echo "Fetch the $MERGE_BRANCH branch"
git fetch origin $MERGE_BRANCH:$MERGE_BRANCH
MERGE_BASE=$(git merge-base HEAD $MERGE_BRANCH)

buf build -o current.bin
buf build ".git#ref=$MERGE_BASE" -o against.bin

buf breaking current.bin --against against.bin --config=buf.yaml
