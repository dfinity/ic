#!/usr/bin/env bash

set -euxo pipefail

BUF="$(readlink "$BUF_PATH")"
CONF="$(readlink "$BUF_CONFIG")"
REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"

cd "$REPO_PATH"

if [[ -n "$(git rev-parse -q --verify MERGE_HEAD)" ]]; then
    echo "Currently merging, skipping buf checks"
    exit 0
fi

if [[ "${CI:-}" == "true" ]]; then
    echo "Fetch the master branch"
    git fetch origin master:master
fi

MERGE_BASE="$(git merge-base HEAD master)"
"$BUF" breaking --config="$CONF" --against ".git#ref=$MERGE_BASE"
