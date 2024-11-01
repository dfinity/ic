#!/usr/bin/env bash

set -eExuo pipefail

if [ "${CI_OVERRIDE_BUF_BREAKING:-false}" = "true" ]; then
    echo "Skipping buf-breaking check because override requested."
    exit 0
fi

MERGE_BASE=${MERGE_BASE_SHA:-HEAD}

BUF="$(readlink "$buf_path")"
CONF="$(readlink "$buf_config")"
REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
cd "$REPO_PATH"

"$BUF" build -o current.bin
"$BUF" build ".git#ref=$MERGE_BASE" -o against.bin

"$BUF" breaking current.bin --against against.bin --config="$CONF"
