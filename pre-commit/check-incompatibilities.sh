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

tempdir=$(mktemp -d)
against="$tempdir/against.bin"
current="$tempdir/current.bin"

trap "rm -rf '$tempdir'" EXIT

cd "$REPO_PATH"

"$BUF" build -o "$current"
"$BUF" build ".git#ref=$MERGE_BASE" -o "$against"

"$BUF" breaking "$current" --against "$against" --config="$CONF"
