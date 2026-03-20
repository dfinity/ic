#!/usr/bin/env bash

set -euo pipefail

MERGE_BASE=${MERGE_BASE_SHA:-HEAD}

BUF="$(realpath "$BUF")"

cd "${BUILD_WORKSPACE_DIRECTORY:?Expected to run from bazel}"

tempdir=$(mktemp -d)
against="$tempdir/against.bin"
current="$tempdir/current.bin"

trap "rm -rf '$tempdir'" EXIT

"$BUF" build -o "$current"
"$BUF" build ".git#ref=$MERGE_BASE" -o "$against"

"$BUF" breaking "$current" --against "$against"
