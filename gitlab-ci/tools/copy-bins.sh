#!/usr/bin/env bash
set -e

if [ "$#" -ne "1" ]; then
    echo >&2 "Usage: $0 <out-path>"
    exit 1
fi

out_path="$(
    cd "$BUILD_WORKING_DIRECTORY"
    realpath --canonicalize-missing "$1"
)"

echo "$out_path"

mkdir -p "$out_path"
cp -fv $BINARIES "$out_path"
