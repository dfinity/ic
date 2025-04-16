#!/usr/bin/env bash

set -euo pipefail

BUILD_WORKSPACE_DIRECTORY="$(dirname $(readlink $WORKSPACE))"
export BUILD_WORKSPACE_DIRECTORY

if ! "$GAZELLE_BIN" update -mode=diff; then
    echo "Some gazelle managed build files need to be regenerated" >&2
    echo "run bazel run //:gazelle" >&2
    exit 1
fi
