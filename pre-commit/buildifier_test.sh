#!/usr/bin/env bash

set -euo pipefail

BUILD_WORKSPACE_DIRECTORY="$(dirname $(readlink $WORKSPACE))"
export BUILD_WORKSPACE_DIRECTORY

if ! "$BUILDIFIER_CHECK_BIN"; then
    echo "Buildifier check failed!" >&2
    echo "Format code:" >&2
    echo "  bazel run //bazel:buildifier" >&2
    echo "Check for failures:" >&2
    echo "  bazel run //bazel:buildifier.check" >&2
    exit 1
fi
