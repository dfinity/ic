#!/usr/bin/env bash

set -eEuo pipefail

# Assign first: `cd "$(...)"` would silently `cd ""` (exit 0) if git failed.
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

INPUT_FILES=(
    ci/container/Dockerfile
    ci/container/init.sh
    ci/container/files/*
)

# print sha of relevant files
sha256sum ${INPUT_FILES[@]} | sha256sum | cut -d' ' -f1
