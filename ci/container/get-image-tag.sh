#!/usr/bin/env bash

set -eEuo pipefail

cd "$(git rev-parse --show-toplevel)"

INPUT_FILES=(
    ci/container/Dockerfile
    ci/container/init.sh
    ci/container/files/*
)

# print sha of relevant files
sha256sum ${INPUT_FILES[@]} | sha256sum | cut -d' ' -f1
