#!/usr/bin/env bash

set -eEuo pipefail

cd "$(git rev-parse --show-toplevel)"

INPUT_FILES=(
    .bazelversion
    rust-toolchain.toml
    ci/container/Dockerfile
    ci/container/files/*
)

# print sha of relevant files
sha256sum ${INPUT_FILES[@]} | sha256sum | cut -d' ' -f1
