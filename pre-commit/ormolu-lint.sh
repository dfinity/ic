#!/usr/bin/env bash

set -euo pipefail

ORMOLU="$(readlink "$ormolu_path")"
REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
cd "$REPO_PATH"

if ! find . -type f -name "*.hs" -exec "$ORMOLU" --mode check {} \+; then
    echo 'Please run `bazel run //:ormolu-format` to fix it' >&2
    exit 1
fi
