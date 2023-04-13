#!/usr/bin/env bash

set -ueo pipefail

REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
cd "$REPO_PATH"

if git grep -I -n -E '\bDfinity\b' . ":(exclude)bazel/pre-commit/DFINITY-capitalization.sh"; then
    echo "[-] Improper capitalisation of DFINITY"
    exit 1
fi
