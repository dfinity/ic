#!/usr/bin/env bash

set -ueo pipefail

REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
cd "$REPO_PATH"

if git grep -I -i -n -E "DO[^\w]?NOT[^\w]?MERGE" . ":(exclude)bazel/pre-commit/BUILD.bazel" \
    ":(exclude)bazel/pre-commit/do-not-merge.sh"; then
    echo "[-] Cannot merge - DO NOT MERGE present in this MR"
    exit 1
fi
