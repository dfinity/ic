#!/usr/bin/env bash

# This script helps us only build bazel targets that have been affected by file
# changes in the branch merging to target branch.
#
# Given a commit range, the scripts writes to stdout all the targets are are affected by the
# file changes in the commit range.
#
# This scripts is inspired by https://github.com/bazelbuild/bazel/blob/master/scripts/ci/ci.sh

set -euo pipefail

COMMIT_RANGE="${1:?Please specify a commit range: "'0deadb33f..HEAD'"}"
shift
DIFF_FILES=$(git diff --name-only "${COMMIT_RANGE}")

if grep -qE "(.*\.bazel|.*\.bzl|\.bazelrc|\.bazelversion|mainnet-canister-revisions\.json|^\.github)" <<<"$DIFF_FILES"; then
    bazel query //...
    exit 0
fi

files=()
for file in $DIFF_FILES; do
    if f="$(bazel query "$file")"; then
        files+=("$f")
    fi
done

if grep -qE ".*\.sh" <<<"$DIFF_FILES"; then
    files+=(//pre-commit:shfmt-check)
fi

if grep -qE ".*\.py" <<<"$DIFF_FILES"; then
    files+=(//pre-commit:ruff-lint)
fi

if grep -qE ".*\.hs" <<<"$DIFF_FILES"; then
    files+=(//pre-commit:ormolu-lint)
fi

if grep -qE ".*\.proto" <<<"$DIFF_FILES"; then
    files+=(
        //pre-commit:protobuf-format-check
        //pre-commit:buf-breaking
    )
fi

if [ ${#files[@]} -eq 0 ]; then
    echo "Changes not detected in bazel targets. No bazel targets to build or test." >&2
    exit 0
fi

bazel query "rdeps(//..., set(${files[*]}))"
