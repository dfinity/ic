#!/usr/bin/env bash

# This script helps us only build bazel targets that have been affected by file
# changes in the branch merging to target branch.
#
# Given a command (build or test) and a commit range, the scripts writes to stdout all the
# targets are are affected by the file changes in the commit range.
#
# This scripts is inspired by https://github.com/bazelbuild/bazel/blob/master/scripts/ci/ci.sh

set -euo pipefail

# Used to differentiate between test & build targets
BAZEL_CMD="${1:?Please specify a command: "'build|test'"}"
shift

COMMIT_RANGE="${1:?Please specify a commit range: "'0deadb33f..HEAD'"}"
shift
DIFF_FILES=$(git diff --name-only "${COMMIT_RANGE}")

# Prints the targets to stdout
function print_targets() {
    # if the bazel command is "test" we wrap the query to only print
    # test targets
    local query="$1"
    case "$BAZEL_CMD" in
        "build")
            bazel query "$query"
            ;;
        "test")
            bazel query 'kind(".*_test", '"$query"')'
            ;;
        *)
            echo "unknown bazel command: '$BAZEL_CMD'" >&2
            exit 1
            ;;
    esac
}

if grep -qE "(.*\.bazel|.*\.bzl|\.bazelrc|\.bazelversion|mainnet-canister-revisions\.json|^\.github)" <<<"$DIFF_FILES"; then
    print_targets //...
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

print_targets "rdeps(//..., set(${files[*]}))"
