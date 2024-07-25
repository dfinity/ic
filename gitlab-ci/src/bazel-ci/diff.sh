#!/usr/bin/env bash

# This script helps us only build bazel targets that have been affected by file
# changes in the branch merging to target branch.
#
# We get the list of files from the diff, query for the ones that are part of any bazel target,
# and then query for the targets that depend on these files.
#
# This scripts is inspired by https://github.com/bazelbuild/bazel/blob/master/scripts/ci/ci.sh

set -euo pipefail

set -x
cd "$(git rev-parse --show-toplevel)"

git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" --quiet
MERGE_BASE="$(git merge-base HEAD origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME)"
COMMIT_RANGE=${COMMIT_RANGE:-$MERGE_BASE".."}
DIFF_FILES=$(git diff --name-only "${COMMIT_RANGE}")

if grep -qE "(.*\.bazel|.*\.bzl|\.bazelrc|\.bazelversion)" <<<"$DIFF_FILES"; then
    echo "Changes detected in bazel files. Considering all targets." >&2
    echo ${BAZEL_TARGETS:-"//..."}
    exit 0
fi

files=()
for file in $DIFF_FILES; do
    if f="$(bazel query "$file")"; then
        files+=("$f")
    fi
done

if grep -qE ".*\.sh" <<<"$DIFF_FILES"; then
    files+=(//pre-commit:shfmt-lint)
fi

if grep -qE ".*\.py" <<<"$DIFF_FILES"; then
    files+=(//pre-commit:ruff-lint)
fi

if grep -qE ".*\.hs" <<<"$DIFF_FILES"; then
    files+=(//pre-commit:ormolu-lint)
fi

if grep -qE ".*\.proto" <<<"$DIFF_FILES"; then
    files+=(//pre-commit:protobuf-format-check)
fi

if [ ${#files[@]} -eq 0 ]; then
    echo "Changes not detected in bazel targets. No bazel targets to build or test." >&2
    exit 0
fi

# To calculate the bazel targets to build or test we find the reverse dependencies
# of the set of changed files in the "universe". The universe is defined as the
# union of the specified $BAZEL_TARGETS. Note that this variable is defined in
# workflows and should be a space-separated list of bazel targets. If it's not
# defined the universe defaults to all targets, i.e.: //...
UNIVERSE="$(echo ${BAZEL_TARGETS:-//...} | sed 's/ /+/')"
if [ "${BAZEL_COMMAND:-}" == "build" ]; then
    TARGETS=$(bazel query "rdeps(${UNIVERSE}, set(${files[*]}))")
elif [ "${BAZEL_COMMAND:-}" == "test" ]; then
    TARGETS=$(bazel query --skip_incompatible_explicit_targets \
      "kind(test, rdeps(${UNIVERSE}, set(${files[*]})))
         except attr('tags', 'manual|system_test_hourly|system_test_nightly|system_test_staging|system_test_hotfix|system_test_nightly_nns', //...)")
else
    echo "Unknown BAZEL_COMMAND: ${BAZEL_COMMAND:-}" >&2
    exit 1
fi

echo "$TARGETS" | tr '\n' ' ' | sed -e 's/,$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
set +x
