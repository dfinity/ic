#!/usr/bin/env bash

# This script helps us only build bazel targets that have been affected by file
# changes in the branch merging to master
#
# For this we grab a list of files changed compared to the tip of master, a list
# of files that are track by bazel, we than do the intersection of the two sets.
#
# With this intersection we then do a reverse lookup on which target depends on
# the intersection and only test those.
#
# This scripts is inspired by https://github.com/bazelbuild/bazel/blob/master/scripts/ci/ci.sh

set -euxo pipefail

function query_bazel_target {
    local file=$1

    # Perform the bazel query and capture both output and exit status
    query_result=$(bazel query "$file" 2>&1)
    query_exit_status=$?

    if [ $query_exit_status -eq 0 ]; then
        # Query was successful, print the target name (assuming there's only one target per file)
        echo "$query_result"
    else
        if echo "$query_result" | grep -q "no such target"; then
            # Target not declared, treat as benign case but don't print anything
            exit 0
        else
            echo "An error occurred: $query_result" >&2
            exit 1
        fi
    fi
}

cd "$(git rev-parse --show-toplevel)"
git fetch origin master --quiet
commit_range=${COMMIT_RANGE:-$(git merge-base HEAD origin/master)".."}
files_changed_master=$(git diff --name-only "${commit_range}")


bazel_path=()
for file in $files_changed_master; do
    target_name=$(query_bazel_target "$file")

    # only add the target if the query was successful and the target name is not empty
    if [[ $? -eq 0 && -n "$target_name" ]]; then
        bazel_path+=("$target_name")
    fi
done

# if bazel_path is empty, we don't need to run any tests
if [ ${#bazel_path[@]} -eq 0 ]; then
    exit 0
fi

targets=""
if [ "${BAZEL_COMMAND:-}" == "build" ]; then
    targets=$(bazel query "kind(.*_binary, rdeps(//..., set(${bazel_path[*]})))")
elif [ "${BAZEL_COMMAND:-}" == "test" ]; then
    targets=$(bazel query "kind(test, rdeps(//..., set(${bazel_path[*]}))) except attr('tags', 'manual', //...)")
else
    echo "Unknown BAZEL_COMMAND: ${BAZEL_COMMAND:-}" >&2
    exit 1
fi

echo "$targets" | tr '\n' ' ' | sed 's/,$//'
