#!/usr/bin/env bash

set -euo pipefail

# Used by ic_version_or_git_sha
commit_sha=$(git rev-parse HEAD)
echo "COMMIT_SHA $commit_sha"

# Used by ic_version_or_git_sha
git_tree_status=$(git diff-index --quiet HEAD -- && echo 'Clean' || echo 'Modified')
echo "GIT_TREE_STATUS $git_tree_status"

# Used to read credentials for S3 upload
echo "HOME ${HOME}"

# Used as farm metadata
test -n "${CI_JOB_NAME:-}" && echo "CI_JOB_NAME ${CI_JOB_NAME}"
if [[ -n "${USER:-}" ]]; then
    echo "USER ${USER}"
elif [[ -n "${HOSTUSER:-}" ]]; then
    echo "USER ${HOSTUSER}"
fi

# Generate a file that changes every time bazel runs. It can be used as dependency for targets we want to always rebuild.
workspace_root="$(git rev-parse --show-toplevel)"
date '+%s' >"$workspace_root/bazel-timestamp.txt"
