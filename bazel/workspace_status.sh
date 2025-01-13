#!/usr/bin/env bash

set -euo pipefail

function remove_url_credentials() {
    sed -Ee 's#//[^:]*:[^@]*@#//#'
}

repo_url=$(git config --get remote.origin.url | remove_url_credentials)
echo "REPO_URL $repo_url"

commit_sha=$(git rev-parse HEAD)
echo "COMMIT_SHA $commit_sha"

git_branch=$(git rev-parse --abbrev-ref HEAD)
echo "GIT_BRANCH $git_branch"

git_tree_status=$(git diff-index --quiet HEAD -- && echo 'Clean' || echo 'Modified')
echo "GIT_TREE_STATUS $git_tree_status"

WORKSPACE_ROOT="$(git rev-parse --show-toplevel)"
echo "STABLE_WORKSPACE_ROOT ${WORKSPACE_ROOT}"

echo "HOME ${HOME}"

test -n "${CI_RUN_ID:-}" && echo "CI_RUN_ID ${CI_RUN_ID}"
test -n "${CI_JOB_NAME:-}" && echo "CI_JOB_NAME ${CI_JOB_NAME}"
test -n "${CI_RUNNER_TAGS:-}" && echo "CI_RUNNER_TAGS ${CI_RUNNER_TAGS}"

if [[ -n "${USER:-}" ]]; then
    echo "USER ${USER}"
elif [[ -n "${HOSTUSER:-}" ]]; then
    echo "USER ${HOSTUSER}"
fi

# Generate a file that changes every time bazel runs. It can be used as dependency for targets we want to always rebuild.
date '+%s' >"${WORKSPACE_ROOT}/bazel-timestamp.txt"
