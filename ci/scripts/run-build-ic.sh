#!/usr/bin/env bash

set -euo pipefail
VERSION=$(git rev-parse HEAD)

cd "$CI_PROJECT_DIR"

protected_branches=("master" "rc--*" "hotfix-*" "master-private")

# if we are on a protected branch or targeting a rc branch we set ic_version to the commit_sha and upload to s3
for pattern in "${protected_branches[@]}"; do
    if [[ "$BRANCH_NAME" == $pattern ]]; then
        IS_PROTECTED_BRANCH="true"
        break
    fi
done

# run build with release on protected branches or if a pull_request is targeting an rc branch
if [ "${IS_PROTECTED_BRANCH:-}" == "true" ] || [[ "${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-}" == "rc--"* ]]; then
    ci/container/build-ic.sh -i -c -b
# otherwise build with no release
else
    ci/container/build-ic.sh -i -c -b --no-release
fi
