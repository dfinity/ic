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
# check if the job requested running only on diff, otherwise run full build with no release
elif [[ "${RUN_ON_DIFF_ONLY:-}" == "true" ]]; then
    TARGETS=$(ci/bazel-scripts/diff.sh)
    ARGS=(--no-release)

    if [ "$TARGETS" == "//..." ]; then
        ARGS+=(-i -c -b)
    else
        if grep -q "ic-os" <<<"$TARGETS"; then
            ARGS+=(-i)
        fi
        if grep -q "publish/canisters" <<<"$TARGETS"; then
            ARGS+=(-c)
        fi
        if grep -q "publish/binaries" <<<"$TARGETS"; then
            ARGS+=(-b)
        fi
    fi

    if [ ${#ARGS[@]} -eq 1 ]; then
        if [ "${IS_PROTECTED_BRANCH:-}" == "true" ]; then
            echo "Error: No changes to build on protected branch. Aborting."
            exit 1
        fi
        echo "No changes that require building IC-OS, binaries or canisters."
        exit 0
    fi
    ci/container/build-ic.sh "${ARGS[@]}"
# otherwise run full build but with no release
else
    ci/container/build-ic.sh -i -c -b --no-release
fi
