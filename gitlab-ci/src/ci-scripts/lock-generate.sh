#!/usr/bin/env bash

set -eufo pipefail

EXIT_STATUS=0

# Check that cargo lock file needs to be regenerated.
cargo check -p ic-sys

# Check that bazel lock file needs to be regenerated.
if ! bazel query @crate_index//:all; then
    CARGO_BAZEL_REPIN=1 bazel sync --only=crate_index
    # Verify that it fixed.
    bazel query @crate_index//:all
    # Ensure pipeline will fail.
    EXIT_STATUS=1
fi

# The same for fuzzing build
if ! SANITIZERS_ENABLED=1 bazel query @crate_index//:all; then
    SANITIZERS_ENABLED=1 CARGO_BAZEL_REPIN=1 bazel sync --only=crate_index
    # Verify that it fixed.
    SANITIZERS_ENABLED=1 bazel query @crate_index//:all
    # Ensure pipeline will fail.
    EXIT_STATUS=1
fi

git add Cargo.lock Cargo.Bazel.*.lock
git status
if ! git diff --cached --quiet; then
    # If a merge request and not on a merge train then update the Cargo.lock file in the MR automatically.
    if [ "$CI_PIPELINE_SOURCE" = "merge_request_event" ] && [ "$CI_MERGE_REQUEST_EVENT_TYPE" != "merge_train" ]; then
        # There are some changes staged
        # Command might fail because the gitlab remote already exists from a previous run.
        git remote add origin "https://gitlab-ci-token:${GITLAB_API_TOKEN}@gitlab.com/${CI_PROJECT_PATH}.git" || true
        git remote set-url origin "https://gitlab-ci-token:${GITLAB_API_TOKEN}@gitlab.com/${CI_PROJECT_PATH}.git" || true
        git config --global user.email "infra+gitlab-automation@dfinity.org"
        git config --global user.name "IDX GitLab Automation"
        git commit -m "Automatically updated Cargo*.lock"
        git push origin HEAD:"${CI_COMMIT_REF_NAME}"
    fi
    EXIT_STATUS=1
fi

exit "${EXIT_STATUS}"
