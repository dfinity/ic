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
    # If a pull request then update the Cargo.lock file in the MR automatically.
    if [ "$CI_PIPELINE_SOURCE" = "pull_request" ]; then
        # There are some changes staged
        if [ -z ${GITHUB_ACTION+x} ]; then
            # On GitLab we have to point the origin to GitLab
            # Command might fail because the gitlab remote already exists from a previous run.
            git remote add origin "https://gitlab-ci-token:${GITLAB_API_TOKEN}@gitlab.com/${CI_PROJECT_PATH}.git" || true
            git remote set-url origin "https://gitlab-ci-token:${GITLAB_API_TOKEN}@gitlab.com/${CI_PROJECT_PATH}.git" || true
            git config --global user.email "infra+gitlab-automation@dfinity.org"
            git config --global user.name "IDX GitLab Automation"
        else
            # On GitHub the origin is already set correctly.
            git config --global user.email "infra+github-automation@dfinity.org"
            git config --global user.name "IDX GitHub Automation"
        fi
        git commit -m "Automatically updated Cargo*.lock"
        git push
    fi
    EXIT_STATUS=1
fi

exit "${EXIT_STATUS}"
