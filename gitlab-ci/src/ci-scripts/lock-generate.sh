#!/usr/bin/env bash

set -eufo pipefail

EXIT_STATUS=0

# Update the cargo lockfile, if necessary
cargo update --workspace

# Repin the bazel crates, if necessary
./bin/bazel-pin.sh

# Stage files and check if anything changed
git add Cargo.lock Cargo.Bazel.*.lock
git status
if ! git diff --cached --quiet; then
    # If this is running from a pull request then update the Cargo.lock file in the PR
    # automatically.
    if [ "$CI_PIPELINE_SOURCE" = "pull_request" ]; then
        # There are some changes staged
        git config --global user.email "infra+github-automation@dfinity.org"
        git config --global user.name "IDX GitHub Automation"
        git commit -m "Automatically updated Cargo*.lock"
        git push
    fi

    # Because the lockfiles need updating, fail the PR
    EXIT_STATUS=1
fi

exit "${EXIT_STATUS}"
