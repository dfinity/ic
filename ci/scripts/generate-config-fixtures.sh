#!/usr/bin/env bash

set -eufo pipefail

EXIT_STATUS=0

# Generate config fixtures if config types have been updated
bazel run //rs/ic_os/config_types/compatibility_tests:generate_config_types_fixture

# Stage files and check if anything changed
git add rs/ic_os/config_types/compatibility_tests/fixtures
git status
if ! git diff --cached --quiet; then
    # There are some changes staged
    git config --global user.email "infra+github-automation@dfinity.org"
    git config --global user.name "IDX GitHub Automation"
    git commit -m "Automatically updated config type fixtures"
    git push

    # Because the fixtures need updating, fail the PR
    EXIT_STATUS=1
fi

exit "${EXIT_STATUS}"
