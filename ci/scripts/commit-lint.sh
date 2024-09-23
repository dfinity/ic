#!/usr/bin/env bash

set -eEuo pipefail

git config --global user.email "idx@dfinity.org"
git config --global user.name "IDX GitLab Automation"

if ! cog verify "${CI_PULL_REQUEST_TITLE}"; then
    echo "Your commit message -m '${CI_PULL_REQUEST_TITLE}' does not respect conventional commit conventions" >&2
    echo "Please visit https://www.conventionalcommits.org/en/v1.0.0/ to learn more about conventional commit" >&2
    exit 1
fi
