#!/usr/bin/env bash

set -eEuo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"/gitlab-ci/container

# print sha of relevant files
sha256sum Dockerfile* files/* ../../requirements.txt ../../.bazelversion | sha256sum | cut -d' ' -f1
