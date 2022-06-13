#!/usr/bin/env bash

set -eEuo pipefail

REPO_ROOT="$(
    cd "$(dirname "$0")"
    git rev-parse --show-toplevel
)"
cd "$REPO_ROOT"/gitlab-ci/docker

# print sha of relevant files
sha256sum Dockerfile* entrypoint.sh | sha256sum | cut -d' ' -f1
