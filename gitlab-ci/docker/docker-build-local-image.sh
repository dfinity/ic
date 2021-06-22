#!/usr/bin/env bash
# Prepare the Docker container image

set -eEuo pipefail

REPO_ROOT="$(
    cd "$(dirname "$0")"
    git rev-parse --show-toplevel
)"
cd "$REPO_ROOT"

VERSION=$(cat "$REPO_ROOT/gitlab-ci/docker/TAG")

# Note: This code builds the docker image via a cron job on the trusted builders
# The trusted builders must have the gitlab registry tags on the image. Please
# do not change this code with speaking with Ali Piccioni or Sasa Tomic.

# Build the container image
DOCKER_BUILDKIT=1 docker build \
    --tag ic-build:$VERSION \
    --tag dfinity/ic-build:$VERSION \
    --tag dfinity/ic-build:latest \
    --tag registry.gitlab.com/dfinity-lab/core/docker/ic-build:$VERSION \
    -f gitlab-ci/docker/Dockerfile .

# Build the container image with support for nix
DOCKER_BUILDKIT=1 docker build \
    --tag ic-build-nix:$VERSION \
    --tag dfinity/ic-build-nix:$VERSION \
    --tag dfinity/ic-build-nix:latest \
    --tag registry.gitlab.com/dfinity-lab/core/docker/ic-build-nix:$VERSION \
    -f gitlab-ci/docker/Dockerfile.withnix .
