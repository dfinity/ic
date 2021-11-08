#!/usr/bin/env bash
# Prepare the Docker container image

set -eEuo pipefail

REPO_ROOT="$(
    cd "$(dirname "$0")"
    git rev-parse --show-toplevel
)"
cd "$REPO_ROOT"

VERSION=$(cat "$REPO_ROOT/gitlab-ci/docker/TAG")
SHA1ICBUILD=$("$REPO_ROOT/gitlab-ci/src/docker_image_check/docker_sha.py" Dockerfile)
SHA1ICBUILDNIX=$("$REPO_ROOT/gitlab-ci/src/docker_image_check/docker_sha.py" Dockerfile.withnix)

# Capsule is a project optimizing the CI build, it may be omitted outside of CI.
CAPSULE_TOKEN="${CAPSULE_TOKEN:-}"
GITLAB_TOKEN="${GITLAB_TOKEN:-}"

# Note: This code builds the docker image via a cron job on the trusted builders
# The trusted builders must have the gitlab registry tags on the image. Please
# do not change this code with speaking with Ali Piccioni or Sasa Tomic.

cd "$REPO_ROOT/gitlab-ci/docker"

# Build the container image
DOCKER_BUILDKIT=1 docker build \
    --build-arg CAPSULE_TOKEN="${CAPSULE_TOKEN}" \
    --build-arg GITLAB_TOKEN="${GITLAB_TOKEN}" \
    --tag ic-build:"$VERSION" \
    --tag dfinity/ic-build:"$VERSION" \
    --tag dfinity/ic-build:latest \
    --tag registry.gitlab.com/dfinity-lab/core/docker/ic-build:"$VERSION"-"$SHA1ICBUILD" \
    -f Dockerfile .

# Build the container image with support for nix
DOCKER_BUILDKIT=1 docker build \
    --build-arg CAPSULE_TOKEN="${CAPSULE_TOKEN}" \
    --build-arg GITLAB_TOKEN="${GITLAB_TOKEN}" \
    --tag ic-build-nix:"$VERSION" \
    --tag dfinity/ic-build-nix:"$VERSION" \
    --tag dfinity/ic-build-nix:latest \
    --tag registry.gitlab.com/dfinity-lab/core/docker/ic-build-nix:"$VERSION"-"$SHA1ICBUILDNIX" \
    -f Dockerfile.withnix .

cd -
