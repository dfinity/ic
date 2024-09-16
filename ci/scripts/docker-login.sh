#!/usr/bin/env bash

set -eEuo pipefail

# login to docker hub to avoid rate limit disruptions
if which docker 2>/dev/null; then
    docker login -u "$DOCKER_HUB_USER" -p "$DOCKER_HUB_PASSWORD_RO"
fi
# docker-bin used by container_pull in WORKSPACES.bazel
if which docker-bin 2>/dev/null; then
    # save auth to user's .docker/config.json
    docker-bin login -u "$DOCKER_HUB_USER" -p "$DOCKER_HUB_PASSWORD_RO"
    # save auth to root's .docker/config.json
    sudo docker-bin login -u "$DOCKER_HUB_USER" -p "$DOCKER_HUB_PASSWORD_RO"
fi
