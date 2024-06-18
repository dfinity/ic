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

# print node name for easier debugging
if [ -n "${NODE_NAME:-}" ]; then
    echo "Node: $NODE_NAME"
fi

if [ "$(uname)" == "Linux" ]; then
    # TODO: patch runner & runner manifest for cleaner bind mount
    # Temporary way to bring required directories to workflow container:
    if [ -e /__w/cache ]; then
        sudo ln -s /__w/cache /
    fi
    if [ -e /__w/ceph-s3-info ]; then
        sudo ln -s /__w/ceph-s3-info /
    fi
    if [ -e /__w/var/tmp ] && [ ! -e /var/tmp ]; then
        sudo ln -s /__w/var/tmp /var/tmp
    fi
    if [ -e /__w/var/sysimage ] && [ ! -e /var/sysimage ]; then
        sudo ln -s /__w/var/sysimage /var/sysimage
    fi
fi
