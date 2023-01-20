#!/usr/bin/env bash

set -e

if [ -e /var/run/docker.sock ]; then
    docker-bin "$@"
else
    sudo podman "$@"
fi
