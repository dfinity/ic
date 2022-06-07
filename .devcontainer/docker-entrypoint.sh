#!/usr/bin/env bash

DOCKER_SOCKET=/var/run/docker.sock
DOCKER_GROUP=docker
USER=ubuntu

if [ -S "$DOCKER_SOCKET" ]; then
    DOCKER_GID="$(stat -c '%g' "$DOCKER_SOCKET")"
    sudo addgroup --gid $DOCKER_GID $DOCKER_GROUP
    sudo usermod -aG $DOCKER_GROUP $USER
fi

exec "$@"
