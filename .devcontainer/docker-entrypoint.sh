#!/usr/bin/env bash

DOCKER_SOCKET=/var/run/docker.sock
DOCKER_GROUP=docker
USER=ubuntu

if [ -S "$DOCKER_SOCKET" ]; then
    DOCKER_GID="$(stat -c '%g' "$DOCKER_SOCKET")"
    if ! getent group "$DOCKER_GID"; then
        sudo addgroup --gid $DOCKER_GID $DOCKER_GROUP
    fi
    sudo usermod -aG $DOCKER_GID $USER
fi

exec "$@"
