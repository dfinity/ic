#!/usr/bin/env bash

DOCKER_SOCKET=/var/run/docker.sock
DOCKER_GROUP=docker

grep -q $DOCKER_GROUP /etc/group
DOCKER_GREP_RET=$?

if [ -S $DOCKER_SOCKET ] && [ $DOCKER_GREP_RET -ne 0 ]; then
    DOCKER_GID=$(stat -c '%g' $DOCKER_SOCKET)

    sudo addgroup --gid $DOCKER_GID $DOCKER_GROUP
    sudo usermod -aG $DOCKER_GROUP ubuntu
fi

exec gosu ubuntu "$@"
