#!/usr/bin/env bash

set -e

if [ -e /var/run/docker.sock ]; then
    docker-bin "$@"
else
    # set podman's root on tmpfs
    mkdir -p /tmp/tmpfs
    if ! mount | grep -q tmp-tmpfs; then
        sudo mount -t tmpfs tmp-tmpfs /tmp/tmpfs
    fi

    sudo podman --root /tmp/tmpfs/podman_root "$@"
fi
