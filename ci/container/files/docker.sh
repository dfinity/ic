#!/usr/bin/env bash

# drop-in replacement for the 'docker' command that uses podman
# with options required by our build

set -e

# set podman's root on tmpfs
mkdir -p /tmp/tmpfs
if ! mount | grep -q tmp-tmpfs; then
    sudo mount -t tmpfs tmp-tmpfs /tmp/tmpfs
fi

sudo podman --root /tmp/tmpfs/podman_root "$@"
