#!/usr/bin/env bash

# Load the vector docker image and start the service

set -euo pipefail

find /config -name *.tar -exec docker load -i {} \;

mkdir -p /etc/vector/config
chown 1000:1000 /etc/vector/config

docker run -d --name vector \
    --entrypoint vector \
    -e VECTOR_WATCH_CONFIG=true \
    -v /etc/vector/config:/etc/vector/config \
    --network host \
    --restart on-failure \
    vector-with-log-fetcher:image \
    --config-dir /etc/vector/config \
