#!/usr/bin/env bash

# Load the vector docker image and start the service

set -euo pipefail

find /config -name *.tar -exec docker load -i {} \;

mkdir -p /etc/vector/generated-config

docker run -d --name vector \
    --entrypoint vector \
    -e VECTOR_WATCH_CONFIG=true \
    -v /etc/vector/generated-config:/etc/vector/generated-config \
    vector-with-log-fetcher:image \
    --config-dir /etc/vector/config \
    --config-dir /etc/vector/generated-config
