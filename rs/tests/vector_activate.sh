#!/usr/bin/env bash

# Load the vector docker image and start the service

set -euo pipefail

docker load -i /config/vector-with-log-fetcher.tar
docker run -d --name vector \
    --entrypoint vector \
    -e VECTOR_WATCH_CONFIG=true \ 
    ghcr.io/dfinity/dre/log-fetcher \
    --config-dir /etc/vector/config
