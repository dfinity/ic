#!/usr/bin/env bash

# Load and start the bitcoind docker image

set -euo pipefail

cp /config/bitcoin.conf /tmp/bitcoin.conf
docker load -i /config/bitcoind.tar
docker run --name=bitcoind-node -d \
    --net=host \
    -v /tmp:/bitcoin/.bitcoin \
    bitcoind:pinned -rpcbind='[::]:8332' -rpcallowip='::/0'
