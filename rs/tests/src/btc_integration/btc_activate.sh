#!/bin/sh
cp /config/bitcoin.conf /tmp/bitcoin.conf
docker load -i /config/image.tar
docker run --name=bitcoind-node -d \
    --net=host \
    -v /tmp:/bitcoin/.bitcoin \
    bazel/image:image -rpcbind=[::]:8332 -rpcallowip=::/0
