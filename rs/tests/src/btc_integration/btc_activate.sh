#!/bin/sh
cp /config/bitcoin.conf /tmp/bitcoin.conf
docker load -i /config/image.tar
docker run --name=bitcoind-node -d \
    -p 8332:8332 \
    -p 18444:18444 \
    -v /tmp:/bitcoin/.bitcoin \
    bazel/image:image
