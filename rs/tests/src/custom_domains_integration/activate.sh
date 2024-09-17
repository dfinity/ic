#!/run/current-system/sw/bin/bash

# load all necessary images

docker load -i "/config/coredns.tar"
docker load -i "/config/pebble.tar"
docker load -i "/config/python3.tar"
docker load -i "/config/openssl.tar"
