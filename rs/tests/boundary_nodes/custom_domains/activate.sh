#!/usr/bin/env bash

# Load docker images for various services. Services are started by the test driver.

set -euo pipefail

# load all necessary images

docker load -i "/config/coredns.tar"
docker load -i "/config/pebble.tar"
docker load -i "/config/python3.tar"
docker load -i "/config/openssl.tar"
