#!/usr/bin/env bash

# Load the vector docker image and start the service

set -euo pipefail

find /config -name *.tar -exec docker load -i {} \;

mkdir -p /etc/vector/config
chown 1000:1000 -R /etc/vector/config
