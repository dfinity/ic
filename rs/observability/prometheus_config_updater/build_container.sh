#!/usr/bin/bash

image_name="registry.gitlab.com/dfinity-lab/core/release/prometheus-config-updater:master"

pushd $(git rev-parse --show-toplevel)
docker build \
    -t "$image_name" \
    -f rs/observability/prometheus_config_updater/Dockerfile.prometheus-config-updater \
    .
popd
docker push $image_name
