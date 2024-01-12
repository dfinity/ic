#!/bin/bash
#
# Script for building and uploading the service discovery container
# used to discovery the scraping targets for metrics and logs.
#
# Update the tag below, and then run the code: `./container-rebuild.sh`
#

set -eExuo pipefail

BUILD_TARGET=multiservice_discovery
BUILD_TAG=0.3.4

echo "#########################################"
echo "Building $BUILD_TARGET:$BUILD_TAG"
echo "#########################################"

bazel build //rs/observability/multiservice_discovery:multiservice_discovery

TOPLEVEL=$(git rev-parse --show-toplevel)
cd "$TOPLEVEL"
TMP_BUILD_DIR="$TOPLEVEL/build-dir-service-discovery"
mkdir -p "$TMP_BUILD_DIR"
cp -f -L "$TOPLEVEL/bazel-bin/rs/observability/multiservice_discovery/multiservice_discovery" "$TMP_BUILD_DIR"

podman build -t $BUILD_TARGET:$BUILD_TAG $TOPLEVEL -f $TOPLEVEL/rs/observability/$BUILD_TARGET/Dockerfile

podman push $BUILD_TARGET:$BUILD_TAG registry.gitlab.com/dfinity-lab/core/release/$BUILD_TARGET:$BUILD_TAG

rm -f "$TOPLEVEL/build-dir/multiservice_discovery"
rmdir "$TOPLEVEL/build-dir"
