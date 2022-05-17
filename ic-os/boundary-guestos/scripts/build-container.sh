#!/usr/bin/env bash

# Build the node as a docker container. If called with no arguments,
# outputs the ID of the built docker image on stdout.
#
# If called with a single argument, tags the generated image after build
# using the given tag.

set -e

BUILD_TAG="$1"

BASE_DIR=$(dirname "${BASH_SOURCE[0]}")/..

# Perform docker build and return the id of the built docker image.
function build_docker_return_id() {
    DOCKER_ID=$(
        # Account for two different output formats of docker command:
        # "classic" docker and "buildkit" docker
        docker build $* 2>&1 | tee >(cat 1>&2) | sed -e 's/Successfully built //' -e t -e 's/.*writing image sha256:\([0-9a-f]\+\).*/\1/' -e t -e d
    )

    echo "${DOCKER_ID}"
}

UBUNTU_ROOTFS_DOCKER_ID=$(build_docker_return_id "${BASE_DIR}/rootfs")

if [ ! -e ${BASE_DIR}/containerfs/etc/ssh/ssh_host_dsa_key ]; then
    ssh-keygen -A -f ${BASE_DIR}/containerfs/
fi

UBUNTU_CONTAINERFS_ID=$(build_docker_return_id --build-arg UBUNTU_ROOTFS="${UBUNTU_ROOTFS_DOCKER_ID}" "${BASE_DIR}/containerfs")

if [ "${BUILD_TAG}" != "" ]; then
    docker tag "${UBUNTU_CONTAINERFS_ID}" "${BUILD_TAG}"
else
    echo "${UBUNTU_CONTAINERFS_ID}"
fi
