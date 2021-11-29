#!/usr/bin/env bash
# Builds the IC-OS image

set -eo pipefail

function usage() {
    cat <<EOF
Usage:
  build-macos [-p password]

  Build whole disk of IC guest OS VM image.

  -p password: Set root password for console access. BE CAREFUL.
EOF
}

while getopts "p:" OPT; do
    case "${OPT}" in
        p)
            ROOT_PASSWORD="${OPTARG}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

SCRIPTS_DIR=$(dirname "${BASH_SOURCE[0]}")
BASE_DIR=$SCRIPTS_DIR/..

docker version

trap "rm -rf bootloader.tar rootfs.tar" EXIT
$SCRIPTS_DIR/build-docker-save.sh $BASE_DIR/bootloader >bootloader.tar
$SCRIPTS_DIR/build-docker-save.sh \
    --build-arg ROOT_PASSWORD="${ROOT_PASSWORD}" \
    $BASE_DIR/rootfs >rootfs.tar

IMAGE_ID=$(
    docker build -f $SCRIPTS_DIR/Dockerfile.macos $BASE_DIR 2>&1 \
        | tee /dev/fd/2 \
        | sed -e 's/.*writing image sha256:\([0-9a-f]\{64\}\) .*/\1/' -e t -e d
)
CONTAINER_ID=$(docker create $IMAGE_ID)
docker cp $CONTAINER_ID:/ic-os.img.tar ic-os.img.tar
docker rm $CONTAINER_ID
