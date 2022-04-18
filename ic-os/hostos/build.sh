#!/usr/bin/env bash
# Builds the IC hostOS image

set -eo pipefail

function usage() {
    cat <<EOF
Usage:
  build [-p password]

  Build whole disk of IC host OS VM image.

  -p password: Set root password for console access. BE CAREFUL.

  TODO
EOF
}

while getopts "p:v:" OPT; do
    case "${OPT}" in
        p)
            ROOT_PASSWORD="${OPTARG}"
            ;;
        v)
            VERSION="${OPTARG}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

BASE_DIR=$(dirname "${BASH_SOURCE[0]}")
SCRIPTS_DIR=$BASE_DIR/../scripts

docker version

trap "rm -rf bootloader.tar rootfs.tar cid" EXIT

VERSION=${VERSION:-$(git rev-parse HEAD)}
echo "Set version"
echo "${VERSION}" >"${BASE_DIR}/rootfs/opt/ic/share/version.txt"
echo "${VERSION}" >"${BASE_DIR}/rootfs/boot/version.txt"

$SCRIPTS_DIR/build-docker-save.sh $BASE_DIR/bootloader >$BASE_DIR/bootloader.tar
$SCRIPTS_DIR/build-docker-save.sh \
    --build-arg ROOT_PASSWORD="${ROOT_PASSWORD}" \
    $BASE_DIR/rootfs >$BASE_DIR/rootfs.tar

IMAGE_ID=$(
    docker build -q -f $BASE_DIR/build/Dockerfile $BASE_DIR/.. 2>&1 \
        | tee /dev/fd/2 \
        | sed -e 's/sha256:\([0-9a-f]\{64\}\)/\1/' -e t -e d
)
docker run -h builder --cidfile cid --privileged $IMAGE_ID
CONTAINER_ID=$(cat cid)
docker cp $CONTAINER_ID:/ic-os/disk-img.tar.gz disk-img.tar.gz
docker cp $CONTAINER_ID:/ic-os/update-img.tar.gz update-img.tar.gz
docker rm $CONTAINER_ID
