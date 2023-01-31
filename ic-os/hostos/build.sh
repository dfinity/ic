#!/usr/bin/env bash
# Builds the IC hostOS image

set -eo pipefail

function usage() {
    cat <<EOF
Usage:
  build [-p password]

  Build whole disk of IC host OS VM image.

  -p password: Set root password for console access. BE CAREFUL.

  -t image type: The type of image to build. Must be either "dev" or "prod".
     If nothing is specified, defaults to building "prod" image.

  -v version: The version written into the image; mandatory

EOF
}

BUILD_TYPE=prod
while getopts "p:v:t:" OPT; do
    case "${OPT}" in
        p)
            ROOT_PASSWORD="${OPTARG}"
            ;;
        t)
            BUILD_TYPE="${OPTARG}"
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

if [ "${BUILD_TYPE}" != "dev" -a "${BUILD_TYPE}" != "prod" ]; then
    echo "Unknown build type: ${BUILD_TYPE}" >&2
    exit 1
fi

if [ "${ROOT_PASSWORD}" != "" -a "${BUILD_TYPE}" != "dev" ]; then
    echo "Root password is valid only for build type 'dev'" >&2
    exit 1
fi

BASE_DIR=$(dirname "${BASH_SOURCE[0]}")
TMPDIR=$(mktemp -d)
SCRIPTS_DIR=$BASE_DIR/../scripts

docker version

trap "rm -rf bootloader.tar rootfs.tar" EXIT

BASE_IMAGE="$(cat ${BASE_DIR}/rootfs/docker-base.${BUILD_TYPE})"

VERSION=${VERSION:-$(git rev-parse HEAD)}
echo "Set version"
echo "${VERSION}" >"${BASE_DIR}/rootfs/opt/ic/share/version.txt"
echo "${VERSION}" >"${BASE_DIR}/rootfs/boot/version.txt"

$SCRIPTS_DIR/build-docker-save.sh $BASE_DIR/bootloader >$BASE_DIR/bootloader.tar
$SCRIPTS_DIR/build-docker-save.sh \
    --build-arg BASE_IMAGE="${BASE_IMAGE}" \
    --build-arg ROOT_PASSWORD="${ROOT_PASSWORD}" \
    $BASE_DIR/rootfs >$BASE_DIR/rootfs.tar

docker build --iidfile $TMPDIR/iidfile -q -f $BASE_DIR/build/Dockerfile $BASE_DIR/.. 2>&1
IMAGE_ID=$(cat $TMPDIR/iidfile | cut -d':' -f2)

docker run -h builder --cidfile $TMPDIR/cid --privileged $IMAGE_ID
CONTAINER_ID=$(cat $TMPDIR/cid)
docker cp $CONTAINER_ID:/ic-os/disk-img.tar.gz disk-img.tar.gz
docker cp $CONTAINER_ID:/ic-os/update-img.tar.gz update-img.tar.gz
docker rm $CONTAINER_ID

rm -rf $TMPDIR
