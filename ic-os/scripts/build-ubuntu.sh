#!/usr/bin/env bash

# Build ubuntu system image -- this consists of the "boot" and "root"
# filesystem images.

set -eo pipefail

function usage() {
    cat <<EOF
Usage:
  build-ubuntu -r root.img -b boot.img -i docker.tar

  Build boot and root filesystem of Ubuntu system image.

  -r root.img: Target to write the root partition image to.
  -b boot.img: Target to write the boot partition image to.
  -i docker.tar: Points to the output of "docker save"
     of the ubuntu docker image. If not given, will implicitly call
     docker build.
EOF
}

# Build ubuntu filesystem images: This consists of the "boot" and
# "root" filesystems.
#
# Arguments:
# - $1: name of the root fs image file
# - $2: name of the boot fs image file
#
# Both image files must be files truncated to a suitable size to build
# the filesystem images into.
#
# This function expects the "tar" output from "docker save" as stdin.
function build_ubuntu_from_tar() {
    local ROOTFS_IMG="$1"
    local BOOTFS_IMG="$2"

    local FAKEROOT_STATE_FILE=$(mktemp -t fakerootstate-XXXXXXXXXXXX)
    local FS_TMPDIR=$(mktemp -d -t fs-XXXXXXXXXXXX)

    fakeroot -s "$FAKEROOT_STATE_FILE" "${BASE_DIR}"/scripts/docker_extract.py "$FS_TMPDIR"

    # Call into helper program such that everything can run under a single
    # fakeroot session (see explanation inside).
    fakeroot -i "$FAKEROOT_STATE_FILE" -- "${BASE_DIR}/scripts/build-boot-and-root-fsimage.sh" "$FS_TMPDIR" "$ROOTFS_IMG" "$BOOTFS_IMG"

    rm -rf "$FAKEROOT_STATE_FILE" "$FS_TMPDIR"
}

while getopts "i:r:b:" OPT; do
    case "${OPT}" in
        i)
            IN_FILE="${OPTARG}"
            ;;
        b)
            OUT_BOOT_IMG="${OPTARG}"
            ;;
        r)
            OUT_ROOT_IMG="${OPTARG}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

BOOT_IMG="${OUT_BOOT_IMG}"
ROOT_IMG="${OUT_ROOT_IMG}"

BASE_DIR=$(dirname "${BASH_SOURCE[0]}")/..

if [ "${OUT_BOOT_IMG}" == "" -o "${OUT_ROOT_IMG}" == "" -o "${IN_FILE}" == "" ]; then
    echo "boot, root,and input image must be given"
    usage
    exit 1
fi

# Truncate to zero first to ensure there are no left-overs.
truncate --size 0 "${BOOT_IMG}"
truncate --size 0 "${ROOT_IMG}"
truncate --size 100M "${BOOT_IMG}"
truncate --size 3G "${ROOT_IMG}"

build_ubuntu_from_tar "${ROOT_IMG}" "${BOOT_IMG}" <"${IN_FILE}"
