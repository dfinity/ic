#!/usr/bin/env bash

# Build ubuntu system image -- this consists of the "boot" and "root"
# filesystem images.

set -eo pipefail

function usage() {
    cat <<EOF
Usage:
  build-ubuntu -r root.img -b boot.img [-i docker.tar] [-v version] [-x execdir]

  Build boot and root filesystem of Ubuntu system image.

  -r root.img: Target to write the root partition image to.
  -b boot.img: Target to write the boot partition image to.
  -i docker.tar: Points to the output of "docker save"
     of the ubuntu docker image. If not given, will implicitly call
     docker build.
  -p password: Set root password for console access. BE CAREFUL.
  -v version: The version written into the image.
  -x execdir: Set executable source dir. Will take all required IC executables
     from source directory and install it into the correct location before
     building the image.
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

declare -a IC_EXECUTABLES=(boundary-node-control-plane)

# Install IC executables from source to target
#
# Arguments:
# - $1: Source directory for executables
# - $2: Target directory for executables
#
# Will install all required executables to the location
# from where they will be picked up by disk image build.
# Executables are stripped if needed and only copied if
# modified relative to their originals.
function install_executables() {
    local SRCDIR="$1"
    local TGTDIR="$2"
    for EXECUTABLE in "${IC_EXECUTABLES[@]}"; do
        if [ ! -f "${TGTDIR}/${EXECUTABLE}" -o "${SRCDIR}/${EXECUTABLE}" -nt "${TGTDIR}/${EXECUTABLE}" ]; then
            echo "Install and strip ${EXECUTABLE}"
            cp "${SRCDIR}/${EXECUTABLE}" "${TGTDIR}/${EXECUTABLE}"
            if [[ "${EXECUTABLE}" =~ ^(replica|canister_sandbox)$ ]]; then
                echo "not stripping ${EXECUTABLE}"
            else
                echo "stripping ${EXECUTABLE}"
                strip "${TGTDIR}/${EXECUTABLE}"
            fi
        fi
    done
}

# Verify that all files requires for build have been put into suitable place.
# This avoids "broken builds" where the build works just fine, but
# the resulting image lacks things and is not bootable.
#
# Arguments:
# - $1: Target directory to verify
function verify_before_build() {
    local TGTDIR="$1"
    for EXECUTABLE in "${IC_EXECUTABLES[@]}"; do
        if [ ! -f "${TGTDIR}/opt/dfinity/${EXECUTABLE}" ]; then
            echo "Missing executable ${EXECUTABLE} -- build will not succeed."
            exit 1
        fi
    done
    if [ "${VERSION}" != "" ]; then
        if [ ! -f "${TGTDIR}/opt/dfinity/version.txt" -o ! -f "${TGTDIR}/boot/version.txt" ]; then
            echo "Missing version.txt -- build will not succeed."
            exit 1
        fi
    fi
}

while getopts "i:r:b:p:v:x:" OPT; do
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
        p)
            ROOT_PASSWORD="${OPTARG}"
            ;;
        v)
            VERSION="${OPTARG}"
            ;;
        x)
            EXEC_SRCDIR="${OPTARG}"
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

if [ "${OUT_BOOT_IMG}" == "" -o "${OUT_ROOT_IMG}" == "" ]; then
    echo "Both boot and root image output must be given"
    usage
    exit 1
fi

# Truncate to zero first to ensure there are no left-overs.
truncate --size 0 "${BOOT_IMG}"
truncate --size 0 "${ROOT_IMG}"
truncate --size 100M "${BOOT_IMG}"
truncate --size 3G "${ROOT_IMG}"

if [ "${IN_FILE}" != "" ]; then
    build_ubuntu_from_tar "${ROOT_IMG}" "${BOOT_IMG}" <"${IN_FILE}"
else
    if [ "${EXEC_SRCDIR}" != "" ]; then
        install_executables "${EXEC_SRCDIR}" "${BASE_DIR}/rootfs/opt/dfinity"
    fi
    if [ "${VERSION}" != "" ]; then
        echo "Set version"
        echo "${VERSION}" >"${BASE_DIR}/rootfs/opt/dfinity/version.txt"
        echo "${VERSION}" >"${BASE_DIR}/rootfs/boot/version.txt"
    fi
    verify_before_build "${BASE_DIR}/rootfs/"
    if [ "${VERSION}" == "" ]; then
        # HACK to make things buildable without explicitly specifying version.
        VERSION=$(cat "${BASE_DIR}/rootfs/opt/dfinity/version.txt")
    fi

    "${BASE_DIR}"/scripts/build-docker-save.sh \
        --build-arg ROOT_PASSWORD="${ROOT_PASSWORD}" \
        "${BASE_DIR}"/rootfs \
        | build_ubuntu_from_tar "${ROOT_IMG}" "${BOOT_IMG}"
fi
