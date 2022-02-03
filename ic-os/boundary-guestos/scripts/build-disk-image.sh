#!/usr/bin/env bash

# Build bootable full disk image containing the initial system image.

set -eo pipefail

# Take a filesystem tree and turn it into a vfat filesystem image.
#
# Arguments:
# - $1: name of file to build filesystem image in; this must be a file truncated
#   to the desired size of the filesystem to be built
# - $2: base directory of file system tree
function fstree_to_vfat() {
    FS_IMAGE="$1"
    FS_DIR="$2"

    mkfs.vfat -i 0 "${FS_IMAGE}"

    # Create all directories in sorted order
    for d in $(cd "${FS_DIR}" && find . -mindepth 1 -type d | sed -e 's/^\.\///' | sort); do
        faketime "1970-1-1 0" mmd -i "${FS_IMAGE}" "::/$d"
    done

    # Copy all files in sorted order
    for f in $(cd "${FS_DIR}" && find . -mindepth 1 -type f | sed -e 's/^\.\///' | sort); do
        faketime "1970-1-1 0" mcopy -o -i "${FS_IMAGE}" "${FS_DIR}/$f" "::/$f"
    done
}

# Build bootloader -- this consists of the EFI System Partition (ESP) +
# a dedicated partition to hold grub modules and configuration.
#
# Arguments:
# - $1: name of the ESP image file; this must be a file truncated
#   to the desired size of the filesystem to be built
# - $2: name of the grub partition image file; this must be a file truncated
#   to the desired size of the filesystem to be built
#
# The function expects the "bootloader docker tarball" output on stdin.
function build_bootloader_from_tar() {
    ESP_IMAGE="$1"
    GRUB_IMAGE="$2"

    local FAKEROOT_STATE_FILE=$(mktemp -t fakerootstate-XXXXXXXXXXXX)
    local DOCKER_EXTRACT_TMPDIR=$(mktemp -d -t bootloader-XXXXXXXXXXXX)
    fakeroot -s "${FAKEROOT_STATE_FILE}" "${BASE_DIR}"/scripts/docker_extract.py "${DOCKER_EXTRACT_TMPDIR}"

    local EFI_FSDIR="${DOCKER_EXTRACT_TMPDIR}"/boot/efi
    local GRUB_FSDIR="${DOCKER_EXTRACT_TMPDIR}"/boot/grub
    cp bootloader/grub.cfg bootloader/grubenv "${GRUB_FSDIR}"/
    fstree_to_vfat "${ESP_IMAGE}" "${EFI_FSDIR}"
    fstree_to_vfat "${GRUB_IMAGE}" "${GRUB_FSDIR}"

    rm -rf "${DOCKER_EXTRACT_TMPDIR}"
}

function usage() {
    cat <<EOF
Usage:
  build-disk-image -o outfile [-t bootloader.tar] [-u ubuntu.tar] [-b boot.img] [-r root.img] [-x execdir]

  Build whole disk of IC guest OS VM image.

  -o outfile: Name of output file; mandatory
  -t bootloader.tar: Docker save tar of the bootloader build
  -u ubuntu.tar: Docker save tar of the ubuntu system image build
  -p password: Set root password for console access. BE CAREFUL.
  -v version: The version written into the image.
  -x execdir: Set executable source dir. Will take all required IC executables
     from source directory and install it into the correct location before
     building the image.

  -b and -r should be given together, and they are mutually exclusive
  with -u. Both designate where to take the ubuntu system from.
  If neither are given, then this will build the ubuntu system using
  docker behind the scenes.

  If -t is given, then this should be the "docker save" of the
  bootloader build. If this is not given, then this will also be
  built implicitly using docker. Options -x, -p and -v take no effect
  if this is given.
EOF
}

BUILD_TYPE=disk
while getopts "o:t:u:b:r:v:p:x:" OPT; do
    case "${OPT}" in
        o)
            OUT_FILE="${OPTARG}"
            ;;
        t)
            BOOTLOADER_TAR="${OPTARG}"
            ;;
        u)
            UBUNTU_TAR="${OPTARG}"
            ;;
        b)
            IN_BOOT_IMG="${OPTARG}"
            ;;
        r)
            IN_ROOT_IMG="${OPTARG}"
            ;;
        v)
            VERSION="${OPTARG}"
            ;;
        p)
            ROOT_PASSWORD="${OPTARG}"
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

if [ "${OUT_FILE}" == "" ]; then
    usage
    exit 1
fi

BASE_DIR=$(dirname "${BASH_SOURCE[0]}")/..
source "${BASE_DIR}"/scripts/partitions.sh

TMPDIR=$(mktemp -d -t build-image-XXXXXXXXXXXX)
trap "rm -rf $TMPDIR" exit

DISK_IMG="${OUT_FILE}"

# Build bootloader partitions.
ESP_IMG="${TMPDIR}/esp.img"
GRUB_IMG="${TMPDIR}/grub.img"
truncate --size 100M "$ESP_IMG"
truncate --size 100M "$GRUB_IMG"
if [ "${BOOTLOADER_TAR}" == "" ]; then
    "${BASE_DIR}"/scripts/build-docker-save.sh "${BASE_DIR}"/bootloader | build_bootloader_from_tar "$ESP_IMG" "$GRUB_IMG"
else
    build_bootloader_from_tar "$ESP_IMG" "$GRUB_IMG" <"${BOOTLOADER_TAR}"
fi

# Prepare empty config partition.
CONFIG_IMG="${TMPDIR}/config.img"
truncate --size 100M "$CONFIG_IMG"
make_ext4fs -T 0 -l 100M "$CONFIG_IMG"

# Prepare or grab partitions for system image A.
if [ "${IN_BOOT_IMG}" != "" -a "${IN_ROOT_IMG}" != "" ]; then
    BOOT_IMG="${IN_ROOT_IMG}"
    BOOT_IMG="${IN_BOOT_IMG}"
else
    BOOT_IMG="${TMPDIR}/boot.img"
    ROOT_IMG="${TMPDIR}/root.img"
    if [ "${UBUNTU_TAR}" == "" ]; then
        "${BASE_DIR}"/scripts/build-ubuntu.sh -r "${ROOT_IMG}" -b "${BOOT_IMG}" -p "${ROOT_PASSWORD}" -x "${EXEC_SRCDIR}" -v "${VERSION}"
    else
        "${BASE_DIR}"/scripts/build-ubuntu.sh -i "${UBUNTU_TAR}" -r "${ROOT_IMG}" -b "${BOOT_IMG}"
    fi
fi

prepare_disk_image "$DISK_IMG"
write_single_partition "$DISK_IMG" esp "$ESP_IMG"
write_single_partition "$DISK_IMG" grub "$GRUB_IMG"
write_single_partition "$DISK_IMG" config "$CONFIG_IMG"
write_single_partition "$DISK_IMG" A_boot "$BOOT_IMG"
write_single_partition "$DISK_IMG" A_root "$ROOT_IMG"

# XXX: enlarge so there is space after last partition to be used
# -- only relevant for direct use in qemu
truncate --size 50G "$DISK_IMG"
