#!/usr/bin/env bash

# Build bootable full disk image containing the initial system image.

set -eo pipefail

# -----------------------------------------------------------------------

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

# -----------------------------------------------------------------------

BASE_DIR=$(dirname "${BASH_SOURCE[0]}")/..
source "${BASE_DIR}"/scripts/partitions.sh

TMPDIR=$(mktemp -d -t build-image-XXXXXXXXXXXX)
UPDATE_DIR=$(mktemp -d -t build-image-XXXXXXXXXXXX)
trap "rm -rf $TMPDIR $UPDATE_DIR" exit

DISK_IMG="disk.img"

# Build bootloader partitions.
BOOTLOADER_TAR="bootloader.tar"
ESP_IMG="${TMPDIR}/esp.img"
GRUB_IMG="${TMPDIR}/grub.img"
truncate --size 100M "$ESP_IMG"
truncate --size 100M "$GRUB_IMG"
build_bootloader_from_tar "$ESP_IMG" "$GRUB_IMG" <"${BOOTLOADER_TAR}"

# Prepare empty config partition.
CONFIG_IMG="${TMPDIR}/config.img"
truncate --size 100M "$CONFIG_IMG"
make_ext4fs -T 0 -l 100M "$CONFIG_IMG"

# Prepare partitions for system image A.
UBUNTU_TAR="rootfs.tar"
BOOT_IMG="${TMPDIR}/boot.img"
ROOT_IMG="${TMPDIR}/root.img"
"${BASE_DIR}"/scripts/build-ubuntu.sh -i "${UBUNTU_TAR}" -r "${ROOT_IMG}" -b "${BOOT_IMG}"

# Update Image
# HACK: allow running without explicitly given version, extract version
# from rootfs. This is NOT good, but workable for the moment.
VERSION=$(debugfs "${ROOT_IMG}" -R "cat /opt/ic/share/version.txt")

echo "${VERSION}" >"${UPDATE_DIR}/VERSION.TXT"
cp "${TMPDIR}/boot.img" "${UPDATE_DIR}/boot.img"
cp "${TMPDIR}/root.img" "${UPDATE_DIR}/root.img"
# Sort by name in tar file -- makes ordering deterministic and ensures
# that VERSION.TXT is first entry, making it quick & easy to extract.
# Override owner, group and mtime to make build independent of the user
# building it.
tar czf "update-img.tar.gz" --sort=name --owner=root:0 --group=root:0 --mtime='UTC 2020-01-01' --sparse -C "${UPDATE_DIR}" .

# Format LVM structure and write images into place
VOLUME_GROUP="hostlvm"
LVM_IMG="${TMPDIR}/lvm.img"
prepare_lvm_image "$LVM_IMG" 107374182400 "$VOLUME_GROUP" "4c7GVZ-Df82-QEcJ-xXtV-JgRL-IjLE-hK0FgA" "eu0VQE-HlTi-EyRc-GceP-xZtn-3j6t-iqEwyv" # 100G

# Assemble all partitions
prepare_disk_image "$DISK_IMG" 108447924224 # 101G
write_single_partition "$DISK_IMG" esp "$ESP_IMG"
write_single_partition "$DISK_IMG" grub "$GRUB_IMG"
write_single_partition "$DISK_IMG" hostlvm "$LVM_IMG"
write_single_lvm_volume "$DISK_IMG" "$VOLUME_GROUP" A_boot "$BOOT_IMG"
write_single_lvm_volume "$DISK_IMG" "$VOLUME_GROUP" A_root "$ROOT_IMG"
write_single_lvm_volume "$DISK_IMG" "$VOLUME_GROUP" config "$CONFIG_IMG"

# Package image in tar
tar --sparse -czaf disk-img.tar.gz "$DISK_IMG"
rm "$DISK_IMG"
