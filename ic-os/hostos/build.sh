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
SCRIPTS_DIR=$BASE_DIR/../scripts
TOOL_DIR="${BASE_DIR}/../../toolchains/sysimage/"

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" exit

source "${SCRIPTS_DIR}/partitions.sh" ${BASE_DIR}

docker version

BASE_IMAGE="$(cat ${BASE_DIR}/rootfs/docker-base.${BUILD_TYPE})"

VERSION=${VERSION:-$(git rev-parse HEAD)}
echo "Set version"
echo "${VERSION}" >"${BASE_DIR}/rootfs/opt/ic/share/version.txt"
echo "${VERSION}" >"${BASE_DIR}/rootfs/boot/version.txt"

# Build bootloader image
BOOTLOADER_TAR="${TMPDIR}/bootloader.tar"
$BASE_DIR/bootloader/build-bootloader-tree.sh -o ${BOOTLOADER_TAR}

# Build main image
ROOTFS_TAR=${TMPDIR}/rootfs.tar
$SCRIPTS_DIR/build-docker-save.sh \
    --build-arg BASE_IMAGE="${BASE_IMAGE}" \
    --build-arg ROOT_PASSWORD="${ROOT_PASSWORD}" \
    $BASE_DIR/rootfs >${ROOTFS_TAR}

# Build bootloader partitions
ESP_IMG_TAR="${TMPDIR}/esp.img.tar"
GRUB_IMG_TAR="${TMPDIR}/grub.img.tar"
"${TOOL_DIR}"/build_vfat_image.py -o "${ESP_IMG_TAR}" -s 100M -p boot/efi -i "${BOOTLOADER_TAR}"
"${TOOL_DIR}"/build_vfat_image.py -o "${GRUB_IMG_TAR}" -s 100M -p boot/grub -i "${BOOTLOADER_TAR}" \
    "${BASE_DIR}/bootloader/grub.cfg:/boot/grub/grub.cfg:644" \
    "${BASE_DIR}/bootloader/grubenv:/boot/grub/grubenv:644"

# Extract bootloader partitions.
ESP_IMG="${TMPDIR}/esp.img"
GRUB_IMG="${TMPDIR}/grub.img"
tar -xOf ${ESP_IMG_TAR} >${ESP_IMG}
tar -xOf ${GRUB_IMG_TAR} >${GRUB_IMG}

# Prepare empty config partition.
CONFIG_IMG="${TMPDIR}/config.img"
truncate --size 100M "$CONFIG_IMG"
make_ext4fs -T 0 -l 100M "$CONFIG_IMG"

# Build partitions for system image A.
BOOT_IMG="${TMPDIR}/boot.img"
ROOT_IMG="${TMPDIR}/root.img"
"${BASE_DIR}"/../scripts/build-ubuntu.sh -i "${ROOTFS_TAR}" -r "${ROOT_IMG}" -b "${BOOT_IMG}"

# Assemble update image
UPDATE_DIR=${TMPDIR}/update
mkdir ${UPDATE_DIR}
echo "${VERSION}" >"${UPDATE_DIR}/VERSION.TXT"
cp "${BOOT_IMG}" "${UPDATE_DIR}/boot.img"
cp "${ROOT_IMG}" "${UPDATE_DIR}/root.img"
# Sort by name in tar file -- makes ordering deterministic and ensures
# that VERSION.TXT is first entry, making it quick & easy to extract.
# Override owner, group and mtime to make build independent of the user
# building it.
tar czf "update-img.tar.gz" --sort=name --owner=root:0 --group=root:0 --mtime='UTC 2020-01-01' --sparse -C "${UPDATE_DIR}" .

# Create HostOS LVM Structure
VOLUME_GROUP="hostlvm"
LVM_IMG="${TMPDIR}/lvm.img"
prepare_lvm_image "$LVM_IMG" 107374182400 "$VOLUME_GROUP" "4c7GVZ-Df82-QEcJ-xXtV-JgRL-IjLE-hK0FgA" "eu0VQE-HlTi-EyRc-GceP-xZtn-3j6t-iqEwyv" # 100G

# Assemble disk image
DISK_IMG="${TMPDIR}/disk.img"
prepare_disk_image "$DISK_IMG" 108447924224 # 101G
write_single_partition "$DISK_IMG" esp "$ESP_IMG"
write_single_partition "$DISK_IMG" grub "$GRUB_IMG"
write_single_partition "$DISK_IMG" hostlvm "$LVM_IMG"
write_single_lvm_volume "$DISK_IMG" "$VOLUME_GROUP" A_boot "$BOOT_IMG"
write_single_lvm_volume "$DISK_IMG" "$VOLUME_GROUP" A_root "$ROOT_IMG"
write_single_lvm_volume "$DISK_IMG" "$VOLUME_GROUP" config "$CONFIG_IMG"

# Package image in tar
tar czf "disk-img.tar.gz" --sort=name --owner=root:0 --group=root:0 --mtime='UTC 2020-01-01' --sparse -C "${TMPDIR}" disk.img

rm -rf $TMPDIR
