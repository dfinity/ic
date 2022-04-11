#!/usr/bin/env bash

# Build bootable full disk image containing the initial system image.

set -eo pipefail

function usage() {
    cat <<EOF
Usage:
  build-disk-image -o outfile [-t bootloader.tar] [-u ubuntu.tar] [-b boot.img] [-r root.img] [-x execdir]

  Build whole disk of IC guest OS VM image.

  -o outfile: Name of output file; mandatory
  -t bootloader.tar: Docker save tar of the bootloader build
  -t image type: The type of image to build. Must be either "dev" or "prod".
     If nothing is specified, defaults to building "prod" image.
  -p password: Set root password for console access. This is only allowed
     for "dev" images
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

BUILD_TYPE=prod
while getopts "o:t:u:b:r:t:v:p:x:" OPT; do
    case "${OPT}" in
        o)
            OUT_FILE="${OPTARG}"
            ;;
        t)
            BUILD_TYPE="${OPTARG}"
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

# Preparatory steps and temporary build directory.
BASE_DIR=$(dirname "${BASH_SOURCE[0]}")/..
source "${BASE_DIR}"/scripts/partitions.sh

TOOL_DIR="${BASE_DIR}/../../toolchains/sysimage/"

TMPDIR=$(mktemp -d -t build-image-XXXXXXXXXXXX)
trap "rm -rf $TMPDIR" exit

# Validate and process arguments

if [ "${OUT_FILE}" == "" ]; then
    usage
    exit 1
fi

if [ "${BUILD_TYPE}" != "dev" -a "${BUILD_TYPE}" != "prod" ]; then
    echo "Unknown build type: ${BUILD_TYPE}"
    exit 1
fi

if [ "${ROOT_PASSWORD}" != "" -a "${BUILD_TYPE}" != "dev" ]; then
    echo "Root password is valid only for build type 'dev'"
    exti 1
fi

if [ "${VERSION}" == "" ]; then
    echo "Version needs to be specified for build to succeed"
fi

BASE_IMAGE=$(cat "${BASE_DIR}/rootfs/docker-base.${BUILD_TYPE}")

# Compute arguments for actual build stage.

declare -a IC_EXECUTABLES=(orchestrator replica canister_sandbox sandbox_launcher vsock_agent state-tool ic-consensus-pool-util ic-crypto-csp ic-regedit ic-btc-adapter ic-canister-http-adapter)
declare -a INSTALL_EXEC_ARGS=()
for IC_EXECUTABLE in "${IC_EXECUTABLES[@]}"; do
    INSTALL_EXEC_ARGS+=("${EXEC_SRCDIR}/${IC_EXECUTABLE}:/opt/ic/bin/${IC_EXECUTABLE}:0755")
done

echo "${VERSION}" >"${TMPDIR}/version.txt"

# Build all pieces and assemble the disk image.

"${TOOL_DIR}"/docker_tar.py -o "${TMPDIR}/boot-tree.tar" "${BASE_DIR}/bootloader"
"${TOOL_DIR}"/docker_tar.py -o "${TMPDIR}/rootfs-tree.tar" -- --build-arg ROOT_PASSWORD="${ROOT_PASSWORD}" --build-arg BASE_IMAGE="${BASE_IMAGE}" "${BASE_DIR}/rootfs"
"${TOOL_DIR}"/build_vfat_image.py -o "${TMPDIR}/partition-esp.tar" -s 100M -p boot/efi -i "${TMPDIR}/boot-tree.tar"
"${TOOL_DIR}"/build_vfat_image.py -o "${TMPDIR}/partition-grub.tar" -s 100M -p boot/grub -i "${TMPDIR}/boot-tree.tar" \
    "${BASE_DIR}/bootloader/grub.cfg:/boot/grub/grub.cfg:644" \
    "${BASE_DIR}/bootloader/grubenv:/boot/grub/grubenv:644"
"${TOOL_DIR}"/build_ext4_image.py -o "${TMPDIR}/partition-config.tar" -s 100M
tar xOf "${TMPDIR}"/rootfs-tree.tar --occurrence=1 etc/selinux/default/contexts/files/file_contexts >"${TMPDIR}/file_contexts"
"${TOOL_DIR}"/build_ext4_image.py -o "${TMPDIR}/partition-boot.tar" -s 1G -i "${TMPDIR}/rootfs-tree.tar" -S "${TMPDIR}/file_contexts" -p boot/ \
    "${TMPDIR}/version.txt:/boot/version.txt:0644" \
    "${BASE_DIR}/rootfs/boot/extra_boot_args:/boot/extra_boot_args:0644"
"${TOOL_DIR}"/build_ext4_image.py -o "${TMPDIR}/partition-root.tar" -s 3G -i "${TMPDIR}/rootfs-tree.tar" -S "${TMPDIR}/file_contexts" \
    "${INSTALL_EXEC_ARGS[@]}" \
    "${TMPDIR}/version.txt:/opt/ic/share/version.txt:0644"
"${TOOL_DIR}"/build_disk_image.py -o "${TMPDIR}/disk.img.tar" -p "${BASE_DIR}/scripts/partitions.csv" \
    ${TMPDIR}/partition-esp.tar \
    ${TMPDIR}/partition-grub.tar \
    ${TMPDIR}/partition-config.tar \
    ${TMPDIR}/partition-boot.tar \
    ${TMPDIR}/partition-root.tar

# For compatibility with previous use of this script, provide the raw
# image as output from this program.
OUT_DIRNAME="$(dirname "${OUT_FILE}")"
OUT_BASENAME="$(basename "${OUT_FILE}")"
tar xf "${TMPDIR}/disk.img.tar" --transform="s/disk.img/${OUT_BASENAME}/" -C "${OUT_DIRNAME}"
# increase size a bit, for immediate qemu use (legacy)
truncate --size 50G "${OUT_FILE}"
