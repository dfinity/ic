#!/usr/bin/env bash

# Build bootable full disk image containing the initial system image.

set -eo pipefail

function usage() {
    cat <<EOF
Usage:
  build-disk-image -o outfile [-t dev] [-x execdir] [-s]

  Build whole disk of Boundary Node guest OS VM image.

  -o outfile: Name of output file; mandatory
  -t image type: The type of image to build. Must be either "dev" or "prod".
      If nothing is specified, defaults to building "prod" image.
  -p password: Set root password for console access. BE CAREFUL.
  -v version: The version written into the image; mandatory
  -x execdir: Set executable source dir. Will take all required IC executables
     from source directory and install it into the correct location before
     building the image; mandatory
  -s: Set SNP flag to true in order to build SEV-SNP enabled image; optional
EOF
}

BUILD_TYPE=prod
while getopts "o:t:v:p:x:s" OPT; do
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
        s)
            SNP=true
            ;;
        *)
            usage >&2
            exit 1
            ;;
    esac
done

# Preparatory steps and temporary build directory.
BASE_DIR=$(dirname "${BASH_SOURCE[0]}")/..
EXTERNAL_DIR="${BASE_DIR}/external"

TOOL_DIR="${BASE_DIR}/../../toolchains/sysimage/"

TMPDIR=$(mktemp -d -t build-image-XXXXXXXXXXXX)
trap "rm -rf $TMPDIR" exit

# Validate and process arguments

if [ "${OUT_FILE}" == "" ]; then
    usage >&2
    exit 1
fi

# For the moment we only support prod but soon also dev!
if [ "${BUILD_TYPE}" != "prod" ]; then
    echo "Unknown build type: ${BUILD_TYPE}" >&2
    exit 1
fi

if [ "${VERSION}" == "" ]; then
    echo "Version needs to be specified for build to succeed" >&2
    exit 1
fi

if [ "${EXEC_SRCDIR}" == "" ]; then
    echo "Executable source dir needs to be specified for build to succeed" >&2
    exit 1
fi

if [ "$SNP" = "true" ]; then
    echo "Build SNP enabled image"
    BASE_IMAGE=$(cat "${BASE_DIR}/rootfs/docker-base.snp")
else
    BASE_IMAGE=$(cat "${BASE_DIR}/rootfs/docker-base.${BUILD_TYPE}")
fi

# Build sev-tool
(
    cd "${EXTERNAL_DIR}"
    if [ ! -e sev-tool ]; then
        git clone https://github.com/AMDESE/sev-tool.git sev-tool
        (
            cd sev-tool
            git checkout 3e6418e09f5ca91d789e115d0751ead1227aab47
        )
    fi
    cd sev-tool
    autoreconf -i && ./configure && make
)

# Compute arguments for actual build stage.

declare -a IC_EXECUTABLES=(
    "boundary-node-control-plane"
    "boundary-node-prober"
    "denylist-updater"
    "ic-balance-exporter"
)

declare -a INSTALL_EXEC_ARGS=()
for IC_EXECUTABLE in "${IC_EXECUTABLES[@]}"; do
    INSTALL_EXEC_ARGS+=("${EXEC_SRCDIR}/${IC_EXECUTABLE}:/opt/ic/bin/${IC_EXECUTABLE}:0755")
done

INSTALL_EXEC_ARGS+=("${EXTERNAL_DIR}/sev-tool/src/sevtool:/opt/ic/bin/sevtool:0755")

echo "${VERSION}" >"${TMPDIR}/version.txt"

# Build all pieces and assemble the disk image.

"${BASE_DIR}"/../bootloader/build-bootloader-tree.sh -o "${TMPDIR}/boot-tree.tar"
"${TOOL_DIR}"/docker_tar.py -o "${TMPDIR}/rootfs-tree.tar" -- --build-arg ROOT_PASSWORD="${ROOT_PASSWORD}" --build-arg BASE_IMAGE="${BASE_IMAGE}" "${BASE_DIR}/rootfs"
"${TOOL_DIR}"/build_vfat_image.py -o "${TMPDIR}/partition-esp.tar" -s 100M -p boot/efi -i "${TMPDIR}/boot-tree.tar"
"${TOOL_DIR}"/build_vfat_image.py -o "${TMPDIR}/partition-grub.tar" -s 100M -p boot/grub -i "${TMPDIR}/boot-tree.tar" \
    "${BASE_DIR}/../bootloader/grub.cfg:/boot/grub/grub.cfg:644" \
    "${BASE_DIR}/../bootloader/grubenv:/boot/grub/grubenv:644"
"${TOOL_DIR}"/build_ext4_image.py -o "${TMPDIR}/partition-config.tar" -s 100M
"${TOOL_DIR}"/build_ext4_image.py -o "${TMPDIR}/partition-root.tar" -s 3G -i "${TMPDIR}/rootfs-tree.tar" \
    "${INSTALL_EXEC_ARGS[@]}" \
    "${TMPDIR}/version.txt:/opt/ic/share/version.txt:0644"

tar xfv "${TMPDIR}/partition-root.tar" -C "${TMPDIR}"
PARTITION="${TMPDIR}/partition.img"
SIGNATURE="${TMPDIR}/ver_hash.img"
root_hash=$(veritysetup format ${PARTITION} ${SIGNATURE} | tail -n 1 | cut -d' ' -f3- | xargs)
echo ${root_hash} >${TMPDIR}/root_hash

"${TOOL_DIR}"/build_ext4_image.py -o "${TMPDIR}/partition-boot.tar" -s 1G -i "${TMPDIR}/rootfs-tree.tar" -p boot/ \
    "${TMPDIR}/version.txt:/boot/version.txt:0644" "${SIGNATURE}:/boot/ver_hash.img:0644" \
    "${TMPDIR}/root_hash:/boot/root_hash:0644"

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
