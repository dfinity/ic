#!/usr/bin/env bash
#
# Build update image. This is the input to the system updater -- it is
# effectively a gzip'ed tar file that contains the images for the "boot"
# and "root" partitions of the system.

set -eo pipefail

function usage() {
    cat <<EOF
Usage:
  build-update-image -o update.tgz [-i ubuntu.dockerimg]  [-x execdir] [-v version]

  Build update artifact image for IC guest OS. This is a gzip'ed tar file containing
  the boot and root filesystem images for the operating system as well version metadata.

  -i ubuntu.dockerimg: Points to the output of "docker save"
     of the ubuntu docker image. If not given, will implicitly call
     docker build.
  -o update.tgz: Target to write the "update image" to. Use "-" for stdout.
  -x execdir: Set executable source dir. Will take all required IC executables
     from source directory and install it into the correct location before
     building the image.
  -v version: The version written into the image.
  -t image type: The type of image to build. Must be either "dev" or "prod".
     If nothing is specified, defaults to building "prod" image.
  -p password: Set root password for console access. This is only allowed
     for "dev" images
EOF
}

BUILD_TYPE=prod
while getopts "i:o:p:t:v:x:" OPT; do
    case "${OPT}" in
        i)
            IN_FILE="${OPTARG}"
            ;;
        o)
            OUT_FILE="${OPTARG}"
            ;;
        p)
            ROOT_PASSWORD="${OPTARG}"
            ;;
        t)
            BUILD_TYPE="${OPTARG}"
            ;;
        v)
            VERSION="${OPTARG}"
            ;;
        x)
            EXEC_SRCDIR="${OPTARG}"
            ;;
        *)
            usage >&2
            exit 1
            ;;
    esac
done

# Preparatory steps and temporary build directory.
BASE_DIR=$(dirname "${BASH_SOURCE[0]}")/..

TOOL_DIR="${BASE_DIR}/../../toolchains/sysimage/"

TMPDIR=$(mktemp -d -t build-image-XXXXXXXXXXXX)
trap "rm -rf $TMPDIR" exit

# Validate and process arguments

if [ "${OUT_FILE}" == "" ]; then
    usage >&2
    exit 1
fi

if [ "${BUILD_TYPE}" != "dev" -a "${BUILD_TYPE}" != "prod" ]; then
    echo "Unknown build type: ${BUILD_TYPE}" >&2
    exit 1
fi

if [ "${ROOT_PASSWORD}" != "" -a "${BUILD_TYPE}" != "dev" ]; then
    echo "Root password is valid only for build type 'dev'" >&2
    exit 1
fi

if [ "${VERSION}" == "" ]; then
    echo "Version needs to be specified for build to succeed" >&2
    exit 1
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

"${TOOL_DIR}"/docker_tar.py -o "${TMPDIR}/rootfs-tree.tar" -- --build-arg ROOT_PASSWORD="${ROOT_PASSWORD}" --build-arg BASE_IMAGE="${BASE_IMAGE}" "${BASE_DIR}/rootfs"
tar xOf "${TMPDIR}"/rootfs-tree.tar --occurrence=1 etc/selinux/default/contexts/files/file_contexts >"${TMPDIR}/file_contexts"
"${TOOL_DIR}"/build_ext4_image.py -o "${TMPDIR}/partition-boot.tar" -s 1G -i "${TMPDIR}/rootfs-tree.tar" -S "${TMPDIR}/file_contexts" -p boot/ \
    "${TMPDIR}/version.txt:/boot/version.txt:0644" \
    "${BASE_DIR}/rootfs/boot/extra_boot_args:/boot/extra_boot_args:0644"
"${TOOL_DIR}"/build_ext4_image.py -o "${TMPDIR}/partition-root.tar" -s 3G -i "${TMPDIR}/rootfs-tree.tar" -S "${TMPDIR}/file_contexts" \
    "${INSTALL_EXEC_ARGS[@]}" \
    "${TMPDIR}/version.txt:/opt/ic/share/version.txt:0644"

# Now assemble the upgrade image

mkdir -p "${TMPDIR}/tar"

tar xf "${TMPDIR}/partition-boot.tar" --transform="s/partition.img/boot.img/" -C "${TMPDIR}/tar"
tar xf "${TMPDIR}/partition-root.tar" --transform="s/partition.img/root.img/" -C "${TMPDIR}/tar"
echo "${VERSION}" >"${TMPDIR}/tar/VERSION.TXT"

tar czf "${OUT_FILE}" --sort=name --owner=root:0 --group=root:0 --mtime='UTC 1970-01-01 00:00:00' --sparse -C "${TMPDIR}/tar" .
