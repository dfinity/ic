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
            usage
            exit 1
            ;;
    esac
done

if [ "${OUT_FILE}" == "" ]; then
    usage
    exit 1
fi

TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" exit
BASE_DIR=$(dirname "${BASH_SOURCE[0]}")/..

BOOT_IMG="${TMPDIR}"/boot.img
ROOT_IMG="${TMPDIR}"/root.img

if [ "${IN_FILE}" != "" ]; then
    "${BASE_DIR}/scripts/build-ubuntu.sh" -i "${IN_FILE}" -r "${ROOT_IMG}" -b "${BOOT_IMG}" -t "${BUILD_TYPE}"
    # HACK: allow running without explicitly given version, extract version
    # from rootfs. This is NOT good, but workable for the moment.
    VERSION=$(debugfs "${ROOT_IMG}" cat /opt/ic/share/version.txt)
else
    "${BASE_DIR}/scripts/build-ubuntu.sh" -r "${ROOT_IMG}" -b "${BOOT_IMG}" -p "${ROOT_PASSWORD}" -v "${VERSION}" -x "${EXEC_SRCDIR}" -t "${BUILD_TYPE}"
fi

echo "${VERSION}" >"${TMPDIR}/VERSION.TXT"
# Sort by name in tar file -- makes ordering deterministic and ensures
# that VERSION.TXT is first entry, making it quick & easy to extract.
# Override owner, group and mtime to make build independent of the user
# building it.
tar czf "${OUT_FILE}" --sort=name --owner=root:0 --group=root:0 --mtime='UTC 2020-01-01' --sparse -C "${TMPDIR}" .

rm -rf "${TMPDIR}"
