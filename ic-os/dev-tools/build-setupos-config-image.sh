#!/usr/bin/env bash

set -e

CONFIG_DIR="${1}"
DATA_DIR="${2}"
OUTPUT_IMAGE="${3}"

# MKFS_VFAT and MTOOLS are the Bazel-built mkfs.fat / mtools binaries, set in the
# environment by the system_test rule (so the build container doesn't need system
# dosfstools/mtools). mtools is a multi-call binary, driven as `mtools -c <cmd>`.

TMPDIR=$(mktemp -d)

tar cf "${TMPDIR}/config.tar" -C "${CONFIG_DIR}" .
tar cf "${TMPDIR}/data.tar" -C "${DATA_DIR}" .

truncate -s 10M "${OUTPUT_IMAGE}"

"$MKFS_VFAT" "${OUTPUT_IMAGE}"

"$MTOOLS" -c mlabel -i "${OUTPUT_IMAGE}" ::OVERRIDE

"$MTOOLS" -c mcopy -i "${OUTPUT_IMAGE}" -o "${TMPDIR}/config.tar" ::
"$MTOOLS" -c mcopy -i "${OUTPUT_IMAGE}" -o "${TMPDIR}/data.tar" ::

rm -rf "${TMPDIR}"
