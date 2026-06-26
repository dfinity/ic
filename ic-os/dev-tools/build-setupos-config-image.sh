#!/usr/bin/env bash

set -e

CONFIG_DIR="${1}"
DATA_DIR="${2}"
OUTPUT_IMAGE="${3}"

# The Bazel-built mkfs.fat / mlabel / mcopy binaries, set in the environment by
# the system_test rule (the build container no longer ships dosfstools/mtools).
# Fall back to the system tools when run outside that environment.
mkfs_fat="${MKFS_FAT:-/usr/sbin/mkfs.fat}"
mlabel="${MLABEL:-mlabel}"
mcopy="${MCOPY:-mcopy}"

TMPDIR=$(mktemp -d)

tar cf "${TMPDIR}/config.tar" -C "${CONFIG_DIR}" .
tar cf "${TMPDIR}/data.tar" -C "${DATA_DIR}" .

truncate -s 10M "${OUTPUT_IMAGE}"

"$mkfs_fat" "${OUTPUT_IMAGE}"

"$mlabel" -i "${OUTPUT_IMAGE}" ::OVERRIDE

"$mcopy" -i "${OUTPUT_IMAGE}" -o "${TMPDIR}/config.tar" ::
"$mcopy" -i "${OUTPUT_IMAGE}" -o "${TMPDIR}/data.tar" ::

rm -rf "${TMPDIR}"
