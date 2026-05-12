#!/usr/bin/env bash

set -e

CONFIG_DIR="${1}"
DATA_DIR="${2}"
OUTPUT_IMAGE="${3}"

TMPDIR=$(mktemp -d)

tar cf "${TMPDIR}/config.tar" -C "${CONFIG_DIR}" .
tar cf "${TMPDIR}/data.tar" -C "${DATA_DIR}" .

truncate -s 10M "${OUTPUT_IMAGE}"

/usr/sbin/mkfs.vfat "${OUTPUT_IMAGE}"

mlabel -i "${OUTPUT_IMAGE}" ::OVERRIDE

mcopy -i "${OUTPUT_IMAGE}" -o "${TMPDIR}/config.tar" ::
mcopy -i "${OUTPUT_IMAGE}" -o "${TMPDIR}/data.tar" ::

rm -rf "${TMPDIR}"
