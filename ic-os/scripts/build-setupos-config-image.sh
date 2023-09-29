#!/usr/bin/env bash

set -e

INPUT_FOLDER="${1}"
OUTPUT_IMAGE="${2}"

TMPDIR=$(mktemp -d)

tar cf "${TMPDIR}/config.tar" -C "${INPUT_FOLDER}" .

truncate -s 10M "${OUTPUT_IMAGE}"

mkfs.vfat "${OUTPUT_IMAGE}"

mlabel -i "${OUTPUT_IMAGE}" ::OVERRIDE

mcopy -i "${OUTPUT_IMAGE}" -o "${TMPDIR}/config.tar" ::

rm -rf "${TMPDIR}"
