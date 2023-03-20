#!/usr/bin/env bash

# Write image to config LVM of hostos image
#
# Arguments:
#   $1: The partition image to be read from.
#   $2: The disk image to write to.

set -eo pipefail

PART_IMAGE=$1
DISK_IMAGE=$2

BASE_DIR=$(dirname "${BASH_SOURCE[0]}")/..
PARTITIONS_CSV="${BASE_DIR}/partitions.csv"
VOLUMES_CSV="${BASE_DIR}/volumes.csv"

# The following are utility functions from `partitions.sh` that are now only
# used here.
# -----------------------------------------------------------------------

# Read partitions.csv in "canonical form" (i.e. remove all comments,
# strip whitespace from fields).
function read_canonical_partitions_csv() {
    sed -e '/^#/d' -e 's/ *, */,/g' <"${PARTITIONS_CSV}"
}

# Read volumes.csv in "canonical form" (i.e. remove all comments,
# strip whitespace from fields).
function read_canonical_volumes_csv() {
    sed -e '/^#/d' -e 's/ *, */,/g' <"${VOLUMES_CSV}"
}

function read_volume_sizes_by_name() {
    read_canonical_volumes_csv \
        | while IFS=, read -r name start size type uuid comment; do
            echo "[$name]=$size"
        done
}

function read_partition_starts_by_name() {
    read_canonical_partitions_csv \
        | while IFS=, read -r name start size type uuid comment; do
            echo "[$name]=$start"
        done
}

function read_volume_starts_by_name() {
    read_canonical_volumes_csv \
        | while IFS=, read -r name start size type uuid comment; do
            echo "[$name]=$start"
        done
}

eval "declare -A VOLUME_SIZE_BY_NAME=( $(read_volume_sizes_by_name) )"
eval "declare -A PARTITION_START_BY_NAME=( $(read_partition_starts_by_name) )"
eval "declare -A VOLUME_START_BY_NAME=( $(read_volume_starts_by_name) )"

# Write a single partition image into a specific volume of the
# lvm vg.
#
# Arguments:
#   $1: The disk image to be written to.
#   $2: The volume group to be written to.
#   $3: The name of the volume that should be written to.
#   $4: The file containing the volume to be written.
function write_single_lvm_volume() {
    local DISK_IMAGE="$1"
    local VOLUME_GROUP="$2"
    local PART_NAME="$3"
    local PART_IMAGE="$4"

    local FILE_SIZE=$(stat -c "%s" "$PART_IMAGE")

    local PART_SIZE=${VOLUME_SIZE_BY_NAME["$PART_NAME"]}
    local PART_SIZE_BYTES=$(("$PART_SIZE" * 4194304))

    local PART_OFFSET=$((${PARTITION_START_BY_NAME["$VOLUME_GROUP"]} * 512))
    local LVM_OFFSET=$((2048 * 512))
    local VOLUME_OFFSET=$((${VOLUME_START_BY_NAME["$PART_NAME"]} * 4194304))

    local OFFSET=$((${PART_OFFSET} + ${LVM_OFFSET} + ${VOLUME_OFFSET}))
    local OFFSET_BLOCKS=$((${OFFSET} / 4096))

    if [ "$FILE_SIZE" -gt "$PART_SIZE_BYTES" ]; then
        echo "Image '${PART_IMAGE}' does not fit in partition '${PART_NAME}' on disk."
        exit 1
    fi

    dd if="$PART_IMAGE" of="$DISK_IMAGE" bs=4096 seek="$OFFSET_BLOCKS" conv=sparse,notrunc
}

# The following are the actual contents of this script
# -----------------------------------------------------------------------

write_single_lvm_volume ${DISK_IMAGE} hostlvm config ${PART_IMAGE}
