#!/usr/bin/env bash

source $(dirname "${BASH_SOURCE[0]}")/partitions.sh

# Extracts the version number from built disk image
# Arguments:
# - $1: disk image file
#
# Output: the version number
function version_from_disk_image() {
    local DISK_IMAGE=$1
    local PART_IMAGE=$(mktemp)
    extract_single_partition "${DISK_IMAGE}" boot "${PART_IMAGE}" 2>/dev/null
    VERSION=$(debugfs "${PART_IMAGE}" -R "cat version.txt" 2>/dev/null || echo -n "unknown")
    #debugfs "${PART_IMAGE}" -R ls
    rm "${PART_IMAGE}"
    echo "${VERSION}"
}
