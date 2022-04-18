#!/usr/bin/env bash

source $(dirname "${BASH_SOURCE[0]}")/partitions.sh ""

# Extract the version number from an upgrade artifact
# Arguments:
# - $1: upgrade artifact file
#
# Output: the version number
function version_from_upgrade_image() {
    # Search for both "VERSION.TXT" (new form) and "version.txt" in
    # the archive. The former is quickly found if it exists (because
    # it is sorted first lexicographically). The latter requires
    # unpacking the entire archive, so should be avoided. This is
    # left here for the "upgrade-to-master" test where we try an
    # upgrade to an artifact of older form.
    tar xOzf "$1" --occurrence=1 ./VERSION.TXT || tar xOzf "$1" --occurrence=1 ./version.txt
}

# Extracts the version number from built disk image
# Arguments:
# - $1: disk image file
#
# Output: the version number
function version_from_disk_image() {
    local DISK_IMAGE=$1
    local PART_IMAGE=$(mktemp)
    extract_single_partition "${DISK_IMAGE}" A_boot "${PART_IMAGE}" 2>/dev/null
    VERSION=$(debugfs "${PART_IMAGE}" -R "cat version.txt" 2>/dev/null || echo -n "unknown")
    #debugfs "${PART_IMAGE}" -R ls
    rm "${PART_IMAGE}"
    echo "${VERSION}"
}
